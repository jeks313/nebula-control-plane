// Package dbsecret resolves Harbor's Postgres login from an AWS Secrets Manager secret —
// specifically Aurora's RDS-managed master credential, which RDS creates and ROTATES (the
// password never enters Terraform state and must not be baked into a DSN). It returns a
// store.CredentialFunc that the data layer calls before each new physical connection, so a
// rotated secret is picked up automatically with no restart and no static password anywhere.
//
// The fetched value is cached for a short TTL so a connection storm doesn't hammer Secrets
// Manager; after the TTL it re-fetches, which is how a rotation is observed.
package dbsecret

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"

	"github.com/jeks313/nebula-control-plane/internal/store"
)

// smAPI is the slice of the Secrets Manager client used here, so tests inject a fake without
// touching AWS. *secretsmanager.Client satisfies it.
type smAPI interface {
	GetSecretValue(context.Context, *secretsmanager.GetSecretValueInput, ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
}

// Config builds a credential provider over an RDS-managed (rotating) secret.
type Config struct {
	SecretARN string        // Secrets Manager ARN (or name) of the RDS-managed credential
	Region    string        // optional; else the default chain (env / instance role region)
	TTL       time.Duration // cache window before a re-fetch (0 -> 60s); bounds rotation-pickup latency
}

// rdsSecret is the JSON shape of an RDS-managed master user secret.
type rdsSecret struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type provider struct {
	api smAPI
	arn string
	ttl time.Duration

	mu        sync.Mutex
	user, pw  string
	fetchedAt time.Time
}

// New builds a store.CredentialFunc backed by the real Secrets Manager client (region /
// credentials from the default chain — the instance role in production — unless Region is
// set). It does not fetch here; the first connection does, so a bad ARN fails fast and loud
// at connect time rather than at process start.
func New(ctx context.Context, cfg Config) (store.CredentialFunc, error) {
	if cfg.SecretARN == "" {
		return nil, errors.New("dbsecret: SecretARN is required")
	}
	var opts []func(*awsconfig.LoadOptions) error
	if cfg.Region != "" {
		opts = append(opts, awsconfig.WithRegion(cfg.Region))
	}
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("dbsecret: load AWS config: %w", err)
	}
	return newProvider(secretsmanager.NewFromConfig(awsCfg), cfg.SecretARN, cfg.TTL).get, nil
}

func newProvider(api smAPI, arn string, ttl time.Duration) *provider {
	if ttl <= 0 {
		ttl = 60 * time.Second
	}
	return &provider{api: api, arn: arn, ttl: ttl}
}

// get returns the current username/password, serving a cached value within the TTL and
// re-fetching past it. The lock is held across the fetch so a burst of new connections makes
// at most one Secrets Manager call (the rest see the fresh cache).
func (p *provider) get(ctx context.Context) (string, string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.user != "" && time.Since(p.fetchedAt) < p.ttl {
		return p.user, p.pw, nil
	}
	out, err := p.api.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{SecretId: &p.arn})
	if err != nil {
		return "", "", fmt.Errorf("dbsecret: get %s: %w", p.arn, err)
	}
	if out.SecretString == nil {
		return "", "", fmt.Errorf("dbsecret: secret %s has no string value", p.arn)
	}
	var s rdsSecret
	if err := json.Unmarshal([]byte(*out.SecretString), &s); err != nil {
		return "", "", fmt.Errorf("dbsecret: parse secret JSON: %w", err)
	}
	if s.Username == "" || s.Password == "" {
		return "", "", fmt.Errorf("dbsecret: secret %s missing username/password", p.arn)
	}
	p.user, p.pw, p.fetchedAt = s.Username, s.Password, time.Now()
	return p.user, p.pw, nil
}
