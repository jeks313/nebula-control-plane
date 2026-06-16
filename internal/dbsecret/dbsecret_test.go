package dbsecret

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

type fakeSM struct {
	calls  int
	secret string
	err    error
}

func (f *fakeSM) GetSecretValue(_ context.Context, _ *secretsmanager.GetSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	s := f.secret
	return &secretsmanager.GetSecretValueOutput{SecretString: &s}, nil
}

func TestProviderParsesAndCaches(t *testing.T) {
	f := &fakeSM{secret: `{"username":"harbor","password":"s3cret","host":"x","engine":"postgres"}`}
	p := newProvider(f, "arn:aws:secretsmanager:...:secret/rds", time.Minute)
	ctx := context.Background()

	u, pw, err := p.get(ctx)
	if err != nil || u != "harbor" || pw != "s3cret" {
		t.Fatalf("get = (%q,%q,%v), want (harbor,s3cret,nil)", u, pw, err)
	}
	if f.calls != 1 {
		t.Fatalf("first get made %d API calls, want 1", f.calls)
	}

	// Within TTL: served from cache, no new API call.
	if _, _, err := p.get(ctx); err != nil {
		t.Fatal(err)
	}
	if f.calls != 1 {
		t.Fatalf("cached get made %d API calls, want still 1", f.calls)
	}

	// Past TTL: re-fetch (this is how a rotated secret is picked up). The new value wins.
	f.secret = `{"username":"harbor","password":"rotated"}`
	p.fetchedAt = time.Now().Add(-2 * time.Minute)
	_, pw, err = p.get(ctx)
	if err != nil || pw != "rotated" {
		t.Fatalf("post-TTL get = (%q,%v), want (rotated,nil)", pw, err)
	}
	if f.calls != 2 {
		t.Fatalf("post-TTL get made %d API calls, want 2", f.calls)
	}
}

func TestProviderErrors(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name   string
		secret string
		apiErr error
	}{
		{"malformed json", `not json`, nil},
		{"missing password", `{"username":"harbor"}`, nil},
		{"missing username", `{"password":"x"}`, nil},
		{"api error", `{"username":"harbor","password":"x"}`, errors.New("access denied")},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := newProvider(&fakeSM{secret: c.secret, err: c.apiErr}, "arn", time.Minute)
			if _, _, err := p.get(ctx); err == nil {
				t.Fatalf("%s: expected an error, got nil", c.name)
			}
		})
	}
}

func TestNewRequiresARN(t *testing.T) {
	if _, err := New(context.Background(), Config{}); err == nil {
		t.Fatal("New with empty SecretARN should error")
	}
}
