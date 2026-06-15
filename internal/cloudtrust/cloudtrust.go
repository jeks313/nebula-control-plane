// Package cloudtrust is the versioned, dual-control-published cloud-attestation trust
// config: which cloud principals (AWS accounts/roles, and — later — Azure subscriptions,
// GCP projects) may attest into the mesh, and the groups + auto-issue posture each is
// granted. The active config is the latest committed cloudtrust.publish dual-control
// change (mirroring how the active firewall policy is the latest committed policy.publish).
//
// The config is provider-agnostic by shape: a fleet-wide DefaultGroups set granted to ANY
// validly-attested host, plus per-provider trusted-principal lists (AWS today; Azure/GCP
// slot in beside it). Per-principal Groups stand in for the full 5.5 immutable-fact group
// map until that lands.
package cloudtrust

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/jeks313/nebula-control-plane/internal/awsattest"
	"github.com/jeks313/nebula-control-plane/internal/dualcontrol"
)

// PublishKind is the dual-control change kind for a cloud-trust config publish.
const PublishKind = "cloudtrust.publish"

// RegisterCommitter installs the cloudtrust.publish commit-time validator on dc —
// the single canonical definition shared by every wiring site (harbor CLI, admin
// API, demo seeder), so the gate can't drift by call site. Re-parsing at commit is
// defense in depth.
func RegisterCommitter(dc *dualcontrol.Controller) {
	dc.Register(PublishKind, func(_ context.Context, ch dualcontrol.Change) error {
		_, err := Parse(ch.Payload)
		return err
	})
}

// ProviderAWS identifies AWS as the attestation provider — stored as attestation
// evidence + a discriminator for future provider sections.
const ProviderAWS = "aws"

// AWSAccount is one trusted AWS account entry.
type AWSAccount struct {
	Account     string   `json:"account"`                // AWS account id — exact match, required
	ARNPatterns []string `json:"arn_patterns,omitempty"` // allowed caller-ARN globs; empty = any ARN IN THIS ACCOUNT
	Groups      []string `json:"groups,omitempty"`       // groups granted to hosts attesting from this account
	AutoIssue   bool     `json:"auto_issue,omitempty"`   // true = issue immediately; false = queue for manual approval
}

// Config is the full cloud-trust config (the dual-control change payload).
type Config struct {
	// DefaultGroups are granted to every validly-attested host, regardless of which
	// account/principal matched (unioned with the matched principal's own groups).
	DefaultGroups []string `json:"default_groups,omitempty"`
	// AWS is the trusted-AWS-account list. Azure/GCP sections will sit beside it.
	AWS []AWSAccount `json:"aws,omitempty"`
}

// Errors callers can branch on.
var (
	ErrEmpty      = errors.New("cloudtrust: at least one trusted principal is required")
	ErrNoAccount  = errors.New("cloudtrust: each AWS entry needs an account id")
	ErrDupAccount = errors.New("cloudtrust: duplicate AWS account entry")
)

// Parse decodes and validates a payload (rejects unknown fields so a typo can't
// silently widen trust).
func Parse(b []byte) (Config, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var c Config
	if err := dec.Decode(&c); err != nil {
		return Config{}, fmt.Errorf("cloudtrust: parse: %w", err)
	}
	if err := Validate(c); err != nil {
		return Config{}, err
	}
	return c, nil
}

// Validate enforces fail-closed structural invariants: at least one trusted principal,
// each AWS entry has an account id, no duplicate accounts. (An entry with no ARN patterns
// trusts the whole account — intentional, but the caller chose it explicitly.)
func Validate(c Config) error {
	if len(c.AWS) == 0 {
		return ErrEmpty
	}
	seen := make(map[string]bool, len(c.AWS))
	for _, a := range c.AWS {
		if a.Account == "" {
			return ErrNoAccount
		}
		if seen[a.Account] {
			return fmt.Errorf("%w: %s", ErrDupAccount, a.Account)
		}
		seen[a.Account] = true
	}
	return nil
}

// MatchAWS resolves a STS-verified AWS identity against the trusted accounts, reusing
// awsattest's vetted account-exact + ARN-glob matching. On a match it returns the
// resolved group set (DefaultGroups ∪ the matched account's groups, deduped+sorted) and
// the auto-issue posture. ok=false means DENY — an identity matching no entry may not
// attest (fail closed).
func (c Config) MatchAWS(id awsattest.Identity) (groups []string, autoIssue, ok bool) {
	for _, a := range c.AWS {
		gate := awsattest.Policy{Accounts: []string{a.Account}, ARNPatterns: a.ARNPatterns}
		if gate.Check(id) == nil {
			return c.resolveGroups(a.Groups), a.AutoIssue, true
		}
	}
	return nil, false, false
}

func (c Config) resolveGroups(principalGroups []string) []string {
	set := make(map[string]struct{}, len(c.DefaultGroups)+len(principalGroups))
	for _, g := range c.DefaultGroups {
		set[g] = struct{}{}
	}
	for _, g := range principalGroups {
		set[g] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for g := range set {
		out = append(out, g)
	}
	sort.Strings(out)
	return out
}
