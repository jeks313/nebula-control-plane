// Package usertrust is the versioned, dual-control-published SSO issuing-identity
// config (ADR 0004, decisions S1–S4): which SAML/OIDC directory groups, in which
// realm, may enroll into the mesh and the mesh (nebula) groups + CIDR (netblock) +
// auto-issue posture each is granted. The active config is the latest committed
// usertrust.publish dual-control change, exactly as the active cloud-trust config is
// the latest committed cloudtrust.publish (it is a peer to cloudtrust, not a fork).
//
// Shape mirrors cloudtrust: a fleet-wide DefaultGroups set granted to ANY validly
// SSO-enrolled host, plus an ordered list of per-directory-group entries. Resolution
// is FIRST-MATCH WINS over the ordered entries (S4) — a user in several matched AD
// groups gets the first matching entry's mesh groups, netblock, and auto-issue, with
// DefaultGroups merged in; there is no union across entries.
package usertrust

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/jeks313/nebula-control-plane/internal/dualcontrol"
)

// PublishKind is the dual-control change kind for a user-trust config publish.
const PublishKind = "usertrust.publish"

// RegisterCommitter installs the usertrust.publish commit-time validator on dc —
// the single canonical definition shared by every wiring site (harbor CLI, admin
// API, demo seeder), so the gate can't drift by call site. Re-parsing at commit is
// defense in depth: the UI also blocks duplicates (S3) but the UI is bypassable, so
// the published config must be self-consistent on its own.
func RegisterCommitter(dc *dualcontrol.Controller) {
	dc.Register(PublishKind, func(_ context.Context, ch dualcontrol.Change) error {
		_, err := Parse(ch.Payload)
		return err
	})
}

// IDPEntry is one trusted directory-group entry (S2). A SAML/OIDC assertion whose
// realm matches and whose group membership includes DirectoryGroup grants the host
// the entry's mesh groups (merged with the config DefaultGroups), draws its overlay
// IP from Netblock, and is issued immediately iff AutoIssue.
type IDPEntry struct {
	// Realm scopes the entry to one IdP/tenant; empty Realm is a wildcard matching
	// any realm. Required for uniqueness only together with DirectoryGroup.
	Realm string `json:"realm"`
	// DirectoryGroup is the SAML/OIDC AD-group name this entry keys on (S2). Required.
	DirectoryGroup string `json:"directory_group"`
	// MeshGroups are the nebula groups granted to a host matching this entry, on top
	// of the config DefaultGroups.
	MeshGroups []string `json:"mesh_groups"`
	// AutoIssue true = issue immediately; false = queue for manual approval (S8
	// defaults this off; admin/privileged groups never auto-issue).
	AutoIssue bool `json:"auto_issue"`
	// Netblock is the named IPAM netblock matching hosts draw their overlay IP from
	// (ADR 0010, per-scope binding). Empty = the bounded 'default' block. Not
	// validated here: the name is resolved at allocation time.
	Netblock string `json:"netblock,omitempty"`
}

// Config is the full user-trust config (the dual-control change payload).
type Config struct {
	// DefaultGroups are granted to every validly SSO-enrolled host, regardless of
	// which entry matched (merged with the matched entry's MeshGroups), mirroring
	// cloudtrust.DefaultGroups.
	DefaultGroups []string `json:"default_groups,omitempty"`
	// IDPEntries is the ordered trusted-directory-group list. Order is significant:
	// resolution is first-match-wins (S4).
	IDPEntries []IDPEntry `json:"idp_entries,omitempty"`
}

// Errors callers can branch on.
var (
	ErrEmpty          = errors.New("usertrust: at least one IdP entry is required")
	ErrNoRealm        = errors.New("usertrust: each IdP entry needs a realm")
	ErrNoGroup        = errors.New("usertrust: each IdP entry needs a directory_group")
	ErrDuplicateGroup = errors.New("usertrust: duplicate (realm, directory_group) entry")
	ErrGrantsNothing  = errors.New("usertrust: entry grants no groups (no mesh_groups and no default_groups)")
)

// Parse decodes and validates a payload (rejects unknown fields so a typo can't
// silently widen trust), mirroring cloudtrust.Parse.
func Parse(b []byte) (Config, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var c Config
	if err := dec.Decode(&c); err != nil {
		return Config{}, fmt.Errorf("usertrust: parse: %w", err)
	}
	if err := Validate(c); err != nil {
		return Config{}, err
	}
	return c, nil
}

// Validate enforces fail-closed structural invariants: at least one entry, each entry
// has a realm and a directory_group, no duplicate (realm, directory_group) across
// entries (S3 AD-group uniqueness — the same group in a *different* realm is allowed),
// and no entry that would grant nothing (no mesh_groups AND no config default_groups,
// which would enroll a host into zero groups).
func Validate(c Config) error {
	if len(c.IDPEntries) == 0 {
		return ErrEmpty
	}
	type key struct{ realm, group string }
	seen := make(map[key]bool, len(c.IDPEntries))
	for _, e := range c.IDPEntries {
		if e.Realm == "" {
			return ErrNoRealm
		}
		if e.DirectoryGroup == "" {
			return ErrNoGroup
		}
		k := key{e.Realm, e.DirectoryGroup}
		if seen[k] {
			return fmt.Errorf("%w: realm=%s directory_group=%s", ErrDuplicateGroup, e.Realm, e.DirectoryGroup)
		}
		seen[k] = true
		if len(e.MeshGroups) == 0 && len(c.DefaultGroups) == 0 {
			return fmt.Errorf("%w: realm=%s directory_group=%s", ErrGrantsNothing, e.Realm, e.DirectoryGroup)
		}
	}
	return nil
}

// Match resolves an SSO identity (its realm + the directory groups the IdP asserted)
// against the ordered entries, FIRST-MATCH WINS for groups, netblock, AND auto-issue
// (S4 — no union across entries). An entry matches when its Realm equals realm (an
// empty entry.Realm is a wildcard matching any realm) AND its DirectoryGroup is one of
// userGroups. On a match it returns the resolved group set (DefaultGroups ∪ the matched
// entry's MeshGroups, deduped+sorted), the matched entry's Netblock (empty = default
// block), the matched entry's AutoIssue, and ok=true. No entry matches → ok=false,
// which means DENY (an identity in no trusted group may not enroll — fail closed).
func Match(cfg Config, realm string, userGroups []string) (groups []string, netblock string, autoIssue, ok bool) {
	for _, e := range cfg.IDPEntries {
		if e.Realm != "" && e.Realm != realm {
			continue
		}
		if !contains(userGroups, e.DirectoryGroup) {
			continue
		}
		return resolveGroups(cfg.DefaultGroups, e.MeshGroups), e.Netblock, e.AutoIssue, true
	}
	return nil, "", false, false
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

func resolveGroups(defaults, entryGroups []string) []string {
	set := make(map[string]struct{}, len(defaults)+len(entryGroups))
	for _, g := range defaults {
		set[g] = struct{}{}
	}
	for _, g := range entryGroups {
		set[g] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for g := range set {
		out = append(out, g)
	}
	sort.Strings(out)
	return out
}
