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
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/jeks313/nebula-control-plane/internal/policy"
)

// The reserved/privileged mesh group set an SSO entry must never AUTO-issue into (the
// IDPEntry.AutoIssue doc: "admin/privileged groups never auto-issue", S8) is owned by
// internal/policy — the single canonical definition the genesis + policy invariants use.
// We reuse policy.IsReservedGroup rather than re-spelling the literals so the set can't
// drift; policy does NOT import usertrust, so the import is clean (no cycle).

// PublishKind is the dual-control change kind for a user-trust config publish.
const PublishKind = "usertrust.publish"

// IDPEntry is one trusted directory-group entry (S2). A SAML/OIDC assertion whose
// realm matches and whose group membership includes DirectoryGroup grants the host
// the entry's mesh groups (merged with the config DefaultGroups), draws its overlay
// IP from Netblock, and is issued immediately iff AutoIssue.
type IDPEntry struct {
	// Realm scopes the entry to one IdP/tenant and is matched EXACTLY against the
	// assertion issuer/realm. Required (Validate rejects an empty realm); together with
	// DirectoryGroup it is the entry's uniqueness key.
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
	// ErrAutoIssuePrivileged enforces S8 ("admin/privileged groups never auto-issue"):
	// an auto_issue=true entry whose GRANTED mesh groups (its mesh_groups ∪ the config
	// default_groups) include a reserved/privileged group is rejected. Such a host must
	// go through manual approval (auto_issue=false), never mint a privileged identity
	// unattended. Security-review final hardening (FIX B).
	ErrAutoIssuePrivileged = errors.New("usertrust: auto_issue entry grants a reserved/privileged group (admin/privileged groups never auto-issue)")
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
		// S8: an auto_issue entry must not grant a reserved/privileged group — neither via
		// its own mesh_groups nor via the fleet-wide default_groups merged into it. A
		// privileged host must be queued for manual approval (auto_issue=false), never
		// minted unattended. Non-auto entries may reference these groups (an admin approves).
		if e.AutoIssue {
			for _, g := range e.MeshGroups {
				if policy.IsReservedGroup(g) {
					return fmt.Errorf("%w: realm=%s directory_group=%s group=%s", ErrAutoIssuePrivileged, e.Realm, e.DirectoryGroup, g)
				}
			}
			for _, g := range c.DefaultGroups {
				if policy.IsReservedGroup(g) {
					return fmt.Errorf("%w: realm=%s directory_group=%s default_group=%s", ErrAutoIssuePrivileged, e.Realm, e.DirectoryGroup, g)
				}
			}
		}
	}
	return nil
}

// ContainsPrivileged reports whether the config contains ANY privileged grant — the
// usertrust half of the ADR-0011 P1.2 PRIVILEGED predicate (resulting-config rule,
// not a delta). Privileged means EITHER:
//   - a reserved-group grant: any IDPEntry's MeshGroups ∪ the fleet-wide DefaultGroups
//     contains a reserved/privileged group (control-plane/lighthouse), reusing
//     policy.IsReservedGroup; OR
//   - any auto_issue=true entry (issuing immediately, unattended, is privileged).
//
// The auto_issue+reserved COMBO is a separate, stricter case: Validate refuses it
// outright (ErrAutoIssuePrivileged, S8) before this predicate is ever consulted — so
// that combo 400s at the PUT, it never reaches the two-person route. This predicate
// catches the still-VALID privileged configs: a non-auto reserved grant (an admin
// approves it) and an auto_issue entry granting only non-reserved groups (both route
// two-person).
func ContainsPrivileged(c Config) bool {
	for _, g := range c.DefaultGroups {
		if policy.IsReservedGroup(g) {
			return true
		}
	}
	for _, e := range c.IDPEntries {
		if e.AutoIssue {
			return true
		}
		for _, g := range e.MeshGroups {
			if policy.IsReservedGroup(g) {
				return true
			}
		}
	}
	return false
}

// Match resolves an SSO identity (its realm + the directory groups the IdP asserted)
// against the ordered entries, FIRST-MATCH WINS for groups, netblock, AND auto-issue
// (S4 — no union across entries). An entry matches when its Realm equals realm EXACTLY
// AND its DirectoryGroup is one of userGroups. On a match it returns the resolved group
// set (DefaultGroups ∪ the matched entry's MeshGroups, deduped+sorted), the matched
// entry's Netblock (empty = default block), the matched entry's AutoIssue, and ok=true.
// No entry matches → ok=false, which means DENY (an identity in no trusted group may not
// enroll — fail closed).
func Match(cfg Config, realm string, userGroups []string) (groups []string, netblock string, autoIssue, ok bool) {
	for _, e := range cfg.IDPEntries {
		if e.Realm != realm {
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
