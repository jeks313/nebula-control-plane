package usertrust

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/jeks313/nebula-control-plane/internal/policy"
)

func TestParseValid(t *testing.T) {
	c, err := Parse([]byte(`{
		"default_groups":["fleet"],
		"idp_entries":[
			{"realm":"corp","directory_group":"eng-web","mesh_groups":["web"],"auto_issue":true,"netblock":"sso-prod"},
			{"realm":"corp","directory_group":"eng-db","mesh_groups":["db"]}
		]
	}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(c.IDPEntries) != 2 || c.IDPEntries[0].DirectoryGroup != "eng-web" || !c.IDPEntries[0].AutoIssue {
		t.Fatalf("unexpected parse: %+v", c)
	}
	// netblock round-trips and is empty (-> default) when omitted.
	if c.IDPEntries[0].Netblock != "sso-prod" {
		t.Fatalf("netblock not parsed: %+v", c.IDPEntries[0])
	}
	if c.IDPEntries[1].Netblock != "" {
		t.Fatalf("omitted netblock should be empty: %+v", c.IDPEntries[1])
	}
	if len(c.DefaultGroups) != 1 || c.DefaultGroups[0] != "fleet" {
		t.Fatalf("default groups: %+v", c.DefaultGroups)
	}
}

func TestParseRejectsUnknownFields(t *testing.T) {
	if _, err := Parse([]byte(`{"idp_entries":[{"realm":"corp","directory_group":"x","mesh_groups":["a"],"oops":true}]}`)); err == nil {
		t.Fatal("expected unknown-field rejection")
	}
}

func TestParseRoundTrip(t *testing.T) {
	in := Config{
		DefaultGroups: []string{"fleet"},
		IDPEntries: []IDPEntry{
			{Realm: "corp", DirectoryGroup: "eng-web", MeshGroups: []string{"web"}, AutoIssue: true, Netblock: "sso-prod"},
			{Realm: "corp", DirectoryGroup: "eng-db", MeshGroups: []string{"db"}},
		},
	}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	out, err := Parse(b)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !reflect.DeepEqual(in, out) {
		t.Fatalf("round-trip mismatch:\n in=%+v\nout=%+v", in, out)
	}
}

func TestValidate(t *testing.T) {
	if err := Validate(Config{}); !errors.Is(err, ErrEmpty) {
		t.Fatalf("empty config: want ErrEmpty, got %v", err)
	}

	// missing realm
	if err := Validate(Config{IDPEntries: []IDPEntry{{DirectoryGroup: "x", MeshGroups: []string{"a"}}}}); !errors.Is(err, ErrNoRealm) {
		t.Fatalf("missing realm: want ErrNoRealm, got %v", err)
	}
	// missing directory_group
	if err := Validate(Config{IDPEntries: []IDPEntry{{Realm: "corp", MeshGroups: []string{"a"}}}}); !errors.Is(err, ErrNoGroup) {
		t.Fatalf("missing group: want ErrNoGroup, got %v", err)
	}

	// duplicate (realm, directory_group) -> rejected (S3)
	dup := Config{IDPEntries: []IDPEntry{
		{Realm: "corp", DirectoryGroup: "eng", MeshGroups: []string{"a"}},
		{Realm: "corp", DirectoryGroup: "eng", MeshGroups: []string{"b"}},
	}}
	if err := Validate(dup); !errors.Is(err, ErrDuplicateGroup) {
		t.Fatalf("dup group: want ErrDuplicateGroup, got %v", err)
	}

	// same group, DIFFERENT realm -> allowed (uniqueness is per (realm, group))
	ok := Config{IDPEntries: []IDPEntry{
		{Realm: "corp", DirectoryGroup: "eng", MeshGroups: []string{"a"}},
		{Realm: "partner", DirectoryGroup: "eng", MeshGroups: []string{"b"}},
	}}
	if err := Validate(ok); err != nil {
		t.Fatalf("same group different realm should be allowed, got %v", err)
	}

	// grants-nothing: no mesh_groups and no default_groups -> rejected
	nothing := Config{IDPEntries: []IDPEntry{{Realm: "corp", DirectoryGroup: "eng"}}}
	if err := Validate(nothing); !errors.Is(err, ErrGrantsNothing) {
		t.Fatalf("grants-nothing: want ErrGrantsNothing, got %v", err)
	}
	// same entry is fine once a default group exists
	withDefault := Config{DefaultGroups: []string{"fleet"}, IDPEntries: []IDPEntry{{Realm: "corp", DirectoryGroup: "eng"}}}
	if err := Validate(withDefault); err != nil {
		t.Fatalf("default_groups should satisfy grants-something, got %v", err)
	}
}

// TestValidateRejectsAutoIssuePrivileged is the FIX B / S8 acceptance: an auto_issue
// entry that would grant a reserved/privileged group (control-plane / lighthouse, sourced
// from internal/policy) is rejected, whether the group rides in via the entry's mesh_groups
// or the fleet-wide default_groups; the SAME grant with auto_issue=false is allowed (an
// admin approves it manually); and a normal auto_issue entry is unaffected.
func TestValidateRejectsAutoIssuePrivileged(t *testing.T) {
	// (1) auto_issue + a reserved group in mesh_groups -> rejected.
	viaMesh := Config{IDPEntries: []IDPEntry{
		{Realm: "corp", DirectoryGroup: "admins", MeshGroups: []string{"ops", policy.GroupControlPlane}, AutoIssue: true},
	}}
	if err := Validate(viaMesh); !errors.Is(err, ErrAutoIssuePrivileged) {
		t.Fatalf("auto_issue + reserved mesh group: want ErrAutoIssuePrivileged, got %v", err)
	}

	// (1b) auto_issue + a reserved group merged in via default_groups -> rejected too
	// (the granted set is mesh_groups ∪ default_groups).
	viaDefault := Config{
		DefaultGroups: []string{policy.GroupLighthouse},
		IDPEntries:    []IDPEntry{{Realm: "corp", DirectoryGroup: "engineers", MeshGroups: []string{"eng"}, AutoIssue: true}},
	}
	if err := Validate(viaDefault); !errors.Is(err, ErrAutoIssuePrivileged) {
		t.Fatalf("auto_issue + reserved default group: want ErrAutoIssuePrivileged, got %v", err)
	}

	// (2) the SAME grant with auto_issue=false -> allowed (privileged via manual approval).
	manual := Config{IDPEntries: []IDPEntry{
		{Realm: "corp", DirectoryGroup: "admins", MeshGroups: []string{"ops", policy.GroupControlPlane}, AutoIssue: false},
	}}
	if err := Validate(manual); err != nil {
		t.Fatalf("auto_issue=false granting a reserved group should be allowed (manual approval), got %v", err)
	}

	// (3) a normal entry with auto_issue=true (no reserved group) -> allowed.
	normal := Config{IDPEntries: []IDPEntry{
		{Realm: "corp", DirectoryGroup: "engineers", MeshGroups: []string{"eng"}, AutoIssue: true},
	}}
	if err := Validate(normal); err != nil {
		t.Fatalf("normal auto_issue entry should be allowed, got %v", err)
	}
}

func TestMatchFirstWins(t *testing.T) {
	cfg := Config{
		DefaultGroups: []string{"fleet"},
		IDPEntries: []IDPEntry{
			{Realm: "corp", DirectoryGroup: "eng-web", MeshGroups: []string{"web"}, AutoIssue: true, Netblock: "sso-prod"},
			{Realm: "corp", DirectoryGroup: "eng-db", MeshGroups: []string{"db"}, Netblock: "sso-db"},
		},
	}

	// user in BOTH groups -> first matching entry wins for groups+netblock+autoIssue (S4)
	groups, netblock, auto, ok := Match(cfg, "corp", []string{"eng-db", "eng-web"})
	if !ok || !auto {
		t.Fatalf("both-groups match: ok=%v auto=%v", ok, auto)
	}
	if !reflect.DeepEqual(groups, []string{"fleet", "web"}) {
		t.Fatalf("first-match groups (DefaultGroups merged): %v", groups)
	}
	if netblock != "sso-prod" {
		t.Fatalf("first-match netblock: want sso-prod, got %q", netblock)
	}

	// user only in the second group -> second entry, no auto-issue
	groups, netblock, auto, ok = Match(cfg, "corp", []string{"eng-db"})
	if !ok || auto {
		t.Fatalf("db-only match: ok=%v auto=%v", ok, auto)
	}
	if !reflect.DeepEqual(groups, []string{"db", "fleet"}) {
		t.Fatalf("db groups: %v", groups)
	}
	if netblock != "sso-db" {
		t.Fatalf("db netblock: want sso-db, got %q", netblock)
	}
}

func TestMatchRealm(t *testing.T) {
	// Build via Parse so the config is one Validate would actually accept — an
	// empty-realm entry is rejected (ErrNoRealm), so realm matching is EXACT: an entry
	// only matches its own realm, never any other. Same group name in two realms.
	cfg, err := Parse([]byte(`{
		"idp_entries":[
			{"realm":"corp","directory_group":"eng","mesh_groups":["corp-eng"]},
			{"realm":"partner","directory_group":"eng","mesh_groups":["partner-eng"]}
		]
	}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	// realm "corp" -> only the corp entry
	groups, _, _, ok := Match(cfg, "corp", []string{"eng"})
	if !ok || !reflect.DeepEqual(groups, []string{"corp-eng"}) {
		t.Fatalf("corp realm: ok=%v groups=%v", ok, groups)
	}

	// realm "partner" -> only the partner entry (no wildcard fall-through)
	groups, _, _, ok = Match(cfg, "partner", []string{"eng"})
	if !ok || !reflect.DeepEqual(groups, []string{"partner-eng"}) {
		t.Fatalf("partner realm: ok=%v groups=%v", ok, groups)
	}

	// a realm matching NO entry -> no match (fail closed), even though the group exists
	if _, _, _, ok := Match(cfg, "stranger", []string{"eng"}); ok {
		t.Fatal("unknown realm should not match any entry")
	}

	// wrong realm against a single realm-specific entry -> no match
	specific := Config{IDPEntries: []IDPEntry{{Realm: "corp", DirectoryGroup: "eng", MeshGroups: []string{"x"}}}}
	if _, _, _, ok := Match(specific, "partner", []string{"eng"}); ok {
		t.Fatal("wrong realm should not match a realm-specific entry")
	}
}

func TestMatchNoMatch(t *testing.T) {
	cfg := Config{IDPEntries: []IDPEntry{{Realm: "corp", DirectoryGroup: "eng", MeshGroups: []string{"x"}}}}
	groups, netblock, auto, ok := Match(cfg, "corp", []string{"sales"})
	if ok || groups != nil || netblock != "" || auto {
		t.Fatalf("no-group match should DENY: groups=%v netblock=%q auto=%v ok=%v", groups, netblock, auto, ok)
	}
}

// TestContainsPrivileged: the ADR-0011 P1.2 usertrust predicate flags auto_issue OR a
// reserved-group grant; a plain config is false. (The auto_issue+reserved COMBO is
// refused earlier by Validate; this predicate covers the still-valid privileged cases.)
func TestContainsPrivileged(t *testing.T) {
	plain := Config{IDPEntries: []IDPEntry{{Realm: "corp", DirectoryGroup: "eng", MeshGroups: []string{"eng"}}}}
	if ContainsPrivileged(plain) {
		t.Fatal("plain config must not be privileged")
	}
	auto := Config{IDPEntries: []IDPEntry{{Realm: "corp", DirectoryGroup: "eng", MeshGroups: []string{"eng"}, AutoIssue: true}}}
	if !ContainsPrivileged(auto) {
		t.Fatal("auto_issue must be privileged")
	}
	// A non-auto entry granting a reserved group (an admin approves it) is privileged.
	reserved := Config{IDPEntries: []IDPEntry{{Realm: "corp", DirectoryGroup: "admins", MeshGroups: []string{"control-plane"}}}}
	if !ContainsPrivileged(reserved) {
		t.Fatal("reserved mesh group must be privileged")
	}
	reservedDefault := Config{DefaultGroups: []string{"lighthouse"}, IDPEntries: []IDPEntry{{Realm: "corp", DirectoryGroup: "eng", MeshGroups: []string{"eng"}}}}
	if !ContainsPrivileged(reservedDefault) {
		t.Fatal("reserved default group must be privileged")
	}
}
