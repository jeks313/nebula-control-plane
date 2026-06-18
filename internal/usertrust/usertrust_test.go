package usertrust

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"
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
	cfg := Config{
		IDPEntries: []IDPEntry{
			{Realm: "corp", DirectoryGroup: "eng", MeshGroups: []string{"corp-eng"}},
			{Realm: "", DirectoryGroup: "eng", MeshGroups: []string{"any-eng"}}, // wildcard realm
		},
	}

	// realm "corp" -> the specific entry (it precedes the wildcard)
	groups, _, _, ok := Match(cfg, "corp", []string{"eng"})
	if !ok || !reflect.DeepEqual(groups, []string{"corp-eng"}) {
		t.Fatalf("corp realm: ok=%v groups=%v", ok, groups)
	}

	// realm "partner" -> only the wildcard entry matches
	groups, _, _, ok = Match(cfg, "partner", []string{"eng"})
	if !ok || !reflect.DeepEqual(groups, []string{"any-eng"}) {
		t.Fatalf("partner realm wildcard: ok=%v groups=%v", ok, groups)
	}

	// wrong realm + non-wildcard-only config -> no match
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
