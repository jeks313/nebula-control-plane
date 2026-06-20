package cloudtrust

import (
	"errors"
	"reflect"
	"testing"

	"github.com/jeks313/nebula-control-plane/internal/awsattest"
)

func TestParseValid(t *testing.T) {
	c, err := Parse([]byte(`{
		"default_groups":["fleet"],
		"aws":[
			{"account":"111122223333","arn_patterns":["arn:aws:sts::111122223333:assumed-role/web/*"],"groups":["web"],"auto_issue":true,"netblock":"aws-prod"},
			{"account":"444455556666","groups":["db"]}
		]
	}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(c.AWS) != 2 || c.AWS[0].Account != "111122223333" || !c.AWS[0].AutoIssue {
		t.Fatalf("unexpected parse: %+v", c)
	}
	// netblock round-trips through Parse (DisallowUnknownFields must accept it) and is
	// empty (-> default) when omitted.
	if c.AWS[0].Netblock != "aws-prod" {
		t.Fatalf("netblock not parsed: %+v", c.AWS[0])
	}
	if c.AWS[1].Netblock != "" {
		t.Fatalf("omitted netblock should be empty: %+v", c.AWS[1])
	}
	if len(c.DefaultGroups) != 1 || c.DefaultGroups[0] != "fleet" {
		t.Fatalf("default groups: %+v", c.DefaultGroups)
	}
}

func TestParseRejectsUnknownFields(t *testing.T) {
	if _, err := Parse([]byte(`{"aws":[{"account":"1","oops":true}]}`)); err == nil {
		t.Fatal("expected unknown-field rejection")
	}
}

func TestValidate(t *testing.T) {
	if err := Validate(Config{}); !errors.Is(err, ErrEmpty) {
		t.Fatalf("empty config: want ErrEmpty, got %v", err)
	}
	if err := Validate(Config{AWS: []AWSAccount{{Account: ""}}}); !errors.Is(err, ErrNoAccount) {
		t.Fatalf("missing id: want ErrNoAccount, got %v", err)
	}
	dup := Config{AWS: []AWSAccount{{Account: "1"}, {Account: "1"}}}
	if err := Validate(dup); !errors.Is(err, ErrDupAccount) {
		t.Fatalf("dup: want ErrDupAccount, got %v", err)
	}
	if err := Validate(Config{AWS: []AWSAccount{{Account: "1"}}}); err != nil {
		t.Fatalf("valid: %v", err)
	}
}

func TestMatchAWS(t *testing.T) {
	c := Config{
		DefaultGroups: []string{"fleet"},
		AWS: []AWSAccount{
			{Account: "111122223333", ARNPatterns: []string{"arn:aws:sts::111122223333:assumed-role/web/*"}, Groups: []string{"web"}, AutoIssue: true, Netblock: "aws-prod"},
			{Account: "444455556666", Groups: []string{"db"}}, // no patterns = any ARN in the account; no netblock = default
		},
	}

	// account + arn match -> default ∪ principal groups (deduped+sorted), auto-issue, bound netblock
	groups, netblock, auto, ok := c.MatchAWS(awsattest.Identity{Account: "111122223333", Arn: "arn:aws:sts::111122223333:assumed-role/web/i-abc"})
	if !ok || !auto {
		t.Fatalf("web match: ok=%v auto=%v", ok, auto)
	}
	if !reflect.DeepEqual(groups, []string{"fleet", "web"}) {
		t.Fatalf("resolved groups: %v", groups)
	}
	if netblock != "aws-prod" {
		t.Fatalf("netblock: want %q, got %q", "aws-prod", netblock)
	}
	// right account, wrong ARN -> no match (fail closed)
	if _, _, _, ok := c.MatchAWS(awsattest.Identity{Account: "111122223333", Arn: "arn:aws:sts::111122223333:assumed-role/admin/i-xyz"}); ok {
		t.Fatal("wrong arn should not match")
	}
	// account with no patterns matches any ARN in it, manual approval (auto=false), no netblock -> default ("")
	groups, netblock, auto, ok = c.MatchAWS(awsattest.Identity{Account: "444455556666", Arn: "arn:aws:sts::444455556666:assumed-role/anything/x"})
	if !ok || auto {
		t.Fatalf("any-arn match: ok=%v auto=%v", ok, auto)
	}
	if !reflect.DeepEqual(groups, []string{"db", "fleet"}) {
		t.Fatalf("resolved groups: %v", groups)
	}
	if netblock != "" {
		t.Fatalf("unbound scope netblock: want %q (default), got %q", "", netblock)
	}
	// untrusted account -> no match, empty netblock
	if _, nb, _, ok := c.MatchAWS(awsattest.Identity{Account: "999988887777", Arn: "arn:aws:sts::999988887777:assumed-role/web/x"}); ok || nb != "" {
		t.Fatalf("untrusted account should not match: ok=%v netblock=%q", ok, nb)
	}
}

// TestContainsPrivileged: the ADR-0011 P1.2 cloudtrust predicate flags auto_issue OR a
// reserved-group grant (per-account groups OR default_groups); a plain config is false.
func TestContainsPrivileged(t *testing.T) {
	plain := Config{AWS: []AWSAccount{{Account: "111", Groups: []string{"web"}}}}
	if ContainsPrivileged(plain) {
		t.Fatal("plain config must not be privileged")
	}
	auto := Config{AWS: []AWSAccount{{Account: "111", Groups: []string{"web"}, AutoIssue: true}}}
	if !ContainsPrivileged(auto) {
		t.Fatal("auto_issue must be privileged")
	}
	reservedPerAccount := Config{AWS: []AWSAccount{{Account: "111", Groups: []string{"control-plane"}}}}
	if !ContainsPrivileged(reservedPerAccount) {
		t.Fatal("per-account reserved group must be privileged")
	}
	reservedDefault := Config{DefaultGroups: []string{"lighthouse"}, AWS: []AWSAccount{{Account: "111", Groups: []string{"web"}}}}
	if !ContainsPrivileged(reservedDefault) {
		t.Fatal("default reserved group must be privileged")
	}
}
