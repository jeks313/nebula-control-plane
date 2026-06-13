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
			{"account":"111122223333","arn_patterns":["arn:aws:sts::111122223333:assumed-role/web/*"],"groups":["web"],"auto_issue":true},
			{"account":"444455556666","groups":["db"]}
		]
	}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(c.AWS) != 2 || c.AWS[0].Account != "111122223333" || !c.AWS[0].AutoIssue {
		t.Fatalf("unexpected parse: %+v", c)
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
			{Account: "111122223333", ARNPatterns: []string{"arn:aws:sts::111122223333:assumed-role/web/*"}, Groups: []string{"web"}, AutoIssue: true},
			{Account: "444455556666", Groups: []string{"db"}}, // no patterns = any ARN in the account
		},
	}

	// account + arn match -> default ∪ principal groups (deduped+sorted), auto-issue
	groups, auto, ok := c.MatchAWS(awsattest.Identity{Account: "111122223333", Arn: "arn:aws:sts::111122223333:assumed-role/web/i-abc"})
	if !ok || !auto {
		t.Fatalf("web match: ok=%v auto=%v", ok, auto)
	}
	if !reflect.DeepEqual(groups, []string{"fleet", "web"}) {
		t.Fatalf("resolved groups: %v", groups)
	}
	// right account, wrong ARN -> no match (fail closed)
	if _, _, ok := c.MatchAWS(awsattest.Identity{Account: "111122223333", Arn: "arn:aws:sts::111122223333:assumed-role/admin/i-xyz"}); ok {
		t.Fatal("wrong arn should not match")
	}
	// account with no patterns matches any ARN in it, manual approval (auto=false)
	groups, auto, ok = c.MatchAWS(awsattest.Identity{Account: "444455556666", Arn: "arn:aws:sts::444455556666:assumed-role/anything/x"})
	if !ok || auto {
		t.Fatalf("any-arn match: ok=%v auto=%v", ok, auto)
	}
	if !reflect.DeepEqual(groups, []string{"db", "fleet"}) {
		t.Fatalf("resolved groups: %v", groups)
	}
	// untrusted account -> no match
	if _, _, ok := c.MatchAWS(awsattest.Identity{Account: "999988887777", Arn: "arn:aws:sts::999988887777:assumed-role/web/x"}); ok {
		t.Fatal("untrusted account should not match")
	}
}
