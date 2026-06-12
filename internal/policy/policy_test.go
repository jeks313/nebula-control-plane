package policy

import (
	"strings"
	"testing"

	"github.com/jeks313/nebula-control-plane/internal/nebulaconfig"
)

func TestParseAndValidate(t *testing.T) {
	p, err := Parse(`
# fleet policy
allow group:web -> group:db tcp 5432
allow any -> group:web tcp 443
`)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Rules) != 2 {
		t.Fatalf("rules = %d, want 2", len(p.Rules))
	}
	if p.Rules[0].FromGroup != "web" || p.Rules[0].ToGroup != "db" || p.Rules[0].Proto != "tcp" || p.Rules[0].Port != "5432" {
		t.Fatalf("rule0 = %+v", p.Rules[0])
	}
}

func TestParseRejectsMalformed(t *testing.T) {
	for _, bad := range []string{
		"allow web db tcp 5432",     // missing ->
		"allow web -> db tcp",       // too few fields
		"allow web -> db ftp 21",    // bad proto
		"allow web -> db tcp 70000", // bad port
		"allow web -> db tcp 0",     // bad port
	} {
		if _, err := Parse(bad); err == nil {
			t.Fatalf("expected parse error for %q", bad)
		}
	}
}

// TestDefaultDeny: a host matching no rule gets only the baseline — no peer
// access (default-deny).
func TestDefaultDeny(t *testing.T) {
	p, _ := Parse("allow group:web -> group:db tcp 5432")
	c := CompileHost(p, []string{"unrelated"})
	// No user inbound (nobody is allowed to it); outbound is only the baseline
	// (control-plane + icmp), never a user rule.
	for _, r := range c.Inbound {
		if r.Proto != "icmp" {
			t.Fatalf("unrelated host should have no non-baseline inbound, got %+v", r)
		}
	}
	if !hasGroup(c.Outbound, GroupControlPlane) {
		t.Fatal("every host must keep control-plane outbound (baseline)")
	}
}

// TestCompileWebAndDb checks the per-host compile for a sample fleet (6.2).
func TestCompileWebAndDb(t *testing.T) {
	p, _ := Parse("allow group:web -> group:db tcp 5432")

	db := CompileHost(p, []string{"db"})
	if !hasRule(db.Inbound, "tcp", "5432", "web") {
		t.Fatalf("db should allow inbound tcp/5432 from web: %+v", db.Inbound)
	}
	web := CompileHost(p, []string{"web"})
	if !hasRule(web.Outbound, "tcp", "5432", "db") {
		t.Fatalf("web should allow outbound tcp/5432 to db: %+v", web.Outbound)
	}
	// web has no inbound from this rule (only baseline icmp).
	for _, r := range web.Inbound {
		if r.Proto != "icmp" {
			t.Fatalf("web should have no non-baseline inbound: %+v", r)
		}
	}
}

// TestControlPlaneBaseline: control-plane hosts accept the mesh; members reach
// control-plane (6.3 baseline, can't be removed).
func TestControlPlaneBaseline(t *testing.T) {
	p, _ := Parse("allow group:web -> group:db tcp 5432")
	core := CompileHost(p, []string{GroupControlPlane})
	if !hasRule(core.Inbound, "any", "any", "") { // host:any
		t.Fatalf("control-plane must accept the mesh: %+v", core.Inbound)
	}
}

// TestInvariantRejectsReservedGroup is the 6.3 acceptance.
func TestInvariantRejectsReservedGroup(t *testing.T) {
	p, _ := Parse("allow group:web -> group:control-plane tcp 22")
	if err := CheckInvariants(p); err == nil {
		t.Fatal("a policy referencing control-plane must be rejected")
	}
	ok, _ := Parse("allow group:web -> group:db tcp 5432")
	if err := CheckInvariants(ok); err != nil {
		t.Fatalf("a clean policy should pass invariants: %v", err)
	}
}

func hasRule(rules []nebulaconfig.Rule, proto, port, group string) bool {
	for _, r := range rules {
		if r.Proto == proto && r.Port == port && r.Group == group && (group != "" || r.Host == "any") {
			return true
		}
	}
	return false
}

func hasGroup(rules []nebulaconfig.Rule, group string) bool {
	for _, r := range rules {
		if r.Group == group {
			return true
		}
	}
	return false
}

func TestParseRoundTripSpacing(t *testing.T) {
	if _, err := Parse(strings.Join([]string{"allow   web   ->   db   tcp   any"}, "")); err != nil {
		t.Fatalf("extra spaces should parse: %v", err)
	}
}
