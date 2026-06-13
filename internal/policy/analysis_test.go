package policy

import (
	"reflect"
	"testing"
)

func mustParse(t *testing.T, text string) Policy {
	t.Helper()
	p, err := Parse(text)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return p
}

func TestReachable(t *testing.T) {
	p := mustParse(t, "allow group:laptops -> group:db tcp 5432\nallow web -> db tcp 443-444\nallow any -> web tcp 443\n")

	cases := []struct {
		from, to, proto, port string
		want                  bool
		reason                string
	}{
		{"laptops", "db", "tcp", "5432", true, "rule"},          // exact rule
		{"laptops", "db", "tcp", "5433", false, "default-deny"}, // no rule for 5433
		{"laptops", "db", "udp", "5432", false, "default-deny"}, // wrong proto
		{"web", "db", "tcp", "443", true, "rule"},               // port range 443-444
		{"web", "db", "tcp", "444", true, "rule"},               // range upper bound
		{"web", "db", "tcp", "445", false, "default-deny"},      // outside range
		{"anyone", "web", "tcp", "443", true, "rule"},           // any-source rule
		{"laptops", "web", "tcp", "443", true, "rule"},          // any-source matches a concrete from
		{"laptops", "db", "icmp", "any", true, "baseline-icmp"}, // ICMP baseline
		{"laptops", "control-plane", "tcp", "443", true, "baseline-control-plane"},
		{"laptops", "db", "any", "any", true, "rule"},           // wildcard query, a rule exists for the pair
		{"db", "laptops", "tcp", "5432", false, "default-deny"}, // direction matters
	}
	for _, c := range cases {
		d := Reachable(p, c.from, c.to, c.proto, c.port)
		if d.Allowed != c.want || d.Reason != c.reason {
			t.Errorf("Reachable(%s->%s %s/%s) = {allowed:%v reason:%s}, want {allowed:%v reason:%s}",
				c.from, c.to, c.proto, c.port, d.Allowed, d.Reason, c.want, c.reason)
		}
	}
}

// TestReachableWildcardDimensions guards the fix for the wildcard short-circuit bug: a
// wildcard query dimension must waive ONLY its own constraint, never the other concrete
// one (else the analysis reports ALLOWED where CompileHost enforces DENY — a false-safe).
func TestReachableWildcardDimensions(t *testing.T) {
	p := mustParse(t, "allow web -> db tcp 5432\nallow svc -> db udp 53\n")
	cases := []struct {
		from, to, proto, port string
		want                  bool
	}{
		{"web", "db", "udp", "any", false}, // udp not permitted web->db (was a false-allow)
		{"web", "db", "any", "22", false},  // port 22 not permitted (was a false-allow)
		{"web", "db", "any", "5432", true}, // any proto, port 5432 -> the tcp rule
		{"web", "db", "tcp", "any", true},  // any tcp port -> the tcp/5432 rule
		{"svc", "db", "tcp", "any", false}, // svc only has udp
		{"svc", "db", "udp", "53", true},
		{"svc", "db", "any", "53", true},
		{"web", "db", "any", "any", true},      // anything reachable (a rule exists)
		{"isolated", "db", "any", "any", true}, // no rule, but the ICMP baseline grants something
		{"isolated", "db", "tcp", "443", false},
	}
	for _, c := range cases {
		d := Reachable(p, c.from, c.to, c.proto, c.port)
		if d.Allowed != c.want {
			t.Errorf("Reachable(%s->%s %s/%s) allowed=%v reason=%s, want allowed=%v",
				c.from, c.to, c.proto, c.port, d.Allowed, d.Reason, c.want)
		}
	}
}

// TestReachableControlPlaneSender: the control-plane outbound baseline is for NON-control-
// plane senders only (a control-plane host has no general outbound — CompileHost), so
// control-plane -> control-plane on tcp/udp is default-deny, not a false baseline allow.
func TestReachableControlPlaneSender(t *testing.T) {
	p := mustParse(t, "")
	if d := Reachable(p, "web", "control-plane", "tcp", "443"); !d.Allowed || d.Reason != "baseline-control-plane" {
		t.Fatalf("web -> control-plane should be baseline-allowed, got %+v", d)
	}
	if d := Reachable(p, "control-plane", "control-plane", "tcp", "443"); d.Allowed {
		t.Fatalf("control-plane -> control-plane tcp should be denied (no general cp outbound), got %+v", d)
	}
	if d := Reachable(p, "control-plane", "control-plane", "icmp", "any"); !d.Allowed {
		t.Fatal("icmp is always baseline-allowed")
	}
}

func TestReachableNearestMiss(t *testing.T) {
	p := mustParse(t, "allow web -> db tcp 443\n")
	d := Reachable(p, "web", "db", "tcp", "5432")
	if d.Allowed || d.Nearest == nil {
		t.Fatalf("want deny with a nearest miss, got %+v", d)
	}
	if d.Nearest.Port != "443" {
		t.Fatalf("nearest miss = %+v, want the web->db tcp 443 rule", d.Nearest)
	}
}

func TestMatrix(t *testing.T) {
	p := mustParse(t, "allow laptops -> web tcp 443\nallow web -> db tcp 5432\n")
	m := Matrix(p, nil)
	if !reflect.DeepEqual(m.Groups, []string{"db", "laptops", "web"}) {
		t.Fatalf("groups = %v", m.Groups)
	}
	find := func(from, to string) MatrixCell {
		for _, c := range m.Cells {
			if c.From == from && c.To == to {
				return c
			}
		}
		t.Fatalf("no cell %s->%s", from, to)
		return MatrixCell{}
	}
	if f := find("laptops", "web").Flows; len(f) != 1 || f[0] != (Flow{"tcp", "443"}) {
		t.Fatalf("laptops->web flows = %v", f)
	}
	if f := find("laptops", "db").Flows; len(f) != 0 {
		t.Fatalf("laptops->db should have no policy flow, got %v", f)
	}
	if len(m.Cells) != 9 { // 3x3
		t.Fatalf("cells = %d, want 9", len(m.Cells))
	}
}

func TestMatrixAnySourceFansOut(t *testing.T) {
	// an any-source rule should appear in every group's row toward the target
	p := mustParse(t, "allow any -> web tcp 443\nallow laptops -> db tcp 5432\n")
	m := Matrix(p, []string{"laptops", "web", "db"})
	count := 0
	for _, c := range m.Cells {
		if c.To == "web" && len(c.Flows) == 1 && c.Flows[0] == (Flow{"tcp", "443"}) {
			count++
		}
	}
	if count != 3 { // every from (laptops, web, db) -> web
		t.Fatalf("any->web should fan out to all 3 sources, got %d", count)
	}
}

func TestParseAndRunTests(t *testing.T) {
	p := mustParse(t, "allow laptops -> db tcp 5432\n")
	asserts, err := ParseTests("# tests\nassert allow group:laptops -> group:db tcp 5432\nassert deny laptops -> db tcp 22\nassert allow any -> control-plane tcp 443\n")
	if err != nil {
		t.Fatalf("parse tests: %v", err)
	}
	if len(asserts) != 3 {
		t.Fatalf("asserts = %d, want 3", len(asserts))
	}
	res := RunTests(p, asserts)
	for _, r := range res {
		if !r.Pass {
			t.Errorf("assertion at line %d failed: expect=%v got=%v reason=%s", r.Assertion.Line, r.Assertion.Expect, r.Got, r.Reason)
		}
	}
}

func TestParseTestsRejectsMalformed(t *testing.T) {
	if _, err := ParseTests("assert maybe laptops -> db tcp 5432"); err == nil {
		t.Fatal("expected rejection of bad verb")
	}
	if _, err := ParseTests("assert allow laptops db tcp 5432"); err == nil {
		t.Fatal("expected rejection of missing arrow")
	}
}
