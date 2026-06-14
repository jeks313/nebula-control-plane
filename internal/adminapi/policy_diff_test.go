package adminapi_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// hasFlowDelta reports whether the diff array (added|removed) contains from->to proto/port.
func hasFlowDelta(arr any, from, to, proto, port string) bool {
	list, _ := arr.([]any)
	for _, e := range list {
		m, _ := e.(map[string]any)
		flow, _ := m["flow"].(map[string]any)
		if m["from"] == from && m["to"] == to && flow["proto"] == proto && flow["port"] == port {
			return true
		}
	}
	return false
}

// setActivePolicy commits a policy via the real dual-control path (propose + a
// distinct approver), so /policy/diff has a real active baseline.
func setActivePolicy(t *testing.T, ts *httptest.Server, dsl string) {
	t.Helper()
	code, ch := req(t, ts, "POST", "/admin/v1/policy/propose", "alice", map[string]any{"policy": dsl})
	if code != http.StatusCreated {
		t.Fatalf("propose status = %d (%v)", code, ch)
	}
	id := int64(ch["id"].(float64))
	if code, out := req(t, ts, "POST", fmt.Sprintf("/admin/v1/approvals/%d/approve", id), "bob", nil); code != http.StatusOK || out["state"] != "committed" {
		t.Fatalf("approve status=%d state=%v", code, out["state"])
	}
}

// TestPolicyDiffOverHTTP: flow-diff against an active policy + blast radius over the
// real issued fleet.
func TestPolicyDiffOverHTTP(t *testing.T) {
	s, h := newServer(t)
	ts := httptest.NewServer(h)
	defer ts.Close()

	// Issued fleet: 2 web hosts, 1 db host, 1 unrelated host.
	issued(t, s, "e-web1", "10.0.0.1", 0, "aws", "111", "arn", "r", []string{"web"})
	issued(t, s, "e-web2", "10.0.0.2", 0, "aws", "111", "arn", "r", []string{"web"})
	issued(t, s, "e-db1", "10.0.0.3", 0, "aws", "222", "arn", "r", []string{"db"})
	issued(t, s, "e-other", "10.0.0.4", 0, "aws", "333", "arn", "r", []string{"other"})

	setActivePolicy(t, ts, "allow web -> db tcp 5432\n")

	doc := loadSpec(t)
	code, out := req(t, ts, "POST", "/admin/v1/policy/diff", "alice",
		map[string]any{"policy": "allow web -> db tcp 443\n"})
	if code != http.StatusOK {
		t.Fatalf("diff status = %d (%v)", code, out)
	}
	conform(t, doc, "POST", "/admin/v1/policy/diff", 200, out)
	if active, _ := out["active"].(map[string]any); active["published"] != true {
		t.Fatalf("active = %v, want published", out["active"])
	}
	if !hasFlowDelta(out["removed"], "web", "db", "tcp", "5432") {
		t.Errorf("expected web->db tcp/5432 removed, got %v", out["removed"])
	}
	if !hasFlowDelta(out["added"], "web", "db", "tcp", "443") {
		t.Errorf("expected web->db tcp/443 added, got %v", out["added"])
	}
	// Blast = web hosts (outbound) ∪ db hosts (inbound) = 3 of 4 issued.
	blast := out["blast"].(map[string]any)
	if int(blast["count"].(float64)) != 3 || int(blast["total"].(float64)) != 4 {
		t.Fatalf("blast = %v, want count 3 total 4", blast)
	}
}

// TestPolicyDiffNoActivePolicy: with nothing committed, every draft flow is "added"
// and the active side reports published:false (not a 500).
func TestPolicyDiffNoActivePolicy(t *testing.T) {
	s, h := newServer(t)
	ts := httptest.NewServer(h)
	defer ts.Close()
	issued(t, s, "e-web1", "10.0.0.1", 0, "aws", "111", "arn", "r", []string{"web"})
	issued(t, s, "e-db1", "10.0.0.3", 0, "aws", "222", "arn", "r", []string{"db"})

	code, out := req(t, ts, "POST", "/admin/v1/policy/diff", "alice",
		map[string]any{"policy": "allow web -> db tcp 443\n"})
	if code != http.StatusOK {
		t.Fatalf("diff status = %d (%v)", code, out)
	}
	if active, _ := out["active"].(map[string]any); active["published"] != false {
		t.Fatalf("active = %v, want published:false", out["active"])
	}
	if !hasFlowDelta(out["added"], "web", "db", "tcp", "443") {
		t.Errorf("expected web->db tcp/443 added, got %v", out["added"])
	}
	if rem, _ := out["removed"].([]any); len(rem) != 0 {
		t.Errorf("nothing should be removed against an empty active, got %v", rem)
	}
	if blast := out["blast"].(map[string]any); int(blast["count"].(float64)) != 2 {
		t.Errorf("blast count = %v, want 2", blast["count"])
	}
}

// TestPolicyDiffAnyFanout: an any-source draft rule's blast is the whole fleet.
func TestPolicyDiffAnyFanout(t *testing.T) {
	s, h := newServer(t)
	ts := httptest.NewServer(h)
	defer ts.Close()
	issued(t, s, "e1", "10.0.0.1", 0, "aws", "1", "arn", "r", []string{"web"})
	issued(t, s, "e2", "10.0.0.2", 0, "aws", "1", "arn", "r", []string{"db"})
	issued(t, s, "e3", "10.0.0.3", 0, "aws", "1", "arn", "r", []string{"other"})

	code, out := req(t, ts, "POST", "/admin/v1/policy/diff", "alice",
		map[string]any{"policy": "allow any -> web tcp 80\n"})
	if code != http.StatusOK {
		t.Fatalf("diff status = %d (%v)", code, out)
	}
	if !hasFlowDelta(out["added"], "any", "web", "tcp", "80") {
		t.Errorf("expected any->web added, got %v", out["added"])
	}
	if blast := out["blast"].(map[string]any); int(blast["count"].(float64)) != 3 {
		t.Errorf("any-source blast count = %v, want 3 (whole fleet)", blast["count"])
	}
}

func TestPolicyDiffBadDraft(t *testing.T) {
	_, h := newServer(t)
	ts := httptest.NewServer(h)
	defer ts.Close()
	if code, _ := req(t, ts, "POST", "/admin/v1/policy/diff", "alice",
		map[string]any{"policy": "this is not valid dsl\n"}); code != http.StatusBadRequest {
		t.Fatalf("bad draft status = %d, want 400", code)
	}
}

// TestPolicyDiffFleetGroupMap exercises fleetGroupMap through blast radius: a
// reserved-group (lighthouse) host counts in the fleet total / any-fanout but is not a
// usable user group, and a re-enrolled host is counted only under its LATEST groups.
func TestPolicyDiffFleetGroupMap(t *testing.T) {
	s, h := newServer(t)
	ts := httptest.NewServer(h)
	defer ts.Close()
	issued(t, s, "lh", "10.0.0.1", 0, "aws", "1", "arn", "r", []string{"lighthouse"}) // reserved-only
	issued(t, s, "w", "10.0.0.2", 0, "aws", "1", "arn", "r", []string{"web"})
	issued(t, s, "re-old", "10.0.0.3", 0, "aws", "1", "arn", "r", []string{"web"})
	issued(t, s, "re-new", "10.0.0.3", 0, "aws", "1", "arn", "r", []string{"db"}) // re-enrolled out of web

	// web->servers: only the genuine web host (.2); .1 is lighthouse-only, .3 moved to db.
	_, out := req(t, ts, "POST", "/admin/v1/policy/diff", "alice", map[string]any{"policy": "allow web -> servers tcp 22\n"})
	if b := out["blast"].(map[string]any); int(b["count"].(float64)) != 1 || int(b["total"].(float64)) != 3 {
		t.Fatalf("web->servers blast = %v, want count 1 total 3", b)
	}
	// any->web fans out to the whole fleet, INCLUDING the reserved-group-only host.
	_, anyOut := req(t, ts, "POST", "/admin/v1/policy/diff", "alice", map[string]any{"policy": "allow any -> web tcp 22\n"})
	if b := anyOut["blast"].(map[string]any); int(b["count"].(float64)) != 3 {
		t.Fatalf("any->web blast = %v, want count 3 (incl reserved-group host)", b)
	}
}

// TestPolicyDiffBlastTruncation: the host list caps at 200 while count stays accurate.
func TestPolicyDiffBlastTruncation(t *testing.T) {
	s, h := newServer(t)
	ts := httptest.NewServer(h)
	defer ts.Close()
	for i := 0; i < 201; i++ {
		issued(t, s, fmt.Sprintf("e%03d", i), fmt.Sprintf("10.1.%d.%d", i/250, i%250), 0, "aws", "1", "arn", "r", []string{"web"})
	}
	_, out := req(t, ts, "POST", "/admin/v1/policy/diff", "alice", map[string]any{"policy": "allow web -> web tcp 22\n"})
	b := out["blast"].(map[string]any)
	if int(b["count"].(float64)) != 201 {
		t.Fatalf("blast count = %v, want 201", b["count"])
	}
	if hosts, _ := b["hosts"].([]any); len(hosts) != 200 {
		t.Fatalf("returned hosts = %d, want 200 (capped)", len(hosts))
	}
	if b["truncated"] != true {
		t.Fatalf("truncated = %v, want true", b["truncated"])
	}
}

// TestPolicyDiffReservedGroupWarning: a draft that violates a publish invariant can be
// previewed but is flagged with a warning (it can never commit).
func TestPolicyDiffReservedGroupWarning(t *testing.T) {
	_, h := newServer(t)
	ts := httptest.NewServer(h)
	defer ts.Close()
	_, out := req(t, ts, "POST", "/admin/v1/policy/diff", "alice", map[string]any{"policy": "allow web -> control-plane tcp 443\n"})
	if w, _ := out["warning"].(string); w == "" {
		t.Fatalf("expected a warning for a reserved-group draft, got %v", out)
	}
}
