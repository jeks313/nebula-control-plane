package adminapi_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jeks313/nebula-control-plane/internal/adminapi"
	"github.com/jeks313/nebula-control-plane/internal/enrollment"
	"github.com/jeks313/nebula-control-plane/internal/store"
	"github.com/jeks313/nebula-control-plane/internal/store/migrate"
)

// enrollSrv builds a read-only (Store-only, CanIssue=false) admin server plus a
// handle to its store so tests can seed enrollment rows directly. This is the
// default admin-api posture: list + deny work; approve returns 501.
func enrollSrv(t *testing.T, role string) (*store.Store, *httptest.Server) {
	t.Helper()
	s, err := store.Open(store.Config{Driver: "sqlite", DSN: store.DefaultSQLiteDSN(t.TempDir() + "/e.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	if err := migrate.Up(s.DB); err != nil {
		t.Fatal(err)
	}
	srv := adminapi.New(adminapi.Config{Store: s, Identity: adminapi.DevHeaderProvider{Roles: []string{role}}})
	return s, httptest.NewServer(srv.Handler())
}

func seedEnrollment(t *testing.T, s *store.Store, id, name, status string) {
	t.Helper()
	e := enrollment.Enrollment{
		EnrollmentID: id, DeviceName: name, PubkeyHash: "fp-" + id,
		Pubkey: []byte("rawkeybytes-should-never-be-returned"),
		Method: "joinkey", Groups: `["servers","prod"]`, Status: status,
		CreatedAt: 1_700_000_000_000_000_000,
	}
	if err := s.DB.Create(&e).Error; err != nil {
		t.Fatal(err)
	}
}

// TestEnrollListAndDeny is the A0.5 read-only showcase: the pending queue is
// listed, a host is denied, and a second deny is rejected as not-pending.
func TestEnrollListAndDeny(t *testing.T) {
	s, ts := enrollSrv(t, "admin")
	defer ts.Close()
	seedEnrollment(t, s, "enr-1", "laptop-a", enrollment.StatusPending)
	seedEnrollment(t, s, "enr-2", "laptop-b", enrollment.StatusPending)

	// Default list shows the pending queue.
	code, body := req(t, ts, "GET", "/admin/v1/enrollments", "alice", nil)
	if code != http.StatusOK {
		t.Fatalf("list status=%d body=%v", code, body)
	}
	if n, _ := body["count"].(float64); n != 2 {
		t.Fatalf("count=%v want 2", body["count"])
	}
	rows, _ := body["enrollments"].([]any)
	if len(rows) != 2 {
		t.Fatalf("rows=%d want 2", len(rows))
	}
	// The raw pubkey bytes must never be in the view.
	first, _ := rows[0].(map[string]any)
	if _, leaked := first["pubkey"]; leaked {
		t.Fatalf("pubkey leaked into enrollment view: %v", first)
	}
	if first["pubkey_hash"] == "" || first["pubkey_hash"] == nil {
		t.Fatalf("missing pubkey_hash: %v", first)
	}

	// Deny enr-1 with a reason.
	code, body = req(t, ts, "POST", "/admin/v1/enrollments/enr-1/deny", "alice", map[string]any{"reason": "unrecognized device"})
	if code != http.StatusOK {
		t.Fatalf("deny status=%d body=%v", code, body)
	}
	if body["status"] != enrollment.StatusDenied {
		t.Fatalf("deny status=%v want denied", body["status"])
	}

	// Denying it again is a conflict — it is no longer pending.
	code, _ = req(t, ts, "POST", "/admin/v1/enrollments/enr-1/deny", "alice", nil)
	if code != http.StatusConflict {
		t.Fatalf("second deny status=%d want 409", code)
	}

	// The pending queue now has one entry; denied filter shows the other.
	_, body = req(t, ts, "GET", "/admin/v1/enrollments", "alice", nil)
	if n, _ := body["count"].(float64); n != 1 {
		t.Fatalf("pending count=%v want 1", body["count"])
	}
	_, body = req(t, ts, "GET", "/admin/v1/enrollments?status=denied", "alice", nil)
	if n, _ := body["count"].(float64); n != 1 {
		t.Fatalf("denied count=%v want 1", body["count"])
	}
}

// TestEnrollApproveNotConfigured: a read-only admin-api cannot issue, so approve
// returns 501 (not a generic 500) — the operator must restart it with the CA.
func TestEnrollApproveNotConfigured(t *testing.T) {
	s, ts := enrollSrv(t, "admin")
	defer ts.Close()
	seedEnrollment(t, s, "enr-1", "laptop-a", enrollment.StatusPending)

	code, body := req(t, ts, "POST", "/admin/v1/enrollments/enr-1/approve", "alice", nil)
	if code != http.StatusNotImplemented {
		t.Fatalf("approve status=%d want 501 body=%v", code, body)
	}
}

// TestEnrollRBAC: a viewer can list the queue but cannot deny or approve.
func TestEnrollRBAC(t *testing.T) {
	s, ts := enrollSrv(t, "viewer")
	defer ts.Close()
	seedEnrollment(t, s, "enr-1", "laptop-a", enrollment.StatusPending)

	if code, _ := req(t, ts, "GET", "/admin/v1/enrollments", "bob", nil); code != http.StatusOK {
		t.Fatalf("viewer list status=%d want 200", code)
	}
	if code, _ := req(t, ts, "POST", "/admin/v1/enrollments/enr-1/deny", "bob", nil); code != http.StatusForbidden {
		t.Fatalf("viewer deny status=%d want 403", code)
	}
	if code, _ := req(t, ts, "POST", "/admin/v1/enrollments/enr-1/approve", "bob", nil); code != http.StatusForbidden {
		t.Fatalf("viewer approve status=%d want 403", code)
	}
}

// TestEnrollUnauthenticated: no dev actor header → 401, before any handler runs.
func TestEnrollUnauthenticated(t *testing.T) {
	_, ts := enrollSrv(t, "admin")
	defer ts.Close()
	if code, _ := req(t, ts, "GET", "/admin/v1/enrollments", "", nil); code != http.StatusUnauthorized {
		t.Fatalf("unauth list status=%d want 401", code)
	}
}
