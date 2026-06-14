package adminapi_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/enrollment"
	"github.com/jeks313/nebula-control-plane/internal/joinkey"
	"github.com/jeks313/nebula-control-plane/internal/store"
	"gorm.io/gorm"
)

var provNow = time.Unix(1_700_000_000, 0).UTC() // == newServer's fixed clock

// hbFull inserts a heartbeat with full control over the condition-bearing columns.
func hbFull(t *testing.T, db *gorm.DB, ip, name string, certNotAfter, lastSeen time.Time, clockMs int, health string) {
	t.Helper()
	sql := `INSERT INTO heartbeats (overlay_ip, device_name, pilot_version, nebula_version, cert_not_after, applied_bundle_version, clock_offset_ms, health, last_seen)
	        VALUES (?, ?, '1.4.0', '1.10.3', ?, 42, ?, ?, ?)`
	if err := db.Exec(sql, ip, name, certNotAfter.UnixNano(), clockMs, health, lastSeen.UnixNano()).Error; err != nil {
		t.Fatal(err)
	}
}

// issued inserts an issued enrollment (id auto-assigned, so later calls win the
// "latest issued" tie). joinKeyID>0 => token provenance; provider!="" => attested.
func issued(t *testing.T, s *store.Store, eid, ip string, joinKeyID int64, provider, account, principal, region string, groups []string) {
	t.Helper()
	g, _ := json.Marshal(groups)
	row := enrollment.Enrollment{
		EnrollmentID: eid, DeviceName: "dev-" + ip, PubkeyHash: eid + "-h",
		Method: "token", Groups: string(g), Status: enrollment.StatusIssued, OverlayIP: ip,
		CreatedAt: provNow.UnixNano(), DecidedAt: provNow.UnixNano(), Approver: "ops",
		JoinKeyID: joinKeyID,
	}
	if provider != "" {
		row.Method = "aws-sigv4"
		row.JoinKeyID = 0
		row.AttestProvider, row.AttestAccount = provider, account
		row.AttestPrincipal, row.AttestRegion = principal, region
		row.VerifiedAt = provNow.UnixNano()
	}
	if err := s.DB.Create(&row).Error; err != nil {
		t.Fatal(err)
	}
}

func devicesBy(t *testing.T, body map[string]any) map[string]map[string]any {
	t.Helper()
	out := map[string]map[string]any{}
	for _, d := range body["devices"].([]any) {
		m := d.(map[string]any)
		out[m["overlay_ip"].(string)] = m
	}
	return out
}

func strs(v any) []string {
	arr, _ := v.([]any)
	out := make([]string, len(arr))
	for i, e := range arr {
		out[i], _ = e.(string)
	}
	return out
}

// TestDeviceProvenance: token and attested hosts surface their provenance + issued
// groups; a host with no issued enrollment carries none.
func TestDeviceProvenance(t *testing.T) {
	s, h := newServer(t)
	_, jk, err := joinkey.Create(context.Background(), s, joinkey.Params{Name: "laptops-2026", Groups: []string{"laptops"}}, provNow)
	if err != nil {
		t.Fatal(err)
	}
	good := provNow.Add(30 * 24 * time.Hour)
	hbFull(t, s.DB, "100.64.0.1", "laptop-1", good, provNow, 0, "ok")
	hbFull(t, s.DB, "100.64.0.2", "ec2-web", good, provNow, 0, "ok")
	hbFull(t, s.DB, "100.64.0.3", "orphan", good, provNow, 0, "ok")
	issued(t, s, "e-token", "100.64.0.1", jk.ID, "", "", "", "", []string{"laptops"})
	issued(t, s, "e-aws", "100.64.0.2", 0, "aws", "111122223333", "arn:aws:sts::111122223333:assumed-role/web/i-1", "eu-central-1", []string{"fleet", "web"})

	_, body := do(t, h, "GET", "/admin/v1/devices", "alice")
	devs := devicesBy(t, body)

	tok := devs["100.64.0.1"]
	if tok["join_key_name"] != "laptops-2026" {
		t.Errorf("token host join_key_name = %v, want laptops-2026", tok["join_key_name"])
	}
	if tok["attest_provider"] != nil {
		t.Errorf("token host should have no attest_provider, got %v", tok["attest_provider"])
	}
	if g := strs(tok["groups"]); len(g) != 1 || g[0] != "laptops" {
		t.Errorf("token host groups = %v, want [laptops]", tok["groups"])
	}

	aws := devs["100.64.0.2"]
	if aws["attest_provider"] != "aws" || aws["attest_account"] != "111122223333" {
		t.Errorf("attested host provenance = provider:%v account:%v", aws["attest_provider"], aws["attest_account"])
	}
	if aws["attest_region"] != "eu-central-1" || aws["attest_principal"] == nil {
		t.Errorf("attested host missing principal/region: %v", aws)
	}
	if aws["join_key_name"] != nil {
		t.Errorf("attested host should have no join_key_name, got %v", aws["join_key_name"])
	}

	orphan := devs["100.64.0.3"]
	if orphan["join_key_name"] != nil || orphan["attest_provider"] != nil || orphan["groups"] != nil {
		t.Errorf("orphan host should carry no provenance, got %v", orphan)
	}
}

// TestDeviceScopeFilters: scope filters narrow to the matching authoritative
// enrollment; combined filters intersect; a non-matching scope returns empty.
func TestDeviceScopeFilters(t *testing.T) {
	s, h := newServer(t)
	_, jk, _ := joinkey.Create(context.Background(), s, joinkey.Params{Name: "laptops-2026", Groups: []string{"laptops"}}, provNow)
	good := provNow.Add(30 * 24 * time.Hour)
	hbFull(t, s.DB, "100.64.0.1", "laptop-1", good, provNow, 0, "ok")
	hbFull(t, s.DB, "100.64.0.2", "ec2-web", good, provNow, 0, "ok")
	hbFull(t, s.DB, "100.64.0.3", "ec2-db", good, provNow, 0, "ok")
	issued(t, s, "e1", "100.64.0.1", jk.ID, "", "", "", "", []string{"laptops"})
	issued(t, s, "e2", "100.64.0.2", 0, "aws", "111122223333", "arn:p", "r", []string{"web"})
	issued(t, s, "e3", "100.64.0.3", 0, "aws", "444455556666", "arn:p", "r", []string{"db"})

	cases := []struct {
		query string
		want  []string
	}{
		{"?provider=aws", []string{"100.64.0.2", "100.64.0.3"}},
		{"?attest_account=111122223333", []string{"100.64.0.2"}},
		{"?join_key=laptops-2026", []string{"100.64.0.1"}},
		{"?provider=aws&attest_account=444455556666", []string{"100.64.0.3"}},
		{"?provider=aws&join_key=laptops-2026", nil}, // contradictory => empty
		{"?attest_account=999999999999", nil},
	}
	for _, c := range cases {
		_, body := do(t, h, "GET", "/admin/v1/devices"+c.query, "alice")
		got := devicesBy(t, body)
		if len(got) != len(c.want) {
			t.Errorf("%s: got %d devices %v, want %v", c.query, len(got), keysOf(got), c.want)
			continue
		}
		for _, ip := range c.want {
			if _, ok := got[ip]; !ok {
				t.Errorf("%s: missing %s (got %v)", c.query, ip, keysOf(got))
			}
		}
	}
}

// TestDeviceProvenanceLatestIssued: when a host re-enrolls, the AUTHORITATIVE
// (latest issued) enrollment drives both the displayed provenance and the scope
// filter — a superseded older enrollment must not match.
func TestDeviceProvenanceLatestIssued(t *testing.T) {
	s, h := newServer(t)
	_, jk, _ := joinkey.Create(context.Background(), s, joinkey.Params{Name: "old-key", Groups: []string{"x"}}, provNow)
	good := provNow.Add(30 * 24 * time.Hour)
	hbFull(t, s.DB, "100.64.0.9", "rehomed", good, provNow, 0, "ok")
	issued(t, s, "old", "100.64.0.9", jk.ID, "", "", "", "", []string{"x"})       // older (lower id)
	issued(t, s, "new", "100.64.0.9", 0, "aws", "111122223333", "arn", "r", []string{"web"}) // newer (higher id)

	_, body := do(t, h, "GET", "/admin/v1/devices", "alice")
	d := devicesBy(t, body)["100.64.0.9"]
	if d["attest_provider"] != "aws" || d["join_key_name"] != nil {
		t.Fatalf("expected latest (attested) provenance, got %v", d)
	}
	// Old join-key scope must NOT match (superseded); the new provider scope must.
	_, byKey := do(t, h, "GET", "/admin/v1/devices?join_key=old-key", "alice")
	if n := len(devicesBy(t, byKey)); n != 0 {
		t.Errorf("superseded join_key filter matched %d, want 0", n)
	}
	_, byProv := do(t, h, "GET", "/admin/v1/devices?provider=aws", "alice")
	if _, ok := devicesBy(t, byProv)["100.64.0.9"]; !ok {
		t.Errorf("latest provider filter should match the re-enrolled host")
	}
}

// TestDeviceConditionMatchesFleetHealth is the anti-drift guarantee: for every
// condition token, the count of /devices?condition=X equals the matching
// /fleet/health total (both computed from the same thresholds + clock).
func TestDeviceConditionMatchesFleetHealth(t *testing.T) {
	s, h := newServer(t)
	expiredCert := provNow.Add(-1 * time.Hour)
	expiringCert := provNow.Add(3 * 24 * time.Hour)
	goodCert := provNow.Add(30 * 24 * time.Hour)
	staleSeen := provNow.Add(-22 * time.Minute)

	hbFull(t, s.DB, "100.64.0.1", "expired", expiredCert, provNow, 0, "ok")
	hbFull(t, s.DB, "100.64.0.2", "expiring", expiringCert, provNow, 0, "ok")
	hbFull(t, s.DB, "100.64.0.3", "stale", goodCert, staleSeen, 0, "ok")
	hbFull(t, s.DB, "100.64.0.4", "skewed", goodCert, provNow, 8000, "ok")
	hbFull(t, s.DB, "100.64.0.5", "unhealthy", goodCert, provNow, 0, "degraded")
	hbFull(t, s.DB, "100.64.0.6", "healthy", goodCert, provNow, 0, "ok")
	hbFull(t, s.DB, "100.64.0.7", "expired+stale", expiredCert, staleSeen, 0, "ok")

	_, health := do(t, h, "GET", "/admin/v1/fleet/health", "alice")
	totals := health["totals"].(map[string]any)

	for _, cond := range []string{"expired", "expiring", "stale", "clock_skewed", "unhealthy"} {
		_, body := do(t, h, "GET", "/admin/v1/devices?condition="+cond, "alice")
		got := len(devicesBy(t, body))
		want := int(totals[cond].(float64))
		if got != want {
			t.Errorf("condition=%s: /devices count %d != /fleet/health total %d", cond, got, want)
		}
	}
	// sanity: the fixture exercises each condition (no all-zero false pass).
	for _, cond := range []string{"expired", "expiring", "stale", "clock_skewed", "unhealthy"} {
		if int(totals[cond].(float64)) == 0 {
			t.Errorf("fixture did not exercise condition %s (total 0)", cond)
		}
	}
}

func TestDeviceBadCondition(t *testing.T) {
	_, h := newServer(t)
	rr, body := do(t, h, "GET", "/admin/v1/devices?condition=bogus", "alice")
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rr.Code)
	}
	if body["title"] != "bad condition" {
		t.Errorf("problem title = %v", body["title"])
	}
}

// TestEnrollmentJoinKeyName: the enrollments queue resolves join_key_id -> name.
func TestEnrollmentJoinKeyName(t *testing.T) {
	s, h := newServer(t)
	_, jk, _ := joinkey.Create(context.Background(), s, joinkey.Params{Name: "ci-runners", Groups: []string{"ci"}}, provNow)
	g, _ := json.Marshal([]string{"ci"})
	row := enrollment.Enrollment{
		EnrollmentID: "p1", DeviceName: "runner-1", PubkeyHash: "h1", Method: "token",
		JoinKeyID: jk.ID, Groups: string(g), Status: enrollment.StatusPending, CreatedAt: provNow.UnixNano(),
	}
	if err := s.DB.Create(&row).Error; err != nil {
		t.Fatal(err)
	}
	_, body := do(t, h, "GET", "/admin/v1/enrollments?status=pending", "alice")
	es := body["enrollments"].([]any)
	if len(es) != 1 {
		t.Fatalf("enrollments = %d, want 1", len(es))
	}
	if name := es[0].(map[string]any)["join_key_name"]; name != "ci-runners" {
		t.Errorf("join_key_name = %v, want ci-runners", name)
	}
}

// walkDevices follows the next_after cursor to completion and returns every
// overlay_ip seen, plus the number of pages. Guards against an infinite loop.
func walkDevices(t *testing.T, h http.Handler, query string) ([]string, int) {
	t.Helper()
	var seen []string
	after := ""
	pages := 0
	for {
		path := "/admin/v1/devices?" + query
		if after != "" {
			path += "&after=" + after
		}
		_, body := do(t, h, "GET", path, "alice")
		pages++
		for _, d := range body["devices"].([]any) {
			seen = append(seen, d.(map[string]any)["overlay_ip"].(string))
		}
		na, ok := body["next_after"].(string)
		if !ok || na == "" {
			break
		}
		after = na
		if pages > 100 {
			t.Fatal("pagination did not terminate")
		}
	}
	return seen, pages
}

// TestDevicePaginationKeyset: walking next_after returns every device exactly once,
// in order, with no overlap and no early stop.
func TestDevicePaginationKeyset(t *testing.T) {
	s, h := newServer(t)
	good := provNow.Add(30 * 24 * time.Hour)
	want := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5"}
	for _, ip := range want {
		hbFull(t, s.DB, ip, "dev-"+ip, good, provNow, 0, "ok")
	}
	seen, pages := walkDevices(t, h, "limit=2")
	if len(seen) != len(want) {
		t.Fatalf("paged devices = %v, want %v", seen, want)
	}
	for i := range want {
		if seen[i] != want[i] {
			t.Fatalf("page order wrong at %d: got %v want %v", i, seen, want)
		}
	}
	if pages < 3 {
		t.Errorf("expected multiple pages at limit=2 over 5 devices, got %d", pages)
	}
}

// TestDevicePaginationUnderScope: the keyset-fill loop returns every scope-matching
// device across pages even when non-matching rows are interleaved (no skip, no dup).
func TestDevicePaginationUnderScope(t *testing.T) {
	s, h := newServer(t)
	_, jk, _ := joinkey.Create(context.Background(), s, joinkey.Params{Name: "k", Groups: []string{"x"}}, provNow)
	good := provNow.Add(30 * 24 * time.Hour)
	// IPs 1,3,5 attested (match provider=aws); 2,4 token (do not match).
	all := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5"}
	for _, ip := range all {
		hbFull(t, s.DB, ip, "dev-"+ip, good, provNow, 0, "ok")
	}
	for i, ip := range all {
		if i%2 == 0 { // 1,3,5
			issued(t, s, "a-"+ip, ip, 0, "aws", "111122223333", "arn", "r", []string{"web"})
		} else { // 2,4
			issued(t, s, "t-"+ip, ip, jk.ID, "", "", "", "", []string{"x"})
		}
	}
	seen, _ := walkDevices(t, h, "provider=aws&limit=2")
	want := []string{"10.0.0.1", "10.0.0.3", "10.0.0.5"}
	if len(seen) != len(want) {
		t.Fatalf("scoped paged devices = %v, want %v", seen, want)
	}
	for i := range want {
		if seen[i] != want[i] {
			t.Fatalf("scoped page order wrong: got %v want %v", seen, want)
		}
	}
}

func keysOf(m map[string]map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
