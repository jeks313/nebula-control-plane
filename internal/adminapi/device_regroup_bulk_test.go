package adminapi_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"gorm.io/gorm"
)

var regroupNow = time.Unix(1_700_000_000, 0) // matches newServer's clock

func postJSON(t *testing.T, h http.Handler, path, actor, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", path, strings.NewReader(body))
	if actor != "" {
		req.Header.Set("X-Harbor-Dev-Actor", actor)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func enrollID(t *testing.T, db *gorm.DB, ip string) int64 {
	t.Helper()
	var id int64
	if err := db.Table("enrollments").Select("id").
		Where("overlay_ip = ? AND status = ?", ip, "issued").Order("id DESC").Scan(&id).Error; err != nil {
		t.Fatalf("enroll id: %v", err)
	}
	return id
}

func liveDevice(t *testing.T, db *gorm.DB, ip, name, groups string) {
	t.Helper()
	seedIssuedDevice(t, db, ip, name, groups)
	hbInsert(t, db, ip, name, regroupNow.Add(time.Hour), regroupNow, "ok")
}

// TestRegroupDryRun: a pattern + delta resolves to per-device targets, excluding reserved / stale /
// no-op hosts, and flags dual-control when the change elevates.
func TestRegroupDryRun(t *testing.T) {
	s, h := newServer(t)
	liveDevice(t, s.DB, "10.44.0.10", "db-1", `["laptops"]`)             // add prod -> elevation entry
	liveDevice(t, s.DB, "10.44.0.11", "db-2", `["laptops","prod"]`)      // already has prod -> no_op
	liveDevice(t, s.DB, "10.44.0.12", "db-cp", `["control-plane"]`)      // reserved -> skip
	seedIssuedDevice(t, s.DB, "10.44.0.13", "db-stale", `["laptops"]`)   // no heartbeat -> stale

	rr := postJSON(t, h, "/admin/v1/devices/regroup?dry_run=true", "alice", `{"name_pattern":"db-*","add":["prod"]}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("dry-run: status=%d body=%s", rr.Code, rr.Body.String())
	}
	var out struct {
		Entries []struct {
			OverlayIP string   `json:"overlay_ip"`
			Target    []string `json:"target"`
		} `json:"entries"`
		Skipped []struct {
			OverlayIP string `json:"overlay_ip"`
			Reason    string `json:"reason"`
		} `json:"skipped"`
		RequiresDualControl bool `json:"requires_dual_control"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Entries) != 1 || out.Entries[0].OverlayIP != "10.44.0.10" {
		t.Fatalf("entries=%+v, want only db-1 (10.44.0.10)", out.Entries)
	}
	if !out.RequiresDualControl {
		t.Fatalf("adding a group is an elevation — should require dual-control")
	}
	reasons := map[string]string{}
	for _, sk := range out.Skipped {
		reasons[sk.OverlayIP] = sk.Reason
	}
	if reasons["10.44.0.11"] != "no_op" || reasons["10.44.0.12"] != "reserved" || reasons["10.44.0.13"] != "stale" {
		t.Fatalf("skip reasons = %v, want 11=no_op 12=reserved 13=stale", reasons)
	}
}

// TestRegroupDryRunEmptyArrays: a pattern matching nothing must serialize entries/skipped as JSON
// arrays, not null — a nil slice (Go) marshals to null and crashes the console's render.
func TestRegroupDryRunEmptyArrays(t *testing.T) {
	_, h := newServer(t)
	rr := postJSON(t, h, "/admin/v1/devices/regroup?dry_run=true", "alice", `{"name_pattern":"nope-*","add":["prod"]}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("dry-run: status=%d body=%s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	if !strings.Contains(body, `"entries":[]`) || !strings.Contains(body, `"skipped":[]`) {
		t.Fatalf("empty dry-run must emit arrays, not null: %s", body)
	}
}

// TestRegroupApplyDirectAndGuard: a small pure-removal applies directly (200); re-applying with a
// stale base_generation is skipped by the optimistic-concurrency guard (no clobber).
func TestRegroupApplyDirectAndGuard(t *testing.T) {
	s, h := newServer(t)
	liveDevice(t, s.DB, "10.44.0.20", "web-1", `["laptops","prod"]`)
	id := enrollID(t, s.DB, "10.44.0.20")

	body := fmt.Sprintf(`{"entries":[{"overlay_ip":"10.44.0.20","enrollment_id":%d,"base_generation":0,"target":["laptops"]}]}`, id)
	rr := postJSON(t, h, "/admin/v1/devices/regroup", "alice", body)
	if rr.Code != http.StatusOK {
		t.Fatalf("apply: status=%d body=%s", rr.Code, rr.Body.String())
	}
	desired, gen := readEnroll(t, s.DB, "10.44.0.20")
	if gen != 1 || strings.Contains(desired, "prod") {
		t.Fatalf("after apply: desired=%q gen=%d, want [laptops] gen 1", desired, gen)
	}

	// re-apply with the now-stale base_generation 0 -> guarded skip, no clobber.
	rr = postJSON(t, h, "/admin/v1/devices/regroup", "alice", body)
	if rr.Code != http.StatusOK {
		t.Fatalf("re-apply status=%d", rr.Code)
	}
	var out struct {
		Results []struct {
			Status string `json:"status"`
		} `json:"results"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	if len(out.Results) != 1 || out.Results[0].Status != "skipped:changed_since_preview" {
		t.Fatalf("re-apply results=%+v, want skipped:changed_since_preview", out.Results)
	}
	if _, gen2 := readEnroll(t, s.DB, "10.44.0.20"); gen2 != 1 {
		t.Fatalf("generation guard failed: moved to %d", gen2)
	}
}

// TestRegroupMatch: the live hint endpoint counts matched vs eligible (same exclusions as the
// dry-run), breaks down skips, samples eligible-first, and emits arrays for an empty pattern.
func TestRegroupMatch(t *testing.T) {
	s, h := newServer(t)
	liveDevice(t, s.DB, "10.44.0.40", "node-1", `["laptops"]`)
	liveDevice(t, s.DB, "10.44.0.41", "node-2", `["laptops"]`)
	liveDevice(t, s.DB, "10.44.0.42", "node-cp", `["control-plane"]`) // reserved -> ineligible
	seedIssuedDevice(t, s.DB, "10.44.0.43", "node-stale", `["laptops"]`) // no heartbeat -> stale

	get := func(t *testing.T, url string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", url, nil)
		req.Header.Set("X-Harbor-Dev-Actor", "alice")
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr
	}

	rr := get(t, "/admin/v1/devices/regroup/match?name_pattern=node-*")
	if rr.Code != http.StatusOK {
		t.Fatalf("match: status=%d body=%s", rr.Code, rr.Body.String())
	}
	var out struct {
		Matched  int `json:"matched"`
		Eligible int `json:"eligible"`
		Sample   []struct {
			Name     string `json:"name"`
			Eligible bool   `json:"eligible"`
		} `json:"sample"`
		Skipped map[string]int `json:"skipped"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Matched != 4 || out.Eligible != 2 {
		t.Fatalf("matched=%d eligible=%d, want 4/2", out.Matched, out.Eligible)
	}
	if out.Skipped["reserved"] != 1 || out.Skipped["stale"] != 1 {
		t.Fatalf("skipped=%v, want reserved=1 stale=1", out.Skipped)
	}
	if len(out.Sample) == 0 || !out.Sample[0].Eligible {
		t.Fatalf("sample must lead with an eligible device: %+v", out.Sample)
	}

	// empty pattern -> zero + arrays (no crash shape)
	rr = get(t, "/admin/v1/devices/regroup/match")
	if !strings.Contains(rr.Body.String(), `"sample":[]`) {
		t.Fatalf("empty pattern must emit a sample array: %s", rr.Body.String())
	}
}

// TestRegroupApplyElevationDualControl: an elevating apply routes to dual-control (202), not a write.
func TestRegroupApplyElevationDualControl(t *testing.T) {
	s, h := newServer(t)
	liveDevice(t, s.DB, "10.44.0.30", "api-1", `["laptops"]`)
	id := enrollID(t, s.DB, "10.44.0.30")
	body := fmt.Sprintf(`{"entries":[{"overlay_ip":"10.44.0.30","enrollment_id":%d,"base_generation":0,"target":["laptops","prod"]}]}`, id)
	rr := postJSON(t, h, "/admin/v1/devices/regroup", "alice", body)
	if rr.Code != http.StatusAccepted {
		t.Fatalf("elevation apply: status=%d, want 202 (dual-control); body=%s", rr.Code, rr.Body.String())
	}
	// the elevation must NOT have written desired yet (awaiting the second approver).
	if desired, _ := readEnroll(t, s.DB, "10.44.0.30"); strings.Contains(desired, "prod") {
		t.Fatalf("elevation wrote desired before approval: %q", desired)
	}
}
