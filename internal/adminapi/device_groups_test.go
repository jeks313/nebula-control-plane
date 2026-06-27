package adminapi_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jeks313/nebula-control-plane/internal/enrollment"
	"gorm.io/gorm"
)

func patchGroups(t *testing.T, h http.Handler, ip, actor, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("PATCH", "/admin/v1/devices/"+ip+"/groups", strings.NewReader(body))
	if actor != "" {
		req.Header.Set("X-Harbor-Dev-Actor", actor)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func seedIssuedDevice(t *testing.T, db *gorm.DB, ip, name, groupsJSON string) {
	t.Helper()
	e := enrollment.Enrollment{
		EnrollmentID: name + "-enr", DeviceName: name, OverlayIP: ip,
		Groups: groupsJSON, DesiredGroups: groupsJSON, Status: "issued",
		Pubkey: []byte("x"), Method: "token", CreatedAt: 1,
	}
	if err := db.Create(&e).Error; err != nil {
		t.Fatalf("seed enrollment: %v", err)
	}
}

func readEnroll(t *testing.T, db *gorm.DB, ip string) (desired string, gen int64) {
	t.Helper()
	var r struct {
		DesiredGroups    string `gorm:"column:desired_groups"`
		GroupsGeneration int64  `gorm:"column:groups_generation"`
	}
	if err := db.Table("enrollments").Select("desired_groups, groups_generation").
		Where("overlay_ip = ? AND status = ?", ip, "issued").Order("id DESC").First(&r).Error; err != nil {
		t.Fatalf("read enrollment: %v", err)
	}
	return r.DesiredGroups, r.GroupsGeneration
}

// TestDeviceGroupSet covers PATCH /admin/v1/devices/{ip}/groups: the happy-path set + generation
// bump, the set-equality no-op, both reserved-group guards, and the 404/401 paths.
func TestDeviceGroupSet(t *testing.T) {
	s, h := newServer(t)
	seedIssuedDevice(t, s.DB, "10.44.0.7", "db-1", `["laptops"]`)

	// set new groups -> 200, desired updated + generation bumped to 1
	if rr := patchGroups(t, h, "10.44.0.7", "alice", `{"groups":["prod","monitored"]}`); rr.Code != http.StatusOK {
		t.Fatalf("set groups: status=%d body=%s", rr.Code, rr.Body.String())
	}
	desired, gen := readEnroll(t, s.DB, "10.44.0.7")
	if gen != 1 {
		t.Fatalf("generation=%d, want 1", gen)
	}
	if !strings.Contains(desired, "prod") || !strings.Contains(desired, "monitored") {
		t.Fatalf("desired_groups=%q, want prod+monitored", desired)
	}

	// no-op: same set (reordered) -> 200, generation NOT bumped
	if rr := patchGroups(t, h, "10.44.0.7", "alice", `{"groups":["monitored","prod"]}`); rr.Code != http.StatusOK {
		t.Fatalf("no-op set: status=%d", rr.Code)
	}
	if _, gen2 := readEnroll(t, s.DB, "10.44.0.7"); gen2 != 1 {
		t.Fatalf("no-op bumped generation to %d, want 1 (set-equality)", gen2)
	}

	// reserved group cannot be ADDED -> 400
	if rr := patchGroups(t, h, "10.44.0.7", "alice", `{"groups":["control-plane"]}`); rr.Code != http.StatusBadRequest {
		t.Fatalf("add reserved: status=%d, want 400", rr.Code)
	}

	// a device that currently HOLDS a reserved group is not manageable here -> 400
	seedIssuedDevice(t, s.DB, "10.44.0.2", "harbor", `["control-plane"]`)
	if rr := patchGroups(t, h, "10.44.0.2", "alice", `{"groups":["prod"]}`); rr.Code != http.StatusBadRequest {
		t.Fatalf("regroup reserved device: status=%d, want 400", rr.Code)
	}

	// unknown overlay IP -> 404
	if rr := patchGroups(t, h, "10.44.9.9", "alice", `{"groups":["x"]}`); rr.Code != http.StatusNotFound {
		t.Fatalf("unknown device: status=%d, want 404", rr.Code)
	}

	// unauthenticated -> 401
	if rr := patchGroups(t, h, "10.44.0.7", "", `{"groups":["x"]}`); rr.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated: status=%d, want 401", rr.Code)
	}
}
