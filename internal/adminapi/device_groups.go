package adminapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"

	"github.com/jeks313/nebula-control-plane/internal/enrollment"
	"github.com/jeks313/nebula-control-plane/internal/policy"
	"gorm.io/gorm"
)

// handleDeviceGroupSet implements PATCH /admin/v1/devices/{ip}/groups — set a device's
// DESIRED groups (ADR 0002 single-device substrate). The body is {"groups":[…]} (the full
// target set). The change is authority-affecting, so it requires device:manage + step-up MFA;
// it takes effect on the host's next heartbeat-triggered renew (groups_generation bumps →
// CmdRenew → handleRenew re-signs from desired_groups). The cert-issue authority event is
// audited in coreapi.handleRenew; here we audit the operator's intent (from → to).
//
// Reserved groups (control-plane/lighthouse) are baseline-owned and cannot be assigned, nor
// can a device that currently holds one be re-grouped through this surface (the renew
// chokepoint is the further backstop). Bulk pattern-select re-group (ADR 0013) layers on top.
func (s *Server) handleDeviceGroupSet(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	if !s.requirePerm(w, id, PermDeviceManage) {
		return
	}
	if !s.requireStepUp(w, id) {
		return
	}
	ip := r.PathValue("ip")
	if _, err := netip.ParseAddr(ip); err != nil {
		writeProblem(w, http.StatusBadRequest, "bad overlay ip", "{ip} must be an overlay address")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "bad request", "could not read body")
		return
	}
	var req struct {
		Groups []string `json:"groups"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		writeProblem(w, http.StatusBadRequest, "bad request", `body must be {"groups":[…]}`)
		return
	}
	groups := normGroups(req.Groups)

	// reserved-group guard: never ADD a reserved group via this surface.
	if policy.GrantsReservedGroup(groups) {
		writeProblem(w, http.StatusBadRequest, "reserved group",
			"control-plane/lighthouse are baseline-owned and cannot be assigned to a device")
		return
	}

	// Resolve the authoritative (latest issued) enrollment at this overlay IP — the SAME row
	// coreapi.device() reads (id DESC), so the write lands on the row renew will re-sign.
	var dev enrollment.Enrollment
	if err := s.cfg.Store.DB.WithContext(r.Context()).
		Where("overlay_ip = ? AND status = ?", ip, enrollment.StatusIssued).
		Order("id DESC").First(&dev).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			writeProblem(w, http.StatusNotFound, "no device", "no issued device at this overlay address")
			return
		}
		s.fail(w, r, "device lookup failed", err)
		return
	}

	// reserved-group guard (other direction): a device that currently holds a reserved group is
	// baseline-owned (harbor-core / a lighthouse) and is not operator-manageable here.
	var current []string
	_ = json.Unmarshal([]byte(dev.Groups), &current)
	if policy.GrantsReservedGroup(current) {
		writeProblem(w, http.StatusBadRequest, "reserved device",
			"this device holds a reserved (control-plane/lighthouse) group and cannot be re-grouped")
		return
	}

	// no-op if the desired set already equals the request (set equality) — don't bump the
	// generation / trigger a renew for an identical set.
	var desired []string
	_ = json.Unmarshal([]byte(dev.DesiredGroups), &desired)
	if sameGroupSet(desired, groups) {
		writeJSON(w, http.StatusOK, deviceGroupResult(ip, groups, dev.GroupsGeneration, dev.GroupsGeneration > dev.IssuedGeneration))
		return
	}

	groupsJSON, _ := json.Marshal(groups)
	newGen := dev.GroupsGeneration + 1
	if err := s.cfg.Store.DB.WithContext(r.Context()).Model(&enrollment.Enrollment{}).
		Where("id = ?", dev.ID).
		Updates(map[string]any{"desired_groups": string(groupsJSON), "groups_generation": newGen}).Error; err != nil {
		s.fail(w, r, "set desired groups failed", err)
		return
	}
	_, _ = s.cfg.Store.AppendAudit(r.Context(), id.Principal, "device-regroup", ip,
		fmt.Sprintf(`{"from":%s,"to":%s,"generation":%d}`, jsonOrEmpty(dev.DesiredGroups), string(groupsJSON), newGen))

	writeJSON(w, http.StatusOK, deviceGroupResult(ip, groups, newGen, true))
}

func deviceGroupResult(ip string, groups []string, generation int64, pending bool) map[string]any {
	return map[string]any{
		"overlay_ip":     ip,
		"desired_groups": groups,
		"generation":     generation,
		"pending":        pending, // re-issue pending on the host's next heartbeat
	}
}

// normGroups trims, drops empties, and de-duplicates (preserving order) a group list.
func normGroups(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, g := range in {
		g = strings.TrimSpace(g)
		if g == "" || seen[g] {
			continue
		}
		seen[g] = true
		out = append(out, g)
	}
	return out
}

// sameGroupSet reports set-equality (order/dup-insensitive) after trimming/dropping empties.
func sameGroupSet(a, b []string) bool {
	na, nb := normGroups(a), normGroups(b)
	if len(na) != len(nb) {
		return false
	}
	m := make(map[string]bool, len(na))
	for _, g := range na {
		m[g] = true
	}
	for _, g := range nb {
		if !m[g] {
			return false
		}
	}
	return true
}

// jsonOrEmpty returns a valid JSON array literal for embedding in an audit detail; an empty
// string (a pre-0030 row that somehow lacks desired_groups) becomes "[]".
func jsonOrEmpty(s string) string {
	if strings.TrimSpace(s) == "" {
		return "[]"
	}
	return s
}
