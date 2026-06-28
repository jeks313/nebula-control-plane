package adminapi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/jeks313/nebula-control-plane/internal/dualcontrol"
	"github.com/jeks313/nebula-control-plane/internal/enrollment"
	"github.com/jeks313/nebula-control-plane/internal/policy"
)

// Bulk device group reassignment (ADR 0013). A dry run resolves a name-pattern/explicit-IP
// selection + an add/remove/replace delta into per-device ABSOLUTE targets and identity tokens
// (overlay_ip, enrollment_id, base_generation); apply commits those exact entries through the
// ADR-0002 absolute-set primitive under optimistic concurrency. Elevating or large ops route
// through dual-control; the cap bounds the renew/KMS burst. Reserved/stale/ephemeral/reaped
// hosts are excluded.

const (
	regroupKind        = "device.groups" // dual-control change kind
	regroupMaxSet      = 100             // cap the committed set (bounds the renew/KMS burst); narrow the pattern beyond this
	regroupDCThreshold = 25              // sets larger than this route through dual-control regardless of add/remove
)

type regroupReq struct {
	NamePattern  string   `json:"name_pattern,omitempty"`
	OverlayIPs   []string `json:"overlay_ips,omitempty"`
	Add          []string `json:"add,omitempty"`
	Remove       []string `json:"remove,omitempty"`
	Replace      []string `json:"replace,omitempty"` // absolute set; ignores add/remove when present
	IncludeStale bool     `json:"include_stale,omitempty"`
	Entries      []applyEntry `json:"entries,omitempty"` // apply path: the dry-run's confirmed entries
}

type dryEntry struct {
	OverlayIP      string   `json:"overlay_ip"`
	EnrollmentID   int64    `json:"enrollment_id"`
	Name           string   `json:"name"`
	From           []string `json:"from"`   // current desired groups
	Target         []string `json:"target"` // computed absolute target
	BaseGeneration int64    `json:"base_generation"`
	WillReduce     bool     `json:"will_reduce"`
	Elevates       bool     `json:"elevates"`
}

type applyEntry struct {
	OverlayIP      string   `json:"overlay_ip"`
	EnrollmentID   int64    `json:"enrollment_id"`
	BaseGeneration int64    `json:"base_generation"`
	Target         []string `json:"target"`
}

type regroupSkip struct {
	OverlayIP string `json:"overlay_ip"`
	Name      string `json:"name"`
	Reason    string `json:"reason"`
}

type regroupResult struct {
	OverlayIP string `json:"overlay_ip"`
	Status    string `json:"status"` // applied | skipped:<reason> | failed:<reason>
}

// candidate is the resolved per-device state the dry run classifies.
type candidate struct {
	ID               int64  `gorm:"column:id"`
	DeviceName       string `gorm:"column:device_name"`
	OverlayIP        string `gorm:"column:overlay_ip"`
	Groups           string `gorm:"column:groups"`
	DesiredGroups    string `gorm:"column:desired_groups"`
	GroupsGeneration int64  `gorm:"column:groups_generation"`
	Ephemeral        bool   `gorm:"column:ephemeral"`
	LastSeen         int64  `gorm:"column:last_seen"`
}

// handleDeviceRegroup implements POST /admin/v1/devices/regroup. ?dry_run=true resolves +
// previews (no writes); otherwise it applies the explicit entries (200), or routes an
// elevating/large change through dual-control (202 + Change). device:manage + step-up.
func (s *Server) handleDeviceRegroup(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	if !s.requirePerm(w, id, PermDeviceManage) {
		return
	}
	if !s.requireStepUp(w, id) {
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "bad request", "could not read body")
		return
	}
	var req regroupReq
	if err := json.Unmarshal(body, &req); err != nil {
		writeProblem(w, http.StatusBadRequest, "bad request", "invalid JSON body")
		return
	}

	if r.URL.Query().Get("dry_run") == "true" {
		s.regroupDryRun(w, r, req)
		return
	}
	s.regroupApply(w, r, id, req)
}

type regroupSample struct {
	Name      string `json:"name"`
	OverlayIP string `json:"overlay_ip"`
	Eligible  bool   `json:"eligible"`
	Reason    string `json:"reason,omitempty"` // skip reason when !eligible
}

type regroupMatchResp struct {
	Matched  int             `json:"matched"`  // name-matched candidates (deduped per overlay_ip)
	Eligible int             `json:"eligible"` // would be acted on (after state exclusions)
	Sample   []regroupSample `json:"sample"`   // up to regroupSampleMax, eligible first
	Skipped  map[string]int  `json:"skipped"`  // reason -> count
}

const regroupSampleMax = 8 // server sample cap; the console shows the first ~4

// handleDeviceRegroupMatch implements GET /admin/v1/devices/regroup/match — a cheap, read-only
// preview-of-the-preview: how many devices a name_pattern resolves to, how many are eligible (after
// the SAME reserved/stale/ephemeral/reaped exclusions the dry-run uses), plus a small name sample.
// Powers the live "N devices match" hint as the operator types. device:manage, NO step-up (read).
func (s *Server) handleDeviceRegroupMatch(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r.Context())
	if !s.requirePerm(w, id, PermDeviceManage) {
		return
	}
	namePattern := r.URL.Query().Get("name_pattern")
	includeStale := r.URL.Query().Get("include_stale") == "true"
	resp := regroupMatchResp{Sample: []regroupSample{}, Skipped: map[string]int{}}
	if strings.TrimSpace(namePattern) == "" {
		writeJSON(w, http.StatusOK, resp)
		return
	}
	cls, err := s.classifyRegroup(r.Context(), namePattern, nil, includeStale)
	if err != nil {
		s.fail(w, r, "resolve devices failed", err)
		return
	}
	resp.Matched = len(cls)
	for _, cc := range cls {
		if cc.reason == "" {
			resp.Eligible++
		} else {
			resp.Skipped[cc.reason]++
		}
	}
	// Sample eligible first, then ineligible, up to the cap — prefer showing the names that
	// would actually change.
	take := func(wantEligible bool) {
		for _, cc := range cls {
			if len(resp.Sample) >= regroupSampleMax {
				return
			}
			if (cc.reason == "") != wantEligible {
				continue
			}
			resp.Sample = append(resp.Sample, regroupSample{
				Name: cc.cand.DeviceName, OverlayIP: cc.cand.OverlayIP,
				Eligible: cc.reason == "", Reason: cc.reason,
			})
		}
	}
	take(true)
	take(false)
	writeJSON(w, http.StatusOK, resp)
}

// regroupDryRun resolves the selection + delta into per-device entries and skips, with no writes.
func (s *Server) regroupDryRun(w http.ResponseWriter, r *http.Request, req regroupReq) {
	ctx := r.Context()
	add, remove := normGroups(req.Add), normGroups(req.Remove)
	replace, hasReplace := normGroups(req.Replace), len(req.Replace) > 0
	if !hasReplace && len(add) == 0 && len(remove) == 0 {
		writeProblem(w, http.StatusBadRequest, "no change", "specify add, remove, or replace")
		return
	}
	if inter := intersect(add, remove); len(inter) > 0 {
		writeProblem(w, http.StatusBadRequest, "ambiguous", "a group appears in both add and remove: "+strings.Join(inter, ", "))
		return
	}
	if policy.GrantsReservedGroup(add) || policy.GrantsReservedGroup(replace) {
		writeProblem(w, http.StatusBadRequest, "reserved group", "control-plane/lighthouse cannot be assigned")
		return
	}

	cls, err := s.classifyRegroup(ctx, req.NamePattern, req.OverlayIPs, req.IncludeStale)
	if err != nil {
		s.fail(w, r, "resolve devices failed", err)
		return
	}

	// Non-nil so they always marshal as JSON arrays (a nil slice → `null`, which the
	// console treats as a crashable shape). Same for each entry's from/target below.
	entries := []dryEntry{}
	skipped := []regroupSkip{}
	capped := 0
	for _, cc := range cls {
		c := cc.cand
		if cc.reason != "" { // state-excluded (reserved/stale/ephemeral/reaped)
			skipped = append(skipped, regroupSkip{c.OverlayIP, c.DeviceName, cc.reason})
			continue
		}
		current := []string{}
		_ = json.Unmarshal([]byte(c.DesiredGroups), &current)
		target := applyDelta(current, add, remove, replace, hasReplace)
		if sameGroupSet(current, target) {
			skipped = append(skipped, regroupSkip{c.OverlayIP, c.DeviceName, "no_op"})
			continue
		}
		if len(entries) >= regroupMaxSet {
			capped++
			continue
		}
		entries = append(entries, dryEntry{
			OverlayIP: c.OverlayIP, EnrollmentID: c.ID, Name: c.DeviceName,
			From: current, Target: target, BaseGeneration: c.GroupsGeneration,
			WillReduce: groupsDropped(current, target), Elevates: groupsDropped(target, current),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"entries":               entries,
		"skipped":               skipped,
		"capped":                capped,
		"requires_dual_control": dcRequired(entries),
	})
}

// regroupApply commits the explicit, dry-run-confirmed entries — directly (200) or, for an
// elevating/large change, via dual-control (202 + Change).
func (s *Server) regroupApply(w http.ResponseWriter, r *http.Request, id Identity, req regroupReq) {
	ctx := r.Context()
	if len(req.Entries) == 0 {
		writeProblem(w, http.StatusBadRequest, "no entries", "apply requires the dry-run entries")
		return
	}
	if len(req.Entries) > regroupMaxSet {
		writeProblem(w, http.StatusBadRequest, "too many", fmt.Sprintf("at most %d devices per op — narrow the pattern", regroupMaxSet))
		return
	}
	for _, e := range req.Entries {
		if policy.GrantsReservedGroup(e.Target) {
			writeProblem(w, http.StatusBadRequest, "reserved group", "control-plane/lighthouse cannot be assigned")
			return
		}
	}
	// Routing: any elevation, or a set over the threshold, needs a distinct second approver.
	if s.dc != nil && applyNeedsDualControl(ctx, s, req.Entries) {
		payload, _ := json.Marshal(req.Entries)
		ch, derr := s.dc.Propose(ctx, regroupKind,
			fmt.Sprintf("re-group %d device(s) (elevating/large — needs a distinct second approver)", len(req.Entries)),
			payload, id.Principal)
		if derr != nil {
			s.fail(w, r, "propose regroup failed", derr)
			return
		}
		writeJSON(w, http.StatusAccepted, changeView(ch, true))
		return
	}
	results := s.applyRegroup(ctx, id.Principal, "b-"+randID(), req.Entries)
	writeJSON(w, http.StatusOK, map[string]any{"results": results})
}

// applyRegroup writes each entry as an absolute set, GUARDED by (enrollment_id, base_generation)
// re-resolved at apply time: a device whose authoritative enrollment or generation moved since the
// preview (re-enroll, concurrent edit), or that is reaped / now holds a reserved group, is skipped.
// Shared by the direct path and the dual-control committer.
func (s *Server) applyRegroup(ctx context.Context, actor, batchID string, entries []applyEntry) []regroupResult {
	out := make([]regroupResult, 0, len(entries))
	for _, e := range entries {
		st := s.applyRegroupOne(ctx, actor, batchID, e)
		out = append(out, regroupResult{OverlayIP: e.OverlayIP, Status: st})
	}
	return out
}

func (s *Server) applyRegroupOne(ctx context.Context, actor, batchID string, e applyEntry) string {
	var cur enrollment.Enrollment
	if err := s.cfg.Store.DB.WithContext(ctx).
		Where("overlay_ip = ? AND status = ?", e.OverlayIP, enrollment.StatusIssued).
		Order("id DESC").First(&cur).Error; err != nil {
		return "skipped:not_found"
	}
	if cur.ID != e.EnrollmentID || cur.GroupsGeneration != e.BaseGeneration {
		return "skipped:changed_since_preview"
	}
	var curGroups []string
	_ = json.Unmarshal([]byte(cur.Groups), &curGroups)
	if policy.GrantsReservedGroup(curGroups) || policy.GrantsReservedGroup(e.Target) {
		return "skipped:reserved"
	}
	targetJSON, _ := json.Marshal(normGroups(e.Target))
	res := s.cfg.Store.DB.WithContext(ctx).Model(&enrollment.Enrollment{}).
		Where("id = ? AND groups_generation = ?", e.EnrollmentID, e.BaseGeneration).
		Updates(map[string]any{"desired_groups": string(targetJSON), "groups_generation": e.BaseGeneration + 1})
	if res.Error != nil {
		return "failed:" + res.Error.Error()
	}
	if res.RowsAffected == 0 {
		return "skipped:changed_since_preview"
	}
	_, _ = s.cfg.Store.AppendAudit(ctx, actor, "device-regroup", e.OverlayIP,
		fmt.Sprintf(`{"batch":%q,"from":%s,"to":%s,"generation":%d}`, batchID, jsonOrEmpty(cur.DesiredGroups), string(targetJSON), e.BaseGeneration+1))
	return "applied"
}

// commitDeviceRegroup is the dual-control committer: it re-resolves + applies the frozen entry
// set at approval time (registered as the regroupKind committer in New()).
func (s *Server) commitDeviceRegroup(ctx context.Context, ch dualcontrol.Change) error {
	var entries []applyEntry
	if err := json.Unmarshal(ch.Payload, &entries); err != nil {
		return err
	}
	s.applyRegroup(ctx, ch.Proposer, fmt.Sprintf("change-%d", ch.ID), entries)
	return nil
}

// applyNeedsDualControl: an elevation (target adds a group vs current desired) or a set larger
// than the threshold routes through dual-control. add-vs-remove is re-derived server-side.
func applyNeedsDualControl(ctx context.Context, s *Server, entries []applyEntry) bool {
	if len(entries) > regroupDCThreshold {
		return true
	}
	for _, e := range entries {
		var cur enrollment.Enrollment
		if err := s.cfg.Store.DB.WithContext(ctx).
			Where("overlay_ip = ? AND status = ?", e.OverlayIP, enrollment.StatusIssued).
			Order("id DESC").First(&cur).Error; err != nil {
			continue
		}
		var current []string
		_ = json.Unmarshal([]byte(cur.DesiredGroups), &current)
		if groupsDropped(e.Target, current) { // target has a group current lacks -> elevation
			return true
		}
	}
	return false
}

// dcRequired (dry-run hint): elevation or oversized set.
func dcRequired(entries []dryEntry) bool {
	if len(entries) > regroupDCThreshold {
		return true
	}
	for _, e := range entries {
		if e.Elevates {
			return true
		}
	}
	return false
}

// classifiedCand is a resolved candidate plus its state-based skip reason ("" = eligible). The
// reason set (reserved/reaped/ephemeral/stale) is shared by the dry-run and the live match hint, so
// the count a user sees while typing matches what apply will act on. It does NOT include the
// delta-dependent no_op exclusion (that needs an add/remove/replace, which the hint doesn't have).
type classifiedCand struct {
	cand   candidate
	reason string
}

func (s *Server) classifyRegroup(ctx context.Context, namePattern string, overlayIPs []string, includeStale bool) ([]classifiedCand, error) {
	cands, err := s.regroupCandidates(ctx, namePattern, overlayIPs)
	if err != nil {
		return nil, err
	}
	reaped, err := s.reapedNameSet(ctx, cands)
	if err != nil {
		return nil, err
	}
	staleNs := s.cfg.Thresholds.StaleAfter.Nanoseconds()
	nowNs := s.now().UnixNano()
	out := make([]classifiedCand, 0, len(cands))
	for _, c := range cands {
		current := []string{}
		_ = json.Unmarshal([]byte(c.DesiredGroups), &current)
		reason := ""
		switch {
		case policy.GrantsReservedGroup(current):
			reason = "reserved" // baseline-owned (control-plane/lighthouse) — not manageable here
		case reaped[c.DeviceName]:
			reason = "reaped"
		case c.Ephemeral:
			reason = "ephemeral"
		case (c.LastSeen == 0 || (staleNs > 0 && c.LastSeen < nowNs-staleNs)) && !includeStale:
			reason = "stale"
		}
		out = append(out, classifiedCand{cand: c, reason: reason})
	}
	return out, nil
}

// regroupCandidates resolves the authoritative (latest issued) enrollment per overlay_ip for the
// name pattern and/or explicit IP set, joined with the heartbeat last_seen (for staleness).
func (s *Server) regroupCandidates(ctx context.Context, namePattern string, overlayIPs []string) ([]candidate, error) {
	q := s.cfg.Store.DB.WithContext(ctx).Table("enrollments AS e").
		Select("e.id, e.device_name, e.overlay_ip, e.groups, e.desired_groups, e.groups_generation, e.ephemeral, COALESCE(h.last_seen, 0) AS last_seen").
		Joins("LEFT JOIN heartbeats h ON h.overlay_ip = e.overlay_ip").
		Where("e.status = ? AND e.overlay_ip <> ''", enrollment.StatusIssued).
		Order("e.id DESC")
	if namePattern != "" {
		q = q.Where("e.device_name LIKE ? ESCAPE '\\'", globToLike(namePattern))
	}
	if len(overlayIPs) > 0 {
		q = q.Where("e.overlay_ip IN ?", overlayIPs)
	}
	var rows []candidate
	if err := q.Find(&rows).Error; err != nil {
		return nil, err
	}
	// dedup: keep the latest issued (highest id, first seen) per overlay_ip.
	seen := make(map[string]bool, len(rows))
	out := rows[:0]
	for _, r := range rows {
		if seen[r.OverlayIP] {
			continue
		}
		seen[r.OverlayIP] = true
		out = append(out, r)
	}
	return out, nil
}

func (s *Server) reapedNameSet(ctx context.Context, cands []candidate) (map[string]bool, error) {
	names := make([]string, 0, len(cands))
	for _, c := range cands {
		names = append(names, c.DeviceName)
	}
	marks, err := s.deviceReapMarks(ctx, names)
	if err != nil {
		return nil, err
	}
	set := make(map[string]bool, len(marks))
	for n := range marks {
		set[n] = true
	}
	return set, nil
}

// applyDelta computes the absolute target: replace wins; otherwise (current ∪ add) \ remove.
func applyDelta(current, add, remove, replace []string, hasReplace bool) []string {
	if hasReplace {
		return normGroups(replace)
	}
	out := append([]string{}, current...)
	out = append(out, add...)
	rm := make(map[string]bool, len(remove))
	for _, g := range remove {
		rm[g] = true
	}
	kept := out[:0]
	for _, g := range out {
		if !rm[g] {
			kept = append(kept, g)
		}
	}
	return normGroups(kept)
}

// groupsDropped reports whether any element of a is absent from b.
func groupsDropped(a, b []string) bool {
	mb := make(map[string]bool, len(b))
	for _, g := range b {
		mb[g] = true
	}
	for _, g := range a {
		if !mb[g] {
			return true
		}
	}
	return false
}

func intersect(a, b []string) []string {
	mb := make(map[string]bool, len(b))
	for _, g := range b {
		mb[g] = true
	}
	var out []string
	for _, g := range a {
		if mb[g] {
			out = append(out, g)
		}
	}
	return out
}

// globToLike converts a glob (*, ?) to a SQL LIKE pattern, escaping LIKE metacharacters with \.
func globToLike(glob string) string {
	var b strings.Builder
	for _, r := range glob {
		switch r {
		case '*':
			b.WriteByte('%')
		case '?':
			b.WriteByte('_')
		case '%', '_', '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func randID() string {
	var b [6]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
