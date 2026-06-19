package revocation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/dualcontrol"
	"github.com/jeks313/nebula-control-plane/internal/store"
	"github.com/jeks313/nebula-control-plane/internal/store/migrate"
)

func setup(t *testing.T) (*store.Store, *[]string) {
	t.Helper()
	s, err := store.Open(store.Config{Driver: "sqlite", DSN: store.DefaultSQLiteDSN(filepath.Join(t.TempDir(), "r.db"))})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	if err := migrate.Up(s.DB); err != nil {
		t.Fatal(err)
	}
	var actions []string
	return s, &actions
}

func newReg(s *store.Store, actions *[]string) *Registry {
	audit := func(_ context.Context, _, action, _, _ string) error {
		*actions = append(*actions, action)
		return nil
	}
	return New(s.DB, audit)
}

// TestAddListLiftActive covers the basic lifecycle: add blocklists a fingerprint,
// list shows it, lift removes it from the active set (kept as history), and each
// state-changing op is audited.
func TestAddListLiftActive(t *testing.T) {
	s, actions := setup(t)
	r := newReg(s, actions)
	ctx := context.Background()

	if _, err := r.Add(ctx, "aaaa", "compromised", "admin"); err != nil {
		t.Fatalf("add: %v", err)
	}
	if fps, _ := r.ActiveFingerprints(ctx); len(fps) != 1 || fps[0] != "aaaa" {
		t.Fatalf("active = %v, want [aaaa]", fps)
	}
	if rows, _ := r.List(ctx); len(rows) != 1 || rows[0].State != StateActive || rows[0].Reason != "compromised" {
		t.Fatalf("list = %+v", rows)
	}

	if err := r.Lift(ctx, "aaaa", "admin"); err != nil {
		t.Fatalf("lift: %v", err)
	}
	if fps, _ := r.ActiveFingerprints(ctx); len(fps) != 0 {
		t.Fatalf("active after lift = %v, want []", fps)
	}
	if rows, _ := r.List(ctx); len(rows) != 1 || rows[0].State != StateLifted {
		t.Fatalf("lifted row = %+v", rows)
	}

	// Two state changes (add + lift) → two audit rows.
	if got := *actions; len(got) != 2 || got[0] != "revocation-add" || got[1] != "revocation-lift" {
		t.Fatalf("audit actions = %v, want [revocation-add revocation-lift]", got)
	}
}

// TestAddIdempotentAndReactivate: re-adding an active fingerprint is rejected
// (ErrAlreadyActive), and adding a previously-lifted one re-activates it.
func TestAddIdempotentAndReactivate(t *testing.T) {
	s, actions := setup(t)
	r := newReg(s, actions)
	ctx := context.Background()

	if _, err := r.Add(ctx, "bbbb", "x", "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Add(ctx, "bbbb", "again", "admin"); !errors.Is(err, ErrAlreadyActive) {
		t.Fatalf("re-add active err = %v, want ErrAlreadyActive", err)
	}
	if err := r.Lift(ctx, "bbbb", "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Add(ctx, "bbbb", "reblock", "admin"); err != nil {
		t.Fatalf("re-activate after lift: %v", err)
	}
	if fps, _ := r.ActiveFingerprints(ctx); len(fps) != 1 || fps[0] != "bbbb" {
		t.Fatalf("active after reactivate = %v, want [bbbb]", fps)
	}
	// Still exactly one row (re-activated in place, not duplicated).
	if rows, _ := r.List(ctx); len(rows) != 1 {
		t.Fatalf("want 1 row after reactivate, got %d", len(rows))
	}
}

// TestNormalizationAndSortDeterminism: fingerprints are lowercased/trimmed (so
// the same cert maps to one row) and ActiveFingerprints is sorted (so an
// unchanged blocklist yields a byte-identical bundle and never trips drift).
func TestNormalizationAndSortDeterminism(t *testing.T) {
	s, actions := setup(t)
	r := newReg(s, actions)
	ctx := context.Background()

	// Mixed case + surrounding space normalizes to lowercase hex.
	if _, err := r.Add(ctx, "  ABCD  ", "", "admin"); err != nil {
		t.Fatal(err)
	}
	// A second add of the same cert in a different case is a duplicate, not a new row.
	if _, err := r.Add(ctx, "abcd", "", "admin"); !errors.Is(err, ErrAlreadyActive) {
		t.Fatalf("case-variant re-add err = %v, want ErrAlreadyActive (normalized dup)", err)
	}

	// Insert out of order; ActiveFingerprints must come back sorted ascending.
	for _, fp := range []string{"ffff", "0000"} {
		if _, err := r.Add(ctx, fp, "", "admin"); err != nil {
			t.Fatal(err)
		}
	}
	fps, _ := r.ActiveFingerprints(ctx)
	if strings.Join(fps, ",") != "0000,abcd,ffff" {
		t.Fatalf("active = %v, want sorted [0000 abcd ffff]", fps)
	}
}

func TestAddEmptyFingerprintRejected(t *testing.T) {
	s, actions := setup(t)
	r := newReg(s, actions)
	if _, err := r.Add(context.Background(), "   ", "", "admin"); !errors.Is(err, ErrNoFingerprint) {
		t.Fatalf("err = %v, want ErrNoFingerprint", err)
	}
}

// seedEnrollment inserts an issued enrollment row so the Guard-1 fingerprint->host
// resolution has data (raw table insert, mirroring how the guard reads it).
func seedEnrollment(t *testing.T, s *store.Store, fp, groupsJSON, overlayIP string) {
	t.Helper()
	if err := s.DB.Table("enrollments").Create(map[string]any{
		"enrollment_id": "e-" + fp,
		"device_name":   "host-" + fp,
		"pubkey_hash":   "ph-" + fp,
		"pubkey":        []byte(fp),
		"method":        "test",
		"fingerprint":   fp,
		"status":        "issued",
		"groups":        groupsJSON,
		"overlay_ip":    overlayIP,
		"created_at":    time.Now().UnixNano(),
	}).Error; err != nil {
		t.Fatalf("seed enrollment %s: %v", fp, err)
	}
}

func activeCount(t *testing.T, s *store.Store) int64 {
	t.Helper()
	var n int64
	if err := s.DB.Model(&Row{}).Where("state = ?", StateActive).Count(&n).Error; err != nil {
		t.Fatalf("count active: %v", err)
	}
	return n
}

// TestAddRefusesReservedGroupHost (Guard 1, a): a fingerprint whose latest issued
// enrollment grants control-plane or lighthouse is refused, and no row is written.
func TestAddRefusesReservedGroupHost(t *testing.T) {
	for _, group := range []string{"control-plane", "lighthouse"} {
		t.Run(group, func(t *testing.T) {
			s, actions := setup(t)
			r := newReg(s, actions)
			ctx := context.Background()
			fp := "cp" + group[:2]
			seedEnrollment(t, s, fp, `["`+group+`"]`, "10.44.0.1")
			if _, err := r.Add(ctx, fp, "x", "admin"); !errors.Is(err, ErrControlPlaneProtected) {
				t.Fatalf("add %s err = %v, want ErrControlPlaneProtected", group, err)
			}
			if n := activeCount(t, s); n != 0 {
				t.Fatalf("rows written = %d, want 0 (refused)", n)
			}
		})
	}
}

// TestAddNormalGroupHostOK (Guard 1, b): a fingerprint resolving to a non-reserved
// host is blocklisted normally.
func TestAddNormalGroupHostOK(t *testing.T) {
	s, actions := setup(t)
	r := newReg(s, actions)
	ctx := context.Background()
	seedEnrollment(t, s, "normalfp", `["workloads"]`, "10.44.64.5")
	if _, err := r.Add(ctx, "normalfp", "compromised", "admin"); err != nil {
		t.Fatalf("add normal-group host: %v", err)
	}
	if n := activeCount(t, s); n != 1 {
		t.Fatalf("rows = %d, want 1", n)
	}
}

// TestAddUnknownFingerprintOK (Guard 1, c): an unknown fingerprint (no enrollment)
// is allowed — it's not a known control-plane host.
func TestAddUnknownFingerprintOK(t *testing.T) {
	s, actions := setup(t)
	r := newReg(s, actions)
	if _, err := r.Add(context.Background(), "unknownfp", "x", "admin"); err != nil {
		t.Fatalf("add unknown fp: %v", err)
	}
	if n := activeCount(t, s); n != 1 {
		t.Fatalf("rows = %d, want 1", n)
	}
}

// TestAddCentralBlockGuard (Guard 1, d): with WithCentralBlock set, a host whose
// overlay IP is inside central is refused even though its groups are empty.
func TestAddCentralBlockGuard(t *testing.T) {
	s, actions := setup(t)
	central := netip.MustParsePrefix("10.44.0.0/27")
	r := newReg(s, actions).WithCentralBlock(central)
	ctx := context.Background()

	// In-central, empty groups -> refused by the central guard.
	seedEnrollment(t, s, "centralfp", `[]`, "10.44.0.10")
	if _, err := r.Add(ctx, "centralfp", "x", "admin"); !errors.Is(err, ErrControlPlaneProtected) {
		t.Fatalf("in-central add err = %v, want ErrControlPlaneProtected", err)
	}
	if n := activeCount(t, s); n != 0 {
		t.Fatalf("rows = %d, want 0 (refused)", n)
	}
	// Just outside central (next /27) -> allowed (proves the guard is precise).
	seedEnrollment(t, s, "outsidefp", `[]`, "10.44.0.32")
	if _, err := r.Add(ctx, "outsidefp", "x", "admin"); err != nil {
		t.Fatalf("out-of-central add: %v", err)
	}
	if n := activeCount(t, s); n != 1 {
		t.Fatalf("rows = %d, want 1", n)
	}
}

// TestApplyBulkControlPlaneAtomic (Guard 2, e): a single control-plane fingerprint
// in the set rejects the WHOLE bulk and writes zero rows.
func TestApplyBulkControlPlaneAtomic(t *testing.T) {
	s, actions := setup(t)
	r := newReg(s, actions)
	ctx := context.Background()
	seedEnrollment(t, s, "cpfp", `["control-plane"]`, "10.44.0.1")
	spec := BulkRevokeSpec{Fingerprints: []string{"goodfp1", "cpfp", "goodfp2"}, Reason: "x"}
	if err := r.applyBulk(ctx, spec, "op"); !errors.Is(err, ErrControlPlaneProtected) {
		t.Fatalf("applyBulk err = %v, want ErrControlPlaneProtected", err)
	}
	if n := activeCount(t, s); n != 0 {
		t.Fatalf("rows = %d, want 0 (atomic reject — nothing applied)", n)
	}
}

// TestApplyBulkPerOpCap (Guard 2, f): more than MaxBulkFingerprints is refused.
func TestApplyBulkPerOpCap(t *testing.T) {
	s, actions := setup(t)
	r := newReg(s, actions)
	fps := make([]string, MaxBulkFingerprints+1)
	for i := range fps {
		fps[i] = "fp" + string(rune('a'+i%26)) + string(rune('0'+i/26))
	}
	if err := r.applyBulk(context.Background(), BulkRevokeSpec{Fingerprints: fps}, "op"); !errors.Is(err, ErrBulkTooLarge) {
		t.Fatalf("over-cap err = %v, want ErrBulkTooLarge", err)
	}
	if n := activeCount(t, s); n != 0 {
		t.Fatalf("rows = %d, want 0", n)
	}
}

// bulkHarness wires a dual-control Controller + a Registry sharing one injectable
// clock and the RegisterCommitter committer, so a test can drive REAL bulk OPERATIONS
// (propose+approve -> committer -> applyBulk) the way production does. The committer
// runs with the change in state 'committing', so applyBulk's window count sees the
// per-op `approvals` ledger — proving the rate limit counts OPERATIONS, not rows.
type bulkHarness struct {
	dc  *dualcontrol.Controller
	reg *Registry
	now *time.Time
}

func newBulkHarness(t *testing.T) *bulkHarness {
	t.Helper()
	s, actions := setup(t)
	clock := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	h := &bulkHarness{now: &clock}
	nowFn := func() time.Time { return *h.now }
	audit := func(_ context.Context, _, action, _, _ string) error { *actions = append(*actions, action); return nil }
	h.dc = dualcontrol.New(dualcontrol.Config{DB: s.DB, Audit: audit, Now: nowFn})
	h.reg = New(s.DB, audit)
	h.reg.now = nowFn
	RegisterCommitter(h.dc, h.reg)
	return h
}

// op runs one full bulk-revoke OPERATION through dual-control (propose as a, approve as
// b) at the harness's current clock, returning the committer/commit error (nil on a
// clean commit, ErrBulkRateLimited wrapped in dualcontrol.ErrCommit when rate-limited).
func (h *bulkHarness) op(t *testing.T, fps []string) error {
	t.Helper()
	ctx := context.Background()
	spec := BulkRevokeSpec{Fingerprints: fps, Reason: "x"}
	payload, _ := json.Marshal(spec)
	ch, err := h.dc.Propose(ctx, BulkRevokeKind, "bulk", payload, "op-a")
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	_, err = h.dc.Approve(ctx, ch.ID, "op-b")
	return err
}

// TestApplyBulkWindowRateCountsOps (Blocker 3, a+b): drive real bulk OPERATIONS through
// dual-control. (a) one bulk of MANY fingerprints is ONE op, and further DISTINCT ops in
// the window keep succeeding up to MaxBulkPerWindow OPERATIONS (proving ops-not-rows —
// the first large bulk does NOT self-trip the limit). (b) the (MaxBulkPerWindow+1)-th op
// in-window is refused with ErrBulkRateLimited. After the window rolls it is allowed again.
//
// FAIL-BEFORE: the pre-fix code counted bulk ROWS, so op #1's MaxBulkFingerprints-sized
// bulk wrote >MaxBulkPerWindow rows and op #2 was wrongly ErrBulkRateLimited.
// PASS-AFTER: op #1's large bulk counts as one op; ops 2..MaxBulkPerWindow succeed.
func TestApplyBulkWindowRateCountsOps(t *testing.T) {
	h := newBulkHarness(t)
	base := *h.now

	// Op #1: a LARGE bulk (many fingerprints) — one OPERATION. Under the old row count
	// this alone would exceed MaxBulkPerWindow and block every later op.
	big := make([]string, MaxBulkFingerprints)
	for i := range big {
		big[i] = fmt.Sprintf("big%03d", i)
	}
	if err := h.op(t, big); err != nil {
		t.Fatalf("op #1 (large bulk) must succeed as ONE op: %v", err)
	}

	// Ops #2..#MaxBulkPerWindow: distinct single-fp ops, each in-window, must all succeed
	// (ops-not-rows). With the buggy row count, op #2 would already be rate-limited.
	for i := 2; i <= MaxBulkPerWindow; i++ {
		*h.now = base.Add(time.Duration(i) * time.Minute)
		if err := h.op(t, []string{fmt.Sprintf("op%d", i)}); err != nil {
			t.Fatalf("op #%d in-window must succeed (ops not rows): %v", i, err)
		}
	}

	// The (MaxBulkPerWindow+1)-th op, still in-window -> refused.
	*h.now = base.Add(time.Duration(MaxBulkPerWindow+1) * time.Minute)
	if err := h.op(t, []string{"overlimit"}); !errors.Is(err, ErrBulkRateLimited) {
		t.Fatalf("op #%d in-window err = %v, want ErrBulkRateLimited", MaxBulkPerWindow+1, err)
	}

	// After the window rolls, allowed again (the earlier ops aged out).
	*h.now = base.Add(BulkWindow + time.Hour)
	if err := h.op(t, []string{"afterroll"}); err != nil {
		t.Fatalf("after window roll must succeed: %v", err)
	}
}

// TestApplyBulkSetsBulkFlag (Guard 2, h): rows written by applyBulk have Bulk=true.
func TestApplyBulkSetsBulkFlag(t *testing.T) {
	s, actions := setup(t)
	r := newReg(s, actions)
	ctx := context.Background()
	if err := r.applyBulk(ctx, BulkRevokeSpec{Fingerprints: []string{"b1", "b2"}, Reason: "audit"}, "op"); err != nil {
		t.Fatalf("applyBulk: %v", err)
	}
	rows, _ := r.List(ctx)
	if len(rows) != 2 {
		t.Fatalf("rows = %d, want 2", len(rows))
	}
	for _, row := range rows {
		if !row.Bulk {
			t.Fatalf("row %s Bulk = false, want true", row.Fingerprint)
		}
	}
}

// TestApplyBulkAlreadyActiveSkips: an already-active fingerprint in a bulk set is a
// skip, not a failure (idempotent), and the rest still apply.
func TestApplyBulkAlreadyActiveSkips(t *testing.T) {
	s, actions := setup(t)
	r := newReg(s, actions)
	ctx := context.Background()
	if _, err := r.Add(ctx, "dup", "first", "admin"); err != nil {
		t.Fatal(err)
	}
	if err := r.applyBulk(ctx, BulkRevokeSpec{Fingerprints: []string{"dup", "fresh"}}, "op"); err != nil {
		t.Fatalf("applyBulk with already-active fp: %v", err)
	}
	if fps, _ := r.ActiveFingerprints(ctx); len(fps) != 2 {
		t.Fatalf("active = %v, want [dup fresh]", fps)
	}
}
