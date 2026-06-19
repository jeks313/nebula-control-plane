// Package revocation is Harbor's cert blocklist (implementation-plan 7.1, design
// §4.7/§8). It is the single source of truth for which Nebula cert fingerprints
// the fleet must refuse: Core renders every host bundle's pki.blocklist from the
// active rows here, so adding (or lifting) a revocation propagates to every host
// via the next signed bundle (3.6/6.4) and is enforced on hosts by drift-revert
// (6.7).
//
// The control is enforced PEER-SIDE: a compromised host's own Pilot may ignore an
// order to block itself, so correctness comes from every OTHER node refusing to
// handshake with a blocklisted fingerprint (§4.7). The SLO that matters is
// therefore propagation latency to the healthy fleet, not to the target.
//
// This package implements the basic, audited add/lift/list operations (single-host
// blocklist, RBAC-gated by the caller). The P10 "cannot blocklist
// control-plane/lighthouses" invariant and the bulk-revoke dual-control + rate
// limiting (7.2) are enforced HERE: Add refuses any fingerprint whose latest
// issued enrollment grants a reserved group (control-plane/lighthouse) or whose
// overlay IP is in the configured central reserved block (always-on, no caller
// opt-out — ErrControlPlaneProtected), and a bulk revoke is gated by dual-control
// (RegisterCommitter) and a durable per-window rate limit (applyBulk).
package revocation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"gorm.io/gorm"

	"github.com/jeks313/nebula-control-plane/internal/dualcontrol"
	"github.com/jeks313/nebula-control-plane/internal/policy"
)

// State values.
const (
	StateActive = "active"
	StateLifted = "lifted"
)

// Errors callers can branch on.
var (
	ErrNoFingerprint = errors.New("revocation: fingerprint is required")
	ErrAlreadyActive = errors.New("revocation: fingerprint is already blocklisted")
	// ErrControlPlaneProtected is the always-on P10 guard: a fingerprint resolving
	// to a control-plane/lighthouse host (reserved group, or — when configured — an
	// overlay IP inside the central reserved block) can never be blocklisted, no
	// matter the caller (severing the control plane would brick the fleet).
	ErrControlPlaneProtected = errors.New("revocation: refusing to blocklist a control-plane/lighthouse host")
)

// Bulk-revoke dual-control + rate-limit constants (7.2).
const (
	// BulkRevokeKind is the dual-control change kind for a bulk revoke. A bulk
	// revoke takes effect only via the maker-checker workflow (RegisterCommitter).
	BulkRevokeKind = "revocation.bulk-revoke"
	// MaxBulkFingerprints caps a single bulk operation's blast radius; larger sets
	// must be split into separate dual-controlled changes.
	MaxBulkFingerprints = 100
	// MaxBulkPerWindow is how many bulk revokes may commit within BulkWindow. The
	// count is durable (rows where bulk=1), so the limit survives restart/HA.
	MaxBulkPerWindow = 3
	// BulkWindow is the rolling window MaxBulkPerWindow applies over.
	BulkWindow = time.Hour
)

// Errors a bulk revoke can return (beyond ErrControlPlaneProtected).
var (
	ErrBulkEmpty       = errors.New("revocation: bulk revoke needs at least one fingerprint")
	ErrBulkTooLarge    = fmt.Errorf("revocation: bulk revoke exceeds the per-operation cap of %d fingerprints — split it into smaller dual-controlled changes", MaxBulkFingerprints)
	ErrBulkRateLimited = fmt.Errorf("revocation: too many bulk revokes in the last %s (max %d) — wait for the window to roll", BulkWindow, MaxBulkPerWindow)
)

// BulkRevokeSpec is the dual-control payload for a bulk revoke.
type BulkRevokeSpec struct {
	Fingerprints []string `json:"fingerprints"`
	Reason       string   `json:"reason"`
}

// Row is a registry record.
type Row struct {
	ID          int64  `gorm:"column:id;primaryKey"`
	Fingerprint string `gorm:"column:fingerprint"`
	Reason      string `gorm:"column:reason"`
	Bulk        bool   `gorm:"column:bulk"`
	State       string `gorm:"column:state"`
	CreatedBy   string `gorm:"column:created_by"`
	CreatedAt   int64  `gorm:"column:created_at"`
	UpdatedAt   int64  `gorm:"column:updated_at"`
}

// TableName pins the table.
func (Row) TableName() string { return "revocations" }

// AuditFunc appends one row to the hash-chained audit log.
type AuditFunc func(ctx context.Context, actor, action, target, details string) error

// Registry manages the cert blocklist.
type Registry struct {
	db      *gorm.DB
	audit   AuditFunc
	now     func() time.Time
	central netip.Prefix // optional belt-and-suspenders central block; zero/invalid = disabled
}

// New builds a Registry.
func New(db *gorm.DB, audit AuditFunc) *Registry {
	return &Registry{db: db, audit: audit, now: time.Now}
}

// WithCentralBlock enables the additive central-netblock guard: an Add whose
// resolved enrollment overlay IP falls inside p is refused (ErrControlPlaneProtected),
// mirroring the device reaper's central guard. The reserved-group check is the
// mandatory baseline regardless; this is belt-and-suspenders for hosts whose groups
// were somehow not written. A zero/invalid prefix (the default) disables it.
// Chainable.
func (r *Registry) WithCentralBlock(p netip.Prefix) *Registry { r.central = p; return r }

// normFingerprint canonicalizes a fingerprint to lowercase hex with no
// surrounding space, so the same cert always maps to one row (Nebula's
// Fingerprint() returns lowercase hex sha256).
func normFingerprint(fp string) string {
	return strings.ToLower(strings.TrimSpace(fp))
}

// Add blocklists a cert fingerprint. If a lifted row for the same fingerprint
// exists it is re-activated; an already-active fingerprint returns
// ErrAlreadyActive (idempotent-friendly: callers may treat it as success).
//
// Before any row is written, the ALWAYS-ON P10 guard runs (no flag, no caller
// opt-out): a fingerprint resolving to a control-plane/lighthouse host is refused
// with ErrControlPlaneProtected. See protectControlPlane for the resolution +
// fail-closed semantics.
func (r *Registry) Add(ctx context.Context, fingerprint, reason, actor string) (Row, error) {
	fp := normFingerprint(fingerprint)
	if fp == "" {
		return Row{}, ErrNoFingerprint
	}
	if err := r.protectControlPlane(ctx, fp); err != nil {
		return Row{}, err
	}
	return r.add(ctx, fp, reason, actor, false)
}

// add writes (or re-activates) one revocation row in its own transaction. It assumes
// the P10 guard has already run (Add + applyBulk both pre-validate), so it is the
// shared create path; bulk=true marks the row as part of a bulk revoke (7.2). The
// single-add path audits here; the bulk path uses addTx directly (inside the bulk tx)
// and audits once for the whole operation.
func (r *Registry) add(ctx context.Context, fp, reason, actor string, bulk bool) (Row, error) {
	var row Row
	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var aerr error
		row, aerr = r.addTx(ctx, tx, fp, reason, actor, bulk)
		return aerr
	})
	if err != nil {
		if errors.Is(err, ErrAlreadyActive) {
			return Row{}, err
		}
		return Row{}, fmt.Errorf("revocation: add: %w", err)
	}
	r.recordAudit(ctx, actor, "revocation-add", fp, fmt.Sprintf("reason=%q", reason))
	return row, nil
}

// addTx writes (or re-activates) one revocation row using the supplied transaction, so
// the bulk path can apply every fingerprint inside one enclosing tx (all-or-nothing).
// It does NOT audit — callers (add, applyBulk) record the audit row.
func (r *Registry) addTx(ctx context.Context, tx *gorm.DB, fp, reason, actor string, bulk bool) (Row, error) {
	now := r.now().UTC().UnixNano()
	var row Row
	switch err := tx.WithContext(ctx).First(&row, "fingerprint = ?", fp).Error; {
	case errors.Is(err, gorm.ErrRecordNotFound):
		row = Row{Fingerprint: fp, Reason: reason, Bulk: bulk, State: StateActive, CreatedBy: actor, CreatedAt: now, UpdatedAt: now}
		return row, tx.Create(&row).Error
	case err != nil:
		return Row{}, err
	}
	if row.State == StateActive {
		return Row{}, ErrAlreadyActive
	}
	// Re-activate a previously lifted revocation.
	row.State, row.Reason, row.Bulk, row.CreatedBy, row.UpdatedAt = StateActive, reason, bulk, actor, now
	return row, tx.Model(&Row{}).Where("fingerprint = ?", fp).Updates(map[string]any{
		"state": StateActive, "reason": reason, "bulk": bulk, "created_by": actor, "updated_at": now,
	}).Error
}

// protectControlPlane is the always-on P10 guard. It resolves fp to its latest
// issued enrollment and refuses (ErrControlPlaneProtected) if that host holds a
// reserved group (control-plane/lighthouse) or — when WithCentralBlock is set —
// an overlay IP inside the central reserved block. Semantics:
//   - unknown fingerprint (gorm.ErrRecordNotFound): ALLOW (not a known host) — nil;
//   - any other DB error: FAIL-CLOSED — refuse the revoke (don't blocklist when we
//     cannot confirm safety);
//   - else parse the groups (malformed → nil, safe) and apply the checks.
//
// It queries the enrollments table by raw name (no enrollment import — avoids an
// import cycle); revocation->policy is fine (policy does not import revocation).
func (r *Registry) protectControlPlane(ctx context.Context, fp string) error {
	var rec struct {
		Groups    string `gorm:"column:groups"`
		OverlayIP string `gorm:"column:overlay_ip"`
	}
	switch err := r.db.WithContext(ctx).Table("enrollments").
		Select("groups, overlay_ip").
		Where("fingerprint = ? AND status = ?", fp, "issued").
		Order("id DESC").First(&rec).Error; {
	case errors.Is(err, gorm.ErrRecordNotFound):
		return nil // not a known control-plane host
	case err != nil:
		// Fail closed: if we can't confirm the host is safe to block, refuse.
		return fmt.Errorf("revocation: control-plane guard: %w", err)
	}
	var groups []string
	_ = json.Unmarshal([]byte(rec.Groups), &groups) // malformed -> nil, safe
	if policy.GrantsReservedGroup(groups) {
		return ErrControlPlaneProtected
	}
	if r.central.IsValid() {
		if ip, err := netip.ParseAddr(rec.OverlayIP); err == nil && r.central.Contains(ip) {
			return ErrControlPlaneProtected
		}
	}
	return nil
}

// bulkRateLockKey is the fixed advisory-lock key bulk commits serialize on (Postgres
// only). An arbitrary constant — it just has to be the same for every bulk commit so
// the window-count + writes are mutually exclusive across HA committers.
const bulkRateLockKey int64 = 0x6275_6c6b_7265_76 // "bulkrev"

// applyBulk applies a validated bulk revoke as actor: normalize+dedup, enforce the
// per-operation cap and the durable per-window rate, PRE-VALIDATE the P10 guard for
// EVERY fingerprint up front (any control-plane fp rejects the WHOLE bulk — atomic,
// nothing applied), then write each as a bulk=true row. An individual fp that is
// already active is treated as success/skip (idempotent), not a failure.
//
// The window-rate check counts OPERATIONS (dual-control changes of kind
// BulkRevokeKind that have reached the committer — state committing/committed — within
// the window), NOT rows: one 100-fp bulk is ONE operation, so a single large bulk no
// longer self-trips the limit. The check AND the per-fingerprint writes run inside ONE
// transaction (so the whole bulk is all-or-nothing on a mid-loop DB error) serialized
// across concurrent HA committers by a fixed-key Postgres advisory xact lock (SQLite is
// single-writer already), closing the read-stale-count/all-pass TOCTOU.
func (r *Registry) applyBulk(ctx context.Context, spec BulkRevokeSpec, actor string) error {
	// 1. Normalize + de-dup (preserve order); reject empty.
	seen := make(map[string]bool, len(spec.Fingerprints))
	fps := make([]string, 0, len(spec.Fingerprints))
	for _, raw := range spec.Fingerprints {
		fp := normFingerprint(raw)
		if fp == "" || seen[fp] {
			continue
		}
		seen[fp] = true
		fps = append(fps, fp)
	}
	if len(fps) == 0 {
		return ErrBulkEmpty
	}
	// 2. Per-operation blast-radius cap.
	if len(fps) > MaxBulkFingerprints {
		return ErrBulkTooLarge
	}
	// 3. PRE-VALIDATE the P10 guard for EVERY fingerprint up front (outside the write tx
	// is fine — protectControlPlane only reads). If ANY is a control-plane host, reject
	// the whole bulk and apply NOTHING (atomic).
	for _, fp := range fps {
		if err := r.protectControlPlane(ctx, fp); err != nil {
			return err
		}
	}
	// 4. Rate-check + writes in ONE serialized transaction. The advisory lock makes the
	// count-then-write atomic against concurrent committers (no TOCTOU); the tx makes the
	// per-fingerprint writes all-or-nothing.
	applied := 0
	windowStart := r.now().UTC().Add(-BulkWindow).UnixNano()
	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if r.db.Name() == "postgres" {
			// Serialize concurrent bulk commits so they can't all read a stale count and
			// all pass. Held until the tx commits/rolls back. SQLite needs no lock (its
			// single writer already serializes).
			if err := tx.Exec("SELECT pg_advisory_xact_lock(?)", bulkRateLockKey).Error; err != nil {
				return fmt.Errorf("revocation: bulk rate lock: %w", err)
			}
		}
		// Count OPERATIONS in the window: dual-control bulk-revoke changes that reached the
		// committer (committing or committed). This is the natural per-op ledger; counting
		// revocation rows would count fingerprints, wrongly tripping after one large bulk.
		//
		// applyBulk runs AS the committer, so the CURRENT op's own change row is already in
		// state 'committing' and IS included in this count (also why concurrent in-flight
		// committers see each other — the TOCTOU we serialize on). The current op therefore
		// makes inWindow == prior-ops + 1, so the limit is "> MaxBulkPerWindow": the
		// MaxBulkPerWindow-th op (count == MaxBulkPerWindow) is allowed, the next is refused.
		var inWindow int64
		if err := tx.Table("approvals").
			Where("kind = ? AND state IN ? AND created_at >= ?",
				BulkRevokeKind, []string{string(dualcontrol.StateCommitting), string(dualcontrol.StateCommitted)}, windowStart).
			Count(&inWindow).Error; err != nil {
			return fmt.Errorf("revocation: bulk rate check: %w", err)
		}
		if inWindow > int64(MaxBulkPerWindow) {
			return ErrBulkRateLimited
		}
		// Apply each as a bulk row within this tx. ErrAlreadyActive on an individual fp is a skip.
		for _, fp := range fps {
			switch _, err := r.addTx(ctx, tx, fp, spec.Reason, actor, true); {
			case errors.Is(err, ErrAlreadyActive):
				// already blocklisted — idempotent skip, not a failure
			case err != nil:
				return fmt.Errorf("revocation: bulk apply %s: %w", fp, err)
			default:
				applied++
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	r.recordAudit(ctx, actor, "revocation-bulk", BulkRevokeKind,
		fmt.Sprintf("applied=%d requested=%d reason=%q", applied, len(fps), spec.Reason))
	return nil
}

// RegisterCommitter installs the bulk-revoke commit-time committer on dc, mirroring
// internal/cloudtrust.RegisterCommitter: at commit it re-unmarshals the change
// payload into a BulkRevokeSpec and calls reg.applyBulk (which re-validates the cap,
// rate, and P10 guard — defense in depth). The proposer is recorded as the actor.
func RegisterCommitter(dc *dualcontrol.Controller, reg *Registry) {
	dc.Register(BulkRevokeKind, func(ctx context.Context, ch dualcontrol.Change) error {
		var spec BulkRevokeSpec
		if err := json.Unmarshal(ch.Payload, &spec); err != nil {
			return fmt.Errorf("revocation: bulk payload: %w", err)
		}
		return reg.applyBulk(ctx, spec, ch.Proposer)
	})
}

// Lift removes a fingerprint from the active blocklist (kept as state='lifted'
// for audit/history). Idempotent: lifting an unknown or already-lifted
// fingerprint is a no-op (no audit row). Use with care — lifting un-revokes a
// host the fleet was refusing.
func (r *Registry) Lift(ctx context.Context, fingerprint, actor string) error {
	fp := normFingerprint(fingerprint)
	if fp == "" {
		return ErrNoFingerprint
	}
	changed := false
	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var row Row
		switch err := tx.First(&row, "fingerprint = ?", fp).Error; {
		case errors.Is(err, gorm.ErrRecordNotFound):
			return nil // never blocklisted; nothing to lift
		case err != nil:
			return err
		}
		if row.State == StateLifted {
			return nil // already lifted
		}
		changed = true
		return tx.Model(&Row{}).Where("fingerprint = ?", fp).
			Updates(map[string]any{"state": StateLifted, "updated_at": r.now().UTC().UnixNano()}).Error
	})
	if err != nil {
		return fmt.Errorf("revocation: lift: %w", err)
	}
	if changed {
		r.recordAudit(ctx, actor, "revocation-lift", fp, "")
	}
	return nil
}

// ActiveFingerprints returns the active blocklist as a sorted slice of
// fingerprints — sorted so an unchanged blocklist yields a byte-identical bundle
// and never trips drift-revert (6.7/6.8). This is the BlocklistSource Core
// consults at bundle-build time.
func (r *Registry) ActiveFingerprints(ctx context.Context) ([]string, error) {
	var fps []string
	if err := r.db.WithContext(ctx).Model(&Row{}).
		Where("state = ?", StateActive).
		Order("fingerprint ASC").Pluck("fingerprint", &fps).Error; err != nil {
		return nil, fmt.Errorf("revocation: active: %w", err)
	}
	sort.Strings(fps) // belt-and-suspenders: guarantee deterministic order
	return fps, nil
}

// List returns every registry row (including lifted), newest first.
func (r *Registry) List(ctx context.Context) ([]Row, error) {
	var rows []Row
	if err := r.db.WithContext(ctx).Order("id DESC").Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("revocation: list: %w", err)
	}
	return rows, nil
}

func (r *Registry) recordAudit(ctx context.Context, actor, action, target, details string) {
	if r.audit == nil {
		return
	}
	_ = r.audit(ctx, actor, action, target, details)
}
