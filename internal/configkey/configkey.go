// Package configkey is Harbor's config-signing-key trust registry and lifecycle state machine
// (design §4.6/§4.8, implementation-plan M8.5). The config-signing key signs the JWS config bundle
// that Pilot PINS and verifies before trusting anything inside; it is a co-equal TCB root, DISTINCT
// from the CA. Online rotation works the identical way CA rotation does (internal/ca): stage K2
// (trusted — it enters every bundle's config_signing_keys), distribute [K1, K2] trust to every host
// and confirm 100% adoption, cut signing over to K2 (active), then retire K1 once the whole LIVE
// fleet trusts the new active key.
//
// This package owns the durable registry of config-signing keys and the legal transitions:
//
//	(new) --Stage--> staged --Activate--> active --(Activate of another)--> draining --Retire--> retired
//	                 staged --Abandon--> retired
//
// The invariants that make rotation safe live here, not in callers:
//   - AT MOST ONE active key (the signing key) — also enforced at the DB layer by a partial unique
//     index, so a racing cut-over can never leave two;
//   - TRUST BEFORE YOU SIGN — TrustedKeys() returns every NON-RETIRED key (staged+active+draining),
//     so a staged key is trusted fleet-wide (advertised in the bundle) before it ever signs;
//   - a key cannot be RETIRED until the whole live fleet trusts the ACTIVE key (Retire is gated on
//     AdoptionStatus(active).FullyAdopted, fail-closed) — dropping a key the fleet still needs to
//     verify a just-fetched bundle would strand it, and unlike a CA there is no per-leaf expiry to
//     bound the drain, so drain == adoption-inverse.
//
// Unlike ca.CA a row holds a RAW P256 PUBLIC KEY (not a cert) and has NO not_after (a bare pubkey
// never expires); its fingerprint is wire.PubkeyHash(pub) = base64url(sha256(pub)) — the SAME value
// stamped as the JWS Kid, so what the registry stores, what signs a bundle, and what a pilot reports
// as trusted are all byte-identical. base64url is CASE-SENSITIVE, so fingerprints are matched exactly
// (not case-folded like the hex CA fingerprints).
package configkey

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/slackhq/nebula/cert"
	"gorm.io/gorm"

	"github.com/jeks313/nebula-control-plane/internal/ca"
	"github.com/jeks313/nebula-control-plane/internal/jws"
	"github.com/jeks313/nebula-control-plane/internal/wire"
)

// State is a config-signing key's lifecycle state.
type State string

// The config-signing key lifecycle states (design §4.6/§4.8).
const (
	StateStaged   State = "staged"   // trusted (advertised in the bundle) but not yet signing
	StateActive   State = "active"   // the current signing key (at most one)
	StateDraining State = "draining" // no longer signing; still trusted while the fleet moves to the new active key
	StateRetired  State = "retired"  // distrusted; out of the trust set; eligible for key deletion
)

// KeyDeleter and NoopKeyDeleter are reused verbatim from the CA package (the KMS
// schedule/cancel-deletion contract is identical for a config-signing key).
type (
	KeyDeleter     = ca.KeyDeleter
	NoopKeyDeleter = ca.NoopKeyDeleter
)

// Errors callers can branch on.
var (
	ErrNotFound          = errors.New("configkey: no such config-signing key")
	ErrInvalidPub        = errors.New("configkey: PEM is not a valid P256 config-signing public key")
	ErrDuplicate         = errors.New("configkey: a key with that name or fingerprint already exists")
	ErrEmptyName         = errors.New("configkey: name is required")
	ErrIllegalTransition = errors.New("configkey: illegal state transition")
	ErrNotDrained        = errors.New("configkey: refusing to retire — the live fleet has not fully adopted the active key")
	ErrNoActive          = errors.New("configkey: no active config-signing key")
)

// ConfigKey is one config-signing key in the rotation lifecycle.
type ConfigKey struct {
	ID          int64  `gorm:"column:id;primaryKey"`
	Name        string `gorm:"column:name"`
	Fingerprint string `gorm:"column:fingerprint"` // wire.PubkeyHash(pub); also the JWS Kid (case-sensitive base64url)
	PubPEM      string `gorm:"column:pub_pem"`     // SubjectPublicKeyInfo PEM of the P256 public key
	// KMSKeyID names how to reach this key's signing backend (KMS ARN / PKCS#11 URI / "software").
	// Empty means trust-only (imported to trust, never to sign here).
	KMSKeyID  string `gorm:"column:kms_key_id"`
	State     State  `gorm:"column:state"`
	CreatedBy string `gorm:"column:created_by"`
	CreatedAt int64  `gorm:"column:created_at"` // unix ns
	UpdatedAt int64  `gorm:"column:updated_at"` // unix ns
	// KeyDeletionScheduledAt/Date record that a RETIRED key's signing key has been scheduled for
	// deletion in its custody backend (KMS) — mirrors ca (M8.4). Both 0 -> not scheduled.
	KeyDeletionScheduledAt int64 `gorm:"column:key_deletion_scheduled_at"` // unix ns; 0 = not scheduled
	KeyDeletionDate        int64 `gorm:"column:key_deletion_date"`         // unix ns; backend-returned deletion date
}

// TableName pins the table.
func (ConfigKey) TableName() string { return "config_signing_keys" }

// AuditFunc appends one row to the hash-chained audit log.
type AuditFunc func(ctx context.Context, actor, action, target, details string) error

// Registry manages the config-signing-key lifecycle.
type Registry struct {
	db    *gorm.DB
	audit AuditFunc
	now   func() time.Time
}

// New builds a Registry.
func New(db *gorm.DB, audit AuditFunc) *Registry {
	return &Registry{db: db, audit: audit, now: time.Now}
}

// parseConfigPub validates that pem is a P256 config-signing PUBLIC key and returns its fingerprint
// (wire.PubkeyHash of the uncompressed point — identical to the JWS Kid). Rejecting a non-P256 /
// unparseable / off-curve key here keeps a bad root out of the trust set at the write path.
func parseConfigPub(pem string) (fingerprint string, err error) {
	pub, _, curve, perr := cert.UnmarshalPublicKeyFromPEM([]byte(pem))
	if perr != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidPub, perr)
	}
	if curve != cert.Curve_P256 {
		return "", fmt.Errorf("%w: curve is %s, only P256 is supported", ErrInvalidPub, curve)
	}
	if _, perr := jws.ParseP256PublicPoint(pub); perr != nil { // ensure it is a real curve point, not garbage
		return "", fmt.Errorf("%w: %v", ErrInvalidPub, perr)
	}
	return wire.PubkeyHash(pub), nil
}

// Stage registers a new config-signing key in the `staged` state: trusted (it enters TrustedKeys
// immediately, so every bundle advertises it) but not yet signing. This is the "mint K2 / trust
// before you sign" step. name is a human label; kmsKeyID names its signing backend (empty =
// trust-only). A duplicate name or fingerprint is rejected.
func (r *Registry) Stage(ctx context.Context, name, pubPEM, kmsKeyID, actor string) (ConfigKey, error) {
	if name == "" {
		return ConfigKey{}, ErrEmptyName
	}
	fp, err := parseConfigPub(pubPEM)
	if err != nil {
		return ConfigKey{}, err
	}
	now := r.now().UTC().UnixNano()
	row := ConfigKey{
		Name: name, Fingerprint: fp, PubPEM: pubPEM, KMSKeyID: kmsKeyID,
		State: StateStaged, CreatedBy: actor, CreatedAt: now, UpdatedAt: now,
	}
	if err := r.db.WithContext(ctx).Create(&row).Error; err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			return ConfigKey{}, fmt.Errorf("%w: %s", ErrDuplicate, name)
		}
		return ConfigKey{}, fmt.Errorf("configkey: stage: %w", err)
	}
	r.recordAudit(ctx, actor, "configkey-stage", name, fmt.Sprintf(`{"fingerprint":%q,"kms_key_id":%q}`, fp, kmsKeyID))
	return row, nil
}

// Activate cuts signing over to the key with id: it must be `staged`, the current `active` key (if
// any) is demoted to `draining`, and the target becomes `active` — all in one transaction so there
// is never a window with zero or two active keys. The partial unique index is the belt-and-
// suspenders backstop against a concurrent activate.
//
// NOTE: the "confirm 100% trust adoption before cut-over" gate is enforced by the CALLER (the
// admin/CLI layer) before invoking Activate; this primitive performs the atomic transition itself.
func (r *Registry) Activate(ctx context.Context, id int64, actor string) error {
	now := r.now().UTC().UnixNano()
	var demoted string
	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var target ConfigKey
		if err := tx.First(&target, "id = ?", id).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrNotFound
			}
			return err
		}
		if target.State != StateStaged {
			return fmt.Errorf("%w: %s -> active (only a staged key can be activated)", ErrIllegalTransition, target.State)
		}
		// Demote the current active key (if any) to draining.
		var cur ConfigKey
		switch err := tx.First(&cur, "state = ?", StateActive).Error; {
		case err == nil:
			if e := tx.Model(&ConfigKey{}).Where("id = ? AND state = ?", cur.ID, StateActive).
				Updates(map[string]any{"state": StateDraining, "updated_at": now}).Error; e != nil {
				return e
			}
			demoted = cur.Name
		case errors.Is(err, gorm.ErrRecordNotFound):
			// first activation — no prior active key
		default:
			return err
		}
		// Promote the target, guarded by its still being staged (CAS) so two racing activates cannot both win.
		res := tx.Model(&ConfigKey{}).Where("id = ? AND state = ?", id, StateStaged).
			Updates(map[string]any{"state": StateActive, "updated_at": now})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return fmt.Errorf("%w: staged -> active (lost a concurrent transition)", ErrIllegalTransition)
		}
		return nil
	})
	if err != nil {
		return err
	}
	r.recordAudit(ctx, actor, "configkey-activate", fmt.Sprintf("id=%d", id), fmt.Sprintf(`{"demoted_to_draining":%q}`, demoted))
	return nil
}

// Retire moves a `draining` key to `retired` (out of the trust set, eligible for key deletion), but
// ONLY once the whole LIVE fleet trusts the ACTIVE key — i.e. every host has adopted the new signing
// key, so dropping this one from the advertised trust set can strand nobody. The gate is FAIL-CLOSED:
// an unknown adoption count, or no active key, never permits a retire that could brick hosts. Unlike
// a CA there is no per-leaf drain; drain == the inverse of AdoptionStatus(active) (design §4.6/§4.8).
func (r *Registry) Retire(ctx context.Context, id int64, staleAfter time.Duration, actor string) error {
	target, err := r.Get(ctx, id)
	if err != nil {
		return err // ErrNotFound or a read error
	}
	if target.State != StateDraining {
		return fmt.Errorf("%w: %s -> retired (only a draining key can be retired)", ErrIllegalTransition, target.State)
	}
	laggards, derr := r.DrainLaggards(ctx, staleAfter)
	if derr != nil {
		return derr // fail closed — never retire on an unknown adoption count / no active key
	}
	if laggards > 0 {
		return fmt.Errorf("%w: %d live host(s) not yet on the active key", ErrNotDrained, laggards)
	}
	now := r.now().UTC().UnixNano()
	// CAS on state=draining guards a concurrent transition.
	res := r.db.WithContext(ctx).Model(&ConfigKey{}).Where("id = ? AND state = ?", id, StateDraining).
		Updates(map[string]any{"state": StateRetired, "updated_at": now})
	if res.Error != nil {
		return fmt.Errorf("configkey: retire: %w", res.Error)
	}
	if res.RowsAffected == 0 {
		return fmt.Errorf("%w: draining -> retired (no longer draining)", ErrIllegalTransition)
	}
	r.recordAudit(ctx, actor, "configkey-retire", fmt.Sprintf("id=%d", id), fmt.Sprintf(`{"drain_laggards":%d}`, laggards))
	return nil
}

// Abandon cancels a `staged` key that was never activated (staged -> retired), e.g. a mistaken or
// superseded stage. Only a staged key can be abandoned.
func (r *Registry) Abandon(ctx context.Context, id int64, actor string) error {
	now := r.now().UTC().UnixNano()
	res := r.db.WithContext(ctx).Model(&ConfigKey{}).Where("id = ? AND state = ?", id, StateStaged).
		Updates(map[string]any{"state": StateRetired, "updated_at": now})
	if res.Error != nil {
		return fmt.Errorf("configkey: abandon: %w", res.Error)
	}
	if res.RowsAffected == 0 {
		var target ConfigKey
		if err := r.db.WithContext(ctx).First(&target, "id = ?", id).Error; errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrNotFound
		}
		return fmt.Errorf("%w: only a staged key can be abandoned", ErrIllegalTransition)
	}
	r.recordAudit(ctx, actor, "configkey-abandon", fmt.Sprintf("id=%d", id), "")
	return nil
}

// Active returns the current signing key, or ErrNoActive if none is active.
func (r *Registry) Active(ctx context.Context) (ConfigKey, error) {
	var row ConfigKey
	switch err := r.db.WithContext(ctx).First(&row, "state = ?", StateActive).Error; {
	case errors.Is(err, gorm.ErrRecordNotFound):
		return ConfigKey{}, ErrNoActive
	case err != nil:
		return ConfigKey{}, fmt.Errorf("configkey: active: %w", err)
	}
	return row, nil
}

// ActiveFingerprint returns the current signing key's fingerprint, or "" (no error) when none is
// active. Lets the adoption/drain paths recognize the active key without importing the sentinels.
func (r *Registry) ActiveFingerprint(ctx context.Context) (string, error) {
	c, err := r.Active(ctx)
	if err != nil {
		if errors.Is(err, ErrNoActive) {
			return "", nil
		}
		return "", err
	}
	return c.Fingerprint, nil
}

// TrustedKeys returns the config-signing PUBLIC-key PEMs the fleet must trust: every NON-RETIRED key
// (staged + active + draining), sorted by fingerprint so an unchanged trust set yields a byte-
// identical list (no false churn). This is the source Core renders into every host bundle's
// config_signing_keys — "trust before you sign".
func (r *Registry) TrustedKeys(ctx context.Context) ([]string, error) {
	var rows []ConfigKey
	if err := r.db.WithContext(ctx).
		Where("state != ?", StateRetired).
		Order("fingerprint ASC").Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("configkey: trusted keys: %w", err)
	}
	out := make([]string, 0, len(rows))
	for _, c := range rows {
		out = append(out, c.PubPEM)
	}
	sort.Strings(out) // belt-and-suspenders: guarantee deterministic order
	return out, nil
}

// Generation returns a monotonic token that bumps whenever the trust set changes — MAX(updated_at)
// across all rows (unix ns), or 0 when the registry is empty. Core stamps it into the bundle as
// ConfigKeyVersion; Pilot uses it to fail-SAFE against a replayed OLD bundle regressing its learned
// trusted set (it only ever adopts the set from a bundle whose ConfigKeyVersion is not older than the
// last it applied). Because every mutate sets updated_at = now, a stage/activate/retire always
// advances it; a spurious backwards clock only makes Pilot keep its last-good set (safe).
func (r *Registry) Generation(ctx context.Context) (int64, error) {
	var max *int64
	if err := r.db.WithContext(ctx).Model(&ConfigKey{}).Select("MAX(updated_at)").Scan(&max).Error; err != nil {
		return 0, fmt.Errorf("configkey: generation: %w", err)
	}
	if max == nil {
		return 0, nil
	}
	return *max, nil
}

// List returns every config-signing key row (all states), newest first.
func (r *Registry) List(ctx context.Context) ([]ConfigKey, error) {
	var rows []ConfigKey
	if err := r.db.WithContext(ctx).Order("id DESC").Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("configkey: list: %w", err)
	}
	return rows, nil
}

// Get returns one config-signing key by id.
func (r *Registry) Get(ctx context.Context, id int64) (ConfigKey, error) {
	var row ConfigKey
	switch err := r.db.WithContext(ctx).First(&row, "id = ?", id).Error; {
	case errors.Is(err, gorm.ErrRecordNotFound):
		return ConfigKey{}, ErrNotFound
	case err != nil:
		return ConfigKey{}, fmt.Errorf("configkey: get: %w", err)
	}
	return row, nil
}

// SeedActive records pubPEM as the single `active` config-signing key IF the registry is empty. It is
// the idempotent boot-seed that carries a pre-M8.5 deployment's existing config-signing key (the
// genesis key, derived from -config-pub / the backend) into the registry on first boot after migration
// 000037, so TrustedKeys/Active reflect reality with no manual step. Returns (row, seeded, err);
// seeded=false (with the existing active row) when the table already has any key. Race-tolerant.
func (r *Registry) SeedActive(ctx context.Context, name, pubPEM, kmsKeyID, actor string) (ConfigKey, bool, error) {
	fp, err := parseConfigPub(pubPEM)
	if err != nil {
		return ConfigKey{}, false, err
	}
	var n int64
	if err := r.db.WithContext(ctx).Model(&ConfigKey{}).Count(&n).Error; err != nil {
		return ConfigKey{}, false, fmt.Errorf("configkey: seed active: %w", err)
	}
	if n > 0 {
		return r.activeOrEmpty(ctx), false, nil
	}
	now := r.now().UTC().UnixNano()
	out := ConfigKey{
		Name: name, Fingerprint: fp, PubPEM: pubPEM, KMSKeyID: kmsKeyID,
		State: StateActive, CreatedBy: actor, CreatedAt: now, UpdatedAt: now,
	}
	if err := r.db.WithContext(ctx).Create(&out).Error; err != nil {
		// Lost a concurrent boot-seed (another process inserted first): the unique name / one-active
		// index rejected us. Treat as already-seeded and return the winner (race-tolerant).
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			return r.activeOrEmpty(ctx), false, nil
		}
		return ConfigKey{}, false, fmt.Errorf("configkey: seed active: %w", err)
	}
	r.recordAudit(ctx, actor, "configkey-seed-active", name, fmt.Sprintf(`{"fingerprint":%q}`, fp))
	return out, true, nil
}

// activeOrEmpty returns the current active key, or the zero value if none/unreadable (best-effort).
func (r *Registry) activeOrEmpty(ctx context.Context) ConfigKey {
	var out ConfigKey
	_ = r.db.WithContext(ctx).First(&out, "state = ?", StateActive).Error
	return out
}

func (r *Registry) recordAudit(ctx context.Context, actor, action, target, details string) {
	if r.audit == nil {
		return
	}
	_ = r.audit(ctx, actor, action, target, details)
}

// Adoption is a point-in-time config-key-trust snapshot for one key (design §4.6/§4.8): of the LIVE
// hosts, how many confirm — via their heartbeat-reported trusted_config_keys — that they trust this
// key. It answers the "100% of live hosts trust the staged key" gate that must precede a cut-over
// (Activate) and, applied to the ACTIVE key, the drain gate that precedes Retire. Stale hosts are
// excluded from the gate population and surfaced only.
type Adoption struct {
	Fingerprint string   // base64url wire.PubkeyHash (case-sensitive)
	Live        int      // hosts heartbeated within staleAfter (the gate population)
	Adopted     int      // live hosts confirming trust of Fingerprint
	Laggards    []string // live overlay IPs NOT yet confirming (sorted) — these block the gate
	Stale       []string // overlay IPs beyond the freshness window (sorted) — EXCLUDED from the gate
}

// FullyAdopted reports whether every LIVE host confirms trust. An empty live fleet is vacuously
// adopted (nothing to strand), so a bootstrap / first-key activate is not chicken-and-egg blocked.
func (a Adoption) FullyAdopted() bool { return len(a.Laggards) == 0 }

// AdoptionStatus is the cut-over/drain gate query. LIVE = last_seen >= now-staleAfter (the same
// freshness window the fleet/reaper/IPAM code uses); staleAfter <= 0 means every heartbeated host
// counts as live. A live host reporting no / empty / malformed trusted_config_keys is a LAGGARD
// (fail-closed: unconfirmed == not adopted). Matches EXACTLY (base64url is case-sensitive — NOT
// case-folded like the hex CA fingerprints). Reads the heartbeats table by RAW NAME (no coreapi
// import) and parses the JSON in Go (dialect-portable; the fleet is small at gate time).
func (r *Registry) AdoptionStatus(ctx context.Context, fingerprint string, staleAfter time.Duration) (Adoption, error) {
	fp := strings.TrimSpace(fingerprint)
	out := Adoption{Fingerprint: fp, Laggards: []string{}, Stale: []string{}}

	var rows []struct {
		OverlayIP         string `gorm:"column:overlay_ip"`
		LastSeen          int64  `gorm:"column:last_seen"`
		TrustedConfigKeys string `gorm:"column:trusted_config_keys"`
	}
	if err := r.db.WithContext(ctx).Table("heartbeats").
		Select("overlay_ip, last_seen, trusted_config_keys").Find(&rows).Error; err != nil {
		return Adoption{}, fmt.Errorf("configkey: adoption status: %w", err)
	}

	all := staleAfter <= 0 // 0 -> every heartbeated host is live
	cutoff := r.now().UnixNano() - staleAfter.Nanoseconds()
	for _, h := range rows {
		if !all && h.LastSeen < cutoff {
			out.Stale = append(out.Stale, h.OverlayIP)
			continue
		}
		out.Live++
		var trusted []string
		_ = json.Unmarshal([]byte(h.TrustedConfigKeys), &trusted) // '' / 'null' / malformed -> nil -> laggard
		if containsExact(trusted, fp) {
			out.Adopted++
		} else {
			out.Laggards = append(out.Laggards, h.OverlayIP)
		}
	}
	sort.Strings(out.Laggards)
	sort.Strings(out.Stale)
	return out, nil
}

// DrainLaggards returns how many LIVE hosts have NOT yet adopted the ACTIVE key — the drain remaining
// that gates Retire (design §4.6/§4.8). Fail-closed: no active key, or an unreadable heartbeats table,
// returns an error (never a spurious 0). A silent/offline host is excluded from the LIVE population
// and so cannot block the drain forever (the operator reaps it or -force's the retire); a host that IS
// live but not yet on the active key correctly blocks retire.
func (r *Registry) DrainLaggards(ctx context.Context, staleAfter time.Duration) (int, error) {
	activeFp, err := r.ActiveFingerprint(ctx)
	if err != nil {
		return 0, err
	}
	if activeFp == "" {
		return 0, ErrNoActive // cannot certify a drain with no active key — fail closed
	}
	ad, err := r.AdoptionStatus(ctx, activeFp, staleAfter)
	if err != nil {
		return 0, err
	}
	return len(ad.Laggards), nil
}

// ScheduleKeyDeletion schedules a RETIRED config-signing key's signing key for deletion in its custody
// backend (mirrors ca, M8.4). Guardrails, fail-closed: ONLY a retired key (an active/draining/staged
// key still signs or is still trusted), only when it has a real key backend (kms_key_id set; a
// trust-only import has nothing to delete), a 7-30 day KMS window, no double-schedule. A retired key
// is not in any host's active trust path (Retire already required 100% adoption of the new active key),
// so no live-dependent recheck is needed here — retirement IS the drain gate. The backend is called
// FIRST and the state persisted only if it accepted; on a persist failure the backend deletion is
// rolled back (best-effort) so we never leave a key silently pending deletion that our state does not
// record. Audited.
func (r *Registry) ScheduleKeyDeletion(ctx context.Context, id int64, pendingDays int32, deleter KeyDeleter, actor string) (time.Time, error) {
	if deleter == nil {
		return time.Time{}, fmt.Errorf("configkey: schedule key deletion: a KeyDeleter is required")
	}
	if pendingDays < 7 || pendingDays > 30 {
		return time.Time{}, fmt.Errorf("configkey: schedule key deletion: pending window must be 7-30 days (KMS limit), got %d", pendingDays)
	}
	target, err := r.Get(ctx, id)
	if err != nil {
		return time.Time{}, err
	}
	if target.State != StateRetired {
		return time.Time{}, fmt.Errorf("%w: only a RETIRED key may be scheduled for deletion (state %s)", ErrIllegalTransition, target.State)
	}
	if strings.TrimSpace(target.KMSKeyID) == "" {
		return time.Time{}, fmt.Errorf("configkey: schedule key deletion: key %d has no backend (trust-only import); nothing to delete", id)
	}
	if target.KeyDeletionScheduledAt != 0 {
		return time.Time{}, fmt.Errorf("configkey: key deletion already scheduled for key %d (cancel first to reschedule)", id)
	}
	delDate, err := deleter.ScheduleDeletion(ctx, target.KMSKeyID, pendingDays)
	if err != nil {
		return time.Time{}, fmt.Errorf("configkey: schedule key deletion: %w", err)
	}
	now := r.now().UTC().UnixNano()
	res := r.db.WithContext(ctx).Model(&ConfigKey{}).Where("id = ? AND state = ? AND key_deletion_scheduled_at = 0", id, StateRetired).
		Updates(map[string]any{"key_deletion_scheduled_at": now, "key_deletion_date": delDate.UTC().UnixNano(), "updated_at": now})
	if res.Error != nil || res.RowsAffected == 0 {
		rb := ""
		if cerr := deleter.CancelDeletion(ctx, target.KMSKeyID); cerr != nil {
			rb = fmt.Sprintf(" — ROLLBACK FAILED (key %s is pending deletion in the backend; cancel it directly): %v", target.KMSKeyID, cerr)
		}
		if res.Error != nil {
			return time.Time{}, fmt.Errorf("configkey: schedule key deletion persist%s: %w", rb, res.Error)
		}
		return time.Time{}, fmt.Errorf("%w: retired -> key-deletion (raced; rolled back backend)%s", ErrIllegalTransition, rb)
	}
	r.recordAudit(ctx, actor, "configkey-key-deletion-scheduled", fmt.Sprintf("id=%d", id),
		fmt.Sprintf(`{"kms_key_id":%q,"deletion_date":%q,"pending_days":%d}`, target.KMSKeyID, delDate.UTC().Format(time.RFC3339), pendingDays))
	return delDate, nil
}

// CancelKeyDeletion aborts a config-signing key's pending key deletion during the backend's window,
// clearing the recorded schedule and restoring the key to usable (mirrors ca). Idempotent guard:
// refuses if none is scheduled. Audited.
func (r *Registry) CancelKeyDeletion(ctx context.Context, id int64, deleter KeyDeleter, actor string) error {
	if deleter == nil {
		return fmt.Errorf("configkey: cancel key deletion: a KeyDeleter is required")
	}
	target, err := r.Get(ctx, id)
	if err != nil {
		return err
	}
	if target.KeyDeletionScheduledAt == 0 {
		return fmt.Errorf("configkey: no key deletion scheduled for key %d", id)
	}
	if err := deleter.CancelDeletion(ctx, target.KMSKeyID); err != nil {
		return fmt.Errorf("configkey: cancel key deletion: %w", err)
	}
	now := r.now().UTC().UnixNano()
	res := r.db.WithContext(ctx).Model(&ConfigKey{}).Where("id = ?", id).
		Updates(map[string]any{"key_deletion_scheduled_at": 0, "key_deletion_date": 0, "updated_at": now})
	if res.Error != nil {
		return fmt.Errorf("configkey: cancel key deletion persist: %w", res.Error)
	}
	if res.RowsAffected == 0 {
		return ErrNotFound
	}
	r.recordAudit(ctx, actor, "configkey-key-deletion-cancelled", fmt.Sprintf("id=%d", id), "{}")
	return nil
}

// PendingKeyDeletions lists config-signing keys whose signing key is scheduled for deletion, oldest
// schedule first. Backs the pending-deletion metric (the alarm signal) and the `config-key list` display.
func (r *Registry) PendingKeyDeletions(ctx context.Context) ([]ConfigKey, error) {
	var rows []ConfigKey
	if err := r.db.WithContext(ctx).Where("key_deletion_scheduled_at > 0").
		Order("key_deletion_date ASC").Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("configkey: pending key deletions: %w", err)
	}
	return rows, nil
}

// containsExact reports whether fps contains fp, matched EXACTLY (base64url is case-sensitive).
func containsExact(fps []string, fp string) bool {
	for _, x := range fps {
		if strings.TrimSpace(x) == fp {
			return true
		}
	}
	return false
}
