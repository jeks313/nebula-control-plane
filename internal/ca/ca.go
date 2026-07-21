// Package ca is Harbor's CA trust-root registry and lifecycle state machine (design
// §4.6, implementation-plan M8). Online CA rotation works because Nebula hosts trust a
// BUNDLE of CA certs: mint CA2 (staged), distribute [CA1, CA2] trust to every host and
// confirm 100% adoption, cut signing over to CA2 (active), let leaf certs drain onto CA2
// as they renew, then retire CA1 once it has no live dependents.
//
// This package owns the durable registry of CAs and the legal transitions between their
// states:
//
//	(new) --Stage--> staged --Activate--> active --(Activate of another)--> draining --Retire--> retired
//	                 staged --Abandon--> retired
//
// The invariants that make rotation safe live here, not in callers:
//   - AT MOST ONE active CA (the signing CA) — also enforced at the DB layer by a partial
//     unique index, so a racing cut-over can never leave two;
//   - TRUST BEFORE YOU SIGN — TrustBundle() returns every NON-RETIRED CA
//     (staged+active+draining), so a staged CA is trusted fleet-wide before it ever signs;
//   - a CA with LIVE DEPENDENTS cannot be retired (Retire refuses while leaf certs still
//     chain to it — the caller supplies the live-dependent count, drain tracking is M8.3).
//
// Signing itself is unchanged: the Signer signs new leaves with the ACTIVE CA's backend;
// cut-over is just which row is active. The same machinery rotates the config-signing key
// (M8.5) by the identical staged→active→draining→retired overlap.
package ca

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/slackhq/nebula/cert"
	"gorm.io/gorm"
)

// State is a CA's lifecycle state.
type State string

// The CA lifecycle states (design §4.6).
const (
	StateStaged   State = "staged"   // trusted (in the bundle) but not yet signing
	StateActive   State = "active"   // the current signing CA (at most one)
	StateDraining State = "draining" // no longer signing; still trusted while its leaves live
	StateRetired  State = "retired"  // distrusted; out of the bundle; eligible for key deletion
)

// Errors callers can branch on.
var (
	ErrNotFound          = errors.New("ca: no such CA")
	ErrInvalidCert       = errors.New("ca: PEM is not a valid P256 CA certificate")
	ErrDuplicate         = errors.New("ca: a CA with that name or fingerprint already exists")
	ErrEmptyName         = errors.New("ca: name is required")
	ErrIllegalTransition = errors.New("ca: illegal state transition")
	ErrHasDependents     = errors.New("ca: refusing to retire a CA with live dependents (leaf certs still chain to it)")
	ErrNoActive          = errors.New("ca: no active CA")
)

// CA is one CA in the rotation lifecycle.
type CA struct {
	ID          int64  `gorm:"column:id;primaryKey"`
	Name        string `gorm:"column:name"`
	Fingerprint string `gorm:"column:fingerprint"`
	CertPEM     string `gorm:"column:cert_pem"`
	// KMSKeyID names how to reach this CA's signing backend (KMS ARN / PKCS#11 URI /
	// "software"). Empty means trust-only (imported to trust, never to sign here).
	KMSKeyID  string `gorm:"column:kms_key_id"`
	State     State  `gorm:"column:state"`
	NotAfter  int64  `gorm:"column:not_after"` // unix ns
	CreatedBy string `gorm:"column:created_by"`
	CreatedAt int64  `gorm:"column:created_at"` // unix ns
	UpdatedAt int64  `gorm:"column:updated_at"` // unix ns
}

// TableName pins the table.
func (CA) TableName() string { return "ca_certs" }

// AuditFunc appends one row to the hash-chained audit log.
type AuditFunc func(ctx context.Context, actor, action, target, details string) error

// Registry manages the CA lifecycle.
type Registry struct {
	db    *gorm.DB
	audit AuditFunc
	now   func() time.Time
}

// New builds a Registry.
func New(db *gorm.DB, audit AuditFunc) *Registry {
	return &Registry{db: db, audit: audit, now: time.Now}
}

// parseCA validates that pem is a P256 Nebula CA certificate and returns its fingerprint
// and expiry. Rejecting a non-CA / non-P256 / unparseable cert here keeps a bad root out
// of the trust bundle at the write path.
func parseCA(pem string) (fingerprint string, notAfter time.Time, err error) {
	c, _, perr := cert.UnmarshalCertificateFromPEM([]byte(pem))
	if perr != nil {
		return "", time.Time{}, fmt.Errorf("%w: %v", ErrInvalidCert, perr)
	}
	if !c.IsCA() {
		return "", time.Time{}, fmt.Errorf("%w: not a CA certificate", ErrInvalidCert)
	}
	if c.Curve() != cert.Curve_P256 {
		return "", time.Time{}, fmt.Errorf("%w: curve is %s, only P256 is supported", ErrInvalidCert, c.Curve())
	}
	fp, _ := c.Fingerprint()
	return fp, c.NotAfter(), nil
}

// Stage registers a new CA in the `staged` state: trusted (it enters TrustBundle
// immediately) but not yet signing. This is the "mint CA2 / trust before you sign" step
// (§4.6 steps 1-2). name is a human label; kmsKeyID names its signing backend (empty =
// trust-only). A duplicate name or fingerprint is rejected.
func (r *Registry) Stage(ctx context.Context, name, certPEM, kmsKeyID, actor string) (CA, error) {
	if name == "" {
		return CA{}, ErrEmptyName
	}
	fp, notAfter, err := parseCA(certPEM)
	if err != nil {
		return CA{}, err
	}
	now := r.now().UTC().UnixNano()
	row := CA{
		Name: name, Fingerprint: fp, CertPEM: certPEM, KMSKeyID: kmsKeyID,
		State: StateStaged, NotAfter: notAfter.UTC().UnixNano(),
		CreatedBy: actor, CreatedAt: now, UpdatedAt: now,
	}
	if err := r.db.WithContext(ctx).Create(&row).Error; err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			return CA{}, fmt.Errorf("%w: %s", ErrDuplicate, name)
		}
		return CA{}, fmt.Errorf("ca: stage: %w", err)
	}
	r.recordAudit(ctx, actor, "ca-stage", name, fmt.Sprintf(`{"fingerprint":%q,"kms_key_id":%q}`, fp, kmsKeyID))
	return row, nil
}

// Activate cuts signing over to the CA with id: it must be `staged`, the current `active`
// CA (if any) is demoted to `draining`, and the target becomes `active` — all in one
// transaction so there is never a window with zero or two active CAs (§4.6 step 3). The
// partial unique index is the belt-and-suspenders backstop against a concurrent activate.
//
// NOTE: the "confirm 100% trust adoption before cut-over" gate (§4.6 step 2, M8.1) is
// enforced by the CALLER (the admin/CLI layer) before invoking Activate; this primitive
// performs the atomic transition itself.
func (r *Registry) Activate(ctx context.Context, id int64, actor string) error {
	now := r.now().UTC().UnixNano()
	var demoted string
	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var target CA
		if err := tx.First(&target, "id = ?", id).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrNotFound
			}
			return err
		}
		if target.State != StateStaged {
			return fmt.Errorf("%w: %s -> active (only a staged CA can be activated)", ErrIllegalTransition, target.State)
		}
		// Demote the current active CA (if any) to draining.
		var cur CA
		switch err := tx.First(&cur, "state = ?", StateActive).Error; {
		case err == nil:
			if e := tx.Model(&CA{}).Where("id = ? AND state = ?", cur.ID, StateActive).
				Updates(map[string]any{"state": StateDraining, "updated_at": now}).Error; e != nil {
				return e
			}
			demoted = cur.Name
		case errors.Is(err, gorm.ErrRecordNotFound):
			// first activation — no prior active CA
		default:
			return err
		}
		// Promote the target. Guarded by its still being staged (CAS) so two racing
		// activates cannot both win.
		res := tx.Model(&CA{}).Where("id = ? AND state = ?", id, StateStaged).
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
	r.recordAudit(ctx, actor, "ca-activate", fmt.Sprintf("id=%d", id), fmt.Sprintf(`{"demoted_to_draining":%q}`, demoted))
	return nil
}

// Retire moves a `draining` CA to `retired` (out of the trust bundle, eligible for key
// deletion), but ONLY when it has no live dependents — liveDependents is the count of
// still-valid leaf certs that chain to this CA, supplied by the caller (drain tracking is
// M8.3). A non-zero count is refused with ErrHasDependents (§4.6 step 5 invariant).
func (r *Registry) Retire(ctx context.Context, id int64, liveDependents int, actor string) error {
	if liveDependents > 0 {
		return fmt.Errorf("%w: %d live", ErrHasDependents, liveDependents)
	}
	now := r.now().UTC().UnixNano()
	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var target CA
		if err := tx.First(&target, "id = ?", id).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrNotFound
			}
			return err
		}
		if target.State != StateDraining {
			return fmt.Errorf("%w: %s -> retired (only a draining CA can be retired)", ErrIllegalTransition, target.State)
		}
		res := tx.Model(&CA{}).Where("id = ? AND state = ?", id, StateDraining).
			Updates(map[string]any{"state": StateRetired, "updated_at": now})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return fmt.Errorf("%w: draining -> retired (lost a concurrent transition)", ErrIllegalTransition)
		}
		return nil
	})
	if err != nil {
		return err
	}
	r.recordAudit(ctx, actor, "ca-retire", fmt.Sprintf("id=%d", id), "")
	return nil
}

// Abandon cancels a `staged` CA that was never activated (staged -> retired), e.g. a
// mistaken or superseded stage. Only a staged CA can be abandoned.
func (r *Registry) Abandon(ctx context.Context, id int64, actor string) error {
	now := r.now().UTC().UnixNano()
	res := r.db.WithContext(ctx).Model(&CA{}).Where("id = ? AND state = ?", id, StateStaged).
		Updates(map[string]any{"state": StateRetired, "updated_at": now})
	if res.Error != nil {
		return fmt.Errorf("ca: abandon: %w", res.Error)
	}
	if res.RowsAffected == 0 {
		// Either it doesn't exist or it isn't staged.
		var target CA
		if err := r.db.WithContext(ctx).First(&target, "id = ?", id).Error; errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrNotFound
		}
		return fmt.Errorf("%w: only a staged CA can be abandoned", ErrIllegalTransition)
	}
	r.recordAudit(ctx, actor, "ca-abandon", fmt.Sprintf("id=%d", id), "")
	return nil
}

// Active returns the current signing CA, or ErrNoActive if none is active.
func (r *Registry) Active(ctx context.Context) (CA, error) {
	var row CA
	switch err := r.db.WithContext(ctx).First(&row, "state = ?", StateActive).Error; {
	case errors.Is(err, gorm.ErrRecordNotFound):
		return CA{}, ErrNoActive
	case err != nil:
		return CA{}, fmt.Errorf("ca: active: %w", err)
	}
	return row, nil
}

// TrustBundle returns the CA certificate PEMs the fleet must trust: every NON-RETIRED CA
// (staged + active + draining), sorted by fingerprint so an unchanged trust set yields a
// byte-identical bundle (no false drift). This is the CABundleSource Core renders into
// every host bundle's ca_bundle — "trust before you sign" (§4.6 step 2).
func (r *Registry) TrustBundle(ctx context.Context) ([]string, error) {
	var rows []CA
	if err := r.db.WithContext(ctx).
		Where("state != ?", StateRetired).
		Order("fingerprint ASC").Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("ca: trust bundle: %w", err)
	}
	out := make([]string, 0, len(rows))
	for _, c := range rows {
		out = append(out, c.CertPEM)
	}
	sort.Strings(out) // belt-and-suspenders: guarantee deterministic order
	return out, nil
}

// List returns every CA row (all states), newest first.
func (r *Registry) List(ctx context.Context) ([]CA, error) {
	var rows []CA
	if err := r.db.WithContext(ctx).Order("id DESC").Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("ca: list: %w", err)
	}
	return rows, nil
}

// Get returns one CA by id.
func (r *Registry) Get(ctx context.Context, id int64) (CA, error) {
	var row CA
	switch err := r.db.WithContext(ctx).First(&row, "id = ?", id).Error; {
	case errors.Is(err, gorm.ErrRecordNotFound):
		return CA{}, ErrNotFound
	case err != nil:
		return CA{}, fmt.Errorf("ca: get: %w", err)
	}
	return row, nil
}

// SeedActive records certPEM as the single `active` CA IF the registry is empty. It is the
// idempotent boot-seed that carries a pre-M8 deployment's existing CA (loaded from
// -ca-cert) into the registry on first boot after migration 000032, so TrustBundle/Active
// reflect reality with no manual step. Returns (row, seeded, err): seeded=false (with the
// existing active row) when the table already has any CA. Mirrors the config/netblock
// boot-seed convention.
func (r *Registry) SeedActive(ctx context.Context, name, certPEM, kmsKeyID, actor string) (CA, bool, error) {
	fp, notAfter, err := parseCA(certPEM)
	if err != nil {
		return CA{}, false, err
	}
	var seeded bool
	var out CA
	terr := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var n int64
		if err := tx.Model(&CA{}).Count(&n).Error; err != nil {
			return err
		}
		if n > 0 {
			// Already populated — return the current active (if any) and seed nothing.
			_ = tx.First(&out, "state = ?", StateActive).Error
			return nil
		}
		now := r.now().UTC().UnixNano()
		out = CA{
			Name: name, Fingerprint: fp, CertPEM: certPEM, KMSKeyID: kmsKeyID,
			State: StateActive, NotAfter: notAfter.UTC().UnixNano(),
			CreatedBy: actor, CreatedAt: now, UpdatedAt: now,
		}
		if err := tx.Create(&out).Error; err != nil {
			return err
		}
		seeded = true
		return nil
	})
	if terr != nil {
		return CA{}, false, fmt.Errorf("ca: seed active: %w", terr)
	}
	if seeded {
		r.recordAudit(ctx, actor, "ca-seed-active", name, fmt.Sprintf(`{"fingerprint":%q}`, fp))
	}
	return out, seeded, nil
}

func (r *Registry) recordAudit(ctx context.Context, actor, action, target, details string) {
	if r.audit == nil {
		return
	}
	_ = r.audit(ctx, actor, action, target, details)
}
