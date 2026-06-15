// Package rollout is Harbor's staged canary rollout engine (implementation-plan
// 6.6, design §4.4). A central change (a new policy from 6.5, a lighthouse
// topology change from 6.8) is rolled out as a new bundle *version* in waves:
// a small canary wave first, then progressively wider waves. Core tells in-wave
// hosts to apply the target version over the heartbeat command channel (4.6) and
// watches their heartbeats; a wave that converges healthy widens to the next,
// and a wave that goes unhealthy or silent past the threshold **auto-rolls-back
// and freezes** the rollout — no operator action — telling the touched hosts to
// revert to the previous version.
//
// The engine is content-agnostic: it orchestrates bundle *versions* + waves +
// health. Core stamps each host's bundle with VersionFor(host) and gates the
// per-wave content on the same membership. Evaluate is safe to call on every
// heartbeat (it drives the state machine as hosts report) and idempotent.
package rollout

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/wire"
	"gorm.io/gorm"
)

// Rollout states.
const (
	StateCanary     = "canary"     // wave 0 (canary) is active
	StateWidening   = "widening"   // a post-canary wave is active
	StateCompleted  = "completed"  // all waves converged
	StateRolledBack = "rolledback" // a wave failed; frozen, hosts reverting
	StateAborted    = "aborted"    // operator-cancelled
)

// Per-host status.
const (
	HostWaiting   = "waiting"
	HostConverged = "converged"
	HostFailed    = "failed"
	HostReverted  = "reverted"
)

// Lanes. A lane is an independent rollout track: at most one rollout is active
// per lane, but lanes run concurrently — so a security/blocklist rollout (7.1)
// never queues behind a policy canary. The policy lane reverts touched hosts to
// prev on rollback; the blocklist lane FREEZES (stops widening) without a content
// revert (the blocklist set is always the latest; an operator lifts a bad entry).
const (
	LanePolicy    = "policy"
	LaneBlocklist = "blocklist"
	// LaneNebula stages a new nebula (data-plane) RELEASE generation across the
	// fleet (ADR 0003 Phase 1c). Like the policy lane it reverts touched hosts to
	// the previous generation on rollback (a bad nebula binary downgrades), unlike
	// the blocklist lane which freezes. The generation maps to a (version, sha256,
	// url) tuple in the nebula_versions registry, stamped per-host into the bundle.
	LaneNebula = "nebula"
)

// lanes is the fixed set Evaluate sweeps each heartbeat.
var lanes = []string{LanePolicy, LaneBlocklist, LaneNebula}

// healthBad is the set of reported health values that fail a wave immediately.
var healthBad = map[string]bool{"unhealthy": true, "degraded": true, "error": true, "critical": true, "red": true}

// Errors.
var (
	ErrActiveExists = errors.New("rollout: a rollout is already active (canary|widening); finish or abort it first")
	ErrNoHosts      = errors.New("rollout: at least one host is required")
	ErrNone         = errors.New("rollout: no rollout found")
	ErrNotActive    = errors.New("rollout: current rollout is not active")
)

// Rollout is a staged rollout record.
type Rollout struct {
	ID            int64  `gorm:"column:id;primaryKey"`
	Lane          string `gorm:"column:lane"`
	Description   string `gorm:"column:description"`
	TargetVersion int    `gorm:"column:target_version"`
	PrevVersion   int    `gorm:"column:prev_version"`
	State         string `gorm:"column:state"`
	ActiveWave    int    `gorm:"column:active_wave"`
	WaveSize      int    `gorm:"column:wave_size"`
	MinHealthy    int    `gorm:"column:min_healthy"`
	ObserveWindow int64  `gorm:"column:observe_window"`
	MissingAfter  int64  `gorm:"column:missing_after"`
	WaveStartedAt int64  `gorm:"column:wave_started_at"`
	CreatedAt     int64  `gorm:"column:created_at"`
	UpdatedAt     int64  `gorm:"column:updated_at"`
	Note          string `gorm:"column:note"`
}

// TableName pins the table.
func (Rollout) TableName() string { return "rollouts" }

// Host is a host's wave assignment + status within a rollout.
type Host struct {
	ID        int64  `gorm:"column:id;primaryKey"`
	RolloutID int64  `gorm:"column:rollout_id"`
	OverlayIP string `gorm:"column:overlay_ip"`
	Wave      int    `gorm:"column:wave"`
	Status    string `gorm:"column:status"`
	UpdatedAt int64  `gorm:"column:updated_at"`
}

// TableName pins the table.
func (Host) TableName() string { return "rollout_hosts" }

// hb is the engine's read-only view of the heartbeats table (owned by coreapi;
// kept as a private model here to avoid an import cycle).
type hb struct {
	OverlayIP               string `gorm:"column:overlay_ip"`
	AppliedBundleVersion    int    `gorm:"column:applied_bundle_version"`
	AppliedBlocklistVersion int    `gorm:"column:applied_blocklist_version"`
	AppliedNebulaVersion    int    `gorm:"column:applied_nebula_version"`
	Health                  string `gorm:"column:health"`
	LastSeen                int64  `gorm:"column:last_seen"`
}

// appliedFor returns the host's applied version on the given lane.
func appliedFor(beat hb, lane string) int {
	switch lane {
	case LaneBlocklist:
		return beat.AppliedBlocklistVersion
	case LaneNebula:
		return beat.AppliedNebulaVersion
	default:
		return beat.AppliedBundleVersion
	}
}

func (hb) TableName() string { return "heartbeats" }

// AuditFunc appends one row to the hash-chained audit log.
type AuditFunc func(ctx context.Context, actor, action, target, details string) error

// Engine drives rollouts over the store.
type Engine struct {
	db    *gorm.DB
	audit AuditFunc
	now   func() time.Time
}

// New builds an Engine.
func New(db *gorm.DB, audit AuditFunc) *Engine {
	return &Engine{db: db, audit: audit, now: time.Now}
}

// SetClock overrides the clock (tests).
func (e *Engine) SetClock(now func() time.Time) { e.now = now }

// StartConfig parameterizes a new rollout.
type StartConfig struct {
	Lane          string // "" -> LanePolicy
	Description   string
	TargetVersion int
	PrevVersion   int
	Hosts         []string      // ordered; the first CanarySize form wave 0
	CanarySize    int           // wave-0 size (default 1)
	WaveSize      int           // post-canary wave size (0 = all remaining in one wave)
	MinHealthy    int           // healthy-converged required per wave (0 = all hosts in the wave)
	Observe       time.Duration // wait this long for a wave to converge before judging it stuck
	MissingAfter  time.Duration // heartbeat silence beyond this => host is down
	Actor         string
}

// Start creates and activates a rollout (wave 0 = canary). It refuses to start
// if one is already active.
func (e *Engine) Start(ctx context.Context, cfg StartConfig) (Rollout, error) {
	if len(cfg.Hosts) == 0 {
		return Rollout{}, ErrNoHosts
	}
	lane := cfg.Lane
	if lane == "" {
		lane = LanePolicy
	}
	if _, ok, err := e.activeCurrent(ctx, lane); err != nil {
		return Rollout{}, err
	} else if ok {
		return Rollout{}, ErrActiveExists
	}
	canary := cfg.CanarySize
	if canary < 1 {
		canary = 1
	}
	if canary > len(cfg.Hosts) {
		canary = len(cfg.Hosts)
	}
	now := e.now().UTC().UnixNano()
	r := Rollout{
		Lane:        lane,
		Description: cfg.Description, TargetVersion: cfg.TargetVersion, PrevVersion: cfg.PrevVersion,
		State: StateCanary, ActiveWave: 0, WaveSize: cfg.WaveSize, MinHealthy: cfg.MinHealthy,
		ObserveWindow: cfg.Observe.Nanoseconds(), MissingAfter: cfg.MissingAfter.Nanoseconds(),
		WaveStartedAt: now, CreatedAt: now, UpdatedAt: now,
	}
	err := e.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&r).Error; err != nil {
			return err
		}
		for i, ip := range cfg.Hosts {
			wave := 0
			if i >= canary {
				if cfg.WaveSize <= 0 {
					wave = 1
				} else {
					wave = 1 + (i-canary)/cfg.WaveSize
				}
			}
			if err := tx.Create(&Host{RolloutID: r.ID, OverlayIP: ip, Wave: wave, Status: HostWaiting, UpdatedAt: now}).Error; err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return Rollout{}, fmt.Errorf("rollout: start: %w", err)
	}
	e.recordAudit(ctx, cfg.Actor, "rollout-start", fmt.Sprintf("rollout#%d", r.ID),
		fmt.Sprintf("lane=%s target=%d prev=%d hosts=%d canary=%d", lane, cfg.TargetVersion, cfg.PrevVersion, len(cfg.Hosts), canary))
	return r, nil
}

// Evaluate advances the current rollout's active wave based on heartbeats:
// convergence widens to the next wave (or completes); failure/silence/timeout
// auto-rolls-back and freezes. It returns whether the state changed. Safe and
// idempotent to call on every heartbeat.
func (e *Engine) Evaluate(ctx context.Context) (changed bool, err error) {
	for _, lane := range lanes {
		c, lerr := e.evaluateLane(ctx, lane)
		if lerr != nil {
			return changed, lerr
		}
		changed = changed || c
	}
	return changed, nil
}

// evaluateLane advances the active rollout (if any) on a single lane.
func (e *Engine) evaluateLane(ctx context.Context, lane string) (changed bool, err error) {
	r, ok, err := e.activeCurrent(ctx, lane)
	if err != nil || !ok {
		return false, err
	}
	var hosts []Host
	if err := e.db.WithContext(ctx).Where("rollout_id = ? AND wave = ?", r.ID, r.ActiveWave).Find(&hosts).Error; err != nil {
		return false, err
	}
	now := e.now().UTC().UnixNano()
	elapsed := now - r.WaveStartedAt

	var converged, failed, missing int
	var trigger string
	for _, h := range hosts {
		var beat hb
		hbErr := e.db.WithContext(ctx).Where("overlay_ip = ?", h.OverlayIP).First(&beat).Error
		switch {
		case hbErr == nil && healthBad[beat.Health]:
			failed++
			if trigger == "" {
				trigger = h.OverlayIP + " reported health=" + beat.Health
			}
		case hbErr == nil && appliedFor(beat, r.Lane) == r.TargetVersion && beat.LastSeen >= now-r.MissingAfter:
			converged++
		case e.isMissing(beat, hbErr, now, r):
			missing++
			if trigger == "" {
				trigger = h.OverlayIP + " went silent (no healthy heartbeat on the target version)"
			}
		default:
			// still applying / observing
		}
	}

	need := r.MinHealthy
	if need <= 0 || need > len(hosts) {
		need = len(hosts)
	}

	switch {
	case failed > 0 || missing > 0:
		return true, e.rollback(ctx, r, trigger)
	case converged >= need:
		return true, e.advance(ctx, r, hosts)
	case elapsed >= r.ObserveWindow:
		return true, e.rollback(ctx, r, fmt.Sprintf("wave %d did not converge within the observe window (%d/%d healthy)", r.ActiveWave, converged, need))
	default:
		return false, nil
	}
}

// isMissing reports whether a wave host should count as down: it has no
// heartbeat (or a stale one) AND enough time has passed since the wave activated
// to have expected one.
func (e *Engine) isMissing(beat hb, hbErr error, now int64, r Rollout) bool {
	if now-r.WaveStartedAt < r.MissingAfter {
		return false // grace period: don't declare down before a heartbeat is due
	}
	if errors.Is(hbErr, gorm.ErrRecordNotFound) {
		return true
	}
	if hbErr != nil {
		return false
	}
	return beat.LastSeen < now-r.MissingAfter
}

func (e *Engine) advance(ctx context.Context, r Rollout, waveHosts []Host) error {
	now := e.now().UTC().UnixNano()
	if err := e.db.WithContext(ctx).Model(&Host{}).
		Where("rollout_id = ? AND wave = ?", r.ID, r.ActiveWave).
		Updates(map[string]any{"status": HostConverged, "updated_at": now}).Error; err != nil {
		return err
	}
	// More waves?
	var remaining int64
	if err := e.db.WithContext(ctx).Model(&Host{}).
		Where("rollout_id = ? AND wave > ?", r.ID, r.ActiveWave).Count(&remaining).Error; err != nil {
		return err
	}
	if remaining == 0 {
		if err := e.update(ctx, r.ID, map[string]any{"state": StateCompleted, "updated_at": now,
			"note": "all waves converged"}); err != nil {
			return err
		}
		e.recordAudit(ctx, "system", "rollout-completed", fmt.Sprintf("rollout#%d", r.ID),
			fmt.Sprintf("target=%d", r.TargetVersion))
		return nil
	}
	if err := e.update(ctx, r.ID, map[string]any{
		"state": StateWidening, "active_wave": r.ActiveWave + 1, "wave_started_at": now, "updated_at": now,
	}); err != nil {
		return err
	}
	e.recordAudit(ctx, "system", "rollout-advanced", fmt.Sprintf("rollout#%d", r.ID),
		fmt.Sprintf("wave %d converged -> activating wave %d", r.ActiveWave, r.ActiveWave+1))
	return nil
}

func (e *Engine) rollback(ctx context.Context, r Rollout, trigger string) error {
	now := e.now().UTC().UnixNano()
	err := e.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// Mark the failing wave's hosts failed; earlier converged waves keep their
		// status but will be commanded back to prev (CommandFor handles waves <=
		// active_wave). Freeze: no further widening.
		if err := tx.Model(&Host{}).Where("rollout_id = ? AND wave = ?", r.ID, r.ActiveWave).
			Updates(map[string]any{"status": HostFailed, "updated_at": now}).Error; err != nil {
			return err
		}
		return tx.Model(&Rollout{}).Where("id = ?", r.ID).Updates(map[string]any{
			"state": StateRolledBack, "updated_at": now, "note": "auto-rollback: " + trigger,
		}).Error
	})
	if err != nil {
		return err
	}
	e.recordAudit(ctx, "system", "rollout-rolledback", fmt.Sprintf("rollout#%d", r.ID),
		"auto-rollback (frozen): "+trigger)
	return nil
}

// CommandFor returns the heartbeat command (if any) to drive a host toward its
// target — or back to prev after a rollback. reportedVersion is the host's last
// applied_bundle_version. It also records a host as reverted once it reports the
// prev version post-rollback.
func (e *Engine) CommandFor(ctx context.Context, overlayIP string, reportedVersion int) (wire.Command, bool) {
	return e.commandForLane(ctx, LanePolicy, overlayIP, reportedVersion)
}

// BlocklistCommandFor is CommandFor for the blocklist lane (7.1). On rollback the
// blocklist lane FREEZES — it does NOT command a content revert (the blocklist set
// is always the latest; an operator lifts a bad entry), so only the forward
// "apply the target" drive is emitted.
func (e *Engine) BlocklistCommandFor(ctx context.Context, overlayIP string, reportedVersion int) (wire.Command, bool) {
	return e.commandForLane(ctx, LaneBlocklist, overlayIP, reportedVersion)
}

// NebulaCommandFor is CommandFor for the nebula lane (ADR 0003 Phase 1c).
// reportedVersion is the host's applied nebula GENERATION (mapped from its running
// version). Like the policy lane it reverts touched hosts to prev on rollback; the
// emitted apply_bundle just re-fetches the host's bundle, which now carries the
// generation's nebula tuple — the pilot's updater then swaps the binary (Phase 1b).
func (e *Engine) NebulaCommandFor(ctx context.Context, overlayIP string, reportedVersion int) (wire.Command, bool) {
	return e.commandForLane(ctx, LaneNebula, overlayIP, reportedVersion)
}

func (e *Engine) commandForLane(ctx context.Context, lane, overlayIP string, reportedVersion int) (wire.Command, bool) {
	r, ok, err := e.current(ctx, lane)
	if err != nil || !ok {
		return wire.Command{}, false
	}
	var h Host
	if err := e.db.WithContext(ctx).Where("rollout_id = ? AND overlay_ip = ?", r.ID, overlayIP).First(&h).Error; err != nil {
		return wire.Command{}, false
	}
	switch r.State {
	case StateCanary, StateWidening:
		// Hosts in an activated wave should be on the target version.
		if h.Wave <= r.ActiveWave && reportedVersion != r.TargetVersion {
			return wire.Command{Type: wire.CmdApplyBundle, BundleVersion: r.TargetVersion}, true
		}
	case StateRolledBack:
		if lane == LaneBlocklist {
			return wire.Command{}, false // freeze: no content revert for the blocklist lane
		}
		// Touched hosts revert to the previous version.
		if h.Wave <= r.ActiveWave {
			if reportedVersion != r.PrevVersion {
				return wire.Command{Type: wire.CmdApplyBundle, BundleVersion: r.PrevVersion}, true
			}
			if h.Status != HostReverted {
				e.markReverted(ctx, h.ID)
			}
		}
	}
	return wire.Command{}, false
}

// VersionFor returns the bundle version Core should stamp for a host, and
// whether a rollout governs it. In-wave hosts of an active rollout get the
// target; everyone else (and after rollback) gets prev.
func (e *Engine) VersionFor(ctx context.Context, overlayIP string) (int, bool) {
	r, ok, err := e.current(ctx, LanePolicy)
	if err != nil || !ok {
		return 0, false
	}
	var h Host
	if err := e.db.WithContext(ctx).Where("rollout_id = ? AND overlay_ip = ?", r.ID, overlayIP).First(&h).Error; err != nil {
		// Not a member: keep them on prev (stable) while a rollout is in flight.
		return r.PrevVersion, true
	}
	if (r.State == StateCanary || r.State == StateWidening) && h.Wave <= r.ActiveWave {
		return r.TargetVersion, true
	}
	return r.PrevVersion, true
}

// BlocklistVersion is the current blocklist-lane version Core stamps on every
// bundle's BlocklistVersion: the highest target ever rolled out on the blocklist
// lane (0 if none). The blocklist CONTENT is always the latest active set, so
// unlike the policy lane this is a single monotonic generation — a host's
// reported applied_blocklist_version is the generation of its last-fetched bundle,
// and the blocklist rollout drives the healthy fleet to converge on it.
func (e *Engine) BlocklistVersion(ctx context.Context) int {
	var v *int
	if err := e.db.WithContext(ctx).Model(&Rollout{}).
		Where("lane = ?", LaneBlocklist).
		Select("MAX(target_version)").Scan(&v).Error; err != nil || v == nil {
		return 0
	}
	return *v
}

// NebulaGenFor returns the nebula-release GENERATION Core should stamp into a
// host's bundle, and whether a nebula rollout governs it. Unlike the policy lane
// (where bundle content is always-latest and the version is just a convergence
// marker), the nebula tuple must match the generation a host should actually RUN,
// so this gates content in every state:
//   - canary|widening: in-wave hosts get the target gen, everyone else gets prev
//   - completed: the whole fleet is on the target gen
//   - rolledback|aborted: the whole fleet reverts to prev (the safe gen)
//
// gen 0 means "unpinned" (e.g. the prev of the first-ever rollout) — Core leaves
// the host's nebula alone. governed=false means no nebula rollout exists at all, so
// Core falls back to its static NebulaVersion config (Phase 1a/1b back-compat).
func (e *Engine) NebulaGenFor(ctx context.Context, overlayIP string) (gen int, governed bool) {
	r, ok, err := e.current(ctx, LaneNebula)
	if err != nil || !ok {
		return 0, false
	}
	switch r.State {
	case StateCompleted:
		return r.TargetVersion, true
	case StateCanary, StateWidening:
		var h Host
		if err := e.db.WithContext(ctx).Where("rollout_id = ? AND overlay_ip = ?", r.ID, overlayIP).First(&h).Error; err != nil {
			return r.PrevVersion, true // not a member: hold on prev while the rollout is in flight
		}
		if h.Wave <= r.ActiveWave {
			return r.TargetVersion, true
		}
		return r.PrevVersion, true
	default: // StateRolledBack | StateAborted
		return r.PrevVersion, true
	}
}

// CurrentNebulaGen is the live fleet-desired nebula generation: the target of the
// most recently COMPLETED nebula rollout (0 if none). Used to compute a new
// rollout's prev (the generation the fleet falls back to on rollback) and to know
// which registry release is "current". A rolled-back rollout's target is excluded
// (the fleet reverted off it), so this tracks what the fleet actually runs.
func (e *Engine) CurrentNebulaGen(ctx context.Context) int {
	var r Rollout
	if err := e.db.WithContext(ctx).
		Where("lane = ? AND state = ?", LaneNebula, StateCompleted).
		Order("id DESC").First(&r).Error; err != nil {
		return 0
	}
	return r.TargetVersion
}

// Status returns the policy lane's current rollout and its hosts.
func (e *Engine) Status(ctx context.Context) (Rollout, []Host, error) {
	return e.StatusLane(ctx, LanePolicy)
}

// StatusLane returns a lane's current rollout and its hosts.
func (e *Engine) StatusLane(ctx context.Context, lane string) (Rollout, []Host, error) {
	r, ok, err := e.current(ctx, lane)
	if err != nil {
		return Rollout{}, nil, err
	}
	if !ok {
		return Rollout{}, nil, ErrNone
	}
	var hosts []Host
	if err := e.db.WithContext(ctx).Where("rollout_id = ?", r.ID).Order("wave ASC, overlay_ip ASC").Find(&hosts).Error; err != nil {
		return Rollout{}, nil, err
	}
	return r, hosts, nil
}

// Abort cancels the policy lane's active rollout, reverting touched hosts to prev.
func (e *Engine) Abort(ctx context.Context, actor string) error {
	return e.AbortLane(ctx, LanePolicy, actor)
}

// AbortLane cancels a lane's active rollout. For the policy lane touched hosts
// revert to prev; for the blocklist lane the rollout simply freezes (no revert).
func (e *Engine) AbortLane(ctx context.Context, lane, actor string) error {
	r, ok, err := e.activeCurrent(ctx, lane)
	if err != nil {
		return err
	}
	if !ok {
		return ErrNotActive
	}
	now := e.now().UTC().UnixNano()
	if err := e.update(ctx, r.ID, map[string]any{"state": StateRolledBack, "updated_at": now,
		"note": "operator-aborted"}); err != nil {
		return err
	}
	e.recordAudit(ctx, actor, "rollout-aborted", fmt.Sprintf("rollout#%d", r.ID), "operator abort (lane="+lane+")")
	return nil
}

// current returns the highest-id rollout on a lane (the "current" one), if any.
func (e *Engine) current(ctx context.Context, lane string) (Rollout, bool, error) {
	var r Rollout
	err := e.db.WithContext(ctx).Where("lane = ?", lane).Order("id DESC").First(&r).Error
	switch {
	case err == nil:
		return r, true, nil
	case errors.Is(err, gorm.ErrRecordNotFound):
		return Rollout{}, false, nil
	default:
		return Rollout{}, false, err
	}
}

// activeCurrent returns the lane's current rollout only if it is active (canary|widening).
func (e *Engine) activeCurrent(ctx context.Context, lane string) (Rollout, bool, error) {
	r, ok, err := e.current(ctx, lane)
	if err != nil || !ok {
		return Rollout{}, false, err
	}
	if r.State == StateCanary || r.State == StateWidening {
		return r, true, nil
	}
	return Rollout{}, false, nil
}

func (e *Engine) update(ctx context.Context, id int64, fields map[string]any) error {
	return e.db.WithContext(ctx).Model(&Rollout{}).Where("id = ?", id).Updates(fields).Error
}

func (e *Engine) markReverted(ctx context.Context, hostID int64) {
	e.db.WithContext(ctx).Model(&Host{}).Where("id = ?", hostID).
		Updates(map[string]any{"status": HostReverted, "updated_at": e.now().UTC().UnixNano()})
}

func (e *Engine) recordAudit(ctx context.Context, actor, action, target, details string) {
	if e.audit == nil {
		return
	}
	_ = e.audit(ctx, actor, action, target, details)
}
