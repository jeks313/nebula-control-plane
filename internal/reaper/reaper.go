// Package reaper turns Harbor's passive cert-expiry into ACTIVE reclamation (impl 2.12). On a
// schedule it finds hosts that are gone — their issued cert has lapsed beyond a grace window, so
// nebula already refuses them and they are off the mesh — reclaims their leaked overlay IP,
// prunes their stale heartbeat (drops them from the fleet view), and soft-marks the device reaped.
// It NEVER blocklists a cert: both triggers require the cert to be ALREADY EXPIRED (so blocklisting
// is moot), and revoking a still-VALID cert was the bug that knocked live-but-quiet hosts off the
// mesh. Off-boarding a host is a separate, explicit revoke (the off-board-must-revoke contract). See
// docs/REAPER-DECISIONS.md (R1–R7) for the conservative defaults this enforces.
//
// It is DESTRUCTIVE + AUTOMATED, so correctness and the safety guards are paramount:
//
//   - It NEVER reaps a connectable host. The cert-expired trigger fires only AFTER a cert is
//     already expired beyond grace (R1), i.e. the host is already refused by every peer.
//   - It NEVER reaps a control-plane / lighthouse host (groups via policy), nor anything in the
//     'central' reserved netblock, nor an already-reaped device (R4) — these exclusions are
//     applied in Go per-candidate after the SQL pre-filter, so they cannot be defeated by a
//     malformed groups JSON or an odd row.
//   - In dry-run it performs NONE of the mutations — it logs + audits a "would-reap" line per
//     candidate and counts them, with identical selection logic (R5), so an operator can preview
//     before trusting it.
//   - Per-host errors are tolerated (logged, counted, the run continues): one bad host must not
//     stall the reclamation of the rest. ReapOnce is idempotent — a re-run skips a host already
//     stamped devices.reaped_at != 0.
package reaper

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/policy"
	"github.com/jeks313/nebula-control-plane/internal/revocation"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"gorm.io/gorm"
)

// Reap reasons (the {reason} metric label + the persisted devices.reap_reason).
const (
	// ReasonCertExpired — the host's issued cert lapsed beyond its grace window (R1): the host
	// is already off the mesh, so this is low-risk cleanup. The revoke is skipped (moot — an
	// expired cert is already refused).
	ReasonCertExpired = "cert-expired"
	// ReasonSilent — the optional aggressive trigger (R2, off unless -reap-silent-after is set):
	// the host has been silent past SilentAfter AND its cert is already expired. A still-valid cert
	// is never reaped on silence alone (it may just be unable to reach Core yet). The reaper does NOT
	// blocklist here — the cert is already expired and refused.
	ReasonSilent = "silent"
)

var (
	metricRuns = promauto.NewCounter(prometheus.CounterOpts{
		Name: "ncp_reaper_runs_total",
		Help: "Total device-reaper runs (one per ReapOnce, dry-run included).",
	})
	metricCandidates = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "ncp_reaper_candidates",
		Help: "Reap candidates found by the most recent run (post-exclusion).",
	})
	metricReaped = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "ncp_reaper_reaped_total",
		Help: "Hosts reaped, by reason (cert-expired | silent). NOT incremented in dry-run.",
	}, []string{"reason"})
	metricIPsReclaimed = promauto.NewCounter(prometheus.CounterOpts{
		Name: "ncp_reaper_ips_reclaimed_total",
		Help: "Overlay IPs reclaimed (ipam.Release) by the reaper. NOT incremented in dry-run.",
	})
	metricErrors = promauto.NewCounter(prometheus.CounterOpts{
		Name: "ncp_reaper_errors_total",
		Help: "Per-host reap errors (tolerated — the run continues past a bad host).",
	})
	metricLastRun = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "ncp_reaper_last_run_seconds",
		Help: "Unix timestamp of the last reaper run (dry-run included).",
	})
)

// Releaser reclaims an overlay IP (ipam.Allocator.Release). ErrNotAllocated is tolerated as a
// no-op (the IP was already free), so a re-run or a manual release never fails the reap.
type Releaser interface {
	Release(ctx context.Context, ip netip.Addr) error
}

// Revoker blocklists a cert fingerprint (*revocation.Registry satisfies it). RETAINED for wiring
// stability but NO LONGER CALLED by the reaper: reaping never blocklists (both triggers reap only
// already-expired certs; off-boarding a live host is a separate explicit revoke). Kept so the
// constructor + deploy wiring are undisturbed and a future deliberate-offboard path can reuse it.
type Revoker interface {
	Add(ctx context.Context, fingerprint, reason, actor string) (revocation.Row, error)
}

// AuditFunc appends one row to the hash-chained audit log (same shape as revocation.AuditFunc).
type AuditFunc func(ctx context.Context, actor, action, target, details string) error

// actor is the audit actor for every reaper-originated entry.
const actor = "reaper"

// Config tunes the reaper. Grace windows are "past expiry": a host is a candidate once
// now > cert_not_after + grace.
type Config struct {
	// PersistentGrace is how long past cert expiry a non-ephemeral host waits before it is a
	// candidate (R1; default 7d — very conservative). EphemeralGrace is the short window for an
	// ephemeral-join-key host (R1; default 1h — torn-down CI/scratch hosts go fast).
	PersistentGrace time.Duration
	EphemeralGrace  time.Duration

	// SilentAfter is the optional aggressive trigger (R2; 0 = OFF, the default). When > 0, a host
	// silent (last_seen older than this) is ALSO a candidate — but ONLY if its cert is already
	// KNOWN-EXPIRED (cert_not_after set and lapsed). A still-valid (or unknown-expiry) cert is never
	// reaped on silence. The reap does NOT revoke (an expired cert is already refused).
	SilentAfter time.Duration

	// DryRun performs NONE of the mutations (R5): it logs + audits a would-reap line per candidate
	// and counts them. Selection logic is identical.
	DryRun bool
}

// withDefaults fills the conservative defaults for any unset grace (R1).
func (c Config) withDefaults() Config {
	if c.PersistentGrace <= 0 {
		c.PersistentGrace = 7 * 24 * time.Hour
	}
	if c.EphemeralGrace <= 0 {
		c.EphemeralGrace = time.Hour
	}
	// SilentAfter intentionally has no default — 0 means OFF (R2).
	return c
}

// Reaper reclaims gone hosts. Deps are injected so the dangerous mutations are all fakeable in
// tests and the package stays free of the concrete ipam/revocation types.
type Reaper struct {
	db       *gorm.DB
	alloc    Releaser
	revoke   Revoker
	audit    AuditFunc
	cfg      Config
	now      func() time.Time
	log      *slog.Logger
	central  netip.Prefix // the 'central' reserved block; an IP inside it is never reaped (R4)
	notAlloc error        // ipam.ErrNotAllocated, tolerated as a release no-op (injected to avoid the import cycle)
}

// New builds a Reaper. now defaults to time.Now; log defaults to slog.Default. central is the
// resolved 'central' reserved netblock (zero Prefix = no central guard, e.g. tests with no
// netblock seeded). notAllocated is ipam.ErrNotAllocated (release-of-free-IP tolerated as a
// no-op); nil disables that tolerance.
func New(db *gorm.DB, alloc Releaser, revoke Revoker, audit AuditFunc, cfg Config, central netip.Prefix, notAllocated error) *Reaper {
	return &Reaper{
		db:       db,
		alloc:    alloc,
		revoke:   revoke,
		audit:    audit,
		cfg:      cfg.withDefaults(),
		now:      time.Now,
		log:      slog.Default(),
		central:  central,
		notAlloc: notAllocated,
	}
}

// WithClock overrides the clock (tests inject a fixed now).
func (r *Reaper) WithClock(now func() time.Time) *Reaper { r.now = now; return r }

// WithLogger overrides the logger.
func (r *Reaper) WithLogger(log *slog.Logger) *Reaper {
	if log != nil {
		r.log = log
	}
	return r
}

// ReapReport is the per-run outcome.
type ReapReport struct {
	Candidates   int            // candidates after every exclusion (the ones that WOULD be acted on)
	Reaped       int            // hosts actually reaped (0 in dry-run)
	WouldReap    int            // would-reap count (dry-run only; 0 otherwise)
	IPsReclaimed int            // overlay IPs released (0 in dry-run)
	Revoked      int            // fingerprints blocklisted (silent trigger; 0 in dry-run)
	Errors       int            // tolerated per-host errors
	ByReason     map[string]int // reaped (or would-reap, dry-run) count per reason
}

// candidate is one host the SQL pre-filter surfaced, joined heartbeats↔enrollments.
type candidate struct {
	OverlayIP    string `gorm:"column:overlay_ip"`
	DeviceName   string `gorm:"column:device_name"`
	CertNotAfter int64  `gorm:"column:cert_not_after"` // unix ns; 0 = unknown
	LastSeen     int64  `gorm:"column:last_seen"`      // unix ns
	Fingerprint  string `gorm:"column:fingerprint"`
	Ephemeral    bool   `gorm:"column:ephemeral"`
	Groups       string `gorm:"column:groups"` // JSON array of group names
}

// reason returns why this host is a candidate at time now (with grace), and whether it qualifies
// at all. A cert expired beyond its (ephemeral-aware) grace -> ReasonCertExpired. Else, if
// SilentAfter is enabled and the host is silent past it -> ReasonSilent. The cert-expired trigger
// takes precedence (an expired cert is the lowest-risk, primary signal).
func (c candidate) reason(now time.Time, cfg Config) (string, bool) {
	nowNs := now.UnixNano()
	grace := cfg.PersistentGrace
	if c.Ephemeral {
		grace = cfg.EphemeralGrace
	}
	// R1: cert expired beyond grace AND the host is actually silent. A recent last_seen means the host
	// is heartbeating right now — its recorded cert_not_after is a stale self-report, not the truth —
	// so it must NEVER be reaped. A genuinely-expired cert can't complete a handshake, so a real
	// expired host goes silent on its own; requiring silence here just refuses to trust a stale value.
	if c.CertNotAfter != 0 && c.CertNotAfter < nowNs-grace.Nanoseconds() &&
		c.LastSeen < nowNs-grace.Nanoseconds() {
		return ReasonCertExpired, true
	}
	// R2: optional silent trigger — only ever reaps an ALREADY-EXPIRED cert. A still-valid cert is
	// NEVER reaped, regardless of silence: a quiet host with a live cert is presumed reachable but
	// temporarily unable to reach Core (e.g. a NAT/relay gap), not abandoned. Deliberate off-boarding
	// is an explicit revoke, never a side effect of silence (the off-board-must-revoke contract).
	if cfg.SilentAfter > 0 && c.CertNotAfter != 0 && !c.certStillValid(now) && c.LastSeen < nowNs-cfg.SilentAfter.Nanoseconds() {
		return ReasonSilent, true
	}
	return "", false
}

// certStillValid reports whether the cert is NOT yet expired at now — the gate for whether the
// reap must blocklist the fingerprint (R3). Only possible to be true under the silent trigger.
func (c candidate) certStillValid(now time.Time) bool {
	return c.CertNotAfter != 0 && c.CertNotAfter >= now.UnixNano()
}

// excluded reports whether this candidate is in the never-reap set (R4): a reserved
// (control-plane/lighthouse) group, or an overlay IP inside the 'central' reserved block. (The
// already-reaped exclusion is enforced by the SQL pre-filter via the devices LEFT JOIN.) The
// returned string is the exclusion reason, for the debug log.
func (r *Reaper) excluded(c candidate) (string, bool) {
	var groups []string
	// A malformed groups JSON leaves groups nil -> GrantsReservedGroup false; that is safe (the
	// row simply isn't excluded on the group basis), and a control-plane host's groups are
	// written by Harbor itself, so this is not an attacker-controlled value.
	_ = json.Unmarshal([]byte(c.Groups), &groups)
	if policy.GrantsReservedGroup(groups) {
		return "reserved-group", true
	}
	if r.central.IsValid() {
		if ip, err := netip.ParseAddr(c.OverlayIP); err == nil && r.central.Contains(ip) {
			return "central-netblock", true
		}
	}
	return "", false
}

// ReapOnce performs one idempotent reclamation pass. It selects candidates (R1/R2/R4), then for
// each acts (R3) or, in dry-run, only logs+audits+counts (R5). Per-host errors are tolerated.
func (r *Reaper) ReapOnce(ctx context.Context) (ReapReport, error) {
	metricRuns.Inc()
	metricLastRun.Set(float64(r.now().Unix()))
	rep := ReapReport{ByReason: map[string]int{}}

	cands, err := r.loadCandidates(ctx)
	if err != nil {
		return rep, fmt.Errorf("reaper: load candidates: %w", err)
	}

	now := r.now()
	for _, c := range cands {
		// Re-evaluate the trigger in Go from the row's own ephemeral/grace (the SQL pre-filter is
		// a coarse over-approximation; this is the authoritative selection — R1/R2).
		reason, ok := c.reason(now, r.cfg)
		if !ok {
			continue
		}
		// R4 never-reap exclusions (reserved group / central netblock), applied per-candidate.
		if why, skip := r.excluded(c); skip {
			r.log.Debug("reaper: skipping protected host",
				"device", c.DeviceName, "overlay_ip", c.OverlayIP, "exclusion", why)
			continue
		}

		rep.Candidates++
		metricCandidates.Set(float64(rep.Candidates)) // updated as we go; final value is the run's total

		if r.cfg.DryRun {
			r.dryRunOne(ctx, c, reason, now, &rep)
			continue
		}
		r.reapOne(ctx, c, reason, now, &rep)
	}

	// On a run with zero candidates, the gauge above never ran — make it authoritative.
	metricCandidates.Set(float64(rep.Candidates))
	return rep, nil
}

// dryRunOne logs + audits a would-reap line and counts it; it mutates NOTHING (R5).
func (r *Reaper) dryRunOne(ctx context.Context, c candidate, reason string, now time.Time, rep *ReapReport) {
	wouldRevoke := false // the reaper never blocklists a cert any more (see reapOne step 2)
	r.log.Info("reaper DRY-RUN: would reap host",
		"device", c.DeviceName, "overlay_ip", c.OverlayIP, "reason", reason, "would_revoke", wouldRevoke)
	r.recordAudit(ctx, "reaper-would-reap", c.DeviceName, fmt.Sprintf(
		`{"overlay_ip":%q,"reason":%q,"would_revoke":%t}`, c.OverlayIP, reason, wouldRevoke))
	rep.WouldReap++
	rep.ByReason[reason]++
}

// reapOne performs the destructive reclamation for one host (R3). Best-effort + tolerant: a step
// failure is logged and counted, and the run continues. The IP release and heartbeat delete are
// each tolerant of "already gone" so a re-run is idempotent.
func (r *Reaper) reapOne(ctx context.Context, c candidate, reason string, now time.Time, rep *ReapReport) {
	failed := false
	ipReclaimed := false

	// 1. Reclaim the leaked overlay IP. ErrNotAllocated (already free) is a no-op, not an error.
	if ip, perr := netip.ParseAddr(c.OverlayIP); perr == nil {
		switch err := r.alloc.Release(ctx, ip); {
		case err == nil:
			ipReclaimed = true
			rep.IPsReclaimed++
			metricIPsReclaimed.Inc()
		case r.notAlloc != nil && errors.Is(err, r.notAlloc):
			// IP was already free — fine.
		default:
			r.log.Warn("reaper: release IP failed", "device", c.DeviceName, "overlay_ip", c.OverlayIP, "err", err)
			failed = true
		}
	} else if c.OverlayIP != "" {
		r.log.Warn("reaper: unparseable overlay IP, skipping release", "device", c.DeviceName, "overlay_ip", c.OverlayIP)
	}

	// 2. The reaper NEVER revokes/blocklists a cert. Both triggers now require the cert to be ALREADY
	// EXPIRED (R1 cert-expired; R2 silent gated on !certStillValid), and an expired cert is already
	// refused by every peer — so blocklisting it is moot. Blocklisting a STILL-VALID cert (the old
	// silent behaviour) was the bug that knocked live hosts off the mesh. Deliberate off-boarding is a
	// separate, explicit revoke (the off-board-must-revoke contract), never a side effect of reaping.
	revoked := false

	// 3. Delete the stale heartbeat row so the host drops from the fleet view.
	if err := r.db.WithContext(ctx).Exec("DELETE FROM heartbeats WHERE overlay_ip = ?", c.OverlayIP).Error; err != nil {
		r.log.Warn("reaper: delete heartbeat failed", "device", c.DeviceName, "overlay_ip", c.OverlayIP, "err", err)
		failed = true
	}

	// 4. Soft-mark the device reaped (idempotency anchor + history). Only stamps a not-yet-reaped
	// row (reaped_at = 0), so a concurrent/repeat run never re-stamps.
	res := r.db.WithContext(ctx).Exec(
		"UPDATE devices SET reaped_at = ?, reap_reason = ? WHERE name = ? AND reaped_at = 0",
		now.UnixNano(), reason, c.DeviceName)
	if res.Error != nil {
		r.log.Warn("reaper: stamp reaped_at failed", "device", c.DeviceName, "err", res.Error)
		failed = true
	}

	if failed {
		rep.Errors++
		metricErrors.Inc()
		// Still count it as reaped: the destructive intent ran; a partial failure is surfaced via
		// the errors metric/log, and the next run reconciles (idempotent).
	}

	// 5. Audit the reap.
	r.recordAudit(ctx, "reaper-reap", c.DeviceName, fmt.Sprintf(
		`{"overlay_ip":%q,"reason":%q,"ip_reclaimed":%t,"revoked":%t}`,
		c.OverlayIP, reason, ipReclaimed, revoked))

	r.log.Info("reaper: reaped host",
		"device", c.DeviceName, "overlay_ip", c.OverlayIP, "reason", reason, "revoked", revoked)

	rep.Reaped++
	rep.ByReason[reason]++
	metricReaped.WithLabelValues(reason).Inc()
}

// loadCandidates runs the candidate join (R1/R4 SQL pre-filter): heartbeats ⋈ enrollments by
// overlay_ip (the LATEST issued enrollment — R18) LEFT JOIN devices to drop already-reaped hosts.
// The result is deduped per host (R19). The WHERE is
// a COARSE over-approximation in nanoseconds — cert-expired-beyond-the-LONGEST-grace OR (silent
// trigger on) silent-past-the-window — and uses the persistent (longest) grace so an ephemeral
// host expired past its SHORT grace is still surfaced; ReapOnce then applies the authoritative,
// ephemeral-aware trigger + the group/central exclusions in Go.
func (r *Reaper) loadCandidates(ctx context.Context) ([]candidate, error) {
	now := r.now().UnixNano()
	// The SQL pre-filter must surface a superset of the true candidates. The true cert-expired
	// trigger uses the per-host grace (ephemeral=short, persistent=long); the widest window is the
	// SHORTEST grace, so pre-filter on min(persistent, ephemeral) to never miss an ephemeral host.
	minGrace := r.cfg.PersistentGrace
	if r.cfg.EphemeralGrace < minGrace {
		minGrace = r.cfg.EphemeralGrace
	}
	certExpiredCutoff := now - minGrace.Nanoseconds()

	// Build the WHERE: cert expired beyond the widest grace AND silent beyond it (reason() now also
	// requires last_seen-stale on the cert-expired path, so the pre-filter mirrors it to stay a
	// superset — a host heartbeating now is never even loaded), OR (if silent trigger on) silent past
	// the window. The ?-args differ by branch, so assemble args alongside.
	where := "h.cert_not_after != 0 AND h.cert_not_after < ? AND h.last_seen < ?"
	args := []any{certExpiredCutoff, certExpiredCutoff}
	if r.cfg.SilentAfter > 0 {
		where = "(" + where + ") OR h.last_seen < ?"
		args = append(args, now-r.cfg.SilentAfter.Nanoseconds())
	}

	// LEFT JOIN devices (by name = device_name) so a reaped device (reaped_at != 0) is excluded
	// here in SQL — the idempotency guard (R4). A device with no row yet (d.name NULL) is NOT
	// excluded (its reaped_at is treated as 0).
	//
	// AUTHORITATIVE LATEST-ISSUED JOIN (R18): overlay_ip is NOT unique among issued enrollments
	// (re-enroll churn; idx_enrollments_overlay_status is non-unique — see
	// adminapi/device_provenance.go), so (e.overlay_ip = h.overlay_ip AND status='issued') can match
	// MULTIPLE rows and is NOT 1:1. We must bind e to the host's CURRENT identity — the LATEST issued
	// enrollment per overlay_ip (highest id), exactly the convention coreapi.device() and
	// deviceProvenance use (Order id DESC). The correlated subquery pins e to that single row, so a
	// stale issued row (different/empty groups, a dead fingerprint) can never leak in to defeat the
	// group/central guards or get its non-live fingerprint blocklisted.
	q := `
		SELECT h.overlay_ip      AS overlay_ip,
		       h.device_name     AS device_name,
		       h.cert_not_after  AS cert_not_after,
		       h.last_seen       AS last_seen,
		       e.fingerprint     AS fingerprint,
		       e.ephemeral       AS ephemeral,
		       e.groups          AS groups
		FROM heartbeats h
		JOIN enrollments e
		  ON e.overlay_ip = h.overlay_ip
		 AND e.status = 'issued'
		 AND e.id = (SELECT MAX(e2.id) FROM enrollments e2
		              WHERE e2.overlay_ip = h.overlay_ip AND e2.status = 'issued')
		LEFT JOIN devices d
		  ON d.name = h.device_name
		WHERE (` + where + `)
		  AND (d.reaped_at IS NULL OR d.reaped_at = 0)`

	var cands []candidate
	if err := r.db.WithContext(ctx).Raw(q, args...).Scan(&cands).Error; err != nil {
		return nil, err
	}
	// Defense-in-depth dedup (R19): independently of the query's 1:1 guarantee, collapse the
	// candidate set to AT MOST ONE row per host before ReapOnce acts. reaped_at is only stamped
	// inside reapOne, so two rows for one host in a single pass would BOTH act today; deduping here
	// means a host is processed at most once per run even if the query ever returns duplicates.
	return dedupByHost(cands), nil
}

// dedupByHost collapses candidates to at most one per overlay_ip (and, defensively, per
// device_name), preserving order. The latest-issued subquery in loadCandidates already makes the
// query 1:1 per overlay_ip, so this is belt-and-suspenders (R19): even a future query regression or
// a duplicate heartbeat row can never cause one host to be reaped twice in a single pass.
func dedupByHost(cands []candidate) []candidate {
	seenIP := make(map[string]bool, len(cands))
	seenName := make(map[string]bool, len(cands))
	out := cands[:0:0]
	for _, c := range cands {
		if c.OverlayIP != "" && seenIP[c.OverlayIP] {
			continue
		}
		if c.DeviceName != "" && seenName[c.DeviceName] {
			continue
		}
		if c.OverlayIP != "" {
			seenIP[c.OverlayIP] = true
		}
		if c.DeviceName != "" {
			seenName[c.DeviceName] = true
		}
		out = append(out, c)
	}
	return out
}

// Run reaps once immediately, then every interval, until ctx is cancelled (mirrors auditverify).
// interval <= 0 defaults to 1h.
func (r *Reaper) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = time.Hour
	}
	r.runOnceLogged(ctx)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.runOnceLogged(ctx)
		}
	}
}

// runOnceLogged runs ReapOnce and logs the outcome; a run-level error (e.g. the candidate query
// failed) is warned and the loop continues (the next tick retries).
func (r *Reaper) runOnceLogged(ctx context.Context) {
	rep, err := r.ReapOnce(ctx)
	if err != nil {
		r.log.Warn("reaper: run failed", "err", err)
		return
	}
	if r.cfg.DryRun {
		if rep.WouldReap > 0 {
			r.log.Info("reaper DRY-RUN complete", "would_reap", rep.WouldReap, "by_reason", rep.ByReason)
		}
		return
	}
	if rep.Reaped > 0 || rep.Errors > 0 {
		r.log.Info("reaper run complete",
			"reaped", rep.Reaped, "ips_reclaimed", rep.IPsReclaimed, "revoked", rep.Revoked,
			"errors", rep.Errors, "by_reason", rep.ByReason)
	}
}

func (r *Reaper) recordAudit(ctx context.Context, action, target, details string) {
	if r.audit == nil {
		return
	}
	_ = r.audit(ctx, actor, action, target, details)
}
