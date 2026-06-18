package reaper

import (
	"context"
	"errors"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/revocation"
	"github.com/jeks313/nebula-control-plane/internal/store"
	"github.com/jeks313/nebula-control-plane/internal/store/migrate"
	"gorm.io/gorm"
)

// --- test harness -----------------------------------------------------------

// fixed clock used across the tests so grace math is deterministic.
var testNow = time.Date(2026, 6, 18, 12, 0, 0, 0, time.UTC)

func clk() func() time.Time { return func() time.Time { return testNow } }

func newDB(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(store.Config{Driver: "sqlite", DSN: store.DefaultSQLiteDSN(filepath.Join(t.TempDir(), "reap.db"))})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	if err := migrate.Up(s.DB); err != nil {
		t.Fatal(err)
	}
	return s
}

// host describes a seeded host across the three tables.
type host struct {
	name         string
	ip           string
	groups       string // JSON; default "[]"
	ephemeral    bool
	fingerprint  string
	certNotAfter time.Time // zero -> stored as 0 (unknown)
	lastSeen     time.Time
	reapedAt     int64 // devices.reaped_at; 0 = not reaped
	noDeviceRow  bool  // skip inserting the devices row (simulates a host with no device record yet)
	noEnrollRow  bool  // skip the enrollment row (so it won't be a candidate — join misses)
}

func seed(t *testing.T, db *gorm.DB, h host) {
	t.Helper()
	groups := h.groups
	if groups == "" {
		groups = "[]"
	}
	var cna int64
	if !h.certNotAfter.IsZero() {
		cna = h.certNotAfter.UnixNano()
	}
	if !h.noEnrollRow {
		eph := 0
		if h.ephemeral {
			eph = 1
		}
		if err := db.Exec(
			`INSERT INTO enrollments (enrollment_id, device_name, pubkey_hash, pubkey, method, status, groups, overlay_ip, fingerprint, ephemeral, created_at)
			 VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
			"e-"+h.name, h.name, "ph", []byte("k"), "token", "issued", groups, h.ip, h.fingerprint, eph, 1,
		).Error; err != nil {
			t.Fatalf("seed enrollment %s: %v", h.name, err)
		}
	}
	if err := db.Exec(
		`INSERT INTO heartbeats (overlay_ip, device_name, cert_not_after, last_seen) VALUES (?,?,?,?)`,
		h.ip, h.name, cna, h.lastSeen.UnixNano(),
	).Error; err != nil {
		t.Fatalf("seed heartbeat %s: %v", h.name, err)
	}
	if !h.noDeviceRow {
		if err := db.Exec(
			`INSERT INTO devices (name, created_at, reaped_at) VALUES (?,?,?)`, h.name, 1, h.reapedAt,
		).Error; err != nil {
			t.Fatalf("seed device %s: %v", h.name, err)
		}
	}
}

// fakeAlloc records released IPs and can be made to fail a specific IP.
type fakeAlloc struct {
	released []string
	failIP   string
	err      error
}

func (f *fakeAlloc) Release(_ context.Context, ip netip.Addr) error {
	if f.failIP != "" && ip.String() == f.failIP {
		if f.err != nil {
			return f.err
		}
		return errors.New("release boom")
	}
	f.released = append(f.released, ip.String())
	return nil
}

// fakeRevoke records blocklisted fingerprints.
type fakeRevoke struct {
	added []string
	err   error
}

func (f *fakeRevoke) Add(_ context.Context, fp, _, _ string) (revocation.Row, error) {
	if f.err != nil {
		return revocation.Row{}, f.err
	}
	f.added = append(f.added, fp)
	return revocation.Row{Fingerprint: fp, State: revocation.StateActive}, nil
}

// auditRec collects (action,target) audit entries.
type auditRec struct{ entries []string }

func (a *auditRec) fn() AuditFunc {
	return func(_ context.Context, _, action, target, _ string) error {
		a.entries = append(a.entries, action+":"+target)
		return nil
	}
}

// build wires a Reaper over db with the given config and fakes, fixed clock, and the central
// netblock 10.44.0.0/27 (the never-reap reserved block). notAllocated defaults to nil; tests that
// exercise the release-of-free-IP tolerance set rp.notAlloc themselves.
func build(db *gorm.DB, cfg Config, alloc Releaser, rev Revoker, au AuditFunc) *Reaper {
	central := netip.MustParsePrefix("10.44.0.0/27")
	return New(db, alloc, rev, au, cfg, central, nil).WithClock(clk())
}

// helper times relative to testNow.
func ago(d time.Duration) time.Time   { return testNow.Add(-d) }
func ahead(d time.Duration) time.Time { return testNow.Add(d) }

// --- candidate selection ----------------------------------------------------

// TestCertExpiredBeyondGraceIsCandidate: a persistent host whose cert expired longer ago than the
// persistent grace IS reaped; expired-but-within-grace is NOT.
func TestCertExpiredBeyondGraceIsCandidate(t *testing.T) {
	s := newDB(t)
	cfg := Config{PersistentGrace: 7 * 24 * time.Hour, EphemeralGrace: time.Hour}

	// expired 8d ago > 7d grace -> candidate.
	seed(t, s.DB, host{name: "old", ip: "100.64.0.10", certNotAfter: ago(8 * 24 * time.Hour), lastSeen: ago(8 * 24 * time.Hour)})
	// expired only 1d ago < 7d grace -> NOT a candidate.
	seed(t, s.DB, host{name: "recent", ip: "100.64.0.11", certNotAfter: ago(24 * time.Hour), lastSeen: ago(24 * time.Hour)})

	al := &fakeAlloc{}
	rp := build(s.DB, cfg, al, &fakeRevoke{}, (&auditRec{}).fn())
	rep, err := rp.ReapOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if rep.Reaped != 1 || rep.ByReason[ReasonCertExpired] != 1 {
		t.Fatalf("reaped=%d byReason=%v, want 1 cert-expired", rep.Reaped, rep.ByReason)
	}
	if len(al.released) != 1 || al.released[0] != "100.64.0.10" {
		t.Fatalf("released=%v, want [100.64.0.10]", al.released)
	}
}

// TestEphemeralUsesShortGrace: an ephemeral host expired past the SHORT (1h) grace is reaped even
// though it is well within the long (7d) persistent grace; a persistent host at the same age is not.
func TestEphemeralUsesShortGrace(t *testing.T) {
	s := newDB(t)
	cfg := Config{PersistentGrace: 7 * 24 * time.Hour, EphemeralGrace: time.Hour}

	// ephemeral, expired 2h ago > 1h ephemeral grace -> candidate.
	seed(t, s.DB, host{name: "eph", ip: "100.64.0.20", ephemeral: true, certNotAfter: ago(2 * time.Hour), lastSeen: ago(2 * time.Hour)})
	// persistent, also expired 2h ago < 7d grace -> NOT a candidate.
	seed(t, s.DB, host{name: "pers", ip: "100.64.0.21", certNotAfter: ago(2 * time.Hour), lastSeen: ago(2 * time.Hour)})

	al := &fakeAlloc{}
	rp := build(s.DB, cfg, al, &fakeRevoke{}, (&auditRec{}).fn())
	rep, _ := rp.ReapOnce(context.Background())
	if rep.Reaped != 1 || al.released[0] != "100.64.0.20" {
		t.Fatalf("reaped=%d released=%v, want only ephemeral 100.64.0.20", rep.Reaped, al.released)
	}
}

// TestReservedGroupNeverReaped: a host carrying control-plane (or lighthouse) is NEVER a candidate,
// even with a long-expired cert.
func TestReservedGroupNeverReaped(t *testing.T) {
	for _, g := range []string{`["control-plane"]`, `["lighthouse"]`, `["app","lighthouse"]`} {
		s := newDB(t)
		cfg := Config{PersistentGrace: time.Hour, EphemeralGrace: time.Hour}
		seed(t, s.DB, host{name: "cp", ip: "100.64.0.30", groups: g, certNotAfter: ago(30 * 24 * time.Hour), lastSeen: ago(30 * 24 * time.Hour)})
		al := &fakeAlloc{}
		rp := build(s.DB, cfg, al, &fakeRevoke{}, (&auditRec{}).fn())
		rp.notAlloc = nil
		rep, _ := rp.ReapOnce(context.Background())
		if rep.Candidates != 0 || rep.Reaped != 0 || len(al.released) != 0 {
			t.Fatalf("group %s: reaped=%d candidates=%d released=%v, want NONE (never-reap)", g, rep.Reaped, rep.Candidates, al.released)
		}
	}
}

// TestCentralNetblockNeverReaped: a host whose overlay IP is inside the central reserved block is
// NEVER a candidate, even long-expired.
func TestCentralNetblockNeverReaped(t *testing.T) {
	s := newDB(t)
	cfg := Config{PersistentGrace: time.Hour, EphemeralGrace: time.Hour}
	// 10.44.0.5 is inside 10.44.0.0/27.
	seed(t, s.DB, host{name: "lh", ip: "10.44.0.5", certNotAfter: ago(30 * 24 * time.Hour), lastSeen: ago(30 * 24 * time.Hour)})
	// a host JUST outside central (10.44.0.32 is the next /27) IS reaped, proving the guard is precise.
	seed(t, s.DB, host{name: "outside", ip: "10.44.0.32", certNotAfter: ago(30 * 24 * time.Hour), lastSeen: ago(30 * 24 * time.Hour)})
	al := &fakeAlloc{}
	rp := build(s.DB, cfg, al, &fakeRevoke{}, (&auditRec{}).fn())
	rep, _ := rp.ReapOnce(context.Background())
	if rep.Reaped != 1 || len(al.released) != 1 || al.released[0] != "10.44.0.32" {
		t.Fatalf("reaped=%d released=%v, want only 10.44.0.32 (central host protected)", rep.Reaped, al.released)
	}
}

// TestAlreadyReapedSkipped_Idempotent: a device already stamped reaped_at != 0 is skipped, and a
// second run after a reap does nothing (idempotent).
func TestAlreadyReapedSkipped_Idempotent(t *testing.T) {
	s := newDB(t)
	cfg := Config{PersistentGrace: time.Hour, EphemeralGrace: time.Hour}

	// pre-reaped: reaped_at already set -> skipped by the SQL pre-filter.
	seed(t, s.DB, host{name: "done", ip: "100.64.0.40", certNotAfter: ago(30 * 24 * time.Hour), lastSeen: ago(30 * 24 * time.Hour), reapedAt: 999})
	// fresh candidate.
	seed(t, s.DB, host{name: "fresh", ip: "100.64.0.41", certNotAfter: ago(30 * 24 * time.Hour), lastSeen: ago(30 * 24 * time.Hour)})

	al := &fakeAlloc{}
	rp := build(s.DB, cfg, al, &fakeRevoke{}, (&auditRec{}).fn())

	rep1, _ := rp.ReapOnce(context.Background())
	if rep1.Reaped != 1 || al.released[0] != "100.64.0.41" {
		t.Fatalf("run1 reaped=%d released=%v, want only fresh", rep1.Reaped, al.released)
	}
	// devices.reaped_at must now be stamped for 'fresh'.
	var stamped int64
	s.DB.Raw("SELECT reaped_at FROM devices WHERE name = ?", "fresh").Scan(&stamped)
	if stamped != testNow.UnixNano() {
		t.Fatalf("fresh reaped_at = %d, want %d", stamped, testNow.UnixNano())
	}

	// Second run: nothing left to do (fresh is now reaped, done was always reaped).
	rep2, _ := rp.ReapOnce(context.Background())
	if rep2.Reaped != 0 || rep2.Candidates != 0 {
		t.Fatalf("run2 reaped=%d candidates=%d, want 0/0 (idempotent)", rep2.Reaped, rep2.Candidates)
	}
}

// TestSilentTriggerOffByDefault: with SilentAfter=0 a host with a STILL-VALID cert that has gone
// silent is NOT reaped; with SilentAfter set it IS, and the still-valid cert is revoked.
func TestSilentTriggerOffByDefault(t *testing.T) {
	mk := func(silentAfter time.Duration) (*fakeAlloc, *fakeRevoke, ReapReport) {
		s := newDB(t)
		cfg := Config{PersistentGrace: 7 * 24 * time.Hour, EphemeralGrace: time.Hour, SilentAfter: silentAfter}
		// cert still VALID (expires 10d from now), but last seen 3d ago.
		seed(t, s.DB, host{name: "quiet", ip: "100.64.0.50", fingerprint: "deadbeef",
			certNotAfter: ahead(10 * 24 * time.Hour), lastSeen: ago(3 * 24 * time.Hour)})
		al, rev := &fakeAlloc{}, &fakeRevoke{}
		rp := build(s.DB, cfg, al, rev, (&auditRec{}).fn())
		rp.notAlloc = nil
		rep, _ := rp.ReapOnce(context.Background())
		return al, rev, rep
	}

	// OFF (default 0): not reaped.
	al, rev, rep := mk(0)
	if rep.Reaped != 0 || len(al.released) != 0 || len(rev.added) != 0 {
		t.Fatalf("silent OFF: reaped=%d released=%v revoked=%v, want NONE", rep.Reaped, al.released, rev.added)
	}

	// ON (2d): reaped under the silent reason, and the still-valid cert is revoked.
	al, rev, rep = mk(2 * 24 * time.Hour)
	if rep.Reaped != 1 || rep.ByReason[ReasonSilent] != 1 {
		t.Fatalf("silent ON: reaped=%d byReason=%v, want 1 silent", rep.Reaped, rep.ByReason)
	}
	if len(rev.added) != 1 || rev.added[0] != "deadbeef" {
		t.Fatalf("silent ON: revoked=%v, want [deadbeef] (still-valid cert must be revoked)", rev.added)
	}
	if rep.Revoked != 1 {
		t.Fatalf("silent ON: rep.Revoked=%d, want 1", rep.Revoked)
	}
}

// --- reap actions -----------------------------------------------------------

// TestReapActions: on a cert-expired reap the IP is released, the heartbeat row is deleted,
// reaped_at + reap_reason are stamped, an audit entry is written, and the (already-expired) cert is
// NOT revoked (moot).
func TestReapActions(t *testing.T) {
	s := newDB(t)
	cfg := Config{PersistentGrace: time.Hour, EphemeralGrace: time.Hour}
	seed(t, s.DB, host{name: "gone", ip: "100.64.0.60", fingerprint: "cafe",
		certNotAfter: ago(2 * time.Hour), lastSeen: ago(2 * time.Hour)})
	al, rev := &fakeAlloc{}, &fakeRevoke{}
	au := &auditRec{}
	rp := build(s.DB, cfg, al, rev, au.fn())
	rep, _ := rp.ReapOnce(context.Background())

	if rep.Reaped != 1 || rep.IPsReclaimed != 1 {
		t.Fatalf("reaped=%d ips=%d, want 1/1", rep.Reaped, rep.IPsReclaimed)
	}
	// Heartbeat deleted.
	var hbCount int64
	s.DB.Raw("SELECT COUNT(*) FROM heartbeats WHERE overlay_ip = ?", "100.64.0.60").Scan(&hbCount)
	if hbCount != 0 {
		t.Fatalf("heartbeat row count = %d, want 0 (deleted)", hbCount)
	}
	// reaped_at + reason stamped.
	var reason string
	var at int64
	s.DB.Raw("SELECT reaped_at, reap_reason FROM devices WHERE name = ?", "gone").Row().Scan(&at, &reason)
	if at != testNow.UnixNano() || reason != ReasonCertExpired {
		t.Fatalf("device mark = (%d,%q), want (%d,%q)", at, reason, testNow.UnixNano(), ReasonCertExpired)
	}
	// Expired cert -> NOT revoked.
	if len(rev.added) != 0 || rep.Revoked != 0 {
		t.Fatalf("revoked=%v rep.Revoked=%d, want NONE (expired cert is moot)", rev.added, rep.Revoked)
	}
	// Audit written.
	if len(au.entries) != 1 || au.entries[0] != "reaper-reap:gone" {
		t.Fatalf("audit=%v, want [reaper-reap:gone]", au.entries)
	}
}

// TestPerHostErrorDoesNotStopRun: one host whose IP release fails is counted as an error but the
// run continues and reaps the others.
func TestPerHostErrorDoesNotStopRun(t *testing.T) {
	s := newDB(t)
	cfg := Config{PersistentGrace: time.Hour, EphemeralGrace: time.Hour}
	for _, ip := range []string{"100.64.0.70", "100.64.0.71", "100.64.0.72"} {
		seed(t, s.DB, host{name: "h" + ip, ip: ip, certNotAfter: ago(2 * time.Hour), lastSeen: ago(2 * time.Hour)})
	}
	al := &fakeAlloc{failIP: "100.64.0.71"}
	rp := build(s.DB, cfg, al, &fakeRevoke{}, (&auditRec{}).fn())
	rep, err := rp.ReapOnce(context.Background())
	if err != nil {
		t.Fatalf("run errored (should tolerate per-host): %v", err)
	}
	if rep.Candidates != 3 {
		t.Fatalf("candidates=%d, want 3", rep.Candidates)
	}
	if rep.Errors != 1 {
		t.Fatalf("errors=%d, want 1 (the failing IP)", rep.Errors)
	}
	// The two good IPs were still released despite the bad one.
	if len(al.released) != 2 {
		t.Fatalf("released=%v, want 2 good IPs", al.released)
	}
}

// TestDryRunDoesNothingButCounts: dry-run mutates nothing (no release, no revoke, no heartbeat
// delete, no reaped stamp) but counts + audits would-reaps.
func TestDryRunDoesNothingButCounts(t *testing.T) {
	s := newDB(t)
	cfg := Config{PersistentGrace: time.Hour, EphemeralGrace: time.Hour, DryRun: true}
	seed(t, s.DB, host{name: "dr", ip: "100.64.0.80", fingerprint: "f0", certNotAfter: ago(2 * time.Hour), lastSeen: ago(2 * time.Hour)})
	al, rev := &fakeAlloc{}, &fakeRevoke{}
	au := &auditRec{}
	rp := build(s.DB, cfg, al, rev, au.fn())
	rep, _ := rp.ReapOnce(context.Background())

	if rep.WouldReap != 1 || rep.Reaped != 0 {
		t.Fatalf("wouldReap=%d reaped=%d, want 1/0", rep.WouldReap, rep.Reaped)
	}
	if len(al.released) != 0 || len(rev.added) != 0 {
		t.Fatalf("dry-run mutated: released=%v revoked=%v", al.released, rev.added)
	}
	// Heartbeat must STILL exist; device must NOT be stamped.
	var hbCount, at int64
	s.DB.Raw("SELECT COUNT(*) FROM heartbeats WHERE overlay_ip = ?", "100.64.0.80").Scan(&hbCount)
	s.DB.Raw("SELECT reaped_at FROM devices WHERE name = ?", "dr").Scan(&at)
	if hbCount != 1 || at != 0 {
		t.Fatalf("dry-run mutated DB: hbCount=%d reaped_at=%d, want 1/0", hbCount, at)
	}
	// would-reap audit written.
	if len(au.entries) != 1 || au.entries[0] != "reaper-would-reap:dr" {
		t.Fatalf("audit=%v, want [reaper-would-reap:dr]", au.entries)
	}
}

// TestNoDeviceRowStillReaps: a candidate with no devices row yet (NULL reaped_at) is still reaped
// (the LEFT JOIN treats it as not-reaped); the stamp UPDATE is a harmless 0-row no-op.
func TestNoDeviceRowStillReaps(t *testing.T) {
	s := newDB(t)
	cfg := Config{PersistentGrace: time.Hour, EphemeralGrace: time.Hour}
	seed(t, s.DB, host{name: "nodev", ip: "100.64.0.90", certNotAfter: ago(2 * time.Hour), lastSeen: ago(2 * time.Hour), noDeviceRow: true})
	al := &fakeAlloc{}
	rp := build(s.DB, cfg, al, &fakeRevoke{}, (&auditRec{}).fn())
	rep, _ := rp.ReapOnce(context.Background())
	if rep.Reaped != 1 || al.released[0] != "100.64.0.90" {
		t.Fatalf("reaped=%d released=%v, want host reaped despite no devices row", rep.Reaped, al.released)
	}
}

// TestReleaseNotAllocatedTolerated: a Release returning the injected ErrNotAllocated is a no-op
// (not an error), so the host still reaps cleanly with no error counted.
func TestReleaseNotAllocatedTolerated(t *testing.T) {
	s := newDB(t)
	cfg := Config{PersistentGrace: time.Hour, EphemeralGrace: time.Hour}
	seed(t, s.DB, host{name: "freeip", ip: "100.64.0.95", certNotAfter: ago(2 * time.Hour), lastSeen: ago(2 * time.Hour)})
	notAlloc := errors.New("ipam: address is not allocated")
	al := &fakeAlloc{failIP: "100.64.0.95", err: notAlloc}
	rp := build(s.DB, cfg, al, &fakeRevoke{}, (&auditRec{}).fn())
	rp.notAlloc = notAlloc // tolerate this exact error
	rep, _ := rp.ReapOnce(context.Background())
	if rep.Reaped != 1 || rep.Errors != 0 || rep.IPsReclaimed != 0 {
		t.Fatalf("reaped=%d errors=%d ips=%d, want 1/0/0 (already-free IP tolerated)", rep.Reaped, rep.Errors, rep.IPsReclaimed)
	}
}

// TestRunCancels: Run reaps once then exits promptly on ctx cancel.
func TestRunCancels(t *testing.T) {
	s := newDB(t)
	cfg := Config{PersistentGrace: time.Hour, EphemeralGrace: time.Hour}
	seed(t, s.DB, host{name: "r", ip: "100.64.0.96", certNotAfter: ago(2 * time.Hour), lastSeen: ago(2 * time.Hour)})
	al := &fakeAlloc{}
	rp := build(s.DB, cfg, al, &fakeRevoke{}, (&auditRec{}).fn())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { rp.Run(ctx, time.Hour); close(done) }()
	// Give the immediate first pass a moment, then cancel.
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after ctx cancel")
	}
	if len(al.released) != 1 {
		t.Fatalf("Run's immediate pass released=%v, want 1", al.released)
	}
}

// TestNoEnrollmentRowNotCandidate: a heartbeat with no matching issued enrollment is NOT a
// candidate (the inner join misses) — guards against reaping a host we have no enrollment record
// for.
func TestNoEnrollmentRowNotCandidate(t *testing.T) {
	s := newDB(t)
	cfg := Config{PersistentGrace: time.Hour, EphemeralGrace: time.Hour}
	seed(t, s.DB, host{name: "orphan", ip: "100.64.0.97", certNotAfter: ago(2 * time.Hour), lastSeen: ago(2 * time.Hour), noEnrollRow: true})
	al := &fakeAlloc{}
	rp := build(s.DB, cfg, al, &fakeRevoke{}, (&auditRec{}).fn())
	rep, _ := rp.ReapOnce(context.Background())
	if rep.Candidates != 0 || rep.Reaped != 0 {
		t.Fatalf("candidates=%d reaped=%d, want 0/0 (no enrollment join)", rep.Candidates, rep.Reaped)
	}
}
