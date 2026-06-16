package integration

// Postgres integration tests. SQLite is the dev/test default everywhere else, so the
// Postgres-only code — the dual-dialect migration SQL, the pg_advisory_xact_lock HA
// serialization (audit chain + rollout lanes), SELECT … FOR UPDATE row locks, and the
// per-arch ServableFleet query — never runs in the normal suite. These tests exercise
// each of those paths against a REAL Postgres so a "valid on SQLite, broken on Postgres"
// regression can't slip through to a live Aurora apply.
//
// They are gated on NCP_TEST_POSTGRES_DSN and SKIP when it is unset, so `go test ./...`
// stays green on machines/CI without a Postgres. To run locally against a throwaway DB:
//
//	podman run -d --rm --name ncp-pg -e POSTGRES_PASSWORD=ncp -e POSTGRES_DB=ncp \
//	    -p 5432:5432 docker.io/library/postgres:16
//	NCP_TEST_POSTGRES_DSN='postgres://postgres:ncp@127.0.0.1:5432/ncp?sslmode=disable' \
//	    go test ./internal/integration/ -run TestPostgresDialect -v
//
// WARNING: the DSN MUST point at a disposable database — pgOpen DROPs the public schema
// to give each subtest a clean slate.

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/enrollment"
	"github.com/jeks313/nebula-control-plane/internal/nebularelease"
	"github.com/jeks313/nebula-control-plane/internal/rollout"
	"github.com/jeks313/nebula-control-plane/internal/store"
	"github.com/jeks313/nebula-control-plane/internal/store/migrate"
	"gorm.io/gorm"
)

const envPostgresDSN = "NCP_TEST_POSTGRES_DSN"

// Two known-valid 64-hex artifact digests (Add/AddArtifact require a sha256-shaped value).
const (
	pgSHAa = "99ac335caeb69d02a6b6b00a3d4b5d0a36ec3971df480a1cc50e6db378342955"
	pgSHAb = "1111111111111111111111111111111111111111111111111111111111111111"
)

// pgOpen opens a Postgres store on the throwaway DB named by NCP_TEST_POSTGRES_DSN and
// resets it to a pristine, empty schema so each subtest is isolated and reruns are
// idempotent. It skips the whole (sub)test when the DSN is unset. The store (and its
// pool) is closed via t.Cleanup, so subtests — which run sequentially — never overlap
// the DROP SCHEMA with another open connection.
func pgOpen(t *testing.T) *store.Store {
	t.Helper()
	dsn := os.Getenv(envPostgresDSN)
	if dsn == "" {
		t.Skipf("set %s to a throwaway Postgres DB to run the Postgres integration tests", envPostgresDSN)
	}
	s, err := store.Open(store.Config{Driver: "postgres", DSN: dsn})
	if err != nil {
		t.Fatalf("open postgres: %v", err)
	}
	if !store.IsPostgres(s.DB) {
		t.Fatalf("driver postgres but dialect reports %q", s.DB.Name())
	}
	if err := s.DB.Exec(`DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public;`).Error; err != nil {
		t.Fatalf("reset schema: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// pgMigrate runs every migration up on a freshly-reset store.
func pgMigrate(t *testing.T, s *store.Store) {
	t.Helper()
	if err := migrate.Up(s.DB); err != nil {
		t.Fatalf("migrate up (postgres): %v", err)
	}
}

// pgHeartbeat upserts a heartbeats row the way coreapi does — a raw INSERT … ON CONFLICT,
// which also exercises that dialect path on Postgres.
func pgHeartbeat(t *testing.T, db *gorm.DB, ip string, version int, health string, lastSeen time.Time) {
	t.Helper()
	const q = `INSERT INTO heartbeats (overlay_ip, device_name, applied_bundle_version, health, last_seen)
	           VALUES (?, ?, ?, ?, ?)
	           ON CONFLICT (overlay_ip) DO UPDATE SET applied_bundle_version=excluded.applied_bundle_version,
	             health=excluded.health, last_seen=excluded.last_seen`
	if err := db.Exec(q, ip, ip, version, health, lastSeen.UnixNano()).Error; err != nil {
		t.Fatalf("heartbeat upsert: %v", err)
	}
}

func TestPostgresDialect(t *testing.T) {
	ctx := context.Background()

	// Dual-dialect migration SQL: every up AND down file must be valid Postgres. A clean
	// up → down → up cycle proves the whole postgres/ migration set round-trips.
	t.Run("migrations_up_down_up", func(t *testing.T) {
		s := pgOpen(t)
		if err := migrate.Up(s.DB); err != nil {
			t.Fatalf("up: %v", err)
		}
		// The migrated schema is real and writable.
		if err := s.DB.Create(&store.Key{Name: "ca", Kind: "ca", Backend: "softhsm", CreatedAt: 1}).Error; err != nil {
			t.Fatalf("write into migrated schema: %v", err)
		}
		if err := migrate.Down(s.DB); err != nil {
			t.Fatalf("down (postgres down migrations): %v", err)
		}
		if err := migrate.Up(s.DB); err != nil {
			t.Fatalf("re-up after down: %v", err)
		}
	})

	// The audit chain's HA serialization is a Postgres transaction-scoped advisory lock
	// (pg_advisory_xact_lock). A SECOND store on the same DB means a second pool AND a
	// second in-process auditMu, so the advisory lock is the ONLY thing serializing the
	// two writers' read-head→write-link — exactly the ≥2-Core HA case. If that raw SQL is
	// wrong the hash chain corrupts (or a seq collides) and VerifyAudit fails.
	t.Run("audit_advisory_lock_concurrency", func(t *testing.T) {
		s := pgOpen(t)
		pgMigrate(t, s)

		s2, err := store.Open(store.Config{Driver: "postgres", DSN: os.Getenv(envPostgresDSN)})
		if err != nil {
			t.Fatalf("open 2nd store: %v", err)
		}
		t.Cleanup(func() { s2.Close() })

		const writers, each = 6, 40 // 240 appends, split across two independent pools
		var wg sync.WaitGroup
		errCh := make(chan error, writers)
		for w := 0; w < writers; w++ {
			st := s
			if w%2 == 1 {
				st = s2 // odd writers use the second pool/mutex => advisory lock must serialize
			}
			tag := fmt.Sprintf("w%d", w)
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := 0; i < each; i++ {
					if _, err := st.AppendAudit(ctx, "alice", "pg-test", tag, fmt.Sprintf("%s-%d", tag, i)); err != nil {
						errCh <- err
						return
					}
				}
			}()
		}
		wg.Wait()
		close(errCh)
		for err := range errCh {
			t.Fatalf("concurrent AppendAudit: %v", err)
		}
		n, err := s.VerifyAudit(ctx)
		if err != nil {
			t.Fatalf("VerifyAudit (chain integrity under contention): %v", err)
		}
		if want := int64(writers * each); n != want {
			t.Fatalf("VerifyAudit verified %d rows, want %d (lost or duplicated appends)", n, want)
		}
	})

	// The rollout engine's HA coordination uses two Postgres-only primitives: Start takes a
	// pg_advisory_xact_lock (lane serialization, rollout.go), and Evaluate's lane transaction
	// takes a SELECT … FOR UPDATE row lock (clause.Locking{Strength:"UPDATE"}). Drive both,
	// and make the FOR UPDATE load-bearing: a converged canary forces Evaluate to perform a
	// real locked UPDATE advancing the wave (asserted via changed==true), not just a locked read.
	t.Run("rollout_for_update_and_advisory", func(t *testing.T) {
		s := pgOpen(t)
		pgMigrate(t, s)
		audit := func(ctx context.Context, actor, action, target, details string) error {
			_, e := s.AppendAudit(ctx, actor, action, target, details)
			return e
		}
		eng := rollout.New(s.DB, audit)
		now := time.Unix(1_700_000_000, 0).UTC()
		eng.SetClock(func() time.Time { return now })
		const canary, second = "10.44.0.10", "10.44.0.11"
		if _, err := eng.Start(ctx, rollout.StartConfig{
			TargetVersion: 2, PrevVersion: 1, Hosts: []string{canary, second},
			CanarySize: 1, Observe: 10 * time.Minute, MissingAfter: 3 * time.Minute, Actor: "alice",
		}); err != nil {
			t.Fatalf("rollout Start (advisory lock) on postgres: %v", err)
		}
		// Converge the canary (it reports the target version, healthy), then Evaluate: wave 0
		// is fully healthy, so the engine advances it under the FOR UPDATE row lock — a real
		// locked write. If FOR UPDATE silently degraded, this assertion would still hold, but
		// a broken locked UPDATE/visibility would surface as changed==false or an error.
		pgHeartbeat(t, s.DB, canary, 2, "healthy", now)
		changed, err := eng.Evaluate(ctx)
		if err != nil {
			t.Fatalf("rollout Evaluate (FOR UPDATE + locked write) on postgres: %v", err)
		}
		if !changed {
			t.Fatal("Evaluate should have advanced the converged canary wave under FOR UPDATE")
		}
	})

	// ServableFleet resolves each host's arch from its latest (id-DESC, first-wins) issued
	// enrollment and joins it to the generation's per-arch artifacts. The ordering +
	// multi-table join is the kind of query whose semantics can differ between engines, so
	// validate the exact arch-affinity scenario on real Postgres.
	t.Run("servable_fleet_per_arch", func(t *testing.T) {
		s := pgOpen(t)
		pgMigrate(t, s)
		rel := nebularelease.New(s.DB)

		g, err := rel.Add(ctx, "1.0.0", "linux", "amd64", pgSHAa, "https://art/linux-amd64", "")
		if err != nil {
			t.Fatalf("Add: %v", err)
		}
		if _, err := rel.AddArtifact(ctx, int(g.Gen), "darwin", "arm64", pgSHAb, "https://art/darwin-arm64"); err != nil {
			t.Fatalf("AddArtifact: %v", err)
		}

		enrollAt := func(eid, ip, goos, goarch string, createdAt int64) {
			t.Helper()
			e := enrollment.Enrollment{
				EnrollmentID: eid, DeviceName: eid, PubkeyHash: eid, Pubkey: []byte{1},
				Method: "joinkey", Status: "issued", OverlayIP: ip, CreatedAt: createdAt,
				GOOS: goos, GOARCH: goarch,
			}
			if err := s.DB.Create(&e).Error; err != nil {
				t.Fatalf("seed enrollment %s: %v", eid, err)
			}
		}
		enrollAt("a", "10.0.0.1", "linux", "amd64", 1)   // default platform -> servable
		enrollAt("b", "10.0.0.2", "darwin", "arm64", 1)  // per-arch artifact -> servable
		enrollAt("c", "10.0.0.3", "windows", "amd64", 1) // no artifact -> excluded
		enrollAt("d", "10.0.0.4", "", "", 1)             // empty arch -> linux/amd64 default -> servable
		// 10.0.0.5 has NO issued enrollment -> resolves to the default platform -> servable.
		// 10.0.0.6: the LATER (higher-id) row is windows/amd64 (unshipped) but carries an
		// EARLIER created_at than the older linux/amd64 row. Only id-DESC first-wins (what Core
		// uses) selects the true-latest row and EXCLUDES the host; a created_at-ASC resolver
		// would wrongly stage it.
		enrollAt("e6-old", "10.0.0.6", "linux", "amd64", 100)
		enrollAt("e6-new", "10.0.0.6", "windows", "amd64", 1)

		ips := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5", "10.0.0.6"}
		servable, excluded, err := rel.ServableFleet(ctx, int(g.Gen), ips)
		if err != nil {
			t.Fatalf("ServableFleet: %v", err)
		}
		if got, want := strings.Join(servable, ","), "10.0.0.1,10.0.0.2,10.0.0.4,10.0.0.5"; got != want {
			t.Errorf("servable = %q, want %q", got, want)
		}
		if len(excluded) != 2 ||
			excluded[0].OverlayIP != "10.0.0.3" || excluded[0].GOOS != "windows" ||
			excluded[1].OverlayIP != "10.0.0.6" || excluded[1].GOOS != "windows" {
			t.Errorf("excluded = %+v, want [10.0.0.3 windows] [10.0.0.6 windows]", excluded)
		}

		if _, _, err := rel.ServableFleet(ctx, 9999, ips); err == nil {
			t.Error("ServableFleet on an unknown generation should error")
		}
	})

	// Rotation-safe credentials: with Config.Credentials set, the password lives ONLY in the
	// provider (in prod: an Aurora RDS-managed secret fetched via the instance role) and is
	// resolved BEFORE EACH connection — never in the DSN, on argv, or on disk. Prove the
	// mechanism: correct creds connect; a wrong provider value makes a NEW connection fail
	// (so resolution is genuinely per-connect, not baked in at Open); rotating the role's
	// password + the provider in lock-step restores connectivity with no restart.
	t.Run("credential_rotation_no_static_password", func(t *testing.T) {
		admin := pgOpen(t) // superuser store (DSN creds) used only to manage the rotato role
		// A dedicated login role we can rotate without disturbing the DSN's superuser. CREATE
		// ROLE is cluster-level, unaffected by pgOpen's schema reset.
		if err := admin.DB.Exec(`DROP ROLE IF EXISTS rotato`).Error; err != nil {
			t.Fatalf("pre-clean role: %v", err)
		}
		if err := admin.DB.Exec(`CREATE ROLE rotato LOGIN PASSWORD 'p1'`).Error; err != nil {
			t.Fatalf("create role: %v", err)
		}
		t.Cleanup(func() { admin.DB.Exec(`DROP ROLE IF EXISTS rotato`) })

		// Passwordless DSN (host/port/dbname/params only) — the provider supplies the login.
		base, err := url.Parse(os.Getenv(envPostgresDSN))
		if err != nil {
			t.Fatalf("parse DSN: %v", err)
		}
		base.User = nil
		pwlessDSN := base.String()
		if strings.Contains(pwlessDSN, "@") {
			t.Fatalf("passwordless DSN still carries userinfo: %q", pwlessDSN)
		}

		// Mutable provider standing in for the Secrets Manager fetch (guarded — BeforeConnect
		// may run from multiple pool goroutines).
		var mu sync.Mutex
		curUser, curPass := "rotato", "p1"
		cred := func(context.Context) (string, string, error) {
			mu.Lock()
			defer mu.Unlock()
			return curUser, curPass, nil
		}
		set := func(u, p string) { mu.Lock(); curUser, curPass = u, p; mu.Unlock() }

		// ConnMaxLifetime≈0 => every Ping opens a fresh physical connection => the provider is
		// consulted each time, so a credential change is observed immediately.
		s, err := store.Open(store.Config{
			Driver: "postgres", DSN: pwlessDSN, Credentials: cred, ConnMaxLifetime: time.Nanosecond,
		})
		if err != nil {
			t.Fatalf("open with credential provider: %v", err)
		}
		t.Cleanup(func() { s.Close() })

		if err := s.Ping(ctx); err != nil {
			t.Fatalf("ping with correct creds (p1): %v", err)
		}
		// Wrong password => a new connection must fail. This is the load-bearing assertion: it
		// would PASS (wrongly) if the password had been captured into the DSN at Open time.
		set("rotato", "wrong")
		if err := s.Ping(ctx); err == nil {
			t.Fatal("ping must FAIL after the provider returns a wrong password (proves per-connection credential resolution)")
		}
		// Rotate role + provider in lock-step => connectivity restored, no restart.
		if err := admin.DB.Exec(`ALTER ROLE rotato PASSWORD 'p2'`).Error; err != nil {
			t.Fatalf("rotate role password: %v", err)
		}
		set("rotato", "p2")
		if err := s.Ping(ctx); err != nil {
			t.Fatalf("ping after rotation to p2 (rotated secret should be picked up): %v", err)
		}
	})
}
