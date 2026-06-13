package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/cloudtrust"
	"github.com/jeks313/nebula-control-plane/internal/coreapi"
	"github.com/jeks313/nebula-control-plane/internal/dualcontrol"
	"github.com/jeks313/nebula-control-plane/internal/enrollment"
	"github.com/jeks313/nebula-control-plane/internal/joinkey"
	"github.com/jeks313/nebula-control-plane/internal/lighthouse"
	"github.com/jeks313/nebula-control-plane/internal/rollout"
	"github.com/jeks313/nebula-control-plane/internal/store/migrate"
	"gorm.io/gorm/clause"
)

// cmdSeedDemo populates a store with a believable synthetic fleet so the web console
// demos end-to-end with REAL API responses — no live Pilot agents required. Heartbeats,
// cert-expiry, versions and bundle versions can't be created through the admin API
// (they arrive from agents), so this writes them straight into the store, alongside
// lighthouses, join keys, pending enrollments, an active rollout, and a valid audit
// chain. DEV/DEMO ONLY. It migrates the DB itself, so the whole demo is two commands
// against ONE -dsn (use the SAME -dsn for admin-api or the console sees an empty DB):
//
//	harbor seed-demo  -driver sqlite -dsn demo.db
//	harbor admin-api  -driver sqlite -dsn demo.db -mock-idp
func cmdSeedDemo(args []string) {
	fs := flag.NewFlagSet("seed-demo", flag.ExitOnError)
	driver, dsn := dbFlags(fs)
	_ = fs.Parse(args)

	s := openStore(*driver, *dsn)
	defer s.Close()
	ctx := context.Background()
	now := time.Now()
	audit := func(c context.Context, a, ac, t, d string) error { _, e := s.AppendAudit(c, a, ac, t, d); return e }

	// Migrate first so the demo is self-contained (one DSN, no separate migrate step to
	// accidentally point at a different DB). migrate.Up is idempotent.
	if err := migrate.Up(s.DB); err != nil {
		fatalf("seed-demo: migrate: %v", err)
	}

	// Fail fast on an already-populated store: the seeder is only partly idempotent
	// (lighthouse/join-key/rollout creation would fatal mid-run on a re-run), and it's
	// meant for a fresh demo DB. One clear message beats a confusing partial failure.
	var hbCount int64
	if err := s.DB.WithContext(ctx).Table("heartbeats").Count(&hbCount).Error; err != nil {
		fatalf("seed-demo: %v", err)
	}
	if hbCount > 0 {
		fatalf("seed-demo: store already has %d devices — seed-demo expects a fresh migrated DB (use a new -dsn)", hbCount)
	}

	devices := seedHeartbeats(now)
	for i := range devices {
		// Upsert-safe so re-running the seeder on the same DB doesn't error on the
		// unique overlay_ip; a fresh migrated DB is the intended target.
		if err := s.DB.WithContext(ctx).Clauses(clause.OnConflict{DoNothing: true}).Create(&devices[i]).Error; err != nil {
			fatalf("seed devices: %v", err)
		}
	}

	// Lighthouses (static registry).
	reg := lighthouse.New(s.DB, audit)
	for _, lh := range []struct {
		ip, host string
		addrs    []string
	}{
		{"100.64.255.1", "lh-fra", []string{"203.0.113.10:4242"}},
		{"100.64.255.2", "lh-iad", []string{"198.51.100.20:4242"}},
		{"100.64.255.3", "lh-sin", []string{"192.0.2.30:4242"}},
	} {
		if _, err := reg.Add(ctx, lh.ip, lh.host, lh.addrs, "chris@hyde.ca"); err != nil {
			fatalf("seed lighthouse %s: %v", lh.host, err)
		}
	}

	// Join keys (one auto-issue, varied caps/expiry).
	for _, p := range []joinkey.Params{
		{Name: "laptops-2026", Groups: []string{"laptops"}, MaxUses: 50, TTL: 30 * 24 * time.Hour, QuotaPerHour: 10},
		{Name: "ci-runners", Groups: []string{"ci", "ephemeral"}, MaxUses: 0, AutoIssue: true, Ephemeral: true},
		{Name: "datacenter-iad", Groups: []string{"servers", "iad"}, MaxUses: 200, TTL: 90 * 24 * time.Hour},
	} {
		if _, _, err := joinkey.Create(ctx, s, p, now); err != nil {
			fatalf("seed joinkey %s: %v", p.Name, err)
		}
	}
	// Show non-zero usage on one key (Create always starts at 0).
	s.DB.WithContext(ctx).Table("join_keys").Where("name = ?", "laptops-2026").Update("used_count", 17)

	// Pending enrollments (awaiting approval in the queue).
	for i, e := range []struct{ name, group string }{
		{"new-laptop-07", "laptops"},
		{"contractor-vm-3", "contractors"},
		{"edge-syd-01", "servers"},
	} {
		groups, _ := json.Marshal([]string{e.group})
		row := enrollment.Enrollment{
			EnrollmentID: fmt.Sprintf("enr-demo-%03d", i+1),
			DeviceName:   e.name,
			PubkeyHash:   fmt.Sprintf("%064x", i+1),
			Method:       "token",
			Groups:       string(groups),
			Status:       enrollment.StatusPending,
			CreatedAt:    now.Add(-time.Duration(i+1) * 11 * time.Minute).UnixNano(),
		}
		if err := s.DB.WithContext(ctx).Clauses(clause.OnConflict{DoNothing: true}).Create(&row).Error; err != nil {
			fatalf("seed enrollment %s: %v", e.name, err)
		}
	}

	// An active rollout to bundle v43 (canary = the two hosts already on v43).
	var canary, rest []string
	for _, d := range devices {
		if d.AppliedBundleVersion == 43 {
			canary = append(canary, d.OverlayIP)
		} else {
			rest = append(rest, d.OverlayIP)
		}
	}
	rng := rollout.New(s.DB, audit)
	if _, err := rng.Start(ctx, rollout.StartConfig{
		Description:   "Pilot 1.4.0 + policy v43",
		TargetVersion: 43,
		PrevVersion:   42,
		Hosts:         append(canary, rest...),
		CanarySize:    len(canary),
		WaveSize:      4,
		MinHealthy:    1,
		Observe:       10 * time.Minute,
		MissingAfter:  5 * time.Minute,
		Actor:         "chris@hyde.ca",
	}); err != nil {
		fatalf("seed rollout: %v", err)
	}

	// A believable recent-activity trail (also fleshes out the verified audit chain).
	for _, a := range []struct{ actor, action, target, detail string }{
		{"chris@hyde.ca", "genesis-complete", "ca", "CA + config-signing keys created"},
		{"chris@hyde.ca", "policy-published", "#42", "allow laptops -> servers tcp 22,443"},
		{"ops@hyde.ca", "enroll-approved", "edge-fra-01", "100.64.0.11"},
		{"ops@hyde.ca", "enroll-approved", "db-iad-01", "100.64.0.12"},
	} {
		if err := audit(ctx, a.actor, a.action, a.target, a.detail); err != nil {
			fatalf("seed audit: %v", err)
		}
	}

	// A dual-control-published cloud-trust config (proposed + approved by distinct
	// actors so it commits and becomes the active config).
	ctCfg := cloudtrust.Config{
		DefaultGroups: []string{"fleet"},
		AWS: []cloudtrust.AWSAccount{
			{Account: "111122223333", ARNPatterns: []string{"arn:aws:sts::111122223333:assumed-role/web-*/*"}, Groups: []string{"web"}, AutoIssue: true},
			{Account: "444455556666", Groups: []string{"db"}}, // manual approval
		},
	}
	payload, _ := json.Marshal(ctCfg)
	dc := dualcontrol.New(dualcontrol.Config{DB: s.DB, Audit: audit})
	dc.Register(cloudtrust.PublishKind, func(_ context.Context, ch dualcontrol.Change) error {
		_, err := cloudtrust.Parse(ch.Payload)
		return err
	})
	ch, err := dc.Propose(ctx, cloudtrust.PublishKind, "AWS production accounts", payload, "chris@hyde.ca")
	if err != nil {
		fatalf("seed cloud-trust propose: %v", err)
	}
	if _, err := dc.Approve(ctx, ch.ID, "ops@hyde.ca"); err != nil {
		fatalf("seed cloud-trust approve: %v", err)
	}

	// Attested enrollments (aws-sigv4) carrying provider evidence — what the UI renders
	// for cloud-attested hosts.
	for i, a := range []struct {
		name, status, account, arn, ip string
		groups                         []string
	}{
		{"ec2-web-01", enrollment.StatusPending, "111122223333", "arn:aws:sts::111122223333:assumed-role/web-prod/i-0abc", "", []string{"fleet", "web"}},
		{"ec2-db-02", enrollment.StatusIssued, "444455556666", "arn:aws:sts::444455556666:assumed-role/db/i-0def", "100.64.0.30", []string{"fleet", "db"}},
	} {
		groups, _ := json.Marshal(a.groups)
		ts := now.Add(-time.Duration(i+1) * 7 * time.Minute).UnixNano()
		row := enrollment.Enrollment{
			EnrollmentID:    fmt.Sprintf("enr-aws-%03d", i+1),
			DeviceName:      a.name,
			PubkeyHash:      fmt.Sprintf("%064x", 100+i),
			Method:          "aws-sigv4",
			Groups:          string(groups),
			Status:          a.status,
			OverlayIP:       a.ip,
			CreatedAt:       ts,
			AttestProvider:  cloudtrust.ProviderAWS,
			AttestAccount:   a.account,
			AttestPrincipal: a.arn,
			AttestRegion:    "us-east-1",
			VerifiedAt:      ts,
		}
		if a.status != enrollment.StatusPending {
			row.DecidedAt = ts
			row.Approver = "ops@hyde.ca"
		}
		if err := s.DB.WithContext(ctx).Clauses(clause.OnConflict{DoNothing: true}).Create(&row).Error; err != nil {
			fatalf("seed attested enrollment %s: %v", a.name, err)
		}
	}

	fmt.Printf("seeded demo fleet: %d devices, 3 lighthouses, 3 join keys, 5 enrollments (3 token + 2 aws-sigv4), 1 active rollout (v43 canary), 1 published cloud-trust config\n", len(devices))
}

// seedHeartbeats builds a believable ~14-host fleet whose facts drive the dashboard:
// a couple of certs near the cliff, one stale host, one clock-skewed, one unhealthy,
// a version spread, and a bundle-version spread (most on v42, the v43 canary leading).
func seedHeartbeats(now time.Time) []coreapi.Heartbeat {
	type spec struct {
		name, ip, pilot, nebula, health string
		bundle                          int
		certDays                        float64
		lastSeen                        time.Duration // ago
		clockMs                         int
	}
	specs := []spec{
		{"edge-fra-01", "100.64.0.11", "1.4.0", "1.10.3", "ok", 43, 27, 25 * time.Second, 40},
		{"edge-fra-02", "100.64.0.12", "1.4.0", "1.10.3", "ok", 43, 31, 30 * time.Second, 55},
		{"db-iad-01", "100.64.0.13", "1.4.0", "1.10.3", "ok", 42, 5, 20 * time.Second, 30}, // expiring (<7d)
		{"db-iad-02", "100.64.0.14", "1.3.2", "1.10.3", "ok", 42, 3, 35 * time.Second, 60}, // expiring (<7d)
		{"app-iad-01", "100.64.0.15", "1.4.0", "1.10.3", "ok", 42, 22, 40 * time.Second, 20},
		{"app-iad-02", "100.64.0.16", "1.4.0", "1.10.3", "degraded", 42, 26, 45 * time.Second, 35}, // unhealthy
		{"gw-sin-01", "100.64.0.17", "1.4.0", "1.10.3", "ok", 42, 48, 28 * time.Second, 8200},      // clock-skewed
		{"gw-sin-02", "100.64.0.18", "1.3.2", "1.9.0", "ok", 42, 52, 22 * time.Minute, 70},         // stale (>5m)
		{"edge-syd-02", "100.64.0.19", "1.4.0", "1.10.3", "ok", 42, 40, 30 * time.Second, 25},
		{"edge-syd-03", "100.64.0.20", "1.4.0", "1.10.3", "ok", 42, 44, 33 * time.Second, 45},
		{"app-fra-01", "100.64.0.21", "1.4.0", "1.10.3", "ok", 42, 19, 26 * time.Second, 50},
		{"app-fra-02", "100.64.0.22", "1.4.0", "1.10.3", "ok", 42, 58, 24 * time.Second, 15},
		{"db-sin-01", "100.64.0.23", "1.3.2", "1.10.3", "ok", 42, 36, 38 * time.Second, 65},
		{"worker-iad-01", "100.64.0.24", "1.4.0", "1.10.3", "ok", 42, 50, 29 * time.Second, 33},
	}
	out := make([]coreapi.Heartbeat, len(specs))
	for i, sp := range specs {
		out[i] = coreapi.Heartbeat{
			OverlayIP:            sp.ip,
			DeviceName:           sp.name,
			PilotVersion:         sp.pilot,
			NebulaVersion:        sp.nebula,
			CertNotAfter:         now.Add(time.Duration(sp.certDays * float64(24*time.Hour))).UnixNano(),
			AppliedBundleVersion: sp.bundle,
			ClockOffsetMs:        sp.clockMs,
			Health:               sp.health,
			LastSeen:             now.Add(-sp.lastSeen).UnixNano(),
		}
	}
	return out
}
