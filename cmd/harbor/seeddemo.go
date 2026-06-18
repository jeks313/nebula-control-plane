package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/netip"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/cloudtrust"
	"github.com/jeks313/nebula-control-plane/internal/coreapi"
	"github.com/jeks313/nebula-control-plane/internal/dualcontrol"
	"github.com/jeks313/nebula-control-plane/internal/enrollment"
	"github.com/jeks313/nebula-control-plane/internal/genesis"
	"github.com/jeks313/nebula-control-plane/internal/ipam"
	"github.com/jeks313/nebula-control-plane/internal/joinkey"
	"github.com/jeks313/nebula-control-plane/internal/lighthouse"
	"github.com/jeks313/nebula-control-plane/internal/netblock"
	"github.com/jeks313/nebula-control-plane/internal/policy"
	"github.com/jeks313/nebula-control-plane/internal/rollout"
	"github.com/jeks313/nebula-control-plane/internal/store/migrate"
	"github.com/jeks313/nebula-control-plane/internal/usertrust"
	"gorm.io/gorm/clause"
)

// Demo IPAM + SSO constants — the overlay pool the fleet + netblocks live in (the
// admin-api default), the SSO issuer/realm the demo IdP asserts, and the provider
// discriminator the SSO enroll path stamps on its evidence (internal/enrollment).
const (
	demoPoolCIDR = "100.64.0.0/16"
	ssoIssuer    = "https://idp.demo.hyde.ca"
	ssoProvider  = "sso"
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

	// Join keys (one auto-issue, varied caps/expiry). Capture the assigned ids so the
	// issued fleet enrollments below can carry join_key_id (the device-provenance link).
	jkIDs := map[string]int64{}
	for _, p := range []joinkey.Params{
		// SubRange binds the key to a named netblock (the office key -> office-vpn), so the
		// JoinKeys UI binding selector shows a real binding (and hosts cluster there).
		{Name: "laptops-2026", Groups: []string{"laptops"}, SubRange: "office-vpn", MaxUses: 50, TTL: 30 * 24 * time.Hour, QuotaPerHour: 10},
		{Name: "ci-runners", Groups: []string{"ci", "ephemeral"}, MaxUses: 0, AutoIssue: true, Ephemeral: true},
		{Name: "datacenter-iad", Groups: []string{"servers", "iad"}, MaxUses: 200, TTL: 90 * 24 * time.Hour},
	} {
		_, jk, err := joinkey.Create(ctx, s, p, now)
		if err != nil {
			fatalf("seed joinkey %s: %v", p.Name, err)
		}
		jkIDs[p.Name] = jk.ID
	}
	// Show non-zero usage on one key (Create always starts at 0).
	s.DB.WithContext(ctx).Table("join_keys").Where("name = ?", "laptops-2026").Update("used_count", 17)

	// Queued + decided token enrollments — each carries its join_key_id so the
	// "Joined via" column resolves the key name consistently across the Pending /
	// Approved / Denied tabs (and the denied one populates the Denied tab + "Decided by").
	for i, e := range []struct {
		name, joinKey, status string
		groups                []string
	}{
		{"new-laptop-07", "laptops-2026", enrollment.StatusPending, []string{"laptops"}},
		{"ci-runner-07", "ci-runners", enrollment.StatusPending, []string{"ci", "ephemeral"}},
		{"edge-syd-01", "datacenter-iad", enrollment.StatusPending, []string{"servers", "iad"}},
		{"old-contractor-vm", "laptops-2026", enrollment.StatusDenied, []string{"laptops"}},
	} {
		groups, _ := json.Marshal(e.groups)
		ts := now.Add(-time.Duration(i+1) * 11 * time.Minute).UnixNano()
		row := enrollment.Enrollment{
			EnrollmentID: fmt.Sprintf("enr-demo-%03d", i+1),
			DeviceName:   e.name,
			PubkeyHash:   fmt.Sprintf("%064x", i+1),
			Method:       "token",
			JoinKeyID:    jkIDs[e.joinKey],
			Groups:       string(groups),
			Status:       e.status,
			CreatedAt:    ts,
		}
		if e.status != enrollment.StatusPending {
			row.DecidedAt = ts
			row.Approver = "ops@hyde.ca"
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
			// Netblock binds the prod account to the aws-prod netblock (ADR 0010), so the
			// CloudTrust UI binding selector shows a real per-scope IPAM binding.
			{Account: "111122223333", ARNPatterns: []string{"arn:aws:sts::111122223333:assumed-role/web-*/*"}, Groups: []string{"web"}, AutoIssue: true, Netblock: "aws-prod"},
			{Account: "444455556666", Groups: []string{"db"}}, // manual approval, draws from default
		},
	}
	payload, _ := json.Marshal(ctCfg)
	dc := dualcontrol.New(dualcontrol.Config{DB: s.DB, Audit: audit})
	cloudtrust.RegisterCommitter(dc)
	ch, err := dc.Propose(ctx, cloudtrust.PublishKind, "AWS production accounts", payload, "chris@hyde.ca")
	if err != nil {
		fatalf("seed cloud-trust propose: %v", err)
	}
	if _, err := dc.Approve(ctx, ch.ID, "ops@hyde.ca"); err != nil {
		fatalf("seed cloud-trust approve: %v", err)
	}

	// Policy: a committed (active) policy + a pending one awaiting a second approver, so
	// the Policy page and the Approvals inbox demo the dual-control publish loop. The
	// pending change is proposed by chris, leaving a distinct admin (e.g. the mock-IdP
	// Ada Admin) able to approve it in the demo.
	policy.RegisterCommitter(dc)
	active := "allow group:laptops -> group:servers tcp 22\nallow any -> group:web tcp 443\n"
	pch, err := dc.Propose(ctx, policy.PublishKind, "baseline access", []byte(active), "chris@hyde.ca")
	if err != nil {
		fatalf("seed policy propose: %v", err)
	}
	if _, err := dc.Approve(ctx, pch.ID, "ops@hyde.ca"); err != nil {
		fatalf("seed policy approve: %v", err)
	}
	pending := "allow group:contractors -> group:servers tcp 22\nallow any -> group:web tcp 443\n"
	if _, err := dc.Propose(ctx, policy.PublishKind, "grant contractors SSH", []byte(pending), "chris@hyde.ca"); err != nil {
		fatalf("seed pending policy: %v", err)
	}

	// ── IPAM (ADR 0010): netblocks, allocations, and a published SSO user-trust config ──
	//
	// seed-demo does not run genesis, so the genesis-seeded 'central'/'default' netblocks
	// are absent. Seed them the same way genesis would (SeedNetblocks — the shared
	// chokepoint), then carve a few NAMED blocks the fleet clusters into. The pool MUST
	// match the admin-api default (so the same DSN's IPAM UI agrees), and the named CIDRs
	// MUST be clear of central (the pool's first /27) — see seedHeartbeats' IP layout.
	pool := netip.MustParsePrefix(demoPoolCIDR)
	nbAlloc, err := ipam.NewAllocator(s, ipam.Pool{Prefix: pool})
	if err != nil {
		fatalf("seed ipam allocator: %v", err)
	}
	nbReg := netblock.New(s.DB, pool, nil, nbAlloc, audit)
	if _, _, err := genesis.SeedNetblocks(ctx, nbReg, pool, netip.Prefix{}, netip.Prefix{}, "chris@hyde.ca"); err != nil {
		fatalf("seed netblocks (central+default): %v", err)
	}
	for _, nb := range []struct{ name, cidr, desc string }{
		{"office-vpn", "100.64.10.0/24", "corporate VPN laptops (token join key)"},
		{"aws-prod", "100.64.20.0/24", "AWS prod EC2 fleet (aws-sigv4 attest)"},
		{"sso-eng", "100.64.30.0/24", "SSO platform-engineering hosts"},
		{"sso-contractors", "100.64.40.0/27", "SSO contractor hosts (small, near-exhausted)"},
	} {
		if _, err := nbReg.Add(ctx, nb.name, netip.MustParsePrefix(nb.cidr), nb.desc, "chris@hyde.ca"); err != nil {
			fatalf("seed netblock %s: %v", nb.name, err)
		}
	}

	// netblock_id lookup so allocation provenance carries the right block.
	nbID := map[string]int64{}
	for _, name := range []string{"central", "default", "office-vpn", "aws-prod", "sso-eng", "sso-contractors"} {
		row, gerr := nbReg.Get(ctx, name)
		if gerr != nil {
			fatalf("seed netblock lookup %s: %v", name, gerr)
		}
		nbID[name] = row.ID
	}

	// ip_allocations with provenance (netblock_id + method). A device row is created for
	// each so the allocation has an owner; the IPAM page joins allocation IP -> heartbeat
	// to compute `used` (allocated ∩ fresh heartbeat). We write rows DIRECTLY (not via the
	// allocator) so we can place specific IPs and drive utilization to chosen levels.
	seedAlloc := func(ip string, netblockID int64, method string) {
		var dev ipam.Device
		// One device per allocation (FirstOrCreate keyed on the synthetic name).
		if err := s.DB.WithContext(ctx).
			Where(ipam.Device{Name: "dev-" + ip}).
			Attrs(ipam.Device{CreatedAt: now.UnixNano()}).
			FirstOrCreate(&dev).Error; err != nil {
			fatalf("seed alloc device %s: %v", ip, err)
		}
		row := ipam.Allocation{
			IP: ip, DeviceID: dev.ID, State: "allocated",
			AllocatedAt: now.UnixNano(), NetblockID: netblockID, Method: method,
		}
		if err := s.DB.WithContext(ctx).Clauses(clause.OnConflict{DoNothing: true}).Create(&row).Error; err != nil {
			fatalf("seed allocation %s: %v", ip, err)
		}
	}

	// 1) Control plane in 'central' (.1 lighthouse, .2 core), method=genesis.
	seedAlloc("100.64.0.1", nbID["central"], "genesis")
	seedAlloc("100.64.0.2", nbID["central"], "genesis")

	// 2) Fleet allocations matching the heartbeat IPs (used = allocated ∩ fresh heartbeat
	//    is non-zero, clustered by join source). office-vpn + aws-prod are well-used
	//    (grow), sso-eng is well-used AND pushed to ~80% alloc (yellow + grow), the
	//    'default' tail-end hosts draw from default.
	for _, f := range []struct {
		ip, block, method string
	}{
		{"100.64.10.11", "office-vpn", "token"}, {"100.64.10.12", "office-vpn", "token"},
		{"100.64.10.13", "office-vpn", "token"}, {"100.64.10.14", "office-vpn", "token"},
		{"100.64.20.15", "aws-prod", "aws-sigv4"}, {"100.64.20.16", "aws-prod", "aws-sigv4"},
		{"100.64.20.17", "aws-prod", "aws-sigv4"}, {"100.64.20.18", "aws-prod", "aws-sigv4"},
		{"100.64.30.19", "sso-eng", "sso"}, {"100.64.30.20", "sso-eng", "sso"},
		{"100.64.30.21", "sso-eng", "sso"}, {"100.64.30.22", "sso-eng", "sso"},
		{"100.64.64.23", "default", "token"}, {"100.64.64.24", "default", "token"},
	} {
		seedAlloc(f.ip, nbID[f.block], f.method)
	}
	// The aws-prod issued ec2-db-02 host (no heartbeat) — allocated, not "used".
	seedAlloc("100.64.20.30", nbID["aws-prod"], "aws-sigv4")

	// 3) Bulk filler to drive the IPAM health card to red/yellow/green:
	//    - sso-eng (/24, cap 255): fill to ~80% allocated => YELLOW. The 4 SSO hosts above
	//      are heartbeat-confirmed, so it's "high alloc + meaningful used" = a GROW signal.
	//    - sso-contractors (/27, cap 31): fill to >90% allocated => RED, with NO fresh
	//      heartbeats, so used ~0 = a RECLAIM signal.
	//    office-vpn/aws-prod stay green (well under 75%), with healthy `used` from the fleet.
	// sso-eng /24 (cap 255): 4 fleet hosts (.19-.22) + filler .50-.249 (200) = 204
	// allocated => 204/255 ≈ 80.0% (YELLOW). The 4 fleet hosts are fresh, so used is
	// meaningful (high alloc + real used = a GROW signal, not idle space).
	for i := 50; i < 250; i++ {
		seedAlloc(fmt.Sprintf("100.64.30.%d", i), nbID["sso-eng"], "sso")
	}
	// sso-contractors /27 (cap 31): allocate .1-.30 (30) => 30/31 ≈ 96.8% RED, no heartbeats.
	for i := 1; i <= 30; i++ {
		seedAlloc(fmt.Sprintf("100.64.40.%d", i), nbID["sso-contractors"], "sso")
	}

	// SSO user-trust config (ADR 0004): published via dual-control exactly like the
	// cloud-trust config above (propose + approve by distinct actors so it commits and
	// becomes the ACTIVE config the User Trust page renders). Ordered IDPEntries with
	// first-match precedence; AD-group uniqueness holds (distinct directory_group per
	// realm). auto_issue=false on both so the SSO enroll path queues for approval (S8).
	usertrust.RegisterCommitter(dc)
	utCfg := usertrust.Config{
		DefaultGroups: []string{"users"},
		IDPEntries: []usertrust.IDPEntry{
			{Realm: ssoIssuer, DirectoryGroup: "AD-Platform-Engineering", MeshGroups: []string{"eng", "platform"}, Netblock: "sso-eng", AutoIssue: false},
			{Realm: ssoIssuer, DirectoryGroup: "AD-Contractors", MeshGroups: []string{"contractors"}, Netblock: "sso-contractors", AutoIssue: false},
		},
	}
	utPayload, _ := json.Marshal(utCfg)
	utCh, err := dc.Propose(ctx, usertrust.PublishKind, "demo IdP user-trust", utPayload, "chris@hyde.ca")
	if err != nil {
		fatalf("seed user-trust propose: %v", err)
	}
	if _, err := dc.Approve(ctx, utCh.ID, "ops@hyde.ca"); err != nil {
		fatalf("seed user-trust approve: %v", err)
	}

	// A pending SSO enrollment so the Approvals queue shows an SSO enrollment to approve,
	// mirroring the SSO enroll path's evidence (provider=sso, account=issuer,
	// principal=email, region=JSON IdP groups). A contractor (manual approval, S8).
	ssoGroupsJSON, _ := json.Marshal([]string{"AD-Contractors"})
	pendingTS := now.Add(-4 * time.Minute).UnixNano()
	ssoPending := enrollment.Enrollment{
		EnrollmentID:    "enr-sso-001",
		DeviceName:      "contractor-vm-01",
		PubkeyHash:      fmt.Sprintf("%064x", 300),
		Method:          "oidc", // wire method; provenance/provider is "sso" (B7)
		Groups:          `["contractors","users"]`,
		Status:          enrollment.StatusPending,
		CreatedAt:       pendingTS,
		AttestProvider:  ssoProvider,
		AttestAccount:   ssoIssuer,
		AttestPrincipal: "morgan.contractor@hyde.ca",
		AttestRegion:    string(ssoGroupsJSON),
		VerifiedAt:      pendingTS,
	}
	if err := s.DB.WithContext(ctx).Clauses(clause.OnConflict{DoNothing: true}).Create(&ssoPending).Error; err != nil {
		fatalf("seed pending sso enrollment: %v", err)
	}

	// IPAM event-trail audit entries so the dashboard's "recent grows / exhaustion" panel
	// isn't empty (it filters audit for these two actions). These mirror what the
	// allocator/registry emit at runtime (netblock.Grow -> netblock-autogrow; an
	// exhausted block -> netblock-exhausted).
	for _, a := range []struct{ actor, action, target, detail string }{
		{"ipam-autogrow", "netblock-autogrow", "office-vpn", `{"cidr":"100.64.10.0/23"}`},
		{"system", "netblock-exhausted", "sso-contractors", `{"reason":"buddy occupied, non-growing"}`},
	} {
		if err := audit(ctx, a.actor, a.action, a.target, a.detail); err != nil {
			fatalf("seed ipam audit: %v", err)
		}
	}

	// Attested enrollments (aws-sigv4) carrying provider evidence — what the UI renders
	// for cloud-attested hosts.
	for i, a := range []struct {
		name, status, account, arn, ip string
		groups                         []string
	}{
		{"ec2-web-01", enrollment.StatusPending, "111122223333", "arn:aws:sts::111122223333:assumed-role/web-prod/i-0abc", "", []string{"fleet", "web"}},
		{"ec2-db-02", enrollment.StatusIssued, "444455556666", "arn:aws:sts::444455556666:assumed-role/db/i-0def", "100.64.20.30", []string{"fleet", "db"}},
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

	// Issued enrollments matching the heartbeat IPs, so the Devices list shows real
	// provenance (and the scope/condition filters have data): a spread across two AWS
	// accounts and the three join keys. enrollments.overlay_ip joins to heartbeats.
	nameByIP := make(map[string]string, len(devices))
	for _, d := range devices {
		nameByIP[d.OverlayIP] = d.DeviceName
	}
	type prov struct {
		// For aws-sigv4: account/arn/region are the STS evidence. For sso: account is
		// the IdP issuer, principal is the user email, region carries the IdP-asserted
		// directory groups as JSON (exactly how the SSO enroll path records evidence).
		ip, method, joinKey, account, arn, principal, region string
		groups                                               []string
	}
	provs := []prov{
		// office-vpn (100.64.10.0/24) — token via the office (laptops-2026) join key.
		{ip: "100.64.10.11", method: "token", joinKey: "laptops-2026", groups: []string{"laptops"}},
		{ip: "100.64.10.12", method: "token", joinKey: "laptops-2026", groups: []string{"laptops"}},
		{ip: "100.64.10.13", method: "token", joinKey: "laptops-2026", groups: []string{"laptops"}},
		{ip: "100.64.10.14", method: "token", joinKey: "laptops-2026", groups: []string{"laptops"}},
		// aws-prod (100.64.20.0/24) — aws-sigv4.
		{ip: "100.64.20.15", method: "aws-sigv4", account: "111122223333", arn: "arn:aws:sts::111122223333:assumed-role/web-prod/i-015", region: "eu-central-1", groups: []string{"fleet", "web"}},
		{ip: "100.64.20.16", method: "aws-sigv4", account: "111122223333", arn: "arn:aws:sts::111122223333:assumed-role/web-prod/i-016", region: "eu-central-1", groups: []string{"fleet", "web"}},
		{ip: "100.64.20.17", method: "aws-sigv4", account: "444455556666", arn: "arn:aws:sts::444455556666:assumed-role/db/i-017", region: "ap-southeast-1", groups: []string{"fleet", "db"}},
		{ip: "100.64.20.18", method: "aws-sigv4", account: "444455556666", arn: "arn:aws:sts::444455556666:assumed-role/db/i-018", region: "ap-southeast-1", groups: []string{"fleet", "db"}},
		// sso-eng (100.64.30.0/24) — SSO-attested (provider=sso); see the SSO block below.
		{ip: "100.64.30.19", method: "sso", account: ssoIssuer, principal: "alex.eng@hyde.ca", region: `["AD-Platform-Engineering"]`, groups: []string{"eng", "platform", "users"}},
		{ip: "100.64.30.20", method: "sso", account: ssoIssuer, principal: "blair.eng@hyde.ca", region: `["AD-Platform-Engineering"]`, groups: []string{"eng", "platform", "users"}},
		{ip: "100.64.30.21", method: "sso", account: ssoIssuer, principal: "casey.eng@hyde.ca", region: `["AD-Platform-Engineering"]`, groups: []string{"eng", "platform", "users"}},
		{ip: "100.64.30.22", method: "sso", account: ssoIssuer, principal: "devon.eng@hyde.ca", region: `["AD-Platform-Engineering"]`, groups: []string{"eng", "platform", "users"}},
		// 'default' bounded fallback (100.64.64.0/18) — datacenter + ci join keys.
		{ip: "100.64.64.23", method: "token", joinKey: "datacenter-iad", groups: []string{"servers", "iad"}},
		{ip: "100.64.64.24", method: "token", joinKey: "ci-runners", groups: []string{"ci", "ephemeral"}},
	}
	for i, p := range provs {
		groups, _ := json.Marshal(p.groups)
		ts := now.Add(-time.Duration(i+1) * 13 * time.Minute).UnixNano()
		row := enrollment.Enrollment{
			EnrollmentID: fmt.Sprintf("enr-fleet-%03d", i+1),
			DeviceName:   nameByIP[p.ip],
			PubkeyHash:   fmt.Sprintf("%064x", 200+i),
			Method:       p.method,
			Groups:       string(groups),
			Status:       enrollment.StatusIssued,
			OverlayIP:    p.ip,
			CreatedAt:    ts,
			DecidedAt:    ts,
			Approver:     "ops@hyde.ca",
		}
		switch p.method {
		case "token":
			row.JoinKeyID = jkIDs[p.joinKey]
		case "sso":
			// Mirror the SSO enroll path's evidence: provider=sso, account=issuer,
			// principal=email, region=JSON-encoded IdP groups. So the Devices/Enrollments
			// pages render "SSO — email @ issuer" provenance for these hosts.
			row.AttestProvider = ssoProvider
			row.AttestAccount = p.account
			row.AttestPrincipal = p.principal
			row.AttestRegion = p.region
			row.VerifiedAt = ts
		default: // aws-sigv4
			row.AttestProvider = cloudtrust.ProviderAWS
			row.AttestAccount = p.account
			row.AttestPrincipal = p.arn
			row.AttestRegion = p.region
			row.VerifiedAt = ts
		}
		if err := s.DB.WithContext(ctx).Clauses(clause.OnConflict{DoNothing: true}).Create(&row).Error; err != nil {
			fatalf("seed fleet enrollment %s: %v", p.ip, err)
		}
	}

	fmt.Printf("seeded demo fleet: %d devices (each with provenance), 3 lighthouses, 3 join keys (office key -> office-vpn netblock), "+
		"%d issued + 5 queued/decided enrollments (pending + denied), 1 active rollout (v43 canary), "+
		"a published cloud-trust config (aws-prod binding) + policy + 1 pending policy change; "+
		"IPAM: central+default + 4 named netblocks (sso-eng ~80%% yellow, sso-contractors >90%% red), "+
		"~240 ip_allocations with netblock+method provenance; "+
		"a published SSO user-trust config (2 IdP entries) + 4 issued SSO enrollments + 1 pending SSO enrollment to approve\n",
		len(devices), len(provs)+1)
}

// seedHeartbeats builds a believable ~14-host fleet whose facts drive the dashboard:
// a couple of certs near the cliff, one stale host, one clock-skewed, one unhealthy,
// a version spread, and a bundle-version spread (most on v42, the v43 canary leading).
//
// The overlay IPs are laid out so each host falls inside one of the demo's named
// netblocks (seeddemo's IPAM seeding): office-vpn (100.64.10.0/24), aws-prod
// (100.64.20.0/24), sso-eng (100.64.30.0/24), and a couple in the bounded 'default'
// block (100.64.64.0/18). Allocation rows for these same IPs are seeded later, so the
// IPAM page's `used` (allocated ∩ fresh heartbeat) is non-zero and clusters by join
// source — they MUST stay out of 'central' (100.64.0.0/27), which only holds the
// lighthouse/core control-plane IPs.
func seedHeartbeats(now time.Time) []coreapi.Heartbeat {
	type spec struct {
		name, ip, pilot, nebula, health string
		bundle                          int
		certDays                        float64
		lastSeen                        time.Duration // ago
		clockMs                         int
	}
	specs := []spec{
		// office-vpn (token via the office join key).
		{"edge-fra-01", "100.64.10.11", "1.4.0", "1.10.3", "ok", 43, 27, 25 * time.Second, 40},
		{"edge-fra-02", "100.64.10.12", "1.4.0", "1.10.3", "ok", 43, 31, 30 * time.Second, 55},
		{"db-iad-01", "100.64.10.13", "1.4.0", "1.10.3", "ok", 42, 5, 20 * time.Second, 30}, // expiring (<7d)
		{"db-iad-02", "100.64.10.14", "1.3.2", "1.10.3", "ok", 42, 3, 35 * time.Second, 60}, // expiring (<7d)
		// aws-prod (aws-sigv4).
		{"app-iad-01", "100.64.20.15", "1.4.0", "1.10.3", "ok", 42, 22, 40 * time.Second, 20},
		{"app-iad-02", "100.64.20.16", "1.4.0", "1.10.3", "degraded", 42, 26, 45 * time.Second, 35}, // unhealthy
		{"gw-sin-01", "100.64.20.17", "1.4.0", "1.10.3", "ok", 42, 48, 28 * time.Second, 8200},      // clock-skewed
		{"gw-sin-02", "100.64.20.18", "1.3.2", "1.9.0", "ok", 42, 52, 22 * time.Minute, 70},         // stale (>5m)
		// sso-eng (SSO via the demo IdP) — back the issued SSO enrollments below.
		{"edge-syd-02", "100.64.30.19", "1.4.0", "1.10.3", "ok", 42, 40, 30 * time.Second, 25},
		{"edge-syd-03", "100.64.30.20", "1.4.0", "1.10.3", "ok", 42, 44, 33 * time.Second, 45},
		{"app-fra-01", "100.64.30.21", "1.4.0", "1.10.3", "ok", 42, 19, 26 * time.Second, 50},
		{"app-fra-02", "100.64.30.22", "1.4.0", "1.10.3", "ok", 42, 58, 24 * time.Second, 15},
		// 'default' bounded fallback (datacenter / ci join keys).
		{"db-sin-01", "100.64.64.23", "1.3.2", "1.10.3", "ok", 42, 36, 38 * time.Second, 65},
		{"worker-iad-01", "100.64.64.24", "1.4.0", "1.10.3", "ok", 42, 50, 29 * time.Second, 33},
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
