package main

import (
	"context"
	"errors"
	"flag"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/adminapi"
	"github.com/jeks313/nebula-control-plane/internal/adminauth"
	"github.com/jeks313/nebula-control-plane/internal/adminui"
	"github.com/jeks313/nebula-control-plane/internal/auditverify"
	"github.com/jeks313/nebula-control-plane/internal/autotls"
	"github.com/jeks313/nebula-control-plane/internal/bundle"
	"github.com/jeks313/nebula-control-plane/internal/coreapi"
	"github.com/jeks313/nebula-control-plane/internal/enrollment"
	"github.com/jeks313/nebula-control-plane/internal/fleet"
	"github.com/jeks313/nebula-control-plane/internal/genesis"
	"github.com/jeks313/nebula-control-plane/internal/httpserve"
	"github.com/jeks313/nebula-control-plane/internal/ipam"
	"github.com/jeks313/nebula-control-plane/internal/lighthouse"
	"github.com/jeks313/nebula-control-plane/internal/nebularelease"
	"github.com/jeks313/nebula-control-plane/internal/netblock"
	"github.com/jeks313/nebula-control-plane/internal/obs"
	"github.com/jeks313/nebula-control-plane/internal/pilotrelease"
	"github.com/jeks313/nebula-control-plane/internal/queue"
	"github.com/jeks313/nebula-control-plane/internal/rollout"
	"github.com/jeks313/nebula-control-plane/internal/signer"
	"github.com/jeks313/nebula-control-plane/internal/store"
	"github.com/jeks313/nebula-control-plane/internal/wire"
)

// Harbor long-running services: the mesh-only core-api + admin console commands (split from main.go).

func cmdCoreAPI(args []string) {
	fs := flag.NewFlagSet("core-api", flag.ExitOnError)
	cf := addCoreFlags(fs)
	addr := fs.String("addr", ":8444", "listen address (bind to Core's overlay IP in production)")
	tlsCert := fs.String("tls-cert", "", "TLS certificate PEM (serve HTTPS; recommended even mesh-only)")
	tlsKey := fs.String("tls-key", "", "TLS private key PEM (with -tls-cert)")
	acme := autotls.RegisterFlags(fs, "/var/lib/harbor/acme") // auto-TLS via Let's Encrypt (DNS-01)
	hostCert := fs.String("host-cert", "", "Core's own Nebula host cert PEM; verified at boot to carry group:control-plane (recommended)")
	auditInterval := fs.Duration("audit-verify-interval", time.Hour, "how often to re-verify the audit chain into metrics (0 disables); a tamper raises ncp_audit_verify_tampered_total")
	lf := addLogFlags(fs)
	_ = fs.Parse(args)
	log := lf.setup()
	if *cf.caCert == "" {
		fatalf("core-api: -ca-cert is required")
	}
	// Bring-up invariant: the node serving the control plane must present
	// group:control-plane, because the firewall baseline routes every member's
	// renew/heartbeat to that group. Fail fast on a misconfigured identity rather than
	// run silently unreachable. (Skipped, with a warning, when -host-cert is unset.)
	if *hostCert != "" {
		pem, rerr := os.ReadFile(*hostCert)
		if rerr != nil {
			fatalf("core-api: read -host-cert: %v", rerr)
		}
		fp, verr := genesis.VerifyControlPlaneCert(pem)
		if verr != nil {
			fatalf("core-api: %v", verr)
		}
		log.Info("core-api control-plane identity verified", "fingerprint", fp)
	} else {
		log.Warn("core-api: -host-cert not set; cannot verify this node carries group:control-plane (the firewall baseline depends on it)")
	}
	pool, err := netip.ParsePrefix(*cf.pool)
	if err != nil {
		fatalf("core-api: bad -pool: %v", err)
	}
	caPEM, err := os.ReadFile(*cf.caCert)
	if err != nil {
		fatalf("core-api: read -ca-cert: %v", err)
	}
	caB := cf.loadBackend(*cf.caKey, *cf.caLbl, *cf.caKmsKeyID, "CA")
	cfgB := cf.loadBackend(*cf.configKey, *cf.configLbl, *cf.cfgKmsKeyID, "config-signing")
	s := openStore(*cf.driver, *cf.dsn)
	defer s.Close()
	audit := func(c context.Context, a, ac, t, d string) error { _, e := s.AppendAudit(c, a, ac, t, d); return e }
	// Boot-seed central/default for an existing mesh upgraded onto the IPAM build: the
	// migrations created an empty netblocks table but genesis-only seeding left the
	// 'default' block (which the enroll consumer resolves unbound joins to) missing, so
	// every new enrollment would error. No-op when the table is already populated, and
	// race-tolerant if admin-api boot-seeds concurrently (D22). A failure is recoverable
	// next boot (a missing default surfaces as audited/metered enrollment errors), so warn
	// rather than abort the control plane.
	if salloc, serr := ipam.NewAllocator(s, ipam.Pool{Prefix: pool}); serr != nil {
		log.Warn("core-api: ipam allocator for boot-seed failed; skipping netblock boot-seed", "err", serr)
	} else {
		sreg := netblock.New(s.DB, pool, nil, salloc, audit)
		if _, serr := genesis.BootSeedNetblocks(context.Background(), sreg, pool, netip.Prefix{}, netip.Prefix{}, "boot-seed", log); serr != nil {
			log.Warn("core-api: boot-seed of central/default netblocks failed; unbound enrollments may error until 'default' exists", "err", serr)
		}
	}
	sg, err := signer.New(signer.Config{
		CACertPEM: caPEM, Backend: caB,
		Policy: signer.IssuePolicy{AllowedNetwork: pool, MaxLifetime: *cf.certLifetime}, Audit: audit,
		// Fleet-wide signing breaker (shared with the enroll consumer, lane "ca") so the
		// cert/hour ceiling holds across ≥2 Cores and a trip halts every Core (HA).
		Breaker: signer.NewSQLBreaker(s.DB, signer.LaneCA, *cf.maxPerHour, time.Hour),
	})
	if err != nil {
		fatalf("core-api: signer: %v", err)
	}
	cfgPub, _ := cfgB.PublicKey()
	api := coreapi.New(coreapi.Config{
		Store: s, Signer: sg, ConfigBackend: cfgB, ConfigKeyID: wire.PubkeyHash(cfgPub),
		CABundlePEM: caPEM, Lighthouses: parseLighthouses(*cf.lighthouse), LighthouseSource: cf.lighthouseSource(s), Policy: cf.policy(s),
		BlocklistSource: cf.blocklistSource(s),
		Rollout:         rollout.New(s.DB, audit),
		NebulaReleases:  nebularelease.New(s.DB),
		PilotReleases:   pilotrelease.New(s.DB),
		Pool:            pool, TunDev: *cf.tunDev, ListenPort: *cf.listenPort, CertLifetime: *cf.certLifetime,
		NebulaVersion: *cf.nebulaVersion, NebulaSHA256: *cf.nebulaSHA256, NebulaURL: *cf.nebulaURL,
		PilotVersion: *cf.pilotVersion, PilotSHA256: *cf.pilotSHA256, PilotURL: *cf.pilotURL,
	})
	// Mesh-only observability: /metrics + /healthz + /readyz alongside the v1 API. The DB
	// readiness probe is cached (1s) so an unauthenticated /readyz flood can't starve the
	// scarce single SQLite connection or contend with real renew/heartbeat traffic.
	mux := http.NewServeMux()
	obs.Mount(mux, obs.Cache(time.Second, obs.Check{Name: "database", Probe: s.Ping}))
	mux.Handle("/", api.Handler())
	srv := &http.Server{
		Addr: *addr, Handler: mux,
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
		WriteTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 8 << 10,
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		log.Info("core-api shutting down", "reason", "signal")
		sc, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sc)
	}()
	// Background metric maintainers, joined on shutdown so an in-flight scan finishes before
	// the DB pool closes (deferred s.Close above): the periodic audit-chain verifier (a tamper
	// raises ncp_audit_verify_tampered_total) and the breaker-gauge reconciler (keeps
	// ncp_signer_breaker_open fleet-truthful on an idle Core).
	var wg sync.WaitGroup
	if *auditInterval > 0 {
		wg.Add(1)
		go func() { defer wg.Done(); auditverify.New(s, *auditInterval, log).Run(ctx) }()
	}
	wg.Add(1)
	go func() { defer wg.Done(); sg.RunBreakerMetric(ctx, 15*time.Second) }()
	if err := acme.Apply(ctx, srv); err != nil {
		fatalf("core-api: auto-TLS: %v", err)
	}
	log.Info("core-api listening", "addr", *addr, "scheme", httpserve.SchemeFor(srv, *tlsCert, *tlsKey), "access", "mesh-only", "pool", pool.String(), "version", version)
	if err := httpserve.Serve(srv, *tlsCert, *tlsKey); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fatalf("core-api: %v", err)
	}
	wg.Wait() // let the verifier/reconciler finish before the deferred s.Close() drops the pool
	log.Info("core-api stopped")
}

// cmdAdminAPI serves the admin HTTP API (UI track A0): the /admin/v1 surface the
// console consumes. Mesh-only — bind to Core's overlay IP in production. Until
// 2.11 (OIDC/MFA/RBAC), -dev-auth trusts an X-Harbor-Dev-Actor header so the
// console can be dogfooded; it must never be enabled in production.
func cmdAdminAPI(args []string) {
	fs := flag.NewFlagSet("admin-api", flag.ExitOnError)
	cf := addCoreFlags(fs) // backend/CA/queue flags — present => issuance mode (enroll approve)
	addr := fs.String("addr", ":8445", "listen address (bind to Core's overlay IP in production)")
	devAuth := fs.Bool("dev-auth", false, "DEV ONLY: trust the X-Harbor-Dev-Actor header for identity (never in prod)")
	devRole := fs.String("dev-role", "admin", "role granted to the dev actor")
	mfaFreshness := fs.Duration("mfa-freshness", 15*time.Minute, "require MFA within this window for privileged actions (dual-control approve, policy publish); 0 disables step-up")
	environment := fs.String("environment", "development", "deployment posture shown in the console banner (e.g. production, staging); anything but production is tinted non-production")
	af := addAdminAuthFlags(fs) // OIDC / GitHub / mock-IdP session auth (2.11)
	expiryWithin := fs.Duration("expiry-within", 7*24*time.Hour, "cert-expiry health window")
	staleAfter := fs.Duration("stale-after", 5*time.Minute, "stale-host health window")
	clockSkew := fs.Int("clock-skew-ms", 5000, "clock-skew health threshold (ms)")
	tlsCert := fs.String("tls-cert", "", "TLS certificate PEM (serve HTTPS; recommended even mesh-only — Secure cookies, HTTP/2)")
	tlsKey := fs.String("tls-key", "", "TLS private key PEM (with -tls-cert)")
	acme := autotls.RegisterFlags(fs, "/var/lib/harbor/acme") // auto-TLS via Let's Encrypt (DNS-01)
	lf := addLogFlags(fs)
	_ = fs.Parse(args)
	// TLS terminates in-process via either a static cert/key pair OR auto-TLS (ACME) — both
	// mean session/CSRF cookies must be Secure (and both satisfy the production guard below).
	tlsOn := (*tlsCert != "" && *tlsKey != "") || acme.Enabled()
	log := lf.setup()

	// Issuance mode: when the CA/signing config is supplied, build the full
	// enrollment consumer so the approval queue can issue certs. Otherwise run
	// read-only (list + deny; approve returns 501).
	var (
		s        *store.Store
		consumer *enrollment.Consumer
		canIssue bool
	)
	if *cf.caCert != "" {
		var q *queue.Durable
		consumer, q, s = cf.build()
		defer q.Close()
		canIssue = true
		log.Info("admin-api issuance mode", "enroll_approve", "enabled")
	} else {
		s = openStore(*cf.driver, *cf.dsn)
		log.Info("admin-api read-only mode", "enroll_approve", "disabled (pass -ca-cert/-config-key/-queue-* to enable)")
	}
	defer s.Close()
	// Fail fast on an unmigrated/stale DB (a common footgun: pointing -dsn at a fresh
	// file). The console's session auth needs the sessions table (migration 000009);
	// without this, login fails later with a cryptic "no such table: sessions" 500.
	if !s.DB.Migrator().HasTable("sessions") {
		fatalf("admin-api: database has no schema (no 'sessions' table) — run 'harbor migrate up' against this -dsn first (or 'harbor seed-demo' for a demo)")
	}
	audit := func(c context.Context, a, ac, t, d string) error { _, e := s.AppendAudit(c, a, ac, t, d); return e }

	// Authentication. Real session auth (OIDC / GitHub / mock IdP) takes precedence;
	// otherwise the -dev-auth header seam; otherwise every request is 401.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if tlsOn {
		*af.secure = true // HTTPS → session/CSRF cookies must be Secure
	}
	// Fail closed on the production posture: -environment=production is the operator's
	// "this is prod" signal, so enforce the invariants here rather than only warning.
	// (af.secure may be set by in-process TLS above or by -auth-secure behind a proxy.)
	if strings.EqualFold(*environment, "production") {
		if *devAuth {
			fatalf("admin-api: -dev-auth must never be enabled in production (-environment=production)")
		}
		if !*af.secure {
			fatalf("admin-api: -environment=production requires Secure cookies; serve TLS in-process (-acme-domain or -tls-cert/-tls-key), or set -auth-secure (only behind a TLS-terminating proxy)")
		}
	}
	sessionIdP, authHandler, csrfWrap, authCleanup := buildAdminAuth(ctx, af, *addr, s.DB)
	defer authCleanup()

	// Bearer-token auth (A0.8) is always available for non-interactive callers
	// (automation/CI/curl); a human session (or the dev seam) is chained behind it.
	tokenProvider := adminauth.NewTokenProvider(adminauth.NewTokenStore(s.DB, nil))
	var human adminapi.IdentityProvider
	switch {
	case sessionIdP != nil:
		human = sessionIdP
		if *devAuth {
			log.Warn("admin-api: -dev-auth ignored — real session auth is configured")
		}
		log.Info("admin-api auth: bearer tokens + session (OIDC/SAML/GitHub)", "login", "/admin/v1/auth/login")
	case *devAuth:
		human = adminapi.DevHeaderProvider{Roles: []string{*devRole}, MFA: *mfaFreshness > 0}
		log.Warn("admin-api auth: bearer tokens + DEV-AUTH — never enable dev-auth in production")
	default:
		log.Info("admin-api auth: bearer tokens only", "hint", "add -oidc-issuer/-github-client-id/-mock-idp or -dev-auth for human login")
	}
	idp := adminapi.ChainProvider{tokenProvider, human} // token first, then the human path

	// IPAM (ADR 0010): wire the netblock registry + allocator the admin IPAM surface
	// reads/writes. Constructed from -pool exactly as enroll/genesis do — the allocator
	// backs the registry's stranding guard, the registry is its netblock resolver.
	pool, perr := netip.ParsePrefix(*cf.pool)
	if perr != nil {
		fatalf("admin-api: bad -pool: %v", perr)
	}
	alloc, aerr := ipam.NewAllocator(s, ipam.Pool{Prefix: pool})
	if aerr != nil {
		fatalf("admin-api: ipam: %v", aerr)
	}
	nbReg := netblock.New(s.DB, pool, nil, alloc, audit)
	alloc = alloc.WithResolver(nbReg)
	// Boot-seed central/default for an existing mesh upgraded onto the IPAM build
	// (migrations created an empty netblocks table but genesis-only seeding left the
	// 'default' block — which unbound enrollments resolve to — missing). No-op when the
	// table is already populated, and race-tolerant if core-api boot-seeds at the same
	// time (D22). A failure surfaces as enrollment errors (audited/metered) and is
	// retried next boot, so warn rather than abort startup.
	if _, err := genesis.BootSeedNetblocks(ctx, nbReg, pool, netip.Prefix{}, netip.Prefix{}, "boot-seed", log); err != nil {
		log.Warn("admin-api: boot-seed of central/default netblocks failed; unbound enrollments may error until 'default' exists", "err", err)
	}

	api := adminapi.New(adminapi.Config{
		Store: s, Identity: idp,
		Rollout: rollout.New(s.DB, audit), Lighthouses: lighthouse.New(s.DB, audit),
		Enrollment: consumer, CanIssue: canIssue,
		Netblocks: nbReg, Allocator: alloc, Pool: pool,
		Thresholds:   fleet.Thresholds{ExpiryWindow: *expiryWithin, StaleAfter: *staleAfter, ClockSkewMs: *clockSkew},
		MFAFreshness: *mfaFreshness,
	})

	// Compose: auth routes (unauthenticated) + the CSRF-guarded JSON API + the web
	// console (SPA). The SPA serves "/" and client routes; /admin/v1 is the API.
	apiHandler := api.Handler()
	if csrfWrap != nil {
		apiHandler = csrfWrap(apiHandler)
	}
	top := http.NewServeMux()
	if authHandler != nil {
		top.Handle("/admin/v1/auth/", authHandler) // unauthenticated login/callback/logout
	}
	obs.Mount(top, obs.Cache(time.Second, obs.Check{Name: "database", Probe: s.Ping})) // /metrics + /healthz + /readyz (unauthenticated)
	top.Handle("/admin/v1/", apiHandler)                                               // the JSON API
	top.Handle("/", adminui.Handler(adminui.Config{Environment: *environment}))        // the React console (or a "not built" stub)
	handler := http.Handler(top)
	if adminui.Embedded() {
		log.Info("admin-api: web console enabled (embedded SPA at /)")
	}

	srv := &http.Server{
		Addr: *addr, Handler: handler,
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
		WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 8 << 10,
	}
	go func() {
		<-ctx.Done()
		log.Info("admin-api shutting down", "reason", "signal")
		sc, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sc)
	}()
	if err := acme.Apply(ctx, srv); err != nil {
		fatalf("admin-api: auto-TLS: %v", err)
	}
	log.Info("admin-api listening", "addr", *addr, "scheme", httpserve.SchemeFor(srv, *tlsCert, *tlsKey), "access", "mesh-only", "version", version)
	if err := httpserve.Serve(srv, *tlsCert, *tlsKey); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fatalf("admin-api: %v", err)
	}
	log.Info("admin-api stopped")
}

func parseLighthouses(s string) []bundle.Lighthouse {
	var out []bundle.Lighthouse
	for _, pair := range parseCSV(s) {
		ip, addr, ok := strings.Cut(pair, "=")
		if !ok {
			fatalf("enroll: bad -lighthouse %q (want overlayIP=host:port)", pair)
		}
		out = append(out, bundle.Lighthouse{OverlayIP: ip, PublicAddrs: []string{addr}})
	}
	return out
}
