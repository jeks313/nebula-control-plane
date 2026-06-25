package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/bundle"
	"github.com/jeks313/nebula-control-plane/internal/cloudtrust"
	"github.com/jeks313/nebula-control-plane/internal/collect"
	"github.com/jeks313/nebula-control-plane/internal/enrollment"
	"github.com/jeks313/nebula-control-plane/internal/gatewayreg"
	"github.com/jeks313/nebula-control-plane/internal/ipam"
	"github.com/jeks313/nebula-control-plane/internal/lighthouse"
	"github.com/jeks313/nebula-control-plane/internal/nebularelease"
	"github.com/jeks313/nebula-control-plane/internal/netblock"
	"github.com/jeks313/nebula-control-plane/internal/nonce"
	"github.com/jeks313/nebula-control-plane/internal/obs"
	"github.com/jeks313/nebula-control-plane/internal/pilotrelease"
	"github.com/jeks313/nebula-control-plane/internal/policy"
	"github.com/jeks313/nebula-control-plane/internal/queue"
	"github.com/jeks313/nebula-control-plane/internal/replay"
	"github.com/jeks313/nebula-control-plane/internal/revocation"
	"github.com/jeks313/nebula-control-plane/internal/rollout"
	"github.com/jeks313/nebula-control-plane/internal/signer"
	"github.com/jeks313/nebula-control-plane/internal/ssoassert"
	"github.com/jeks313/nebula-control-plane/internal/store"
	"github.com/jeks313/nebula-control-plane/internal/usertrust"
	"github.com/jeks313/nebula-control-plane/internal/wire"
)

// Harbor enrollment consumer wiring (coreFlags) + the enroll worker/collect/pending/approve commands (split from main.go).

// coreFlags wires Core's enrollment consumer (worker/approve).
type coreFlags struct {
	driver, dsn                            *string
	backend                                *string
	caCert, caKey, configKey               *string
	module, token, pin, caLbl, configLbl   *string
	caKmsKeyID, cfgKmsKeyID, kmsRegion     *string
	hmacKey, queueDSN, queueKey            *string
	pool                                   *string
	tunDev                                 *string
	listenPort                             *int
	nebulaVersion, nebulaSHA256, nebulaURL *string
	pilotVersion, pilotSHA256, pilotURL    *string
	certLifetime                           *time.Duration
	ephemeralCertLifetime                  *time.Duration
	maxPerHour                             *int
	lighthouse                             *string
	lighthouseDB                           *bool
	blocklistDB                            *bool
	policyFile                             *string
	policyDB                               *bool
	cloudTrustDB                           *bool
	userTrustDB                            *bool
	ssoAssertPub                           *string
}

func addCoreFlags(fs *flag.FlagSet) *coreFlags {
	cf := &coreFlags{}
	cf.driver, cf.dsn = dbFlags(fs)
	// Signing + queue + pool flag DEFAULTS come from HARBOR_* env vars when set (an explicit -flag still
	// wins), mirroring dbFlags — so an interactive shell on the control-plane node can run a core
	// subcommand (e.g. `harbor enroll approve <id> -approver A`) without retyping the CA/KMS/queue/pool
	// wiring. The systemd units pass explicit flags, so they are unaffected; tests with no env keep the
	// original defaults. /etc/profile.d/harbor-cli.sh exports these on the harbor node (bootstrap-genesis).
	cf.backend = fs.String("backend", envOr("HARBOR_BACKEND", "software"), "CA/config backend: software|pkcs11|kms (default: $HARBOR_BACKEND, else software)")
	cf.caCert = fs.String("ca-cert", os.Getenv("HARBOR_CA_CERT"), "CA certificate PEM (required) (default: $HARBOR_CA_CERT)")
	cf.caKey = fs.String("ca-key", os.Getenv("HARBOR_CA_KEY"), "software CA key (software backend) (default: $HARBOR_CA_KEY)")
	cf.configKey = fs.String("config-key", os.Getenv("HARBOR_CONFIG_KEY"), "software config-signing key (software backend) (default: $HARBOR_CONFIG_KEY)")
	cf.module = fs.String("pkcs11-module", "/usr/lib/softhsm/libsofthsm2.so", "PKCS#11 module")
	cf.token = fs.String("pkcs11-token", "", "PKCS#11 token label")
	cf.pin = fs.String("pkcs11-pin", "", "PKCS#11 PIN")
	cf.caLbl = fs.String("pkcs11-ca-key-label", "", "PKCS#11 CA key label")
	cf.configLbl = fs.String("pkcs11-config-key-label", "", "PKCS#11 config-signing key label")
	cf.caKmsKeyID = fs.String("kms-ca-key-id", os.Getenv("HARBOR_KMS_CA_KEY_ID"), "KMS CA key id/arn (kms backend) (default: $HARBOR_KMS_CA_KEY_ID)")
	cf.cfgKmsKeyID = fs.String("kms-config-key-id", os.Getenv("HARBOR_KMS_CONFIG_KEY_ID"), "KMS config-signing key id/arn (kms backend) (default: $HARBOR_KMS_CONFIG_KEY_ID)")
	cf.kmsRegion = fs.String("kms-region", os.Getenv("HARBOR_KMS_REGION"), "AWS region for KMS (kms backend; else the default chain) (default: $HARBOR_KMS_REGION)")
	cf.hmacKey = fs.String("hmac-key", os.Getenv("HARBOR_HMAC_KEY"), "nonce HMAC key (base64url, shared with gateway) (required) (default: $HARBOR_HMAC_KEY)")
	cf.queueDSN = fs.String("queue-dsn", os.Getenv("HARBOR_QUEUE_DSN"), "durable queue DSN (required) (default: $HARBOR_QUEUE_DSN)")
	cf.queueKey = fs.String("queue-key", os.Getenv("HARBOR_QUEUE_KEY"), "queue HMAC key (base64url, shared with gateway) (required) (default: $HARBOR_QUEUE_KEY)")
	cf.pool = fs.String("pool", envOr("HARBOR_POOL", "100.64.0.0/16"), "overlay pool CIDR (default: $HARBOR_POOL, else 100.64.0.0/16)")
	cf.tunDev = fs.String("tun-dev", "nebula1", "nebula TUN device name stamped into this mesh's bundles (use a DISTINCT name per mesh on multi-mesh hosts)")
	cf.listenPort = fs.Int("listen-port", 4242, "nebula UDP listen port stamped into this mesh's bundles (use a DISTINCT port per mesh on multi-mesh hosts)")
	cf.nebulaVersion = fs.String("nebula-version", "", "nebula version Harbor distributes to the fleet (ADR 0003); stamped into every bundle (empty -> hosts keep their current nebula)")
	cf.nebulaSHA256 = fs.String("nebula-sha256", "", "hex SHA-256 of the nebula binary (the integrity anchor pilots verify before exec); required with -nebula-url")
	cf.nebulaURL = fs.String("nebula-url", "", "URL pilots fetch the nebula binary from (sha-verified, so the source need not be trusted)")
	cf.pilotVersion = fs.String("pilot-version", "", "pilot (agent) version Harbor distributes to the fleet (ADR 0003 Phase 3c); stamped into every bundle (empty -> hosts keep their current pilot)")
	cf.pilotSHA256 = fs.String("pilot-sha256", "", "hex SHA-256 of the pilot binary (the integrity anchor pilots verify before re-exec); required with -pilot-url")
	cf.pilotURL = fs.String("pilot-url", "", "URL pilots fetch the new pilot binary from (sha-verified)")
	cf.certLifetime = fs.Duration("cert-lifetime", 30*24*time.Hour, "issued cert validity")
	cf.ephemeralCertLifetime = fs.Duration("ephemeral-cert-lifetime", 24*time.Hour, "issued cert validity for hosts joining via an ephemeral join key (shorter than -cert-lifetime; foundation for the auto-reaping lifecycle, impl 2.12)")
	cf.maxPerHour = fs.Int("max-certs-per-hour", 0, "signing circuit-breaker ceiling (0=unlimited)")
	cf.lighthouse = fs.String("lighthouse", "", "lighthouses for the bundle: overlayIP=host:port[,...]")
	cf.lighthouseDB = fs.Bool("lighthouse-db", false, "source lighthouses from the DB registry (6.8) instead of -lighthouse")
	cf.blocklistDB = fs.Bool("blocklist-db", false, "source the cert blocklist (pki.blocklist) from the DB revocations registry (7.1)")
	cf.policyFile = fs.String("policy", "", "central firewall policy file (M6); omit for Pilot's local default")
	cf.policyDB = fs.Bool("policy-db", false, "use the dual-control published policy from the DB (6.5) instead of -policy")
	cf.cloudTrustDB = fs.Bool("cloudtrust-db", false, "enable AWS SigV4 attestation using the dual-control published cloud-trust config from the DB (M5)")
	// SSO enrollment (ADR 0004). Both pieces are required for SSO; with either unset the
	// enroll consumer fails closed (ErrSSONotConfigured) and oidc enrollments are denied.
	cf.userTrustDB = fs.Bool("usertrust-db", false, "enable SSO enrollment using the dual-control published user-trust config from the DB (ADR 0004 S1); read live per enrollment")
	cf.ssoAssertPub = fs.String("sso-assert-pub", "", "PINNED gateway assertion-signing PUBLIC key PEM (ADR 0004 S6 — from genesis sso-assert.pub); enables SSO assertion verification. Unset -> SSO enrollments are denied (fail closed)")
	return cf
}

// policy resolves the central firewall policy Core serves into bundles. With
// -policy-db it reads the active, dual-control-published policy from the store
// (6.5 — the active policy is the latest committed policy.publish change);
// otherwise it reads the -policy file (or nil for Pilot's local default).
func (cf *coreFlags) policy(s *store.Store) *policy.Policy {
	if *cf.policyDB {
		p, ok := activePolicy(context.Background(), s)
		if !ok {
			fmt.Fprintln(os.Stderr, "harbor: -policy-db set but no policy has been published yet; serving default-deny")
			return nil
		}
		return &p
	}
	if *cf.policyFile == "" {
		return nil
	}
	p := loadPolicy(*cf.policyFile)
	return &p
}

// cloudTrust resolves the active cloud-attestation trust config (M5). With
// -cloudtrust-db it reads the latest committed cloudtrust.publish change; nil means
// aws-sigv4 attestation stays disabled (fail closed). Read once at startup, like policy.
func (cf *coreFlags) cloudTrust(s *store.Store) *cloudtrust.Config {
	if !*cf.cloudTrustDB {
		return nil
	}
	c, ok := activeCloudTrust(context.Background(), s)
	if !ok {
		fmt.Fprintln(os.Stderr, "harbor: -cloudtrust-db set but no cloud-trust config has been published yet; aws-sigv4 attestation disabled")
		return nil
	}
	return &c
}

// assertionVerifyKey resolves the PINNED gateway assertion-signing public key (ADR 0004
// S6) from -sso-assert-pub. nil (flag unset) means SSO verification is disabled and the
// enroll consumer fails closed (ErrSSONotConfigured) on an oidc enrollment. Read once at
// startup, like the CA cert — the pinned key is a deploy-time trust anchor, not a
// live-rotated value.
func (cf *coreFlags) assertionVerifyKey() *ecdsa.PublicKey {
	if *cf.ssoAssertPub == "" {
		return nil
	}
	pem, err := os.ReadFile(*cf.ssoAssertPub)
	if err != nil {
		fatalf("read -sso-assert-pub: %v", err)
	}
	pub, err := ssoassert.ParsePublicKeyPEM(pem)
	if err != nil {
		fatalf("-sso-assert-pub: %v", err)
	}
	return pub
}

// userTrustActive returns the LIVE active user-trust source for the enroll consumer (ADR
// 0004 S1). Unlike cloudTrust (a snapshot pointer read once at consumer build), this is a
// GETTER closure so the dual-control-published config is read live per enrollment —
// changing who may enroll needs no Core restart (the seam UserTrustActive expects, B8).
// nil (flag unset) means SSO is disabled and the consumer fails closed. The getter itself
// returns nil until a config is published; the consumer treats that as not-configured.
func (cf *coreFlags) userTrustActive(s *store.Store) func() *usertrust.Config {
	if !*cf.userTrustDB {
		return nil
	}
	return func() *usertrust.Config {
		c, ok := activeUserTrust(context.Background(), s)
		if !ok {
			return nil // not published yet -> SSO not configured (fail closed)
		}
		return &c
	}
}

// lighthouseSource returns the live registry source when -lighthouse-db is set,
// else nil (Core then uses the static -lighthouse list).
func (cf *coreFlags) lighthouseSource(s *store.Store) func(context.Context) ([]bundle.Lighthouse, error) {
	if !*cf.lighthouseDB {
		return nil
	}
	reg := lighthouse.New(s.DB, nil)
	return reg.Active
}

// blocklistSource returns the live revocations source (pki.blocklist) when
// -blocklist-db is set, else nil. Consulted at bundle-build time so a revocation
// propagates to the healthy fleet via the next signed bundle (7.1).
func (cf *coreFlags) blocklistSource(s *store.Store) func(context.Context) ([]string, error) {
	if !*cf.blocklistDB {
		return nil
	}
	reg := revocation.New(s.DB, nil)
	return reg.ActiveFingerprints
}

// buildConsumer assembles the enrollment Consumer (signer, IPAM, nonce verify,
// policy/blocklist/lighthouse sources, cloud-trust) over store s, delivering poll
// results to `results`. Shared by the queue worker (results = the durable queue)
// and the ADR-0005 collector (results = a ship-back CaptureSink). Needs -ca-cert
// + -hmac-key; the queue is the caller's concern.
func (cf *coreFlags) buildConsumer(s *store.Store, results enrollment.ResultSink) *enrollment.Consumer {
	if *cf.caCert == "" || *cf.hmacKey == "" {
		fatalf("-ca-cert and -hmac-key are required")
	}
	pool, err := netip.ParsePrefix(*cf.pool)
	if err != nil {
		fatalf("bad -pool: %v", err)
	}
	caPEM, err := os.ReadFile(*cf.caCert)
	if err != nil {
		fatalf("read -ca-cert: %v", err)
	}
	caB := cf.loadBackend(*cf.caKey, *cf.caLbl, *cf.caKmsKeyID, "CA")
	cfgB := cf.loadBackend(*cf.configKey, *cf.configLbl, *cf.cfgKmsKeyID, "config-signing")
	audit := func(c context.Context, a, ac, t, d string) error { _, e := s.AppendAudit(c, a, ac, t, d); return e }
	sg, err := signer.New(signer.Config{
		CACertPEM: caPEM, Backend: caB,
		Policy: signer.IssuePolicy{AllowedNetwork: pool, MaxLifetime: *cf.certLifetime},
		// Fleet-wide signing breaker (shared with core-api renewal, lane "ca") so the
		// cert/hour ceiling holds across ≥2 Cores and a trip halts every Core (HA).
		Breaker: signer.NewSQLBreaker(s.DB, signer.LaneCA, *cf.maxPerHour, time.Hour),
		Audit:   audit,
	})
	if err != nil {
		fatalf("signer: %v", err)
	}
	alloc, err := ipam.NewAllocator(s, ipam.Pool{Prefix: pool})
	if err != nil {
		fatalf("ipam: %v", err)
	}
	// IPAM (ADR 0010): resolve netblock names via the DB-backed registry (cached,
	// invalidated on CRUD) so per-join-method CIDRs + provenance + auto-grow are live.
	nbReg := netblock.New(s.DB, pool, nil, alloc, audit)
	alloc = alloc.WithResolver(nbReg)
	ring, err := nonce.NewKeyring([][]byte{readB64Key(*cf.hmacKey)}, 0, 0)
	if err != nil {
		fatalf("nonce key: %v", err)
	}
	cfgPub, _ := cfgB.PublicKey()
	ct := cf.cloudTrust(s) // nil unless -cloudtrust-db && a config is published
	// A newly enrolling host joins on the CURRENT fleet-desired nebula release (the
	// latest completed nebula-lane rollout, 6.6/1c), falling back to the static flags
	// when no release has settled. Staged updates after enrollment converge via renew.
	eng := rollout.New(s.DB, audit)
	reg := nebularelease.New(s.DB)
	nebulaReleaseFor := func(ctx context.Context, goos, goarch string) (version, sha256, url string) {
		if gen := eng.CurrentNebulaGen(ctx); gen != 0 {
			if v, sh, u, ok := reg.Lookup(ctx, gen, goos, goarch); ok {
				return v, sh, u
			}
			// A settled release exists but not for this host's arch: leave nebula unset rather
			// than fall back to a wrong-arch static flag — the host converges once its arch is registered.
			return "", "", ""
		}
		return *cf.nebulaVersion, *cf.nebulaSHA256, *cf.nebulaURL
	}
	// A new host also joins on the current fleet-desired PILOT release (3c), falling
	// back to the static flags.
	pilotReg := pilotrelease.New(s.DB)
	pilotReleaseFor := func(ctx context.Context, goos, goarch string) (version, sha256, url string) {
		if gen := eng.CurrentPilotGen(ctx); gen != 0 {
			if v, sh, u, ok := pilotReg.Lookup(ctx, gen, goos, goarch); ok {
				return v, sh, u
			}
			return "", "", "" // settled release exists but not for this arch — leave pilot unset
		}
		return *cf.pilotVersion, *cf.pilotSHA256, *cf.pilotURL
	}
	return enrollment.New(enrollment.Config{
		// Shared, DB-backed replay guard so single-use holds across ≥2 Core processes
		// (a per-process cache would let a nonce be reused once per Core).
		Store: s, Nonces: ring, Replay: replay.NewSQLStore(s.DB, 2*time.Minute),
		Signer: sg, Allocator: alloc, Pool: pool, CertLifetime: *cf.certLifetime,
		EphemeralCertTTL: *cf.ephemeralCertLifetime,
		TunDev:           *cf.tunDev, ListenPort: *cf.listenPort,
		NebulaVersion: *cf.nebulaVersion, NebulaSHA256: *cf.nebulaSHA256, NebulaURL: *cf.nebulaURL,
		NebulaReleaseFor: nebulaReleaseFor,
		PilotVersion:     *cf.pilotVersion, PilotSHA256: *cf.pilotSHA256, PilotURL: *cf.pilotURL,
		PilotReleaseFor: pilotReleaseFor,
		ConfigBackend:   cfgB, ConfigKeyID: wire.PubkeyHash(cfgPub),
		CABundlePEM: caPEM, Lighthouses: parseLighthouses(*cf.lighthouse), LighthouseSource: cf.lighthouseSource(s), Policy: cf.policy(s),
		BlocklistSource: cf.blocklistSource(s),
		Results:         results, ResultTTL: time.Hour,
		CloudTrust: ct, AWSSigV4Enabled: ct != nil,
		// SSO enrollment (ADR 0004): the PINNED gateway assertion-signing public key (S6,
		// read once) + the LIVE user-trust source (S1, a getter read per enrollment). With
		// either unset, processSSO returns the terminal ErrSSONotConfigured (fail closed).
		AssertionVerifyKey: cf.assertionVerifyKey(),
		UserTrustActive:    cf.userTrustActive(s),
	})
}

func (cf *coreFlags) build() (*enrollment.Consumer, *queue.Durable, *store.Store) {
	return cf.buildWithStore(openStore(*cf.driver, *cf.dsn))
}

// buildWithStore is build() over a CALLER-OPENED store, so a caller that must run
// a step against the store BEFORE the consumer is assembled (e.g. admin-api's
// boot-seed, which the consumer's build-time policy/cloud-trust snapshot depends
// on — fail-closed bug, ADR 0011 Phase 1 C8) can do so on the same handle. The
// consumer then reads the freshly-seeded config rather than an empty store.
func (cf *coreFlags) buildWithStore(s *store.Store) (*enrollment.Consumer, *queue.Durable, *store.Store) {
	if *cf.queueDSN == "" || *cf.queueKey == "" {
		fatalf("enroll: -queue-dsn and -queue-key are required")
	}
	q, err := queue.OpenDurable(queue.DurableConfig{DSN: *cf.queueDSN, Key: readB64Key(*cf.queueKey)})
	if err != nil {
		fatalf("enroll: queue: %v", err)
	}
	cons := cf.buildConsumer(s, q)
	return cons, q, s
}

func (cf *coreFlags) loadBackend(softKey, label, kmsKeyID, what string) signer.Backend {
	switch *cf.backend {
	case "software":
		if softKey == "" {
			fatalf("enroll: software backend requires the %s key path", what)
		}
		pem, err := os.ReadFile(softKey)
		if err != nil {
			fatalf("enroll: read %s key: %v", what, err)
		}
		b, err := signer.LoadSoftwareBackendPEM(pem)
		if err != nil {
			fatalf("enroll: load %s key: %v", what, err)
		}
		return b
	case "pkcs11":
		b, err := signer.NewPKCS11Backend(signer.PKCS11Config{ModulePath: *cf.module, TokenLabel: *cf.token, Pin: *cf.pin, KeyLabel: label})
		if err != nil {
			fatalf("enroll: %s pkcs11: %v", what, err)
		}
		return b
	case "kms":
		if kmsKeyID == "" {
			fatalf("enroll: kms backend requires the %s KMS key id", what)
		}
		b, err := signer.NewKMSBackend(context.Background(), signer.KMSConfig{KeyID: kmsKeyID, Region: *cf.kmsRegion})
		if err != nil {
			fatalf("enroll: %s kms: %v", what, err)
		}
		return b
	default:
		fatalf("enroll: unknown backend %q", *cf.backend)
		return nil
	}
}

func cmdEnrollCore(args []string) {
	if len(args) < 1 {
		fatalf("enroll: want 'worker', 'pending', or 'approve'")
	}
	switch args[0] {
	case "worker":
		enrollWorker(args[1:])
	case "pending":
		enrollPending(args[1:])
	case "approve":
		enrollApprove(args[1:])
	default:
		fatalf("enroll: unknown subcommand %q", args[0])
	}
}

func enrollWorker(args []string) {
	fs := flag.NewFlagSet("enroll worker", flag.ExitOnError)
	cf := addCoreFlags(fs)
	batch := fs.Int("batch", 16, "max messages claimed per cycle")
	interval := fs.Duration("interval", 500*time.Millisecond, "idle poll interval")
	lease := fs.Duration("lease", time.Minute, "claim lease duration")
	lf := addLogFlags(fs)
	_ = fs.Parse(args)
	log := lf.setup()

	cons, q, s := cf.build()
	defer s.Close()
	defer q.Close()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	log.Info("enroll worker started", "batch", *batch, "interval", interval.String(), "lease", lease.String())
	var total int
	for ctx.Err() == nil {
		n, err := cons.Drain(ctx, q, *batch, *lease)
		if err != nil {
			log.Error("enroll worker: drain failed", "err", err)
		}
		if n == 0 {
			select {
			case <-ctx.Done():
			case <-time.After(*interval):
			}
		} else {
			total += n
			log.Info("enroll worker: processed batch", "count", n, "total", total)
		}
	}
	log.Info("enroll worker stopped", "total_processed", total)
}

// cmdCollect runs the ADR-0005 pull collector: it PULLS pending candidates from a
// gateway over leaf-pinned mTLS, verifies + issues them (reusing the enrollment
// Consumer), pushes results back, and acks — replacing the shared-queue `enroll
// worker` for the off-mesh / split-gateway topology. Phase 1 polls one gateway
// from flags; the gateway registry (`harbor gateway …`) is Phase 2.
func cmdCollect(args []string) {
	fs := flag.NewFlagSet("collect", flag.ExitOnError)
	cf := addCoreFlags(fs)
	gwURL := fs.String("gateway-url", "", "gateway collect URL (https://host:port) to pull from")
	gwCertPath := fs.String("gateway-cert", "", "gateway's pinned server cert PEM (leaf-pinned)")
	clientCertPath := fs.String("client-cert", "", "Harbor's collect client cert PEM")
	clientKeyPath := fs.String("client-key", "", "Harbor's collect client key PEM")
	interval := fs.Duration("interval", 5*time.Second, "gateway poll interval")
	batch := fs.Int("batch", 64, "candidates claimed per poll")
	once := fs.Bool("once", false, "collect a single batch and exit (cron/test)")
	obsAddr := fs.String("obs-addr", "", "internal listener for /metrics + /healthz + /readyz (e.g. 10.44.0.2:9445); served plaintext over the overlay, empty disables")
	lf := addLogFlags(fs)
	_ = fs.Parse(args)
	log := lf.setup()

	if *clientCertPath == "" || *clientKeyPath == "" {
		fatalf("collect: -client-cert and -client-key are required")
	}
	clientCert, err := tls.LoadX509KeyPair(*clientCertPath, *clientKeyPath)
	if err != nil {
		fatalf("collect: client cert: %v", err)
	}

	s := openStore(*cf.driver, *cf.dsn)
	defer s.Close()
	sink := collect.NewCaptureSink()
	cons := cf.buildConsumer(s, sink)
	coll := collect.New(collect.Config{Processor: cons, Sink: sink, ClientCert: clientCert, Batch: *batch, Logger: log})

	// Gateways to poll: a single ad-hoc gateway from flags (Phase-1 override), or —
	// the default — every ACTIVE gateway in the registry (Phase 2), re-read each
	// cycle so `harbor gateway add/remove` takes effect live.
	mode := "registry"
	var gateways func() []collect.Gateway
	if *gwURL != "" {
		mode = "single-flag"
		if *gwCertPath == "" {
			fatalf("collect: -gateway-url requires -gateway-cert")
		}
		gwPEM, err := os.ReadFile(*gwCertPath)
		if err != nil {
			fatalf("collect: read -gateway-cert: %v", err)
		}
		gwPin, err := collect.PinFromCertPEM(gwPEM)
		if err != nil {
			fatalf("collect: -gateway-cert: %v", err)
		}
		gw := collect.Gateway{Name: "gateway", URL: *gwURL, ServerCertPin: gwPin}
		gateways = func() []collect.Gateway { return []collect.Gateway{gw} }
	} else {
		reg := gatewayreg.New(s.DB, nil)
		gateways = func() []collect.Gateway {
			rows, err := reg.Active(context.Background())
			if err != nil {
				log.Warn("collect: read gateway registry", "err", err)
				return nil
			}
			out := make([]collect.Gateway, 0, len(rows))
			for _, row := range rows {
				pin, err := collect.PinFromCertPEM([]byte(row.CertPEM))
				if err != nil {
					log.Warn("collect: skipping gateway with an unparseable pinned cert", "name", row.Name, "err", err)
					continue
				}
				out = append(out, collect.Gateway{Name: row.Name, URL: row.URL, ServerCertPin: pin})
			}
			return out
		}
	}

	if *once {
		total := 0
		for _, gw := range gateways() {
			n, err := coll.CollectOnce(context.Background(), gw)
			if err != nil {
				fatalf("collect %s: %v", gw.Name, err)
			}
			total += n
		}
		fmt.Printf("collected %d candidate(s)\n", total)
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if *obsAddr != "" {
		obs.Serve(ctx, *obsAddr, log) // /metrics (Go runtime + process) for the collector (Phase 7b)
	}
	log.Info("harbor collect running", "mode", mode, "interval", interval.String())
	_ = coll.Run(ctx, gateways, *interval)
	log.Info("harbor collect stopped")
}

func enrollPending(args []string) {
	fs := flag.NewFlagSet("enroll pending", flag.ExitOnError)
	driver, dsn := dbFlags(fs)
	_ = fs.Parse(args)
	s := openStore(*driver, *dsn)
	defer s.Close()
	cons := enrollment.New(enrollment.Config{Store: s}) // Pending() needs only the store
	pend, err := cons.Pending(context.Background())
	if err != nil {
		fatalf("%v", err)
	}
	if len(pend) == 0 {
		fmt.Println("no enrollments awaiting approval")
		return
	}
	fmt.Printf("%-28s %-16s %-22s %s\n", "ENROLLMENT_ID", "DEVICE", "PUBKEY_HASH", "GROUPS")
	for _, e := range pend {
		fmt.Printf("%-28s %-16s %-22s %s\n", e.EnrollmentID, e.DeviceName, e.PubkeyHash[:20]+"…", e.Groups)
	}
}

func enrollApprove(args []string) {
	if len(args) < 1 {
		fatalf("enroll approve: want an <enrollment_id>")
	}
	// The enrollment id is positional and comes first; flags follow.
	id := args[0]
	fs := flag.NewFlagSet("enroll approve", flag.ExitOnError)
	cf := addCoreFlags(fs)
	// -approver attributes the approval in the audit trail, so it stays REQUIRED (never blank). It may
	// default from $HARBOR_APPROVER for an operator who sets it in their OWN shell, but bootstrap does
	// NOT export it into the shared /etc/profile.d (that would mis-attribute every approval to one id).
	approver := fs.String("approver", os.Getenv("HARBOR_APPROVER"), "approving admin identity (required; default: $HARBOR_APPROVER)")
	_ = fs.Parse(args[1:])
	if *approver == "" {
		fatalf("enroll approve: -approver is required")
	}
	cons, q, s := cf.build()
	defer s.Close()
	defer q.Close()
	res, err := cons.Approve(context.Background(), id, *approver)
	if err != nil {
		fatalf("%v", err)
	}
	fmt.Printf("approved %s by %s — issued, overlay IP %s\n", id, *approver, res.OverlayIP)
}
