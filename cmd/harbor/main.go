// Command harbor is the Nebula Control Plane central service (enrollment, IPAM,
// signing, policy, rotation). M2 brings up the data layer + signing spine; this
// CLI currently drives schema migrations and the hash-chained audit log.
package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"net/http"

	"github.com/jeks313/nebula-control-plane/internal/adminapi"
	"github.com/jeks313/nebula-control-plane/internal/adminauth"
	"github.com/jeks313/nebula-control-plane/internal/adminui"
	"github.com/jeks313/nebula-control-plane/internal/bundle"
	"github.com/jeks313/nebula-control-plane/internal/cloudtrust"
	"github.com/jeks313/nebula-control-plane/internal/collect"
	"github.com/jeks313/nebula-control-plane/internal/coreapi"
	"github.com/jeks313/nebula-control-plane/internal/dualcontrol"
	"github.com/jeks313/nebula-control-plane/internal/enrollment"
	"github.com/jeks313/nebula-control-plane/internal/fleet"
	"github.com/jeks313/nebula-control-plane/internal/gatewayreg"
	"github.com/jeks313/nebula-control-plane/internal/genesis"
	"github.com/jeks313/nebula-control-plane/internal/httpserve"
	"github.com/jeks313/nebula-control-plane/internal/ipam"
	"github.com/jeks313/nebula-control-plane/internal/joinkey"
	"github.com/jeks313/nebula-control-plane/internal/lighthouse"
	"github.com/jeks313/nebula-control-plane/internal/nebulaconfig"
	"github.com/jeks313/nebula-control-plane/internal/nonce"
	"github.com/jeks313/nebula-control-plane/internal/policy"
	"github.com/jeks313/nebula-control-plane/internal/queue"
	"github.com/jeks313/nebula-control-plane/internal/replay"
	"github.com/jeks313/nebula-control-plane/internal/revocation"
	"github.com/jeks313/nebula-control-plane/internal/rollout"
	"github.com/jeks313/nebula-control-plane/internal/signer"
	"github.com/jeks313/nebula-control-plane/internal/store"
	"github.com/jeks313/nebula-control-plane/internal/store/migrate"
	"github.com/jeks313/nebula-control-plane/internal/wire"
	"github.com/slackhq/nebula/cert"
)

// version is overridden at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	defaultLog() // baseline structured logger; service commands refine it via -log-format/-log-level
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "migrate":
		cmdMigrate(os.Args[2:])
	case "audit":
		cmdAudit(os.Args[2:])
	case "ipam":
		cmdIPAM(os.Args[2:])
	case "joinkey":
		cmdJoinKey(os.Args[2:])
	case "enroll":
		cmdEnrollCore(os.Args[2:])
	case "core-api":
		cmdCoreAPI(os.Args[2:])
	case "collect":
		cmdCollect(os.Args[2:])
	case "admin-api":
		cmdAdminAPI(os.Args[2:])
	case "admin-token":
		cmdAdminToken(os.Args[2:])
	case "seed-demo":
		cmdSeedDemo(os.Args[2:])
	case "fleet":
		cmdFleet(os.Args[2:])
	case "lighthouse":
		cmdLighthouse(os.Args[2:])
	case "gateway":
		cmdGateway(os.Args[2:])
	case "blocklist":
		cmdBlocklist(os.Args[2:])
	case "rollout":
		cmdRollout(os.Args[2:])
	case "policy":
		cmdPolicy(os.Args[2:])
	case "genesis":
		cmdGenesis(os.Args[2:])
	case "ca-init":
		cmdCAInit(os.Args[2:])
	case "issue-cert":
		cmdIssueCert(os.Args[2:])
	case "cloudtrust":
		cmdCloudTrust(os.Args[2:])
	case "version", "--version", "-v":
		fmt.Printf("harbor %s\n", version)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "harbor: unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `harbor — Nebula Control Plane central service

usage:
  harbor migrate up|down   [-driver sqlite|postgres] [-dsn <dsn>]
  harbor audit add         -actor A -action X [-target T] [-details D] [db flags]
  harbor audit verify      [db flags]
  harbor ipam allocate     -device NAME [-range R] [-pool CIDR] [-quarantine D] [db flags]
  harbor ipam release      -ip ADDR [-pool CIDR] [-quarantine D] [db flags]
  harbor joinkey create    -name N [-groups a,b] [-max-uses K] [-ttl D] [-auto-issue] [db flags]
  harbor joinkey list      [db flags]
  harbor joinkey revoke    -name N [db flags]
  harbor enroll worker     [core flags]      run the queue consumer (Core)
  harbor enroll pending    [db flags]        list enrollments awaiting approval
  harbor enroll approve    <id> -approver A  [core flags]  approve a pending host
  harbor core-api          -addr ADDR [core flags]  mesh-only API (renew/heartbeat)
  harbor collect           -client-cert C -client-key K [core flags]   ADR-0005 pull collector:
                           drain registered gateways over mTLS (or one via -gateway-url/-gateway-cert)
  harbor gateway add       -name N -url https://host:port -cert GW.crt -actor A [db flags]
  harbor gateway remove    -name N -actor A [db flags]
  harbor gateway list      [db flags]
  harbor admin-api         -addr ADDR [-dev-auth] [db flags]  mesh-only admin API (console)
  harbor seed-demo         [db flags]      DEV ONLY: populate a synthetic fleet for the console demo
  harbor fleet             [-expiry-within D] [-stale-after D] [-alert] [db flags]
  harbor lighthouse add    -ip OVERLAY -addrs host:port[,...] [-name N] -actor A [db flags]
  harbor lighthouse replace -ip OVERLAY -addrs host:port[,...] -actor A [db flags]
  harbor lighthouse remove -ip OVERLAY -actor A [db flags]   (keeps >=1 active)
  harbor lighthouse list   [db flags]
  harbor blocklist add     -fingerprint FP | -device OVERLAY [-reason R] -actor A
                           [-canary K] [-wave-size W] [-observe D] [-no-rollout] [db flags]
  harbor blocklist remove  -fingerprint FP | -device OVERLAY -actor A [db flags]   (lifts the block)
  harbor blocklist list    [db flags]
  harbor blocklist status  [db flags]      blocklist-lane rollout convergence (7.1b)
  harbor rollout start     -target N -prev M -hosts ip1,ip2,... [-canary K]
                           [-wave-size W] [-min-healthy H] [-observe D] [-missing-after D] -actor A
  harbor rollout step      [db flags]      force one evaluation (cron/ops)
  harbor rollout status    [db flags]
  harbor rollout abort     -actor A [db flags]
  harbor policy validate   <policy.txt>
  harbor policy compile    -groups a,b <policy.txt>   preview a host's firewall
  harbor policy propose    <policy.txt> -proposer A   open a dual-control publish (6.5)
  harbor policy approve    <change-id> -approver B    second, distinct admin → publish
  harbor policy deny       <change-id> -actor A [-reason R]
  harbor policy list       [-pending] [db flags]
  harbor policy active     [db flags]                 show the published policy
  harbor genesis           -out DIR -operator-a A -operator-b B -lighthouse-pub PEM [...]
  harbor ca-init           -ca-cert OUT [-backend software|pkcs11] [-ca-key OUT] [...]
  harbor issue-cert        -name DEVICE -in-pub HOST.pub -ca-cert CA [-groups a,b] [...]
  harbor version

core flags (enroll worker/approve): -ca-cert, -ca-key/-config-key (software) or
  -pkcs11-* labels, -hmac-key, -queue-dsn, -queue-key, -pool, -cert-lifetime,
  -lighthouse "overlayIP=host:port[,...]", -blocklist-db (source pki.blocklist
  from the revocations registry, 7.1).

backend flags (ca-init, issue-cert):
  -backend software|pkcs11   software persists the CA key to -ca-key (local dev);
                             pkcs11 uses a SoftHSM/HSM token (requires -tags pkcs11):
  -pkcs11-module PATH -pkcs11-token LABEL -pkcs11-pin PIN -pkcs11-key-label LABEL

db flags default to a local SQLite file (./harbor.db). Set -driver postgres
-dsn "postgres://user:pass@host/db?sslmode=require" for production.
`)
}

// dbFlags adds -driver/-dsn to a flagset and returns accessors. Default is local
// SQLite so dev needs zero setup; the same flags slot in Postgres for prod.
func dbFlags(fs *flag.FlagSet) (*string, *string) {
	driver := fs.String("driver", "sqlite", "sqlite|postgres")
	dsn := fs.String("dsn", "", "data source name (default: ./harbor.db for sqlite)")
	return driver, dsn
}

func resolveDSN(driver, dsn string) string {
	if dsn != "" {
		return dsn
	}
	if driver == "sqlite" {
		return store.DefaultSQLiteDSN("harbor.db")
	}
	return dsn
}

func cmdMigrate(args []string) {
	if len(args) < 1 {
		fatalf("migrate: want 'up' or 'down'")
	}
	// The direction is positional and comes first; flag parsing must run on the
	// remainder, since flag.Parse stops at the first non-flag argument.
	dir := args[0]
	fs := flag.NewFlagSet("migrate", flag.ExitOnError)
	driver, dsn := dbFlags(fs)
	_ = fs.Parse(args[1:])

	s := openStore(*driver, *dsn)
	defer s.Close()
	var err error
	switch dir {
	case "up":
		err = migrate.Up(s.DB)
	case "down":
		err = migrate.Down(s.DB)
	default:
		fatalf("migrate: unknown direction %q (want up|down)", dir)
	}
	if err != nil {
		fatalf("%v", err)
	}
	fmt.Printf("harbor migrate %s: ok (%s)\n", dir, *driver)
}

func cmdAudit(args []string) {
	if len(args) < 1 {
		fatalf("audit: want 'add' or 'verify'")
	}
	switch args[0] {
	case "add":
		auditAdd(args[1:])
	case "verify":
		auditVerify(args[1:])
	default:
		fatalf("audit: unknown subcommand %q (want add|verify)", args[0])
	}
}

func auditAdd(args []string) {
	fs := flag.NewFlagSet("audit add", flag.ExitOnError)
	driver, dsn := dbFlags(fs)
	actor := fs.String("actor", "", "who performed the action (required)")
	action := fs.String("action", "", "what action (required)")
	target := fs.String("target", "", "the action's target")
	details := fs.String("details", "", "free-form detail (e.g. JSON)")
	_ = fs.Parse(args)
	if *actor == "" || *action == "" {
		fatalf("audit add: -actor and -action are required")
	}
	s := openStore(*driver, *dsn)
	defer s.Close()
	e, err := s.AppendAudit(context.Background(), *actor, *action, *target, *details)
	if err != nil {
		fatalf("%v", err)
	}
	fmt.Printf("audit: appended seq=%d hash=%x\n", e.Seq, e.Hash)
}

func auditVerify(args []string) {
	fs := flag.NewFlagSet("audit verify", flag.ExitOnError)
	driver, dsn := dbFlags(fs)
	_ = fs.Parse(args)
	s := openStore(*driver, *dsn)
	defer s.Close()
	n, err := s.VerifyAudit(context.Background())
	if err != nil {
		fmt.Fprintf(os.Stderr, "audit: VERIFICATION FAILED after %d rows: %v\n", n, err)
		os.Exit(1)
	}
	fmt.Printf("audit: chain verified, %d rows intact\n", n)
}

func cmdIPAM(args []string) {
	if len(args) < 1 {
		fatalf("ipam: want 'allocate' or 'release'")
	}
	fs := flag.NewFlagSet("ipam", flag.ExitOnError)
	driver, dsn := dbFlags(fs)
	poolStr := fs.String("pool", "100.64.0.0/16", "overlay pool CIDR")
	quarantine := fs.Duration("quarantine", 0, "quarantine TTL on release")
	device := fs.String("device", "", "device name (allocate)")
	subRange := fs.String("range", "", "sub-range name (allocate)")
	ipStr := fs.String("ip", "", "address to release (release)")
	_ = fs.Parse(args[1:])

	prefix, err := netip.ParsePrefix(*poolStr)
	if err != nil {
		fatalf("ipam: bad -pool: %v", err)
	}
	s := openStore(*driver, *dsn)
	defer s.Close()
	alloc, err := ipam.NewAllocator(s, ipam.Pool{Prefix: prefix, QuarantineTTL: *quarantine})
	if err != nil {
		fatalf("%v", err)
	}

	switch args[0] {
	case "allocate":
		if *device == "" {
			fatalf("ipam allocate: -device is required")
		}
		ip, err := alloc.Allocate(context.Background(), *device, *subRange)
		if err != nil {
			fatalf("%v", err)
		}
		fmt.Printf("ipam: allocated %s to %s\n", ip, *device)
	case "release":
		if *ipStr == "" {
			fatalf("ipam release: -ip is required")
		}
		addr, err := netip.ParseAddr(*ipStr)
		if err != nil {
			fatalf("ipam release: bad -ip: %v", err)
		}
		if err := alloc.Release(context.Background(), addr); err != nil {
			fatalf("%v", err)
		}
		fmt.Printf("ipam: released %s (quarantine %s)\n", addr, *quarantine)
	default:
		fatalf("ipam: unknown subcommand %q (want allocate|release)", args[0])
	}
}

// backendFlags adds the CA-backend selection flags shared by ca-init/issue-cert.
type backendFlags struct {
	kind, caKey, module, token, pin, keyLabel *string
}

func addBackendFlags(fs *flag.FlagSet) *backendFlags {
	return &backendFlags{
		kind:     fs.String("backend", "software", "CA backend: software|pkcs11"),
		caKey:    fs.String("ca-key", "", "software CA private key path (software backend)"),
		module:   fs.String("pkcs11-module", "/usr/lib/softhsm/libsofthsm2.so", "PKCS#11 module"),
		token:    fs.String("pkcs11-token", "", "PKCS#11 token label"),
		pin:      fs.String("pkcs11-pin", "", "PKCS#11 user PIN"),
		keyLabel: fs.String("pkcs11-key-label", "", "PKCS#11 CA key label"),
	}
}

// load returns a backend bound to an existing CA key (issue-cert path).
func (b *backendFlags) load() (signer.Backend, error) {
	switch *b.kind {
	case "software":
		if *b.caKey == "" {
			return nil, fmt.Errorf("software backend requires -ca-key")
		}
		pem, err := os.ReadFile(*b.caKey)
		if err != nil {
			return nil, err
		}
		return signer.LoadSoftwareBackendPEM(pem)
	case "pkcs11":
		return signer.NewPKCS11Backend(signer.PKCS11Config{
			ModulePath: *b.module, TokenLabel: *b.token, Pin: *b.pin, KeyLabel: *b.keyLabel,
		})
	default:
		return nil, fmt.Errorf("unknown backend %q (want software|pkcs11)", *b.kind)
	}
}

func cmdJoinKey(args []string) {
	if len(args) < 1 {
		fatalf("joinkey: want 'create', 'list', or 'revoke'")
	}
	fs := flag.NewFlagSet("joinkey", flag.ExitOnError)
	driver, dsn := dbFlags(fs)
	name := fs.String("name", "", "join key name")
	groups := fs.String("groups", "", "comma-separated groups granted by this key")
	subRange := fs.String("sub-range", "", "restrict allocations to this pool sub-range")
	maxUses := fs.Int("max-uses", 1, "max uses (0 = unlimited/reusable)")
	ttl := fs.Duration("ttl", 0, "validity (0 = no expiry)")
	autoIssue := fs.Bool("auto-issue", false, "skip manual approval (HEAVILY DISCOURAGED)")
	ephemeral := fs.Bool("ephemeral", false, "nodes joined with this key are ephemeral")
	quota := fs.Int("quota", 0, "max enrollments/hour via this key (0 = unlimited; recommended for reusable/auto-issue keys)")
	_ = fs.Parse(args[1:])

	s := openStore(*driver, *dsn)
	defer s.Close()
	ctx := context.Background()

	switch args[0] {
	case "create":
		if *name == "" {
			fatalf("joinkey create: -name is required")
		}
		if *autoIssue {
			fmt.Fprintln(os.Stderr, "WARNING: -auto-issue makes this a bearer secret that joins the")
			fmt.Fprintln(os.Stderr, "         network with NO human approval. Anyone holding it can join.")
			fmt.Fprintln(os.Stderr, "         Pair with short -ttl, low -max-uses, and tight -groups.")
		}
		secret, jk, err := joinkey.Create(ctx, s, joinkey.Params{
			Name: *name, Groups: parseCSV(*groups), SubRange: *subRange,
			MaxUses: *maxUses, TTL: *ttl, AutoIssue: *autoIssue, Ephemeral: *ephemeral,
			QuotaPerHour: *quota,
		}, time.Now())
		if err != nil {
			fatalf("%v", err)
		}
		approval := "manual approval REQUIRED"
		if jk.AutoIssue {
			approval = "AUTO-ISSUE (no approval)"
		}
		fmt.Printf("join key %q created — %s\n", jk.Name, approval)
		fmt.Printf("  groups: %v  max-uses: %d  ephemeral: %v\n", jk.GroupList(), jk.MaxUses, jk.Ephemeral)
		fmt.Printf("\n  SECRET (shown once, store it now):\n  %s\n", secret)
	case "list":
		keys, err := joinkey.List(ctx, s)
		if err != nil {
			fatalf("%v", err)
		}
		fmt.Printf("%-20s %-10s %-8s %-10s %-7s %s\n", "NAME", "STATE", "USES", "AUTO", "EPHEM", "GROUPS")
		for _, k := range keys {
			uses := fmt.Sprintf("%d/%d", k.UsedCount, k.MaxUses)
			if k.MaxUses == 0 {
				uses = fmt.Sprintf("%d/∞", k.UsedCount)
			}
			fmt.Printf("%-20s %-10s %-8s %-10v %-7v %v\n", k.Name, k.State, uses, k.AutoIssue, k.Ephemeral, k.GroupList())
		}
	case "revoke":
		if *name == "" {
			fatalf("joinkey revoke: -name is required")
		}
		if err := joinkey.Revoke(ctx, s, *name); err != nil {
			fatalf("%v", err)
		}
		fmt.Printf("join key %q revoked\n", *name)
	default:
		fatalf("joinkey: unknown subcommand %q", args[0])
	}
}

// coreFlags wires Core's enrollment consumer (worker/approve).
type coreFlags struct {
	driver, dsn                          *string
	backend                              *string
	caCert, caKey, configKey             *string
	module, token, pin, caLbl, configLbl *string
	hmacKey, queueDSN, queueKey          *string
	pool                                 *string
	tunDev                               *string
	listenPort                           *int
	certLifetime                         *time.Duration
	maxPerHour                           *int
	lighthouse                           *string
	lighthouseDB                         *bool
	blocklistDB                          *bool
	policyFile                           *string
	policyDB                             *bool
	cloudTrustDB                         *bool
}

func addCoreFlags(fs *flag.FlagSet) *coreFlags {
	cf := &coreFlags{}
	cf.driver, cf.dsn = dbFlags(fs)
	cf.backend = fs.String("backend", "software", "CA/config backend: software|pkcs11")
	cf.caCert = fs.String("ca-cert", "", "CA certificate PEM (required)")
	cf.caKey = fs.String("ca-key", "", "software CA key (software backend)")
	cf.configKey = fs.String("config-key", "", "software config-signing key (software backend)")
	cf.module = fs.String("pkcs11-module", "/usr/lib/softhsm/libsofthsm2.so", "PKCS#11 module")
	cf.token = fs.String("pkcs11-token", "", "PKCS#11 token label")
	cf.pin = fs.String("pkcs11-pin", "", "PKCS#11 PIN")
	cf.caLbl = fs.String("pkcs11-ca-key-label", "", "PKCS#11 CA key label")
	cf.configLbl = fs.String("pkcs11-config-key-label", "", "PKCS#11 config-signing key label")
	cf.hmacKey = fs.String("hmac-key", "", "nonce HMAC key (base64url, shared with gateway) (required)")
	cf.queueDSN = fs.String("queue-dsn", "", "durable queue DSN (required)")
	cf.queueKey = fs.String("queue-key", "", "queue HMAC key (base64url, shared with gateway) (required)")
	cf.pool = fs.String("pool", "100.64.0.0/16", "overlay pool CIDR")
	cf.tunDev = fs.String("tun-dev", "nebula1", "nebula TUN device name stamped into this mesh's bundles (use a DISTINCT name per mesh on multi-mesh hosts)")
	cf.listenPort = fs.Int("listen-port", 4242, "nebula UDP listen port stamped into this mesh's bundles (use a DISTINCT port per mesh on multi-mesh hosts)")
	cf.certLifetime = fs.Duration("cert-lifetime", 30*24*time.Hour, "issued cert validity")
	cf.maxPerHour = fs.Int("max-certs-per-hour", 0, "signing circuit-breaker ceiling (0=unlimited)")
	cf.lighthouse = fs.String("lighthouse", "", "lighthouses for the bundle: overlayIP=host:port[,...]")
	cf.lighthouseDB = fs.Bool("lighthouse-db", false, "source lighthouses from the DB registry (6.8) instead of -lighthouse")
	cf.blocklistDB = fs.Bool("blocklist-db", false, "source the cert blocklist (pki.blocklist) from the DB revocations registry (7.1)")
	cf.policyFile = fs.String("policy", "", "central firewall policy file (M6); omit for Pilot's local default")
	cf.policyDB = fs.Bool("policy-db", false, "use the dual-control published policy from the DB (6.5) instead of -policy")
	cf.cloudTrustDB = fs.Bool("cloudtrust-db", false, "enable AWS SigV4 attestation using the dual-control published cloud-trust config from the DB (M5)")
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
	caB := cf.loadBackend(*cf.caKey, *cf.caLbl, "CA")
	cfgB := cf.loadBackend(*cf.configKey, *cf.configLbl, "config-signing")
	audit := func(c context.Context, a, ac, t, d string) error { _, e := s.AppendAudit(c, a, ac, t, d); return e }
	sg, err := signer.New(signer.Config{
		CACertPEM: caPEM, Backend: caB,
		Policy:          signer.Policy{AllowedNetwork: pool, MaxLifetime: *cf.certLifetime},
		MaxCertsPerHour: *cf.maxPerHour, Audit: audit,
	})
	if err != nil {
		fatalf("signer: %v", err)
	}
	alloc, err := ipam.NewAllocator(s, ipam.Pool{Prefix: pool})
	if err != nil {
		fatalf("ipam: %v", err)
	}
	ring, err := nonce.NewKeyring([][]byte{readB64Key(*cf.hmacKey)}, 0, 0)
	if err != nil {
		fatalf("nonce key: %v", err)
	}
	cfgPub, _ := cfgB.PublicKey()
	ct := cf.cloudTrust(s) // nil unless -cloudtrust-db && a config is published
	return enrollment.New(enrollment.Config{
		Store: s, Nonces: ring, Replay: replay.New(2 * time.Minute),
		Signer: sg, Allocator: alloc, Pool: pool, CertLifetime: *cf.certLifetime,
		TunDev: *cf.tunDev, ListenPort: *cf.listenPort,
		ConfigBackend: cfgB, ConfigKeyID: wire.PubkeyHash(cfgPub),
		CABundlePEM: caPEM, Lighthouses: parseLighthouses(*cf.lighthouse), LighthouseSource: cf.lighthouseSource(s), Policy: cf.policy(s),
		BlocklistSource: cf.blocklistSource(s),
		Results:         results, ResultTTL: time.Hour,
		CloudTrust: ct, AWSSigV4Enabled: ct != nil,
	})
}

func (cf *coreFlags) build() (*enrollment.Consumer, *queue.Durable, *store.Store) {
	if *cf.queueDSN == "" || *cf.queueKey == "" {
		fatalf("enroll: -queue-dsn and -queue-key are required")
	}
	s := openStore(*cf.driver, *cf.dsn)
	q, err := queue.OpenDurable(queue.DurableConfig{DSN: *cf.queueDSN, Key: readB64Key(*cf.queueKey)})
	if err != nil {
		fatalf("enroll: queue: %v", err)
	}
	cons := cf.buildConsumer(s, q)
	return cons, q, s
}

func (cf *coreFlags) loadBackend(softKey, label, what string) signer.Backend {
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
	approver := fs.String("approver", "", "approving admin identity (required)")
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

// cmdLighthouse manages the lighthouse fleet registry (6.8). Core serves the
// active rows into every bundle's static_host_map when run with -lighthouse-db.
func cmdLighthouse(args []string) {
	if len(args) < 1 {
		fatalf("lighthouse: want add|replace|remove|list")
	}
	sub := args[0]
	fs := flag.NewFlagSet("lighthouse "+sub, flag.ExitOnError)
	driver, dsn := dbFlags(fs)
	ip := fs.String("ip", "", "lighthouse overlay IP")
	addrs := fs.String("addrs", "", "comma-separated public underlay addrs host:port")
	name := fs.String("name", "", "optional friendly hostname")
	actor := fs.String("actor", "operator", "admin identity for the audit trail")
	_ = fs.Parse(args[1:])

	s := openStore(*driver, *dsn)
	defer s.Close()
	audit := func(c context.Context, a, ac, t, d string) error { _, e := s.AppendAudit(c, a, ac, t, d); return e }
	reg := lighthouse.New(s.DB, audit)
	ctx := context.Background()

	switch sub {
	case "add":
		if *ip == "" || *addrs == "" {
			fatalf("lighthouse add: -ip and -addrs are required")
		}
		if _, err := reg.Add(ctx, *ip, *name, parseCSV(*addrs), *actor); err != nil {
			fatalf("lighthouse add: %v", err)
		}
		fmt.Printf("added lighthouse %s (%s)\n", *ip, *addrs)
	case "replace":
		if *ip == "" || *addrs == "" {
			fatalf("lighthouse replace: -ip and -addrs are required")
		}
		if _, err := reg.Replace(ctx, *ip, parseCSV(*addrs), *actor); err != nil {
			fatalf("lighthouse replace: %v", err)
		}
		fmt.Printf("re-addressed lighthouse %s -> %s\n", *ip, *addrs)
	case "remove":
		if *ip == "" {
			fatalf("lighthouse remove: -ip is required")
		}
		if err := reg.Remove(ctx, *ip, *actor); err != nil {
			fatalf("lighthouse remove: %v", err)
		}
		fmt.Printf("removed lighthouse %s (no longer advertised)\n", *ip)
	case "list":
		rows, err := reg.List(ctx)
		if err != nil {
			fatalf("lighthouse list: %v", err)
		}
		if len(rows) == 0 {
			fmt.Println("no lighthouses registered")
			return
		}
		fmt.Printf("%-16s %-9s %-20s %s\n", "OVERLAY_IP", "STATE", "HOSTNAME", "PUBLIC_ADDRS")
		for _, r := range rows {
			fmt.Printf("%-16s %-9s %-20s %v\n", r.OverlayIP, r.State, r.Hostname, r.Addrs())
		}
	default:
		fatalf("lighthouse: unknown subcommand %q", sub)
	}
}

// cmdGateway manages the pull-based enrollment-gateway registry (ADR 0005). The
// collector (`harbor collect`) polls the active gateways here over leaf-pinned
// mTLS. Adding a gateway pins its self-signed server cert; removing it stops the
// collector polling it. Mirrors `harbor lighthouse`.
func cmdGateway(args []string) {
	if len(args) < 1 {
		fatalf("gateway: want add|remove|list")
	}
	sub := args[0]
	fs := flag.NewFlagSet("gateway "+sub, flag.ExitOnError)
	driver, dsn := dbFlags(fs)
	name := fs.String("name", "", "gateway name")
	url := fs.String("url", "", "gateway collect URL (https://host:port)")
	certPath := fs.String("cert", "", "gateway's server cert PEM (its leaf is pinned)")
	actor := fs.String("actor", "operator", "admin identity for the audit trail")
	_ = fs.Parse(args[1:])

	s := openStore(*driver, *dsn)
	defer s.Close()
	audit := func(c context.Context, a, ac, t, d string) error { _, e := s.AppendAudit(c, a, ac, t, d); return e }
	reg := gatewayreg.New(s.DB, audit)
	ctx := context.Background()

	switch sub {
	case "add":
		if *name == "" || *url == "" || *certPath == "" {
			fatalf("gateway add: -name, -url and -cert are required")
		}
		certPEM, err := os.ReadFile(*certPath)
		if err != nil {
			fatalf("gateway add: read -cert: %v", err)
		}
		if _, err := reg.Add(ctx, *name, *url, string(certPEM), *actor); err != nil {
			fatalf("gateway add: %v", err)
		}
		pin, _ := collect.PinFromCertPEM(certPEM)
		fmt.Printf("registered gateway %s (%s)\npinned leaf (sha256): %x\n", *name, *url, pin)
	case "remove":
		if *name == "" {
			fatalf("gateway remove: -name is required")
		}
		if err := reg.Remove(ctx, *name, *actor); err != nil {
			fatalf("gateway remove: %v", err)
		}
		fmt.Printf("removed gateway %s (no longer polled)\n", *name)
	case "list":
		rows, err := reg.List(ctx)
		if err != nil {
			fatalf("gateway list: %v", err)
		}
		if len(rows) == 0 {
			fmt.Println("no gateways registered")
			return
		}
		fmt.Printf("%-16s %-9s %-36s %s\n", "NAME", "STATE", "URL", "PIN")
		for _, r := range rows {
			var pinStr string
			if pin, err := collect.PinFromCertPEM([]byte(r.CertPEM)); err == nil {
				pinStr = fmt.Sprintf("%x", pin[:8])
			} else {
				pinStr = "(bad cert)"
			}
			fmt.Printf("%-16s %-9s %-36s %s…\n", r.Name, r.State, r.URL, pinStr)
		}
	default:
		fatalf("gateway: unknown subcommand %q", sub)
	}
}

// cmdBlocklist manages the cert blocklist (7.1, design §4.7). A blocklisted
// fingerprint is refused mesh-wide PEER-SIDE: every other host stops handshaking
// with it once they pull the next signed bundle (run core-api / enroll with
// -blocklist-db so the blocklist is sourced live). Target a cert by -fingerprint,
// or by -device (overlay IP) to resolve the host's current fingerprint from its
// enrollment. Bulk revoke + the can't-blocklist-control-plane invariant land in 7.2.
func cmdBlocklist(args []string) {
	if len(args) < 1 {
		fatalf("blocklist: want add|remove|list|status")
	}
	sub := args[0]
	fs := flag.NewFlagSet("blocklist "+sub, flag.ExitOnError)
	driver, dsn := dbFlags(fs)
	fp := fs.String("fingerprint", "", "cert fingerprint (hex sha256) to blocklist")
	device := fs.String("device", "", "overlay IP of a host; resolves to its current cert fingerprint")
	reason := fs.String("reason", "", "why (recorded in the audit trail)")
	actor := fs.String("actor", "operator", "admin identity for the audit trail")
	// Staged fast-propagation (7.1b): add/remove pace the push as a blocklist-lane
	// rollout (canary -> widen -> freeze on an unhealthy canary). core-api drives it
	// on heartbeats. -no-rollout skips it (the change still propagates at renewal).
	noRollout := fs.Bool("no-rollout", false, "skip the staged fast-push; rely on each host's next renewal to propagate")
	canary := fs.Int("canary", 1, "canary wave size for the staged blocklist rollout")
	waveSize := fs.Int("wave-size", 0, "hosts per post-canary wave (0 = all remaining in one wave)")
	observe := fs.Duration("observe", 5*time.Minute, "per-wave convergence window before judging it stuck")
	missingAfter := fs.Duration("missing-after", 3*time.Minute, "heartbeat silence => host considered down")
	_ = fs.Parse(args[1:])

	s := openStore(*driver, *dsn)
	defer s.Close()
	audit := func(c context.Context, a, ac, t, d string) error { _, e := s.AppendAudit(c, a, ac, t, d); return e }
	reg := revocation.New(s.DB, audit)
	eng := rollout.New(s.DB, audit)
	ctx := context.Background()

	// resolve turns -fingerprint / -device into a concrete fingerprint to target.
	resolve := func() string {
		switch {
		case *fp != "":
			return *fp
		case *device != "":
			var e enrollment.Enrollment
			err := s.DB.WithContext(ctx).
				Where("overlay_ip = ? AND status = ?", *device, enrollment.StatusIssued).
				Order("id DESC").First(&e).Error
			if err != nil {
				fatalf("blocklist: no issued device at overlay IP %s: %v", *device, err)
			}
			if e.Fingerprint == "" {
				fatalf("blocklist: device %s has no recorded fingerprint (issued before M7.1?) — pass -fingerprint", *device)
			}
			return e.Fingerprint
		default:
			fatalf("blocklist %s: -fingerprint or -device is required", sub)
			return ""
		}
	}

	// startRollout paces a blocklist change across the healthy fleet (7.1b). The
	// blocklist CONTENT is already the latest active set; this only stages WHO is
	// told to refetch (canary first), freezing if the canary goes unhealthy.
	startRollout := func() {
		if *noRollout {
			fmt.Println("note: -no-rollout — the change propagates at each host's next renewal (slow path)")
			return
		}
		var ips []string
		if err := s.DB.WithContext(ctx).Table("heartbeats").Order("overlay_ip ASC").Pluck("overlay_ip", &ips).Error; err != nil {
			fatalf("blocklist: read fleet: %v", err)
		}
		target := eng.BlocklistVersion(ctx) + 1
		r, err := eng.Start(ctx, rollout.StartConfig{
			Lane: rollout.LaneBlocklist, Description: "blocklist change",
			TargetVersion: target, PrevVersion: target - 1, Hosts: ips,
			CanarySize: *canary, WaveSize: *waveSize, Observe: *observe, MissingAfter: *missingAfter, Actor: *actor,
		})
		switch {
		case errors.Is(err, rollout.ErrNoHosts):
			fmt.Println("note: no fleet heartbeats yet — the change propagates at renewal; no rollout started")
		case errors.Is(err, rollout.ErrActiveExists):
			fmt.Println("note: a blocklist rollout is already in flight — this change rides the latest content and converges with it")
		case err != nil:
			fatalf("blocklist: start rollout: %v", err)
		default:
			fmt.Printf("staged blocklist rollout v%d to %d host(s) (canary %d); core-api drives convergence on heartbeats\n", r.TargetVersion, len(ips), *canary)
		}
	}

	switch sub {
	case "add":
		f := resolve()
		switch _, err := reg.Add(ctx, f, *reason, *actor); {
		case errors.Is(err, revocation.ErrAlreadyActive):
			fmt.Printf("already blocklisted %s\n", f)
		case err != nil:
			fatalf("blocklist add: %v", err)
		default:
			fmt.Printf("blocklisted %s\n", f)
			startRollout()
		}
	case "remove":
		f := resolve()
		var active int64
		s.DB.WithContext(ctx).Table("revocations").Where("fingerprint = ? AND state = ?", f, revocation.StateActive).Count(&active)
		if err := reg.Lift(ctx, f, *actor); err != nil {
			fatalf("blocklist remove: %v", err)
		}
		if active == 0 {
			fmt.Printf("not blocklisted: %s\n", f)
			return
		}
		fmt.Printf("lifted blocklist for %s\n", f)
		startRollout()
	case "list":
		rows, err := reg.List(ctx)
		if err != nil {
			fatalf("blocklist list: %v", err)
		}
		if len(rows) == 0 {
			fmt.Println("no revocations")
			return
		}
		fmt.Printf("%-64s %-7s %-5s %s\n", "FINGERPRINT", "STATE", "BULK", "REASON")
		for _, r := range rows {
			fmt.Printf("%-64s %-7s %-5t %s\n", r.Fingerprint, r.State, r.Bulk, r.Reason)
		}
	case "status":
		r, hosts, err := eng.StatusLane(ctx, rollout.LaneBlocklist)
		if errors.Is(err, rollout.ErrNone) {
			fmt.Println("no blocklist rollout")
			return
		}
		if err != nil {
			fatalf("blocklist status: %v", err)
		}
		converged := 0
		for _, h := range hosts {
			if h.Status == rollout.HostConverged {
				converged++
			}
		}
		fmt.Printf("blocklist rollout v%d: state=%s wave=%d  %d/%d hosts converged\n", r.TargetVersion, r.State, r.ActiveWave, converged, len(hosts))
		for _, h := range hosts {
			fmt.Printf("  %-16s wave=%d %s\n", h.OverlayIP, h.Wave, h.Status)
		}
	default:
		fatalf("blocklist: unknown subcommand %q", sub)
	}
}

// cmdRollout drives staged canary rollouts (6.6). core-api evaluates rollouts on
// every heartbeat; this CLI starts/inspects/forces them for ops and cron.
func cmdRollout(args []string) {
	if len(args) < 1 {
		fatalf("rollout: want start|step|status|abort")
	}
	sub := args[0]
	fs := flag.NewFlagSet("rollout "+sub, flag.ExitOnError)
	driver, dsn := dbFlags(fs)
	target := fs.Int("target", 0, "target bundle version")
	prev := fs.Int("prev", 1, "previous (stable) bundle version")
	hosts := fs.String("hosts", "", "ordered overlay IPs; the first -canary form the canary wave")
	canary := fs.Int("canary", 1, "canary wave size")
	waveSize := fs.Int("wave-size", 0, "post-canary hosts per wave (0 = all remaining)")
	minHealthy := fs.Int("min-healthy", 0, "healthy-converged required per wave (0 = all in wave)")
	observe := fs.Duration("observe", 10*time.Minute, "wait this long for a wave to converge before judging it stuck")
	missingAfter := fs.Duration("missing-after", 3*time.Minute, "heartbeat silence beyond this => host is down")
	desc := fs.String("desc", "", "rollout description")
	actor := fs.String("actor", "operator", "admin identity for the audit trail")
	_ = fs.Parse(args[1:])

	s := openStore(*driver, *dsn)
	defer s.Close()
	audit := func(c context.Context, a, ac, t, d string) error { _, e := s.AppendAudit(c, a, ac, t, d); return e }
	eng := rollout.New(s.DB, audit)
	ctx := context.Background()

	switch sub {
	case "start":
		if *target == 0 || *hosts == "" {
			fatalf("rollout start: -target and -hosts are required")
		}
		r, err := eng.Start(ctx, rollout.StartConfig{
			Description: *desc, TargetVersion: *target, PrevVersion: *prev, Hosts: parseCSV(*hosts),
			CanarySize: *canary, WaveSize: *waveSize, MinHealthy: *minHealthy,
			Observe: *observe, MissingAfter: *missingAfter, Actor: *actor,
		})
		if err != nil {
			fatalf("rollout start: %v", err)
		}
		fmt.Printf("started rollout #%d: %d -> %d, canary %d of %d host(s)\n", r.ID, *prev, *target, *canary, len(parseCSV(*hosts)))
	case "step":
		changed, err := eng.Evaluate(ctx)
		if err != nil {
			fatalf("rollout step: %v", err)
		}
		printRolloutStatus(ctx, eng)
		if !changed {
			fmt.Println("(no state change)")
		}
	case "status":
		printRolloutStatus(ctx, eng)
	case "abort":
		if err := eng.Abort(ctx, *actor); err != nil {
			fatalf("rollout abort: %v", err)
		}
		fmt.Println("rollout aborted — touched hosts will revert to prev")
	default:
		fatalf("rollout: unknown subcommand %q", sub)
	}
}

func printRolloutStatus(ctx context.Context, eng *rollout.Engine) {
	r, hosts, err := eng.Status(ctx)
	if err != nil {
		if errors.Is(err, rollout.ErrNone) {
			fmt.Println("no rollouts")
			return
		}
		fatalf("rollout status: %v", err)
	}
	fmt.Printf("rollout #%d: %s  %d -> %d  active_wave=%d\n", r.ID, r.State, r.PrevVersion, r.TargetVersion, r.ActiveWave)
	if r.Note != "" {
		fmt.Printf("  note: %s\n", r.Note)
	}
	fmt.Printf("  %-16s %-5s %s\n", "OVERLAY_IP", "WAVE", "STATUS")
	for _, h := range hosts {
		fmt.Printf("  %-16s %-5d %s\n", h.OverlayIP, h.Wave, h.Status)
	}
}

func cmdPolicy(args []string) {
	if len(args) < 1 {
		fatalf("policy: want 'validate' or 'compile'")
	}
	switch args[0] {
	case "validate":
		if len(args) < 2 {
			fatalf("policy validate: want a <policy.txt>")
		}
		p := loadPolicy(args[1])
		fmt.Printf("policy: valid — %d rule(s), invariants pass\n", len(p.Rules))
	case "compile":
		fs := flag.NewFlagSet("policy compile", flag.ExitOnError)
		groups := fs.String("groups", "", "comma-separated groups of the target host")
		_ = fs.Parse(args[1:])
		if fs.NArg() < 1 {
			fatalf("policy compile: want a <policy.txt>")
		}
		p := loadPolicy(fs.Arg(0))
		c := policy.CompileHost(p, parseCSV(*groups))
		fmt.Printf("# firewall for a host in groups %v\ninbound:\n", parseCSV(*groups))
		printRules(c.Inbound)
		fmt.Println("outbound:")
		printRules(c.Outbound)
	case "propose":
		policyPropose(args[1:])
	case "approve":
		policyApprove(args[1:])
	case "deny":
		policyDeny(args[1:])
	case "list":
		policyList(args[1:])
	case "active":
		policyActive(args[1:])
	default:
		fatalf("policy: unknown subcommand %q", args[0])
	}
}

// KindPolicyPublish is the dual-control change kind for firewall policy publish
// (6.5); shared with the admin API via internal/policy so both write the same
// dual-control records.
const KindPolicyPublish = policy.PublishKind

// newPolicyController builds the dual-control controller wired to the audit log,
// with a committer that re-validates the policy payload at commit time (defense
// in depth — invariants are also checked at propose).
func newPolicyController(s *store.Store) *dualcontrol.Controller {
	audit := func(c context.Context, a, ac, t, d string) error { _, e := s.AppendAudit(c, a, ac, t, d); return e }
	dc := dualcontrol.New(dualcontrol.Config{DB: s.DB, Audit: audit})
	dc.Register(KindPolicyPublish, func(ctx context.Context, ch dualcontrol.Change) error {
		p, err := policy.Parse(string(ch.Payload))
		if err != nil {
			return err
		}
		return policy.CheckInvariants(p)
	})
	// Cloud-trust-publish committer so the CLI approve path commits these changes too.
	dc.Register(cloudtrust.PublishKind, func(_ context.Context, ch dualcontrol.Change) error {
		_, err := cloudtrust.Parse(ch.Payload)
		return err
	})
	return dc
}

// activeCloudTrust returns the currently published cloud-trust config (latest committed
// cloudtrust.publish), if any.
func activeCloudTrust(ctx context.Context, s *store.Store) (cloudtrust.Config, bool) {
	dc := newPolicyController(s)
	ch, ok, err := dc.LatestCommitted(ctx, cloudtrust.PublishKind)
	if err != nil {
		fatalf("cloudtrust: read active: %v", err)
	}
	if !ok {
		return cloudtrust.Config{}, false
	}
	c, err := cloudtrust.Parse(ch.Payload)
	if err != nil {
		fatalf("cloudtrust: active config #%d is unparseable: %v", ch.ID, err)
	}
	return c, true
}

// activePolicy returns the currently published policy (latest committed
// policy.publish), if any.
func activePolicy(ctx context.Context, s *store.Store) (policy.Policy, bool) {
	dc := newPolicyController(s)
	ch, ok, err := dc.LatestCommitted(ctx, KindPolicyPublish)
	if err != nil {
		fatalf("policy: read active: %v", err)
	}
	if !ok {
		return policy.Policy{}, false
	}
	p, err := policy.Parse(string(ch.Payload))
	if err != nil {
		fatalf("policy: active policy #%d is unparseable: %v", ch.ID, err)
	}
	return p, true
}

func policyPropose(args []string) {
	if len(args) < 1 {
		fatalf("policy propose: want a <policy.txt>")
	}
	// The policy file is positional and comes first; flags follow (flag.Parse
	// stops at the first non-flag argument).
	file := args[0]
	fs := flag.NewFlagSet("policy propose", flag.ExitOnError)
	driver, dsn := dbFlags(fs)
	proposer := fs.String("proposer", "", "proposing admin identity (required)")
	_ = fs.Parse(args[1:])
	if *proposer == "" {
		fatalf("policy propose: -proposer is required")
	}
	// Validate + invariant-check before opening a change — never queue a policy
	// that could not be published.
	p := loadPolicy(file)
	raw, err := os.ReadFile(file)
	if err != nil {
		fatalf("policy propose: read %s: %v", file, err)
	}
	s := openStore(*driver, *dsn)
	defer s.Close()
	ch, err := newPolicyController(s).Propose(context.Background(), KindPolicyPublish,
		fmt.Sprintf("firewall policy (%d rules)", len(p.Rules)), raw, *proposer)
	if err != nil {
		fatalf("policy propose: %v", err)
	}
	fmt.Printf("proposed policy change #%d by %s — needs %d distinct approver(s); approve with:\n", ch.ID, *proposer, ch.Quorum)
	fmt.Printf("  harbor policy approve %d -approver <other-admin>\n", ch.ID)
}

func policyApprove(args []string) {
	id := positionalID(args, "policy approve", "<change-id>")
	fs := flag.NewFlagSet("policy approve", flag.ExitOnError)
	driver, dsn := dbFlags(fs)
	approver := fs.String("approver", "", "approving admin identity, distinct from the proposer (required)")
	_ = fs.Parse(args[1:])
	if *approver == "" {
		fatalf("policy approve: -approver is required")
	}
	s := openStore(*driver, *dsn)
	defer s.Close()
	ch, err := newPolicyController(s).Approve(context.Background(), id, *approver)
	if err != nil {
		fatalf("policy approve: %v", err)
	}
	switch dualcontrol.State(ch.State) {
	case dualcontrol.StateCommitted:
		fmt.Printf("policy change #%d committed by %s — now the active fleet policy\n", id, *approver)
	default:
		fmt.Printf("policy change #%d: recorded %s's approval (state=%s)\n", id, *approver, ch.State)
	}
}

func policyDeny(args []string) {
	id := positionalID(args, "policy deny", "<change-id>")
	fs := flag.NewFlagSet("policy deny", flag.ExitOnError)
	driver, dsn := dbFlags(fs)
	actor := fs.String("actor", "", "admin identity recording the denial (required)")
	reason := fs.String("reason", "", "denial reason")
	_ = fs.Parse(args[1:])
	if *actor == "" {
		fatalf("policy deny: -actor is required")
	}
	s := openStore(*driver, *dsn)
	defer s.Close()
	if _, err := newPolicyController(s).Deny(context.Background(), id, *actor, *reason); err != nil {
		fatalf("policy deny: %v", err)
	}
	fmt.Printf("policy change #%d denied by %s\n", id, *actor)
}

func policyList(args []string) {
	fs := flag.NewFlagSet("policy list", flag.ExitOnError)
	driver, dsn := dbFlags(fs)
	pending := fs.Bool("pending", false, "show only changes awaiting approval")
	_ = fs.Parse(args)
	s := openStore(*driver, *dsn)
	defer s.Close()
	state := dualcontrol.State("")
	if *pending {
		state = dualcontrol.StatePending
	}
	changes, err := newPolicyController(s).List(context.Background(), state)
	if err != nil {
		fatalf("policy list: %v", err)
	}
	if len(changes) == 0 {
		fmt.Println("no policy changes")
		return
	}
	fmt.Printf("%-4s %-10s %-18s %-10s %s\n", "ID", "STATE", "PROPOSER", "QUORUM", "TARGET")
	for _, c := range changes {
		_, sigs, _ := newPolicyController(s).Get(context.Background(), c.ID)
		approvals := 0
		for _, sg := range sigs {
			if sg.Decision == "approve" {
				approvals++
			}
		}
		fmt.Printf("%-4d %-10s %-18s %d/%-8d %s\n", c.ID, c.State, c.Proposer, approvals, c.Quorum, c.Target)
	}
}

func policyActive(args []string) {
	fs := flag.NewFlagSet("policy active", flag.ExitOnError)
	driver, dsn := dbFlags(fs)
	_ = fs.Parse(args)
	s := openStore(*driver, *dsn)
	defer s.Close()
	dc := newPolicyController(s)
	ch, ok, err := dc.LatestCommitted(context.Background(), KindPolicyPublish)
	if err != nil {
		fatalf("policy active: %v", err)
	}
	if !ok {
		fmt.Println("no policy published yet (fleet is default-deny)")
		return
	}
	fmt.Printf("# active policy: change #%d, hash %x\n%s\n", ch.ID, ch.PayloadHash[:8], string(ch.Payload))
}

// positionalID extracts a required positional int64 id that precedes flags.
func positionalID(args []string, cmd, what string) int64 {
	if len(args) < 1 {
		fatalf("%s: want %s", cmd, what)
	}
	id, err := strconv.ParseInt(args[0], 10, 64)
	if err != nil {
		fatalf("%s: bad %s %q", cmd, what, args[0])
	}
	return id
}

func loadPolicy(path string) policy.Policy {
	raw, err := os.ReadFile(path)
	if err != nil {
		fatalf("policy: read %s: %v", path, err)
	}
	p, err := policy.Parse(string(raw))
	if err != nil {
		fatalf("%v", err)
	}
	if err := policy.CheckInvariants(p); err != nil {
		fatalf("%v", err)
	}
	return p
}

func printRules(rules []nebulaconfig.Rule) {
	for _, r := range rules {
		sel := "host:" + r.Host
		if r.Group != "" {
			sel = "group:" + r.Group
		}
		fmt.Printf("  - %-4s %-6s %s\n", r.Proto, r.Port, sel)
	}
}

func cmdFleet(args []string) {
	fs := flag.NewFlagSet("fleet", flag.ExitOnError)
	driver, dsn := dbFlags(fs)
	expiryWithin := fs.Duration("expiry-within", 7*24*time.Hour, "flag certs expiring within this")
	staleAfter := fs.Duration("stale-after", 5*time.Minute, "flag devices silent longer than this")
	clockSkew := fs.Int("clock-skew-ms", 5000, "flag clock offset beyond this (ms)")
	alert := fs.Bool("alert", false, "exit non-zero if any renewal-health alert fires")
	_ = fs.Parse(args)

	s := openStore(*driver, *dsn)
	defer s.Close()
	rep, err := fleet.Generate(context.Background(), s, time.Now(), fleet.Thresholds{
		ExpiryWindow: *expiryWithin, StaleAfter: *staleAfter, ClockSkewMs: *clockSkew,
	})
	if err != nil {
		fatalf("%v", err)
	}

	fmt.Printf("fleet: %d device(s)  expired=%d  expiring<%s=%d  stale>%s=%d  clock-skewed=%d  unhealthy=%d\n",
		rep.Total, rep.Expired, *expiryWithin, rep.ExpiringSoon, *staleAfter, rep.Stale, rep.ClockSkewed, rep.Unhealthy)
	if len(rep.AtRisk) > 0 {
		fmt.Printf("\n%-16s %-16s %-24s %-12s %s\n", "OVERLAY_IP", "DEVICE", "CERT_NOT_AFTER", "LAST_SEEN", "RISK")
		for _, d := range rep.AtRisk {
			fmt.Printf("%-16s %-16s %-24s %-12s %v\n", d.OverlayIP, d.Name,
				d.CertNotAfter.UTC().Format(time.RFC3339), d.LastSeen.UTC().Format("15:04:05"), d.Reasons)
		}
	}
	if len(rep.Alerts) > 0 {
		fmt.Println("\nALERTS:")
		for _, a := range rep.Alerts {
			fmt.Printf("  ⚠ %s\n", a)
		}
	}
	if *alert && rep.HasAlerts() {
		os.Exit(1)
	}
}

func cmdCoreAPI(args []string) {
	fs := flag.NewFlagSet("core-api", flag.ExitOnError)
	cf := addCoreFlags(fs)
	addr := fs.String("addr", ":8444", "listen address (bind to Core's overlay IP in production)")
	tlsCert := fs.String("tls-cert", "", "TLS certificate PEM (serve HTTPS; recommended even mesh-only)")
	tlsKey := fs.String("tls-key", "", "TLS private key PEM (with -tls-cert)")
	hostCert := fs.String("host-cert", "", "Core's own Nebula host cert PEM; verified at boot to carry group:control-plane (recommended)")
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
	caB := cf.loadBackend(*cf.caKey, *cf.caLbl, "CA")
	cfgB := cf.loadBackend(*cf.configKey, *cf.configLbl, "config-signing")
	s := openStore(*cf.driver, *cf.dsn)
	defer s.Close()
	audit := func(c context.Context, a, ac, t, d string) error { _, e := s.AppendAudit(c, a, ac, t, d); return e }
	sg, err := signer.New(signer.Config{
		CACertPEM: caPEM, Backend: caB,
		Policy: signer.Policy{AllowedNetwork: pool, MaxLifetime: *cf.certLifetime}, Audit: audit,
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
		Pool:            pool, TunDev: *cf.tunDev, ListenPort: *cf.listenPort, CertLifetime: *cf.certLifetime,
	})
	srv := &http.Server{
		Addr: *addr, Handler: api.Handler(),
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
	log.Info("core-api listening", "addr", *addr, "scheme", httpserve.Scheme(*tlsCert, *tlsKey), "access", "mesh-only", "pool", pool.String(), "version", version)
	if err := httpserve.Serve(srv, *tlsCert, *tlsKey); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fatalf("core-api: %v", err)
	}
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
	lf := addLogFlags(fs)
	_ = fs.Parse(args)
	tlsOn := *tlsCert != "" && *tlsKey != ""
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
			fatalf("admin-api: -environment=production requires Secure cookies; supply -tls-cert/-tls-key, or set -auth-secure (only behind a TLS-terminating proxy)")
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

	api := adminapi.New(adminapi.Config{
		Store: s, Identity: idp,
		Rollout: rollout.New(s.DB, audit), Lighthouses: lighthouse.New(s.DB, audit),
		Enrollment: consumer, CanIssue: canIssue,
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
	top.Handle("/admin/v1/", apiHandler)                                        // the JSON API
	top.Handle("/", adminui.Handler(adminui.Config{Environment: *environment})) // the React console (or a "not built" stub)
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
	log.Info("admin-api listening", "addr", *addr, "scheme", httpserve.Scheme(*tlsCert, *tlsKey), "access", "mesh-only", "version", version)
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

func readB64Key(path string) []byte {
	raw, err := os.ReadFile(path)
	if err != nil {
		fatalf("read key %s: %v", path, err)
	}
	k, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		fatalf("key %s not base64url: %v", path, err)
	}
	return k
}

func cmdGenesis(args []string) {
	fs := flag.NewFlagSet("genesis", flag.ExitOnError)
	driver, dsn := dbFlags(fs)
	backend := fs.String("backend", "software", "CA/config-signing backend: software|pkcs11")
	outDir := fs.String("out", "", "output directory for keys/certs/manifest (required)")
	opA := fs.String("operator-a", "", "first ceremony operator (required)")
	opB := fs.String("operator-b", "", "second ceremony operator (required, must differ)")
	caName := fs.String("ca-name", "harbor-ca", "CA name")
	poolStr := fs.String("pool", "100.64.0.0/16", "overlay pool CIDR")
	lhName := fs.String("lighthouse-name", "lighthouse-1", "first lighthouse name")
	lhIPStr := fs.String("lighthouse-ip", "100.64.0.1", "lighthouse overlay IP")
	lhAddr := fs.String("lighthouse-addr", "", "lighthouse public underlay addr (host:port)")
	lhPub := fs.String("lighthouse-pub", "", "lighthouse host public key PEM (from `pilot init`) (required)")
	coreName := fs.String("core-name", "harbor-core", "Core (control-plane) node name")
	coreIPStr := fs.String("core-ip", "100.64.0.2", "Core overlay IP (used only with -core-pub)")
	corePub := fs.String("core-pub", "", "Core host public key PEM (from `pilot init`); issues Core's control-plane cert (recommended)")
	caLife := fs.Duration("ca-lifetime", 10*365*24*time.Hour, "CA validity")
	certLife := fs.Duration("cert-lifetime", 365*24*time.Hour, "lighthouse cert validity")
	// software key paths (default under -out)
	caKeyPath := fs.String("ca-key", "", "software CA key out (default <out>/ca.key)")
	cfgKeyPath := fs.String("config-key", "", "software config-signing key out (default <out>/config-signing.key)")
	// pkcs11 labels
	module := fs.String("pkcs11-module", "/usr/lib/softhsm/libsofthsm2.so", "PKCS#11 module")
	token := fs.String("pkcs11-token", "", "PKCS#11 token label")
	pin := fs.String("pkcs11-pin", "", "PKCS#11 PIN")
	caLabel := fs.String("pkcs11-ca-key-label", "", "PKCS#11 CA key label")
	cfgLabel := fs.String("pkcs11-config-key-label", "", "PKCS#11 config-signing key label")
	_ = fs.Parse(args)

	if *outDir == "" || *opA == "" || *opB == "" || *lhPub == "" {
		fatalf("genesis: -out, -operator-a, -operator-b and -lighthouse-pub are required")
	}
	pool, err := netip.ParsePrefix(*poolStr)
	if err != nil {
		fatalf("genesis: bad -pool: %v", err)
	}
	lhIP, err := netip.ParseAddr(*lhIPStr)
	if err != nil {
		fatalf("genesis: bad -lighthouse-ip: %v", err)
	}
	lhPubPEM, err := os.ReadFile(*lhPub)
	if err != nil {
		fatalf("genesis: read -lighthouse-pub: %v", err)
	}
	// Optional Core (control-plane) node — recommended, so the host the firewall
	// baseline routes to (group:control-plane) exists from the start.
	var corePubPEM []byte
	var coreIP netip.Addr
	if *corePub != "" {
		if corePubPEM, err = os.ReadFile(*corePub); err != nil {
			fatalf("genesis: read -core-pub: %v", err)
		}
		if coreIP, err = netip.ParseAddr(*coreIPStr); err != nil {
			fatalf("genesis: bad -core-ip: %v", err)
		}
	}
	if err := os.MkdirAll(*outDir, 0o700); err != nil {
		fatalf("genesis: mkdir out: %v", err)
	}
	if *caKeyPath == "" {
		*caKeyPath = filepath.Join(*outDir, "ca.key")
	}
	if *cfgKeyPath == "" {
		*cfgKeyPath = filepath.Join(*outDir, "config-signing.key")
	}

	// Build the two backends.
	var caB, cfgB signer.Backend
	var caSoft, cfgSoft *signer.SoftwareBackend
	switch *backend {
	case "software":
		if caSoft, err = signer.NewSoftwareBackend(); err != nil {
			fatalf("%v", err)
		}
		if cfgSoft, err = signer.NewSoftwareBackend(); err != nil {
			fatalf("%v", err)
		}
		caB, cfgB = caSoft, cfgSoft
	case "pkcs11":
		if caB, err = signer.NewPKCS11Backend(signer.PKCS11Config{ModulePath: *module, TokenLabel: *token, Pin: *pin, KeyLabel: *caLabel}); err != nil {
			fatalf("genesis: CA backend: %v", err)
		}
		if cfgB, err = signer.NewPKCS11Backend(signer.PKCS11Config{ModulePath: *module, TokenLabel: *token, Pin: *pin, KeyLabel: *cfgLabel}); err != nil {
			fatalf("genesis: config-signing backend: %v", err)
		}
	default:
		fatalf("genesis: unknown backend %q", *backend)
	}

	s := openStore(*driver, *dsn)
	defer s.Close()
	if err := migrate.Up(s.DB); err != nil { // genesis is bootstrap: ensure schema
		fatalf("genesis: migrate: %v", err)
	}

	res, err := genesis.Run(context.Background(), s, caB, cfgB, genesis.Params{
		OperatorA: *opA, OperatorB: *opB, CAName: *caName, Pool: pool,
		LighthouseName: *lhName, LighthouseIP: lhIP, LighthouseAddr: *lhAddr,
		LighthousePub: lhPubPEM,
		CoreName:      *coreName, CoreIP: coreIP, CorePub: corePubPEM,
		CALifetime: *caLife, CertLifetime: *certLife,
	})
	if err != nil {
		fatalf("%v", err)
	}

	// Persist software private keys (O_EXCL — never clobber a trust root).
	if caSoft != nil {
		writeKeyExcl(*caKeyPath, caSoft.PrivateKeyPEM())
		writeKeyExcl(*cfgKeyPath, cfgSoft.PrivateKeyPEM())
	}
	writeOut(filepath.Join(*outDir, "ca.crt"), res.CACertPEM)
	writeOut(filepath.Join(*outDir, "config-signing.pub"), res.ConfigSigningPubPEM)
	writeOut(filepath.Join(*outDir, *lhName+".crt"), res.LighthouseCertPEM)
	if res.CoreCertPEM != nil {
		writeOut(filepath.Join(*outDir, *coreName+".crt"), res.CoreCertPEM)
	}
	writeOut(filepath.Join(*outDir, "genesis.json"), res.ManifestJSON)

	fmt.Printf("genesis complete (%s backend), operators: %s + %s\n", *backend, *opA, *opB)
	fmt.Printf("  CA fingerprint:        %s\n", res.CAFingerprint)
	fmt.Printf("  config-signing key id: %s\n", res.ConfigSigningKeyID)
	fmt.Printf("  lighthouse %s @ %s, cert %s\n", *lhName, res.LighthouseIP, res.LighthouseFingerprint)
	if res.CoreCertPEM != nil {
		fmt.Printf("  core %s @ %s, cert %s (group: control-plane)\n", *coreName, res.CoreIP, res.CoreFingerprint)
		fmt.Printf("  wrote: %s/{ca.crt,config-signing.pub,%s.crt,%s.crt,genesis.json}\n", *outDir, *lhName, *coreName)
		fmt.Printf("  -> run core-api with -host-cert %s/%s.crt so it verifies its control-plane identity at boot.\n", *outDir, *coreName)
	} else {
		fmt.Printf("  wrote: %s/{ca.crt,config-signing.pub,%s.crt,genesis.json}\n", *outDir, *lhName)
		fmt.Fprintln(os.Stderr, "  WARNING: no -core-pub given, so Core's control-plane cert was NOT issued. The firewall baseline routes the fleet to group:control-plane; issue Core's cert (re-run with -core-pub, or `harbor issue-cert -groups control-plane`) before bring-up or heartbeat/renew will be unreachable.")
	}
}

func writeKeyExcl(path string, b []byte) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		fatalf("genesis: write key %s: %v", path, err)
	}
	defer f.Close()
	if _, err := f.Write(b); err != nil {
		fatalf("genesis: write key %s: %v", path, err)
	}
}

func writeOut(path string, b []byte) {
	if err := os.WriteFile(path, b, 0o644); err != nil {
		fatalf("genesis: write %s: %v", path, err)
	}
}

func cmdCAInit(args []string) {
	fs := flag.NewFlagSet("ca-init", flag.ExitOnError)
	driver, dsn := dbFlags(fs)
	bf := addBackendFlags(fs)
	name := fs.String("name", "harbor-ca", "CA name")
	netsStr := fs.String("networks", "", "comma-separated CA network CIDRs (optional)")
	caCertOut := fs.String("ca-cert", "", "output path for the CA certificate (required)")
	lifetime := fs.Duration("lifetime", 10*365*24*time.Hour, "CA validity")
	_ = fs.Parse(args)
	if *caCertOut == "" {
		fatalf("ca-init: -ca-cert is required")
	}

	nets, err := parsePrefixes(*netsStr)
	if err != nil {
		fatalf("ca-init: %v", err)
	}

	// Build the backend. For software we generate a fresh key and persist it.
	var backend signer.Backend
	var softKeyPEM []byte
	switch *bf.kind {
	case "software":
		if *bf.caKey == "" {
			fatalf("ca-init: software backend requires -ca-key")
		}
		sb, err := signer.NewSoftwareBackend()
		if err != nil {
			fatalf("%v", err)
		}
		backend, softKeyPEM = sb, sb.PrivateKeyPEM()
	case "pkcs11":
		backend, err = bf.load() // key must already exist in the token
		if err != nil {
			fatalf("ca-init: %v", err)
		}
	default:
		fatalf("ca-init: unknown backend %q", *bf.kind)
	}

	now := time.Now()
	caCert, caPEM, err := signer.SelfSignCA(backend, signer.CATemplate{
		Name: *name, Networks: nets, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(*lifetime),
	})
	if err != nil {
		fatalf("%v", err)
	}

	// Persist the software CA key (O_EXCL: never clobber an existing CA key).
	if softKeyPEM != nil {
		f, err := os.OpenFile(*bf.caKey, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
		if err != nil {
			fatalf("ca-init: write ca-key: %v", err)
		}
		_, _ = f.Write(softKeyPEM)
		f.Close()
	}
	if err := os.WriteFile(*caCertOut, caPEM, 0o644); err != nil {
		fatalf("ca-init: write ca-cert: %v", err)
	}

	// Record the CA key in the keys table + audit.
	s := openStore(*driver, *dsn)
	defer s.Close()
	pub, _ := backend.PublicKey()
	if err := s.DB.Create(&store.Key{
		Name: *name, Kind: "ca", Backend: *bf.kind, Curve: "P256",
		PublicKey: pub, State: "active", CreatedAt: now.UnixNano(),
	}).Error; err != nil {
		fatalf("ca-init: record key: %v", err)
	}
	fp, _ := caCert.Fingerprint()
	if _, err := s.AppendAudit(context.Background(), "operator", "ca-init", *name,
		fmt.Sprintf(`{"backend":%q,"fingerprint":%q}`, *bf.kind, fp)); err != nil {
		fatalf("ca-init: audit: %v", err)
	}
	fmt.Printf("ca-init: CA %q created (%s)\n  ca-cert: %s\n  fingerprint: %s\n",
		*name, *bf.kind, *caCertOut, fp)
}

func cmdIssueCert(args []string) {
	fs := flag.NewFlagSet("issue-cert", flag.ExitOnError)
	driver, dsn := dbFlags(fs)
	bf := addBackendFlags(fs)
	caCertPath := fs.String("ca-cert", "", "CA certificate path (required)")
	name := fs.String("name", "", "device name (required)")
	inPub := fs.String("in-pub", "", "host public key PEM path (required)")
	groupsStr := fs.String("groups", "", "comma-separated groups")
	poolStr := fs.String("pool", "100.64.0.0/16", "overlay pool CIDR")
	subRange := fs.String("range", "", "pool sub-range name")
	lifetime := fs.Duration("lifetime", 30*24*time.Hour, "certificate validity")
	maxPerHour := fs.Int("max-per-hour", 0, "signing circuit-breaker ceiling (0=unlimited)")
	out := fs.String("out", "", "output path for the issued cert (default: stdout)")
	_ = fs.Parse(args)
	if *name == "" || *inPub == "" || *caCertPath == "" {
		fatalf("issue-cert: -name, -in-pub and -ca-cert are required")
	}

	pubPEM, err := os.ReadFile(*inPub)
	if err != nil {
		fatalf("issue-cert: read -in-pub: %v", err)
	}
	pub, _, curve, err := cert.UnmarshalPublicKeyFromPEM(pubPEM)
	if err != nil {
		fatalf("issue-cert: parse host public key: %v", err)
	}
	if curve != cert.Curve_P256 {
		fatalf("issue-cert: host key curve is %s, want P256", curve)
	}
	caPEM, err := os.ReadFile(*caCertPath)
	if err != nil {
		fatalf("issue-cert: read -ca-cert: %v", err)
	}
	pool, err := netip.ParsePrefix(*poolStr)
	if err != nil {
		fatalf("issue-cert: bad -pool: %v", err)
	}

	backend, err := bf.load()
	if err != nil {
		fatalf("issue-cert: %v", err)
	}

	s := openStore(*driver, *dsn)
	defer s.Close()
	audit := func(ctx context.Context, actor, action, target, details string) error {
		_, err := s.AppendAudit(ctx, actor, action, target, details)
		return err
	}
	sg, err := signer.New(signer.Config{
		CACertPEM:       caPEM,
		Backend:         backend,
		Policy:          signer.Policy{AllowedNetwork: pool, MaxLifetime: *lifetime},
		MaxCertsPerHour: *maxPerHour,
		Audit:           audit,
	})
	if err != nil {
		fatalf("issue-cert: %v", err)
	}
	alloc, err := ipam.NewAllocator(s, ipam.Pool{Prefix: pool})
	if err != nil {
		fatalf("issue-cert: %v", err)
	}

	ctx := context.Background()
	ip, err := alloc.Allocate(ctx, *name, *subRange)
	if err != nil {
		fatalf("issue-cert: allocate IP: %v", err)
	}

	// Backdate NotBefore for clock-skew tolerance; keep the validity window
	// exactly -lifetime so it sits within the policy ceiling.
	notBefore := time.Now().Add(-5 * time.Minute)
	tmpl := signer.Template{
		Name:      *name,
		Networks:  []netip.Prefix{netip.PrefixFrom(ip, pool.Bits())},
		Groups:    parseCSV(*groupsStr),
		NotBefore: notBefore,
		NotAfter:  notBefore.Add(*lifetime),
		PublicKey: pub,
	}
	c, certPEM, err := sg.Issue(ctx, "operator", tmpl)
	if err != nil {
		// Roll back the IP so a failed issue doesn't leak an allocation.
		_ = alloc.Release(ctx, ip)
		fatalf("issue-cert: %v", err)
	}

	if *out == "" {
		fmt.Print(string(certPEM))
	} else if err := os.WriteFile(*out, certPEM, 0o644); err != nil {
		fatalf("issue-cert: write cert: %v", err)
	}
	fp, _ := c.Fingerprint()
	fmt.Fprintf(os.Stderr, "issue-cert: %s -> %s groups=%v\n  fingerprint: %s\n",
		*name, ip, tmpl.Groups, fp)
}

func parseCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func parsePrefixes(s string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, p := range parseCSV(s) {
		pre, err := netip.ParsePrefix(p)
		if err != nil {
			return nil, fmt.Errorf("bad CIDR %q: %w", p, err)
		}
		out = append(out, pre)
	}
	return out, nil
}

func openStore(driver, dsn string) *store.Store {
	s, err := store.Open(store.Config{Driver: driver, DSN: resolveDSN(driver, dsn)})
	if err != nil {
		fatalf("%v", err)
	}
	return s
}

func fatalf(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "harbor: "+format+"\n", a...)
	os.Exit(1)
}
