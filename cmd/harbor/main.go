// Command harbor is the Nebula Control Plane central service (enrollment, IPAM,
// signing, policy, rotation). M2 brings up the data layer + signing spine; this
// CLI currently drives schema migrations and the hash-chained audit log.
package main

import (
	"context"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/genesis"
	"github.com/jeks313/nebula-control-plane/internal/ipam"
	"github.com/jeks313/nebula-control-plane/internal/joinkey"
	"github.com/jeks313/nebula-control-plane/internal/signer"
	"github.com/jeks313/nebula-control-plane/internal/store"
	"github.com/jeks313/nebula-control-plane/internal/store/migrate"
	"github.com/slackhq/nebula/cert"
)

// version is overridden at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
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
	case "genesis":
		cmdGenesis(os.Args[2:])
	case "ca-init":
		cmdCAInit(os.Args[2:])
	case "issue-cert":
		cmdIssueCert(os.Args[2:])
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
  harbor genesis           -out DIR -operator-a A -operator-b B -lighthouse-pub PEM [...]
  harbor ca-init           -ca-cert OUT [-backend software|pkcs11] [-ca-key OUT] [...]
  harbor issue-cert        -name DEVICE -in-pub HOST.pub -ca-cert CA [-groups a,b] [...]
  harbor version

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
		LighthousePub: lhPubPEM, CALifetime: *caLife, CertLifetime: *certLife,
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
	writeOut(filepath.Join(*outDir, "genesis.json"), res.ManifestJSON)

	fmt.Printf("genesis complete (%s backend), operators: %s + %s\n", *backend, *opA, *opB)
	fmt.Printf("  CA fingerprint:        %s\n", res.CAFingerprint)
	fmt.Printf("  config-signing key id: %s\n", res.ConfigSigningKeyID)
	fmt.Printf("  lighthouse %s @ %s, cert %s\n", *lhName, res.LighthouseIP, res.LighthouseFingerprint)
	fmt.Printf("  wrote: %s/{ca.crt,config-signing.pub,%s.crt,genesis.json}\n", *outDir, *lhName)
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
