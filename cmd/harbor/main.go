// Command harbor is the Nebula Control Plane central service (enrollment, IPAM,
// signing, policy, rotation). M2 brings up the data layer + signing spine; this
// CLI currently drives schema migrations and the hash-chained audit log.
package main

import (
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/fleet"
	"github.com/jeks313/nebula-control-plane/internal/ipam"
	"github.com/jeks313/nebula-control-plane/internal/joinkey"
	"github.com/jeks313/nebula-control-plane/internal/signer"
	"github.com/jeks313/nebula-control-plane/internal/store"
	"github.com/jeks313/nebula-control-plane/internal/store/migrate"
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
		os.Exit(1) //nolint:gocritic // CLI fatal exit: deferred store Close is best-effort (OS reclaims on exit)
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
		os.Exit(1) //nolint:gocritic // intentional exit-code signal; deferred store Close is best-effort
	}
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
