package main

import (
	"context"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/genesis"
	"github.com/jeks313/nebula-control-plane/internal/ipam"
	"github.com/jeks313/nebula-control-plane/internal/signer"
	"github.com/jeks313/nebula-control-plane/internal/store"
	"github.com/jeks313/nebula-control-plane/internal/store/migrate"
	"github.com/slackhq/nebula/cert"
)

// Harbor CA/PKI ceremony commands: genesis, ca-init, issue-cert (split from main.go).

func cmdGenesis(args []string) {
	fs := flag.NewFlagSet("genesis", flag.ExitOnError)
	driver, dsn := dbFlags(fs)
	backend := fs.String("backend", "software", "CA/config-signing backend: software|pkcs11|kms")
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
	// kms key ids/arns (ECC_NIST_P256). The keys pre-exist in KMS (operator/terraform);
	// genesis self-signs the CA cert + emits the config-signing pub from them.
	kmsCAKeyID := fs.String("kms-ca-key-id", "", "KMS CA key id/arn (kms backend)")
	kmsCfgKeyID := fs.String("kms-config-key-id", "", "KMS config-signing key id/arn (kms backend)")
	kmsRegion := fs.String("kms-region", "", "AWS region for KMS (kms backend; else the default chain)")
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
	case "kms":
		if *kmsCAKeyID == "" || *kmsCfgKeyID == "" {
			fatalf("genesis: kms backend requires -kms-ca-key-id and -kms-config-key-id")
		}
		ctx := context.Background()
		if caB, err = signer.NewKMSBackend(ctx, signer.KMSConfig{KeyID: *kmsCAKeyID, Region: *kmsRegion}); err != nil {
			fatalf("genesis: CA KMS backend: %v", err)
		}
		if cfgB, err = signer.NewKMSBackend(ctx, signer.KMSConfig{KeyID: *kmsCfgKeyID, Region: *kmsRegion}); err != nil {
			fatalf("genesis: config-signing KMS backend: %v", err)
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
		caKeyPEM, err := caSoft.PrivateKeyPEM()
		if err != nil {
			fatalf("genesis: export CA key: %v", err)
		}
		cfgKeyPEM, err := cfgSoft.PrivateKeyPEM()
		if err != nil {
			fatalf("genesis: export config-signing key: %v", err)
		}
		writeKeyExcl(*caKeyPath, caKeyPEM)
		writeKeyExcl(*cfgKeyPath, cfgKeyPEM)
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
		if softKeyPEM, err = sb.PrivateKeyPEM(); err != nil {
			fatalf("ca-init: export CA key: %v", err)
		}
		backend = sb
	case "pkcs11", "kms":
		backend, err = bf.load() // key must already exist in the token / KMS
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
		Policy:          signer.IssuePolicy{AllowedNetwork: pool, MaxLifetime: *lifetime},
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
