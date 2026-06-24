package main

import (
	"context"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/genesis"
	"github.com/jeks313/nebula-control-plane/internal/ipam"
	"github.com/jeks313/nebula-control-plane/internal/netblock"
	"github.com/jeks313/nebula-control-plane/internal/policy"
	"github.com/jeks313/nebula-control-plane/internal/signer"
	"github.com/jeks313/nebula-control-plane/internal/store"
	"github.com/slackhq/nebula/cert"
)

// mintParams are the resolved inputs to creating a NEW lighthouse identity.
type mintParams struct {
	Name     string        // lighthouse device name (e.g. lighthouse-2)
	IP       netip.Addr    // PINNED overlay IP (reserved; baked into static_host_map)
	Pool     netip.Prefix  // overlay pool CIDR
	Lifetime time.Duration // certificate validity
	PubPEM   []byte        // the lighthouse host's public key PEM (P256; generated off-box)
}

// mintResult is what a mint produced.
type mintResult struct {
	CertPEM     []byte
	Fingerprint string
	OverlayIP   string
}

// mintLighthouse creates a new lighthouse identity: it reserves the PINNED overlay IP, issues a
// cert in the `lighthouse` group from the host's own public key, and records an ISSUED
// enrollment row for it (so the P10 revocation guard protects it AND `lighthouse rotate-cert`
// can later re-sign it). It is the symmetric "add a lighthouse" primitive — the same mint+enroll
// the genesis ceremony does for the first lighthouse, exposed so the bootstrap can stand up
// additional lighthouses for HA (and so an operator can scale lighthouses out day-2).
//
// It does NOT register the lighthouse in the discovery registry — that's `lighthouse add`
// (which needs the public underlay address, known only once its NLB/EIP exists). This is the
// pure, testable core; cmdLighthouseMint is its flag-parsing wrapper.
func mintLighthouse(ctx context.Context, s *store.Store, audit auditFn, backend signer.Backend, caPEM []byte, p mintParams) (mintResult, error) {
	pub, _, curve, err := cert.UnmarshalPublicKeyFromPEM(p.PubPEM)
	if err != nil {
		return mintResult{}, fmt.Errorf("parse host public key: %w", err)
	}
	if curve != cert.Curve_P256 {
		return mintResult{}, fmt.Errorf("host key curve is %s, want P256", curve)
	}

	alloc, err := ipam.NewAllocator(s, ipam.Pool{Prefix: p.Pool})
	if err != nil {
		return mintResult{}, err
	}
	// Wire the netblock registry as the resolver so the pinned allocation carries netblock_id
	// provenance (best-effort, like genesis/issue-cert) — a literal keeps the func types simple.
	alloc = alloc.WithResolver(netblock.New(s.DB, p.Pool, nil, alloc,
		func(c context.Context, a, ac, t, d string) error { return audit(c, a, ac, t, d) }))
	if err := alloc.AllocateSpecific(ctx, p.Name, p.IP, "genesis"); err != nil {
		return mintResult{}, fmt.Errorf("reserve lighthouse IP %s: %w", p.IP, err)
	}

	sg, err := signer.New(signer.Config{
		CACertPEM: caPEM,
		Backend:   backend,
		Policy:    signer.IssuePolicy{AllowedNetwork: p.Pool, MaxLifetime: p.Lifetime},
		Audit:     audit,
	})
	if err != nil {
		_ = alloc.Release(ctx, p.IP)
		return mintResult{}, fmt.Errorf("signer: %w", err)
	}
	nb := time.Now().Add(-5 * time.Minute)
	c, certPEM, err := sg.Issue(ctx, "operator:lighthouse-mint", signer.Template{
		Name:      p.Name,
		Networks:  []netip.Prefix{netip.PrefixFrom(p.IP, p.Pool.Bits())},
		Groups:    []string{policy.GroupLighthouse},
		NotBefore: nb,
		NotAfter:  nb.Add(p.Lifetime),
		PublicKey: pub,
	})
	if err != nil {
		_ = alloc.Release(ctx, p.IP) // don't leak the reservation on a failed issue
		return mintResult{}, fmt.Errorf("issue: %w", err)
	}
	fp, _ := c.Fingerprint()
	// Record the issued enrollment (idempotent) so rotate-cert resolves this lighthouse by name
	// and the revocation guard refuses to blocklist it. Stores the RAW pubkey (PEM -> bytes).
	if err := genesis.RecordControlPlaneEnrollment(ctx, s.DB, fp,
		[]string{policy.GroupLighthouse}, p.IP.String(), p.Name, p.PubPEM, string(certPEM)); err != nil {
		return mintResult{}, fmt.Errorf("record enrollment: %w", err)
	}
	return mintResult{CertPEM: certPEM, Fingerprint: fp, OverlayIP: p.IP.String()}, nil
}

// cmdLighthouseMint is the flag-parsing wrapper around mintLighthouse.
func cmdLighthouseMint(args []string) {
	fs := flag.NewFlagSet("lighthouse mint", flag.ExitOnError)
	driver, dsn := dbFlags(fs)
	bf := addBackendFlags(fs)
	caCertPath := fs.String("ca-cert", "", "CA certificate path (required)")
	name := fs.String("name", "", "lighthouse device name, e.g. lighthouse-2 (required)")
	ipStr := fs.String("ip", "", "PINNED overlay IP for the lighthouse (required)")
	inPub := fs.String("in-pub", "", "lighthouse host public key PEM path (required; from `pilot init`)")
	poolStr := fs.String("pool", "100.64.0.0/16", "overlay pool CIDR")
	lifetime := fs.Duration("lifetime", 365*24*time.Hour, "certificate validity")
	out := fs.String("out", "", "output path for the issued cert PEM (default: stdout)")
	_ = fs.Parse(args)
	if *caCertPath == "" || *name == "" || *ipStr == "" || *inPub == "" {
		fatalf("lighthouse mint: -ca-cert, -name, -ip and -in-pub are required")
	}
	ip, err := netip.ParseAddr(*ipStr)
	if err != nil {
		fatalf("lighthouse mint: bad -ip: %v", err)
	}
	pool, err := netip.ParsePrefix(*poolStr)
	if err != nil {
		fatalf("lighthouse mint: bad -pool: %v", err)
	}
	caPEM, err := os.ReadFile(*caCertPath)
	if err != nil {
		fatalf("lighthouse mint: read -ca-cert: %v", err)
	}
	pubPEM, err := os.ReadFile(*inPub)
	if err != nil {
		fatalf("lighthouse mint: read -in-pub: %v", err)
	}
	backend, err := bf.load()
	if err != nil {
		fatalf("lighthouse mint: %v", err)
	}

	s := openStore(*driver, *dsn)
	defer s.Close()
	ctx := context.Background()
	audit := func(c context.Context, a, ac, t, d string) error { _, e := s.AppendAudit(c, a, ac, t, d); return e }

	res, err := mintLighthouse(ctx, s, audit, backend, caPEM, mintParams{
		Name: *name, IP: ip, Pool: pool, Lifetime: *lifetime, PubPEM: pubPEM,
	})
	if err != nil {
		fatalf("lighthouse mint: %v", err)
	}
	if *out == "" {
		fmt.Print(string(res.CertPEM))
	} else if err := os.WriteFile(*out, res.CertPEM, 0o644); err != nil {
		fatalf("lighthouse mint: write -out: %v", err)
	}
	fmt.Fprintf(os.Stderr, "lighthouse mint: %s @ %s issued (group lighthouse)\n  fingerprint: %s\n  next: harbor lighthouse add -ip %s -addrs <underlay:port>\n",
		*name, res.OverlayIP, res.Fingerprint, res.OverlayIP)
}
