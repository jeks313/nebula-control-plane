package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/enrollment"
	"github.com/jeks313/nebula-control-plane/internal/signer"
	"github.com/slackhq/nebula/cert"
	"gorm.io/gorm"
)

// rotateParams are the resolved inputs to a lighthouse cert re-sign (the command fills
// these from flags; tests construct them directly).
type rotateParams struct {
	Name     string        // lighthouse device name (its issued enrollment is the re-sign source)
	Pool     netip.Prefix  // overlay pool CIDR — sets the cert's network prefix bits
	Lifetime time.Duration // new certificate validity
	Within   time.Duration // only re-sign if the current cert expires within this window (0 = always)
	Now      time.Time     // clock injection point; zero => time.Now()
}

// rotateResult reports what a re-sign did. Rotated==false means "not due" (a no-op):
// the current cert is still comfortably valid, so nothing was signed or written.
type rotateResult struct {
	Rotated     bool
	CertPEM     []byte
	Fingerprint string
	NotAfter    time.Time
	OverlayIP   string
	DeviceName  string
}

// auditFn matches signer.Config.Audit and store.AppendAudit's shape.
type auditFn func(ctx context.Context, actor, action, target, details string) error

// rotateLighthouseCert re-signs the lighthouse's certificate IN PLACE: same overlay IP, same
// groups, same existing public key (cert-only rotation), with a fresh expiry — WITHOUT allocating
// a new IP. Identity is read STRICTLY from the lighthouse's own latest ISSUED enrollment row
// (never asserted by the caller), and it fails closed if that row isn't in the "lighthouse" group.
//
// It is the re-mint primitive for the Fargate lighthouse's scheduled rotation: the returned cert
// is re-injected into the lighthouse's Secrets Manager secret and the ECS service redeployed
// (by rotate-lighthouse-cert.sh). With p.Within > 0 it is idempotent for a timer — it no-ops
// (Rotated=false) unless the current cert expires within the window — so a monthly timer only
// actually rotates (and triggers an ECS redeploy) as the cert approaches expiry.
//
// This is the pure, testable core; cmdLighthouseRotateCert is its flag-parsing wrapper.
func rotateLighthouseCert(ctx context.Context, db *gorm.DB, audit auditFn, backend signer.Backend, caPEM []byte, p rotateParams) (rotateResult, error) {
	now := p.Now
	if now.IsZero() {
		now = time.Now()
	}

	// Re-sign source: the lighthouse's latest ISSUED enrollment. Its IP/groups/pubkey are
	// authoritative — we never take identity from the caller.
	var e enrollment.Enrollment
	if err := db.WithContext(ctx).
		Where("device_name = ? AND status = ?", p.Name, enrollment.StatusIssued).
		Order("id DESC").First(&e).Error; err != nil {
		return rotateResult{}, fmt.Errorf("no issued enrollment for %q: %w", p.Name, err)
	}
	var groups []string
	_ = json.Unmarshal([]byte(e.Groups), &groups)
	isLH := false
	for _, g := range groups {
		if g == "lighthouse" { // matches genesis' lighthouse group
			isLH = true
		}
	}
	if !isLH {
		return rotateResult{}, fmt.Errorf("%q is not in the lighthouse group (groups=%v) — refusing", p.Name, groups)
	}
	ip, err := netip.ParseAddr(e.OverlayIP)
	if err != nil {
		return rotateResult{}, fmt.Errorf("enrollment has bad overlay IP %q: %w", e.OverlayIP, err)
	}

	// rotate-if-within guard: no-op when the current cert is comfortably valid, so the timer
	// only rotates — and only forces an ECS redeploy — when the cert is approaching expiry.
	if cur, _, perr := cert.UnmarshalCertificateFromPEM(e.CertPEM); perr == nil && p.Within > 0 {
		if cur.NotAfter().After(now.Add(p.Within)) {
			return rotateResult{Rotated: false, OverlayIP: e.OverlayIP, DeviceName: e.DeviceName, NotAfter: cur.NotAfter()}, nil
		}
	}

	sg, err := signer.New(signer.Config{
		CACertPEM: caPEM,
		Backend:   backend,
		Policy:    signer.IssuePolicy{AllowedNetwork: p.Pool, MaxLifetime: p.Lifetime},
		Audit:     audit,
	})
	if err != nil {
		return rotateResult{}, fmt.Errorf("signer: %w", err)
	}
	nb := now.Add(-5 * time.Minute)
	c, certPEM, err := sg.Issue(ctx, "operator:lighthouse-rotate", signer.Template{
		Name:      e.DeviceName,
		Networks:  []netip.Prefix{netip.PrefixFrom(ip, p.Pool.Bits())},
		Groups:    groups,
		NotBefore: nb,
		NotAfter:  nb.Add(p.Lifetime),
		PublicKey: e.Pubkey, // cert-only rotation: re-sign the SAME key (no key churn, no realloc)
	})
	if err != nil {
		return rotateResult{}, fmt.Errorf("re-sign: %w", err)
	}
	fp, _ := c.Fingerprint()

	// Keep the DB truthful: the enrollment's current cert + fingerprint, plus an audit-chain entry.
	if err := db.WithContext(ctx).Model(&enrollment.Enrollment{}).Where("id = ?", e.ID).
		Updates(map[string]any{"cert_pem": certPEM, "fingerprint": fp}).Error; err != nil {
		return rotateResult{}, fmt.Errorf("update enrollment: %w", err)
	}
	if audit != nil {
		_ = audit(ctx, "operator", "lighthouse-cert-rotate", e.OverlayIP,
			fmt.Sprintf(`{"name":%q,"fingerprint":%q,"not_after":%q}`, e.DeviceName, fp, c.NotAfter().UTC().Format(time.RFC3339)))
	}

	return rotateResult{
		Rotated:     true,
		CertPEM:     certPEM,
		Fingerprint: fp,
		NotAfter:    c.NotAfter(),
		OverlayIP:   e.OverlayIP,
		DeviceName:  e.DeviceName,
	}, nil
}

// cmdLighthouseRotateCert is the flag-parsing wrapper around rotateLighthouseCert. On a no-op
// (cert not yet due) it prints a one-line note to stderr and emits nothing on stdout, so the
// rotate script can treat empty stdout as "nothing to do".
func cmdLighthouseRotateCert(args []string) {
	fs := flag.NewFlagSet("lighthouse rotate-cert", flag.ExitOnError)
	driver, dsn := dbFlags(fs)
	bf := addBackendFlags(fs)
	caCertPath := fs.String("ca-cert", "", "CA certificate path (required)")
	name := fs.String("name", "lighthouse-1", "lighthouse device name (its issued enrollment is the re-sign source)")
	poolStr := fs.String("pool", "100.64.0.0/16", "overlay pool CIDR (sets the cert's network prefix)")
	lifetime := fs.Duration("lifetime", 365*24*time.Hour, "new certificate validity")
	within := fs.Duration("rotate-if-within", 0, "only re-sign if the CURRENT cert expires within this window (0 = always); otherwise no-op with empty stdout")
	out := fs.String("out", "", "output path for the new cert PEM (default: stdout)")
	_ = fs.Parse(args)
	if *caCertPath == "" {
		fatalf("lighthouse rotate-cert: -ca-cert is required")
	}
	pool, err := netip.ParsePrefix(*poolStr)
	if err != nil {
		fatalf("lighthouse rotate-cert: bad -pool: %v", err)
	}
	caPEM, err := os.ReadFile(*caCertPath)
	if err != nil {
		fatalf("lighthouse rotate-cert: read -ca-cert: %v", err)
	}
	backend, err := bf.load()
	if err != nil {
		fatalf("lighthouse rotate-cert: %v", err)
	}

	s := openStore(*driver, *dsn)
	defer s.Close()
	ctx := context.Background()
	audit := func(c context.Context, a, ac, t, d string) error { _, e := s.AppendAudit(c, a, ac, t, d); return e }

	res, err := rotateLighthouseCert(ctx, s.DB, audit, backend, caPEM, rotateParams{
		Name: *name, Pool: pool, Lifetime: *lifetime, Within: *within,
	})
	if err != nil {
		fatalf("lighthouse rotate-cert: %v", err)
	}
	if !res.Rotated {
		fmt.Fprintf(os.Stderr, "lighthouse rotate-cert: %s valid until %s (more than %s away) — not due, skipping\n",
			*name, res.NotAfter.UTC().Format(time.RFC3339), *within)
		return
	}

	if *out == "" {
		fmt.Print(string(res.CertPEM)) // stdout = the new cert PEM (the rotate script captures it)
	} else if err := os.WriteFile(*out, res.CertPEM, 0o644); err != nil {
		fatalf("lighthouse rotate-cert: write -out: %v", err)
	}
	fmt.Fprintf(os.Stderr, "lighthouse rotate-cert: %s @ %s re-signed, valid until %s\n  fingerprint: %s\n",
		res.DeviceName, res.OverlayIP, res.NotAfter.UTC().Format(time.RFC3339), res.Fingerprint)
}
