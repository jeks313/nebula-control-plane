package main

import (
	"context"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"strings"

	"github.com/jeks313/nebula-control-plane/internal/genesis"
	"github.com/jeks313/nebula-control-plane/internal/policy"
	"github.com/slackhq/nebula/cert"
	"gorm.io/gorm"
)

// cmdBackfillCPEnrollment is the break-glass repair for a LIVE mesh whose genesis
// predates the fix that records an issued `enrollments` row for the control-plane
// certs (lighthouse + Core). Without that row the always-on P10 revocation guard
// (internal/revocation.protectControlPlane) resolves the fingerprint to not-found and
// would ALLOW the control plane to be blocklisted, and coreapi.handleRenew (which needs
// an issued row) cannot renew the cert. This command backfills the missing row from the
// cert PEM itself, sharing genesis.RecordControlPlaneEnrollment so the column set never
// drifts from genesis.
//
// It is deliberately CONSTRAINED to control-plane rows only (see the abuse guard in
// backfillCPEnrollment): it can ONLY write an issued enrollment for a cert that grants a
// reserved group OR sits in the central reserved block, so it can never be used to forge
// an issued-enrollment for an arbitrary host.
func cmdBackfillCPEnrollment(args []string) {
	fs := flag.NewFlagSet("backfill-cp-enrollment", flag.ExitOnError)
	driver, dsn := dbFlags(fs)
	certPath := fs.String("cert", "", "nebula cert PEM to backfill (required; e.g. /etc/nebula/host.crt or the lighthouse cert)")
	poolStr := fs.String("pool", "", "overlay pool CIDR (required; the central reserved block is its first /27, genesis.CentralBlock)")
	nameOverride := fs.String("name", "", "override the device name (default: the cert's name)")
	groupsOverride := fs.String("groups", "", "override the groups, comma-separated (default: the cert's groups)")
	ipOverride := fs.String("overlay-ip", "", "override the overlay IP (default: derived from the cert's networks)")
	_ = fs.Parse(args)

	if *certPath == "" {
		fatalf("backfill-cp-enrollment: -cert is required")
	}
	// -pool is required and fails closed: the central-block half of the abuse guard is
	// derived deterministically from it (the pool's first /27, genesis.CentralBlock),
	// mirroring the reaper (serve.go) and blocklist bulk-revoke.
	if *poolStr == "" {
		fatalf("backfill-cp-enrollment: -pool is required (the central-block guard derives from it)")
	}
	pool, err := netip.ParsePrefix(*poolStr)
	if err != nil {
		fatalf("backfill-cp-enrollment: bad -pool %q: %v", *poolStr, err)
	}
	central := genesis.CentralBlock(pool)
	if !central.IsValid() {
		fatalf("backfill-cp-enrollment: central block could not be computed from -pool %q (fail-closed)", *poolStr)
	}

	certPEM, err := os.ReadFile(*certPath)
	if err != nil {
		fatalf("backfill-cp-enrollment: read -cert: %v", err)
	}

	s := openStore(*driver, *dsn)
	defer s.Close()
	if !s.DB.Migrator().HasTable("enrollments") {
		fatalf("backfill-cp-enrollment: database has no schema (no 'enrollments' table) — run 'harbor migrate up' against this -dsn first")
	}

	res, err := backfillCPEnrollment(context.Background(), s.DB, certPEM, central, backfillOverrides{
		name:      *nameOverride,
		groups:    parseCSV(*groupsOverride),
		overlayIP: *ipOverride,
	})
	if err != nil {
		fatalf("backfill-cp-enrollment: %v", err)
	}
	if res.AlreadyPresent {
		fmt.Printf("backfill-cp-enrollment: already present (idempotent) — issued enrollment exists for fingerprint %s\n", res.Fingerprint)
		return
	}
	fmt.Printf("backfill-cp-enrollment: inserted issued enrollment — fingerprint=%s overlay_ip=%s groups=%v\n",
		res.Fingerprint, res.OverlayIP, res.Groups)
	fmt.Println("  the revocation control-plane guard and renewal can now resolve this cert.")
}

// backfillOverrides are the optional flag overrides for the cert-derived values.
type backfillOverrides struct {
	name      string
	groups    []string
	overlayIP string
}

// backfillResult reports what the backfill did (testable, no os.Exit).
type backfillResult struct {
	Fingerprint    string
	OverlayIP      string
	Groups         []string
	AlreadyPresent bool
}

// backfillCPEnrollment is the testable core of `harbor backfill-cp-enrollment`, free of
// flag-parsing / os.Exit (mirrors publishCloudTrust / proposeBulkRevoke). It parses the
// nebula cert PEM with the SAME library the rest of the codebase uses
// (github.com/slackhq/nebula/cert), derives fingerprint / public key / groups / overlay
// IP / name (flags override when set), enforces the abuse guard, then writes the issued
// row via the shared genesis.RecordControlPlaneEnrollment (idempotent).
//
// ABUSE GUARD (fail-closed): it REFUSES — writing NOTHING — unless the resolved groups
// grant a reserved group (policy.GrantsReservedGroup) OR the resolved overlay IP is
// inside the caller-supplied central reserved block. This is what bounds the command to
// control-plane rows only: it can never forge an issued enrollment for an arbitrary,
// non-control-plane cert.
func backfillCPEnrollment(ctx context.Context, db *gorm.DB, certPEM []byte, central netip.Prefix, ov backfillOverrides) (backfillResult, error) {
	c, _, err := cert.UnmarshalCertificateFromPEM(certPEM)
	if err != nil {
		return backfillResult{}, fmt.Errorf("parse -cert: %w", err)
	}
	fp, err := c.Fingerprint()
	if err != nil {
		return backfillResult{}, fmt.Errorf("cert fingerprint: %w", err)
	}

	// Resolve each value from the cert, letting a set flag override it.
	name := c.Name()
	if ov.name != "" {
		name = ov.name
	}
	groups := c.Groups()
	if len(ov.groups) > 0 {
		groups = ov.groups
	}
	overlayIP := ov.overlayIP
	if overlayIP == "" {
		if nets := c.Networks(); len(nets) > 0 {
			overlayIP = nets[0].Addr().String()
		}
	}

	// ABUSE GUARD (fail-closed): only a control-plane cert may be backfilled.
	reserved := policy.GrantsReservedGroup(groups)
	inCentral := false
	if central.IsValid() {
		if ip, perr := netip.ParseAddr(overlayIP); perr == nil && central.Contains(ip) {
			inCentral = true
		}
	}
	if !reserved && !inCentral {
		return backfillResult{}, fmt.Errorf(
			"refusing to backfill %q (fp %s): its groups %v do not grant a reserved group (%s/%s) and its overlay IP %q is not in the central block %s — this command can only write control-plane protection rows",
			name, fp, groups, policy.GroupControlPlane, policy.GroupLighthouse, strings.TrimSpace(overlayIP), central)
	}

	// Idempotent: detect whether an issued row already exists so we can report it (the
	// shared writer is itself a no-op in that case).
	var n int64
	if err := db.WithContext(ctx).Table("enrollments").
		Where("fingerprint = ? AND status = ?", strings.ToLower(strings.TrimSpace(fp)), "issued").
		Count(&n).Error; err != nil {
		return backfillResult{}, fmt.Errorf("check existing enrollment: %w", err)
	}

	pubPEM := c.MarshalPublicKeyPEM()
	if err := genesis.RecordControlPlaneEnrollment(ctx, db, fp, groups, overlayIP, name, pubPEM, string(certPEM)); err != nil {
		return backfillResult{}, err
	}
	return backfillResult{
		Fingerprint:    strings.ToLower(strings.TrimSpace(fp)),
		OverlayIP:      overlayIP,
		Groups:         groups,
		AlreadyPresent: n > 0,
	}, nil
}
