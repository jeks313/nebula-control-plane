package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/ca"
	"github.com/jeks313/nebula-control-plane/internal/store"
	"github.com/slackhq/nebula/cert"
)

// caSeedIdentity derives the CA-rotation registry name + signing-backend id for the
// CURRENT CA (the one loaded from -ca-cert), so the boot-seed records it faithfully. The
// name is the CA cert's own Name(); the kms id is however this Core signs with it (KMS ARN
// / PKCS#11 label / "software").
func caSeedIdentity(caPEM []byte, cf *coreFlags) (name, kmsID string) {
	name = "ca-genesis"
	if c, _, err := cert.UnmarshalCertificateFromPEM(caPEM); err == nil && c.Name() != "" {
		name = c.Name()
	}
	switch {
	case *cf.caKmsKeyID != "":
		kmsID = *cf.caKmsKeyID
	case *cf.caLbl != "":
		kmsID = "pkcs11:" + *cf.caLbl
	default:
		kmsID = "software"
	}
	return name, kmsID
}

// caTrustSource boot-seeds the current CA into the M8 rotation registry (idempotent,
// race-tolerant) and returns the live trust-bundle source Core renders into every host
// bundle's ca_bundle. Once a second CA is staged (`harbor ca stage`), the fleet trusts
// [CA1, CA2] via the next signed bundle — the "trust before you sign" step of online CA
// rotation (design §4.6). Fail-open: a registry read error at bundle-build time falls back
// to the static -ca-cert (see enrollment/coreapi caBundle()).
func (cf *coreFlags) caTrustSource(s *store.Store, caPEM []byte, audit ca.AuditFunc) func(context.Context) ([]string, error) {
	reg := ca.New(s.DB, audit)
	name, kmsID := caSeedIdentity(caPEM, cf)
	if _, seeded, err := reg.SeedActive(context.Background(), name, string(caPEM), kmsID, "boot-seed"); err != nil {
		slog.Warn("ca: boot-seed of the current CA into the rotation registry failed; ca_bundle falls back to -ca-cert", "err", err)
	} else if seeded {
		slog.Info("ca: seeded the current CA into the rotation registry (M8)", "name", name, "kms_key_id", kmsID)
	}
	return reg.TrustBundle
}

// adoptionGate is the pure M8.1 cut-over decision: proceed iff the target CA is fully
// adopted by live hosts OR -force overrides. Returns a human refusal message when it blocks.
// Extracted so it is unit-testable without spawning a process (cmdCA calls os.Exit).
func adoptionGate(ad ca.Adoption, force bool) (proceed bool, refusal string) {
	if ad.FullyAdopted() || force {
		return true, ""
	}
	return false, fmt.Sprintf("only %d of %d live host(s) confirm trust of the target CA; %d laggard(s): %s",
		ad.Adopted, ad.Live, len(ad.Laggards), strings.Join(ad.Laggards, ", "))
}

// cmdCA is the `harbor ca` break-glass CLI for the CA-rotation lifecycle (M8, design §4.6):
// list the CAs and their states; stage a new CA (mint CA2 → trusted fleet-wide before it
// signs); check adoption; activate it (cut signing over, demoting the prior active to
// draining); retire a drained CA; or abandon a staged CA. The 100%-adoption gate on activate
// is enforced (M8.1: `ca adoption` + the gate); the console surface lands in a later slice.
func cmdCA(args []string) {
	if len(args) < 1 {
		fatalf("ca: want list|stage|adoption|activate|retire|abandon")
	}
	sub := args[0]
	fs := flag.NewFlagSet("ca "+sub, flag.ExitOnError)
	driver, dsn := dbFlags(fs)
	certPath := fs.String("cert", "", "stage: CA certificate PEM file (the new CA to trust)")
	name := fs.String("name", "", "stage: human label for the CA (e.g. ca-2027)")
	kmsKeyID := fs.String("kms-key-id", "", "stage: how to reach its signing backend (KMS ARN / 'pkcs11:<label>' / 'software'); empty = trust-only")
	id := fs.Int64("id", 0, "activate/retire/abandon: the CA row id (see `ca list`)")
	dependents := fs.Int("dependents", -1, "retire: count of live leaf certs still chaining to this CA (must be 0 to retire; drain tracking is M8.3, so confirm this yourself)")
	actor := fs.String("actor", "operator", "admin identity for the audit trail")
	force := fs.Bool("force", false, "activate: cut over even if <100% of LIVE hosts confirm trust of the target CA (break-glass — may strand laggards)")
	staleAfter := fs.Duration("stale-after", 5*time.Minute, "activate/adoption: heartbeat freshness window defining a LIVE host (keep aligned with serve/admin-api -stale-after)")
	_ = fs.Parse(args[1:])

	s := openStore(*driver, *dsn)
	defer s.Close()
	audit := func(c context.Context, a, ac, t, d string) error { _, e := s.AppendAudit(c, a, ac, t, d); return e }
	reg := ca.New(s.DB, audit)
	ctx := context.Background()

	switch sub {
	case "list":
		rows, err := reg.List(ctx)
		if err != nil {
			fatalf("ca list: %v", err)
		}
		if len(rows) == 0 {
			fmt.Println("no CAs yet (the current CA is seeded on core-api / enroll-worker startup)")
			return
		}
		fmt.Printf("%-4s %-18s %-9s %-12s %s\n", "ID", "NAME", "STATE", "NOT_AFTER", "FINGERPRINT")
		for _, c := range rows {
			fmt.Printf("%-4d %-18s %-9s %-12s %s\n", c.ID, c.Name, c.State,
				time.Unix(0, c.NotAfter).UTC().Format("2006-01-02"), c.Fingerprint)
		}
	case "stage":
		if *certPath == "" || *name == "" {
			fatalf("ca stage: -cert and -name are required")
		}
		pem, err := os.ReadFile(*certPath)
		if err != nil {
			fatalf("ca stage: read -cert: %v", err)
		}
		row, err := reg.Stage(ctx, *name, string(pem), *kmsKeyID, *actor)
		if err != nil {
			fatalf("ca stage: %v", err)
		}
		fmt.Printf("staged CA %q (id %d, fp %s)\n", row.Name, row.ID, row.Fingerprint)
		fmt.Printf("  -> now trusted fleet-wide via the next signed bundle. Watch `harbor ca adoption -id %d`; `ca activate` refuses until 100%% unless -force.\n", row.ID)
	case "activate":
		if *id == 0 {
			fatalf("ca activate: -id is required (see `ca list`)")
		}
		target, err := reg.Get(ctx, *id)
		if err != nil {
			fatalf("ca activate: %v", err)
		}
		ad, err := reg.AdoptionStatus(ctx, target.Fingerprint, *staleAfter)
		if err != nil {
			fatalf("ca activate: adoption check: %v", err)
		}
		if proceed, refusal := adoptionGate(ad, *force); !proceed {
			fatalf("ca activate: REFUSING to cut over — %s.\n"+
				"Cutting over now would STRAND those host(s) when signing moves to CA %q (%s…). "+
				"Wait for 100%% (watch `harbor ca adoption -id %d`), or override with -force.",
				refusal, target.Name, target.Fingerprint[:12], *id)
		}
		if !ad.FullyAdopted() {
			fmt.Printf("WARNING: -force overriding the adoption gate — %d live host(s) do not yet trust CA %q and may be stranded\n",
				len(ad.Laggards), target.Name)
		} else if ad.Live == 0 {
			if len(ad.Stale) > 0 {
				// Distinguish a genuinely-empty fleet from a temporarily fully-stale one (a
				// management blip): the latter is safe (the prior CA is still trusted while
				// draining, so a returning host re-adopts from the bundle before it renews),
				// but the operator should SEE it rather than read a bare "0 live hosts".
				fmt.Printf("note: 0 LIVE hosts, but %d stale (beyond the freshness window). Cut-over is safe (the prior CA stays trusted while draining, so they re-adopt on return before renewing), but consider waiting if this is a transient outage. Proceeding.\n", len(ad.Stale))
			} else {
				fmt.Println("note: 0 live hosts heartbeating — nothing to confirm; proceeding")
			}
		}
		if err := reg.Activate(ctx, *id, *actor); err != nil {
			fatalf("ca activate: %v", err)
		}
		fmt.Printf("activated CA id %d — new enrollments/renewals now sign with it; the prior active CA is draining\n", *id)
	case "adoption":
		if *id == 0 {
			fatalf("ca adoption: -id is required (see `ca list`)")
		}
		target, err := reg.Get(ctx, *id)
		if err != nil {
			fatalf("ca adoption: %v", err)
		}
		ad, err := reg.AdoptionStatus(ctx, target.Fingerprint, *staleAfter)
		if err != nil {
			fatalf("ca adoption: %v", err)
		}
		pct := 100.0
		if ad.Live > 0 {
			pct = float64(ad.Adopted) / float64(ad.Live) * 100
		}
		gate := "NOT yet fully adopted"
		if ad.FullyAdopted() {
			gate = "fully adopted — safe to `ca activate`"
		}
		fmt.Printf("CA %q (id %d, state %s, fp %s)\n", target.Name, target.ID, target.State, target.Fingerprint)
		fmt.Printf("adoption: %d/%d live host(s) confirm trust (%.0f%%) — %s\n", ad.Adopted, ad.Live, pct, gate)
		if len(ad.Laggards) > 0 {
			fmt.Printf("  laggards (live, not yet confirming): %s\n", strings.Join(ad.Laggards, ", "))
		}
		if len(ad.Stale) > 0 {
			fmt.Printf("  stale (beyond the freshness window; excluded from the gate): %s\n", strings.Join(ad.Stale, ", "))
		}
	case "retire":
		if *id == 0 {
			fatalf("ca retire: -id is required")
		}
		if *dependents < 0 {
			fatalf("ca retire: pass -dependents N (0 to retire). Drain tracking (which CA signed each leaf) is M8.3, so you must confirm no live leaf still chains to this CA.")
		}
		if err := reg.Retire(ctx, *id, *dependents, *actor); err != nil {
			fatalf("ca retire: %v", err)
		}
		fmt.Printf("retired CA id %d — out of the trust bundle; schedule its KMS key deletion (with alarms)\n", *id)
	case "abandon":
		if *id == 0 {
			fatalf("ca abandon: -id is required")
		}
		if err := reg.Abandon(ctx, *id, *actor); err != nil {
			fatalf("ca abandon: %v", err)
		}
		fmt.Printf("abandoned staged CA id %d\n", *id)
	default:
		fatalf("ca: unknown subcommand %q (want list|stage|adoption|activate|retire|abandon)", sub)
	}
}
