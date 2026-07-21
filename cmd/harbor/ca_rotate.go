package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
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

// cmdCA is the `harbor ca` break-glass CLI for the CA-rotation lifecycle (M8, design §4.6):
// list the CAs and their states; stage a new CA (mint CA2 → trusted fleet-wide before it
// signs); activate it (cut signing over, demoting the prior active to draining); retire a
// drained CA; or abandon a staged CA. The console surface + the 100%-adoption gate on
// activate land in later slices; this is the operator primitive.
func cmdCA(args []string) {
	if len(args) < 1 {
		fatalf("ca: want list|stage|activate|retire|abandon")
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
		fmt.Println("  -> it is now trusted fleet-wide via the next signed bundle. Confirm 100% adoption before `ca activate`.")
	case "activate":
		if *id == 0 {
			fatalf("ca activate: -id is required (see `ca list`)")
		}
		if err := reg.Activate(ctx, *id, *actor); err != nil {
			fatalf("ca activate: %v", err)
		}
		fmt.Printf("activated CA id %d — new enrollments/renewals now sign with it; the prior active CA is draining\n", *id)
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
		fatalf("ca: unknown subcommand %q (want list|stage|activate|retire|abandon)", sub)
	}
}
