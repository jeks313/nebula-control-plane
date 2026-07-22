package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/ca"
	"github.com/jeks313/nebula-control-plane/internal/coreapi"
	"github.com/jeks313/nebula-control-plane/internal/signer"
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
	seededCA, seeded, err := reg.SeedActive(context.Background(), name, string(caPEM), kmsID, "boot-seed")
	switch {
	case err != nil:
		slog.Warn("ca: boot-seed of the current CA into the rotation registry failed; ca_bundle falls back to -ca-cert", "err", err)
	case seeded:
		slog.Info("ca: seeded the current CA into the rotation registry (M8)", "name", name, "kms_key_id", kmsID)
		// M8.3 backfill (hygiene): pre-8.3 issued enrollments have an empty ca_fingerprint but
		// were all signed by this genesis CA — stamp them so drain counts / `ca list` are
		// populated. NOT a correctness dependency (ca.LiveDependents also falls back to each
		// leaf's own Issuer()). Idempotent: the WHERE self-limits to 0 rows on later boots.
		if res := s.DB.Exec("UPDATE enrollments SET ca_fingerprint = ? WHERE ca_fingerprint = '' AND status = 'issued'", seededCA.Fingerprint); res.Error != nil {
			slog.Warn("ca: ca_fingerprint backfill failed (non-fatal; LiveDependents falls back to the leaf Issuer)", "err", res.Error)
		} else if res.RowsAffected > 0 {
			slog.Info("ca: backfilled ca_fingerprint on pre-8.3 issued enrollments", "rows", res.RowsAffected)
		}
	}
	return reg.TrustBundle
}

// activeCASource adapts the CA-rotation registry's active CA into the signer's ActiveCARef so the
// M8.3b hot-swap reconciler can watch for a newly-activated CA without the signer package importing
// ca. "No active CA" maps to an empty ref (the reconciler keeps the current signing CA rather than
// swapping to nothing).
func (cf *coreFlags) activeCASource(s *store.Store, audit ca.AuditFunc) func(context.Context) (signer.ActiveCARef, error) {
	reg := ca.New(s.DB, audit)
	return func(ctx context.Context) (signer.ActiveCARef, error) {
		c, err := reg.Active(ctx)
		if err != nil {
			if errors.Is(err, ca.ErrNoActive) {
				return signer.ActiveCARef{}, nil
			}
			return signer.ActiveCARef{}, err
		}
		return signer.ActiveCARef{Fingerprint: c.Fingerprint, CertPEM: []byte(c.CertPEM), KMSKeyID: c.KMSKeyID}, nil
	}
}

// caDrainSource returns the M8.3c accelerated-drain source core-api consults on each heartbeat to
// force-renew a draining CA's remaining leaf holders. ca.Registry implements coreapi.CADrainSource.
func (cf *coreFlags) caDrainSource(s *store.Store, audit ca.AuditFunc) coreapi.CADrainSource {
	return ca.New(s.DB, audit)
}

// activeCABackendFactory builds the signing backend for a rotated-in active CA (M8.3b), reading
// its stored signing-backend id EXACTLY as caSeedIdentity records it: a "pkcs11:<label>" URI, the
// literal "software", or otherwise a KMS key id/ARN. Non-fatal (the reconciler logs + retries).
// The factory is only ever called for a CA that DIFFERS from the one this process booted with (the
// reconciler short-circuits an unchanged active CA), so a software CA can only mean a NEW software
// key this process does not hold -> refuse with a clear message (restart with the new -ca-key). The
// poc uses KMS, where the stored ARN suffices and NO CA private key is ever handled here (P2 — the
// key stays in KMS; this only names it).
func (cf *coreFlags) activeCABackendFactory() signer.BackendFactory {
	return func(ctx context.Context, kmsKeyID string, _ []byte) (signer.Backend, error) {
		switch {
		case strings.HasPrefix(kmsKeyID, "pkcs11:"):
			return signer.NewPKCS11Backend(signer.PKCS11Config{
				ModulePath: *cf.module, TokenLabel: *cf.token, Pin: *cf.pin,
				KeyLabel: strings.TrimPrefix(kmsKeyID, "pkcs11:"),
			})
		case kmsKeyID == "software" || kmsKeyID == "":
			return nil, fmt.Errorf("software-backed process cannot reach a new software CA key %q at runtime; restart with the new -ca-key to cut over (KMS/PKCS#11 cut over live)", kmsKeyID)
		default:
			return signer.NewKMSBackend(ctx, signer.KMSConfig{KeyID: kmsKeyID, Region: *cf.kmsRegion})
		}
	}
}

// startCACutoverReconciler launches the M8.3b hot-swap reconciler for a signing process (core-api
// or the enroll worker): it polls the active CA and cuts sg over when a new CA is activated. It is
// fail-safe (a bad tick keeps the prior CA) and bounded by -ca-cutover-interval (0 disables). The
// goroutine is registered on wg so it drains on shutdown before the DB pool closes.
func (cf *coreFlags) startCACutoverReconciler(ctx context.Context, wg *sync.WaitGroup, sg *signer.Signer, s *store.Store, audit ca.AuditFunc, log *slog.Logger) {
	interval := *cf.caCutoverInterval
	if interval <= 0 {
		log.Info("ca: online CA-rotation cut-over reconciler disabled (-ca-cutover-interval=0); activate a CA then restart to cut signing over")
		return
	}
	src := cf.activeCASource(s, audit)
	factory := cf.activeCABackendFactory()
	wg.Add(1)
	go func() {
		defer wg.Done()
		sg.RunActiveCAReconciler(ctx, src, factory, interval, log)
	}()
	log.Info("ca: online CA-rotation cut-over reconciler started (M8.3b)", "interval", interval.String())
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
		fatalf("ca: want list|stage|adoption|activate|retire|abandon|force-renew|schedule-key-deletion|cancel-key-deletion")
	}
	sub := args[0]
	fs := flag.NewFlagSet("ca "+sub, flag.ExitOnError)
	driver, dsn := dbFlags(fs)
	certPath := fs.String("cert", "", "stage: CA certificate PEM file (the new CA to trust)")
	name := fs.String("name", "", "stage: human label for the CA (e.g. ca-2027)")
	kmsKeyID := fs.String("kms-key-id", "", "stage: how to reach its signing backend (KMS ARN / 'pkcs11:<label>' / 'software'); empty = trust-only")
	id := fs.Int64("id", 0, "adoption/activate/retire/abandon/force-renew/*-key-deletion: the CA row id (see `ca list`)")
	actor := fs.String("actor", "operator", "admin identity for the audit trail")
	force := fs.Bool("force", false, "activate: cut over even if <100% of LIVE hosts confirm trust of the target CA (break-glass — may strand laggards)")
	staleAfter := fs.Duration("stale-after", 5*time.Minute, "activate/adoption: heartbeat freshness window defining a LIVE host (keep aligned with serve/admin-api -stale-after)")
	window := fs.Duration("window", 30*time.Minute, "force-renew: spread the forced renewals of a draining CA's stragglers evenly over this window (waves)")
	stop := fs.Bool("stop", false, "force-renew: cancel an in-progress accelerated drain (revert to natural renewal)")
	pendingDays := fs.Int("pending-window-days", 30, "schedule-key-deletion: KMS pending window before the key is destroyed (7-30 days; cancellable until then)")
	backend := fs.String("backend", envOr("HARBOR_BACKEND", "software"), "schedule/cancel-key-deletion: key custody backend (kms drives real KMS deletion; else software no-op) (default: $HARBOR_BACKEND, else software)")
	kmsRegion := fs.String("kms-region", os.Getenv("HARBOR_KMS_REGION"), "schedule/cancel-key-deletion: AWS region for the KMS key deleter (kms backend) (default: $HARBOR_KMS_REGION)")
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
		fmt.Printf("%-4s %-18s %-9s %-12s %-9s %-12s %s\n", "ID", "NAME", "STATE", "NOT_AFTER", "LIVE-DEPS", "KEY-DEL", "FINGERPRINT")
		for _, c := range rows {
			deps := "?" // "?" if the count read fails, so the table still prints
			if n, derr := reg.LiveDependents(ctx, c.Fingerprint); derr == nil {
				deps = strconv.Itoa(n)
			}
			keyDel := "-" // M8.4: the date the CA's signing key is destroyed, once scheduled
			if c.KeyDeletionScheduledAt != 0 {
				keyDel = time.Unix(0, c.KeyDeletionDate).UTC().Format("2006-01-02")
			}
			fmt.Printf("%-4d %-18s %-9s %-12s %-9s %-12s %s\n", c.ID, c.Name, c.State,
				time.Unix(0, c.NotAfter).UTC().Format("2006-01-02"), deps, keyDel, c.Fingerprint)
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
		// The live-dependent count is computed automatically now (M8.3 drain tracking) and
		// Retire refuses fail-closed while any live leaf still chains to this CA.
		if err := reg.Retire(ctx, *id, *actor); err != nil {
			fatalf("ca retire: %v", err)
		}
		fmt.Printf("retired CA id %d — 0 live dependents confirmed; out of the trust bundle; schedule its KMS key deletion (with alarms)\n", *id)
	case "abandon":
		if *id == 0 {
			fatalf("ca abandon: -id is required")
		}
		if err := reg.Abandon(ctx, *id, *actor); err != nil {
			fatalf("ca abandon: %v", err)
		}
		fmt.Printf("abandoned staged CA id %d\n", *id)
	case "force-renew":
		if *id == 0 {
			fatalf("ca force-renew: -id is required (a draining CA — see `ca list`)")
		}
		if *stop {
			if err := reg.StopForceRenew(ctx, *id, *actor); err != nil {
				fatalf("ca force-renew -stop: %v", err)
			}
			fmt.Printf("stopped the accelerated drain of CA id %d (reverted to natural renewal)\n", *id)
			return
		}
		if err := reg.ForceRenew(ctx, *id, *window, *actor); err != nil {
			fatalf("ca force-renew: %v", err)
		}
		deps := -1
		if row, gerr := reg.Get(ctx, *id); gerr == nil {
			if n, lerr := reg.LiveDependents(ctx, row.Fingerprint); lerr == nil {
				deps = n
			}
		}
		fmt.Printf("accelerated drain of CA id %d started — its %d remaining leaf holder(s) are force-renewed onto the active CA in waves over %s\n", *id, deps, window.String())
		fmt.Printf("  watch `harbor ca list` LIVE-DEPS fall to 0, then `harbor ca retire -id %d`. `ca force-renew -id %d -stop` cancels.\n", *id, *id)
	case "schedule-key-deletion":
		if *id == 0 {
			fatalf("ca schedule-key-deletion: -id is required (a RETIRED CA — see `ca list`)")
		}
		deleter, derr := caKeyDeleter(ctx, *backend, *kmsRegion)
		if derr != nil {
			fatalf("ca schedule-key-deletion: %v", derr)
		}
		delDate, err := reg.ScheduleKeyDeletion(ctx, *id, int32(*pendingDays), deleter, *actor)
		if err != nil {
			fatalf("ca schedule-key-deletion: %v", err)
		}
		fmt.Printf("scheduled CA id %d's signing key for deletion on %s (%d-day window)\n", *id, delDate.UTC().Format(time.RFC3339), *pendingDays)
		fmt.Printf("  the key still exists until then — `harbor ca cancel-key-deletion -id %d` aborts it. Alarm on ncp_ca_key_deletion_seconds_remaining.\n", *id)
	case "cancel-key-deletion":
		if *id == 0 {
			fatalf("ca cancel-key-deletion: -id is required")
		}
		deleter, derr := caKeyDeleter(ctx, *backend, *kmsRegion)
		if derr != nil {
			fatalf("ca cancel-key-deletion: %v", derr)
		}
		if err := reg.CancelKeyDeletion(ctx, *id, deleter, *actor); err != nil {
			fatalf("ca cancel-key-deletion: %v", err)
		}
		fmt.Printf("cancelled the pending key deletion for CA id %d (key restored to usable)\n", *id)
	default:
		fatalf("ca: unknown subcommand %q (want list|stage|adoption|activate|retire|abandon|force-renew|schedule-key-deletion|cancel-key-deletion)", sub)
	}
}
