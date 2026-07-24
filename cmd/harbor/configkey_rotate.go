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

	"github.com/jeks313/nebula-control-plane/internal/configkey"
	"github.com/jeks313/nebula-control-plane/internal/configsign"
	"github.com/jeks313/nebula-control-plane/internal/signer"
	"github.com/jeks313/nebula-control-plane/internal/store"
)

// configKeySeedIdentity derives the config-key-rotation registry name + signing-backend id for the
// CURRENT config-signing key (the one loaded from -config-key/-config-label/-kms-config-key-id), so
// the boot-seed records it faithfully. A bare pubkey has no Name(), so the genesis key gets a fixed
// label; the kms id is however this process signs bundles with it.
func configKeySeedIdentity(cf *coreFlags) (name, kmsID string) {
	name = "config-genesis"
	switch {
	case *cf.cfgKmsKeyID != "":
		kmsID = *cf.cfgKmsKeyID
	case *cf.configLbl != "":
		kmsID = "pkcs11:" + *cf.configLbl
	default:
		kmsID = "software"
	}
	return name, kmsID
}

// configKeyTrustSource boot-seeds the current config-signing key into the M8.5 rotation registry
// (idempotent, race-tolerant) and returns BOTH the live trust source Core renders into every bundle's
// config_signing_keys AND the version source stamped as ConfigKeyVersion (anti-rollback). Once a
// second key is staged (`harbor config-key stage`), the fleet trusts [K1, K2] via the next signed
// bundle — "trust before you sign" (design §4.6/§4.8). Fail-open: a registry read at bundle-build time
// falls back to the static config key (see enrollment/coreapi configKeys()).
func (cf *coreFlags) configKeyTrustSource(s *store.Store, cfgPubPEM []byte, audit configkey.AuditFunc) (keys func(context.Context) ([]string, error), version func(context.Context) (int64, error)) {
	reg := configkey.New(s.DB, audit)
	name, kmsID := configKeySeedIdentity(cf)
	_, seeded, err := reg.SeedActive(context.Background(), name, string(cfgPubPEM), kmsID, "boot-seed")
	switch {
	case err != nil:
		slog.Warn("configkey: boot-seed of the current config-signing key failed; config_signing_keys falls back to the static key", "err", err)
	case seeded:
		slog.Info("configkey: seeded the current config-signing key into the rotation registry (M8.5)", "name", name, "kms_key_id", kmsID)
	}
	return reg.TrustedKeys, reg.Generation
}

// newConfigSigner builds the hot-swappable ConfigSigner over the boot config backend (M8.5). A
// build failure is fatal — the process cannot sign bundles without it — matching signer.New.
func (cf *coreFlags) newConfigSigner(cfgB signer.Backend, audit configsign.AuditFunc) *configsign.ConfigSigner {
	cs, err := configsign.New(cfgB, audit, nil)
	if err != nil {
		fatalf("config-signing: %v", err)
	}
	return cs
}

// activeConfigKeySource adapts the config-key registry's active key into configsign.ActiveConfigKeyRef
// so the M8.5 hot-swap reconciler can watch for a newly-activated key without configsign importing
// configkey. "No active key" maps to an empty ref (keep the current signing key rather than swapping
// to nothing).
func (cf *coreFlags) activeConfigKeySource(s *store.Store, audit configkey.AuditFunc) func(context.Context) (configsign.ActiveConfigKeyRef, error) {
	reg := configkey.New(s.DB, audit)
	return func(ctx context.Context) (configsign.ActiveConfigKeyRef, error) {
		c, err := reg.Active(ctx)
		if err != nil {
			if errors.Is(err, configkey.ErrNoActive) {
				return configsign.ActiveConfigKeyRef{}, nil
			}
			return configsign.ActiveConfigKeyRef{}, err
		}
		return configsign.ActiveConfigKeyRef{Fingerprint: c.Fingerprint, PubPEM: c.PubPEM, KMSKeyID: c.KMSKeyID}, nil
	}
}

// activeConfigKeyBackendFactory builds the signing backend for a rotated-in active config key (M8.5),
// reading its stored id EXACTLY as configKeySeedIdentity records it: a "pkcs11:<label>" URI, the
// literal "software", or otherwise a KMS key id/ARN. The factory is only called for a key that DIFFERS
// from the one this process booted with, so a software key means a NEW software key this process does
// not hold -> refuse (restart with the new -config-key). The poc uses KMS, where the stored ARN
// suffices and NO config-signing private key is handled here (P2 — the key stays in KMS).
func (cf *coreFlags) activeConfigKeyBackendFactory() configsign.BackendFactory {
	return func(ctx context.Context, kmsKeyID string, _ []byte) (signer.Backend, error) {
		switch {
		case strings.HasPrefix(kmsKeyID, "pkcs11:"):
			return signer.NewPKCS11Backend(signer.PKCS11Config{
				ModulePath: *cf.module, TokenLabel: *cf.token, Pin: *cf.pin,
				KeyLabel: strings.TrimPrefix(kmsKeyID, "pkcs11:"),
			})
		case kmsKeyID == "software" || kmsKeyID == "":
			return nil, fmt.Errorf("software-backed process cannot reach a new software config key %q at runtime; restart with the new -config-key to cut over (KMS/PKCS#11 cut over live)", kmsKeyID)
		default:
			return signer.NewKMSBackend(ctx, signer.KMSConfig{KeyID: kmsKeyID, Region: *cf.kmsRegion})
		}
	}
}

// startConfigKeyCutoverReconciler launches the M8.5 hot-swap reconciler for a signing process
// (core-api / enroll worker / collector / admin-api-issuance): it polls the active config key and
// cuts cs over when a new key is activated. Fail-safe (a bad tick keeps the prior key) and bounded by
// -ca-cutover-interval (reused; 0 disables). Registered on wg so it drains on shutdown.
func (cf *coreFlags) startConfigKeyCutoverReconciler(ctx context.Context, wg *sync.WaitGroup, cs *configsign.ConfigSigner, s *store.Store, audit configkey.AuditFunc, log *slog.Logger) {
	if cs == nil {
		return
	}
	interval := *cf.caCutoverInterval
	if interval <= 0 {
		log.Info("configkey: config-key-rotation cut-over reconciler disabled (-ca-cutover-interval=0); activate a key then restart to cut over")
		return
	}
	src := cf.activeConfigKeySource(s, audit)
	factory := cf.activeConfigKeyBackendFactory()
	// Eager reconcile BEFORE serving so a restart with a stale -config-key argv doesn't sign under a
	// since-retired key for an interval; no-op when the boot key is already active; fail-safe on error.
	if swapped, err := cs.ReconcileActiveConfigKey(ctx, src, factory); err != nil {
		log.Warn("configkey: initial cut-over reconcile failed; signing with the boot config key until it succeeds", "err", err)
	} else if swapped {
		log.Info("configkey: hot-swapped bundle signing to the active config key on startup", "fingerprint", cs.CurrentFingerprint())
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		cs.RunReconciler(ctx, src, factory, interval, log)
	}()
	log.Info("configkey: config-key-rotation cut-over reconciler started (M8.5)", "interval", interval.String())
}

// configAdoptionGate is the pure M8.5 cut-over decision: proceed iff the target key is fully adopted
// by live hosts OR -force overrides. Returns a human refusal message when it blocks.
func configAdoptionGate(ad configkey.Adoption, force bool) (proceed bool, refusal string) {
	if ad.FullyAdopted() || force {
		return true, ""
	}
	return false, fmt.Sprintf("only %d of %d live host(s) confirm trust of the target config key; %d laggard(s): %s",
		ad.Adopted, ad.Live, len(ad.Laggards), strings.Join(ad.Laggards, ", "))
}

// cmdConfigKey is the `harbor config-key` break-glass CLI for the config-signing-key rotation
// lifecycle (M8.5, design §4.6/§4.8): list the keys and their states; stage a new key (K2 → trusted
// fleet-wide before it signs); check adoption; activate it (cut bundle signing over, demoting the
// prior active to draining); retire a drained key (gated on the fleet trusting the new active key);
// abandon a staged key; or schedule/cancel deletion of a retired key's KMS key. Read-only list +
// adoption are ALSO surfaced in the console; the lifecycle actions remain break-glass CLI.
func cmdConfigKey(args []string) {
	if len(args) < 1 {
		fatalf("config-key: want list|stage|adoption|activate|retire|abandon|schedule-key-deletion|cancel-key-deletion")
	}
	sub := args[0]
	fs := flag.NewFlagSet("config-key "+sub, flag.ExitOnError)
	driver, dsn := dbFlags(fs)
	pubPath := fs.String("pub", "", "stage: config-signing PUBLIC key PEM file (the new key K2 to trust)")
	name := fs.String("name", "", "stage: human label for the key (e.g. config-2027)")
	kmsKeyID := fs.String("kms-key-id", "", "stage: how to reach its signing backend (KMS ARN / 'pkcs11:<label>' / 'software'); empty = trust-only")
	id := fs.Int64("id", 0, "adoption/activate/retire/abandon/*-key-deletion: the key row id (see `config-key list`)")
	actor := fs.String("actor", "operator", "admin identity for the audit trail")
	force := fs.Bool("force", false, "activate: cut over even if <100% of LIVE hosts confirm trust of the target key (break-glass — a stranded host rejects EVERY bundle until re-pinned)")
	staleAfter := fs.Duration("stale-after", 5*time.Minute, "activate/adoption/retire: heartbeat freshness window defining a LIVE host (keep aligned with serve/admin-api -stale-after)")
	pendingDays := fs.Int("pending-window-days", 30, "schedule-key-deletion: KMS pending window before the key is destroyed (7-30 days; cancellable until then)")
	backend := fs.String("backend", envOr("HARBOR_BACKEND", "software"), "schedule/cancel-key-deletion: key custody backend (kms drives real KMS deletion; else software no-op) (default: $HARBOR_BACKEND, else software)")
	kmsRegion := fs.String("kms-region", os.Getenv("HARBOR_KMS_REGION"), "schedule/cancel-key-deletion: AWS region for the KMS key deleter (kms backend) (default: $HARBOR_KMS_REGION)")
	_ = fs.Parse(args[1:])

	s := openStore(*driver, *dsn)
	defer s.Close()
	audit := func(c context.Context, a, ac, t, d string) error { _, e := s.AppendAudit(c, a, ac, t, d); return e }
	reg := configkey.New(s.DB, audit)
	ctx := context.Background()

	switch sub {
	case "list":
		rows, err := reg.List(ctx)
		if err != nil {
			fatalf("config-key list: %v", err)
		}
		if len(rows) == 0 {
			fmt.Println("no config-signing keys yet (the current key is seeded on core-api / enroll-worker startup)")
			return
		}
		activeFp, _ := reg.ActiveFingerprint(ctx)
		trusted := map[string]bool{}
		if tks, terr := reg.List(ctx); terr == nil {
			for _, k := range tks {
				if k.State != configkey.StateRetired {
					trusted[k.Fingerprint] = true
				}
			}
		}
		// Drain remaining is fleet-level (laggards on the active key), the same for every draining key.
		drain := "?"
		if n, derr := reg.DrainLaggards(ctx, *staleAfter); derr == nil {
			drain = strconv.Itoa(n)
		}
		fmt.Printf("%-4s %-16s %-9s %-7s %-8s %-10s %s\n", "ID", "NAME", "STATE", "ACTIVE", "TRUSTED", "KEY-DEL", "FINGERPRINT")
		for _, c := range rows {
			act := ""
			if c.Fingerprint == activeFp {
				act = "*"
			}
			tr := ""
			if trusted[c.Fingerprint] {
				tr = "yes"
			}
			keyDel := "-"
			if c.KeyDeletionScheduledAt != 0 {
				keyDel = time.Unix(0, c.KeyDeletionDate).UTC().Format("2006-01-02")
			}
			fmt.Printf("%-4d %-16s %-9s %-7s %-8s %-10s %s\n", c.ID, c.Name, c.State, act, tr, keyDel, c.Fingerprint)
		}
		fmt.Printf("drain remaining (live hosts not yet on the active key): %s\n", drain)
	case "stage":
		if *pubPath == "" || *name == "" {
			fatalf("config-key stage: -pub and -name are required")
		}
		pem, err := os.ReadFile(*pubPath)
		if err != nil {
			fatalf("config-key stage: read -pub: %v", err)
		}
		row, err := reg.Stage(ctx, *name, string(pem), *kmsKeyID, *actor)
		if err != nil {
			fatalf("config-key stage: %v", err)
		}
		fmt.Printf("staged config key %q (id %d, fp %s)\n", row.Name, row.ID, row.Fingerprint)
		fmt.Printf("  -> now trusted fleet-wide via the next signed bundle. Watch `harbor config-key adoption -id %d`; `activate` refuses until 100%% unless -force.\n", row.ID)
	case "adoption":
		if *id == 0 {
			fatalf("config-key adoption: -id is required (see `config-key list`)")
		}
		target, err := reg.Get(ctx, *id)
		if err != nil {
			fatalf("config-key adoption: %v", err)
		}
		ad, err := reg.AdoptionStatus(ctx, target.Fingerprint, *staleAfter)
		if err != nil {
			fatalf("config-key adoption: %v", err)
		}
		pct := 100.0
		if ad.Live > 0 {
			pct = float64(ad.Adopted) / float64(ad.Live) * 100
		}
		gate := "NOT yet fully adopted"
		if ad.FullyAdopted() {
			gate = "fully adopted — safe to `config-key activate`"
		}
		fmt.Printf("config key %q (id %d, state %s, fp %s)\n", target.Name, target.ID, target.State, target.Fingerprint)
		fmt.Printf("adoption: %d/%d live host(s) confirm trust (%.0f%%) — %s\n", ad.Adopted, ad.Live, pct, gate)
		if len(ad.Laggards) > 0 {
			fmt.Printf("  laggards (live, not yet confirming): %s\n", strings.Join(ad.Laggards, ", "))
		}
		if len(ad.Stale) > 0 {
			fmt.Printf("  stale (beyond the freshness window; excluded from the gate): %s\n", strings.Join(ad.Stale, ", "))
		}
	case "activate":
		if *id == 0 {
			fatalf("config-key activate: -id is required (see `config-key list`)")
		}
		target, err := reg.Get(ctx, *id)
		if err != nil {
			fatalf("config-key activate: %v", err)
		}
		ad, err := reg.AdoptionStatus(ctx, target.Fingerprint, *staleAfter)
		if err != nil {
			fatalf("config-key activate: adoption check: %v", err)
		}
		if proceed, refusal := configAdoptionGate(ad, *force); !proceed {
			fatalf("config-key activate: REFUSING to cut over — %s.\n"+
				"Cutting over now would STRAND those host(s): once signing moves to key %q (%s…) they would reject EVERY bundle "+
				"(the config key is the ROOT of bundle trust, not a member) and could not receive the bundle that would fix them. "+
				"Wait for 100%% (watch `harbor config-key adoption -id %d`), or override with -force with eyes open.",
				refusal, target.Name, target.Fingerprint[:12], *id)
		}
		if !ad.FullyAdopted() {
			fmt.Printf("WARNING: -force overriding the adoption gate — %d live host(s) do not yet trust config key %q and will reject every bundle until re-pinned (8.6)\n",
				len(ad.Laggards), target.Name)
		} else if ad.Live == 0 {
			if len(ad.Stale) > 0 {
				fmt.Printf("note: 0 LIVE hosts, but %d stale. Cut-over is safe (the prior key stays trusted while draining, so they re-adopt on return before renewing). Proceeding.\n", len(ad.Stale))
			} else {
				fmt.Println("note: 0 live hosts heartbeating — nothing to confirm; proceeding")
			}
		}
		if err := reg.Activate(ctx, *id, *actor); err != nil {
			fatalf("config-key activate: %v", err)
		}
		fmt.Printf("activated config key id %d — bundles now sign with it (hot-swapped, no restart); the prior key is draining\n", *id)
	case "retire":
		if *id == 0 {
			fatalf("config-key retire: -id is required (a draining key — see `config-key list`)")
		}
		// Retire refuses fail-closed until the whole LIVE fleet trusts the ACTIVE key (drain == adoption).
		if err := reg.Retire(ctx, *id, *staleAfter, *actor); err != nil {
			fatalf("config-key retire: %v", err)
		}
		fmt.Printf("retired config key id %d — the live fleet is fully on the active key; out of the trust set; schedule its KMS key deletion (with alarms)\n", *id)
	case "abandon":
		if *id == 0 {
			fatalf("config-key abandon: -id is required")
		}
		if err := reg.Abandon(ctx, *id, *actor); err != nil {
			fatalf("config-key abandon: %v", err)
		}
		fmt.Printf("abandoned staged config key id %d\n", *id)
	case "schedule-key-deletion":
		if *id == 0 {
			fatalf("config-key schedule-key-deletion: -id is required (a RETIRED key — see `config-key list`)")
		}
		deleter, derr := caKeyDeleter(ctx, *backend, *kmsRegion)
		if derr != nil {
			fatalf("config-key schedule-key-deletion: %v", derr)
		}
		delDate, err := reg.ScheduleKeyDeletion(ctx, *id, int32(*pendingDays), deleter, *actor)
		if err != nil {
			fatalf("config-key schedule-key-deletion: %v", err)
		}
		fmt.Printf("scheduled config key id %d's signing key for deletion on %s (%d-day window)\n", *id, delDate.UTC().Format(time.RFC3339), *pendingDays)
		fmt.Printf("  the key still exists until then — `harbor config-key cancel-key-deletion -id %d` aborts it. Alarm on ncp_configkey_key_deletion_seconds_remaining.\n", *id)
	case "cancel-key-deletion":
		if *id == 0 {
			fatalf("config-key cancel-key-deletion: -id is required")
		}
		deleter, derr := caKeyDeleter(ctx, *backend, *kmsRegion)
		if derr != nil {
			fatalf("config-key cancel-key-deletion: %v", derr)
		}
		if err := reg.CancelKeyDeletion(ctx, *id, deleter, *actor); err != nil {
			fatalf("config-key cancel-key-deletion: %v", err)
		}
		fmt.Printf("cancelled the pending key deletion for config key id %d (key restored to usable)\n", *id)
	default:
		fatalf("config-key: unknown subcommand %q (want list|stage|adoption|activate|retire|abandon|schedule-key-deletion|cancel-key-deletion)", sub)
	}
}
