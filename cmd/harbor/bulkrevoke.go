package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"strings"

	"github.com/jeks313/nebula-control-plane/internal/dualcontrol"
	"github.com/jeks313/nebula-control-plane/internal/genesis"
	"github.com/jeks313/nebula-control-plane/internal/revocation"
	"github.com/jeks313/nebula-control-plane/internal/store"
)

// bulkRevoke is the dual-controlled, rate-limited bulk-revoke path (7.2). It is a
// sibling of single `blocklist add` (which stays single-operator): blocklisting MANY
// fingerprints at once is high blast-radius, so it requires TWO distinct operators
// (propose as -operator-a, approve as -operator-b) and is capped + rate-limited in
// internal/revocation. The control-plane/lighthouse guard (always-on) and the optional
// -pool central guard reject any privileged fingerprint, atomically, before anything is
// applied. The store + flags are owned by cmdBlocklist (shared flag set); this is the
// thin wiring around the testable core proposeBulkRevoke.
func bulkRevoke(s *store.Store, fpFile, reason, opA, opB, pool string) {
	if fpFile == "" || opA == "" || opB == "" {
		fatalf("blocklist bulk-revoke: -fingerprints, -operator-a and -operator-b are required")
	}
	if opA == opB {
		fatalf("blocklist bulk-revoke: -operator-a and -operator-b must differ (two-person control)")
	}

	fps, err := readFingerprints(fpFile)
	if err != nil {
		fatalf("blocklist bulk-revoke: read -fingerprints: %v", err)
	}
	if len(fps) == 0 {
		fatalf("blocklist bulk-revoke: -fingerprints file %q has no fingerprints", fpFile)
	}

	// The central-block guard is ALWAYS-ON (no optional gating): -pool is required and
	// the reserved block is derived deterministically from it (the pool's first /27,
	// genesis.CentralBlock), mirroring the reaper (serve.go) and single blocklist add.
	// Missing or invalid -pool fails closed.
	if pool == "" {
		fatalf("blocklist bulk-revoke: -pool is required (the always-on central-block guard derives from it)")
	}
	p, perr := netip.ParsePrefix(pool)
	if perr != nil {
		fatalf("blocklist bulk-revoke: bad -pool %q: %v", pool, perr)
	}
	central := genesis.CentralBlock(p)
	if !central.IsValid() {
		fatalf("blocklist bulk-revoke: central guard could not be computed from -pool %q (fail-closed)", pool)
	}

	if !s.DB.Migrator().HasTable("approvals") {
		fatalf("blocklist bulk-revoke: database has no schema (no 'approvals' table) — run 'harbor migrate up' against this -dsn first")
	}

	spec := revocation.BulkRevokeSpec{Fingerprints: fps, Reason: reason}
	ch, err := proposeBulkRevoke(s, spec, opA, opB, central)
	if err != nil {
		fatalf("blocklist bulk-revoke: %v", err)
	}
	fmt.Printf("bulk revoke: change #%d committed by %s + %s — %d fingerprint(s) blocklisted\n", ch.ID, opA, opB, len(fps))
	fmt.Println("  run core-api / enroll with -blocklist-db so the change propagates to the fleet.")
}

// proposeBulkRevoke commits a bulk revoke via dual-control: propose as opA, approve
// as opB (distinct → quorum 2 → committed). The committer re-validates the spec at
// commit (cap, rate, control-plane guard) — defense in depth. The central-block guard
// is always wired (central is derived fail-closed from the required -pool by the caller).
// Returns the committed change. (Testable core of `blocklist bulk-revoke`, free of
// flag-parsing / os.Exit — mirrors publishCloudTrust.)
func proposeBulkRevoke(s *store.Store, spec revocation.BulkRevokeSpec, opA, opB string, central netip.Prefix) (dualcontrol.Change, error) {
	ctx := context.Background()
	audit := func(c context.Context, a, ac, t, d string) error { _, e := s.AppendAudit(c, a, ac, t, d); return e }
	dc := dualcontrol.New(dualcontrol.Config{DB: s.DB, Audit: audit})
	// Central guard is always-on (caller derives it fail-closed from the required -pool).
	reg := revocation.New(s.DB, audit).WithCentralBlock(central)
	revocation.RegisterCommitter(dc, reg)

	payload, _ := json.Marshal(spec)
	target := fmt.Sprintf("bulk revoke (%d fingerprints)", len(spec.Fingerprints))
	ch, err := dc.Propose(ctx, revocation.BulkRevokeKind, target, payload, opA)
	if err != nil {
		return dualcontrol.Change{}, fmt.Errorf("propose: %w", err)
	}
	committed, err := dc.Approve(ctx, ch.ID, opB)
	if err != nil {
		return dualcontrol.Change{}, fmt.Errorf("approve: %w", err)
	}
	if committed.State != "committed" {
		return dualcontrol.Change{}, fmt.Errorf("change %d did not commit (state=%s)", ch.ID, committed.State)
	}
	return committed, nil
}

// readFingerprints reads one hex fingerprint per line, ignoring blank lines and
// `#` comments. Normalization (lowercase/trim) + de-dup happen in applyBulk.
func readFingerprints(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out, sc.Err()
}
