package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strconv"

	"github.com/jeks313/nebula-control-plane/internal/cloudtrust"
	"github.com/jeks313/nebula-control-plane/internal/config"
	"github.com/jeks313/nebula-control-plane/internal/dualcontrol"
	"github.com/jeks313/nebula-control-plane/internal/nebulaconfig"
	"github.com/jeks313/nebula-control-plane/internal/policy"
	"github.com/jeks313/nebula-control-plane/internal/store"
	"github.com/jeks313/nebula-control-plane/internal/usertrust"
)

// Harbor firewall-policy subcommands + the dual-control controller wiring (split from main.go for cohesion).

func cmdPolicy(args []string) {
	if len(args) < 1 {
		fatalf("policy: want 'validate' or 'compile'")
	}
	switch args[0] {
	case "validate":
		if len(args) < 2 {
			fatalf("policy validate: want a <policy.txt>")
		}
		p := loadPolicy(args[1])
		fmt.Printf("policy: valid — %d rule(s), invariants pass\n", len(p.Rules))
	case "compile":
		fs := flag.NewFlagSet("policy compile", flag.ExitOnError)
		groups := fs.String("groups", "", "comma-separated groups of the target host")
		_ = fs.Parse(args[1:])
		if fs.NArg() < 1 {
			fatalf("policy compile: want a <policy.txt>")
		}
		p := loadPolicy(fs.Arg(0))
		c := policy.CompileHost(p, parseCSV(*groups))
		fmt.Printf("# firewall for a host in groups %v\ninbound:\n", parseCSV(*groups))
		printRules(c.Inbound)
		fmt.Println("outbound:")
		printRules(c.Outbound)
	case "propose":
		policyPropose(args[1:])
	case "approve":
		policyApprove(args[1:])
	case "deny":
		policyDeny(args[1:])
	case "list":
		policyList(args[1:])
	case "active":
		policyActive(args[1:])
	default:
		fatalf("policy: unknown subcommand %q", args[0])
	}
}

// newPolicyController builds the dual-control controller wired to the audit log, with
// committers that re-validate the payload at commit time AND write the ADR-0011
// Phase-1 config store (the single source of truth). A two-person CLI publish/approve
// therefore lands in the SAME store the admin-API single-operator PUT writes — both
// paths converge. Re-validating at commit is defense in depth (the propose path
// already validated).
func newPolicyController(s *store.Store) *dualcontrol.Controller {
	audit := func(c context.Context, a, ac, t, d string) error { _, e := s.AppendAudit(c, a, ac, t, d); return e }
	dc := dualcontrol.New(dualcontrol.Config{DB: s.DB, Audit: audit})
	cs := config.New(s.DB, audit)
	registerStoreCommitter(dc, cs, policy.PublishKind, func(b []byte) error {
		p, err := policy.Parse(string(b))
		if err != nil {
			return err
		}
		return policy.CheckInvariants(p)
	})
	registerStoreCommitter(dc, cs, cloudtrust.PublishKind, func(b []byte) error { _, e := cloudtrust.Parse(b); return e })
	registerStoreCommitter(dc, cs, usertrust.PublishKind, func(b []byte) error { _, e := usertrust.Parse(b); return e })
	return dc
}

// registerStoreCommitter wires a dual-control committer that re-validates a config
// payload and writes it to the config store on commit (mirrors the admin-API
// registerConfigCommitter, so the CLI publish and the API converge on the store).
func registerStoreCommitter(dc *dualcontrol.Controller, cs *config.Store, kind string, validate func([]byte) error) {
	dc.Register(kind, func(ctx context.Context, ch dualcontrol.Change) error {
		if err := validate(ch.Payload); err != nil {
			return err
		}
		_, err := cs.Set(ctx, kind, ch.Payload, ch.Proposer)
		return err
	})
}

// seedConfigStore is the ADR-0011 Phase-1 boot data-migration (C8). For each of the
// three config kinds, if the new config store has no row yet AND a committed
// dual-control change of that kind exists in the legacy ledger, it RE-VALIDATES that
// latest committed payload and carries it into the store (SeedIfEmpty — insert only if
// absent). This is idempotent (a no-op once the store is populated) and runs at
// core-api/admin-api startup, so the live PoC's current committed config is not lost on
// the cutover. A failure is recoverable next boot, so the caller warns rather than aborts.
//
// Strictness (FIX 2): the legacy payload is re-validated (Parse + Validate, plus
// CheckInvariants for policy) BEFORE seeding. A legacy config that no longer passes the
// current validators (strictness drift since it was committed) is SKIPPED with a loud
// WARNING rather than seeded — never carry an invalid config into the store. The
// enforcement readers fail-closed on an unparseable store row, so a skipped kind still
// degrades safely (deny / default-deny); this just catches the drift at seed, loudly,
// instead of silently planting a bad row.
func seedConfigStore(ctx context.Context, s *store.Store, warn func(kind string, err error)) {
	cs := config.New(s.DB, nil)
	dc := newPolicyController(s) // only LatestCommitted is used here (read-only)
	// validateLegacy mirrors each kind's commit-time validator (re-validation is defense
	// in depth — the config was validated when it was committed, but the validators may
	// have tightened since). cloudtrust/usertrust Parse already runs Validate; policy
	// additionally needs CheckInvariants (Parse only runs Validate).
	validateLegacy := func(kind string, payload []byte) error {
		switch kind {
		case policy.PublishKind:
			p, err := policy.Parse(string(payload))
			if err != nil {
				return err
			}
			return policy.CheckInvariants(p)
		case cloudtrust.PublishKind:
			_, err := cloudtrust.Parse(payload)
			return err
		case usertrust.PublishKind:
			_, err := usertrust.Parse(payload)
			return err
		default:
			return fmt.Errorf("unknown config kind %q", kind)
		}
	}
	for _, kind := range []string{policy.PublishKind, cloudtrust.PublishKind, usertrust.PublishKind} {
		row, err := cs.Get(ctx, kind)
		if err != nil {
			warn(kind, err)
			continue
		}
		if row != nil {
			continue // store already has it — nothing to seed
		}
		ch, ok, err := dc.LatestCommitted(ctx, kind)
		if err != nil {
			warn(kind, err)
			continue
		}
		if !ok {
			continue // nothing committed in the legacy ledger either
		}
		// Re-validate before seeding: a strictness-drifted legacy config is skipped
		// loudly, not seeded. (Idempotency is unaffected — once the store has a row this
		// kind is short-circuited above.)
		if verr := validateLegacy(kind, ch.Payload); verr != nil {
			warn(kind, fmt.Errorf("legacy committed config fails current validation — SKIPPING seed (reader stays fail-closed): %w", verr))
			continue
		}
		if _, err := cs.SeedIfEmpty(ctx, kind, ch.Payload, "migration"); err != nil {
			warn(kind, err)
		}
	}
}

// configStore builds the ADR-0011 Phase-1 config store over s. The enforcement
// readers below read the active config from THIS store (the single source of truth),
// not the dual-control ledger — both the single-operator PUT and the two-person
// commit converge on it. No audit hook is needed for a read-only consumer.
func configStore(s *store.Store) *config.Store { return config.New(s.DB, nil) }

// activeCloudTrust returns the currently active cloud-trust config from the config
// store (ADR 0011 Phase 1), if any.
func activeCloudTrust(ctx context.Context, s *store.Store) (cloudtrust.Config, bool) {
	row, err := configStore(s).Get(ctx, cloudtrust.PublishKind)
	if err != nil {
		fatalf("cloudtrust: read active: %v", err)
	}
	if row == nil {
		return cloudtrust.Config{}, false
	}
	c, err := cloudtrust.Parse(row.Payload)
	if err != nil {
		fatalf("cloudtrust: active config is unparseable: %v", err)
	}
	return c, true
}

// activeUserTrust returns the currently published user-trust config (latest committed
// usertrust.publish, S1), if any. Peer to activeCloudTrust: the active user-trust config
// is the latest committed usertrust.publish dual-control change, read the same way. The
// enrollment consumer reads this LIVE per enrollment via a getter (cf. cloud-trust's
// build-time snapshot) so the dual-control flow can change who may enroll without a Core
// restart — see (cf).userTrustActive.
//
// Unlike activeCloudTrust (a build-time snapshot read once at startup, where a fatalf is
// acceptable fail-fast), this is the LIVE per-enrollment path on a long-running harbor
// process (core-api/collect). It MUST NOT exit: a transient DB blip or one malformed
// committed config would otherwise crash the running control plane (a self-inflicted DoS).
// On ANY error (DB error OR parse failure) it returns false + a clear Warn, so SSO
// enrollment fails closed via the existing ErrSSONotConfigured deny (the getter sees
// not-found) instead of taking the process down. Security review final hardening (FIX A).
func activeUserTrust(ctx context.Context, s *store.Store) (usertrust.Config, bool) {
	row, err := configStore(s).Get(ctx, usertrust.PublishKind)
	if err != nil {
		slog.Warn("usertrust: read active failed; treating SSO as not configured (fail closed)", "err", err)
		return usertrust.Config{}, false
	}
	if row == nil {
		return usertrust.Config{}, false
	}
	c, err := usertrust.Parse(row.Payload)
	if err != nil {
		slog.Warn("usertrust: active config is unparseable; treating SSO as not configured (fail closed)", "err", err)
		return usertrust.Config{}, false
	}
	return c, true
}

// activePolicy returns the currently active policy from the config store (ADR 0011
// Phase 1), if any.
func activePolicy(ctx context.Context, s *store.Store) (policy.Policy, bool) {
	row, err := configStore(s).Get(ctx, policy.PublishKind)
	if err != nil {
		fatalf("policy: read active: %v", err)
	}
	if row == nil {
		return policy.Policy{}, false
	}
	p, err := policy.Parse(string(row.Payload))
	if err != nil {
		fatalf("policy: active policy is unparseable: %v", err)
	}
	return p, true
}

func policyPropose(args []string) {
	if len(args) < 1 {
		fatalf("policy propose: want a <policy.txt>")
	}
	// The policy file is positional and comes first; flags follow (flag.Parse
	// stops at the first non-flag argument).
	file := args[0]
	fs := flag.NewFlagSet("policy propose", flag.ExitOnError)
	driver, dsn := dbFlags(fs)
	proposer := fs.String("proposer", "", "proposing admin identity (required)")
	_ = fs.Parse(args[1:])
	if *proposer == "" {
		fatalf("policy propose: -proposer is required")
	}
	// Validate + invariant-check before opening a change — never queue a policy
	// that could not be published.
	p := loadPolicy(file)
	raw, err := os.ReadFile(file)
	if err != nil {
		fatalf("policy propose: read %s: %v", file, err)
	}
	s := openStore(*driver, *dsn)
	defer s.Close()
	ch, err := newPolicyController(s).Propose(context.Background(), policy.PublishKind,
		fmt.Sprintf("firewall policy (%d rules)", len(p.Rules)), raw, *proposer)
	if err != nil {
		fatalf("policy propose: %v", err)
	}
	fmt.Printf("proposed policy change #%d by %s — needs %d distinct approver(s); approve with:\n", ch.ID, *proposer, ch.Quorum)
	fmt.Printf("  harbor policy approve %d -approver <other-admin>\n", ch.ID)
}

func policyApprove(args []string) {
	id := positionalID(args, "policy approve", "<change-id>")
	fs := flag.NewFlagSet("policy approve", flag.ExitOnError)
	driver, dsn := dbFlags(fs)
	approver := fs.String("approver", "", "approving admin identity, distinct from the proposer (required)")
	_ = fs.Parse(args[1:])
	if *approver == "" {
		fatalf("policy approve: -approver is required")
	}
	s := openStore(*driver, *dsn)
	defer s.Close()
	ch, err := newPolicyController(s).Approve(context.Background(), id, *approver)
	if err != nil {
		fatalf("policy approve: %v", err)
	}
	switch dualcontrol.State(ch.State) {
	case dualcontrol.StateCommitted:
		fmt.Printf("policy change #%d committed by %s — now the active fleet policy\n", id, *approver)
	default:
		fmt.Printf("policy change #%d: recorded %s's approval (state=%s)\n", id, *approver, ch.State)
	}
}

func policyDeny(args []string) {
	id := positionalID(args, "policy deny", "<change-id>")
	fs := flag.NewFlagSet("policy deny", flag.ExitOnError)
	driver, dsn := dbFlags(fs)
	actor := fs.String("actor", "", "admin identity recording the denial (required)")
	reason := fs.String("reason", "", "denial reason")
	_ = fs.Parse(args[1:])
	if *actor == "" {
		fatalf("policy deny: -actor is required")
	}
	s := openStore(*driver, *dsn)
	defer s.Close()
	if _, err := newPolicyController(s).Deny(context.Background(), id, *actor, *reason); err != nil {
		fatalf("policy deny: %v", err)
	}
	fmt.Printf("policy change #%d denied by %s\n", id, *actor)
}

func policyList(args []string) {
	fs := flag.NewFlagSet("policy list", flag.ExitOnError)
	driver, dsn := dbFlags(fs)
	pending := fs.Bool("pending", false, "show only changes awaiting approval")
	_ = fs.Parse(args)
	s := openStore(*driver, *dsn)
	defer s.Close()
	state := dualcontrol.State("")
	if *pending {
		state = dualcontrol.StatePending
	}
	changes, err := newPolicyController(s).List(context.Background(), state)
	if err != nil {
		fatalf("policy list: %v", err)
	}
	if len(changes) == 0 {
		fmt.Println("no policy changes")
		return
	}
	fmt.Printf("%-4s %-10s %-18s %-10s %s\n", "ID", "STATE", "PROPOSER", "QUORUM", "TARGET")
	for _, c := range changes {
		_, sigs, _ := newPolicyController(s).Get(context.Background(), c.ID)
		approvals := 0
		for _, sg := range sigs {
			if sg.Decision == "approve" {
				approvals++
			}
		}
		fmt.Printf("%-4d %-10s %-18s %d/%-8d %s\n", c.ID, c.State, c.Proposer, approvals, c.Quorum, c.Target)
	}
}

func policyActive(args []string) {
	fs := flag.NewFlagSet("policy active", flag.ExitOnError)
	driver, dsn := dbFlags(fs)
	_ = fs.Parse(args)
	s := openStore(*driver, *dsn)
	defer s.Close()
	p, ok := activePolicy(context.Background(), s)
	if !ok {
		fmt.Println("no policy published yet (fleet is default-deny)")
		return
	}
	fmt.Printf("# active policy: %d rule(s)\n", len(p.Rules))
	for _, r := range p.Rules {
		fmt.Printf("allow %s -> %s %s %s\n", r.FromGroup, r.ToGroup, r.Proto, r.Port)
	}
}

// positionalID extracts a required positional int64 id that precedes flags.
func positionalID(args []string, cmd, what string) int64 {
	if len(args) < 1 {
		fatalf("%s: want %s", cmd, what)
	}
	id, err := strconv.ParseInt(args[0], 10, 64)
	if err != nil {
		fatalf("%s: bad %s %q", cmd, what, args[0])
	}
	return id
}

func loadPolicy(path string) policy.Policy {
	raw, err := os.ReadFile(path)
	if err != nil {
		fatalf("policy: read %s: %v", path, err)
	}
	p, err := policy.Parse(string(raw))
	if err != nil {
		fatalf("%v", err)
	}
	if err := policy.CheckInvariants(p); err != nil {
		fatalf("%v", err)
	}
	return p
}

func printRules(rules []nebulaconfig.Rule) {
	for _, r := range rules {
		sel := "host:" + r.Host
		if r.Group != "" {
			sel = "group:" + r.Group
		}
		fmt.Printf("  - %-4s %-6s %s\n", r.Proto, r.Port, sel)
	}
}
