package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strconv"

	"github.com/jeks313/nebula-control-plane/internal/cloudtrust"
	"github.com/jeks313/nebula-control-plane/internal/dualcontrol"
	"github.com/jeks313/nebula-control-plane/internal/nebulaconfig"
	"github.com/jeks313/nebula-control-plane/internal/policy"
	"github.com/jeks313/nebula-control-plane/internal/store"
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

// newPolicyController builds the dual-control controller wired to the audit log,
// with a committer that re-validates the policy payload at commit time (defense
// in depth — invariants are also checked at propose).
func newPolicyController(s *store.Store) *dualcontrol.Controller {
	audit := func(c context.Context, a, ac, t, d string) error { _, e := s.AppendAudit(c, a, ac, t, d); return e }
	dc := dualcontrol.New(dualcontrol.Config{DB: s.DB, Audit: audit})
	// Commit-time validation lives in the domain packages (single canonical
	// definition, shared with the admin API + demo seeder so the gate can't drift).
	policy.RegisterCommitter(dc)
	cloudtrust.RegisterCommitter(dc)
	return dc
}

// activeCloudTrust returns the currently published cloud-trust config (latest committed
// cloudtrust.publish), if any.
func activeCloudTrust(ctx context.Context, s *store.Store) (cloudtrust.Config, bool) {
	dc := newPolicyController(s)
	ch, ok, err := dc.LatestCommitted(ctx, cloudtrust.PublishKind)
	if err != nil {
		fatalf("cloudtrust: read active: %v", err)
	}
	if !ok {
		return cloudtrust.Config{}, false
	}
	c, err := cloudtrust.Parse(ch.Payload)
	if err != nil {
		fatalf("cloudtrust: active config #%d is unparseable: %v", ch.ID, err)
	}
	return c, true
}

// activePolicy returns the currently published policy (latest committed
// policy.publish), if any.
func activePolicy(ctx context.Context, s *store.Store) (policy.Policy, bool) {
	dc := newPolicyController(s)
	ch, ok, err := dc.LatestCommitted(ctx, policy.PublishKind)
	if err != nil {
		fatalf("policy: read active: %v", err)
	}
	if !ok {
		return policy.Policy{}, false
	}
	p, err := policy.Parse(string(ch.Payload))
	if err != nil {
		fatalf("policy: active policy #%d is unparseable: %v", ch.ID, err)
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
	dc := newPolicyController(s)
	ch, ok, err := dc.LatestCommitted(context.Background(), policy.PublishKind)
	if err != nil {
		fatalf("policy active: %v", err)
	}
	if !ok {
		fmt.Println("no policy published yet (fleet is default-deny)")
		return
	}
	fmt.Printf("# active policy: change #%d, hash %x\n%s\n", ch.ID, ch.PayloadHash[:8], string(ch.Payload))
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
