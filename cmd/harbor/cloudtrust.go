package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/jeks313/nebula-control-plane/internal/cloudtrust"
	"github.com/jeks313/nebula-control-plane/internal/dualcontrol"
	"github.com/jeks313/nebula-control-plane/internal/store"
)

// cmdCloudTrust is the operator-side cloud-trust config tooling. Today it has one
// subcommand: publish.
func cmdCloudTrust(args []string) {
	if len(args) < 1 {
		fatalf("cloudtrust: want 'publish'")
	}
	switch args[0] {
	case "publish":
		cloudTrustPublish(args[1:])
	default:
		fatalf("cloudtrust: unknown subcommand %q (want publish)", args[0])
	}
}

// cloudTrustPublish commits a cloud-trust config (which cloud accounts/roles may
// attest, and the groups + admission they get) so core-api/worker run with
// -cloudtrust-db will honor aws-sigv4 attestation. It is the operator/bootstrap path
// — it still requires TWO distinct operators (it proposes as one and approves as the
// other), the same two-person stand-in genesis uses, so it is not a single-actor
// bypass of the API's dual-control. The console's POST /cloudtrust/propose is the
// day-to-day path; this is for bootstrap/break-glass where the API isn't up yet.
func cloudTrustPublish(args []string) {
	fs := flag.NewFlagSet("cloudtrust publish", flag.ExitOnError)
	driver, dsn := dbFlags(fs)
	configPath := fs.String("config", "", "cloud-trust config JSON file (required): {default_groups, aws:[{account, arn_patterns, groups, auto_issue}]}")
	opA := fs.String("operator-a", "", "proposing operator (required)")
	opB := fs.String("operator-b", "", "approving operator (required, must differ from -operator-a)")
	description := fs.String("description", "", "change description (default: 'cloud-trust config (N AWS accounts)')")
	_ = fs.Parse(args)

	if *configPath == "" || *opA == "" || *opB == "" {
		fatalf("cloudtrust publish: -config, -operator-a and -operator-b are required")
	}
	if *opA == *opB {
		fatalf("cloudtrust publish: -operator-a and -operator-b must differ (two-person control)")
	}

	raw, err := os.ReadFile(*configPath)
	if err != nil {
		fatalf("cloudtrust publish: read -config: %v", err)
	}
	// Validate strictly (DisallowUnknownFields + non-empty aws + unique accounts), then
	// re-marshal to a canonical payload the commit-time committer will re-parse.
	cfg, err := cloudtrust.Parse(raw)
	if err != nil {
		fatalf("cloudtrust publish: invalid config: %v", err)
	}

	s := openStore(*driver, *dsn)
	defer s.Close()
	if !s.DB.Migrator().HasTable("approvals") {
		fatalf("cloudtrust publish: database has no schema (no 'approvals' table) — run 'harbor migrate up' against this -dsn first")
	}
	target := *description
	if target == "" {
		target = fmt.Sprintf("cloud-trust config (%d AWS accounts)", len(cfg.AWS))
	}
	ch, err := publishCloudTrust(s, cfg, *opA, *opB, target)
	if err != nil {
		fatalf("cloudtrust publish: %v", err)
	}
	fmt.Printf("cloud-trust published: change #%d committed by %s + %s\n", ch.ID, *opA, *opB)
	fmt.Printf("  %d AWS account(s); default groups: %v\n", len(cfg.AWS), cfg.DefaultGroups)
	fmt.Println("  run core-api / enroll worker with -cloudtrust-db to honor aws-sigv4 attestation.")
}

// publishCloudTrust commits a cloud-trust config via dual-control: propose as opA,
// approve as opB (distinct → quorum 2 → committed). The committer re-parses the
// payload at commit (defense in depth). Returns the committed change. (Testable core
// of `cloudtrust publish`, free of flag-parsing / os.Exit.)
func publishCloudTrust(s *store.Store, cfg cloudtrust.Config, opA, opB, target string) (dualcontrol.Change, error) {
	ctx := context.Background()
	dc := newPolicyController(s) // committer re-validates AND writes the config store (ADR 0011)
	payload, _ := json.Marshal(cfg)
	ch, err := dc.Propose(ctx, cloudtrust.PublishKind, target, payload, opA)
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
