package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/jeks313/nebula-control-plane/internal/dualcontrol"
	"github.com/jeks313/nebula-control-plane/internal/store"
	"github.com/jeks313/nebula-control-plane/internal/usertrust"
)

// cmdUserTrust is the operator-side SSO user-trust config tooling (ADR 0004). Today it
// has one subcommand: publish. Peer to cmdCloudTrust.
func cmdUserTrust(args []string) {
	if len(args) < 1 {
		fatalf("usertrust: want 'publish'")
	}
	switch args[0] {
	case "publish":
		userTrustPublish(args[1:])
	default:
		fatalf("usertrust: unknown subcommand %q (want publish)", args[0])
	}
}

// userTrustPublish commits a user-trust config (which SAML/OIDC directory groups, in
// which realm, may enroll into the mesh and the mesh groups + netblock + auto-issue each
// is granted — S1–S4) so a Core run with -usertrust-db will honor SSO enrollment. It is
// the operator/bootstrap path — it still requires TWO distinct operators (proposes as one
// and approves as the other), the same two-person stand-in genesis uses, so it is not a
// single-actor bypass of the API's dual-control. The console's POST /usertrust/propose is
// the day-to-day path; this is for bootstrap/break-glass where the API isn't up yet.
// Mirrors cloudTrustPublish exactly.
func userTrustPublish(args []string) {
	fs := flag.NewFlagSet("usertrust publish", flag.ExitOnError)
	driver, dsn := dbFlags(fs)
	configPath := fs.String("config", "", "user-trust config JSON file (required): {default_groups, idp_entries:[{realm, directory_group, mesh_groups, auto_issue, netblock}]}")
	opA := fs.String("operator-a", "", "proposing operator (required)")
	opB := fs.String("operator-b", "", "approving operator (required, must differ from -operator-a)")
	description := fs.String("description", "", "change description (default: 'user-trust config (N IdP entries)')")
	_ = fs.Parse(args)

	if *configPath == "" || *opA == "" || *opB == "" {
		fatalf("usertrust publish: -config, -operator-a and -operator-b are required")
	}
	if *opA == *opB {
		fatalf("usertrust publish: -operator-a and -operator-b must differ (two-person control)")
	}

	raw, err := os.ReadFile(*configPath)
	if err != nil {
		fatalf("usertrust publish: read -config: %v", err)
	}
	// Validate strictly (DisallowUnknownFields + AD-group uniqueness S3 + grants-nothing),
	// then re-marshal to a canonical payload the commit-time committer will re-parse.
	cfg, err := usertrust.Parse(raw)
	if err != nil {
		fatalf("usertrust publish: invalid config: %v", err)
	}

	s := openStore(*driver, *dsn)
	defer s.Close()
	if !s.DB.Migrator().HasTable("approvals") {
		fatalf("usertrust publish: database has no schema (no 'approvals' table) — run 'harbor migrate up' against this -dsn first")
	}
	target := *description
	if target == "" {
		target = fmt.Sprintf("user-trust config (%d IdP entries)", len(cfg.IDPEntries))
	}
	ch, err := publishUserTrust(s, cfg, *opA, *opB, target)
	if err != nil {
		fatalf("usertrust publish: %v", err)
	}
	fmt.Printf("user-trust published: change #%d committed by %s + %s\n", ch.ID, *opA, *opB)
	fmt.Printf("  %d IdP entry(ies); default groups: %v\n", len(cfg.IDPEntries), cfg.DefaultGroups)
	fmt.Println("  run the enroll worker / collect / admin-api with -usertrust-db (+ -sso-assert-pub) to honor SSO enrollment.")
}

// publishUserTrust commits a user-trust config via dual-control: propose as opA, approve
// as opB (distinct → quorum 2 → committed). The committer re-parses the payload at commit
// (defense in depth). Returns the committed change. (Testable core of `usertrust publish`,
// free of flag-parsing / os.Exit.) Mirrors publishCloudTrust.
func publishUserTrust(s *store.Store, cfg usertrust.Config, opA, opB, target string) (dualcontrol.Change, error) {
	ctx := context.Background()
	dc := newPolicyController(s) // committer re-validates AND writes the config store (ADR 0011)
	payload, _ := json.Marshal(cfg)
	ch, err := dc.Propose(ctx, usertrust.PublishKind, target, payload, opA)
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
