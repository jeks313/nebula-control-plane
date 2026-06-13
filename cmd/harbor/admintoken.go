package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/adminauth"
)

// cmdAdminToken mints and manages non-interactive admin API tokens (A0.8). These
// are LOCAL bootstrap commands: they create the credential automation uses to call
// /admin/v1, so they cannot themselves require that credential — they touch the
// store directly, like genesis/ca-init. Minting + revoking are audited.
func cmdAdminToken(args []string) {
	if len(args) < 1 {
		fatalf("admin-token: want 'create', 'list', or 'revoke'")
	}
	switch args[0] {
	case "create":
		adminTokenCreate(args[1:])
	case "list":
		adminTokenList(args[1:])
	case "revoke":
		adminTokenRevoke(args[1:])
	default:
		fatalf("admin-token: unknown subcommand %q (want create|list|revoke)", args[0])
	}
}

func adminTokenCreate(args []string) {
	fs := flag.NewFlagSet("admin-token create", flag.ExitOnError)
	driver, dsn := dbFlags(fs)
	name := fs.String("name", "", "token name/label (required)")
	roles := fs.String("roles", "", "scoped roles, CSV (e.g. operator or operator,viewer)")
	ttl := fs.Duration("ttl", 0, "lifetime (e.g. 720h); 0 = never expires")
	by := fs.String("by", "operator", "who is minting this token (recorded in the audit log)")
	_ = fs.Parse(args)
	if *name == "" {
		fatalf("admin-token create: -name is required")
	}
	scoped := parseCSV(*roles)

	s := openStore(*driver, *dsn)
	defer s.Close()
	ctx := context.Background()
	ts := adminauth.NewTokenStore(s.DB, nil)
	token, row, err := ts.Mint(ctx, *name, "", scoped, *by, *ttl)
	if err != nil {
		fatalf("admin-token create: %v", err)
	}
	_, _ = s.AppendAudit(ctx, *by, "admin-token-create", *name, fmt.Sprintf("roles=%v ttl=%s", scoped, ttl.String()))

	// Result -> stdout (clean), so it can be captured. The token is shown ONCE.
	fmt.Printf("created admin token %q\n", row.Name)
	fmt.Printf("  principal: %s\n", row.Principal)
	fmt.Printf("  roles:     %v\n", row.RoleList())
	if row.ExpiresAt == 0 {
		fmt.Printf("  expires:   never\n")
	} else {
		fmt.Printf("  expires:   %s\n", time.Unix(0, row.ExpiresAt).UTC().Format(time.RFC3339))
	}
	fmt.Println()
	fmt.Println("  TOKEN (shown once — store it securely, e.g. HARBOR_TOKEN):")
	fmt.Printf("    %s\n", token)
	fmt.Println()
	fmt.Println(`  use: curl -H "Authorization: Bearer $HARBOR_TOKEN" https://<core>:8445/admin/v1/me`)
}

func adminTokenList(args []string) {
	fs := flag.NewFlagSet("admin-token list", flag.ExitOnError)
	driver, dsn := dbFlags(fs)
	_ = fs.Parse(args)
	s := openStore(*driver, *dsn)
	defer s.Close()
	rows, err := adminauth.NewTokenStore(s.DB, nil).List(context.Background())
	if err != nil {
		fatalf("admin-token list: %v", err)
	}
	if len(rows) == 0 {
		fmt.Println("no admin tokens")
		return
	}
	now := time.Now()
	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tPRINCIPAL\tROLES\tSTATUS\tEXPIRES\tLAST_USED")
	for _, t := range rows {
		fmt.Fprintf(tw, "%s\t%s\t%v\t%s\t%s\t%s\n",
			t.Name, t.Principal, t.RoleList(), tokenStatus(t, now), tsOrDash(t.ExpiresAt), tsOrDash(t.LastUsedAt))
	}
	_ = tw.Flush()
}

func adminTokenRevoke(args []string) {
	fs := flag.NewFlagSet("admin-token revoke", flag.ExitOnError)
	driver, dsn := dbFlags(fs)
	name := fs.String("name", "", "name of the token(s) to revoke (required)")
	by := fs.String("by", "operator", "who is revoking (recorded in the audit log)")
	_ = fs.Parse(args)
	if *name == "" {
		fatalf("admin-token revoke: -name is required")
	}
	s := openStore(*driver, *dsn)
	defer s.Close()
	ctx := context.Background()
	n, err := adminauth.NewTokenStore(s.DB, nil).Revoke(ctx, *name)
	if err != nil {
		fatalf("admin-token revoke: %v", err)
	}
	_, _ = s.AppendAudit(ctx, *by, "admin-token-revoke", *name, fmt.Sprintf("count=%d", n))
	fmt.Printf("revoked %d active token(s) named %q\n", n, *name)
}

func tokenStatus(t adminauth.AdminToken, now time.Time) string {
	switch {
	case t.RevokedAt != 0:
		return "revoked"
	case !t.Active(now):
		return "expired"
	default:
		return "active"
	}
}

func tsOrDash(ns int64) string {
	if ns == 0 {
		return "-"
	}
	return time.Unix(0, ns).UTC().Format(time.RFC3339)
}
