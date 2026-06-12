// Command harbor is the Nebula Control Plane central service (enrollment, IPAM,
// signing, policy, rotation). M2 brings up the data layer + signing spine; this
// CLI currently drives schema migrations and the hash-chained audit log.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/jeks313/nebula-control-plane/internal/store"
	"github.com/jeks313/nebula-control-plane/internal/store/migrate"
)

// version is overridden at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "migrate":
		cmdMigrate(os.Args[2:])
	case "audit":
		cmdAudit(os.Args[2:])
	case "version", "--version", "-v":
		fmt.Printf("harbor %s\n", version)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "harbor: unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `harbor — Nebula Control Plane central service

usage:
  harbor migrate up|down   [-driver sqlite|postgres] [-dsn <dsn>]
  harbor audit add         -actor A -action X [-target T] [-details D] [db flags]
  harbor audit verify      [db flags]
  harbor version

db flags default to a local SQLite file (./harbor.db). Set -driver postgres
-dsn "postgres://user:pass@host/db?sslmode=require" for production.
`)
}

// dbFlags adds -driver/-dsn to a flagset and returns accessors. Default is local
// SQLite so dev needs zero setup; the same flags slot in Postgres for prod.
func dbFlags(fs *flag.FlagSet) (*string, *string) {
	driver := fs.String("driver", "sqlite", "sqlite|postgres")
	dsn := fs.String("dsn", "", "data source name (default: ./harbor.db for sqlite)")
	return driver, dsn
}

func resolveDSN(driver, dsn string) string {
	if dsn != "" {
		return dsn
	}
	if driver == "sqlite" {
		return store.DefaultSQLiteDSN("harbor.db")
	}
	return dsn
}

func cmdMigrate(args []string) {
	if len(args) < 1 {
		fatalf("migrate: want 'up' or 'down'")
	}
	// The direction is positional and comes first; flag parsing must run on the
	// remainder, since flag.Parse stops at the first non-flag argument.
	dir := args[0]
	fs := flag.NewFlagSet("migrate", flag.ExitOnError)
	driver, dsn := dbFlags(fs)
	_ = fs.Parse(args[1:])

	s := openStore(*driver, *dsn)
	defer s.Close()
	var err error
	switch dir {
	case "up":
		err = migrate.Up(s.DB)
	case "down":
		err = migrate.Down(s.DB)
	default:
		fatalf("migrate: unknown direction %q (want up|down)", dir)
	}
	if err != nil {
		fatalf("%v", err)
	}
	fmt.Printf("harbor migrate %s: ok (%s)\n", dir, *driver)
}

func cmdAudit(args []string) {
	if len(args) < 1 {
		fatalf("audit: want 'add' or 'verify'")
	}
	switch args[0] {
	case "add":
		auditAdd(args[1:])
	case "verify":
		auditVerify(args[1:])
	default:
		fatalf("audit: unknown subcommand %q (want add|verify)", args[0])
	}
}

func auditAdd(args []string) {
	fs := flag.NewFlagSet("audit add", flag.ExitOnError)
	driver, dsn := dbFlags(fs)
	actor := fs.String("actor", "", "who performed the action (required)")
	action := fs.String("action", "", "what action (required)")
	target := fs.String("target", "", "the action's target")
	details := fs.String("details", "", "free-form detail (e.g. JSON)")
	_ = fs.Parse(args)
	if *actor == "" || *action == "" {
		fatalf("audit add: -actor and -action are required")
	}
	s := openStore(*driver, *dsn)
	defer s.Close()
	e, err := s.AppendAudit(context.Background(), *actor, *action, *target, *details)
	if err != nil {
		fatalf("%v", err)
	}
	fmt.Printf("audit: appended seq=%d hash=%x\n", e.Seq, e.Hash)
}

func auditVerify(args []string) {
	fs := flag.NewFlagSet("audit verify", flag.ExitOnError)
	driver, dsn := dbFlags(fs)
	_ = fs.Parse(args)
	s := openStore(*driver, *dsn)
	defer s.Close()
	n, err := s.VerifyAudit(context.Background())
	if err != nil {
		fmt.Fprintf(os.Stderr, "audit: VERIFICATION FAILED after %d rows: %v\n", n, err)
		os.Exit(1)
	}
	fmt.Printf("audit: chain verified, %d rows intact\n", n)
}

func openStore(driver, dsn string) *store.Store {
	s, err := store.Open(store.Config{Driver: driver, DSN: resolveDSN(driver, dsn)})
	if err != nil {
		fatalf("%v", err)
	}
	return s
}

func fatalf(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "harbor: "+format+"\n", a...)
	os.Exit(1)
}
