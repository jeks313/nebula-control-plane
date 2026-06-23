package main

import (
	"flag"
	"testing"
)

// TestDBFlagsEnvDefaults: the DB connection flags default from HARBOR_DB_* env vars (so an interactive
// `harbor <cmd>` needs no flags), and an explicit -flag still overrides the env.
func TestDBFlagsEnvDefaults(t *testing.T) {
	t.Setenv("HARBOR_DB_DRIVER", "postgres")
	t.Setenv("HARBOR_DSN", "postgres://db.example/harbor?sslmode=require")
	t.Setenv("HARBOR_DB_SECRET_ARN", "arn:aws:secretsmanager:ca-central-1:1:secret:x")
	t.Setenv("HARBOR_DB_SECRET_REGION", "ca-central-1")

	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	driver, dsn := dbFlags(fs)
	if err := fs.Parse(nil); err != nil {
		t.Fatal(err)
	}
	if *driver != "postgres" {
		t.Errorf("driver = %q, want postgres (from $HARBOR_DB_DRIVER)", *driver)
	}
	if *dsn != "postgres://db.example/harbor?sslmode=require" {
		t.Errorf("dsn = %q, want the $HARBOR_DSN value", *dsn)
	}
	if dbPool.secretARN == nil || *dbPool.secretARN == "" {
		t.Errorf("db-secret-arn did not default from $HARBOR_DB_SECRET_ARN")
	}
	if dbPool.secretRegion == nil || *dbPool.secretRegion != "ca-central-1" {
		t.Errorf("db-secret-region did not default from $HARBOR_DB_SECRET_REGION")
	}

	// An explicit flag overrides the env default.
	fs2 := flag.NewFlagSet("t2", flag.ContinueOnError)
	driver2, _ := dbFlags(fs2)
	if err := fs2.Parse([]string{"-driver", "sqlite"}); err != nil {
		t.Fatal(err)
	}
	if *driver2 != "sqlite" {
		t.Errorf("explicit -driver should override $HARBOR_DB_DRIVER, got %q", *driver2)
	}
}

// TestDBFlagsNoEnv: with the env unset, the original sqlite/empty defaults stand (services + tests).
func TestDBFlagsNoEnv(t *testing.T) {
	t.Setenv("HARBOR_DB_DRIVER", "")
	t.Setenv("HARBOR_DSN", "")
	t.Setenv("HARBOR_DB_SECRET_ARN", "")
	t.Setenv("HARBOR_DB_SECRET_REGION", "")
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	driver, dsn := dbFlags(fs)
	if err := fs.Parse(nil); err != nil {
		t.Fatal(err)
	}
	if *driver != "sqlite" {
		t.Errorf("driver default = %q, want sqlite", *driver)
	}
	if *dsn != "" {
		t.Errorf("dsn default = %q, want empty", *dsn)
	}
}
