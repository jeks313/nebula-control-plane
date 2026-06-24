package main

import (
	"context"
	"flag"

	"github.com/jeks313/nebula-control-plane/internal/lighthouse"
)

// cmdLighthouseRotationRecord records the outcome of one scheduled rotation run for a lighthouse
// (the rotation timer/script calls it per lighthouse after handling it). It feeds the rotation
// LIVENESS metrics (ncp_lighthouse_rotation_*): -result is ok (rotated + re-injected + ECS
// stable), skip (cert not yet due), or fail (any error; -error is the detail). It always stamps
// the last-run time, so a dead timer is detectable even when no rotation was due.
func cmdLighthouseRotationRecord(args []string) {
	fs := flag.NewFlagSet("lighthouse rotation-record", flag.ExitOnError)
	driver, dsn := dbFlags(fs)
	name := fs.String("name", "", "lighthouse device name (required)")
	result := fs.String("result", "", "ok|skip|fail (required)")
	errMsg := fs.String("error", "", "error detail when -result=fail")
	_ = fs.Parse(args)
	if *name == "" || *result == "" {
		fatalf("lighthouse rotation-record: -name and -result (ok|skip|fail) are required")
	}

	s := openStore(*driver, *dsn)
	defer s.Close()
	audit := func(c context.Context, a, ac, t, d string) error { _, e := s.AppendAudit(c, a, ac, t, d); return e }
	reg := lighthouse.New(s.DB, audit)
	if err := reg.RecordRotation(context.Background(), *name, *result, *errMsg); err != nil {
		fatalf("lighthouse rotation-record: %v", err)
	}
}
