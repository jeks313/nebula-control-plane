package main

import (
	"flag"
	"testing"
)

// TestCoreFlagsEnvDefaults: the CA/KMS/queue/pool flags default from HARBOR_* env vars (so an
// interactive `harbor enroll approve <id> -approver A` needs no signing/queue flags), and an
// explicit -flag still overrides. Mirrors TestDBFlagsEnvDefaults — same mechanism, signing side.
func TestCoreFlagsEnvDefaults(t *testing.T) {
	t.Setenv("HARBOR_BACKEND", "kms")
	t.Setenv("HARBOR_CA_CERT", "/home/ec2-user/ncp/genesis/ca.crt")
	t.Setenv("HARBOR_KMS_CA_KEY_ID", "arn:aws:kms:ca-central-1:1:key/ca")
	t.Setenv("HARBOR_KMS_CONFIG_KEY_ID", "arn:aws:kms:ca-central-1:1:key/cfg")
	t.Setenv("HARBOR_KMS_REGION", "ca-central-1")
	t.Setenv("HARBOR_HMAC_KEY", "/home/ec2-user/ncp/hmac.b64")
	t.Setenv("HARBOR_QUEUE_DSN", "/home/ec2-user/ncp/queue.db")
	t.Setenv("HARBOR_QUEUE_KEY", "/home/ec2-user/ncp/queue.b64")
	t.Setenv("HARBOR_POOL", "10.44.0.0/16")

	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	cf := addCoreFlags(fs)
	if err := fs.Parse(nil); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ name, got, want string }{
		{"backend", *cf.backend, "kms"},
		{"ca-cert", *cf.caCert, "/home/ec2-user/ncp/genesis/ca.crt"},
		{"kms-ca-key-id", *cf.caKmsKeyID, "arn:aws:kms:ca-central-1:1:key/ca"},
		{"kms-config-key-id", *cf.cfgKmsKeyID, "arn:aws:kms:ca-central-1:1:key/cfg"},
		{"kms-region", *cf.kmsRegion, "ca-central-1"},
		{"hmac-key", *cf.hmacKey, "/home/ec2-user/ncp/hmac.b64"},
		{"queue-dsn", *cf.queueDSN, "/home/ec2-user/ncp/queue.db"},
		{"queue-key", *cf.queueKey, "/home/ec2-user/ncp/queue.b64"},
		{"pool", *cf.pool, "10.44.0.0/16"},
	} {
		if c.got != c.want {
			t.Errorf("%s = %q, want %q (from env default)", c.name, c.got, c.want)
		}
	}

	// An explicit flag still overrides the env default (so the systemd units, which pass explicit
	// flags, are unaffected by whatever is exported in /etc/profile.d).
	fs2 := flag.NewFlagSet("t2", flag.ContinueOnError)
	cf2 := addCoreFlags(fs2)
	if err := fs2.Parse([]string{"-backend", "software", "-pool", "100.64.0.0/16"}); err != nil {
		t.Fatal(err)
	}
	if *cf2.backend != "software" {
		t.Errorf("explicit -backend should override $HARBOR_BACKEND, got %q", *cf2.backend)
	}
	if *cf2.pool != "100.64.0.0/16" {
		t.Errorf("explicit -pool should override $HARBOR_POOL, got %q", *cf2.pool)
	}
}

// TestCoreFlagsNoEnv: with the env unset, the original defaults stand (software backend, empty
// signing/queue, 100.64/16 pool) — so existing callers and tests are unaffected.
func TestCoreFlagsNoEnv(t *testing.T) {
	for _, k := range []string{
		"HARBOR_BACKEND", "HARBOR_CA_CERT", "HARBOR_KMS_CA_KEY_ID", "HARBOR_KMS_CONFIG_KEY_ID",
		"HARBOR_KMS_REGION", "HARBOR_HMAC_KEY", "HARBOR_QUEUE_DSN", "HARBOR_QUEUE_KEY", "HARBOR_POOL",
	} {
		t.Setenv(k, "")
	}
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	cf := addCoreFlags(fs)
	if err := fs.Parse(nil); err != nil {
		t.Fatal(err)
	}
	if *cf.backend != "software" {
		t.Errorf("backend default = %q, want software", *cf.backend)
	}
	if *cf.queueDSN != "" {
		t.Errorf("queue-dsn default = %q, want empty", *cf.queueDSN)
	}
	if *cf.pool != "100.64.0.0/16" {
		t.Errorf("pool default = %q, want 100.64.0.0/16", *cf.pool)
	}
}
