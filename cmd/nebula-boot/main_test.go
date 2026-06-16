package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPrepareMissingIdentity(t *testing.T) {
	// Any missing identity var fails closed.
	cases := []map[string]string{
		{},
		{envCACert: "ca", envHostCert: "crt"},   // no key
		{envCACert: "ca", envHostKey: "key"},    // no cert
		{envHostCert: "crt", envHostKey: "key"}, // no ca
	}
	for i, env := range cases {
		if _, err := prepare(func(k string) string { return env[k] }); err == nil {
			t.Errorf("case %d: expected an error for incomplete identity", i)
		}
	}
}

func TestPrepareWritesIdentityAndConfig(t *testing.T) {
	env := map[string]string{
		envCACert:     "CA-PEM",
		envHostCert:   "HOST-CRT-PEM",
		envHostKey:    "HOST-KEY-PEM",
		envNebulaPort: "4500",
		envStatsPort:  "9100",
	}
	cfgPath, err := prepare(func(k string) string { return env[k] })
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	dir := filepath.Dir(cfgPath)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	for name, want := range map[string]string{
		"ca.crt":   "CA-PEM",
		"host.crt": "HOST-CRT-PEM",
		"host.key": "HOST-KEY-PEM",
	} {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if string(b) != want {
			t.Errorf("%s = %q, want %q", name, b, want)
		}
	}

	// The host private key must not be world-readable.
	info, err := os.Stat(filepath.Join(dir, "host.key"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("host.key mode = %v, want 0600", info.Mode().Perm())
	}

	cfg, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"am_lighthouse: true",
		"disabled: true",
		"port: 4500",
		"0.0.0.0:9100",
		filepath.Join(dir, "ca.crt"),
		filepath.Join(dir, "host.key"),
	} {
		if !strings.Contains(string(cfg), want) {
			t.Errorf("config.yml missing %q\n--- config ---\n%s", want, cfg)
		}
	}
}

func TestPortDefaultAndInvalid(t *testing.T) {
	if p, err := port("", 4242); err != nil || p != 4242 {
		t.Errorf(`port("",4242) = %d,%v; want 4242,nil`, p, err)
	}
	if p, err := port("4500", 4242); err != nil || p != 4500 {
		t.Errorf("port(4500) = %d,%v; want 4500,nil", p, err)
	}
	if _, err := port("notaport", 4242); err == nil {
		t.Error("expected error for non-numeric port")
	}
	if _, err := port("70000", 4242); err == nil {
		t.Error("expected error for out-of-range port")
	}
}
