// Command nebula-boot is the Fargate lighthouse's shell-less boot shim (ADR 0006). nebula
// is a third-party binary that reads its identity from FILE paths and needs a rendered
// config — work a shell entrypoint used to do. A distroless image has no shell, so this
// tiny static Go program does it: read the Secrets-Manager-injected CA/cert/key + ports
// from env, materialize them into a tmpdir, render a tun.disabled lighthouse config.yml,
// then exec nebula.
//
// tun.disabled: a lighthouse passes no data-plane traffic to/from itself, so it needs no
// TUN device (hence no CAP_NET_ADMIN / privilege) — it can run as the distroless nonroot
// user. It still does the cert-authenticated Nebula handshake and serves discovery +
// hole-punch coordination over UDP.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// Identity + port env vars ECS injects (the lighthouse counterpart to cmd/gateway's
// NCP_GW_* material vars). The PEM vars hold the literal PEM.
const (
	envCACert     = "NCP_LH_CA_CRT_PEM"
	envHostCert   = "NCP_LH_HOST_CRT_PEM"
	envHostKey    = "NCP_LH_HOST_KEY_PEM"
	envNebulaPort = "NCP_LH_NEBULA_PORT"
	envStatsPort  = "NCP_LH_STATS_PORT"

	nebulaBin = "/usr/local/bin/nebula"
)

func main() {
	configPath, err := prepare(os.Getenv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "nebula-boot: %v\n", err)
		os.Exit(1)
	}
	// Replace this process with nebula so nebula is PID 1 and receives Fargate's stop signal
	// directly (clean shutdown — no shim in the signal path).
	argv := []string{nebulaBin, "-config", configPath}
	if err := syscall.Exec(nebulaBin, argv, os.Environ()); err != nil {
		fmt.Fprintf(os.Stderr, "nebula-boot: exec %s: %v\n", nebulaBin, err)
		os.Exit(1)
	}
}

// prepare reads the injected identity + ports via getenv, materializes the cert files and
// the rendered config into a fresh tmpdir, and returns the config path. Split from main so
// it is testable without exec'ing nebula.
func prepare(getenv func(string) string) (string, error) {
	ca, hostCrt, hostKey := getenv(envCACert), getenv(envHostCert), getenv(envHostKey)
	if ca == "" || hostCrt == "" || hostKey == "" {
		return "", fmt.Errorf("missing identity: set $%s, $%s and $%s", envCACert, envHostCert, envHostKey)
	}
	nebulaPort, err := port(getenv(envNebulaPort), 4242)
	if err != nil {
		return "", fmt.Errorf("%s: %w", envNebulaPort, err)
	}
	statsPort, err := port(getenv(envStatsPort), 4280)
	if err != nil {
		return "", fmt.Errorf("%s: %w", envStatsPort, err)
	}

	dir, err := os.MkdirTemp("", "nebula-boot")
	if err != nil {
		return "", err
	}
	for _, f := range []struct {
		name string
		data string
		mode os.FileMode
	}{
		{"ca.crt", ca, 0o644},
		{"host.crt", hostCrt, 0o644},
		{"host.key", hostKey, 0o600}, // the host private key is sensitive
	} {
		if err := os.WriteFile(filepath.Join(dir, f.name), []byte(f.data), f.mode); err != nil {
			return "", err
		}
	}
	configPath := filepath.Join(dir, "config.yml")
	if err := os.WriteFile(configPath, []byte(renderConfig(dir, nebulaPort, statsPort)), 0o644); err != nil {
		return "", err
	}
	return configPath, nil
}

// port parses a TCP/UDP port from s, returning def when s is empty.
func port(s string, def int) (int, error) {
	if strings.TrimSpace(s) == "" {
		return def, nil
	}
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n < 1 || n > 65535 {
		return 0, fmt.Errorf("invalid port %q", s)
	}
	return n, nil
}

// renderConfig renders the tun.disabled lighthouse config (matching the former shell
// entrypoint's heredoc): cert paths under dir, UDP discovery on nebulaPort, and prometheus
// stats on statsPort — the latter is the NLB's TCP health-check target (UDP target groups
// can't be UDP-health-checked) and is internal-only (SG: NLB only).
func renderConfig(dir string, nebulaPort, statsPort int) string {
	return fmt.Sprintf(`pki:
  ca: %[1]s/ca.crt
  cert: %[1]s/host.crt
  key: %[1]s/host.key
static_host_map: {}
lighthouse:
  am_lighthouse: true
listen:
  host: 0.0.0.0
  port: %[2]d
punchy:
  punch: true
  respond: true
tun:
  disabled: true
stats:
  type: prometheus
  listen: 0.0.0.0:%[3]d
  path: /metrics
  namespace: nebula
  subsystem: lighthouse
  interval: 10s
firewall:
  outbound:
    - port: any
      proto: any
      host: any
  inbound:
    - port: any
      proto: any
      host: any
`, dir, nebulaPort, statsPort)
}
