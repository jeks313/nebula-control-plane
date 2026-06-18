package main

import "testing"

const sampleCfg = `pki:
  ca: /etc/nebula/ca.crt
listen:
  host: 0.0.0.0
  port: 4242
stats:
  type: prometheus
  listen: 0.0.0.0:4280
  path: /metrics
firewall:
  inbound:
    - port: any
      proto: icmp
`

func TestStatsListenAddr(t *testing.T) {
	if got := statsListenAddr([]byte(sampleCfg)); got != "0.0.0.0:4280" {
		t.Errorf("statsListenAddr = %q, want 0.0.0.0:4280", got)
	}
	// No stats block -> empty.
	noStats := "listen:\n  port: 4242\nfirewall:\n  inbound: []\n"
	if got := statsListenAddr([]byte(noStats)); got != "" {
		t.Errorf("statsListenAddr(no stats) = %q, want empty", got)
	}
}

func TestStripStatsBlock(t *testing.T) {
	out := string(stripStatsBlock([]byte(sampleCfg)))
	if statsListenAddr([]byte(out)) != "" {
		t.Errorf("stats block survived strip:\n%s", out)
	}
	// The surrounding sections must remain.
	for _, want := range []string{"pki:", "listen:", "port: 4242", "firewall:", "proto: icmp"} {
		if !contains(out, want) {
			t.Errorf("strip dropped %q:\n%s", want, out)
		}
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
