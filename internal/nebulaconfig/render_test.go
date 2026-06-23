package nebulaconfig

import (
	"testing"

	"gopkg.in/yaml.v3"
)

func baseValues() Values {
	v := Values{
		CACertPath: "/etc/ncp/ca.crt",
		CertPath:   "/etc/ncp/host.crt",
		KeyPath:    "/etc/ncp/host.key",
		Lighthouses: []Lighthouse{
			{OverlayIP: "100.64.0.1", PublicAddrs: []string{"198.51.100.1:4242"}},
		},
	}
	v.Defaults()
	return v
}

// decode renders and parses the result, failing on invalid YAML. The returned
// map lets tests assert structure the way Nebula's own loader would see it.
func decode(t *testing.T, v Values) map[string]any {
	t.Helper()
	out, err := Render(v)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	var m map[string]any
	if err := yaml.Unmarshal(out, &m); err != nil {
		t.Fatalf("rendered config is not valid YAML: %v\n---\n%s", err, out)
	}
	return m
}

func TestRenderNonLighthouse(t *testing.T) {
	m := decode(t, baseValues())

	pki := m["pki"].(map[string]any)
	if pki["key"] != "/etc/ncp/host.key" {
		t.Errorf("pki.key = %v", pki["key"])
	}

	lh := m["lighthouse"].(map[string]any)
	if lh["am_lighthouse"] != false {
		t.Errorf("am_lighthouse = %v, want false", lh["am_lighthouse"])
	}
	hosts := lh["hosts"].([]any)
	if len(hosts) != 1 || hosts[0] != "100.64.0.1" {
		t.Errorf("lighthouse.hosts = %v, want [100.64.0.1]", hosts)
	}

	// Relay: a non-lighthouse host routes through the lighthouse as its relay (ADR 0006), so the
	// relay list mirrors the lighthouses.
	rel := m["relay"].(map[string]any)
	if rel["am_relay"] != false {
		t.Errorf("relay.am_relay = %v, want false", rel["am_relay"])
	}
	if rel["use_relays"] != true {
		t.Errorf("relay.use_relays = %v, want true", rel["use_relays"])
	}
	relays := rel["relays"].([]any)
	if len(relays) != 1 || relays[0] != "100.64.0.1" {
		t.Errorf("relay.relays = %v, want [100.64.0.1]", relays)
	}

	shm := m["static_host_map"].(map[string]any)
	if _, ok := shm["100.64.0.1"]; !ok {
		t.Errorf("static_host_map missing lighthouse: %v", shm)
	}

	fw := m["firewall"].(map[string]any)
	inbound := fw["inbound"].([]any)
	// Tight default (icmp only) PLUS the nebula stats port (tcp) so the /metrics endpoint is
	// scrapeable over the overlay by the monitoring node — see Values.StatsPort / Defaults.
	if len(inbound) != 2 {
		t.Fatalf("default inbound len = %d, want 2 (icmp + stats port)", len(inbound))
	}
	if r := inbound[0].(map[string]any); r["proto"] != "icmp" {
		t.Errorf("default inbound[0] proto = %v, want icmp (tight default)", r["proto"])
	}
	if r := inbound[1].(map[string]any); r["proto"] != "tcp" {
		t.Errorf("default inbound[1] proto = %v, want tcp (nebula stats port)", r["proto"])
	}
}

func TestRenderLighthouseEmitsEmptyHosts(t *testing.T) {
	v := baseValues()
	v.AmLighthouse = true
	m := decode(t, v)

	lh := m["lighthouse"].(map[string]any)
	if lh["am_lighthouse"] != true {
		t.Errorf("am_lighthouse = %v, want true", lh["am_lighthouse"])
	}
	// A lighthouse must point at no one: hosts must be an empty list, not null.
	hosts, ok := lh["hosts"].([]any)
	if !ok {
		t.Fatalf("lighthouse.hosts is %T, want empty list", lh["hosts"])
	}
	if len(hosts) != 0 {
		t.Errorf("lighthouse.hosts = %v, want []", hosts)
	}

	// A lighthouse IS the relay: am_relay true, use_relays false, and relays must be an empty list
	// (not null — nebula rejects null), mirroring the hosts invariant.
	rel := m["relay"].(map[string]any)
	if rel["am_relay"] != true {
		t.Errorf("relay.am_relay = %v, want true", rel["am_relay"])
	}
	if rel["use_relays"] != false {
		t.Errorf("relay.use_relays = %v, want false", rel["use_relays"])
	}
	relays, ok := rel["relays"].([]any)
	if !ok {
		t.Fatalf("relay.relays is %T, want empty list", rel["relays"])
	}
	if len(relays) != 0 {
		t.Errorf("relay.relays = %v, want []", relays)
	}
}

func TestRenderGroupsSelector(t *testing.T) {
	v := baseValues()
	v.Inbound = []Rule{{Port: "443", Proto: "tcp", Groups: []string{"web", "prod"}}}
	m := decode(t, v)

	fw := m["firewall"].(map[string]any)
	r := fw["inbound"].([]any)[0].(map[string]any)
	groups := r["groups"].([]any)
	if len(groups) != 2 || groups[0] != "web" || groups[1] != "prod" {
		t.Errorf("groups = %v, want [web prod]", groups)
	}
}

func TestRenderRequiresPKIPaths(t *testing.T) {
	v := baseValues()
	v.KeyPath = ""
	if _, err := Render(v); err == nil {
		t.Fatal("Render should fail when a PKI path is empty")
	}
}
