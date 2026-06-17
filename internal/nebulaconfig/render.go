// Package nebulaconfig renders a nebula config.yml from a template plus a values
// set (implementation-plan M1.7). The values are split in two: PKI paths come
// from Pilot's own layout (paths.Layout), while policy fields (lighthouses,
// firewall, listen port) are a local stand-in for what Harbor will hand down
// centrally from M6. The rendered shape mirrors the config proven out by the M0
// netns spike, so "renders a config Nebula accepts" stays true by construction.
package nebulaconfig

import (
	"bytes"
	_ "embed"
	"fmt"
	"strings"
	"text/template"
)

//go:embed template.yml.tmpl
var tmplText string

var tmpl = template.Must(template.New("nebula-config").Parse(tmplText))

// Lighthouse is a control-plane lighthouse this host should know about. It feeds
// both static_host_map (overlay IP -> public addrs) and, for non-lighthouse
// hosts, lighthouse.hosts.
type Lighthouse struct {
	OverlayIP   string   `yaml:"overlay_ip"`   // e.g. 100.64.0.1
	PublicAddrs []string `yaml:"public_addrs"` // e.g. ["198.51.100.1:4242"]
}

// Rule is one firewall rule. Exactly one selector (Host, Group, Groups, or CIDR)
// should be set; SelectorYAML emits the first one found.
type Rule struct {
	Port   string   `yaml:"port"`
	Proto  string   `yaml:"proto"`
	Host   string   `yaml:"host,omitempty"`
	Group  string   `yaml:"group,omitempty"`
	Groups []string `yaml:"groups,omitempty"`
	CIDR   string   `yaml:"cidr,omitempty"`
}

// SelectorYAML returns the inline YAML for the rule's target selector. Called
// from the template.
func (r Rule) SelectorYAML() string {
	switch {
	case len(r.Groups) > 0:
		return "groups: [" + strings.Join(quoteAll(r.Groups), ", ") + "]"
	case r.Group != "":
		return "group: " + r.Group
	case r.CIDR != "":
		return "cidr: " + r.CIDR
	default:
		host := r.Host
		if host == "" {
			host = "any"
		}
		return "host: " + host
	}
}

func quoteAll(ss []string) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = `"` + s + `"`
	}
	return out
}

// Values is everything the template needs. Policy fields default via Defaults();
// the PKI paths must be set by the caller from paths.Layout.
type Values struct {
	// PKI paths (set from paths.Layout — not operator-supplied).
	CACertPath string `yaml:"-"`
	CertPath   string `yaml:"-"`
	KeyPath    string `yaml:"-"`

	AmLighthouse       bool         `yaml:"am_lighthouse"`
	LighthouseInterval int          `yaml:"lighthouse_interval"`
	Lighthouses        []Lighthouse `yaml:"lighthouses"`

	ListenHost string `yaml:"listen_host"`
	ListenPort int    `yaml:"listen_port"`

	TunDev string `yaml:"tun_dev"`
	MTU    int    `yaml:"mtu"`

	// Prometheus stats: nebula's built-in /metrics listener (data-plane metrics — handshakes,
	// tunnels, tx/rx). StatsPort 0 disables it. Bound on 0.0.0.0 but reachable only over the
	// overlay (the node SGs don't open it on the underlay), so it's mesh-only like core-api.
	StatsPort      int    `yaml:"stats_port"`
	StatsSubsystem string `yaml:"stats_subsystem"`

	LogLevel  string `yaml:"log_level"`
	LogFormat string `yaml:"log_format"`

	Blocklist []string `yaml:"blocklist"`
	Inbound   []Rule   `yaml:"inbound"`
	Outbound  []Rule   `yaml:"outbound"`
}

// Hosts returns the lighthouse overlay IPs this node should point at. A
// lighthouse points at no one, so the list is empty when AmLighthouse is set —
// the template then emits "hosts: []".
func (v Values) Hosts() []string {
	if v.AmLighthouse {
		return nil
	}
	hosts := make([]string, 0, len(v.Lighthouses))
	for _, lh := range v.Lighthouses {
		hosts = append(hosts, lh.OverlayIP)
	}
	return hosts
}

// Defaults fills unset policy fields with safe local-dev defaults. It does not
// touch the PKI paths. The default firewall is intentionally tight: outbound is
// open (a host may reach the mesh) but inbound allows only ICMP, so a freshly
// rendered node is pingable for smoke tests yet exposes no services until real
// policy arrives from Harbor (M6).
func (v *Values) Defaults() {
	if v.LighthouseInterval == 0 {
		v.LighthouseInterval = 60
	}
	if v.ListenHost == "" {
		v.ListenHost = "0.0.0.0"
	}
	if v.ListenPort == 0 {
		v.ListenPort = 4242
	}
	if v.TunDev == "" {
		v.TunDev = "nebula1"
	}
	if v.MTU == 0 {
		v.MTU = 1300
	}
	if v.StatsPort == 0 {
		v.StatsPort = 8080 // nebula prometheus /metrics (same port the Fargate lighthouse uses)
	}
	if v.StatsSubsystem == "" {
		v.StatsSubsystem = "node"
	}
	if v.LogLevel == "" {
		v.LogLevel = "info"
	}
	if v.LogFormat == "" {
		v.LogFormat = "text"
	}
	if len(v.Outbound) == 0 {
		v.Outbound = []Rule{{Port: "any", Proto: "any", Host: "any"}}
	}
	if len(v.Inbound) == 0 {
		v.Inbound = []Rule{{Port: "any", Proto: "icmp", Host: "any"}}
	}
}

// Render writes the rendered config to a byte slice. PKI paths must be set.
func Render(v Values) ([]byte, error) {
	if v.CACertPath == "" || v.CertPath == "" || v.KeyPath == "" {
		return nil, fmt.Errorf("nebulaconfig: PKI paths (ca/cert/key) must be set")
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, v); err != nil {
		return nil, fmt.Errorf("nebulaconfig: render: %w", err)
	}
	return buf.Bytes(), nil
}
