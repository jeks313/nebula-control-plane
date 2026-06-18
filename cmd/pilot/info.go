package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/bundle"
	"github.com/jeks313/nebula-control-plane/internal/enrollclient"
	"github.com/jeks313/nebula-control-plane/internal/paths"
	"github.com/jeks313/nebula-control-plane/internal/pilotservice"
	"github.com/slackhq/nebula/cert"
	"gopkg.in/yaml.v3"
)

// info.go implements `pilot info` — a read-only diagnostic + onboarding command. It
// reports this node's identity, its per-mesh membership (reusing the same local-state
// reads as `pilot status`), best-effort Harbor reachability, and — the headline — the
// cloud attestation identity this machine would present, so an operator can copy the
// account/role/ARN into Harbor's cloudtrust config to onboard the host.

// nodeInfo is the whole `pilot info` report (the --json shape).
type nodeInfo struct {
	Node   NodeSection  `json:"node"`
	Meshes []MeshInfo   `json:"meshes"`
	Cloud  CloudSection `json:"cloud"`
}

// NodeSection is the host-level facts.
type NodeSection struct {
	Hostname      string `json:"hostname"`
	OS            string `json:"os"`
	Arch          string `json:"arch"`
	PilotVersion  string `json:"pilot_version"`
	NebulaVersion string `json:"nebula_version,omitempty"`
}

// MeshInfo is one joined mesh's local state.
type MeshInfo struct {
	Mesh         string       `json:"mesh"`
	StateDir     string       `json:"state_dir"`
	OverlayIP    string       `json:"overlay_ip,omitempty"`
	CommonName   string       `json:"common_name,omitempty"`
	Groups       []string     `json:"groups,omitempty"`
	NotBefore    string       `json:"not_before,omitempty"`
	NotAfter     string       `json:"not_after,omitempty"`
	TimeToExpiry string       `json:"time_to_expiry,omitempty"`
	Expired      bool         `json:"expired,omitempty"`
	CertFP       string       `json:"cert_fingerprint,omitempty"`
	CAFP         string       `json:"ca_fingerprint,omitempty"`
	Lighthouses  []string     `json:"lighthouses,omitempty"`
	CoreURL      string       `json:"core_url,omitempty"`
	BundleVer    int          `json:"bundle_version,omitempty"`
	Service      string       `json:"service,omitempty"`
	Harbor       *HarborProbe `json:"harbor,omitempty"`
	// Note carries any non-fatal read problem (e.g. an unparseable cert) so a
	// degraded mesh still appears in the report instead of being silently dropped.
	Note string `json:"note,omitempty"`
}

// HarborProbe is the best-effort reachability of a mesh's core API.
type HarborProbe struct {
	URL        string `json:"url"`
	Reachable  bool   `json:"reachable"`
	StatusCode int    `json:"status_code,omitempty"`
	LatencyMS  int64  `json:"latency_ms,omitempty"`
	Endpoint   string `json:"endpoint,omitempty"`
	Error      string `json:"error,omitempty"`
}

// CloudSection is the detected cloud instance identity (the onboarding headline).
type CloudSection struct {
	Provider string     `json:"provider"` // "aws" | "azure" | "none"
	AWS      *AWSMeta   `json:"aws,omitempty"`
	Azure    *AzureMeta `json:"azure,omitempty"`
}

// defaultMeshDir is the conventional single-mesh `-dir` layout (the `pilot supervise
// -dir /etc/nebula` deployment, where ALL state — config.yml, ca.crt, host.crt,
// host.key, bundle.json — sits flat in one dir rather than under StateRoot/<mesh>).
// `pilot info` auto-detects it so a `-dir` host (common on servers) isn't reported as
// "not joined to any mesh". A package-level var so tests can point it at a temp dir.
var defaultMeshDir = "/etc/nebula"

// cmdInfo gathers + prints the node report. It never fails on a down Harbor or an
// off-cloud host — `info` is a diagnostic, so partial data is the norm.
func cmdInfo(args []string) {
	fs := flag.NewFlagSet("info", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "emit the full report as JSON (for scripted onboarding)")
	mesh := fs.String("mesh", "", "report only this mesh (default: every joined mesh)")
	dir := fs.String("dir", "", "report exactly this state dir as one mesh (the single-mesh `-dir` layout); bypasses the StateRoot scan")
	_ = fs.Parse(args)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	info := gatherInfo(ctx, *mesh, *dir)

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(info); err != nil {
			fatalf("info: encode json: %v", err)
		}
		return
	}
	printInfo(os.Stdout, info)
}

// gatherInfo collects the whole report. meshFilter "" means every joined mesh; meshDir
// (the -dir flag) "" means scan StateRoot + auto-detect the conventional single-mesh dir.
func gatherInfo(ctx context.Context, meshFilter, meshDir string) nodeInfo {
	host, _ := os.Hostname()
	info := nodeInfo{
		Node: NodeSection{
			Hostname:      host,
			OS:            runtime.GOOS,
			Arch:          runtime.GOARCH,
			PilotVersion:  version,
			NebulaVersion: nebulaVersion(defaultNebulaPath),
		},
	}

	switch {
	case meshDir != "":
		// Explicit -dir: report exactly that directory as one mesh, bypassing both the
		// StateRoot scan and the single-mesh auto-detect. viaDir: this is a `-dir`
		// supervise deployment, so introspect its running process for liveness + core URL.
		info.Meshes = append(info.Meshes, gatherMeshAt(ctx, filepath.Base(meshDir), meshDir, true))
	case meshFilter != "":
		// -mesh x: just that mesh under StateRoot (works even before its dir exists). A
		// multi-mesh entry — keep the per-mesh OS service + service.env behavior.
		info.Meshes = append(info.Meshes, gatherMeshAt(ctx, meshFilter, filepath.Join(pilotservice.StateRoot, meshFilter), false))
	default:
		// The multi-mesh StateRoot scan (per-mesh OS services; not viaDir)...
		seen := map[string]bool{}
		for _, m := range infoMeshes("") {
			base := filepath.Join(pilotservice.StateRoot, m)
			seen[filepath.Clean(base)] = true
			info.Meshes = append(info.Meshes, gatherMeshAt(ctx, m, base, false))
		}
		// ...plus the conventional single-mesh `-dir` dir, if it holds mesh state and
		// isn't already covered by a StateRoot entry (the no-double-report guard). viaDir:
		// it's a `-dir` supervise deployment, so introspect the running process.
		if !seen[filepath.Clean(defaultMeshDir)] && hasMeshState(defaultMeshDir) {
			info.Meshes = append(info.Meshes, gatherMeshAt(ctx, filepath.Base(defaultMeshDir), defaultMeshDir, true))
		}
	}

	info.Cloud = gatherCloud(ctx, "", nil)
	return info
}

// infoMeshes returns the meshes to report: just the filter if set (so `-mesh x` works
// even before its dir exists), else every joined mesh under StateRoot.
func infoMeshes(filter string) []string {
	if filter != "" {
		return []string{filter}
	}
	ms := listMeshes()
	sort.Strings(ms)
	return ms
}

// hasMeshState reports whether base looks like a real mesh state dir — used to decide
// whether to auto-detect the conventional single-mesh `-dir` layout. A host.crt or a
// config.yml is enough to count it as a deployment worth reporting.
func hasMeshState(base string) bool {
	layout := paths.New(base)
	return fileExists(layout.HostCert()) || fileExists(layout.Config())
}

// gatherMeshAt reads one mesh's local state from baseDir, then layers on the service
// state and a best-effort Harbor probe. It splits the pure on-disk reads (readMeshState,
// testable against any base dir) from the side-effecting OS/network calls. label is the
// reported mesh name; for a StateRoot mesh it's the mesh id, for a `-dir`/auto-detected
// single-mesh deployment it's filepath.Base(baseDir) (the StateDir is shown too, so the
// exact label is secondary).
//
// viaDir selects how liveness + the core URL are learned:
//   - viaDir=false (multi-mesh StateRoot/`-mesh` entries): the per-mesh OS service is
//     queryable by label, so use pilotservice.Status; the core URL comes from service.env.
//   - viaDir=true (the `-dir` flag + the auto-detected /etc/nebula deployment): there is
//     no per-mesh OS service to query — instead introspect the running `pilot supervise`
//     process targeting baseDir for liveness/pid, and fall back to its `-core` flag for
//     the core URL (config.yml doesn't carry it), so the Harbor probe still runs.
func gatherMeshAt(ctx context.Context, label, baseDir string, viaDir bool) MeshInfo {
	mi := readMeshState(baseDir)
	mi.Mesh = label

	if viaDir {
		// `-dir` supervise deployment: the misleading multi-mesh pilotservice.Status
		// (which looks up pilot@<label>) doesn't match it, so derive liveness + core URL
		// from the running supervise process instead.
		proc := findSuperviseProc(baseDir)
		if proc.Running {
			mi.Service = fmt.Sprintf("active (supervise, pid %d)", proc.PID)
		} else {
			mi.Service = "not running (no supervise process for this dir)"
		}
		// config.yml doesn't carry the core URL (it's a supervise runtime flag) and a
		// `-dir` host has no service.env, so adopt the process's `-core` value when
		// readMeshState found none — this is what lets probeHarbor run below.
		if mi.CoreURL == "" && proc.Core != "" {
			mi.CoreURL = proc.Core
		}
	} else {
		// Multi-mesh: local service state (same source as `pilot status`). Best-effort —
		// show the lookup error rather than failing; the on-disk identity is the headline.
		if rep, err := pilotservice.Status(label); err != nil {
			mi.Service = err.Error()
		} else {
			mi.Service = rep
		}
	}

	// Best-effort Harbor reachability.
	if mi.CoreURL != "" {
		mi.Harbor = probeHarbor(ctx, mi.CoreURL)
	}
	return mi
}

// readMeshState reads a mesh's local identity/config from its state dir, mirroring
// cmdStatus's reads: cert -> overlay IP/common-name/groups/expiry(+fingerprint);
// ca.crt -> CA fingerprint; config.yml -> lighthouses; service.env -> core URL;
// bundle.json -> applied (verified) bundle version. Missing files are simply absent
// fields — this never fails, so a partially-enrolled mesh still reports.
func readMeshState(base string) MeshInfo {
	layout := paths.New(base)
	mi := MeshInfo{StateDir: base}

	// Cert: overlay IP, common name, groups, validity (+ fingerprint).
	if pem, err := os.ReadFile(layout.HostCert()); err == nil {
		if c, _, err := cert.UnmarshalCertificateFromPEM(pem); err == nil {
			if nets := c.Networks(); len(nets) > 0 {
				mi.OverlayIP = nets[0].Addr().String()
			}
			mi.CommonName = c.Name()
			mi.Groups = c.Groups()
			nb, na := c.NotBefore(), c.NotAfter()
			mi.NotBefore = nb.UTC().Format(time.RFC3339)
			mi.NotAfter = na.UTC().Format(time.RFC3339)
			now := time.Now()
			if now.After(na) {
				mi.Expired = true
				mi.TimeToExpiry = "expired " + humanDur(now.Sub(na)) + " ago"
			} else {
				mi.TimeToExpiry = "in " + humanDur(na.Sub(now))
			}
			if fp, err := c.Fingerprint(); err == nil {
				mi.CertFP = fp
			}
		} else {
			mi.Note = "host cert unparseable: " + err.Error()
		}
	}

	// CA bundle: fingerprint of the first (leaf-trust) CA cert.
	if pem, err := os.ReadFile(layout.CABundle()); err == nil {
		if c, _, err := cert.UnmarshalCertificateFromPEM(pem); err == nil {
			if fp, err := c.Fingerprint(); err == nil {
				mi.CAFP = fp
			}
		}
	}

	// Lighthouses: from config.yml's static_host_map keys (overlay IPs).
	mi.Lighthouses = readLighthouses(layout.Config())

	// Core/Harbor URL: from the per-mesh service.env (NCP_CORE_URL), where install
	// writes it. config.yml does not carry it (it's a service runtime arg).
	mi.CoreURL = readCoreURL(base)

	// Applied bundle version: from the verified bundle.json (pinned config-signing key).
	mi.BundleVer = readBundleVersion(base, layout.Bundle())
	return mi
}

// readLighthouses extracts the lighthouse overlay IPs from a rendered config.yml's
// static_host_map (overlay IP -> public addrs). "" / unparseable -> nil.
func readLighthouses(configPath string) []string {
	b, err := os.ReadFile(configPath)
	if err != nil {
		return nil
	}
	var cfg struct {
		StaticHostMap map[string][]string `yaml:"static_host_map"`
	}
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return nil
	}
	out := make([]string, 0, len(cfg.StaticHostMap))
	for ip := range cfg.StaticHostMap {
		out = append(out, ip)
	}
	sort.Strings(out)
	return out
}

// readCoreURL reads NCP_CORE_URL from a mesh's service.env (the per-mesh systemd
// EnvironmentFile / launchd env). "" if absent.
func readCoreURL(base string) string {
	b, err := os.ReadFile(filepath.Join(base, "service.env"))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if v, ok := strings.CutPrefix(line, "NCP_CORE_URL="); ok {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// readBundleVersion returns the applied config bundle version from the on-disk
// bundle.json, verified against the mesh's pinned config-signing key (the same pin
// `supervise` uses). 0 if there's no bundle/pin or it doesn't verify — info never
// trusts an unverified bundle's contents.
func readBundleVersion(base, bundlePath string) int {
	raw, err := os.ReadFile(bundlePath)
	if err != nil {
		return 0
	}
	pubPEM, err := os.ReadFile(filepath.Join(base, "config-signing.pub"))
	if err != nil {
		return 0
	}
	pinned, err := enrollclient.ParsePinnedConfigPub(pubPEM)
	if err != nil {
		return 0
	}
	b, err := bundle.Verify(raw, pinned)
	if err != nil {
		return 0
	}
	return b.BundleVersion
}

// probeHarbor does a short, best-effort GET of the core API's health endpoint
// (/healthz, then /readyz) and reports reachability + latency. It never fails the
// command — a down Harbor is itself useful diagnostic output.
func probeHarbor(ctx context.Context, coreURL string) *HarborProbe {
	p := &HarborProbe{URL: coreURL}
	client := &http.Client{Timeout: 2 * time.Second}
	base := strings.TrimRight(coreURL, "/")
	for _, ep := range []string{"/healthz", "/readyz"} {
		start := time.Now()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+ep, http.NoBody)
		if err != nil {
			p.Error = err.Error()
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			p.Error = err.Error()
			continue // try the next endpoint
		}
		resp.Body.Close()
		p.Endpoint = ep
		p.StatusCode = resp.StatusCode
		p.LatencyMS = time.Since(start).Milliseconds()
		p.Error = ""
		// 2xx is reachable+healthy; any HTTP answer at all proves reachability.
		p.Reachable = true
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return p
		}
	}
	return p
}

// gatherCloud probes AWS + Azure IMDS concurrently (short timeout, fail-graceful), so
// an off-cloud host (where BOTH probes hit the full timeout on the link-local address)
// waits ~one timeout, not two. base is "" in production (the link-local address); tests
// inject a fake server. client is nil in production (a short-timeout default). AWS wins
// when both somehow respond (Harbor only verifies AWS sigv4).
func gatherCloud(ctx context.Context, base string, client *http.Client) CloudSection {
	var (
		aws *AWSMeta
		az  *AzureMeta
		wg  sync.WaitGroup
	)
	wg.Add(2)
	go func() { defer wg.Done(); aws = detectAWS(ctx, base, client) }()
	go func() { defer wg.Done(); az = detectAzure(ctx, base, client) }()
	wg.Wait()

	switch {
	case aws != nil:
		return CloudSection{Provider: "aws", AWS: aws}
	case az != nil:
		return CloudSection{Provider: "azure", Azure: az}
	default:
		return CloudSection{Provider: "none"}
	}
}

// humanDur renders a duration as a coarse, human-friendly span (e.g. "12d 3h",
// "45m") for the time-until-expiry line.
func humanDur(d time.Duration) string {
	if d < 0 {
		d = -d
	}
	switch {
	case d >= 48*time.Hour:
		days := d / (24 * time.Hour)
		hrs := (d % (24 * time.Hour)) / time.Hour
		return fmt.Sprintf("%dd %dh", days, hrs)
	case d >= time.Hour:
		return fmt.Sprintf("%dh %dm", d/time.Hour, (d%time.Hour)/time.Minute)
	case d >= time.Minute:
		return fmt.Sprintf("%dm", d/time.Minute)
	default:
		return fmt.Sprintf("%ds", d/time.Second)
	}
}

// printInfo renders the human-readable report.
func printInfo(w *os.File, info nodeInfo) {
	p := func(format string, a ...any) { fmt.Fprintf(w, format, a...) }

	p("node\n")
	p("  hostname:   %s\n", info.Node.Hostname)
	p("  os/arch:    %s/%s\n", info.Node.OS, info.Node.Arch)
	p("  pilot:      %s\n", info.Node.PilotVersion)
	if info.Node.NebulaVersion != "" {
		p("  nebula:     %s\n", info.Node.NebulaVersion)
	} else {
		p("  nebula:     (not determinable)\n")
	}

	p("\nmesh membership\n")
	if len(info.Meshes) == 0 {
		p("  not joined to any mesh.\n")
	}
	for _, m := range info.Meshes {
		p("  mesh %q  (%s)\n", m.Mesh, m.StateDir)
		if m.OverlayIP == "" && m.CommonName == "" {
			p("    no identity on disk (not enrolled to this mesh)\n")
		}
		if m.OverlayIP != "" {
			p("    overlay ip:     %s\n", m.OverlayIP)
		}
		if m.CommonName != "" {
			p("    common name:    %s\n", m.CommonName)
		}
		if len(m.Groups) > 0 {
			p("    groups:         %s\n", strings.Join(m.Groups, ", "))
		}
		if m.NotAfter != "" {
			p("    cert valid:     %s -> %s\n", m.NotBefore, m.NotAfter)
			p("    expires:        %s\n", m.TimeToExpiry)
		}
		if m.CertFP != "" {
			p("    cert fp:        %s\n", m.CertFP)
		}
		if m.CAFP != "" {
			p("    ca fp:          %s\n", m.CAFP)
		}
		if len(m.Lighthouses) > 0 {
			p("    lighthouses:    %s\n", strings.Join(m.Lighthouses, ", "))
		}
		if m.CoreURL != "" {
			p("    harbor/core:    %s\n", m.CoreURL)
		}
		if m.BundleVer > 0 {
			p("    bundle version: %d\n", m.BundleVer)
		}
		if m.Service != "" {
			p("    service:        %s\n", m.Service)
		}
		if m.Harbor != nil {
			p("    harbor status:  %s\n", harborLine(m.Harbor))
		}
		if m.Note != "" {
			p("    note:           %s\n", m.Note)
		}
	}

	p("\ncloud attestation\n")
	printCloud(w, info.Cloud)
}

// harborLine renders a HarborProbe as one human line.
func harborLine(h *HarborProbe) string {
	if !h.Reachable {
		if h.Error != "" {
			return fmt.Sprintf("unreachable (%s)", h.Error)
		}
		return "unreachable"
	}
	return fmt.Sprintf("reachable — %s %d in %dms", h.Endpoint, h.StatusCode, h.LatencyMS)
}

// printCloud renders the cloud section (the onboarding headline).
func printCloud(w *os.File, c CloudSection) {
	p := func(format string, a ...any) { fmt.Fprintf(w, format, a...) }
	switch c.Provider {
	case "aws":
		a := c.AWS
		p("  provider:       AWS (EC2 IMDSv2)\n")
		p("  account id:     %s\n", a.AccountID)
		p("  region:         %s\n", a.Region)
		p("  instance id:    %s\n", a.InstanceID)
		if a.InstanceType != "" {
			p("  instance type:  %s\n", a.InstanceType)
		}
		if a.ImageID != "" {
			p("  image id:       %s\n", a.ImageID)
		}
		if len(a.Roles) > 0 {
			p("  iam role(s):    %s\n", strings.Join(a.Roles, ", "))
		} else {
			p("  iam role(s):    (none — sigv4 enrollment requires an instance role)\n")
		}
		if a.AssumedRoleARN != "" {
			p("  attests as:     %s\n", a.AssumedRoleARN)
		}
		if a.CloudtrustARNPattern != "" {
			p("\n  cloudtrust onboarding hint — add to this mesh's cloudtrust config:\n")
			p("    account:      %s\n", a.AccountID)
			p("    arn pattern:  %s\n", a.CloudtrustARNPattern)
		}
	case "azure":
		a := c.Azure
		p("  provider:       Azure (IMDS)\n")
		p("  subscription:   %s\n", a.SubscriptionID)
		p("  resource group: %s\n", a.ResourceGroup)
		p("  vm name:        %s\n", a.VMName)
		p("  vm id:          %s\n", a.VMID)
		p("  location:       %s\n", a.Location)
		p("  managed id:     %t\n", a.ManagedIdentity)
		p("  NOTE: Azure attestation is not yet supported by Harbor (AWS sigv4 only) — informational.\n")
	default:
		p("  no cloud instance metadata detected (not on AWS/Azure, or IMDS blocked).\n")
	}
}
