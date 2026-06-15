//go:build linux

package pilotservice

import (
	"strings"
	"testing"
)

func TestRenderEnv(t *testing.T) {
	got := RenderEnv(Spec{Mesh: "prod", CoreURL: "http://10.45.0.2:8444", NebulaPath: "/usr/local/bin/nebula"})
	for _, want := range []string{"NCP_CORE_URL=http://10.45.0.2:8444", "NCP_NEBULA=/usr/local/bin/nebula"} {
		if !strings.Contains(got, want) {
			t.Errorf("RenderEnv missing %q:\n%s", want, got)
		}
	}
	// Empty nebula path falls back to the conventional absolute path.
	if !strings.Contains(RenderEnv(Spec{Mesh: "x"}), "NCP_NEBULA=/usr/local/bin/nebula") {
		t.Error("RenderEnv should default NCP_NEBULA to /usr/local/bin/nebula")
	}
}

func TestServiceIdentity(t *testing.T) {
	if ServiceLabel("dev") != "pilot@dev" {
		t.Errorf("ServiceLabel(dev) = %q, want pilot@dev", ServiceLabel("dev"))
	}
	if !strings.Contains(LogHint("dev"), "journalctl -u pilot@dev") {
		t.Errorf("LogHint(dev) = %q", LogHint("dev"))
	}
	if got := (Spec{StateDir: "/var/lib/pilot/dev"}).envFile(); got != "/var/lib/pilot/dev/service.env" {
		t.Errorf("envFile() = %q", got)
	}
}

func TestTemplateUnitShape(t *testing.T) {
	// Template-instance (%i), keep-alive hardening, hot-reload, and the supervise
	// handoff must all be present in the unit.
	if UnitTemplatePath != "/etc/systemd/system/pilot@.service" {
		t.Errorf("UnitTemplatePath = %q", UnitTemplatePath)
	}
	for _, want := range []string{
		"%i", // systemd instance templating
		"ExecStart=/usr/local/bin/pilot supervise",
		"-core ${NCP_CORE_URL}",
		"ExecReload=/bin/kill -HUP $MAINPID",
		"KillMode=process", // pilot owns nebula's lifecycle; survives a pilot crash for re-adopt (ADR 0003 Phase 3)
		"CapabilityBoundingSet=CAP_NET_ADMIN",
		"ProtectSystem=strict",
		"DeviceAllow=/dev/net/tun rw",
		"WantedBy=multi-user.target",
	} {
		if !strings.Contains(templateUnit, want) {
			t.Errorf("templateUnit missing %q", want)
		}
	}
}
