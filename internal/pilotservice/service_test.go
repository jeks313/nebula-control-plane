package pilotservice

import "strings"

import "testing"

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

func TestSpecNames(t *testing.T) {
	s := Spec{Mesh: "dev", StateDir: "/var/lib/pilot/dev"}
	if s.Instance() != "pilot@dev" {
		t.Errorf("Instance() = %q, want pilot@dev", s.Instance())
	}
	if s.EnvFile() != "/var/lib/pilot/dev/service.env" {
		t.Errorf("EnvFile() = %q", s.EnvFile())
	}
}

func TestTemplateUnitShape(t *testing.T) {
	// Template-instance (%i), keep-alive hardening, hot-reload, and the supervise
	// handoff must all be present in the unit.
	for _, want := range []string{
		"pilot@.service", // (doc/intent) — checked via path const below
		"%i",             // systemd instance templating
		"ExecStart=/usr/local/bin/pilot supervise",
		"-core ${NCP_CORE_URL}",
		"ExecReload=/bin/kill -HUP $MAINPID",
		"CapabilityBoundingSet=CAP_NET_ADMIN",
		"ProtectSystem=strict",
		"DeviceAllow=/dev/net/tun rw",
		"WantedBy=multi-user.target",
	} {
		if want == "pilot@.service" {
			if UnitTemplatePath != "/etc/systemd/system/pilot@.service" {
				t.Errorf("UnitTemplatePath = %q", UnitTemplatePath)
			}
			continue
		}
		if !strings.Contains(templateUnit, want) {
			t.Errorf("templateUnit missing %q", want)
		}
	}
}
