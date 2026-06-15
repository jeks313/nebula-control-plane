//go:build darwin

package pilotservice

import (
	"strings"
	"testing"
)

func TestRenderPlist(t *testing.T) {
	s := Spec{Mesh: "prod", StateDir: "/usr/local/var/pilot/prod", CoreURL: "http://10.45.0.2:8444", NebulaPath: "/usr/local/bin/nebula"}
	p := renderPlist(s)
	for _, want := range []string{
		"<key>Label</key><string>com.nebula-control-plane.pilot.prod</string>",
		"<string>/usr/local/bin/pilot</string>",
		"<string>supervise</string>",
		"<string>/usr/local/var/pilot/prod/config.yml</string>",
		"<string>http://10.45.0.2:8444</string>",
		"<key>RunAtLoad</key><true/>",
		"<key>SuccessfulExit</key><false/>",
		"<key>AbandonProcessGroup</key><true/>", // nebula survives a pilot crash for re-adopt (ADR 0003 Phase 3)
		"<string>/usr/local/var/pilot/prod/pilot.log</string>",
	} {
		if !strings.Contains(p, want) {
			t.Errorf("renderPlist missing %q:\n%s", want, p)
		}
	}
}

func TestDarwinIdentity(t *testing.T) {
	if ServiceLabel("dev") != "com.nebula-control-plane.pilot.dev" {
		t.Errorf("ServiceLabel(dev) = %q", ServiceLabel("dev"))
	}
	if plistPath("dev") != "/Library/LaunchDaemons/com.nebula-control-plane.pilot.dev.plist" {
		t.Errorf("plistPath(dev) = %q", plistPath("dev"))
	}
	if !strings.Contains(LogHint("dev"), "/usr/local/var/pilot/dev/pilot.log") {
		t.Errorf("LogHint(dev) = %q", LogHint("dev"))
	}
}
