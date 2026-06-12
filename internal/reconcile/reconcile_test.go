package reconcile

import (
	"testing"

	"github.com/jeks313/nebula-control-plane/internal/nebulaconfig"
	"github.com/jeks313/nebula-control-plane/internal/supervisor"
)

func base() nebulaconfig.Values {
	v := nebulaconfig.Values{
		CACertPath: "/x/ca.crt", CertPath: "/x/host.crt", KeyPath: "/x/host.key",
	}
	v.Defaults()
	return v
}

func TestClassify(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*nebulaconfig.Values)
		want   ChangeKind
	}{
		{"identical", func(*nebulaconfig.Values) {}, NoChange},
		{"firewall rule", func(v *nebulaconfig.Values) {
			v.Inbound = []nebulaconfig.Rule{{Port: "443", Proto: "tcp", Group: "web"}}
		}, ReloadOnly},
		{"lighthouse change", func(v *nebulaconfig.Values) {
			v.Lighthouses = []nebulaconfig.Lighthouse{{OverlayIP: "100.64.0.1", PublicAddrs: []string{"x:4242"}}}
		}, ReloadOnly},
		{"log level", func(v *nebulaconfig.Values) { v.LogLevel = "debug" }, ReloadOnly},
		{"listen port", func(v *nebulaconfig.Values) { v.ListenPort = 4243 }, RestartRequired},
		{"listen host", func(v *nebulaconfig.Values) { v.ListenHost = "10.0.0.5" }, RestartRequired},
		{"tun device", func(v *nebulaconfig.Values) { v.TunDev = "nebula2" }, RestartRequired},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			oldV := base()
			newV := base()
			tc.mutate(&newV)
			if got := Classify(oldV, newV); got != tc.want {
				t.Fatalf("Classify(%s) = %v, want %v", tc.name, got, tc.want)
			}
		})
	}
}

// fakeController records what Apply asked it to do, and can simulate a platform
// where reload is unsupported (Windows).
type fakeController struct {
	reloads, restarts int
	reloadErr         error
}

func (f *fakeController) Reload() error  { f.reloads++; return f.reloadErr }
func (f *fakeController) Restart() error { f.restarts++; return nil }

func TestApplyReloadOnly(t *testing.T) {
	oldV := base()
	newV := base()
	newV.LogLevel = "debug"

	c := &fakeController{}
	kind, err := Apply(c, oldV, newV)
	if err != nil {
		t.Fatal(err)
	}
	if kind != ReloadOnly {
		t.Fatalf("kind = %v, want ReloadOnly", kind)
	}
	if c.reloads != 1 || c.restarts != 0 {
		t.Fatalf("reloads=%d restarts=%d, want 1/0", c.reloads, c.restarts)
	}
}

func TestApplyReloadFallsBackToRestartOnWindows(t *testing.T) {
	oldV := base()
	newV := base()
	newV.LogLevel = "debug"

	// Simulate Windows: Reload reports unsupported -> Apply must restart.
	c := &fakeController{reloadErr: supervisor.ErrReloadUnsupported}
	kind, err := Apply(c, oldV, newV)
	if err != nil {
		t.Fatal(err)
	}
	if kind != ReloadOnly {
		t.Fatalf("kind = %v, want ReloadOnly (decision), got action via restart", kind)
	}
	if c.reloads != 1 || c.restarts != 1 {
		t.Fatalf("reloads=%d restarts=%d, want 1/1 (attempt then fallback)", c.reloads, c.restarts)
	}
}

func TestApplyRestartRequired(t *testing.T) {
	oldV := base()
	newV := base()
	newV.ListenPort = 4243

	c := &fakeController{}
	kind, err := Apply(c, oldV, newV)
	if err != nil {
		t.Fatal(err)
	}
	if kind != RestartRequired {
		t.Fatalf("kind = %v, want RestartRequired", kind)
	}
	if c.reloads != 0 || c.restarts != 1 {
		t.Fatalf("reloads=%d restarts=%d, want 0/1", c.reloads, c.restarts)
	}
}

func TestApplyNoChange(t *testing.T) {
	v := base()
	c := &fakeController{}
	kind, err := Apply(c, v, v)
	if err != nil {
		t.Fatal(err)
	}
	if kind != NoChange || c.reloads != 0 || c.restarts != 0 {
		t.Fatalf("kind=%v reloads=%d restarts=%d, want no-change/0/0", kind, c.reloads, c.restarts)
	}
}
