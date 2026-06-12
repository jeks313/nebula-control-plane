// Package reconcile decides how to apply a new desired nebula config over the
// running one (implementation-plan M1.8, the "reload vs restart" matrix). It
// classifies a config change and drives the supervisor's Reload/Restart
// primitives accordingly, including the Windows fallback (no SIGHUP → restart).
//
// The caller is responsible for rendering and atomically writing the new
// config.yml *before* calling Apply: Reload makes nebula re-read the file in
// place; Restart makes it re-read on the next start.
package reconcile

import (
	"errors"
	"reflect"

	"github.com/jeks313/nebula-control-plane/internal/nebulaconfig"
	"github.com/jeks313/nebula-control-plane/internal/supervisor"
)

// ChangeKind is the outcome of classifying old→new config.
type ChangeKind int

const (
	// NoChange means old and new are identical; nothing to do.
	NoChange ChangeKind = iota
	// ReloadOnly means the change hot-reloads via SIGHUP on Unix (firewall,
	// lighthouse/static host map, punchy, logging, and a same-IP/same-curve
	// PKI refresh). On Windows it degrades to a restart.
	ReloadOnly
	// RestartRequired means nebula cannot hot-reload the change and must be
	// cycled.
	RestartRequired
)

func (k ChangeKind) String() string {
	switch k {
	case NoChange:
		return "no-change"
	case ReloadOnly:
		return "reload"
	case RestartRequired:
		return "restart"
	default:
		return "unknown"
	}
}

// Classify determines what applying new over old requires, per the Nebula
// v1.10.x reload matrix. The restart triggers are the fields Nebula cannot
// hot-reload: the listen socket (host/port) and the tun device name. A cert
// overlay-IP or curve change also forces a restart, but those live in the issued
// certificate rather than in these rendered Values, and are handled at
// renewal/enrollment (M3/M4).
func Classify(oldV, newV nebulaconfig.Values) ChangeKind {
	if reflect.DeepEqual(oldV, newV) {
		return NoChange
	}
	if oldV.ListenHost != newV.ListenHost ||
		oldV.ListenPort != newV.ListenPort ||
		oldV.TunDev != newV.TunDev {
		return RestartRequired
	}
	return ReloadOnly
}

// Controller is the subset of the supervisor that reconcile drives.
// *supervisor.Supervisor satisfies it.
type Controller interface {
	Reload() error
	Restart() error
}

// Apply classifies the change and executes it. ReloadOnly attempts a hot reload
// and falls back to a restart where reload is unsupported (Windows).
// RestartRequired always restarts. NoChange does nothing. The returned
// ChangeKind reflects what was *decided* (e.g. ReloadOnly even if it fell back
// to restart on Windows), so callers can log intent vs. action.
func Apply(c Controller, oldV, newV nebulaconfig.Values) (ChangeKind, error) {
	kind := Classify(oldV, newV)
	switch kind {
	case NoChange:
		return kind, nil
	case ReloadOnly:
		err := c.Reload()
		if errors.Is(err, supervisor.ErrReloadUnsupported) {
			return kind, c.Restart() // Windows: no SIGHUP, restart instead
		}
		return kind, err
	default: // RestartRequired
		return kind, c.Restart()
	}
}
