// Package pilotsetup is the reusable host-setup step shared by `pilot init` and
// `pilot install`: lay out the per-mesh dir, generate the host key once (never
// clobbering a live one), and render config.yml. It returns errors instead of
// exiting, so both the standalone `init` CLI and the `install` orchestrator can
// call it. PKI material (cert + CA bundle) is provisioned separately by enroll.
package pilotsetup

import (
	"errors"
	"fmt"
	"os"

	"github.com/jeks313/nebula-control-plane/internal/hostkey"
	"github.com/jeks313/nebula-control-plane/internal/nebulaconfig"
	"github.com/jeks313/nebula-control-plane/internal/paths"
	"gopkg.in/yaml.v3"
)

// InitParams configures a host-setup run.
type InitParams struct {
	Layout       paths.Layout // where identity material + config live (per-mesh base)
	ValuesPath   string       // optional YAML config-policy values
	AmLighthouse bool         // render as a lighthouse
	TunDev       string       // per-mesh TUN device name; "" → renderer default (nebula1)
	ListenPort   int          // per-mesh nebula UDP port; 0 → renderer default (4242)
}

// InitResult reports what setup did.
type InitResult struct {
	KeyGenerated bool // true if a new host key was created (false if one already existed)
}

// Init prepares the host directory: ensures the (owner-only) base dir, generates
// the P256 host key iff one does not already exist, and renders config.yml. It is
// idempotent — re-running never overwrites a live host key, which is what makes
// `pilot install` safe to re-run.
func Init(p InitParams) (InitResult, error) {
	var res InitResult
	if err := p.Layout.Ensure(); err != nil {
		return res, err
	}

	// Host key: generate once; never clobber a live key (the idempotency anchor).
	if _, err := os.Stat(p.Layout.HostKey()); errors.Is(err, os.ErrNotExist) {
		kp, err := hostkey.Generate()
		if err != nil {
			return res, err
		}
		if err := kp.WritePrivateKey(p.Layout.HostKey()); err != nil {
			return res, err
		}
		if err := kp.WritePublicKey(p.Layout.HostPub()); err != nil {
			return res, err
		}
		res.KeyGenerated = true
	} else if err != nil {
		return res, fmt.Errorf("stat host key: %w", err)
	}

	// Config: policy from the optional values file; PKI paths from the layout;
	// per-mesh TUN/port overrides (multi-mesh) applied before Defaults() fills the rest.
	var v nebulaconfig.Values
	if p.ValuesPath != "" {
		raw, err := os.ReadFile(p.ValuesPath)
		if err != nil {
			return res, fmt.Errorf("read values: %w", err)
		}
		if err := yaml.Unmarshal(raw, &v); err != nil {
			return res, fmt.Errorf("parse values: %w", err)
		}
	}
	if p.AmLighthouse {
		v.AmLighthouse = true
	}
	if p.TunDev != "" {
		v.TunDev = p.TunDev
	}
	if p.ListenPort != 0 {
		v.ListenPort = p.ListenPort
	}
	v.CACertPath = p.Layout.CABundle()
	v.CertPath = p.Layout.HostCert()
	v.KeyPath = p.Layout.HostKey()
	v.Defaults()

	cfg, err := nebulaconfig.Render(v)
	if err != nil {
		return res, err
	}
	if err := os.WriteFile(p.Layout.Config(), cfg, 0644); err != nil {
		return res, fmt.Errorf("write config: %w", err)
	}
	return res, nil
}
