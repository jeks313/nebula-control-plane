// Package paths defines Pilot's on-disk layout and the per-platform protection
// of that directory (implementation-plan M1.3). All of a host's identity material
// — its key-agreement key, signed certificate, the CA trust bundle, and the
// rendered nebula config — lives under one base directory that only the Pilot
// service account (and SYSTEM/root) may read.
//
// POSIX is the floor implemented here (dir 0700, key file 0600). Windows DACL
// hardening and DPAPI-at-rest wrapping are tracked as M1.3 (Windows) / M1.3a and
// are stubbed in secure_windows.go until there is a Windows runner to test them.
package paths

import (
	"fmt"
	"path/filepath"
)

// Layout is the set of files Pilot manages, rooted at Base.
type Layout struct {
	Base string
}

// New returns a Layout rooted at base. If base is empty, DefaultBase() is used.
func New(base string) Layout {
	if base == "" {
		base = DefaultBase()
	}
	return Layout{Base: base}
}

// HostKey is the host's P256 key-agreement private key (owner-only). Secret.
func (l Layout) HostKey() string { return filepath.Join(l.Base, "host.key") }

// HostPub is the matching public key, sent to the control plane to be signed.
func (l Layout) HostPub() string { return filepath.Join(l.Base, "host.pub") }

// HostCert is the signed Nebula certificate issued by the control-plane CA.
func (l Layout) HostCert() string { return filepath.Join(l.Base, "host.crt") }

// CABundle is the trust bundle of CA certificate(s) — a bundle so a CA rotation
// (design §"CA rotation") can publish old+new together during the overlap.
func (l Layout) CABundle() string { return filepath.Join(l.Base, "ca.crt") }

// Config is the rendered nebula config.yml that the supervised nebula reads.
func (l Layout) Config() string { return filepath.Join(l.Base, "config.yml") }

// EnrollTicket holds an in-progress enrollment's retrieval ticket, so a host
// left PENDING (awaiting approval) can resume and fetch its bundle later.
func (l Layout) EnrollTicket() string { return filepath.Join(l.Base, "enroll-ticket.json") }

// Bundle is the last verified config bundle (JWS), retained so Pilot can detect
// config drift and re-assert the signed version (M6.7).
func (l Layout) Bundle() string { return filepath.Join(l.Base, "bundle.json") }

// Ensure creates the base directory with owner-only protection appropriate to
// the platform. It is idempotent.
func (l Layout) Ensure() error {
	if l.Base == "" {
		return fmt.Errorf("paths: empty base directory")
	}
	if err := secureMkdir(l.Base); err != nil {
		return fmt.Errorf("paths: prepare %s: %w", l.Base, err)
	}
	return nil
}
