// Package drift is Pilot's config drift detection + revert (implementation-plan
// M6.7). The host's nebula config.yml (firewall + lighthouses) is owned by the
// last signed bundle. If anyone edits it locally, Pilot re-asserts the signed
// version on the next sync and logs the tamper — hosts can't drift away from
// central policy.
package drift

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/bundle"
	"github.com/jeks313/nebula-control-plane/internal/paths"
)

// Config builds a Monitor.
type Config struct {
	Layout          paths.Layout
	PinnedConfigPub *ecdsa.PublicKey
	Interval        time.Duration // sync cadence (0 -> 1m)
	Reload          func() error  // hot-reload nebula after a revert (optional)
	// Locker, if set, serializes the revert with the other host-state writers
	// (renew, apply_bundle) so a revert can't interleave a concurrent write.
	Locker sync.Locker
	Now    func() time.Time
	Logger *slog.Logger
}

// Monitor re-asserts the signed config on a cadence.
type Monitor struct{ cfg Config }

// New builds a Monitor.
func New(cfg Config) *Monitor {
	if cfg.Interval <= 0 {
		cfg.Interval = time.Minute
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Monitor{cfg: cfg}
}

// Run checks for drift on Interval until ctx is cancelled.
func (m *Monitor) Run(ctx context.Context) error {
	for {
		if _, err := m.Sync(ctx); err != nil {
			m.cfg.Logger.Warn("drift: sync failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(m.cfg.Interval):
		}
	}
}

// Sync compares the on-disk config to the signed bundle's rendering and reverts
// if they differ. Returns whether a revert happened.
func (m *Monitor) Sync(ctx context.Context) (reverted bool, err error) {
	if m.cfg.Locker != nil {
		m.cfg.Locker.Lock()
		defer m.cfg.Locker.Unlock()
	}
	raw, err := os.ReadFile(m.cfg.Layout.Bundle())
	if err != nil {
		// No bundle yet (not enrolled) — nothing to enforce.
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	// The authoritative config comes only from a bundle that verifies against the
	// pinned key — a tampered bundle file is itself ignored (and re-fetched on
	// the next renewal).
	b, err := bundle.Verify(raw, m.cfg.PinnedConfigPub)
	if err != nil {
		return false, fmt.Errorf("drift: stored bundle does not verify: %w", err)
	}
	want, err := bundle.RenderNebulaConfig(b, m.cfg.Layout.CABundle(), m.cfg.Layout.HostCert(), m.cfg.Layout.HostKey())
	if err != nil {
		return false, err
	}

	got, err := os.ReadFile(m.cfg.Layout.Config())
	if err != nil && !os.IsNotExist(err) {
		return false, err
	}
	if bytes.Equal(got, want) {
		return false, nil
	}

	// Drift: re-assert the signed config and reload.
	if err := os.WriteFile(m.cfg.Layout.Config(), want, 0o644); err != nil {
		return false, fmt.Errorf("drift: revert write: %w", err)
	}
	m.cfg.Logger.Warn("drift: local config edit detected; reverted to the signed version", "config", m.cfg.Layout.Config())
	if m.cfg.Reload != nil {
		if err := m.cfg.Reload(); err != nil {
			m.cfg.Logger.Warn("drift: reload after revert failed", "err", err)
		}
	}
	return true, nil
}
