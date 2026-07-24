// Package renew is Pilot's proactive certificate renewal (implementation-plan
// 4.4). It renews at ~⅔ of the cert's life, randomized with jitter so a fleet
// enrolled together spreads its renewals across a window instead of stampeding
// the Signer (tripping the circuit-breaker) or throttling KMS. On renewal it
// rotates the key and triggers a supervised SIGHUP hot-reload (same IP/curve =
// zero restart, per M1.8).
package renew

import (
	"context"
	"crypto/ecdsa"
	"log/slog"
	"math/rand"
	"os"
	"sync"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/enrollclient"
	"github.com/jeks313/nebula-control-plane/internal/paths"
	"github.com/slackhq/nebula/cert"
)

// Defaults.
const (
	DefaultFrac       = 2.0 / 3.0 // renew at ~⅔ of life
	DefaultJitterFrac = 0.15      // spread renewals across ±7.5% of life
	minFrac           = 0.05      // never schedule absurdly early/late
	maxFrac           = 0.95
)

// Schedule returns when to renew a cert with the given validity window. The
// target is `frac` of the lifetime, offset by a random amount within
// ±jitterFrac/2 of the lifetime — so N hosts with the same window pick N
// different times. rnd must be non-nil (per-host source).
func Schedule(notBefore, notAfter time.Time, frac, jitterFrac float64, rnd *rand.Rand) time.Time {
	life := notAfter.Sub(notBefore)
	at := frac + (rnd.Float64()-0.5)*jitterFrac
	if at < minFrac {
		at = minFrac
	}
	if at > maxFrac {
		at = maxFrac
	}
	return notBefore.Add(time.Duration(float64(life) * at))
}

// Config builds a Manager.
type Config struct {
	Layout          paths.Layout
	CoreURL         string
	PinnedConfigPub []*ecdsa.PublicKey

	// Reload triggers a hot-reload of nebula after a renewal (e.g. the
	// supervisor's Reload). Optional.
	Reload func() error
	// Renew performs the renewal; defaults to enrollclient.Renew over CoreURL.
	Renew func(ctx context.Context) (enrollclient.Result, error)
	// Locker, if set, serializes layout-mutating ops with the other host-state
	// writers (drift revert, apply_bundle) so concurrent goroutines never tear the
	// identity/config files. Optional (nil = no locking, e.g. in tests).
	Locker sync.Locker

	Frac       float64       // 0 -> DefaultFrac
	JitterFrac float64       // 0 -> DefaultJitterFrac
	RetryDelay time.Duration // wait after a failed renewal (0 -> 1m)
	ReArmDelay time.Duration // min wait between cycles (0 -> 1m), a hot-loop floor
	Now        func() time.Time
	Rand       *rand.Rand
	Logger     *slog.Logger
}

// Manager runs the renewal loop.
type Manager struct {
	cfg Config
	now func() time.Time
}

// New builds a Manager with defaults filled in.
func New(cfg Config) *Manager {
	if cfg.Frac == 0 {
		cfg.Frac = DefaultFrac
	}
	if cfg.JitterFrac == 0 {
		cfg.JitterFrac = DefaultJitterFrac
	}
	if cfg.RetryDelay <= 0 {
		cfg.RetryDelay = time.Minute
	}
	if cfg.ReArmDelay <= 0 {
		cfg.ReArmDelay = time.Minute
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Rand == nil {
		cfg.Rand = rand.New(rand.NewSource(time.Now().UnixNano()))
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Renew == nil {
		cfg.Renew = func(ctx context.Context) (enrollclient.Result, error) {
			return enrollclient.Renew(ctx, enrollclient.RenewParams{
				CoreURL: cfg.CoreURL, Layout: cfg.Layout, PinnedConfigPub: cfg.PinnedConfigPub,
			})
		}
	}
	return &Manager{cfg: cfg, now: cfg.Now}
}

// Run renews the host's cert on schedule until ctx is cancelled.
func (m *Manager) Run(ctx context.Context) error {
	for {
		if ctx.Err() != nil {
			return nil //nolint:nilerr // ctx cancelled is a clean shutdown, not an error
		}
		nb, na, err := m.certWindow()
		if err != nil {
			m.cfg.Logger.Warn("renew: cannot read certificate; retrying", "err", err)
			if !m.sleep(ctx, m.cfg.RetryDelay) {
				return nil
			}
			continue
		}

		at := Schedule(nb, na, m.cfg.Frac, m.cfg.JitterFrac, m.cfg.Rand)
		wait := at.Sub(m.now())
		if wait < 0 {
			wait = 0
		}
		m.cfg.Logger.Info("renew: next renewal scheduled", "at", at.UTC(), "in", wait.Round(time.Second), "not_after", na.UTC())
		if !m.sleep(ctx, wait) {
			return nil
		}

		if err := m.RenewNow(ctx); err != nil {
			m.cfg.Logger.Warn("renew: failed; will retry", "err", err)
			if !m.sleep(ctx, m.cfg.RetryDelay) {
				return nil
			}
			continue
		}
		// Floor between cycles so a stub/clock edge can't hot-loop.
		if !m.sleep(ctx, m.cfg.ReArmDelay) {
			return nil
		}
	}
}

// RenewNow performs a single renewal + hot-reload immediately (used by the
// scheduled loop and by a Core-issued `renew` command, 4.6).
func (m *Manager) RenewNow(ctx context.Context) error {
	if m.cfg.Locker != nil {
		m.cfg.Locker.Lock()
		defer m.cfg.Locker.Unlock()
	}
	res, err := m.cfg.Renew(ctx)
	if err != nil {
		return err
	}
	m.cfg.Logger.Info("renew: certificate renewed", "overlay_ip", res.OverlayIP)
	if m.cfg.Reload != nil {
		if err := m.cfg.Reload(); err != nil {
			m.cfg.Logger.Warn("renew: reload after renewal failed", "err", err)
		}
	}
	return nil
}

func (m *Manager) certWindow() (notBefore, notAfter time.Time, err error) {
	pem, err := os.ReadFile(m.cfg.Layout.HostCert())
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	c, _, err := cert.UnmarshalCertificateFromPEM(pem)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	return c.NotBefore(), c.NotAfter(), nil
}

func (m *Manager) sleep(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	select {
	case <-ctx.Done():
		return false
	case <-time.After(d):
		return true
	}
}
