// Package nebulaupdate keeps the nebula data-plane binary at the version Harbor
// distributes in the signed bundle (ADR 0003 Phase 1). It reads the desired
// nebula_version / nebula_sha256 / nebula_url from the host's CURRENT signed
// bundle and, when the on-disk binary's SHA-256 doesn't match the desired one,
// fetches the bytes, verifies them against the bundle's sha (the integrity anchor
// — so the URL/CDN need not be trusted), atomically installs the new binary
// (keeping the previous one as <path>.last-good for revert), and triggers a
// supervised restart (a binary swap is not hot-reloadable, per reconcile M1.8).
//
// On Windows the running .exe is locked, so a rename can't replace a live nebula;
// self-update there is deferred to ADR 0003 Phase 3 (Windows degrades to a service
// restart) — Run no-ops with a log there.
package nebulaupdate

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/binverify"
	"github.com/jeks313/nebula-control-plane/internal/bundle"
	"github.com/jeks313/nebula-control-plane/internal/paths"
)

// defaultMaxBytes caps the artifact download. nebula is ~10-20 MB; 128 MiB is a
// generous ceiling that still bounds a malicious/misconfigured URL.
const defaultMaxBytes = 128 << 20

// Config builds a Manager.
type Config struct {
	Layout          paths.Layout
	PinnedConfigPub *ecdsa.PublicKey // verifies the bundle the desired version comes from
	NebulaPath      string           // the binary the supervisor execs
	Restart         func() error     // supervised stop+start after a swap (optional)
	// Healthy, if set, is the pilot-local rollback gate (ADR 0003 Phase 1c): after a
	// swap + Restart it must report whether the NEW nebula actually came up and held.
	// restartedAt is the instant just before Restart was requested, so the gate can
	// ignore the old (still-shutting-down) process and judge only the new one. On
	// false the updater reverts to <path>.last-good and restarts — recovering a host
	// whose new binary kills its own connectivity, the failure Harbor's fleet-level
	// rollback can't reach (an isolated host is off the mesh). nil skips the gate
	// (Harbor-driven rollback only).
	Healthy    func(ctx context.Context, restartedAt time.Time) bool
	HTTPClient *http.Client  // nil -> a 5-minute-timeout client
	Interval   time.Duration // check cadence (0 -> 5m)
	MaxBytes   int64         // 0 -> defaultMaxBytes
	Logger     *slog.Logger
}

// Manager runs the nebula-version reconciliation loop.
type Manager struct {
	cfg Config

	mu sync.Mutex // serializes Sync; guards quarantine
	// quarantine holds the SHAs of artifacts that came down intact but failed to
	// come up (the health gate). Re-attempting them would crash-loop the host every
	// Interval, so a quarantined desired SHA is a no-op until the bundle pins a
	// different one (Harbor rolled the lane back, or shipped a fixed build).
	quarantine map[string]bool
}

// New builds a Manager with defaults filled in.
func New(cfg Config) *Manager {
	if cfg.Interval <= 0 {
		cfg.Interval = 5 * time.Minute
	}
	if cfg.MaxBytes <= 0 {
		cfg.MaxBytes = defaultMaxBytes
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 5 * time.Minute}
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Manager{cfg: cfg, quarantine: map[string]bool{}}
}

// Run reconciles the nebula version on Interval until ctx is cancelled.
func (m *Manager) Run(ctx context.Context) error {
	if runtime.GOOS == "windows" {
		m.cfg.Logger.Info("nebula self-update deferred on windows (ADR 0003 Phase 3)")
		<-ctx.Done()
		return nil
	}
	for {
		if _, err := m.Sync(ctx); err != nil {
			m.cfg.Logger.Warn("nebula update: sync failed; will retry", "err", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(m.cfg.Interval):
		}
	}
}

// Sync brings the on-disk nebula to the bundle's desired version, returning whether
// it installed a new binary. It is a no-op when the bundle pins no version, the
// on-disk binary already matches, or the bundle can't be read/verified.
func (m *Manager) Sync(ctx context.Context) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	want, ok := m.desired()
	if !ok || want.sha == "" {
		return false, nil // no desired version pinned -> leave the host's nebula alone
	}
	if binverify.SHA256(m.cfg.NebulaPath, want.sha) == nil {
		return false, nil // already at the desired sha
	}
	if m.quarantine[want.sha] {
		// This artifact already failed to come up; re-trying it would crash-loop the
		// host. Wait for the bundle to pin a different sha (Harbor rolled back / shipped
		// a fix) before touching nebula again.
		return false, nil
	}
	if want.url == "" {
		return false, fmt.Errorf("nebulaupdate: bundle pins nebula %s (sha %s) but gives no url to fetch it", want.version, shortSHA(want.sha))
	}
	data, err := m.fetch(ctx, want.url, want.sha)
	if err != nil {
		return false, err
	}
	if err := m.install(data); err != nil {
		return false, err
	}
	m.cfg.Logger.Info("nebula updated", "version", want.version, "sha", shortSHA(want.sha), "path", m.cfg.NebulaPath)
	// Capture the restart instant BEFORE requesting it, so the health gate counts
	// only the new child (started after this), not the old one still shutting down.
	restartedAt := time.Now()
	if m.cfg.Restart != nil {
		if err := m.cfg.Restart(); err != nil {
			m.cfg.Logger.Warn("nebula update: restart failed (new binary in place; the supervisor will pick it up)", "err", err)
		}
	}

	// Pilot-local rollback gate (ADR 0003 Phase 1c): if the new binary doesn't come
	// up, revert to last-good so a bad release never bricks an isolated host.
	if m.cfg.Healthy != nil && !m.cfg.Healthy(ctx, restartedAt) {
		// A cancelled ctx (shutdown) is NOT a binary failure — don't revert/quarantine a
		// possibly-healthy binary just because we're stopping. The next start re-runs the
		// gate with a fresh ctx.
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		if rerr := m.revertLastGood(); rerr != nil {
			// Nothing to fall back to (e.g. a failed FIRST install, no last-good) or the
			// revert itself failed. Deliberately do NOT quarantine: the on-disk binary still
			// matches the desired sha, so the next Sync short-circuits (no fetch/crash-loop)
			// and a future bundle change can retry. revertLastGood is crash-safe, so on a
			// revert error the prior binary is still in place at <path> — never missing.
			return false, fmt.Errorf("nebulaupdate: nebula %s did not come up and could not revert: %w", want.version, rerr)
		}
		// Reverted successfully -> quarantine the bad sha so the loop (on-disk now != the
		// desired sha) does not re-fetch and re-fail the same artifact every Interval.
		m.quarantine[want.sha] = true
		if m.cfg.Restart != nil {
			_ = m.cfg.Restart() // bring the known-good binary back up
		}
		m.cfg.Logger.Warn("nebula update reverted: new binary did not come up; restored last-good",
			"version", want.version, "sha", shortSHA(want.sha))
		return false, fmt.Errorf("nebulaupdate: nebula %s did not come up; reverted to last-good", want.version)
	}
	return true, nil
}

// revertLastGood restores the binary kept by install when a swapped-in nebula fails
// to come up. It is crash-safe and never leaves <path> missing: the failed binary is
// COPIED aside to <path>.failed (best-effort, for diagnosis), then last-good is
// copied in via copyFile's stage-then-atomic-rename. Nothing is moved OUT of <path>,
// so on any error the prior (failed) binary is still runnable there — a partial
// revert never bricks the host — and <path>.last-good is preserved for a future
// revert. Returns an error (and changes nothing destructive) when there is no
// last-good to revert to, e.g. a failed first install.
func (m *Manager) revertLastGood() error {
	path := m.cfg.NebulaPath
	lastGood := path + ".last-good"
	if _, err := os.Stat(lastGood); err != nil {
		return fmt.Errorf("no last-good binary to revert to: %w", err)
	}
	_ = copyFile(path, path+".failed")               // keep the bad binary for diagnosis (best-effort, non-destructive)
	if err := copyFile(lastGood, path); err != nil { // atomic; <path> keeps the bad binary on failure
		return fmt.Errorf("restore last-good: %w", err)
	}
	return nil
}

type desiredVer struct{ version, sha, url string }

// desired reads the host's current signed bundle and returns its pinned nebula
// version/sha/url. A missing or unverifiable bundle yields ok=false (skip + retry).
func (m *Manager) desired() (desiredVer, bool) {
	raw, err := os.ReadFile(m.cfg.Layout.Bundle())
	if err != nil {
		return desiredVer{}, false
	}
	b, err := bundle.Verify(raw, m.cfg.PinnedConfigPub)
	if err != nil {
		return desiredVer{}, false
	}
	return desiredVer{version: b.NebulaVersion, sha: b.NebulaSHA256, url: b.NebulaURL}, true
}

// fetch GETs the artifact (bounded) and returns its bytes only if their SHA-256
// matches wantSHA — the bundle-anchored integrity check that makes the source
// untrusted.
func (m *Manager) fetch(ctx context.Context, url, wantSHA string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("nebulaupdate: request: %w", err)
	}
	resp, err := m.cfg.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("nebulaupdate: fetch %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("nebulaupdate: fetch %s: status %d", url, resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, m.cfg.MaxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("nebulaupdate: read body: %w", err)
	}
	if int64(len(data)) > m.cfg.MaxBytes {
		return nil, fmt.Errorf("nebulaupdate: artifact exceeds the %d-byte cap", m.cfg.MaxBytes)
	}
	sum := sha256.Sum256(data)
	if got := hex.EncodeToString(sum[:]); got != wantSHA {
		return nil, fmt.Errorf("nebulaupdate: sha mismatch (got %s, want %s) — refusing", shortSHA(got), shortSHA(wantSHA))
	}
	return data, nil
}

// install atomically replaces the nebula binary, keeping the previous one as
// <path>.last-good. The write + re-verify happens off to the side (<path>.new), then
// a rename flips it in — atomic on the same filesystem; the running nebula keeps its
// old inode until the supervised restart execs the new file.
//
// Crash-safety: the prior binary is COPIED (not moved) to last-good, so <path> always
// holds a runnable binary even if the swap below fails or the process dies mid-install
// — never the "old binary moved out, new one not yet in" gap. On any error <path> is
// left untouched (the prior binary) and the temp file is cleaned up.
func (m *Manager) install(data []byte) error {
	path := m.cfg.NebulaPath
	tmp := path + ".new"
	if err := os.WriteFile(tmp, data, 0o755); err != nil {
		return fmt.Errorf("nebulaupdate: write %s: %w", tmp, err)
	}
	if err := os.Chmod(tmp, 0o755); err != nil { // WriteFile keeps stale perms if tmp pre-existed
		_ = os.Remove(tmp)
		return fmt.Errorf("nebulaupdate: chmod %s: %w", tmp, err)
	}
	// Defense in depth: re-verify the file we just wrote (catches a truncated write).
	sum := sha256.Sum256(data)
	if err := binverify.SHA256(tmp, hex.EncodeToString(sum[:])); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("nebulaupdate: post-write verify: %w", err)
	}
	if _, err := os.Stat(path); err == nil {
		if err := copyFile(path, path+".last-good"); err != nil {
			_ = os.Remove(tmp)
			return fmt.Errorf("nebulaupdate: keep last-good: %w", err)
		}
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp) // <path> still holds the prior binary; nothing was moved out
		return fmt.Errorf("nebulaupdate: install: %w", err)
	}
	return nil
}

// copyFile copies src to dst (mode 0o755) crash-safely: it stages to dst+".tmp" and
// atomically renames it into place, so dst is never a partial file. Used to preserve
// the running binary as last-good WITHOUT moving it, so <path> always holds a
// runnable binary across an install/revert.
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dst + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Chmod(tmp, 0o755); err != nil { // OpenFile honors umask; force the exec bits
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func shortSHA(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}
