// Package nebulaboot materializes a known-good nebula binary embedded in the pilot
// (ADR 0003 Phase 2) on first run, so a fresh host can bring up the data plane with
// NO pre-installed binary and NO network — offline first-boot. Harbor (Phase 1)
// distributes newer versions thereafter; this embedded copy is just the bootstrap
// default. It also doubles as the ultimate fallback for the Phase 1c local revert: a
// host can never be left with no runnable nebula.
//
// The embedded binary is gated behind the `embed_nebula` build tag: a release build
// fetches the matching nebula into assets/ (see `make embed-nebula`) and builds with
// `-tags embed_nebula`; the default build embeds nothing, so `go build ./...` needs no
// asset. It is platform-specific — the build embeds the nebula matching the pilot's
// GOOS/GOARCH.
package nebulaboot

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"

	"github.com/jeks313/nebula-control-plane/internal/binverify"
)

// MaterializeEmbedded writes the build-embedded nebula (if any) to path when no binary
// exists there yet (ADR 0003 Phase 2). It is the pilot entry point; see Materialize.
//
// On Windows it ALSO materializes the embedded Wintun driver (wintun.dll) into the exact
// subtree nebula probes at startup, so a self-contained pilot.exe brings up the overlay
// with no pre-installed driver. embeddedWintun() is nil on every non-Windows / non-embed
// build, making the Wintun step a clean no-op there. The returned bool reflects only the
// nebula write (the data-plane binary); a Wintun-write failure is surfaced as an error.
func MaterializeEmbedded(path string, logger *slog.Logger) (bool, error) {
	wrote, err := Materialize(path, embedded(), logger)
	if err != nil {
		return wrote, err
	}
	if _, werr := MaterializeWintun(path, embeddedWintun(), logger); werr != nil {
		return wrote, werr
	}
	return wrote, nil
}

// MaterializeWintun writes Wintun (data) where nebula actually loads it on Windows, when
// data is non-empty and no wintun.dll is there yet. nebula's TUN init (checkWinTunExists,
// slackhq/nebula overlay/tun_windows.go) does an EXPLICIT syscall.LoadDLL of
// <dir-of-nebula.exe>\dist\windows\wintun\bin\<arch>\wintun.dll and fails newTun() if it
// is absent — it does NOT fall back to the implicit DLL search order, so the driver MUST
// land in that exact subtree (not flat beside the exe). <arch> is runtime.GOARCH with
// nebula's 386->x86 remap (Wintun bundles the 32-bit driver under bin\x86). data is empty
// on every non-Windows / non-embed build, so this is a clean no-op there; the arch/path
// logic only runs on the Windows host (where runtime.GOARCH is the host arch). Split out
// (data passed in, not read from the embed) so the logic is testable without the real driver.
func MaterializeWintun(nebulaPath string, data []byte, logger *slog.Logger) (bool, error) {
	if len(data) == 0 {
		return false, nil
	}
	arch := runtime.GOARCH
	if arch == "386" { // Wintun bundles the 386 driver under bin\x86 (matches nebula's remap)
		arch = "x86"
	}
	// Materialize MkdirAll's filepath.Dir(path), so the nested dist\windows\wintun\bin\<arch>
	// dirs are created automatically.
	wintunPath := filepath.Join(filepath.Dir(nebulaPath), "dist", "windows", "wintun", "bin", arch, "wintun.dll")
	wrote, err := Materialize(wintunPath, data, logger)
	if err != nil {
		return wrote, fmt.Errorf("nebulaboot: materialize wintun: %w", err)
	}
	return wrote, nil
}

// Materialize writes data to path atomically (mode 0o755) when there is no binary at
// path yet, returning whether it wrote one. It is a NO-OP when a binary already exists
// (Phase 1 / the operator owns it from then on) or when data is empty (a default build
// that embedded nothing). data is split out from the embed source so the logic is
// testable without the real ~20 MB asset.
func Materialize(path string, data []byte, logger *slog.Logger) (bool, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if len(data) == 0 {
		return false, nil // this build embedded no nebula (default build): nothing to bootstrap
	}
	switch _, err := os.Stat(path); {
	case err == nil:
		return false, nil // a binary is already in place; do not clobber it
	case !errors.Is(err, fs.ErrNotExist):
		return false, fmt.Errorf("nebulaboot: stat %s: %w", path, err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return false, fmt.Errorf("nebulaboot: mkdir for %s: %w", path, err)
	}
	// Write off to the side, verify, then atomically rename in — so a crash mid-write
	// never leaves a truncated binary at path.
	tmp := path + ".embed"
	if err := os.WriteFile(tmp, data, 0o755); err != nil {
		return false, fmt.Errorf("nebulaboot: write %s: %w", tmp, err)
	}
	if err := os.Chmod(tmp, 0o755); err != nil { // WriteFile honors umask; force the exec bits
		_ = os.Remove(tmp)
		return false, fmt.Errorf("nebulaboot: chmod %s: %w", tmp, err)
	}
	sum := sha256.Sum256(data)
	if err := binverify.SHA256(tmp, hex.EncodeToString(sum[:])); err != nil {
		_ = os.Remove(tmp)
		return false, fmt.Errorf("nebulaboot: post-write verify: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return false, fmt.Errorf("nebulaboot: install %s: %w", path, err)
	}
	logger.Info("materialized embedded nebula (offline bootstrap)",
		"path", path, "sha", hex.EncodeToString(sum[:])[:12], "bytes", len(data))
	return true, nil
}
