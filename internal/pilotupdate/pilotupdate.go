// Package pilotupdate self-updates the pilot binary without dropping the data plane
// (ADR 0003 Phase 3b). The mechanic — chosen because once nebula is running it holds
// its tunnels independently of pilot:
//
//  1. swap the pilot binary on disk (keeping <path>.last-good), atomically;
//  2. write the RUNNING nebula's PID to a pidfile + a pending-revert marker
//     (deadline = now + ConfirmWithin);
//  3. syscall.Exec the new pilot with -adopt-nebula-pid <pid> — exec keeps the same
//     PID and its children, so nebula survives, and the new pilot RE-ADOPTS it
//     (supervisor adopt-PID mode, 3a) instead of forking a fresh one. Zero drop.
//
// Safety — this is the highest-stakes operation (a bad pilot can brick a host only
// reachable over the mesh pilot maintains):
//   - CheckRevert, at every pilot startup, reverts the binary to last-good if a
//     pending marker is PAST its deadline — i.e. a prior new-pilot re-exec'd but never
//     Confirmed (it crashed/hung and the service manager restarted us). The service
//     manager is the recovery anchor for the "started but unhealthy" case; the
//     "binary won't exec at all" case needs the optional `pilot launch` watchdog.
//   - Confirm clears the marker once the new pilot is healthy, committing the update.
//
// The syscall.Exec seam (ReExec) is injectable so the swap / pidfile / marker / revert
// logic is unit-testable; the re-exec itself and the service-restart revert path are
// NOT unit-testable and must be live-validated on a real host.
package pilotupdate

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/binverify"
)

const adoptFlag = "-adopt-nebula-pid"

// defaultMaxBytes caps the pilot download (a static Go binary is ~20-40 MB).
const defaultMaxBytes = 256 << 20

// Config builds a Manager.
type Config struct {
	SelfPath      string                    // the pilot binary to swap (typically os.Executable())
	NebulaPidPath string                    // where to write the running nebula PID for re-adoption
	NebulaPID     func() int                // the running nebula PID (from the supervisor); 0 if none
	Args          []string                  // argv to re-exec with (typically os.Args)
	ReExec        func(argv []string) error // nil -> syscall.Exec (real re-exec)
	HTTPClient    *http.Client
	MaxBytes      int64
	ConfirmWithin time.Duration // window the new pilot has to Confirm before a restart reverts (0 -> 90s)
	Now           func() time.Time
	Logger        *slog.Logger
}

// Manager runs the pilot self-update mechanism.
type Manager struct{ cfg Config }

// New builds a Manager with defaults filled in.
func New(cfg Config) *Manager {
	if cfg.ReExec == nil {
		cfg.ReExec = realReExec
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 10 * time.Minute}
	}
	if cfg.MaxBytes <= 0 {
		cfg.MaxBytes = defaultMaxBytes
	}
	if cfg.ConfirmWithin <= 0 {
		cfg.ConfirmWithin = 90 * time.Second
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Manager{cfg: cfg}
}

// marker is the pending-revert record, written next to the pilot binary before a
// re-exec and cleared by Confirm.
type marker struct {
	Version  string `json:"version"`
	Deadline int64  `json:"deadline"` // unix ns; past it without a Confirm => the update failed
}

func (m *Manager) markerPath() string { return m.cfg.SelfPath + ".pending-update" }
func (m *Manager) lastGood() string   { return m.cfg.SelfPath + ".last-good" }

// Sync updates the pilot to the desired version when the on-disk pilot's sha differs,
// returning whether it began an update. On the happy path Apply does NOT return (the
// process is re-exec'd), so a nil error with began=true is only seen when ReExec is
// stubbed (tests). A no-op when desiredSHA is empty or already current.
func (m *Manager) Sync(desiredVersion, desiredSHA, url string) (began bool, err error) {
	desiredSHA = strings.ToLower(strings.TrimSpace(desiredSHA))
	if desiredSHA == "" {
		return false, nil
	}
	if binverify.SHA256(m.cfg.SelfPath, desiredSHA) == nil {
		return false, nil // already running the desired pilot
	}
	if url == "" {
		return false, fmt.Errorf("pilotupdate: desired pilot %s (sha %s) but no url to fetch it", desiredVersion, short(desiredSHA))
	}
	data, err := m.fetch(url, desiredSHA)
	if err != nil {
		return false, err
	}
	if err := m.Apply(data, desiredVersion); err != nil {
		return false, err
	}
	return true, nil
}

// Apply swaps the pilot binary to data, records nebula's PID + a pending-revert
// marker, and re-execs the new pilot to re-adopt nebula. On success it does NOT return
// (the process is replaced); it returns an error only if a pre-exec step fails, with
// the binary left unchanged.
func (m *Manager) Apply(data []byte, version string) error {
	// Re-read the running nebula PID HERE (not before the fetch): if nebula crashed or is
	// restarting right now, re-execing would fork a fresh nebula = a data-plane drop, so
	// DEFER — leave the binary untouched and let the loop retry once nebula is back. This
	// narrows the crash-during-fetch race to the few file ops below.
	pid := 0
	if m.cfg.NebulaPID != nil {
		pid = m.cfg.NebulaPID()
	}
	if pid <= 0 {
		m.cfg.Logger.Info("pilot self-update: deferring; no running nebula to re-adopt")
		return nil
	}
	// ARM the revert protection (pidfile + marker) BEFORE swapping the binary, so any
	// failure here leaves the current (good) binary in place — a swapped-but-unprotected
	// binary (no marker => no revert) can never exist.
	if m.cfg.NebulaPidPath != "" {
		if err := os.WriteFile(m.cfg.NebulaPidPath, []byte(strconv.Itoa(pid)), 0o600); err != nil {
			return fmt.Errorf("pilotupdate: write nebula pidfile: %w", err)
		}
	}
	mk := marker{Version: version, Deadline: m.cfg.Now().Add(m.cfg.ConfirmWithin).UnixNano()}
	if err := m.writeMarker(mk); err != nil {
		return err
	}
	if err := swap(m.cfg.SelfPath, m.lastGood(), data); err != nil {
		_ = m.clearMarker() // un-arm: nothing was swapped, so there is nothing to revert
		if m.cfg.NebulaPidPath != "" {
			_ = os.Remove(m.cfg.NebulaPidPath)
		}
		return err
	}
	argv := reexecArgv(m.cfg.Args, m.cfg.SelfPath, pid)
	m.cfg.Logger.Info("pilot self-update: re-exec into new binary, re-adopting nebula",
		"version", version, "nebula_pid", pid, "confirm_within", m.cfg.ConfirmWithin)
	return m.cfg.ReExec(argv) // does not return on success
}

// CheckRevert is called once at pilot startup, BEFORE supervising. If a pending marker
// is past its deadline (a prior new-pilot re-exec'd but never Confirmed — it crashed or
// hung and the service manager restarted us), it reverts the binary to last-good,
// clears the marker, and returns reverted=true. The caller should then exit non-zero so
// the service manager relaunches the now-good binary (which re-adopts nebula). A marker
// still within its deadline is left in place: THIS run is the update on trial.
func (m *Manager) CheckRevert() (reverted bool, err error) {
	mk, ok, rerr := m.readMarker()
	if rerr != nil {
		// A corrupt/unreadable marker can't tell us whether an update is on trial; acting
		// on garbage could false-revert a healthy pilot, so clear it and proceed.
		_ = m.clearMarker()
		return false, fmt.Errorf("pilotupdate: unreadable update marker (cleared): %w", rerr)
	}
	if !ok {
		return false, nil
	}
	if m.cfg.Now().UnixNano() < mk.Deadline {
		return false, nil // update still on trial; Confirm (or a later restart) decides
	}
	// Past the deadline without a Confirm: the update failed.
	if same, _ := sameContents(m.cfg.SelfPath, m.lastGood()); same {
		// Already reverted, but a prior clearMarker failed (transient fs error) so the
		// marker lingered. Do NOT loop (re-exit forever): clear best-effort and run the
		// already-good binary.
		_ = m.clearMarker()
		return false, nil
	}
	if err := restoreRetry(m.lastGood(), m.cfg.SelfPath); err != nil {
		// Nothing to revert to, or the revert keeps failing. The caller must NOT exit-loop
		// (that would just relaunch the same bad binary); it runs the current binary and
		// alerts loudly. The marker is left so a later restart on a healthy fs can still
		// revert.
		return false, fmt.Errorf("pilotupdate: pilot %s failed to confirm and revert failed: %w", mk.Version, err)
	}
	_ = m.clearMarker() // if this fails, the sameContents check above breaks the loop next time
	m.cfg.Logger.Warn("pilot self-update reverted: new pilot did not confirm in time; restored last-good", "version", mk.Version)
	return true, nil
}

// Confirm clears the pending marker once the new pilot is healthy, committing the
// update. version is the running pilot's own version: Confirm only clears a marker for
// THAT version, so a stale/mismatched instance can't clear a different update's revert
// protection. No-op when there is no marker or it is for another version. The clear is
// retried (a transient failure would otherwise let a later restart false-revert a
// healthy pilot).
func (m *Manager) Confirm(version string) error {
	mk, ok, err := m.readMarker()
	if err != nil || !ok {
		return err
	}
	if version != "" && mk.Version != version {
		return nil // not this pilot's marker — don't clear someone else's revert protection
	}
	if err := m.clearMarkerRetry(); err != nil {
		return fmt.Errorf("pilotupdate: confirm could not clear marker (a later restart may false-revert): %w", err)
	}
	m.cfg.Logger.Info("pilot self-update confirmed", "version", mk.Version)
	return nil
}

// Pending reports whether an unconfirmed update is on trial (a marker exists). The
// pilot uses this to know it should arm a Confirm once it comes up healthy.
func (m *Manager) Pending() bool {
	_, ok, _ := m.readMarker()
	return ok
}

func (m *Manager) writeMarker(mk marker) error {
	b, _ := json.Marshal(mk)
	if err := os.WriteFile(m.markerPath(), b, 0o600); err != nil {
		return fmt.Errorf("pilotupdate: write marker: %w", err)
	}
	return nil
}

func (m *Manager) readMarker() (marker, bool, error) {
	b, err := os.ReadFile(m.markerPath())
	if errors.Is(err, fs.ErrNotExist) {
		return marker{}, false, nil
	}
	if err != nil {
		return marker{}, false, fmt.Errorf("pilotupdate: read marker: %w", err)
	}
	var mk marker
	if err := json.Unmarshal(b, &mk); err != nil {
		return marker{}, false, fmt.Errorf("pilotupdate: parse marker: %w", err)
	}
	return mk, true, nil
}

func (m *Manager) clearMarker() error {
	if err := os.Remove(m.markerPath()); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// clearMarkerRetry removes the marker, retrying a few times to ride out a transient fs
// error — a marker that lingers can cause a later restart to false-revert a healthy pilot.
func (m *Manager) clearMarkerRetry() error {
	var err error
	for i := 0; i < 3; i++ {
		if err = m.clearMarker(); err == nil {
			return nil
		}
	}
	return err
}

func (m *Manager) fetch(url, wantSHA string) ([]byte, error) {
	resp, err := m.cfg.HTTPClient.Get(url) //nolint:noctx // bounded by HTTPClient.Timeout
	if err != nil {
		return nil, fmt.Errorf("pilotupdate: fetch %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("pilotupdate: fetch %s: status %d", url, resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, m.cfg.MaxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("pilotupdate: read body: %w", err)
	}
	if int64(len(data)) > m.cfg.MaxBytes {
		return nil, fmt.Errorf("pilotupdate: pilot artifact exceeds the %d-byte cap", m.cfg.MaxBytes)
	}
	sum := sha256.Sum256(data)
	if got := hex.EncodeToString(sum[:]); got != wantSHA {
		return nil, fmt.Errorf("pilotupdate: sha mismatch (got %s, want %s) — refusing", short(got), short(wantSHA))
	}
	return data, nil
}

// ReadAdoptPID reads the nebula PID written for re-adoption (0 if absent/garbage), and
// removes the pidfile so a later normal start doesn't try to adopt a stale PID.
func ReadAdoptPID(path string) int {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || pid <= 0 {
		return 0 // garbage: leave the file for inspection, don't adopt a bogus PID
	}
	_ = os.Remove(path) // valid PID: consume it so a later normal start doesn't re-adopt a stale PID
	return pid
}

func realReExec(argv []string) error {
	if len(argv) == 0 {
		return errors.New("pilotupdate: empty argv for re-exec")
	}
	return syscall.Exec(argv[0], argv, os.Environ())
}

// reexecArgv builds the argv for the new pilot: self as argv[0], the original args with
// any prior -adopt-nebula-pid stripped, and a fresh -adopt-nebula-pid <pid> appended
// (only when there is a nebula to adopt). Stripping avoids accumulating the flag across
// repeated self-updates.
func reexecArgv(origArgs []string, self string, pid int) []string {
	var rest []string
	if len(origArgs) > 1 {
		rest = stripAdoptFlag(origArgs[1:])
	}
	argv := append([]string{self}, rest...)
	if pid > 0 {
		argv = append(argv, adoptFlag, strconv.Itoa(pid))
	}
	return argv
}

// stripAdoptFlag removes -adopt-nebula-pid (in both `-flag value` and `-flag=value`
// forms, with one or two leading dashes) from an args slice.
func stripAdoptFlag(args []string) []string {
	out := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		a := args[i]
		base := strings.TrimLeft(a, "-")
		if base == "adopt-nebula-pid" { // separate value form: skip this and the next token
			i++
			continue
		}
		if strings.HasPrefix(base, "adopt-nebula-pid=") { // -flag=value form
			continue
		}
		out = append(out, a)
	}
	return out
}

func short(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}
