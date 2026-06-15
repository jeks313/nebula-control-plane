package pilotupdate_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/pilotupdate"
)

func sha256hex(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

// harness wires a Manager over temp files with a stubbed re-exec (captures argv) and a
// fixed clock, so the swap / pidfile / marker / revert logic is exercised without an
// actual process replacement.
type harness struct {
	m       *pilotupdate.Manager
	self    string
	pidPath string
	argv    []string // captured re-exec argv
	now     time.Time
}

func newHarness(t *testing.T, selfBytes []byte) *harness {
	t.Helper()
	dir := t.TempDir()
	self := filepath.Join(dir, "pilot")
	if err := os.WriteFile(self, selfBytes, 0o755); err != nil {
		t.Fatal(err)
	}
	h := &harness{self: self, pidPath: filepath.Join(dir, "nebula.pid"), now: time.Unix(1_700_000_000, 0)}
	h.m = pilotupdate.New(pilotupdate.Config{
		SelfPath: self, NebulaPidPath: h.pidPath,
		NebulaPID: func() int { return 4242 },
		Args:      []string{self, "supervise", "-config", "x"},
		ReExec:    func(argv []string) error { h.argv = argv; return nil },
		Now:       func() time.Time { return h.now },
	})
	return h
}

func TestApplySwapsRecordsAndReExecs(t *testing.T) {
	old := bytes.Repeat([]byte("OLD"), 1000)
	h := newHarness(t, old)
	newBin := bytes.Repeat([]byte("NEW"), 1000)

	if err := h.m.Apply(newBin, "2.0.0"); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if got, _ := os.ReadFile(h.self); !bytes.Equal(got, newBin) {
		t.Fatal("pilot binary should be the new one after Apply")
	}
	if got, _ := os.ReadFile(h.self + ".last-good"); !bytes.Equal(got, old) {
		t.Fatal("the previous pilot must be kept as last-good")
	}
	if got, _ := os.ReadFile(h.pidPath); string(got) != "4242" {
		t.Fatalf("nebula pidfile = %q, want 4242", got)
	}
	// Re-exec argv: self + original args (adopt flag not duplicated) + the adopt flag.
	want := []string{h.self, "supervise", "-config", "x", "-adopt-nebula-pid", "4242"}
	if len(h.argv) != len(want) {
		t.Fatalf("re-exec argv = %v, want %v", h.argv, want)
	}
	for i := range want {
		if h.argv[i] != want[i] {
			t.Fatalf("re-exec argv = %v, want %v", h.argv, want)
		}
	}
	if !h.m.Pending() {
		t.Fatal("a marker must be pending after Apply (until Confirm)")
	}
}

func TestCheckRevertPastDeadlineRestoresLastGood(t *testing.T) {
	good := bytes.Repeat([]byte("GOOD"), 1000)
	h := newHarness(t, good) // self starts as the good binary
	bad := bytes.Repeat([]byte("BAD"), 1000)
	// Apply swaps in `bad` and keeps `good` as last-good + writes the marker.
	if err := h.m.Apply(bad, "2.0.0"); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(h.self); !bytes.Equal(got, bad) {
		t.Fatal("precondition: self should be the bad binary after Apply")
	}
	h.now = h.now.Add(2 * time.Minute) // advance past the confirm deadline (new pilot never Confirmed)

	reverted, err := h.m.CheckRevert()
	if err != nil || !reverted {
		t.Fatalf("past-deadline CheckRevert: reverted=%v err=%v", reverted, err)
	}
	if got, _ := os.ReadFile(h.self); !bytes.Equal(got, good) {
		t.Fatal("CheckRevert must restore the last-good (good) binary")
	}
	if h.m.Pending() {
		t.Fatal("the marker must be cleared after a revert")
	}
}

func TestCheckRevertWithinDeadlineKeeps(t *testing.T) {
	h := newHarness(t, []byte("OLD"))
	if err := h.m.Apply([]byte("NEW"), "2.0.0"); err != nil { // self=NEW, last-good=OLD, marker set
		t.Fatal(err)
	}
	// Still within the confirm window: the update is on trial, do not revert.
	reverted, err := h.m.CheckRevert()
	if err != nil || reverted {
		t.Fatalf("within-deadline CheckRevert must not revert: reverted=%v err=%v", reverted, err)
	}
	if got, _ := os.ReadFile(h.self); string(got) != "NEW" {
		t.Fatal("within-deadline must leave the new binary in place")
	}
	if !h.m.Pending() {
		t.Fatal("the marker must remain while on trial")
	}
}

func TestConfirmClearsMarker(t *testing.T) {
	h := newHarness(t, []byte("OLD"))
	if err := h.m.Apply([]byte("NEW"), "2.0.0"); err != nil {
		t.Fatal(err)
	}
	// A mismatched version must NOT clear another update's revert protection.
	if err := h.m.Confirm("9.9.9"); err != nil {
		t.Fatal(err)
	}
	if !h.m.Pending() {
		t.Fatal("Confirm with the wrong version must leave the marker")
	}
	if err := h.m.Confirm("2.0.0"); err != nil {
		t.Fatal(err)
	}
	if h.m.Pending() {
		t.Fatal("Confirm must clear the matching pending marker")
	}
	// After Confirm, even past the deadline there is nothing to revert.
	h.now = h.now.Add(2 * time.Minute)
	if reverted, _ := h.m.CheckRevert(); reverted {
		t.Fatal("a confirmed update must not revert later")
	}
}

// TestApplyDefersWhenNoNebula: with no running nebula to re-adopt, Apply must leave the
// binary untouched + not re-exec (re-execing would fork a fresh nebula = a drop).
func TestApplyDefersWhenNoNebula(t *testing.T) {
	dir := t.TempDir()
	self := filepath.Join(dir, "pilot")
	old := []byte("OLD")
	if err := os.WriteFile(self, old, 0o755); err != nil {
		t.Fatal(err)
	}
	var reexeced bool
	m := pilotupdate.New(pilotupdate.Config{
		SelfPath: self, NebulaPidPath: filepath.Join(dir, "nebula.pid"),
		NebulaPID: func() int { return 0 }, // nebula is down
		Args:      []string{self},
		ReExec:    func([]string) error { reexeced = true; return nil },
	})
	if err := m.Apply([]byte("NEW"), "2.0.0"); err != nil {
		t.Fatalf("defer should be a clean no-op, got %v", err)
	}
	if reexeced {
		t.Fatal("must not re-exec when there is no nebula to re-adopt")
	}
	if got, _ := os.ReadFile(self); string(got) != "OLD" {
		t.Fatal("must not swap the binary when deferring")
	}
	if m.Pending() {
		t.Fatal("a deferred update must not arm a revert marker")
	}
}

// TestReadAdoptPIDGarbageLeavesFile: a corrupt pidfile yields 0 AND is left in place
// (don't silently destroy it; it aids recovery + a re-read).
func TestReadAdoptPIDGarbageLeavesFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "nebula.pid")
	if err := os.WriteFile(p, []byte("not-a-pid"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := pilotupdate.ReadAdoptPID(p); got != 0 {
		t.Fatalf("garbage pidfile must yield 0, got %d", got)
	}
	if _, err := os.Stat(p); err != nil {
		t.Fatal("a garbage pidfile must be left in place, not deleted")
	}
}

// TestCheckRevertAlreadyRevertedNoLoop: a lingering past-deadline marker when the
// binary already equals last-good (a prior revert that couldn't clear the marker) must
// NOT loop — it clears + proceeds rather than re-reverting/exiting forever.
func TestCheckRevertAlreadyRevertedNoLoop(t *testing.T) {
	good := bytes.Repeat([]byte("GOOD"), 1000)
	h := newHarness(t, good)
	// self == last-good (already reverted), but a stale past-deadline marker remains.
	if err := os.WriteFile(h.self+".last-good", good, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := h.m.Apply(good, "2.0.0"); err != nil { // self stays `good`; marker armed
		t.Fatal(err)
	}
	h.now = h.now.Add(2 * time.Minute) // past the deadline

	reverted, err := h.m.CheckRevert()
	if err != nil || reverted {
		t.Fatalf("already-reverted must not loop: reverted=%v err=%v", reverted, err)
	}
	if h.m.Pending() {
		t.Fatal("the lingering marker must be cleared")
	}
}

// TestCheckRevertCorruptMarker: an unreadable marker is cleared + does not trigger a
// (false) revert of a healthy binary.
func TestCheckRevertCorruptMarker(t *testing.T) {
	h := newHarness(t, []byte("HEALTHY"))
	if err := os.WriteFile(h.self+".pending-update", []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	reverted, err := h.m.CheckRevert()
	if err == nil {
		t.Fatal("a corrupt marker should surface an error")
	}
	if reverted {
		t.Fatal("a corrupt marker must not trigger a revert")
	}
	if h.m.Pending() {
		t.Fatal("a corrupt marker must be cleared")
	}
	if got, _ := os.ReadFile(h.self); string(got) != "HEALTHY" {
		t.Fatal("the healthy binary must be untouched")
	}
}

func TestReadAdoptPID(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "nebula.pid")
	if err := os.WriteFile(p, []byte("  321\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := pilotupdate.ReadAdoptPID(p); got != 321 {
		t.Fatalf("ReadAdoptPID = %d, want 321", got)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatal("ReadAdoptPID must remove the pidfile so a stale PID isn't re-adopted")
	}
	if got := pilotupdate.ReadAdoptPID(filepath.Join(dir, "absent")); got != 0 {
		t.Fatalf("absent pidfile must yield 0, got %d", got)
	}
}

func TestSyncFetchesVerifiesApplies(t *testing.T) {
	newBin := bytes.Repeat([]byte("v2"), 2048)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(newBin) }))
	defer srv.Close()

	h := newHarness(t, []byte("v1"))
	// re-point the manager's HTTP client at the test server (New defaulted one).
	h.m = pilotupdate.New(pilotupdate.Config{
		SelfPath: h.self, NebulaPidPath: h.pidPath, NebulaPID: func() int { return 7 },
		Args: []string{h.self}, ReExec: func(argv []string) error { h.argv = argv; return nil },
		Now: func() time.Time { return h.now }, HTTPClient: srv.Client(),
	})

	began, err := h.m.Sync("2.0.0", sha256hex(newBin), srv.URL+"/pilot")
	if err != nil || !began {
		t.Fatalf("Sync should begin an update: began=%v err=%v", began, err)
	}
	if got, _ := os.ReadFile(h.self); !bytes.Equal(got, newBin) {
		t.Fatal("Sync must install the fetched pilot")
	}

	// Idempotent: the on-disk sha now matches -> no-op.
	began2, err := h.m.Sync("2.0.0", sha256hex(newBin), srv.URL+"/pilot")
	if err != nil || began2 {
		t.Fatalf("Sync must no-op when already current: began=%v err=%v", began2, err)
	}
}

func TestSyncShaMismatchRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("WRONG")) }))
	defer srv.Close()
	h := newHarness(t, []byte("v1"))
	h.m = pilotupdate.New(pilotupdate.Config{
		SelfPath: h.self, NebulaPidPath: h.pidPath, Args: []string{h.self},
		ReExec: func(argv []string) error { h.argv = argv; return nil },
		Now:    func() time.Time { return h.now }, HTTPClient: srv.Client(),
	})
	began, err := h.m.Sync("2.0.0", sha256hex([]byte("expected-not-WRONG")), srv.URL+"/pilot")
	if err == nil || began {
		t.Fatalf("sha mismatch must refuse: began=%v err=%v", began, err)
	}
	if h.argv != nil {
		t.Fatal("must not re-exec on a sha mismatch")
	}
}
