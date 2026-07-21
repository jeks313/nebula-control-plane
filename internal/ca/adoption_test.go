package ca

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/store"
)

// fpOf returns a deterministic 64-hex fingerprint for a label — a stand-in CA fingerprint
// for adoption tests (AdoptionStatus string-matches, so no real cert is needed).
func fpOf(label string) string {
	h := sha256.Sum256([]byte(label))
	return hex.EncodeToString(h[:])
}

// seedHB inserts a heartbeats row (overlay_ip/device_name/last_seen are the only NOT-NULL
// columns without a default; trusted_cas is the M8.1 JSON array under test).
func seedHB(t *testing.T, s *store.Store, ip string, lastSeen int64, trustedCAs string) {
	t.Helper()
	if err := s.DB.Exec(`INSERT INTO heartbeats (overlay_ip, device_name, last_seen, trusted_cas) VALUES (?,?,?,?)`,
		ip, "dev-"+ip, lastSeen, trustedCAs).Error; err != nil {
		t.Fatalf("seed heartbeat %s: %v", ip, err)
	}
}

func fixedNow(r *Registry) (now time.Time) {
	now = time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	r.now = func() time.Time { return now }
	return now
}

// TestAdoptionZeroToFull: as live hosts report trusting a staged CA, adoption climbs from
// 0% to 100% and FullyAdopted flips only when every live host confirms.
func TestAdoptionZeroToFull(t *testing.T) {
	s, r := setup(t)
	ctx := context.Background()
	now := fixedNow(r)
	fp2 := fpOf("ca-2")
	ca1 := `["` + fpOf("ca-1") + `"]`
	for _, ip := range []string{"100.64.0.10", "100.64.0.11", "100.64.0.12"} {
		seedHB(t, s, ip, now.UnixNano(), ca1) // trust only CA1
	}
	ad, err := r.AdoptionStatus(ctx, fp2, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if ad.Live != 3 || ad.Adopted != 0 || len(ad.Laggards) != 3 || ad.FullyAdopted() {
		t.Fatalf("initial: %+v", ad)
	}

	// One host now trusts CA2 too.
	if err := s.DB.Exec(`UPDATE heartbeats SET trusted_cas=? WHERE overlay_ip=?`,
		`["`+fpOf("ca-1")+`","`+fp2+`"]`, "100.64.0.10").Error; err != nil {
		t.Fatal(err)
	}
	if ad, _ = r.AdoptionStatus(ctx, fp2, 5*time.Minute); ad.Adopted != 1 || len(ad.Laggards) != 2 || ad.FullyAdopted() {
		t.Fatalf("1/3: %+v", ad)
	}

	// All hosts trust CA2.
	if err := s.DB.Exec(`UPDATE heartbeats SET trusted_cas=?`, `["`+fp2+`"]`).Error; err != nil {
		t.Fatal(err)
	}
	if ad, _ = r.AdoptionStatus(ctx, fp2, 5*time.Minute); ad.Adopted != 3 || len(ad.Laggards) != 0 || !ad.FullyAdopted() {
		t.Fatalf("3/3: %+v", ad)
	}
}

// TestAdoptionExcludesStale: hosts beyond the freshness window are excluded from the gate
// population (returned in .Stale), so a long-silent host cannot block a cut-over.
func TestAdoptionExcludesStale(t *testing.T) {
	s, r := setup(t)
	ctx := context.Background()
	now := fixedNow(r)
	fp2 := fpOf("ca-2")
	seedHB(t, s, "live-1", now.UnixNano(), `["`+fp2+`"]`)
	seedHB(t, s, "live-2", now.Add(-time.Minute).UnixNano(), `["`+fp2+`"]`)
	seedHB(t, s, "stale-1", now.Add(-10*time.Minute).UnixNano(), `[]`) // stale + does not trust fp2
	ad, err := r.AdoptionStatus(ctx, fp2, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if ad.Live != 2 || ad.Adopted != 2 || len(ad.Laggards) != 0 || !ad.FullyAdopted() {
		t.Fatalf("live counts: %+v", ad)
	}
	if len(ad.Stale) != 1 || ad.Stale[0] != "stale-1" {
		t.Fatalf("stale = %v, want [stale-1]", ad.Stale)
	}
}

// TestAdoptionUnreportedIsLaggard: a live host reporting empty/null/malformed trusted_cas is
// a laggard (fail-closed) — and AdoptionStatus never errors on bad JSON.
func TestAdoptionUnreportedIsLaggard(t *testing.T) {
	s, r := setup(t)
	ctx := context.Background()
	now := fixedNow(r)
	seedHB(t, s, "h-empty", now.UnixNano(), "")
	seedHB(t, s, "h-null", now.UnixNano(), "null")
	seedHB(t, s, "h-bad", now.UnixNano(), "{not json")
	ad, err := r.AdoptionStatus(ctx, fpOf("ca-2"), 5*time.Minute)
	if err != nil {
		t.Fatalf("must tolerate malformed trusted_cas: %v", err)
	}
	if ad.Live != 3 || ad.Adopted != 0 || len(ad.Laggards) != 3 {
		t.Fatalf("all should be laggards: %+v", ad)
	}
}

// TestAdoptionEmptyFleet: no live hosts -> vacuously fully adopted (bootstrap must not be
// chicken-and-egg blocked).
func TestAdoptionEmptyFleet(t *testing.T) {
	_, r := setup(t)
	fixedNow(r)
	ad, err := r.AdoptionStatus(context.Background(), fpOf("ca-2"), 5*time.Minute)
	if err != nil || ad.Live != 0 || !ad.FullyAdopted() {
		t.Fatalf("empty fleet: %+v err=%v", ad, err)
	}
}

// TestAdoptionFingerprintCaseInsensitive: a host reporting an upper-cased fingerprint still
// counts as trusting the (lowercase-canonical) CA.
func TestAdoptionFingerprintCaseInsensitive(t *testing.T) {
	s, r := setup(t)
	now := fixedNow(r)
	fp2 := fpOf("ca-2")
	seedHB(t, s, "h1", now.UnixNano(), `["`+strings.ToUpper(fp2)+`"]`)
	ad, _ := r.AdoptionStatus(context.Background(), fp2, 5*time.Minute)
	if ad.Adopted != 1 || !ad.FullyAdopted() {
		t.Fatalf("upper-cased fp should still count: %+v", ad)
	}
}

// TestAdoptionStaleAfterZero: staleAfter<=0 counts every heartbeated host as live.
func TestAdoptionStaleAfterZero(t *testing.T) {
	s, r := setup(t)
	now := fixedNow(r)
	fp2 := fpOf("ca-2")
	seedHB(t, s, "ancient", now.Add(-100*time.Hour).UnixNano(), `["`+fp2+`"]`)
	ad, _ := r.AdoptionStatus(context.Background(), fp2, 0)
	if ad.Live != 1 || ad.Adopted != 1 || len(ad.Stale) != 0 {
		t.Fatalf("staleAfter=0 -> all live: %+v", ad)
	}
}
