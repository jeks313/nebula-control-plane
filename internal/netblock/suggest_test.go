package netblock

import (
	"net/netip"
	"testing"
)

func mustP(s string) netip.Prefix { return netip.MustParsePrefix(s) }

func suggest(t *testing.T, reqLen int, pool string, carves ...string) netip.Prefix {
	t.Helper()
	var cs []netip.Prefix
	for _, c := range carves {
		cs = append(cs, mustP(c))
	}
	got, err := Suggest(reqLen, mustP(pool), nil, cs)
	if err != nil {
		t.Fatalf("Suggest(/%d, %s, %v) error: %v", reqLen, pool, carves, err)
	}
	return got
}

// TestSuggestWorkedExample is the ADR's worked example: with central at the start
// of the pool (10.44.0.0/27 occupying the 10.44.0.0/24 envelope), two consecutive
// /27 requests land in SEPARATE /24s — each free to grow to a full /24 in place.
func TestSuggestWorkedExample(t *testing.T) {
	pool := "10.44.0.0/16"
	// Start with central in the first /24 envelope.
	carves := []string{"10.44.0.0/27"}

	// First /27 request: skips the (occupied) 10.44.0.0/24 envelope, lands at the
	// start of the next free envelope -> 10.44.1.0/27.
	first := suggest(t, 27, pool, carves...)
	if first != mustP("10.44.1.0/27") {
		t.Fatalf("first /27 = %s, want 10.44.1.0/27", first)
	}
	carves = append(carves, first.String())

	// Second /27 request: 10.44.1.0/24 is now soft-claimed (its envelope holds the
	// first carve), so it lands at the start of the NEXT free /24 -> 10.44.2.0/27.
	second := suggest(t, 27, pool, carves...)
	if second != mustP("10.44.2.0/27") {
		t.Fatalf("second /27 = %s, want 10.44.2.0/27", second)
	}

	// Each is free to grow to a full /24 in place (same network address).
	if first.Masked().Addr() != mustP("10.44.1.0/24").Addr() {
		t.Fatalf("first /27 %s cannot grow to 10.44.1.0/24 in place", first)
	}
	if second.Masked().Addr() != mustP("10.44.2.0/24").Addr() {
		t.Fatalf("second /27 %s cannot grow to 10.44.2.0/24 in place", second)
	}
}

// TestSuggestEmptyPoolPlacesAtStart: with no carves, a /27 lands at the very start
// of the pool (start-of-envelope placement).
func TestSuggestEmptyPoolPlacesAtStart(t *testing.T) {
	got := suggest(t, 27, "10.44.0.0/16")
	if got != mustP("10.44.0.0/27") {
		t.Fatalf("/27 in empty pool = %s, want 10.44.0.0/27", got)
	}
}

// TestSuggestEnvelopeFloor: a /24 request (== EnvelopeFloor) gets a /24 envelope
// (no coarser), so consecutive /24s pack one-per-envelope from the start.
func TestSuggestEnvelopeFloor(t *testing.T) {
	pool := "10.44.0.0/16"
	first := suggest(t, 24, pool)
	if first != mustP("10.44.0.0/24") {
		t.Fatalf("first /24 = %s, want 10.44.0.0/24", first)
	}
	second := suggest(t, 24, pool, first.String())
	if second != mustP("10.44.1.0/24") {
		t.Fatalf("second /24 = %s, want 10.44.1.0/24", second)
	}
}

// TestSuggestCoarserThanFloor: a /20 request is coarser than the /24 floor, so its
// envelope is the /20 itself (E clamps up to P), placed at the pool start.
func TestSuggestCoarserThanFloor(t *testing.T) {
	got := suggest(t, 20, "10.44.0.0/16")
	if got != mustP("10.44.0.0/20") {
		t.Fatalf("/20 = %s, want 10.44.0.0/20", got)
	}
}

// TestSuggestWorstFitUnderPressure: when every /24 envelope holds at least one
// carve (no fresh envelope), worst-fit packs into the envelope with the MOST free
// /27 slots. Here we fill a small pool's three /24 envelopes unevenly.
func TestSuggestWorstFitUnderPressure(t *testing.T) {
	pool := "10.44.0.0/22" // four /24 envelopes: .0 .1 .2 .3
	// Occupy one /27 in each /24 so none is a "fresh" envelope; leave .3 with the
	// fewest occupied (1) — but make .2 hold MORE carves so worst-fit avoids it.
	carves := []string{
		"10.44.0.0/27",                                   // .0 has 1 used
		"10.44.1.0/27",                                   // .1 has 1 used
		"10.44.2.0/27", "10.44.2.32/27", "10.44.2.64/27", // .2 has 3 used (least free)
		"10.44.3.0/27", "10.44.3.32/27", // .3 has 2 used
	}
	got := suggest(t, 27, pool, carves...)
	// Worst-fit -> the envelope with the most free /27 slots. .0 and .1 each have 7
	// free; tie broken by lowest-address envelope -> .0, lowest free slot 10.44.0.32/27.
	if got != mustP("10.44.0.32/27") {
		t.Fatalf("worst-fit /27 = %s, want 10.44.0.32/27", got)
	}
}

// TestSuggestPoolFull: no aligned /P slot anywhere -> ErrPoolFull.
func TestSuggestPoolFull(t *testing.T) {
	pool := "10.44.0.0/30" // a /30 cannot contain any /27 -> bad prefix len, not pool-full
	if _, err := Suggest(27, mustP(pool), nil, nil); err != ErrBadPrefixLen {
		t.Fatalf("err = %v, want ErrBadPrefixLen", err)
	}
	// A /26 pool holds exactly two /27 slots; carve both, then a third request is full.
	pool = "10.44.0.0/26"
	carves := []netip.Prefix{mustP("10.44.0.0/27"), mustP("10.44.0.32/27")}
	if _, err := Suggest(27, mustP(pool), nil, carves); err != ErrPoolFull {
		t.Fatalf("err = %v, want ErrPoolFull", err)
	}
}

// TestSuggestDeterministic: identical inputs yield an identical result (the overlay
// redraws without jitter; the server-side default matches the UI).
func TestSuggestDeterministic(t *testing.T) {
	pool := mustP("10.44.0.0/16")
	carves := []netip.Prefix{mustP("10.44.0.0/27"), mustP("10.44.1.0/27")}
	var prev netip.Prefix
	for i := 0; i < 5; i++ {
		got, err := Suggest(27, pool, nil, carves)
		if err != nil {
			t.Fatal(err)
		}
		if i > 0 && got != prev {
			t.Fatalf("non-deterministic: run %d = %s, prev = %s", i, got, prev)
		}
		prev = got
	}
}

// TestSuggestReservedAvoided: a reserved address inside an envelope makes that
// envelope non-fresh, pushing placement to the next clear envelope.
func TestSuggestReservedAvoided(t *testing.T) {
	pool := mustP("10.44.0.0/16")
	reserved := []netip.Addr{netip.MustParseAddr("10.44.0.5")}
	got, err := Suggest(27, pool, reserved, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got != mustP("10.44.1.0/27") {
		t.Fatalf("/27 with reserved in first envelope = %s, want 10.44.1.0/27", got)
	}
}

func TestBuddyOf(t *testing.T) {
	cases := []struct{ in, want string }{
		{"10.44.1.0/27", "10.44.1.32/27"}, // lower half -> upper buddy
		{"10.44.1.32/27", "10.44.1.0/27"}, // upper half -> lower buddy
		{"10.44.0.0/24", "10.44.1.0/24"},  // lower half -> upper buddy
		{"10.44.2.0/24", "10.44.3.0/24"},  // lower half (of /23) -> upper buddy
	}
	for _, c := range cases {
		got := buddyOf(mustP(c.in))
		if got != mustP(c.want).Masked() {
			t.Errorf("buddyOf(%s) = %s, want %s", c.in, got, c.want)
		}
	}
}
