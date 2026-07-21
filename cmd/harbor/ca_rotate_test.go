package main

import (
	"testing"

	"github.com/jeks313/nebula-control-plane/internal/ca"
)

// TestAdoptionGate is the pure M8.1 cut-over decision (the CLI's activate gate): proceed at
// full adoption or under -force; refuse (with a message) when live hosts lag.
func TestAdoptionGate(t *testing.T) {
	full := ca.Adoption{Live: 3, Adopted: 3}
	if ok, msg := adoptionGate(full, false); !ok || msg != "" {
		t.Fatalf("full adoption should proceed cleanly: ok=%v msg=%q", ok, msg)
	}
	part := ca.Adoption{Live: 3, Adopted: 1, Laggards: []string{"100.64.0.5", "100.64.0.6"}}
	ok, msg := adoptionGate(part, false)
	if ok || msg == "" {
		t.Fatalf("partial adoption should refuse with a message: ok=%v msg=%q", ok, msg)
	}
	if ok, _ := adoptionGate(part, true); !ok {
		t.Fatal("-force must override the gate")
	}
	// Empty live fleet is vacuously adopted (bootstrap).
	if ok, _ := adoptionGate(ca.Adoption{Live: 0}, false); !ok {
		t.Fatal("empty live fleet should proceed")
	}
}
