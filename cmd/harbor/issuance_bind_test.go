package main

import (
	"net/netip"
	"strings"
	"testing"
)

// TestCheckIssuanceBind exercises the ADR 0009 (Phase 0) startup guard: an
// issuance-mode server (-ca-cert) may bind only loopback or the overlay pool;
// the unspecified address and any public/out-of-pool address are refused unless
// -allow-public-issuance is set, and a non-issuance-mode server is never guarded.
func TestCheckIssuanceBind(t *testing.T) {
	pool := netip.MustParsePrefix("10.44.0.0/16")

	tests := []struct {
		name        string
		addr        string
		issuance    bool
		allowPublic bool
		wantErr     bool
	}{
		// Allowed binds in issuance mode.
		{name: "loopback ipv4", addr: "127.0.0.1:443", issuance: true, wantErr: false},
		{name: "loopback ipv4 high", addr: "127.0.0.5:8444", issuance: true, wantErr: false},
		{name: "loopback ipv6", addr: "[::1]:443", issuance: true, wantErr: false},
		{name: "overlay core-api live", addr: "10.44.0.2:8444", issuance: true, wantErr: false},
		{name: "overlay admin-api live", addr: "10.44.0.2:443", issuance: true, wantErr: false},

		// Refused binds in issuance mode.
		{name: "unspecified ipv4", addr: "0.0.0.0:443", issuance: true, wantErr: true},
		{name: "empty host (all interfaces)", addr: ":443", issuance: true, wantErr: true},
		{name: "unspecified ipv6", addr: "[::]:443", issuance: true, wantErr: true},
		{name: "public out-of-pool", addr: "203.0.113.5:443", issuance: true, wantErr: true},
		{name: "private out-of-pool", addr: "192.168.1.10:443", issuance: true, wantErr: true},

		// Each refused case is allowed when -allow-public-issuance is set.
		{name: "unspecified ipv4 + override", addr: "0.0.0.0:443", issuance: true, allowPublic: true, wantErr: false},
		{name: "empty host + override", addr: ":443", issuance: true, allowPublic: true, wantErr: false},
		{name: "unspecified ipv6 + override", addr: "[::]:443", issuance: true, allowPublic: true, wantErr: false},
		{name: "public out-of-pool + override", addr: "203.0.113.5:443", issuance: true, allowPublic: true, wantErr: false},

		// Non-issuance mode is never guarded, regardless of address.
		{name: "non-issuance unspecified", addr: "0.0.0.0:443", issuance: false, wantErr: false},
		{name: "non-issuance public", addr: "203.0.113.5:443", issuance: false, wantErr: false},
		{name: "non-issuance empty host", addr: ":443", issuance: false, wantErr: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := checkIssuanceBind(tc.addr, pool, tc.issuance, tc.allowPublic)
			if tc.wantErr && err == nil {
				t.Fatalf("checkIssuanceBind(%q, %s, issuance=%v, allowPublic=%v): want error, got nil",
					tc.addr, pool, tc.issuance, tc.allowPublic)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("checkIssuanceBind(%q, %s, issuance=%v, allowPublic=%v): want nil, got %v",
					tc.addr, pool, tc.issuance, tc.allowPublic, err)
			}
			// A refusal must name the offending addr and point at the override, so the
			// operator can act on the message.
			if tc.wantErr {
				if !strings.Contains(err.Error(), tc.addr) {
					t.Errorf("error does not name addr %q: %v", tc.addr, err)
				}
				if !strings.Contains(err.Error(), "-allow-public-issuance") {
					t.Errorf("error does not mention the -allow-public-issuance override: %v", err)
				}
				if !strings.Contains(err.Error(), "ADR 0009") {
					t.Errorf("error does not cite ADR 0009: %v", err)
				}
			}
		})
	}
}
