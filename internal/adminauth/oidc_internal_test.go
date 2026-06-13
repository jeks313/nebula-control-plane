package adminauth

import "testing"

// TestMFAFromClaims: MFA is honored only when amr asserts it AND auth_time is
// present. Crucially, a missing auth_time does NOT fall back to iat (which would
// make a cached/old MFA look fresh) — it returns nil (fail closed).
func TestMFAFromClaims(t *testing.T) {
	// amr=mfa + auth_time → the auth_time instant.
	got := mfaFromClaims(map[string]any{"amr": []any{"pwd", "mfa"}, "auth_time": float64(1_700_000_000)})
	if got == nil || got.Unix() != 1_700_000_000 {
		t.Fatalf("amr=mfa + auth_time → %v, want the auth_time instant", got)
	}
	// amr=mfa but NO auth_time → nil (no iat fallback; forces a step-up).
	if got := mfaFromClaims(map[string]any{"amr": []any{"pwd", "mfa"}}); got != nil {
		t.Fatalf("amr=mfa without auth_time → %v, want nil (must not fall back to iat)", got)
	}
	// No MFA method asserted → nil.
	if got := mfaFromClaims(map[string]any{"amr": []any{"pwd"}, "auth_time": float64(1_700_000_000)}); got != nil {
		t.Fatalf("amr without mfa → %v, want nil", got)
	}
}
