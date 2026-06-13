package adminauth

import "testing"

// TestSafeReturnTo locks the open-redirect defense: only same-origin relative
// paths survive; every external/host-confusion form collapses to "/".
func TestSafeReturnTo(t *testing.T) {
	keep := []string{"/", "/dashboard", "/fleet/health?expiry=7d", "/a/b/c#frag"}
	for _, p := range keep {
		if got := safeReturnTo(p); got != p {
			t.Errorf("safeReturnTo(%q) = %q, want it preserved", p, got)
		}
	}
	reject := []string{
		"",                       // empty
		"dashboard",              // not absolute
		"//evil.com",             // protocol-relative
		`/\evil.com`,             // backslash → browsers fold to //evil.com
		`/\/evil.com`,            // backslash variant
		"/\tevil.com",            // control char
		"/\nevil.com",            // control char
		"https://evil.com",       // absolute URL (no leading /)
		"http://evil.com/path",   // absolute URL
		"/path\\with\\backslash", // any backslash is rejected
	}
	for _, p := range reject {
		if got := safeReturnTo(p); got != "/" {
			t.Errorf("safeReturnTo(%q) = %q, want \"/\" (external/unsafe)", p, got)
		}
	}
}
