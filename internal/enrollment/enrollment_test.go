package enrollment

import (
	"encoding/json"
	"reflect"
	"testing"
)

// TestIdPGroupsRoundTrip proves the approve-path re-derivation of an SSO enrollment's
// IdP groups survives a group name containing a comma. processSSO JSON-encodes the
// groups into the AttestRegion evidence column; approveNetblock decodes them via
// decodeGroups before re-running usertrust.Match. A comma-join (the prior encoding)
// would split "platform,db" into two bogus groups and miss the matched entry, falling
// back to the wrong (default) netblock.
func TestIdPGroupsRoundTrip(t *testing.T) {
	cases := [][]string{
		nil,
		{},
		{"eng-web"},
		{"eng-web", "eng-db"},
		{"platform,db", "team=eng,role=admin"}, // comma-bearing names must round-trip
	}
	for _, groups := range cases {
		// Encode exactly as processSSO stores it into AttestRegion.
		encoded, err := json.Marshal(groups)
		if err != nil {
			t.Fatalf("marshal %v: %v", groups, err)
		}
		got := decodeGroups(string(encoded))
		// nil and empty both normalize to "no groups" (decodeGroups returns nil/empty
		// equivalently for Match's purposes); compare lengths + contents.
		if len(got) != len(groups) {
			t.Fatalf("round-trip length: in=%v out=%v", groups, got)
		}
		if len(groups) > 0 && !reflect.DeepEqual(got, groups) {
			t.Fatalf("round-trip mismatch:\n in=%v\nout=%v", groups, got)
		}
	}
}

// TestDecodeGroupsEmptyAndInvalid: an empty column yields nil (no spurious "" group),
// and a non-JSON value (defensive — should never be written) yields nil rather than
// panicking or producing a bogus group.
func TestDecodeGroupsEmptyAndInvalid(t *testing.T) {
	if got := decodeGroups(""); got != nil {
		t.Fatalf("empty column: want nil, got %v", got)
	}
	if got := decodeGroups("not-json"); got != nil {
		t.Fatalf("invalid JSON: want nil, got %v", got)
	}
}
