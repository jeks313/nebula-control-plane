//go:build !embed_nebula

package nebulaboot

// embedded returns nil in the default build: no nebula is embedded, so the pilot
// relies on a pre-installed binary or Phase 1 distribution. A release build with
// `-tags embed_nebula` (see embed_on.go + `make embed-nebula`) embeds the real binary.
func embedded() []byte { return nil }

// embeddedWintun returns nil in the default build. Only a Windows release build with
// `-tags embed_nebula` embeds Wintun (nebula's TUN driver) — see embed_wintun_windows.go;
// every other build (here, and embed_wintun_other.go) returns nil so the materialize is
// a clean no-op off Windows.
func embeddedWintun() []byte { return nil }
