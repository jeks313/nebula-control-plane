//go:build embed_nebula && !windows

package nebulaboot

// embeddedWintun returns nil on non-Windows embed builds: Wintun is a Windows-only TUN
// driver, so only the Windows embed build (embed_wintun_windows.go) carries it. Linux/
// macOS use the kernel tun/utun device — nothing to materialize.
func embeddedWintun() []byte { return nil }
