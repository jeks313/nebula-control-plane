//go:build embed_nebula && windows

package nebulaboot

import (
	"bytes"
	"compress/gzip"
	_ "embed"
	"io"
)

// wintunGz is the gzipped Wintun driver (nebula's Windows TUN device), fetched by
// `make embed-nebula` into assets/wintun.gz from the same slackhq release zip as the
// embedded nebula.exe. nebula loads wintun.dll via the standard Windows DLL search
// order (the loading executable's directory first), so MaterializeEmbedded writes it
// beside nebula.exe — letting a self-contained pilot.exe bring up the overlay on a
// fresh host with no pre-installed driver and no network (offline first-boot).
//
//go:embed assets/wintun.gz
var wintunGz []byte

func embeddedWintun() []byte {
	zr, err := gzip.NewReader(bytes.NewReader(wintunGz))
	if err != nil {
		return nil
	}
	defer zr.Close()
	data, err := io.ReadAll(zr)
	if err != nil {
		return nil
	}
	return data
}
