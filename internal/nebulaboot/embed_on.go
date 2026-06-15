//go:build embed_nebula

package nebulaboot

import (
	"bytes"
	"compress/gzip"
	_ "embed"
	"io"
)

// nebulaGz is the gzipped nebula binary for this build's GOOS/GOARCH, fetched by
// `make embed-nebula` into assets/nebula.gz. Gzipped (~8 MB vs ~20 MB) to keep the
// pilot binary's growth modest; it is decompressed lazily, only on a first-boot
// materialize.
//
//go:embed assets/nebula.gz
var nebulaGz []byte

func embedded() []byte {
	zr, err := gzip.NewReader(bytes.NewReader(nebulaGz))
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
