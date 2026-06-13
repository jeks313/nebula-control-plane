//go:build ui

package adminui

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed all:dist
var distFS embed.FS

// Handler serves the embedded React console with the given runtime config.
func Handler(cfg Config) http.Handler {
	sub, err := fs.Sub(distFS, "dist")
	if err != nil {
		return notBuilt()
	}
	return spaHandler(sub, cfg)
}

// Embedded reports that a UI bundle is compiled in.
func Embedded() bool { return true }
