//go:build !ui

package adminui

import "net/http"

// Handler returns the "not built" placeholder (this binary was compiled without
// -tags ui, so no SPA is embedded). The /admin/v1 JSON API is unaffected.
func Handler(_ Config) http.Handler { return notBuilt() }

// Embedded reports that no UI bundle is compiled in.
func Embedded() bool { return false }
