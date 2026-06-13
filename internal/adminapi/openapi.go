package adminapi

import (
	_ "embed"
	"net/http"
)

// openapiSpec is the admin API contract. It is embedded (no runtime parsing) and
// served as-is; the contract test (adminapi) parses it and asserts it matches the
// implemented routes + live response shapes, so spec and server can't drift.
//
//go:embed openapi.yaml
var openapiSpec []byte

// Spec returns the embedded OpenAPI document (used by the contract test and by
// UI client codegen).
func Spec() []byte { return openapiSpec }

// handleOpenAPI serves the contract, unauthenticated (no fleet data in it).
func (s *Server) handleOpenAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/yaml")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(openapiSpec)
}
