package adminapi

import (
	"net/http"

	"github.com/jeks313/nebula-control-plane/internal/version"
)

// handleVersion implements GET /admin/v1/version — the harbor build identity (CalVer + commit +
// build time) plus the embedded git changelog grouped by date (newest first). Authenticated (any
// logged-in user), no special permission, like /me. Because the changelog + version are baked into
// THIS binary at build time, the response always describes the build actually running on Harbor.
func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	type day struct {
		Date    string           `json:"date"`
		Commits []version.Change `json:"commits"`
	}
	days := []day{}
	idx := map[string]int{}
	for _, c := range version.Changelog() {
		i, ok := idx[c.Date]
		if !ok {
			days = append(days, day{Date: c.Date})
			i = len(days) - 1
			idx[c.Date] = i
		}
		days[i].Commits = append(days[i].Commits, c)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"version":    version.Version,
		"commit":     version.Commit,
		"build_time": version.BuildTime,
		"days":       days,
	})
}
