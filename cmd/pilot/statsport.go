package main

import (
	"bufio"
	"bytes"
	"log/slog"
	"net"
	"os"
	"strings"
)

// disableStatsOnPortConflict makes nebula's prometheus stats listener FAIL-OPEN. nebula treats a
// stats `listen` bind failure as fatal, so a metrics-port conflict would otherwise take the whole
// data plane down with it. A metrics port must never sink the tunnel: before launching nebula we
// test-bind the configured stats port, and if it's already in use we strip the stats block from
// the config (logging loudly) so nebula still comes up — just without metrics. The next
// enrollment/renew re-renders the block, so stats return once the port is free; setting the stats
// port to 0 (nebulaconfig.Values.StatsPort) disables it outright. A non-standard default port
// (see internal/nebulaconfig) already makes a collision unlikely; this is the safety net.
func disableStatsOnPortConflict(configPath string, log *slog.Logger) {
	b, err := os.ReadFile(configPath)
	if err != nil {
		return // a missing/unreadable config is the supervisor's to report
	}
	listen := statsListenAddr(b)
	if listen == "" {
		return // no stats block configured — nothing to guard
	}
	if ln, err := net.Listen("tcp", listen); err == nil {
		_ = ln.Close()
		return // port is free — keep stats enabled
	}
	if err := os.WriteFile(configPath, stripStatsBlock(b), 0o644); err != nil {
		log.Error("nebula stats port in use; could not rewrite the config to disable it — nebula may fail to start",
			"listen", listen, "err", err)
		return
	}
	log.Warn("nebula stats port in use — disabled the stats listener so the data plane still starts "+
		"(free the port or set the stats port to 0; a re-enroll/renew restores stats)", "listen", listen)
}

// statsListenAddr returns the `listen:` value inside a top-level `stats:` block (host:port as
// nebula would bind it, e.g. "0.0.0.0:4280"), or "" when there is no stats block.
func statsListenAddr(cfg []byte) string {
	sc := bufio.NewScanner(bytes.NewReader(cfg))
	inStats := false
	for sc.Scan() {
		line := sc.Text()
		if len(line) > 0 && line[0] != ' ' && line[0] != '\t' { // a top-level key resets the section
			inStats = strings.HasPrefix(line, "stats:")
			continue
		}
		if inStats {
			if v := strings.TrimSpace(line); strings.HasPrefix(v, "listen:") {
				return strings.TrimSpace(strings.TrimPrefix(v, "listen:"))
			}
		}
	}
	return ""
}

// stripStatsBlock removes a top-level `stats:` block (the key plus its indented body) from a
// nebula config, leaving everything else byte-for-byte intact.
func stripStatsBlock(cfg []byte) []byte {
	var out bytes.Buffer
	sc := bufio.NewScanner(bytes.NewReader(cfg))
	skipping := false
	for sc.Scan() {
		line := sc.Text()
		if len(line) > 0 && line[0] != ' ' && line[0] != '\t' { // a top-level key
			skipping = strings.HasPrefix(line, "stats:")
			if skipping {
				continue // drop the `stats:` line itself
			}
		}
		if skipping {
			continue // drop the indented body (and blank lines) under stats:
		}
		out.WriteString(line)
		out.WriteByte('\n')
	}
	return out.Bytes()
}
