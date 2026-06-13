// Package clilog configures structured logging for Harbor's commands. Logs are
// human-readable text on a terminal and JSON when running as a service (the
// default "auto" mode keys off whether stderr is a TTY), so the same binary is
// pleasant to run by hand and machine-parseable under systemd/containers.
//
// Convention: logs go to STDERR; STDOUT is reserved for a command's actual output
// (tables, ids, "ok") so `harbor ... | jq` and shell pipelines stay clean.
package clilog

import (
	"log/slog"
	"os"
	"strings"
)

// Options configures the logger. Zero values mean: format "auto", level "info".
type Options struct {
	Format string // "auto" (default) | "text" | "json"
	Level  string // "debug" | "info" (default) | "warn" | "error"
	Source bool   // include source file:line (debugging)
}

// Setup builds the logger, installs it as slog's default (so library code using
// slog.Default() — heartbeat, renew, drift, adminapi, … — inherits the format),
// and returns it.
func Setup(o Options) *slog.Logger {
	h := newHandler(os.Stderr, o)
	l := slog.New(h)
	slog.SetDefault(l)
	return l
}

func newHandler(w *os.File, o Options) slog.Handler {
	opts := &slog.HandlerOptions{Level: parseLevel(o.Level), AddSource: o.Source}
	if useJSON(o.Format, w) {
		return slog.NewJSONHandler(w, opts)
	}
	return slog.NewTextHandler(w, opts)
}

// useJSON decides the format: explicit json/text wins; "auto" (or empty) uses JSON
// when the stream is NOT a terminal (i.e. when running as a service).
func useJSON(format string, w *os.File) bool {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "json":
		return true
	case "text":
		return false
	default: // auto
		return !isTerminal(w)
	}
}

func parseLevel(s string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// isTerminal reports whether f is a character device (a TTY). Stdlib-only, so no
// new dependency; works for the console cases that matter on Linux/macOS/Windows.
func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}
