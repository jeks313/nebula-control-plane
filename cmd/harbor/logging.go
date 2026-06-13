package main

import (
	"flag"
	"log/slog"
	"os"

	"github.com/jeks313/nebula-control-plane/internal/clilog"
)

// logOpts are the shared logging flags for the long-running service commands
// (core-api, admin-api, enroll worker). Interactive commands keep clean stdout
// output and don't need them.
type logOpts struct {
	format *string
	level  *string
}

func addLogFlags(fs *flag.FlagSet) logOpts {
	return logOpts{
		format: fs.String("log-format", "auto", "log format: auto (text on a TTY, JSON as a service) | text | json"),
		level:  fs.String("log-level", "info", "log level: debug | info | warn | error"),
	}
}

// setup installs the configured logger as slog's default (so the engine libraries
// inherit the format) and returns it.
func (o logOpts) setup() *slog.Logger {
	return clilog.Setup(clilog.Options{Format: *o.format, Level: *o.level})
}

// defaultLog installs a baseline logger before any subcommand parses flags, from
// HARBOR_LOG_FORMAT / HARBOR_LOG_LEVEL (else auto / info), so even code paths that
// log via slog.Default() before a service flag override are formatted sensibly.
func defaultLog() {
	clilog.Setup(clilog.Options{Format: os.Getenv("HARBOR_LOG_FORMAT"), Level: os.Getenv("HARBOR_LOG_LEVEL")})
}
