package clilog

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"
)

func TestUseJSON(t *testing.T) {
	// Explicit formats win regardless of the stream.
	if !useJSON("json", os.Stdout) {
		t.Error(`"json" should force JSON`)
	}
	if useJSON("text", os.Stdout) {
		t.Error(`"text" should force text`)
	}
	// "auto" on a non-terminal (a regular file = running as a service) → JSON.
	f, err := os.Create(filepath.Join(t.TempDir(), "out"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if !useJSON("auto", f) {
		t.Error(`"auto" to a non-TTY should be JSON (service mode)`)
	}
	if !useJSON("", f) {
		t.Error(`empty format defaults to auto → JSON to a non-TTY`)
	}
}

func TestParseLevel(t *testing.T) {
	cases := map[string]slog.Level{
		"debug": slog.LevelDebug, "info": slog.LevelInfo, "INFO": slog.LevelInfo,
		"warn": slog.LevelWarn, "warning": slog.LevelWarn, "error": slog.LevelError,
		"": slog.LevelInfo, "nonsense": slog.LevelInfo,
	}
	for in, want := range cases {
		if got := parseLevel(in); got != want {
			t.Errorf("parseLevel(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestSetupReturnsDefault(t *testing.T) {
	l := Setup(Options{Format: "json", Level: "warn"})
	if l == nil || slog.Default() != l {
		t.Fatal("Setup must install itself as slog.Default")
	}
}
