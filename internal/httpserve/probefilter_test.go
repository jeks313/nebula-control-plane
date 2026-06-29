package httpserve

import (
	"bytes"
	"log"
	"net/http"
	"testing"
)

// TestQuietProbeNoise: installs the filter when ErrorLog is nil; leaves a caller-set ErrorLog alone.
func TestQuietProbeNoise(t *testing.T) {
	srv := &http.Server{}
	quietProbeNoise(srv)
	if srv.ErrorLog == nil {
		t.Fatal("expected quietProbeNoise to install an ErrorLog when nil")
	}
	preset := log.New(&bytes.Buffer{}, "", 0)
	srv2 := &http.Server{ErrorLog: preset}
	quietProbeNoise(srv2)
	if srv2.ErrorLog != preset {
		t.Fatal("expected quietProbeNoise to leave a caller-set ErrorLog untouched")
	}
}

// TestProbeFilter: benign handshake noise from health checks / scanners is dropped; genuine
// server errors (and any non-handshake line) pass through unchanged.
func TestProbeFilter(t *testing.T) {
	drop := []string{
		"http: TLS handshake error from 10.99.2.33:58527: EOF\n",
		"http: TLS handshake error from 10.0.0.1:5: read tcp ...: connection reset by peer\n",
		"http: TLS handshake error from 10.0.0.1:5: read tcp ...: i/o timeout\n",
		"http: TLS handshake error from 1.2.3.4:9: tls: first record does not look like a TLS handshake\n",
	}
	keep := []string{
		"http: TLS handshake error from 1.2.3.4:9: tls: no cipher suite supported by both client and server\n",
		"http: Server closed\n",
		"some other error\n",
	}
	for _, line := range drop {
		var sink bytes.Buffer
		n, err := (probeFilter{w: &sink}).Write([]byte(line))
		if err != nil || n != len(line) {
			t.Fatalf("write reported n=%d err=%v, want full+nil for %q", n, err, line)
		}
		if sink.Len() != 0 {
			t.Errorf("expected DROP, but wrote %q", sink.String())
		}
	}
	for _, line := range keep {
		var sink bytes.Buffer
		if _, err := (probeFilter{w: &sink}).Write([]byte(line)); err != nil {
			t.Fatal(err)
		}
		if sink.String() != line {
			t.Errorf("expected PASS-THROUGH of %q, got %q", line, sink.String())
		}
	}
}
