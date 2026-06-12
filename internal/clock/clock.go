// Package clock checks the host clock against an external time reference
// (implementation-plan M1.13). The whole identity model — nonce TTLs, cert
// validity windows, attestation freshness (design §4.3) — assumes synced clocks.
// A grossly skewed clock should fail closed on identity operations (P8): a host
// that can't trust its own clock must refuse to enroll/renew rather than present
// stale or future-dated material.
//
// This is a sanity check against *gross* drift (minutes/hours/days), not a
// security-grade time source: plain SNTP is unauthenticated and spoofable. The
// upgrade path is authenticated time (NTS) or Harbor's signed Date over the
// mesh; until then this catches the common real failure (a VM whose RTC is
// hours off), which is what breaks cert validity.
package clock

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

// secondsFrom1900To1970 converts between the NTP epoch (1900-01-01) and Unix.
const secondsFrom1900To1970 = 2208988800

const packetSize = 48

// Result is the outcome of a single time query.
type Result struct {
	Server string
	// Offset is local clock minus reference: positive means the local clock is
	// ahead of true time, negative means behind.
	Offset time.Duration
	// RTT is the measured round trip, for context on the offset's confidence.
	RTT time.Duration
}

func toNTP(t time.Time) (sec, frac uint32) {
	secs := uint64(t.Unix()) + secondsFrom1900To1970
	frac64 := (uint64(t.Nanosecond()) << 32) / uint64(time.Second/time.Nanosecond)
	return uint32(secs), uint32(frac64)
}

func fromNTP(sec, frac uint32) time.Time {
	if sec == 0 && frac == 0 {
		return time.Time{}
	}
	secs := int64(sec) - secondsFrom1900To1970
	nsec := (int64(frac) * int64(time.Second/time.Nanosecond)) >> 32
	return time.Unix(secs, nsec).UTC()
}

// Query performs one SNTP (RFC 4330) exchange and computes the local clock's
// offset from the server. server may be "host" (port 123 assumed) or "host:port".
func Query(ctx context.Context, server string, timeout time.Duration) (Result, error) {
	addr := server
	if _, _, err := net.SplitHostPort(server); err != nil {
		addr = net.JoinHostPort(server, "123")
	}

	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "udp", addr)
	if err != nil {
		return Result{}, fmt.Errorf("clock: dial %s: %w", addr, err)
	}
	defer conn.Close()

	deadline := time.Now().Add(timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetDeadline(deadline)

	req := make([]byte, packetSize)
	req[0] = 0x23 // LI=0 (no warning), VN=4, Mode=3 (client)

	t1 := time.Now()
	s, f := toNTP(t1)
	binary.BigEndian.PutUint32(req[40:], s) // Transmit Timestamp (origin)
	binary.BigEndian.PutUint32(req[44:], f)

	if _, err := conn.Write(req); err != nil {
		return Result{}, fmt.Errorf("clock: send to %s: %w", addr, err)
	}

	resp := make([]byte, packetSize)
	n, err := conn.Read(resp)
	t4 := time.Now()
	if err != nil {
		return Result{}, fmt.Errorf("clock: read from %s: %w", addr, err)
	}
	if n < packetSize {
		return Result{}, fmt.Errorf("clock: short NTP reply from %s: %d bytes", addr, n)
	}

	// T2 = server receive (bytes 32..39), T3 = server transmit (bytes 40..47).
	t2 := fromNTP(binary.BigEndian.Uint32(resp[32:]), binary.BigEndian.Uint32(resp[36:]))
	t3 := fromNTP(binary.BigEndian.Uint32(resp[40:]), binary.BigEndian.Uint32(resp[44:]))
	if t2.IsZero() || t3.IsZero() {
		return Result{}, fmt.Errorf("clock: %s returned zero timestamps (kiss-o'-death?)", addr)
	}

	// Standard NTP offset of server relative to client:
	//   theta = ((T2 - T1) + (T3 - T4)) / 2   (≈ reference - local)
	// We report local - reference, so negate.
	theta := (t2.Sub(t1) + t3.Sub(t4)) / 2
	rtt := t4.Sub(t1) - t3.Sub(t2)
	return Result{Server: addr, Offset: -theta, RTT: rtt}, nil
}

// Check queries server and returns an error if the absolute offset exceeds
// maxSkew. The error is the fail-closed signal for identity operations.
func Check(ctx context.Context, server string, maxSkew, timeout time.Duration) (Result, error) {
	r, err := Query(ctx, server, timeout)
	if err != nil {
		return r, err
	}
	if abs(r.Offset) > maxSkew {
		return r, fmt.Errorf("clock: local skew %s exceeds max %s (reference %s) — refusing (fail-closed)",
			r.Offset.Round(time.Millisecond), maxSkew, r.Server)
	}
	return r, nil
}

func abs(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}
