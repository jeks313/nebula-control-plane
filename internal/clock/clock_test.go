package clock

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// fakeNTP runs a local UDP server that answers like an NTP server whose clock is
// `skew` ahead of this machine's. Returns its address and a stop func.
func fakeNTP(t *testing.T, skew time.Duration) (string, func()) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		buf := make([]byte, 64)
		for {
			_ = pc.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
			n, raddr, err := pc.ReadFrom(buf)
			select {
			case <-done:
				return
			default:
			}
			if err != nil || n < packetSize {
				continue
			}
			resp := make([]byte, packetSize)
			resp[0] = 0x24 // LI=0, VN=4, Mode=4 (server)
			resp[1] = 1    // stratum 1
			s, f := toNTP(time.Now().Add(skew))
			binary.BigEndian.PutUint32(resp[32:], s) // receive (T2)
			binary.BigEndian.PutUint32(resp[36:], f)
			binary.BigEndian.PutUint32(resp[40:], s) // transmit (T3)
			binary.BigEndian.PutUint32(resp[44:], f)
			_, _ = pc.WriteTo(resp, raddr)
		}
	}()
	return pc.LocalAddr().String(), func() { close(done); pc.Close() }
}

func TestNTPRoundTrip(t *testing.T) {
	want := time.Unix(1_700_000_000, 123_456_789).UTC()
	s, f := toNTP(want)
	got := fromNTP(s, f)
	if d := got.Sub(want); d < -time.Microsecond || d > time.Microsecond {
		t.Fatalf("round trip off by %v (got %v want %v)", d, got, want)
	}
}

func TestQueryComputesOffset(t *testing.T) {
	const skew = 3 * time.Second // reference is 3s ahead -> local is 3s behind
	addr, stop := fakeNTP(t, skew)
	defer stop()

	r, err := Query(context.Background(), addr, 2*time.Second)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	// local - reference should be about -3s.
	if d := r.Offset + skew; d < -250*time.Millisecond || d > 250*time.Millisecond {
		t.Fatalf("offset = %v, want ~%v", r.Offset, -skew)
	}
}

func TestCheckFailsClosedBeyondSkew(t *testing.T) {
	addr, stop := fakeNTP(t, 10*time.Second)
	defer stop()

	if _, err := Check(context.Background(), addr, 2*time.Second, 2*time.Second); err == nil {
		t.Fatal("Check should fail when skew exceeds max")
	}
}

func TestCheckPassesWithinSkew(t *testing.T) {
	addr, stop := fakeNTP(t, 0)
	defer stop()

	if _, err := Check(context.Background(), addr, 2*time.Second, 2*time.Second); err != nil {
		t.Fatalf("Check should pass for a synced clock: %v", err)
	}
}

func TestQueryTimeoutOnNoServer(t *testing.T) {
	// Nothing is listening here; Query must error (and fail closed upstream)
	// rather than hang.
	_, err := Query(context.Background(), "127.0.0.1:1", 200*time.Millisecond)
	if err == nil {
		t.Fatal("expected error querying a dead address")
	}
}
