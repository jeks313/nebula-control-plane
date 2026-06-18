package ipam

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/store"
	"github.com/jeks313/nebula-control-plane/internal/store/migrate"
)

func newStore(t *testing.T) *store.Store {
	t.Helper()
	dsn := store.DefaultSQLiteDSN(filepath.Join(t.TempDir(), "harbor.db"))
	s, err := store.Open(store.Config{Driver: "sqlite", DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	if err := migrate.Up(s.DB); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func newAllocator(t *testing.T, pool Pool) *Allocator {
	t.Helper()
	a, err := NewAllocator(newStore(t), pool)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestAllocateSequential(t *testing.T) {
	a := newAllocator(t, Pool{Prefix: netip.MustParsePrefix("100.64.0.0/24")})
	ctx := context.Background()
	want := []string{"100.64.0.1", "100.64.0.2", "100.64.0.3"} // .0 (network) skipped
	for i, w := range want {
		got, err := a.Allocate(ctx, fmt.Sprintf("dev-%d", i), "", "token")
		if err != nil {
			t.Fatal(err)
		}
		if got.String() != w {
			t.Fatalf("alloc %d = %s, want %s", i, got, w)
		}
	}
}

func TestReleaseNoQuarantineReuses(t *testing.T) {
	a := newAllocator(t, Pool{Prefix: netip.MustParsePrefix("100.64.0.0/24")})
	ctx := context.Background()
	ip, _ := a.Allocate(ctx, "dev-a", "", "token")
	if err := a.Release(ctx, ip); err != nil {
		t.Fatal(err)
	}
	reused, _ := a.Allocate(ctx, "dev-b", "", "token")
	if reused != ip {
		t.Fatalf("expected immediate reuse of %s, got %s", ip, reused)
	}
	if err := a.Release(ctx, netip.MustParseAddr("100.64.0.200")); !errors.Is(err, ErrNotAllocated) {
		t.Fatalf("release of unallocated IP = %v, want ErrNotAllocated", err)
	}
}

func TestReleaseQuarantineHonored(t *testing.T) {
	a := newAllocator(t, Pool{
		Prefix:        netip.MustParsePrefix("100.64.0.0/24"),
		QuarantineTTL: time.Hour,
	})
	now := time.Now()
	a.now = func() time.Time { return now }
	ctx := context.Background()

	ip1, _ := a.Allocate(ctx, "dev-a", "", "token") // 100.64.0.1
	if err := a.Release(ctx, ip1); err != nil {
		t.Fatal(err)
	}
	// While quarantined, the same IP must NOT be handed out again.
	ip2, _ := a.Allocate(ctx, "dev-b", "", "token")
	if ip2 == ip1 {
		t.Fatalf("quarantined IP %s was reused immediately", ip1)
	}

	// After the quarantine window, it becomes reusable.
	now = now.Add(2 * time.Hour)
	if err := a.Release(ctx, ip2); err != nil {
		t.Fatal(err)
	}
	ip3, _ := a.Allocate(ctx, "dev-c", "", "token")
	if ip3 != ip1 {
		t.Fatalf("after quarantine expiry expected reuse of %s, got %s", ip1, ip3)
	}
}

func TestSubRanges(t *testing.T) {
	a := newAllocator(t, Pool{
		Prefix: netip.MustParsePrefix("100.64.0.0/16"),
		SubRanges: map[string]netip.Prefix{
			"aws":   netip.MustParsePrefix("100.64.0.0/24"),
			"azure": netip.MustParsePrefix("100.64.1.0/24"),
		},
	})
	ctx := context.Background()
	aws, err := a.Allocate(ctx, "aws-1", "aws", "token")
	if err != nil {
		t.Fatal(err)
	}
	if !netip.MustParsePrefix("100.64.0.0/24").Contains(aws) {
		t.Fatalf("aws alloc %s not in aws sub-range", aws)
	}
	az, err := a.Allocate(ctx, "az-1", "azure", "token")
	if err != nil {
		t.Fatal(err)
	}
	if !netip.MustParsePrefix("100.64.1.0/24").Contains(az) {
		t.Fatalf("azure alloc %s not in azure sub-range", az)
	}
	if _, err := a.Allocate(ctx, "x", "gcp", "token"); !errors.Is(err, ErrUnknownSubRange) {
		t.Fatalf("unknown sub-range err = %v", err)
	}
}

func TestPoolExhausted(t *testing.T) {
	a := newAllocator(t, Pool{Prefix: netip.MustParsePrefix("100.64.0.0/30")}) // .1,.2,.3 usable
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if _, err := a.Allocate(ctx, fmt.Sprintf("d%d", i), "", "token"); err != nil {
			t.Fatalf("alloc %d: %v", i, err)
		}
	}
	if _, err := a.Allocate(ctx, "overflow", "", "token"); !errors.Is(err, ErrPoolExhausted) {
		t.Fatalf("err = %v, want ErrPoolExhausted", err)
	}
}

// TestConcurrentAllocationsNoCollision is the M2.6 acceptance: parallel
// allocations never hand out the same address.
func TestConcurrentAllocationsNoCollision(t *testing.T) {
	a := newAllocator(t, Pool{Prefix: netip.MustParsePrefix("100.64.0.0/24")})
	ctx := context.Background()
	const n = 150

	var mu sync.Mutex
	got := make(map[string]int)
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ip, err := a.Allocate(ctx, fmt.Sprintf("dev-%d", i), "", "token")
			if err != nil {
				errs <- err
				return
			}
			mu.Lock()
			got[ip.String()]++
			mu.Unlock()
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent allocate: %v", err)
	}
	if len(got) != n {
		t.Fatalf("got %d distinct IPs, want %d", len(got), n)
	}
	for ip, c := range got {
		if c != 1 {
			t.Fatalf("IP %s handed out %d times", ip, c)
		}
	}
}
