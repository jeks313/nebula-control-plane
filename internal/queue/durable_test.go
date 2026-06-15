package queue

import (
	"context"
	"crypto/sha256"
	"errors"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func newDurable(t *testing.T, opts ...func(*DurableConfig)) *Durable {
	t.Helper()
	cfg := DurableConfig{
		DSN: filepath.Join(t.TempDir(), "q.db") + "?_pragma=busy_timeout(5000)",
		Key: make([]byte, 32),
	}
	for _, o := range opts {
		o(&cfg)
	}
	d, err := OpenDurable(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

func cand(id string) Candidate {
	return Candidate{EnrollmentID: id, PubkeyHash: "pk-" + id, RequestJWS: []byte("jws-" + id), ReceivedAt: time.Now()}
}

// TestConcurrentOpen guards the co-located deploy where the gateway, worker, and
// admin all open the SAME local queue at once: GORM's AutoMigrate isn't
// cross-process/-goroutine atomic, so concurrent first-opens used to race the
// CREATE and the loser got "table already exists". OpenDurable must tolerate that.
func TestConcurrentOpen(t *testing.T) {
	dsn := filepath.Join(t.TempDir(), "q.db") + "?_pragma=busy_timeout(5000)"
	const n = 6
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		go func() {
			d, err := OpenDurable(DurableConfig{DSN: dsn, Key: make([]byte, 32)})
			if d != nil {
				_ = d.Close()
			}
			errs <- err
		}()
	}
	for i := 0; i < n; i++ {
		if err := <-errs; err != nil {
			t.Fatalf("concurrent OpenDurable failed: %v", err)
		}
	}
}

func TestPublishClaimAck(t *testing.T) {
	d := newDurable(t)
	ctx := context.Background()
	if err := d.Publish(ctx, cand("a")); err != nil {
		t.Fatal(err)
	}
	leased, err := d.Claim(ctx, 10, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(leased) != 1 || leased[0].Candidate.EnrollmentID != "a" || string(leased[0].Candidate.RequestJWS) != "jws-a" {
		t.Fatalf("bad claim: %+v", leased)
	}
	if err := d.Ack(ctx, leased[0].ID); err != nil {
		t.Fatal(err)
	}
	// After ack, nothing left.
	if n, _ := d.Depth(ctx); n != 0 {
		t.Fatalf("depth = %d, want 0", n)
	}
}

func TestPublishIdempotent(t *testing.T) {
	d := newDurable(t)
	ctx := context.Background()
	if err := d.Publish(ctx, cand("dup")); err != nil {
		t.Fatal(err)
	}
	if err := d.Publish(ctx, cand("dup")); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("err = %v, want ErrDuplicate", err)
	}
}

func TestBackpressure(t *testing.T) {
	d := newDurable(t, func(c *DurableConfig) { c.MaxDepth = 2 })
	ctx := context.Background()
	_ = d.Publish(ctx, cand("1"))
	_ = d.Publish(ctx, cand("2"))
	if err := d.Publish(ctx, cand("3")); !errors.Is(err, ErrBackpressure) {
		t.Fatalf("err = %v, want ErrBackpressure", err)
	}
}

func TestForgedMessageDeadLettered(t *testing.T) {
	d := newDurable(t)
	ctx := context.Background()
	if err := d.Publish(ctx, cand("ok")); err != nil {
		t.Fatal(err)
	}
	// Tamper the stored message behind the MAC's back.
	if err := d.db.Model(&item{}).Where("enrollment_id = ?", "ok").
		Update("pubkey_hash", "attacker").Error; err != nil {
		t.Fatal(err)
	}
	leased, err := d.Claim(ctx, 10, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(leased) != 0 {
		t.Fatalf("forged message must not be delivered, got %d", len(leased))
	}
	// It is dead-lettered, not redelivered.
	var dead int64
	d.db.Model(&item{}).Where("status = ?", statusDead).Count(&dead)
	if dead != 1 {
		t.Fatalf("dead count = %d, want 1", dead)
	}
}

func TestNackRetryThenPoison(t *testing.T) {
	d := newDurable(t, func(c *DurableConfig) { c.MaxAttempts = 2 })
	ctx := context.Background()
	_ = d.Publish(ctx, cand("p"))

	// attempt 1
	l, _ := d.Claim(ctx, 1, time.Minute)
	if len(l) != 1 || l[0].Attempts != 1 {
		t.Fatalf("attempt 1: %+v", l)
	}
	_ = d.Nack(ctx, l[0].ID) // back to ready

	// attempt 2 (== MaxAttempts) -> nack now poisons
	l, _ = d.Claim(ctx, 1, time.Minute)
	if len(l) != 1 || l[0].Attempts != 2 {
		t.Fatalf("attempt 2: %+v", l)
	}
	_ = d.Nack(ctx, l[0].ID)

	if l2, _ := d.Claim(ctx, 1, time.Minute); len(l2) != 0 {
		t.Fatalf("poisoned message should not redeliver, got %d", len(l2))
	}
}

func TestLeaseReclaim(t *testing.T) {
	d := newDurable(t)
	ctx := context.Background()
	_ = d.Publish(ctx, cand("x"))
	// Claim with an already-expired lease (negative TTL) so it reclaims next time.
	if l, _ := d.Claim(ctx, 1, -time.Second); len(l) != 1 {
		t.Fatal("first claim")
	}
	// Not acked; lease already expired -> reclaimable.
	if l, _ := d.Claim(ctx, 1, time.Minute); len(l) != 1 {
		t.Fatal("expired lease should be reclaimable")
	}
}

// putIssued stores an issued result retrievable with secret.
func putIssued(t *testing.T, d *Durable, id, secret string, bundle []byte) {
	t.Helper()
	sum := sha256.Sum256([]byte(secret))
	if err := d.PutResult(context.Background(), id, "issued", sum[:], bundle, "", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
}

// TestGetResultOneTime: an issued bundle is delivered exactly once; a second read
// is ErrResultGone.
func TestGetResultOneTime(t *testing.T) {
	d := newDurable(t)
	ctx := context.Background()
	putIssued(t, d, "e1", "sek", []byte("bundle-bytes"))

	r, err := d.GetResult(ctx, "e1", "sek")
	if err != nil {
		t.Fatalf("first read: %v", err)
	}
	if string(r.Bundle) != "bundle-bytes" {
		t.Fatalf("bundle = %q, want bundle-bytes", r.Bundle)
	}
	if _, err := d.GetResult(ctx, "e1", "sek"); !errors.Is(err, ErrResultGone) {
		t.Fatalf("second read err = %v, want ErrResultGone", err)
	}
}

// TestGetResultConcurrentOneTime proves the consume is atomic: with N readers
// racing the same issued result, exactly one gets the bundle (no cross-process /
// concurrent TOCTOU double-delivery).
func TestGetResultConcurrentOneTime(t *testing.T) {
	d := newDurable(t)
	putIssued(t, d, "e2", "sek", []byte("once"))

	const n = 8
	var delivered int64
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := d.GetResult(context.Background(), "e2", "sek")
			switch {
			case err == nil && len(r.Bundle) > 0:
				atomic.AddInt64(&delivered, 1)
			case errors.Is(err, ErrResultGone):
				// expected for the losers
			default:
				t.Errorf("unexpected GetResult result: bundle=%q err=%v", r.Bundle, err)
			}
		}()
	}
	wg.Wait()
	if delivered != 1 {
		t.Fatalf("one-time bundle delivered %d times, want exactly 1", delivered)
	}
}
