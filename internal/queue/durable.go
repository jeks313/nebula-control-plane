package queue

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// Durable is a SQLite-backed enrollment queue (implementation-plan 3.3a). It is
// its OWN store, separate from Harbor's main DB, so the gateway gets queue-only
// access (publish), never the CA/devices/audit. Each message carries an HMAC
// over its contents (the gateway↔Core shared key) so Core rejects forged or
// tampered messages; the unique enrollment_id makes publish idempotent (replay-
// safe); lease/ack/nack give at-least-once with poison handling, and a depth cap
// provides backpressure. Production swaps this for SQS/NATS behind queue.Queue.
type Durable struct {
	db          *gorm.DB
	key         []byte
	maxDepth    int
	maxAttempts int
	now         func() time.Time
}

// Status values.
const (
	statusReady    = "ready"
	statusInflight = "inflight"
	statusDead     = "dead"
)

// Errors.
var (
	ErrDuplicate    = errors.New("queue: duplicate enrollment_id (idempotent no-op)")
	ErrBackpressure = errors.New("queue: at capacity")
)

type item struct {
	ID                  int64  `gorm:"column:id;primaryKey"`
	EnrollmentID        string `gorm:"column:enrollment_id;uniqueIndex"`
	PubkeyHash          string `gorm:"column:pubkey_hash"`
	RequestJWS          []byte `gorm:"column:request_jws"`
	RetrievalSecretHash []byte `gorm:"column:retrieval_secret_hash"`
	ReceivedAt          int64  `gorm:"column:received_at"`
	MAC                 []byte `gorm:"column:mac"`
	Status              string `gorm:"column:status"`
	Attempts            int    `gorm:"column:attempts"`
	LeaseUntil          int64  `gorm:"column:lease_until"`
}

func (item) TableName() string { return "queue_items" }

// DurableConfig tunes the queue.
type DurableConfig struct {
	DSN         string // sqlite DSN (its own file)
	Key         []byte // gateway↔Core HMAC key (>=16 bytes)
	MaxDepth    int    // backpressure threshold (0 = default 10000)
	MaxAttempts int    // poison threshold (0 = default 5)
}

// OpenDurable opens (and creates) the queue store.
func OpenDurable(cfg DurableConfig) (*Durable, error) {
	if len(cfg.Key) < 16 {
		return nil, fmt.Errorf("queue: HMAC key must be >= 16 bytes")
	}
	db, err := gorm.Open(sqlite.Open(cfg.DSN), &gorm.Config{
		Logger:                 logger.Default.LogMode(logger.Silent),
		SkipDefaultTransaction: true,
		TranslateError:         true,
	})
	if err != nil {
		return nil, fmt.Errorf("queue: open %s: %w", cfg.DSN, err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		return nil, err
	}
	sqlDB.SetMaxOpenConns(1)
	if err := db.AutoMigrate(&item{}); err != nil {
		return nil, fmt.Errorf("queue: migrate: %w", err)
	}
	d := &Durable{db: db, key: cfg.Key, maxDepth: cfg.MaxDepth, maxAttempts: cfg.MaxAttempts, now: time.Now}
	if d.maxDepth <= 0 {
		d.maxDepth = 10000
	}
	if d.maxAttempts <= 0 {
		d.maxAttempts = 5
	}
	return d, nil
}

// Close releases the queue store.
func (d *Durable) Close() error {
	sqlDB, err := d.db.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}

// Publish appends an authenticated message. Re-publishing the same
// enrollment_id is an idempotent no-op (ErrDuplicate). Returns ErrBackpressure
// when the queue is at capacity.
func (d *Durable) Publish(ctx context.Context, c Candidate) error {
	var depth int64
	if err := d.db.WithContext(ctx).Model(&item{}).
		Where("status IN ?", []string{statusReady, statusInflight}).Count(&depth).Error; err != nil {
		return fmt.Errorf("queue: depth: %w", err)
	}
	if int(depth) >= d.maxDepth {
		return ErrBackpressure
	}
	it := item{
		EnrollmentID: c.EnrollmentID, PubkeyHash: c.PubkeyHash, RequestJWS: c.RequestJWS,
		RetrievalSecretHash: c.RetrievalSecretHash, ReceivedAt: c.ReceivedAt.UnixNano(),
		Status: statusReady,
	}
	it.MAC = d.mac(it)
	err := d.db.WithContext(ctx).Create(&it).Error
	if errors.Is(err, gorm.ErrDuplicatedKey) {
		return ErrDuplicate
	}
	if err != nil {
		return fmt.Errorf("queue: publish: %w", err)
	}
	return nil
}

// Leased is a claimed message plus its delivery handle.
type Leased struct {
	ID        int64
	Candidate Candidate
	Attempts  int
}

// Claim leases up to limit ready messages for leaseTTL. Messages whose MAC fails
// verification are dead-lettered (poison) and never delivered.
func (d *Durable) Claim(ctx context.Context, limit int, leaseTTL time.Duration) ([]Leased, error) {
	now := d.now().UnixNano()
	// Reclaim expired in-flight leases.
	if err := d.db.WithContext(ctx).Model(&item{}).
		Where("status = ? AND lease_until <= ?", statusInflight, now).
		Update("status", statusReady).Error; err != nil {
		return nil, fmt.Errorf("queue: reclaim: %w", err)
	}

	var rows []item
	if err := d.db.WithContext(ctx).Where("status = ?", statusReady).
		Order("id").Limit(limit).Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("queue: claim select: %w", err)
	}

	var out []Leased
	for _, it := range rows {
		if !hmac.Equal(it.MAC, d.mac(it)) {
			// Forged/tampered message — dead-letter it, don't deliver.
			d.db.WithContext(ctx).Model(&item{}).Where("id = ?", it.ID).Update("status", statusDead)
			continue
		}
		res := d.db.WithContext(ctx).Model(&item{}).
			Where("id = ? AND status = ?", it.ID, statusReady).
			Updates(map[string]any{
				"status": statusInflight, "lease_until": d.now().Add(leaseTTL).UnixNano(),
				"attempts": gorm.Expr("attempts + 1"),
			})
		if res.RowsAffected == 0 {
			continue // raced
		}
		out = append(out, Leased{
			ID:       it.ID,
			Attempts: it.Attempts + 1,
			Candidate: Candidate{
				EnrollmentID: it.EnrollmentID, PubkeyHash: it.PubkeyHash,
				RequestJWS: it.RequestJWS, RetrievalSecretHash: it.RetrievalSecretHash,
				ReceivedAt: time.Unix(0, it.ReceivedAt),
			},
		})
	}
	return out, nil
}

// Ack removes a successfully processed message.
func (d *Durable) Ack(ctx context.Context, id int64) error {
	return d.db.WithContext(ctx).Delete(&item{}, id).Error
}

// Nack returns a message for redelivery, or dead-letters it once it has burned
// through maxAttempts (poison handling).
func (d *Durable) Nack(ctx context.Context, id int64) error {
	var it item
	if err := d.db.WithContext(ctx).First(&it, id).Error; err != nil {
		return err
	}
	if it.Attempts >= d.maxAttempts {
		return d.db.WithContext(ctx).Model(&item{}).Where("id = ?", id).Update("status", statusDead).Error
	}
	return d.db.WithContext(ctx).Model(&item{}).Where("id = ?", id).
		Updates(map[string]any{"status": statusReady, "lease_until": 0}).Error
}

// Depth reports ready+inflight messages (for metrics/backpressure visibility).
func (d *Durable) Depth(ctx context.Context) (int, error) {
	var n int64
	err := d.db.WithContext(ctx).Model(&item{}).Where("status IN ?", []string{statusReady, statusInflight}).Count(&n).Error
	return int(n), err
}

func (d *Durable) mac(it item) []byte {
	h := hmac.New(sha256.New, d.key)
	writeField(h, []byte(it.EnrollmentID))
	writeField(h, []byte(it.PubkeyHash))
	writeField(h, it.RequestJWS)
	writeField(h, it.RetrievalSecretHash)
	return h.Sum(nil)
}

func writeField(h interface{ Write([]byte) (int, error) }, b []byte) {
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(len(b)))
	_, _ = h.Write(n[:])
	_, _ = h.Write(b)
}
