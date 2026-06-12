package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"time"

	"gorm.io/gorm"
)

// hashLen is the chain digest size (SHA-256).
const hashLen = sha256.Size

// genesisPrev is the prev_hash of the first row: 32 zero bytes.
var genesisPrev = make([]byte, hashLen)

// auditHash computes a row's hash. Every field that defines the row — including
// its sequence number and the previous row's hash — is committed to, so any
// content change, reorder, or gap is detectable. Fields are length-prefixed so
// no concatenation ambiguity exists (e.g. actor="a",action="bc" can't collide
// with actor="ab",action="c").
func auditHash(e Audit) []byte {
	h := sha256.New()
	writeUint(h, uint64(e.Seq))
	writeUint(h, uint64(e.TS))
	writeField(h, []byte(e.Actor))
	writeField(h, []byte(e.Action))
	writeField(h, []byte(e.Target))
	writeField(h, []byte(e.Details))
	writeField(h, e.PrevHash)
	return h.Sum(nil)
}

func writeUint(h hash.Hash, v uint64) {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	_, _ = h.Write(b[:])
}

func writeField(h hash.Hash, b []byte) {
	writeUint(h, uint64(len(b)))
	_, _ = h.Write(b)
}

// AppendAudit adds a row to the chain and returns it. Appends are serialized
// (single logical writer) so the prev-hash link is always correct; for HA Harbor
// with multiple Core writers this needs a DB advisory lock (tracked for M9.5).
func (s *Store) AppendAudit(ctx context.Context, actor, action, target, details string) (Audit, error) {
	s.auditMu.Lock()
	defer s.auditMu.Unlock()

	var e Audit
	err := s.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var last Audit
		seq := int64(1)
		prev := genesisPrev
		switch err := tx.Order("seq DESC").First(&last).Error; {
		case err == nil:
			seq = last.Seq + 1
			prev = last.Hash
		case errors.Is(err, gorm.ErrRecordNotFound):
			// genesis row
		default:
			return err
		}

		e = Audit{
			Seq:      seq,
			TS:       time.Now().UTC().UnixNano(),
			Actor:    actor,
			Action:   action,
			Target:   target,
			Details:  details,
			PrevHash: prev,
		}
		e.Hash = auditHash(e)
		return tx.Create(&e).Error
	})
	if err != nil {
		return Audit{}, fmt.Errorf("store: append audit: %w", err)
	}
	return e, nil
}

// VerifyAudit walks the whole chain in order and returns the number of rows
// verified. It returns an error at the first inconsistency — a recomputed-hash
// mismatch (content tampered), a broken prev-hash link (row removed/reordered),
// or a sequence gap.
func (s *Store) VerifyAudit(ctx context.Context) (int64, error) {
	rows, err := s.audit(ctx)
	if err != nil {
		return 0, err
	}
	prev := genesisPrev
	var want int64 = 1
	for _, r := range rows {
		if r.Seq != want {
			return want - 1, fmt.Errorf("store: audit chain: expected seq %d, got %d (gap or reorder)", want, r.Seq)
		}
		if !bytes.Equal(r.PrevHash, prev) {
			return r.Seq - 1, fmt.Errorf("store: audit chain: broken link at seq %d", r.Seq)
		}
		if !bytes.Equal(r.Hash, auditHash(r)) {
			return r.Seq - 1, fmt.Errorf("store: audit chain: hash mismatch at seq %d (row tampered)", r.Seq)
		}
		prev = r.Hash
		want++
	}
	return want - 1, nil
}

func (s *Store) audit(ctx context.Context) ([]Audit, error) {
	var rows []Audit
	if err := s.DB.WithContext(ctx).Order("seq ASC").Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("store: read audit: %w", err)
	}
	return rows, nil
}
