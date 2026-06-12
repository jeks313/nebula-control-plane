// Package queue carries vetted enrollment candidates from the credential-less
// gateway to Core (protocol §5, implementation-plan 3.3/3.3a). The gateway only
// publishes; Core is the sole consumer and re-verifies everything. v1 ships an
// in-process Memory queue for the minimal local footprint; 3.3a swaps in a
// durable, authenticated queue (SQLite/SQS/NATS) behind this interface.
package queue

import (
	"context"
	"sync"
	"time"
)

// Candidate is what the gateway hands Core after structural validation. Core
// re-verifies RequestJWS + nonce + credential — the gateway is not trusted to
// have authorized anything.
type Candidate struct {
	EnrollmentID        string
	PubkeyHash          string
	RequestJWS          []byte // raw flattened JWS bytes as received
	RetrievalSecretHash []byte // SHA-256 of the secret returned to the client
	ReceivedAt          time.Time
}

// Queue is the publish side used by the gateway.
type Queue interface {
	Publish(ctx context.Context, c Candidate) error
}

// Memory is an in-process FIFO queue (dev/local). Core drains it.
type Memory struct {
	mu    sync.Mutex
	items []Candidate
}

// NewMemory returns an empty in-memory queue.
func NewMemory() *Memory { return &Memory{} }

// Publish appends a candidate.
func (m *Memory) Publish(_ context.Context, c Candidate) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.items = append(m.items, c)
	return nil
}

// Drain returns and clears all pending candidates (Core consumer / tests).
func (m *Memory) Drain() []Candidate {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := m.items
	m.items = nil
	return out
}

// Len reports the number of pending candidates.
func (m *Memory) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.items)
}
