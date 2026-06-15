// Package dualcontrol is Harbor's reusable two-person / dual-control approval
// primitive (implementation-plan 2.11). A privileged change is *proposed* by one
// authenticated admin and takes effect only once a second, distinct admin signs
// off: no single identity can both propose and approve (the maker-checker rule).
//
// It is generic over the change Kind so policy publish (6.5), bulk revoke (7.2),
// privileged group grants and CA/key rotation all reuse one audited workflow
// rather than reinventing maker-checker per feature. Callers register a
// Committer per Kind; the committer runs only after quorum is reached, and the
// change is marked committed only if the committer succeeds (fail-closed, P8).
//
// Every transition — propose, approve, deny, commit, and rejected attempts
// (self-approval, duplicate signer) — is written to the hash-chained audit log.
package dualcontrol

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
	"time"

	"gorm.io/gorm"
)

// State is a change's lifecycle position. pending and the three terminals.
type State string

// Dual-control change lifecycle states.
const (
	StatePending    State = "pending"
	StateCommitting State = "committing" // transient: an approver won the commit claim and is running the committer
	StateCommitted  State = "committed"
	StateDenied     State = "denied"
	StateFailed     State = "failed" // quorum reached but the committer errored
)

// Decision is one admin's vote on a change.
const (
	decisionApprove = "approve"
	decisionDeny    = "deny"
)

// Errors callers can branch on.
var (
	ErrNotFound       = errors.New("dualcontrol: change not found")
	ErrNotPending     = errors.New("dualcontrol: change is not pending")
	ErrSelfApproval   = errors.New("dualcontrol: proposer cannot approve their own change (two-person rule)")
	ErrDuplicateActor = errors.New("dualcontrol: this actor has already signed off on the change")
	ErrNoProposer     = errors.New("dualcontrol: a proposer identity is required")
	ErrNoActor        = errors.New("dualcontrol: an actor identity is required")
	// ErrCommit wraps a committer's business failure (quorum was reached but the
	// effect was rejected/failed) so callers can distinguish it from infra errors.
	ErrCommit = errors.New("dualcontrol: commit failed")
)

// Change is one privileged change awaiting (or past) dual control.
type Change struct {
	ID          int64  `gorm:"column:id;primaryKey"`
	Kind        string `gorm:"column:kind"`
	Target      string `gorm:"column:target"`
	Payload     []byte `gorm:"column:payload"`
	PayloadHash []byte `gorm:"column:payload_hash"`
	State       string `gorm:"column:state"`
	Quorum      int    `gorm:"column:quorum"`
	Proposer    string `gorm:"column:proposer"`
	CreatedAt   int64  `gorm:"column:created_at"` // unix ns
	DecidedAt   int64  `gorm:"column:decided_at"` // unix ns; 0 while pending
}

// TableName pins the table.
func (Change) TableName() string { return "approvals" }

// Signoff is one admin's recorded vote on a change.
type Signoff struct {
	ID        int64  `gorm:"column:id;primaryKey"`
	ChangeID  int64  `gorm:"column:change_id"`
	Actor     string `gorm:"column:actor"`
	Decision  string `gorm:"column:decision"`
	CreatedAt int64  `gorm:"column:created_at"`
}

// TableName pins the table.
func (Signoff) TableName() string { return "approval_signoffs" }

// AuditFunc appends one row to the hash-chained audit log.
type AuditFunc func(ctx context.Context, actor, action, target, details string) error

// Committer applies an approved change's payload. It runs exactly once, after
// quorum is reached. If it returns an error the change is marked StateFailed and
// nothing takes effect.
type Committer func(ctx context.Context, c Change) error

// Config builds a Controller.
type Config struct {
	DB     *gorm.DB
	Audit  AuditFunc        // optional; no-op if nil
	Quorum int              // distinct approvers required (min 2)
	Now    func() time.Time // injectable clock for tests
}

// Controller runs the dual-control workflow over the approvals tables.
type Controller struct {
	cfg        Config
	mu         sync.RWMutex
	committers map[string]Committer
}

// New builds a Controller. Quorum is clamped to a minimum of 2 — dual control
// is, definitionally, at least two people.
func New(cfg Config) *Controller {
	if cfg.Quorum < 2 {
		cfg.Quorum = 2
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Controller{cfg: cfg, committers: map[string]Committer{}}
}

// DB returns the underlying connection (used to build sibling controllers that
// share the same store).
func (c *Controller) DB() *gorm.DB { return c.cfg.DB }

// Register binds a committer to a change Kind. Without one, an approved change
// still records its quorum but applies a no-op (useful when "latest committed"
// is itself the effect, as with policy publish).
func (c *Controller) Register(kind string, fn Committer) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.committers[kind] = fn
}

func (c *Controller) committer(kind string) Committer {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.committers[kind]
}

// Propose records a new pending change and counts the proposer as the first
// sign-off. Reaching quorum therefore needs (quorum-1) *distinct* checkers.
func (c *Controller) Propose(ctx context.Context, kind, target string, payload []byte, proposer string) (Change, error) {
	if proposer == "" {
		return Change{}, ErrNoProposer
	}
	sum := sha256.Sum256(payload)
	now := c.cfg.Now().UTC().UnixNano()
	ch := Change{
		Kind: kind, Target: target, Payload: payload, PayloadHash: sum[:],
		State: string(StatePending), Quorum: c.cfg.Quorum, Proposer: proposer, CreatedAt: now,
	}
	err := c.cfg.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&ch).Error; err != nil {
			return err
		}
		return tx.Create(&Signoff{ChangeID: ch.ID, Actor: proposer, Decision: decisionApprove, CreatedAt: now}).Error
	})
	if err != nil {
		return Change{}, fmt.Errorf("dualcontrol: propose: %w", err)
	}
	c.audit(ctx, proposer, "dualcontrol-propose", c.target(ch),
		fmt.Sprintf("kind=%s quorum=%d hash=%x", kind, ch.Quorum, ch.PayloadHash))
	return ch, nil
}

// Approve records actor's approval. When the distinct-approver count reaches the
// change's quorum, the registered committer runs; on success the change becomes
// committed, on failure StateFailed. A proposer approving their own change, or
// any actor signing twice, is rejected and audited.
func (c *Controller) Approve(ctx context.Context, id int64, actor string) (Change, error) {
	if actor == "" {
		return Change{}, ErrNoActor
	}
	var (
		ch            Change
		quorumReached bool
	)
	err := c.cfg.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := loadPending(tx, id, &ch); err != nil {
			return err
		}
		if actor == ch.Proposer {
			return ErrSelfApproval
		}
		var dup int64
		if err := tx.Model(&Signoff{}).Where("change_id = ? AND actor = ?", id, actor).Count(&dup).Error; err != nil {
			return err
		}
		if dup > 0 {
			return ErrDuplicateActor
		}
		now := c.cfg.Now().UTC().UnixNano()
		if err := tx.Create(&Signoff{ChangeID: id, Actor: actor, Decision: decisionApprove, CreatedAt: now}).Error; err != nil {
			return err
		}
		var approvals int64
		if err := tx.Model(&Signoff{}).
			Where("change_id = ? AND decision = ?", id, decisionApprove).
			Count(&approvals).Error; err != nil {
			return err
		}
		quorumReached = approvals >= int64(ch.Quorum)
		return nil
	})
	if err != nil {
		// Audit rejected attempts too — a blocked single-approver publish is a
		// security-relevant event.
		switch {
		case errors.Is(err, ErrSelfApproval), errors.Is(err, ErrDuplicateActor):
			c.audit(ctx, actor, "dualcontrol-approve-blocked", c.target(ch), err.Error())
		}
		return Change{}, err
	}

	if !quorumReached {
		c.audit(ctx, actor, "dualcontrol-approve", c.target(ch), "awaiting further approval")
		return c.reload(ctx, id)
	}

	// Quorum reached. Atomically CLAIM the commit so exactly one approver runs the
	// committer even if two reach quorum concurrently: a compare-and-set on the
	// pending->committing transition. Dialect-agnostic (no FOR UPDATE needed; the
	// SQLite path is single-writer anyway, the Postgres path serializes on this
	// UPDATE). The committer runs outside the signoff tx so a commit failure still
	// leaves the sign-off durable + the change marked failed.
	claim := c.cfg.DB.WithContext(ctx).Model(&Change{}).
		Where("id = ? AND state = ?", id, string(StatePending)).
		Update("state", string(StateCommitting))
	if claim.Error != nil {
		return Change{}, fmt.Errorf("dualcontrol: claim commit: %w", claim.Error)
	}
	if claim.RowsAffected == 0 {
		// Another approver already won the race (committing/committed). Not an error.
		return c.reload(ctx, id)
	}

	if fn := c.committer(ch.Kind); fn != nil {
		if cerr := fn(ctx, ch); cerr != nil {
			c.finalize(ctx, id, StateFailed)
			c.audit(ctx, actor, "dualcontrol-commit-failed", c.target(ch), cerr.Error())
			out, _ := c.reload(ctx, id)
			return out, fmt.Errorf("%w: %w", ErrCommit, cerr)
		}
	}
	c.finalize(ctx, id, StateCommitted)
	c.audit(ctx, actor, "dualcontrol-commit", c.target(ch),
		fmt.Sprintf("kind=%s quorum=%d hash=%x", ch.Kind, ch.Quorum, ch.PayloadHash))
	return c.reload(ctx, id)
}

// Deny vetoes a pending change. A single deny is sufficient (fail-closed): one
// objecting reviewer stops the change. The proposer may deny to withdraw.
func (c *Controller) Deny(ctx context.Context, id int64, actor, reason string) (Change, error) {
	if actor == "" {
		return Change{}, ErrNoActor
	}
	var ch Change
	err := c.cfg.DB.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := loadPending(tx, id, &ch); err != nil {
			return err
		}
		now := c.cfg.Now().UTC().UnixNano()
		// Record the deny vote unless this actor already voted (best-effort).
		var dup int64
		tx.Model(&Signoff{}).Where("change_id = ? AND actor = ?", id, actor).Count(&dup)
		if dup == 0 {
			if err := tx.Create(&Signoff{ChangeID: id, Actor: actor, Decision: decisionDeny, CreatedAt: now}).Error; err != nil {
				return err
			}
		}
		return tx.Model(&Change{}).Where("id = ?", id).
			Updates(map[string]any{"state": string(StateDenied), "decided_at": now}).Error
	})
	if err != nil {
		return Change{}, err
	}
	c.audit(ctx, actor, "dualcontrol-deny", c.target(ch), reason)
	return c.reload(ctx, id)
}

// Get returns a change and its sign-offs.
func (c *Controller) Get(ctx context.Context, id int64) (Change, []Signoff, error) {
	var ch Change
	if err := c.cfg.DB.WithContext(ctx).First(&ch, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return Change{}, nil, ErrNotFound
		}
		return Change{}, nil, err
	}
	var sigs []Signoff
	if err := c.cfg.DB.WithContext(ctx).Where("change_id = ?", id).Order("created_at ASC").Find(&sigs).Error; err != nil {
		return Change{}, nil, err
	}
	return ch, sigs, nil
}

// List returns changes filtered by state ("" = all), newest first.
func (c *Controller) List(ctx context.Context, state State) ([]Change, error) {
	q := c.cfg.DB.WithContext(ctx).Order("id DESC")
	if state != "" {
		q = q.Where("state = ?", string(state))
	}
	var out []Change
	if err := q.Find(&out).Error; err != nil {
		return nil, err
	}
	return out, nil
}

// LatestCommitted returns the most recently committed change of a kind. Policy
// publish uses this: the active policy *is* the latest committed policy.publish.
func (c *Controller) LatestCommitted(ctx context.Context, kind string) (Change, bool, error) {
	var ch Change
	err := c.cfg.DB.WithContext(ctx).
		Where("kind = ? AND state = ?", kind, string(StateCommitted)).
		Order("id DESC").First(&ch).Error
	switch {
	case err == nil:
		return ch, true, nil
	case errors.Is(err, gorm.ErrRecordNotFound):
		return Change{}, false, nil
	default:
		return Change{}, false, err
	}
}

func loadPending(tx *gorm.DB, id int64, ch *Change) error {
	if err := tx.First(ch, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrNotFound
		}
		return err
	}
	if State(ch.State) != StatePending {
		return ErrNotPending
	}
	return nil
}

func (c *Controller) finalize(ctx context.Context, id int64, state State) {
	now := c.cfg.Now().UTC().UnixNano()
	c.cfg.DB.WithContext(ctx).Model(&Change{}).Where("id = ?", id).
		Updates(map[string]any{"state": string(state), "decided_at": now})
}

func (c *Controller) reload(ctx context.Context, id int64) (Change, error) {
	var ch Change
	if err := c.cfg.DB.WithContext(ctx).First(&ch, "id = ?", id).Error; err != nil {
		return Change{}, err
	}
	return ch, nil
}

func (c *Controller) audit(ctx context.Context, actor, action, target, details string) {
	if c.cfg.Audit == nil {
		return
	}
	_ = c.cfg.Audit(ctx, actor, action, target, details)
}

func (c *Controller) target(ch Change) string {
	if ch.Target != "" {
		return ch.Target
	}
	return fmt.Sprintf("%s#%d", ch.Kind, ch.ID)
}
