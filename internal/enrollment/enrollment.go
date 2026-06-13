// Package enrollment is Core's authoritative enrollment consumer
// (implementation-plan 3.4/3.5). It drains vetted candidates from the queue and,
// trusting the gateway for nothing, re-verifies the request JWS + nonce (with a
// replay cache), validates and consumes a join key, resolves groups from that
// key, and decides issue-vs-PENDING. Bearer-secret (join-key) joins default to
// PENDING manual approval (design §4.1c); only a key with auto_issue mints a
// cert immediately. Attestation methods (M5) will be allowed to auto-issue.
package enrollment

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/bundle"
	"github.com/jeks313/nebula-control-plane/internal/ipam"
	"github.com/jeks313/nebula-control-plane/internal/joinkey"
	"github.com/jeks313/nebula-control-plane/internal/jws"
	"github.com/jeks313/nebula-control-plane/internal/nonce"
	"github.com/jeks313/nebula-control-plane/internal/policy"
	"github.com/jeks313/nebula-control-plane/internal/queue"
	"github.com/jeks313/nebula-control-plane/internal/replay"
	"github.com/jeks313/nebula-control-plane/internal/signer"
	"github.com/jeks313/nebula-control-plane/internal/store"
	"github.com/jeks313/nebula-control-plane/internal/wire"
	"gorm.io/gorm"
)

// Statuses.
const (
	StatusPending = "pending"
	StatusIssued  = "issued"
	StatusDenied  = "denied"
)

// Errors surfaced to the caller (the wire delivery layer maps these to the
// protocol error model).
var (
	ErrBadRequest = errors.New("enrollment: malformed request")
	ErrSignature  = errors.New("enrollment: request signature invalid")
	ErrNonce      = errors.New("enrollment: nonce invalid")
	ErrReplay     = errors.New("enrollment: nonce replay")
	ErrMethod     = errors.New("enrollment: unsupported method")
	ErrNotPending = errors.New("enrollment: not a pending enrollment")
	ErrQuota      = errors.New("enrollment: join-key enrollment quota exceeded")
)

// Enrollment is a persisted enrollment attempt (the PENDING queue + result).
type Enrollment struct {
	ID           int64  `gorm:"column:id;primaryKey"`
	EnrollmentID string `gorm:"column:enrollment_id"`
	DeviceName   string `gorm:"column:device_name"`
	PubkeyHash   string `gorm:"column:pubkey_hash"`
	Pubkey       []byte `gorm:"column:pubkey"`
	Method       string `gorm:"column:method"`
	JoinKeyID    int64  `gorm:"column:join_key_id"`
	Groups       string `gorm:"column:groups"`
	Status       string `gorm:"column:status"`
	CertPEM      []byte `gorm:"column:cert_pem"`
	OverlayIP    string `gorm:"column:overlay_ip"`
	CreatedAt    int64  `gorm:"column:created_at"`
	DecidedAt    int64  `gorm:"column:decided_at"`
	Approver     string `gorm:"column:approver"`
}

func (Enrollment) TableName() string { return "enrollments" }

// Result summarizes a processed enrollment.
type Result struct {
	EnrollmentID string
	Status       string
	OverlayIP    string
	CertPEM      []byte
}

// Config builds a Consumer.
type Config struct {
	Store        *store.Store
	Nonces       *nonce.Keyring
	Replay       *replay.Cache
	Signer       *signer.Signer
	Allocator    *ipam.Allocator
	Pool         netip.Prefix
	CertLifetime time.Duration
	EnrollWindow time.Duration // per-key quota window (0 -> 1h)
	Now          func() time.Time

	// Bundle assembly + delivery (3.6/3.6a). Optional: if ConfigBackend/Results
	// are nil, the enrollment is still recorded but no signed bundle/result is
	// produced (used by lower-level tests).
	ConfigBackend signer.Backend // config-signing key (signs bundles)
	ConfigKeyID   string         // its kid (pinned by Pilot)
	CABundlePEM   []byte         // CA cert PEM for the bundle's ca_bundle
	Lighthouses   []bundle.Lighthouse
	// LighthouseSource, if set, is consulted at bundle-build time so registry
	// changes (6.8) propagate live; overrides Lighthouses, with a fallback to it
	// on error (a transient registry read must not sever discovery).
	LighthouseSource func(context.Context) ([]bundle.Lighthouse, error)
	Policy           *policy.Policy // central firewall (M6); nil -> Pilot's local default
	Results          *queue.Durable // result store (gateway↔Core shared store)
	ResultTTL        time.Duration  // result/ticket validity (0 -> 1h)
}

// Consumer processes enrollment candidates.
type Consumer struct {
	cfg Config
	now func() time.Time
}

// New builds a Consumer.
func New(cfg Config) *Consumer {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Consumer{cfg: cfg, now: cfg.Now}
}

// Drain claims a batch from the durable queue, processes each, and acks
// terminal outcomes (success or a recorded business decision) while nacking
// transient/infra failures for redelivery (poison handling lives in the queue).
func (c *Consumer) Drain(ctx context.Context, q *queue.Durable, batch int, lease time.Duration) (int, error) {
	leased, err := q.Claim(ctx, batch, lease)
	if err != nil {
		return 0, err
	}
	for _, l := range leased {
		_, perr := c.Process(ctx, l.Candidate)
		if perr == nil || terminal(perr) {
			_ = q.Ack(ctx, l.ID)
		} else {
			_ = q.Nack(ctx, l.ID)
		}
	}
	return len(leased), nil
}

// terminal reports whether an error is a final business outcome (don't retry)
// vs. a transient/infra failure (retry).
func terminal(err error) bool {
	for _, t := range []error{
		ErrBadRequest, ErrSignature, ErrNonce, ErrReplay, ErrMethod, ErrQuota,
		joinkey.ErrNotFound, joinkey.ErrExpired, joinkey.ErrExhausted,
	} {
		if errors.Is(err, t) {
			return true
		}
	}
	return false
}

// Process handles one queued candidate end to end. It is idempotent: a redelivered
// candidate (same enrollment_id) returns the recorded result without re-issuing.
func (c *Consumer) Process(ctx context.Context, cand queue.Candidate) (Result, error) {
	if r, ok := c.existing(ctx, cand.EnrollmentID); ok {
		return r, nil
	}
	req, pubBytes, err := c.verify(ctx, cand)
	if err != nil {
		return Result{}, err
	}
	if req.Method != wire.MethodToken {
		return Result{}, fmt.Errorf("%w: %q (only token/join-key is implemented; attestation is M5)", ErrMethod, req.Method)
	}

	// Validate + consume the join key.
	var cred struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal(req.Credential, &cred)
	jk, err := joinkey.Lookup(ctx, c.cfg.Store, cred.Token, c.now())
	if err != nil {
		c.deny(ctx, cand, req, pubBytes, "enroll-denied", err.Error())
		return Result{EnrollmentID: cand.EnrollmentID, Status: StatusDenied}, err
	}

	// Per-key enrollment rate quota (3.10): a leaked/reusable key can't mint a
	// fleet. Checked before consuming a use; blocks both auto-issue and pending.
	if jk.QuotaPerHour > 0 {
		n, qerr := c.recentEnrollments(ctx, jk.ID)
		if qerr != nil {
			return Result{}, qerr // transient -> retry
		}
		if n >= jk.QuotaPerHour {
			reason := fmt.Sprintf("join-key %q quota %d/h exceeded", jk.Name, jk.QuotaPerHour)
			c.deny(ctx, cand, req, pubBytes, "enroll-quota-exceeded", reason)
			return Result{EnrollmentID: cand.EnrollmentID, Status: StatusDenied}, ErrQuota
		}
	}

	if err := joinkey.Consume(ctx, c.cfg.Store, jk); err != nil {
		c.deny(ctx, cand, req, pubBytes, "enroll-denied", err.Error())
		return Result{EnrollmentID: cand.EnrollmentID, Status: StatusDenied}, err
	}

	groups := jk.Groups
	deviceName := deviceName(req, cand.PubkeyHash)

	// Approval decision: bearer secrets are PENDING by default.
	if !jk.AutoIssue {
		c.record(ctx, cand.EnrollmentID, req, pubBytes, jk.ID, groups, StatusPending, nil, "")
		c.writeResult(ctx, cand.EnrollmentID, cand.RetrievalSecretHash, nil, StatusPending, "")
		_ = c.audit(ctx, "system", "enroll-pending", deviceName,
			fmt.Sprintf(`{"join_key":%q,"reason":"manual approval required"}`, jk.Name))
		return Result{EnrollmentID: cand.EnrollmentID, Status: StatusPending}, nil
	}

	// auto_issue: mint immediately.
	ip, certPEM, notAfter, err := c.issue(ctx, "enroll-auto", deviceName, pubBytes, jk.GroupList())
	if err != nil {
		return Result{}, err
	}
	bundleJWS, err := c.buildBundle(ctx, deviceName, ip.String(), jk.GroupList(), certPEM, notAfter)
	if err != nil {
		return Result{}, err
	}
	c.record(ctx, cand.EnrollmentID, req, pubBytes, jk.ID, groups, StatusIssued, certPEM, ip.String())
	c.writeResult(ctx, cand.EnrollmentID, cand.RetrievalSecretHash, bundleJWS, StatusIssued, "")
	return Result{EnrollmentID: cand.EnrollmentID, Status: StatusIssued, OverlayIP: ip.String(), CertPEM: certPEM}, nil
}

// Approve issues a cert for a PENDING enrollment (the 3.9 workflow adds RBAC +
// dual-control on top of this primitive).
func (c *Consumer) Approve(ctx context.Context, enrollmentID, approver string) (Result, error) {
	var e Enrollment
	err := c.cfg.Store.DB.WithContext(ctx).Where("enrollment_id = ?", enrollmentID).First(&e).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return Result{}, ErrNotPending
	}
	if err != nil {
		return Result{}, err
	}
	if e.Status != StatusPending {
		return Result{}, ErrNotPending
	}

	var groups []string
	_ = json.Unmarshal([]byte(e.Groups), &groups)
	ip, certPEM, notAfter, err := c.issue(ctx, approver, e.DeviceName, e.Pubkey, groups)
	if err != nil {
		return Result{}, err
	}
	// Compare-and-set the issuance: commit the cert ONLY if the row is still
	// pending, so a concurrent deny cannot leave a host marked denied while we
	// deliver it a cert (and two approves cannot both win). If we lose the race,
	// the bundle is never delivered (writeResult below is skipped) — the signed
	// cert is therefore never handed to the host and is unusable — and we release
	// the IP we speculatively allocated so it does not leak.
	now := c.now().UnixNano()
	claim := c.cfg.Store.DB.WithContext(ctx).Model(&Enrollment{}).
		Where("enrollment_id = ? AND status = ?", enrollmentID, StatusPending).
		Updates(map[string]any{
			"status": StatusIssued, "cert_pem": certPEM, "overlay_ip": ip.String(),
			"decided_at": now, "approver": approver,
		})
	if claim.Error != nil {
		_ = c.cfg.Allocator.Release(ctx, ip)
		return Result{}, claim.Error
	}
	if claim.RowsAffected == 0 {
		_ = c.cfg.Allocator.Release(ctx, ip)
		return Result{}, ErrNotPending // another mutator decided it first; cert undelivered
	}
	// We won the claim — deliver the bundle (secret hash preserved from the pending row).
	bundleJWS, err := c.buildBundle(ctx, e.DeviceName, ip.String(), groups, certPEM, notAfter)
	if err != nil {
		return Result{}, err
	}
	c.writeResult(ctx, enrollmentID, nil, bundleJWS, StatusIssued, "")
	_ = c.audit(ctx, approver, "enroll-approved", e.DeviceName, fmt.Sprintf(`{"overlay_ip":%q}`, ip))
	return Result{EnrollmentID: enrollmentID, Status: StatusIssued, OverlayIP: ip.String(), CertPEM: certPEM}, nil
}

// Deny rejects a PENDING enrollment: it records the decision and flips the poll
// result to denied so the waiting host learns it was rejected. No signing — works
// on a Store-only Consumer (the admin queue's reject action, 3.9).
func (c *Consumer) Deny(ctx context.Context, enrollmentID, approver, reason string) (Result, error) {
	var e Enrollment
	err := c.cfg.Store.DB.WithContext(ctx).Where("enrollment_id = ?", enrollmentID).First(&e).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return Result{}, ErrNotPending
	}
	if err != nil {
		return Result{}, err
	}
	if e.Status != StatusPending {
		return Result{}, ErrNotPending
	}
	// Compare-and-set the transition so a concurrent approve/deny on the same row
	// cannot both win (the read above is only a friendly fast-path; this UPDATE is
	// the real gate). Mirrors the dualcontrol commit-claim: scope the write with
	// `AND status = pending` and treat RowsAffected == 0 as "lost the race". Without
	// this, an approve racing a deny could mint a cert for a host recorded denied.
	now := c.now().UnixNano()
	res := c.cfg.Store.DB.WithContext(ctx).Model(&Enrollment{}).
		Where("enrollment_id = ? AND status = ?", enrollmentID, StatusPending).
		Updates(map[string]any{"status": StatusDenied, "decided_at": now, "approver": approver})
	if res.Error != nil {
		return Result{}, res.Error
	}
	if res.RowsAffected == 0 {
		return Result{}, ErrNotPending // another mutator decided it first
	}
	c.writeResult(ctx, enrollmentID, nil, nil, StatusDenied, reason) // no-op if no result store configured
	_ = c.audit(ctx, approver, "enroll-denied", e.DeviceName, reason)
	return Result{EnrollmentID: enrollmentID, Status: StatusDenied}, nil
}

// deny records a denied enrollment + result + audit (the shared rejection path).
func (c *Consumer) deny(ctx context.Context, cand queue.Candidate, req wire.EnrollRequest, pubBytes []byte, action, reason string) {
	c.record(ctx, cand.EnrollmentID, req, pubBytes, 0, "[]", StatusDenied, nil, "")
	c.writeResult(ctx, cand.EnrollmentID, cand.RetrievalSecretHash, nil, StatusDenied, reason)
	_ = c.audit(ctx, "system", action, req.CSR.RequestedName, reason)
}

// recentEnrollments counts accepted (pending+issued) enrollments for a join key
// within the quota window.
func (c *Consumer) recentEnrollments(ctx context.Context, joinKeyID int64) (int, error) {
	window := c.cfg.EnrollWindow
	if window <= 0 {
		window = time.Hour
	}
	cutoff := c.now().Add(-window).UnixNano()
	var n int64
	err := c.cfg.Store.DB.WithContext(ctx).Model(&Enrollment{}).
		Where("join_key_id = ? AND status IN ? AND created_at > ?",
			joinKeyID, []string{StatusPending, StatusIssued}, cutoff).Count(&n).Error
	if err != nil {
		return 0, fmt.Errorf("enrollment: count quota: %w", err)
	}
	return int(n), nil
}

// existing returns the recorded result for an enrollment_id, if already processed.
func (c *Consumer) existing(ctx context.Context, enrollmentID string) (Result, bool) {
	var e Enrollment
	if err := c.cfg.Store.DB.WithContext(ctx).Where("enrollment_id = ?", enrollmentID).First(&e).Error; err == nil {
		return Result{EnrollmentID: enrollmentID, Status: e.Status, OverlayIP: e.OverlayIP, CertPEM: e.CertPEM}, true
	}
	return Result{}, false
}

// Pending lists enrollments awaiting approval (feeds the admin queue, 3.9).
func (c *Consumer) Pending(ctx context.Context) ([]Enrollment, error) {
	var es []Enrollment
	err := c.cfg.Store.DB.WithContext(ctx).Where("status = ?", StatusPending).Order("id").Find(&es).Error
	return es, err
}

func (c *Consumer) verify(ctx context.Context, cand queue.Candidate) (wire.EnrollRequest, []byte, error) {
	var env jws.Flattened
	if err := json.Unmarshal(cand.RequestJWS, &env); err != nil {
		return wire.EnrollRequest{}, nil, ErrBadRequest
	}
	plBytes, err := jwsPayload(env)
	if err != nil {
		return wire.EnrollRequest{}, nil, ErrBadRequest
	}
	var req wire.EnrollRequest
	if err := json.Unmarshal(plBytes, &req); err != nil || req.Type != "enroll" || req.Nonce == "" {
		return wire.EnrollRequest{}, nil, ErrBadRequest
	}
	pubBytes, err := b64.DecodeString(req.CSR.PublicKey)
	if err != nil || len(pubBytes) != 65 {
		return wire.EnrollRequest{}, nil, ErrBadRequest
	}
	pub, err := jws.ParseP256PublicPoint(pubBytes)
	if err != nil {
		return wire.EnrollRequest{}, nil, ErrBadRequest
	}
	pubkeyHash := wire.PubkeyHash(pubBytes)

	hdr, _, err := jws.Verify(env, pub)
	if err != nil || hdr.Typ != wire.TypEnrollRequest || hdr.Kid != pubkeyHash || pubkeyHash != cand.PubkeyHash {
		return wire.EnrollRequest{}, nil, ErrSignature
	}
	if err := c.cfg.Nonces.Verify(req.Nonce, []byte(pubkeyHash)); err != nil {
		return wire.EnrollRequest{}, nil, ErrNonce
	}
	if c.cfg.Replay != nil && !c.cfg.Replay.Observe(req.Nonce) {
		return wire.EnrollRequest{}, nil, ErrReplay
	}
	return req, pubBytes, nil
}

func (c *Consumer) issue(ctx context.Context, actor, deviceName string, pubBytes []byte, groups []string) (ip netip.Addr, certPEM []byte, notAfter time.Time, err error) {
	ip, err = c.cfg.Allocator.Allocate(ctx, deviceName, "")
	if err != nil {
		return netip.Addr{}, nil, time.Time{}, fmt.Errorf("enrollment: allocate IP: %w", err)
	}
	nb := c.now().Add(-5 * time.Minute)
	notAfter = nb.Add(c.cfg.CertLifetime)
	_, certPEM, err = c.cfg.Signer.Issue(ctx, actor, signer.Template{
		Name:      deviceName,
		Networks:  []netip.Prefix{netip.PrefixFrom(ip, c.cfg.Pool.Bits())},
		Groups:    groups,
		NotBefore: nb,
		NotAfter:  notAfter,
		PublicKey: pubBytes,
	})
	if err != nil {
		_ = c.cfg.Allocator.Release(ctx, ip) // don't leak the IP on a failed sign
		return netip.Addr{}, nil, time.Time{}, fmt.Errorf("enrollment: sign: %w", err)
	}
	return ip, certPEM, notAfter, nil
}

// buildBundle assembles + signs the config bundle (3.6). Returns nil if no
// config-signing backend is configured.
func (c *Consumer) buildBundle(ctx context.Context, deviceName, ip string, groups []string, certPEM []byte, notAfter time.Time) ([]byte, error) {
	if c.cfg.ConfigBackend == nil {
		return nil, nil
	}
	b := bundle.Bundle{
		BundleVersion: 1,
		IssuedAt:      c.now().UTC().Format(time.RFC3339),
		Device:        bundle.Device{Name: deviceName, OverlayIP: ip, Groups: groups},
		Certificate:   string(certPEM),
		CABundle:      []string{string(c.cfg.CABundlePEM)},
		Firewall:      bundle.CompileFirewall(c.cfg.Policy, groups),
		Lighthouses:   c.lighthouses(ctx),
		NotAfter:      notAfter.UTC().Format(time.RFC3339),
	}
	return bundle.Sign(c.cfg.ConfigBackend, c.cfg.ConfigKeyID, b)
}

// lighthouses returns the fleet's lighthouses for a bundle: the live registry
// (6.8) when a source is set, else the static list; a failed read falls back to
// the static list rather than severing discovery.
func (c *Consumer) lighthouses(ctx context.Context) []bundle.Lighthouse {
	if c.cfg.LighthouseSource == nil {
		return c.cfg.Lighthouses
	}
	lhs, err := c.cfg.LighthouseSource(ctx)
	if err != nil || len(lhs) == 0 {
		return c.cfg.Lighthouses
	}
	return lhs
}

// writeResult records a poll result (3.6a). No-op if no result store is set.
func (c *Consumer) writeResult(ctx context.Context, enrollmentID string, secretHash, bundleJWS []byte, status, reason string) {
	if c.cfg.Results == nil {
		return
	}
	ttl := c.cfg.ResultTTL
	if ttl <= 0 {
		ttl = time.Hour
	}
	_ = c.cfg.Results.PutResult(ctx, enrollmentID, status, secretHash, bundleJWS, reason, c.now().Add(ttl))
}

func (c *Consumer) record(ctx context.Context, enrollmentID string, req wire.EnrollRequest, pubBytes []byte, joinKeyID int64, groups, status string, certPEM []byte, ip string) {
	e := Enrollment{
		EnrollmentID: enrollmentID,
		DeviceName:   deviceName(req, wire.PubkeyHash(pubBytes)),
		PubkeyHash:   wire.PubkeyHash(pubBytes),
		Pubkey:       pubBytes,
		Method:       req.Method,
		JoinKeyID:    joinKeyID,
		Groups:       groups,
		Status:       status,
		CertPEM:      certPEM,
		OverlayIP:    ip,
		CreatedAt:    c.now().UnixNano(),
	}
	if status != StatusPending {
		e.DecidedAt = c.now().UnixNano()
	}
	_ = c.cfg.Store.DB.WithContext(ctx).Create(&e).Error
}

func (c *Consumer) audit(ctx context.Context, actor, action, target, details string) error {
	_, err := c.cfg.Store.AppendAudit(ctx, actor, action, target, details)
	return err
}

var b64 = base64.RawURLEncoding

func jwsPayload(env jws.Flattened) ([]byte, error) {
	if env.Payload == "" {
		return nil, ErrBadRequest
	}
	return b64.DecodeString(env.Payload)
}

func deviceName(req wire.EnrollRequest, pubkeyHash string) string {
	if req.CSR.RequestedName != "" {
		return req.CSR.RequestedName
	}
	return "dev-" + pubkeyHash[:10]
}
