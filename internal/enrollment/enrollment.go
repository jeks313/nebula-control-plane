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

	"github.com/jeks313/nebula-control-plane/internal/ipam"
	"github.com/jeks313/nebula-control-plane/internal/joinkey"
	"github.com/jeks313/nebula-control-plane/internal/jws"
	"github.com/jeks313/nebula-control-plane/internal/nonce"
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
	Now          func() time.Time
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

// Process handles one queued candidate end to end.
func (c *Consumer) Process(ctx context.Context, cand queue.Candidate) (Result, error) {
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
	jk, err := joinkey.ValidateAndConsume(ctx, c.cfg.Store, cred.Token, c.now())
	if err != nil {
		c.record(ctx, cand.EnrollmentID, req, pubBytes, 0, "[]", StatusDenied, nil, "")
		_ = c.audit(ctx, "system", "enroll-denied", req.CSR.RequestedName, err.Error())
		return Result{EnrollmentID: cand.EnrollmentID, Status: StatusDenied}, err
	}

	groups := jk.Groups
	deviceName := deviceName(req, cand.PubkeyHash)

	// Approval decision: bearer secrets are PENDING by default.
	if !jk.AutoIssue {
		c.record(ctx, cand.EnrollmentID, req, pubBytes, jk.ID, groups, StatusPending, nil, "")
		_ = c.audit(ctx, "system", "enroll-pending", deviceName,
			fmt.Sprintf(`{"join_key":%q,"reason":"manual approval required"}`, jk.Name))
		return Result{EnrollmentID: cand.EnrollmentID, Status: StatusPending}, nil
	}

	// auto_issue: mint immediately.
	ip, certPEM, err := c.issue(ctx, "enroll-auto", deviceName, pubBytes, jk.GroupList())
	if err != nil {
		return Result{}, err
	}
	c.record(ctx, cand.EnrollmentID, req, pubBytes, jk.ID, groups, StatusIssued, certPEM, ip.String())
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
	ip, certPEM, err := c.issue(ctx, approver, e.DeviceName, e.Pubkey, groups)
	if err != nil {
		return Result{}, err
	}
	now := c.now().UnixNano()
	if err := c.cfg.Store.DB.WithContext(ctx).Model(&Enrollment{}).
		Where("enrollment_id = ?", enrollmentID).
		Updates(map[string]any{
			"status": StatusIssued, "cert_pem": certPEM, "overlay_ip": ip.String(),
			"decided_at": now, "approver": approver,
		}).Error; err != nil {
		return Result{}, err
	}
	_ = c.audit(ctx, approver, "enroll-approved", e.DeviceName, fmt.Sprintf(`{"overlay_ip":%q}`, ip))
	return Result{EnrollmentID: enrollmentID, Status: StatusIssued, OverlayIP: ip.String(), CertPEM: certPEM}, nil
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

func (c *Consumer) issue(ctx context.Context, actor, deviceName string, pubBytes []byte, groups []string) (netip.Addr, []byte, error) {
	ip, err := c.cfg.Allocator.Allocate(ctx, deviceName, "")
	if err != nil {
		return netip.Addr{}, nil, fmt.Errorf("enrollment: allocate IP: %w", err)
	}
	nb := c.now().Add(-5 * time.Minute)
	cert, certPEM, err := c.cfg.Signer.Issue(ctx, actor, signer.Template{
		Name:      deviceName,
		Networks:  []netip.Prefix{netip.PrefixFrom(ip, c.cfg.Pool.Bits())},
		Groups:    groups,
		NotBefore: nb,
		NotAfter:  nb.Add(c.cfg.CertLifetime),
		PublicKey: pubBytes,
	})
	if err != nil {
		_ = c.cfg.Allocator.Release(ctx, ip) // don't leak the IP on a failed sign
		return netip.Addr{}, nil, fmt.Errorf("enrollment: sign: %w", err)
	}
	_ = cert
	return ip, certPEM, nil
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
