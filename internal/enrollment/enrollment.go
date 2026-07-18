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
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/awsattest"
	"github.com/jeks313/nebula-control-plane/internal/bundle"
	"github.com/jeks313/nebula-control-plane/internal/cloudtrust"
	"github.com/jeks313/nebula-control-plane/internal/ipam"
	"github.com/jeks313/nebula-control-plane/internal/joinkey"
	"github.com/jeks313/nebula-control-plane/internal/jws"
	"github.com/jeks313/nebula-control-plane/internal/nonce"
	"github.com/jeks313/nebula-control-plane/internal/policy"
	"github.com/jeks313/nebula-control-plane/internal/queue"
	"github.com/jeks313/nebula-control-plane/internal/replay"
	"github.com/jeks313/nebula-control-plane/internal/signer"
	"github.com/jeks313/nebula-control-plane/internal/ssoassert"
	"github.com/jeks313/nebula-control-plane/internal/store"
	"github.com/jeks313/nebula-control-plane/internal/usertrust"
	"github.com/jeks313/nebula-control-plane/internal/wire"
	"github.com/slackhq/nebula/cert"
	"gorm.io/gorm"
)

// Statuses.
const (
	StatusPending = "pending"
	StatusIssued  = "issued"
	StatusDenied  = "denied"
)

// defaultEphemeralCertTTL is the fallback cert validity for an ephemeral-join-key host
// when Config.EphemeralCertTTL is 0/unset. 24h is meaningfully shorter than the standard
// ~30d cert lifetime, so the feature does something useful out of the box (a short-lived
// CI runner / spot host gets a self-expiring credential) without operator configuration.
const defaultEphemeralCertTTL = 24 * time.Hour

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
	// ErrReservedGroup is the enrollment CHOKEPOINT refusal: ordinary enrollment (any
	// method, and admin Approve) may never issue a reserved group (control-plane /
	// lighthouse). Those identities bypass the fleet firewall and are revocation-immune,
	// so they are minted ONLY by the genesis ceremony and `harbor lighthouse-mint`, which
	// sign via the signer directly and never pass through this consumer.
	ErrReservedGroup = errors.New("enrollment: refusing to issue a reserved group (control-plane/lighthouse) via enrollment")

	// SSO (oidc/saml) enrollment outcomes (ADR 0004; decisions S5–S8). All terminal
	// for THIS attempt — a denied SSO enrollment is acked, never redelivered (the
	// single-use nonce was already consumed in verify(), so a redelivery would only
	// hit ErrReplay; the host re-enrolls with a fresh nonce for a replay-safe retry).
	ErrSSONotConfigured = errors.New("enrollment: SSO not configured")             // nil pinned key or user-trust seam
	ErrSSOAssertion     = errors.New("enrollment: SSO assertion invalid")          // bad signature / wrong key / expired / malformed
	ErrSSOBinding       = errors.New("enrollment: SSO assertion binding mismatch") // pubkey-hash or nonce does not match this request (anti-relay)
	ErrSSONotAllowed    = errors.New("enrollment: SSO identity not in user-trust") // no matching user-trust entry
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
	// Desired-vs-issued group reassignment (ADR 0002 / ADR 0013). DesiredGroups is the
	// control-plane-authoritative target set; Groups (above) stays "what the live cert was
	// signed with". GroupsGeneration bumps on every desired change; IssuedGeneration records
	// the generation the live cert was issued at. GroupsGeneration > IssuedGeneration means the
	// host is pending a re-issue (it renews on its next heartbeat). ReductionPendingEnforcement
	// + ReductionOldNotAfter mark a soft (advisory) group REMOVAL: the old, higher-privilege
	// cert stays valid until that unix-seconds expiry (or it is revoked in Phase 3). Seeded
	// DesiredGroups == Groups at enrollment (see record() AND the genesis direct-insert).
	DesiredGroups               string `gorm:"column:desired_groups;default:'[]'"`
	GroupsGeneration            int64  `gorm:"column:groups_generation"`
	IssuedGeneration            int64  `gorm:"column:issued_generation"`
	ReductionPendingEnforcement bool   `gorm:"column:reduction_pending_enforcement"`
	ReductionOldNotAfter        int64  `gorm:"column:reduction_old_not_after"`
	// SubRange is the IPAM netblock NAME this enrollment is bound to, resolved at enroll
	// time (the join key's sub-range, or the matched cloud-trust / user-trust scope; ADR
	// 0010 Phase 2). Persisted like Groups so Approve allocates from the SAME block the
	// enroll-time decision chose, rather than re-deriving it at approve time (which needs
	// the trust config loaded in the approving process). Empty -> the bounded 'default' block.
	SubRange  string `gorm:"column:sub_range"`
	Status    string `gorm:"column:status"`
	CertPEM   []byte `gorm:"column:cert_pem"`
	OverlayIP string `gorm:"column:overlay_ip"`
	// Fingerprint is the host's CURRENT issued cert fingerprint (hex sha256),
	// updated on issue and on every renewal. It lets a host be blocklisted by name
	// / overlay IP — resolved to its live fingerprint (M7.1). Empty until issued.
	Fingerprint string `gorm:"column:fingerprint"`
	CreatedAt   int64  `gorm:"column:created_at"`
	DecidedAt   int64  `gorm:"column:decided_at"`
	Approver    string `gorm:"column:approver"`
	// Ephemeral records whether this host joined via an ephemeral join key
	// (joinkey.Ephemeral), captured at issue time. It is the foundation for the
	// auto-reaping device lifecycle (impl 2.12, still future): for now it shortens the
	// issued cert TTL (Config.EphemeralCertTTL) and is surfaced so an operator can SEE
	// which hosts are ephemeral. Always false for cloud-sigv4 / SSO enrollments (ephemeral
	// is a join-key concept for now).
	Ephemeral bool `gorm:"column:ephemeral"`
	// Cloud-attestation evidence (M5; provider-agnostic). Empty for token enrollments.
	AttestProvider  string `gorm:"column:attest_provider"`  // e.g. "aws"
	AttestAccount   string `gorm:"column:attest_account"`   // AWS account / Azure sub / GCP project
	AttestPrincipal string `gorm:"column:attest_principal"` // AWS ARN / Azure principal / GCP SA
	AttestRegion    string `gorm:"column:attest_region"`
	VerifiedAt      int64  `gorm:"column:verified_at"`

	// Host platform (per-arch release URL support): the pilot self-reports runtime.GOOS/GOARCH
	// at enrollment (advisory — NOT attested, unlike the cloud evidence above), and the heartbeat
	// refreshes it. Core stamps the host's arch-specific binary from it. Empty = unknown -> the
	// linux/amd64 default at release lookup.
	GOOS   string `gorm:"column:goos"`
	GOARCH string `gorm:"column:goarch"`
}

func (Enrollment) TableName() string { return "enrollments" }

// Result summarizes a processed enrollment.
type Result struct {
	EnrollmentID string
	Status       string
	OverlayIP    string
	CertPEM      []byte
}

// ResultSink is where a processed enrollment's poll result is delivered. The
// co-located gateway writes it to the shared durable queue (`*queue.Durable`
// satisfies this); the pull-based collector (ADR 0005) ships it back to the
// originating gateway over mTLS. Decoupling the Consumer from a concrete queue is
// what lets the same verify+issue logic serve both transports.
type ResultSink interface {
	PutResult(ctx context.Context, enrollmentID, status string, secretHash, bundle []byte, reason string, expiresAt time.Time) error
}

// Config builds a Consumer.
type Config struct {
	Store        *store.Store
	Nonces       *nonce.Keyring
	Replay       replay.Observer
	Signer       *signer.Signer
	Allocator    *ipam.Allocator
	Pool         netip.Prefix
	CertLifetime time.Duration
	// EphemeralCertTTL is the (meaningfully shorter) cert validity for a host that joins
	// via an ephemeral join key (joinkey.Ephemeral) — the foundation for the auto-reaping
	// device lifecycle (impl 2.12, still future): a short-lived host gets a short-lived
	// cert so a vanished ephemeral host's credential expires fast on its own. 0/unset
	// falls back to defaultEphemeralCertTTL (24h). The signer's MaxLifetime / CA-expiry
	// guards still apply — shorter is always safe. Ignored for non-ephemeral joins (they
	// use CertLifetime) and for cloud-sigv4 / SSO (always non-ephemeral for now).
	EphemeralCertTTL time.Duration
	EnrollWindow     time.Duration // per-key quota window (0 -> 1h)
	Now              func() time.Time

	// Bundle assembly + delivery (3.6/3.6a). Optional: if ConfigBackend/Results
	// are nil, the enrollment is still recorded but no signed bundle/result is
	// produced (used by lower-level tests).
	ConfigBackend signer.Backend // config-signing key (signs bundles)
	ConfigKeyID   string         // its kid (pinned by Pilot)
	CABundlePEM   []byte         // CA cert PEM for the bundle's ca_bundle
	Lighthouses   []bundle.Lighthouse
	// TunDev + ListenPort are this mesh's nebula TUN device name + UDP listen port,
	// stamped into every issued bundle so a multi-mesh host gets distinct values per
	// mesh. Empty/zero -> the renderer's nebula1/4242 defaults (single-mesh hosts and
	// existing meshes are unaffected).
	TunDev     string
	ListenPort int
	// NebulaVersion / NebulaSHA256 / NebulaURL distribute the data-plane binary
	// (ADR 0003 Phase 1), stamped into every issued bundle. MUST match coreapi.Config's
	// so an enroll and a later renew agree on the nebula version. All empty -> hosts
	// keep their current nebula.
	NebulaVersion string
	NebulaSHA256  string
	NebulaURL     string
	// NebulaReleaseFor, if set, returns the CURRENT fleet-desired nebula tuple for a
	// newly enrolling host (ADR 0003 Phase 1c) — the latest settled release from the
	// registry — overriding the static NebulaVersion fields above. So a new host joins
	// on the current version rather than a stale flag value; later staged updates
	// converge via the renew/heartbeat path. nil -> the static fields. goos/goarch are
	// the host's reported platform (from the enroll request), so the FIRST bundle already
	// carries the host's arch-specific artifact (empty -> the linux/amd64 default).
	NebulaReleaseFor func(ctx context.Context, goos, goarch string) (version, sha256, url string)
	// PilotVersion / PilotSHA256 / PilotURL distribute the PILOT binary (ADR 0003 Phase
	// 3c), stamped into every issued bundle; PilotReleaseFor (if set) overrides them with
	// the current fleet-desired pilot release for a newly enrolling host (per-arch, like
	// NebulaReleaseFor).
	PilotVersion    string
	PilotSHA256     string
	PilotURL        string
	PilotReleaseFor func(ctx context.Context, goos, goarch string) (version, sha256, url string)
	// LighthouseSource, if set, is consulted at bundle-build time so registry
	// changes (6.8) propagate live; overrides Lighthouses, with a fallback to it
	// on error (a transient registry read must not sever discovery).
	LighthouseSource func(context.Context) ([]bundle.Lighthouse, error)
	Policy           *policy.Policy // central firewall (M6); nil -> Pilot's local default
	// BlocklistSource, if set, is consulted at bundle-build time so revocations
	// (7.1) propagate live into pki.blocklist; a transient read error falls back to
	// an empty blocklist rather than failing the enrollment (fail-open on
	// availability — peers still hold the blocklist from their own bundles).
	BlocklistSource func(context.Context) ([]string, error)
	Results         ResultSink    // result delivery (shared queue, or the ADR-0005 collector's ship-back sink)
	ResultTTL       time.Duration // result/ticket validity (0 -> 1h)

	// Cloud attestation (M5). AWSSigV4Enabled gates the aws-sigv4 method; CloudTrust
	// is the active dual-control trust config (which accounts/roles may attest +
	// their groups/auto-issue). Both nil/false => aws-sigv4 enrollments are denied
	// (fail closed). AWSVerify is the STS verification config (test-only Endpoint
	// override; leave its Endpoint empty in prod so the allowlisted signed URL is used).
	AWSSigV4Enabled bool
	AWSVerify       awsattest.VerifyConfig
	CloudTrust      *cloudtrust.Config

	// SSO enrollment (ADR 0004; decisions S5–S8). The off-mesh gateway (ADR 0005)
	// authenticates the user against the IdP and signs a short-lived assertion
	// (internal/ssoassert) binding the IdP identity to the enrolling device; mesh-only
	// Core pulls the candidate and re-verifies EVERYTHING here before deciding.
	//
	// AssertionVerifyKey is the PINNED gateway assertion-signing public key (the public
	// half of the dedicated ECDSA P-256 keypair, S6 — distinct from the CA). Core pins
	// it; the gateway holds the private half. nil => SSO is not configured and an oidc
	// enrollment is denied (fail closed).
	AssertionVerifyKey *ecdsa.PublicKey
	// UserTrustActive sources the ACTIVE user-trust config (S1 — the latest committed
	// usertrust.publish dual-control change). It is a getter SEAM rather than a snapshot
	// pointer (cf. CloudTrust, read once at build) so the published config is read live
	// per enrollment — the dual-control flow can change who may enroll without a Core
	// restart. nil getter, OR a getter returning nil, => SSO is not configured (fail
	// closed). The real source (a usertrust.publish reader) + the genesis key
	// distribution are wired in cmd/harbor as a LATER integration step; this is the seam.
	UserTrustActive func() *usertrust.Config
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

// Terminal reports whether an error is a final business outcome (don't retry) vs.
// a transient/infra failure (retry). Exported for the ADR-0005 pull collector,
// which uses it to decide ack (done) vs nack (redeliver) on a claimed candidate.
func Terminal(err error) bool { return terminal(err) }

// terminal reports whether an error is a final business outcome (don't retry)
// vs. a transient/infra failure (retry).
func terminal(err error) bool {
	for _, t := range []error{
		ErrBadRequest, ErrSignature, ErrNonce, ErrReplay, ErrMethod, ErrQuota, ErrReservedGroup,
		joinkey.ErrNotFound, joinkey.ErrExpired, joinkey.ErrExhausted,
		// Attestation outcomes are all terminal for THIS attempt. A bad/forged/
		// un-allowlisted attestation will never succeed; an STS-unavailable error also
		// denies (rather than nacking) because the single-use nonce was already consumed
		// in verify(), so a queue redelivery would only hit ErrReplay — the host instead
		// re-enrolls with a fresh nonce (replay-safe recovery).
		awsattest.ErrBinding, awsattest.ErrUnsignedBinding, awsattest.ErrBadRequest,
		awsattest.ErrBadEndpoint, awsattest.ErrAttestation, awsattest.ErrNotAllowed,
		awsattest.ErrSTSUnavailable,
		// SSO (oidc/saml) outcomes are all terminal for THIS attempt: a forged/expired/
		// wrong-bound assertion or an untrusted identity will never succeed, and a
		// not-configured deny is a fixed posture — none warrant a queue redelivery.
		ErrSSONotConfigured, ErrSSOAssertion, ErrSSOBinding, ErrSSONotAllowed,
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
	if req.Method == wire.MethodAWSSigV4 {
		return c.processAttested(ctx, cand, req, pubBytes)
	}
	if req.Method == wire.MethodOIDC {
		return c.processSSO(ctx, cand, req, pubBytes)
	}
	if req.Method != wire.MethodToken {
		return Result{}, fmt.Errorf("%w: %q (token/join-key, aws-sigv4 and oidc/sso are implemented)", ErrMethod, req.Method)
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

	// Approval decision: bearer secrets are PENDING by default. The key's ephemeral flag
	// is recorded on the row now so a later Approve re-derives the same shorter cert TTL
	// (the Approve path re-reads the key, mirroring the netblock re-derivation).
	if !jk.AutoIssue {
		if err := c.record(ctx, cand.EnrollmentID, req, pubBytes, jk.ID, groups, jk.SubRange, StatusPending, nil, "", "", evidence{}, jk.Ephemeral); err != nil {
			return Result{}, fmt.Errorf("enroll: persist pending enrollment: %w", err) // transient -> nack, don't deliver
		}
		c.writeResult(ctx, cand.EnrollmentID, cand.RetrievalSecretHash, nil, StatusPending, "")
		_ = c.audit(ctx, "system", "enroll-pending", deviceName,
			fmt.Sprintf(`{"join_key":%q,"reason":"manual approval required"}`, jk.Name))
		return Result{EnrollmentID: cand.EnrollmentID, Status: StatusPending}, nil
	}

	// auto_issue: mint immediately. The join key's sub-range carries the netblock
	// name (ADR 0010 — reusing join_keys.sub_range); empty -> the default block. An
	// ephemeral key shortens the cert TTL (issue's ephemeral arg) and is stamped on the row.
	ip, certPEM, fp, notAfter, err := c.issue(ctx, "enroll-auto", deviceName, pubBytes, jk.GroupList(), jk.SubRange, "token", jk.Ephemeral)
	if err != nil {
		return Result{}, err
	}
	bundleJWS, err := c.buildBundle(ctx, deviceName, ip.String(), jk.GroupList(), certPEM, notAfter, req.Client.OS, req.Client.Arch)
	if err != nil {
		return Result{}, err
	}
	if err := c.record(ctx, cand.EnrollmentID, req, pubBytes, jk.ID, groups, jk.SubRange, StatusIssued, certPEM, ip.String(), fp, evidence{}, jk.Ephemeral); err != nil {
		return Result{}, fmt.Errorf("enroll: persist issued enrollment: %w", err) // transient -> nack, don't deliver the bundle
	}
	c.writeResult(ctx, cand.EnrollmentID, cand.RetrievalSecretHash, bundleJWS, StatusIssued, "")
	return Result{EnrollmentID: cand.EnrollmentID, Status: StatusIssued, OverlayIP: ip.String(), CertPEM: certPEM}, nil
}

// processAttested handles an aws-sigv4 enrollment: verify the presigned STS attestation
// (bound to THIS enrollment's nonce + host pubkey — the same single-use nonce the outer
// JWS verify already consumed), enforce the dual-control cloud-trust allowlist, derive
// groups from the matched account (∪ default groups), capture provider evidence, and
// auto-issue or queue for manual approval per the account's posture. Fails closed.
func (c *Consumer) processAttested(ctx context.Context, cand queue.Candidate, req wire.EnrollRequest, pubBytes []byte) (Result, error) {
	if !c.cfg.AWSSigV4Enabled || c.cfg.CloudTrust == nil {
		c.deny(ctx, cand, req, pubBytes, "enroll-denied", "aws-sigv4 attestation is not enabled on this control plane")
		return Result{EnrollmentID: cand.EnrollmentID, Status: StatusDenied}, fmt.Errorf("%w: aws-sigv4 disabled", ErrMethod)
	}

	var pres awsattest.PresignedRequest
	if err := json.Unmarshal(req.Credential, &pres); err != nil {
		c.deny(ctx, cand, req, pubBytes, "enroll-denied", "malformed attestation credential")
		return Result{EnrollmentID: cand.EnrollmentID, Status: StatusDenied}, fmt.Errorf("%w: %w", awsattest.ErrBadRequest, err)
	}

	// Verify binds to the nonce + pubkey hash already validated by c.verify() — do NOT
	// introduce a second nonce. STS vouches for the identity; we trust nothing the host
	// supplied beyond the SigV4-signed, allowlisted request.
	id, err := awsattest.Verify(ctx, pres, req.Nonce, wire.PubkeyHash(pubBytes), c.cfg.AWSVerify)
	if err != nil {
		// Fail closed for this attempt. STS-unavailable is denied (not nacked): the
		// nonce was already consumed in verify(), so a redelivery would hit ErrReplay —
		// the host re-enrolls with a fresh nonce instead (replay-safe recovery).
		reason := "attestation rejected: " + err.Error()
		if errors.Is(err, awsattest.ErrSTSUnavailable) {
			reason = "cloud attestation verifier (AWS STS) is unavailable; re-enroll to retry"
		}
		c.deny(ctx, cand, req, pubBytes, "enroll-denied", reason)
		return Result{EnrollmentID: cand.EnrollmentID, Status: StatusDenied}, err
	}

	groupsSlice, netblock, autoIssue, ok := c.cfg.CloudTrust.MatchAWS(id)
	if !ok {
		reason := fmt.Sprintf("AWS account %s / role %s is not in the cloud-trust config", id.Account, id.Arn)
		c.deny(ctx, cand, req, pubBytes, "enroll-denied", reason)
		return Result{EnrollmentID: cand.EnrollmentID, Status: StatusDenied}, fmt.Errorf("%w: account %s", awsattest.ErrNotAllowed, id.Account)
	}

	ev := evidence{
		provider:   cloudtrust.ProviderAWS,
		account:    id.Account,
		principal:  id.Arn,
		region:     regionFromSTSURL(pres.URL),
		verifiedAt: c.now().UnixNano(),
	}
	if groupsSlice == nil {
		groupsSlice = []string{}
	}
	groupsJSON, _ := json.Marshal(groupsSlice)
	deviceName := deviceName(req, cand.PubkeyHash)

	// Attested-but-not-auto-issue still queues for manual approval (an operator-set
	// posture per account). JoinKeyID stays 0 — there is no join key.
	// Attested (cloud-sigv4) enrollments are non-ephemeral for now — ephemeral is a
	// join-key concept; pass ephemeral=false through record/issue.
	if !autoIssue {
		if err := c.record(ctx, cand.EnrollmentID, req, pubBytes, 0, string(groupsJSON), netblock, StatusPending, nil, "", "", ev, false); err != nil {
			return Result{}, fmt.Errorf("enroll: persist pending enrollment: %w", err) // transient -> nack, don't deliver
		}
		c.writeResult(ctx, cand.EnrollmentID, cand.RetrievalSecretHash, nil, StatusPending, "")
		_ = c.audit(ctx, "system", "enroll-pending", deviceName,
			fmt.Sprintf(`{"method":"aws-sigv4","account":%q,"reason":"manual approval required"}`, id.Account))
		return Result{EnrollmentID: cand.EnrollmentID, Status: StatusPending}, nil
	}

	// Cloud-trust -> netblock binding (ADR 0010 Phase 2): the matched AWSAccount's
	// Netblock (empty -> the bounded 'default' block) scopes the allocation. Method
	// records the join source.
	ip, certPEM, fp, notAfter, err := c.issue(ctx, "enroll-attested", deviceName, pubBytes, groupsSlice, netblock, "aws-sigv4", false)
	if err != nil {
		return Result{}, err
	}
	bundleJWS, err := c.buildBundle(ctx, deviceName, ip.String(), groupsSlice, certPEM, notAfter, req.Client.OS, req.Client.Arch)
	if err != nil {
		return Result{}, err
	}
	if err := c.record(ctx, cand.EnrollmentID, req, pubBytes, 0, string(groupsJSON), netblock, StatusIssued, certPEM, ip.String(), fp, ev, false); err != nil {
		return Result{}, fmt.Errorf("enroll: persist issued enrollment: %w", err) // transient -> nack, don't deliver the bundle
	}
	c.writeResult(ctx, cand.EnrollmentID, cand.RetrievalSecretHash, bundleJWS, StatusIssued, "")
	_ = c.audit(ctx, "system", "enroll-attested", deviceName,
		fmt.Sprintf(`{"method":"aws-sigv4","account":%q,"arn":%q}`, id.Account, id.Arn))
	return Result{EnrollmentID: cand.EnrollmentID, Status: StatusIssued, OverlayIP: ip.String(), CertPEM: certPEM}, nil
}

// providerSSO is the attestation-evidence provider recorded for an SSO enrollment
// (S7 — SAML first; OIDC is the near-free follow-on, both ride the same path). The
// AttestProvider/AttestAccount/AttestPrincipal evidence columns are provider-agnostic
// (M5): for SSO, account = the IdP issuer/realm, principal = the IdP subject/email.
const providerSSO = "sso"

// processSSO handles an SSO (oidc/saml) enrollment (ADR 0004; decisions S5–S8). The
// credential is the off-mesh gateway's portal-signed assertion (a compact ES256 JWS
// from internal/ssoassert). Trusting the gateway for NOTHING beyond "the IdP said this",
// Core re-verifies the assertion against the PINNED gateway key + the clock, re-checks
// the device binding (pubkey hash + the SAME single-use nonce the outer JWS verify
// already consumed — anti-relay), resolves the issuing identity from the dual-control
// user-trust config (usertrust.Match, first-match-wins), records provider-agnostic
// evidence, and lands PENDING by default (S8) — honoring auto-issue only when the
// matched entry set it. Fails closed: every rejection is a TERMINAL deny.
func (c *Consumer) processSSO(ctx context.Context, cand queue.Candidate, req wire.EnrollRequest, pubBytes []byte) (Result, error) {
	// Config seam (fail closed). Need BOTH the pinned gateway key to verify the
	// assertion AND a user-trust source to authorize it; either absent => not configured.
	if c.cfg.AssertionVerifyKey == nil || c.cfg.UserTrustActive == nil {
		c.deny(ctx, cand, req, pubBytes, "enroll-denied", "SSO enrollment is not configured on this control plane")
		return Result{EnrollmentID: cand.EnrollmentID, Status: StatusDenied}, ErrSSONotConfigured
	}
	active := c.cfg.UserTrustActive()
	if active == nil {
		c.deny(ctx, cand, req, pubBytes, "enroll-denied", "no user-trust config has been published")
		return Result{EnrollmentID: cand.EnrollmentID, Status: StatusDenied}, ErrSSONotConfigured
	}

	// Envelope: the credential is {"assertion":"<compact-jws>"} — a typed wrapper so the
	// SSO credential is self-describing and future SSO fields can ride alongside it
	// without overloading the bare token (B5). An empty/malformed envelope is terminal.
	var cred struct {
		Assertion string `json:"assertion"`
	}
	if err := json.Unmarshal(req.Credential, &cred); err != nil || cred.Assertion == "" {
		c.deny(ctx, cand, req, pubBytes, "enroll-denied", "malformed SSO credential envelope")
		return Result{EnrollmentID: cand.EnrollmentID, Status: StatusDenied}, fmt.Errorf("%w: malformed credential envelope", ErrSSOAssertion)
	}

	// 1) Verify the assertion against the PINNED gateway key + the validity window. This
	// rejects a forged/wrong-key signature, a malformed token or wrong typ, and a token
	// outside its window — but proves only that the gateway vouched for these facts.
	a, err := ssoassert.Verify(c.cfg.AssertionVerifyKey, []byte(cred.Assertion), c.now())
	if err != nil {
		reason := "SSO assertion rejected: " + err.Error()
		c.deny(ctx, cand, req, pubBytes, "enroll-denied", reason)
		return Result{EnrollmentID: cand.EnrollmentID, Status: StatusDenied}, fmt.Errorf("%w: %w", ErrSSOAssertion, err)
	}

	// 2) Binding (anti-relay): the assertion MUST be bound to THIS enrolling device.
	//   (a) its PubkeyHash must equal the request's host pubkey hash, and
	//   (b) its Nonce must pass the SAME single-use nonce verification the other paths
	//       use, bound to that pubkey hash — reusing c.verify()'s mechanism rather than
	//       inventing a parallel one. (The outer JWS verify already consumed req.Nonce
	//       via the replay observer; here we re-prove the ASSERTION's embedded nonce is
	//       the same one, authentic for this pubkey — so a gateway assertion minted for a
	//       different device or a different enrollment cannot be relayed onto this one.)
	pubkeyHash := wire.PubkeyHash(pubBytes)
	if a.PubkeyHash != pubkeyHash {
		c.deny(ctx, cand, req, pubBytes, "enroll-denied", "SSO assertion is bound to a different device key")
		return Result{EnrollmentID: cand.EnrollmentID, Status: StatusDenied}, fmt.Errorf("%w: pubkey hash", ErrSSOBinding)
	}
	if a.Nonce != req.Nonce {
		c.deny(ctx, cand, req, pubBytes, "enroll-denied", "SSO assertion is bound to a different enrollment nonce")
		return Result{EnrollmentID: cand.EnrollmentID, Status: StatusDenied}, fmt.Errorf("%w: nonce mismatch", ErrSSOBinding)
	}
	// This only RE-CONFIRMS the authenticity verify() already established for req.Nonce
	// (a.Nonce == req.Nonce above) — it adds no anti-replay of its own. The single-use
	// property comes solely from verify()'s replay observer, which consumed req.Nonce once.
	if err := c.cfg.Nonces.Verify(a.Nonce, []byte(pubkeyHash)); err != nil {
		c.deny(ctx, cand, req, pubBytes, "enroll-denied", "SSO assertion nonce is not authentic for this device")
		return Result{EnrollmentID: cand.EnrollmentID, Status: StatusDenied}, fmt.Errorf("%w: %w", ErrSSOBinding, err)
	}

	// 3) Policy: resolve the issuing identity from the active user-trust config —
	// first-match-wins over the ordered entries (S4), keyed on the assertion's realm
	// (issuer) + the IdP-asserted directory groups. No match => DENY (fail closed).
	groupsSlice, netblock, autoIssue, ok := usertrust.Match(*active, a.Issuer, a.IdPGroups)
	if !ok {
		reason := fmt.Sprintf("SSO identity %q (realm %q) is in no trusted user-trust group", a.Subject, a.Issuer)
		c.deny(ctx, cand, req, pubBytes, "enroll-denied", reason)
		return Result{EnrollmentID: cand.EnrollmentID, Status: StatusDenied}, fmt.Errorf("%w: realm %s", ErrSSONotAllowed, a.Issuer)
	}

	// Evidence (provider-agnostic columns, M5): provider=sso, account=the IdP issuer/realm,
	// principal=email when present else subject, region=the IdP-asserted directory groups
	// (so the pending row shows what membership drove the match). No cloud STS here. The
	// groups are JSON-encoded (not comma-joined) into AttestRegion so a group name
	// containing a comma round-trips exactly on the approve path's re-derivation.
	principal := a.Email
	if principal == "" {
		principal = a.Subject
	}
	idpGroupsJSON, _ := json.Marshal(a.IdPGroups)
	ev := evidence{
		provider:   providerSSO,
		account:    a.Issuer,
		principal:  principal,
		region:     string(idpGroupsJSON),
		verifiedAt: c.now().UnixNano(),
	}
	if groupsSlice == nil {
		groupsSlice = []string{}
	}
	groupsJSON, _ := json.Marshal(groupsSlice)
	deviceName := deviceName(req, cand.PubkeyHash)

	// Defense-in-depth (S8, security-review FIX B): usertrust.Validate already rejects a
	// published auto_issue config that grants a reserved/privileged group, so this should
	// be unreachable for any committed config — but a resolved auto-issue set that somehow
	// includes a reserved group is FORCED to pending here (never minted unattended), behind
	// the config-time gate. Cheap (a slice scan) and a different layer, so not duplicative.
	if autoIssue && policy.GrantsReservedGroup(groupsSlice) {
		autoIssue = false
	}

	// 4) Admission (S8): default PENDING — Phase 1 issues nothing automatically; an admin
	// approves in the existing queue. Honor the matched entry's auto-issue ONLY when set.
	// JoinKeyID stays 0 (there is no join key). The wire method is "oidc" (req.Method);
	// the IPAM provenance enum is token|aws-sigv4|sso|genesis, so the allocation is
	// recorded as "sso" (B7 — wire oidc → provenance sso).
	// SSO enrollments are non-ephemeral for now — ephemeral is a join-key concept;
	// pass ephemeral=false through record/issue.
	if !autoIssue {
		if err := c.record(ctx, cand.EnrollmentID, req, pubBytes, 0, string(groupsJSON), netblock, StatusPending, nil, "", "", ev, false); err != nil {
			return Result{}, fmt.Errorf("enroll: persist pending enrollment: %w", err) // transient -> nack, don't deliver
		}
		c.writeResult(ctx, cand.EnrollmentID, cand.RetrievalSecretHash, nil, StatusPending, "")
		_ = c.audit(ctx, "system", "enroll-pending", deviceName,
			fmt.Sprintf(`{"method":"sso","realm":%q,"subject":%q,"reason":"manual approval required"}`, a.Issuer, a.Subject))
		return Result{EnrollmentID: cand.EnrollmentID, Status: StatusPending}, nil
	}

	ip, certPEM, fp, notAfter, err := c.issue(ctx, "enroll-sso", deviceName, pubBytes, groupsSlice, netblock, providerSSO, false)
	if err != nil {
		return Result{}, err
	}
	bundleJWS, err := c.buildBundle(ctx, deviceName, ip.String(), groupsSlice, certPEM, notAfter, req.Client.OS, req.Client.Arch)
	if err != nil {
		return Result{}, err
	}
	if err := c.record(ctx, cand.EnrollmentID, req, pubBytes, 0, string(groupsJSON), netblock, StatusIssued, certPEM, ip.String(), fp, ev, false); err != nil {
		return Result{}, fmt.Errorf("enroll: persist issued enrollment: %w", err) // transient -> nack, don't deliver the bundle
	}
	c.writeResult(ctx, cand.EnrollmentID, cand.RetrievalSecretHash, bundleJWS, StatusIssued, "")
	_ = c.audit(ctx, "system", "enroll-sso", deviceName,
		fmt.Sprintf(`{"method":"sso","realm":%q,"subject":%q}`, a.Issuer, a.Subject))
	return Result{EnrollmentID: cand.EnrollmentID, Status: StatusIssued, OverlayIP: ip.String(), CertPEM: certPEM}, nil
}

// regionFromSTSURL extracts the AWS region from a signed STS host
// (sts.<region>.amazonaws.com); the global endpoint sts.amazonaws.com -> "global".
func regionFromSTSURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	h := strings.TrimSuffix(u.Hostname(), ".amazonaws.com")
	h = strings.TrimPrefix(h, "sts")
	h = strings.TrimPrefix(h, ".")
	if h == "" {
		return "global"
	}
	return h
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
	// Re-derive the netblock binding from the pending row: a join-key enrollment draws
	// from the key's sub-range (netblock name); an aws-sigv4 enrollment re-resolves the
	// matched cloud-trust scope's netblock from the active config + the row's stored
	// attestation evidence (ADR 0010 Phase 2); an SSO enrollment re-resolves the matched
	// user-trust entry's netblock the same way. The wire method recorded on the row
	// (token|aws-sigv4|oidc) maps to the IPAM provenance method (oidc -> sso, B7).
	// Use the netblock resolved + persisted at ENROLL time (where the trust config was
	// loaded), so the approved cert lands in the right block regardless of whether THIS
	// process has the user-trust/cloud-trust config. Fall back to re-deriving only for
	// rows enrolled before sub_range was persisted (in-flight pending at upgrade time).
	netblockName := e.SubRange
	if netblockName == "" {
		netblockName = c.approveNetblock(ctx, e)
	}
	// Re-derive ephemeral from the join key (mirroring the netblock re-derivation) so the
	// approved cert's TTL + the recorded flag match what auto-issue would have produced.
	// The pending row already carries the flag (recorded at processToken time); re-reading
	// the key keeps Approve consistent with approveNetblock and tolerant of a row written
	// before this column existed. Cloud-sigv4 / SSO are always non-ephemeral.
	ephemeral := c.approveEphemeral(ctx, e)
	ip, certPEM, fp, notAfter, err := c.issue(ctx, approver, e.DeviceName, e.Pubkey, groups, netblockName, provenanceMethod(e.Method), ephemeral)
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
			"fingerprint": fp, "decided_at": now, "approver": approver, "ephemeral": ephemeral,
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
	bundleJWS, err := c.buildBundle(ctx, e.DeviceName, ip.String(), groups, certPEM, notAfter, e.GOOS, e.GOARCH)
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
	// Best-effort: a denial issues no cert, so a failed record only loses the
	// history row — the audit append below still records the rejection, and there
	// is no bundle to withhold. (Contrast the issue/pending paths, which fail closed.)
	_ = c.record(ctx, cand.EnrollmentID, req, pubBytes, 0, "[]", "", StatusDenied, nil, "", "", evidence{}, false)
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

// BuildDeliverable re-derives the signed poll result to ship for an enrollment that
// has been DECIDED (issued/denied), or ok=false if it is still pending (nothing to
// deliver yet) or unknown to us. It rebuilds the issued bundle from the stored row —
// the same inputs Approve used — so the ADR-0005 collector can carry an admin approval
// to the gateway on its OUTBOUND poll, without the gateway ever calling in to Harbor.
// Primitive return types so *Consumer satisfies collect.Resolver with no import cycle.
func (c *Consumer) BuildDeliverable(ctx context.Context, enrollmentID string) (status string, bundleJWS []byte, reason string, ok bool, err error) {
	var e Enrollment
	if derr := c.cfg.Store.DB.WithContext(ctx).Where("enrollment_id = ?", enrollmentID).First(&e).Error; derr != nil {
		if errors.Is(derr, gorm.ErrRecordNotFound) {
			return "", nil, "", false, nil // gateway holds a pending result for an id we don't recognize — skip
		}
		return "", nil, "", false, derr
	}
	switch e.Status {
	case StatusIssued:
		var groups []string
		_ = json.Unmarshal([]byte(e.Groups), &groups)
		crt, _, cerr := cert.UnmarshalCertificateFromPEM(e.CertPEM)
		if cerr != nil {
			return "", nil, "", false, fmt.Errorf("enroll: deliverable %s: parse cert: %w", enrollmentID, cerr)
		}
		b, berr := c.buildBundle(ctx, e.DeviceName, e.OverlayIP, groups, e.CertPEM, crt.NotAfter(), e.GOOS, e.GOARCH)
		if berr != nil {
			return "", nil, "", false, berr
		}
		return StatusIssued, b, "", true, nil
	case StatusDenied:
		return StatusDenied, nil, "enrollment denied by an administrator", true, nil
	default: // pending or unknown — nothing to deliver yet
		return "", nil, "", false, nil
	}
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
	if c.cfg.Replay != nil {
		first, rerr := c.cfg.Replay.Observe(req.Nonce)
		if rerr != nil {
			// Infra failure (shared store unreachable), NOT a replay: return a
			// non-terminal error so the candidate is retried, not dropped.
			return wire.EnrollRequest{}, nil, fmt.Errorf("enrollment: replay store: %w", rerr)
		}
		if !first {
			return wire.EnrollRequest{}, nil, ErrReplay
		}
	}
	return req, pubBytes, nil
}

// approveNetblock resolves the netblock name for a pending enrollment being
// approved (ADR 0010 Phase 2):
//   - a join-key enrollment (JoinKeyID != 0) draws from the key's sub-range (the
//     netblock name);
//   - an aws-sigv4 enrollment re-resolves the matched cloud-trust scope's netblock
//     from the active config + the attestation evidence stored on the row, so a
//     pending attested enrollment lands in the SAME block its auto-issue sibling
//     would have;
//   - anything else returns "" -> the bounded 'default' block.
//
// A best-effort read/match miss falls back to "" so an approval is never blocked on
// a transient lookup or a since-removed scope.
func (c *Consumer) approveNetblock(ctx context.Context, e Enrollment) string {
	if e.JoinKeyID != 0 {
		var jk joinkey.JoinKey
		if err := c.cfg.Store.DB.WithContext(ctx).First(&jk, "id = ?", e.JoinKeyID).Error; err != nil {
			return ""
		}
		return jk.SubRange
	}
	if e.Method == wire.MethodAWSSigV4 && c.cfg.CloudTrust != nil && e.AttestProvider == cloudtrust.ProviderAWS {
		_, netblock, _, ok := c.cfg.CloudTrust.MatchAWS(awsattest.Identity{Account: e.AttestAccount, Arn: e.AttestPrincipal})
		if ok {
			return netblock
		}
	}
	// An SSO enrollment re-resolves the matched user-trust entry's netblock from the
	// active config + the row's stored evidence (issuer = AttestAccount, the
	// IdP-asserted groups recorded JSON-encoded in AttestRegion), so a pending SSO
	// enrollment lands in the SAME block its auto-issue sibling would have (ADR 0010
	// per-scope binding, mirroring the aws-sigv4 case above).
	if e.Method == wire.MethodOIDC && c.cfg.UserTrustActive != nil && e.AttestProvider == providerSSO {
		if active := c.cfg.UserTrustActive(); active != nil {
			groups := decodeGroups(e.AttestRegion)
			if _, netblock, _, ok := usertrust.Match(*active, e.AttestAccount, groups); ok {
				return netblock
			}
		}
	}
	return ""
}

// approveEphemeral re-derives whether a pending enrollment is ephemeral, on approve:
//   - a join-key enrollment (JoinKeyID != 0) re-reads the key's Ephemeral flag, exactly
//     mirroring approveNetblock's sub-range re-derivation, so an approved cert's TTL and the
//     recorded flag match what the auto-issue sibling would have produced. A read miss
//     (key since deleted) falls back to the flag already recorded on the row.
//   - cloud-sigv4 / SSO enrollments are always non-ephemeral for now (false).
func (c *Consumer) approveEphemeral(ctx context.Context, e Enrollment) bool {
	if e.JoinKeyID != 0 {
		var jk joinkey.JoinKey
		if err := c.cfg.Store.DB.WithContext(ctx).First(&jk, "id = ?", e.JoinKeyID).Error; err != nil {
			return e.Ephemeral // key gone; trust the flag recorded at processToken time
		}
		return jk.Ephemeral
	}
	return false
}

// decodeGroups reverses the JSON-encode used to store an SSO enrollment's IdP groups in
// the AttestRegion evidence column (empty/invalid -> nil), so a group name containing a
// comma round-trips exactly (unlike a comma-split).
func decodeGroups(s string) []string {
	if s == "" {
		return nil
	}
	var groups []string
	if err := json.Unmarshal([]byte(s), &groups); err != nil {
		return nil
	}
	return groups
}

// provenanceMethod maps the WIRE enrollment method (recorded on the row) to the IPAM
// provenance enum (token|aws-sigv4|sso|genesis, ADR 0010). The wire SSO method is
// "oidc" but the IPAM enum is "sso" (B7), so a re-issue on approve records the same
// provenance the auto-issue path would have. All other wire methods pass through.
func provenanceMethod(wireMethod string) string {
	if wireMethod == wire.MethodOIDC {
		return providerSSO
	}
	return wireMethod
}

// certTTL returns the cert validity for this issue: the (shorter) ephemeral TTL for a
// host that joined via an ephemeral join key, else the standard CertLifetime. An unset
// EphemeralCertTTL falls back to defaultEphemeralCertTTL (24h). The signer still enforces
// MaxLifetime / CA-expiry, so a shorter ephemeral window is always safe.
func (c *Consumer) certTTL(ephemeral bool) time.Duration {
	if !ephemeral {
		return c.cfg.CertLifetime
	}
	if c.cfg.EphemeralCertTTL > 0 {
		return c.cfg.EphemeralCertTTL
	}
	return defaultEphemeralCertTTL
}

// issue allocates an overlay IP from the named netblock (empty -> the bounded
// 'default' block) recording the join method as provenance, then signs the leaf.
// netblockName comes from the join source (a join key's sub-range, a cloud-trust
// scope, or — later — an SSO entry); method is token | aws-sigv4 | sso (ADR 0010).
// ephemeral shortens the cert validity (certTTL) for an ephemeral-join-key host; it is
// the join-key Ephemeral flag threaded through from processToken / re-derived on Approve.
func (c *Consumer) issue(ctx context.Context, actor, deviceName string, pubBytes []byte, groups []string, netblockName, method string, ephemeral bool) (ip netip.Addr, certPEM []byte, fingerprint string, notAfter time.Time, err error) {
	// CHOKEPOINT (P10): ordinary enrollment must NEVER mint a reserved group
	// (control-plane/lighthouse). All auto-issue methods (token/aws-sigv4/sso) AND admin
	// Approve funnel through here, so this single guard closes every enrollment route,
	// independent of the admin perimeter (join keys / trust configs are also guarded there).
	// A reserved-group identity bypasses the fleet firewall AND is revocation-immune, so it
	// may only be minted by genesis / `harbor lighthouse-mint` (which sign via the signer
	// directly, not through this consumer). Refuse BEFORE allocating an IP or touching the CA.
	if policy.GrantsReservedGroup(groups) {
		gj, _ := json.Marshal(groups)
		_ = c.audit(ctx, "system", "enroll-reserved-group-refused", deviceName,
			fmt.Sprintf(`{"groups":%s,"method":%q,"actor":%q}`, gj, method, actor))
		return netip.Addr{}, nil, "", time.Time{}, fmt.Errorf("%w: %s", ErrReservedGroup, gj)
	}
	ip, err = c.cfg.Allocator.Allocate(ctx, deviceName, netblockName, method)
	if err != nil {
		// An exhaustion denial is a clean terminal "no addresses available" — surface
		// it (the allocator already bumped the exhaustion metric); audit so the
		// operator can make room before the host re-enrolls.
		if errors.Is(err, ipam.ErrPoolExhausted) {
			_ = c.audit(ctx, "system", "enroll-exhausted", deviceName,
				fmt.Sprintf(`{"netblock":%q,"method":%q,"reason":"no addresses available"}`, netblockName, method))
		}
		return netip.Addr{}, nil, "", time.Time{}, fmt.Errorf("enrollment: allocate IP: %w", err)
	}
	nb := c.now().Add(-5 * time.Minute)
	notAfter = nb.Add(c.certTTL(ephemeral))
	crt, pem, ierr := c.cfg.Signer.Issue(ctx, actor, signer.Template{
		Name:      deviceName,
		Networks:  []netip.Prefix{netip.PrefixFrom(ip, c.cfg.Pool.Bits())},
		Groups:    groups,
		NotBefore: nb,
		NotAfter:  notAfter,
		PublicKey: pubBytes,
	})
	if ierr != nil {
		_ = c.cfg.Allocator.Release(ctx, ip) // don't leak the IP on a failed sign
		return netip.Addr{}, nil, "", time.Time{}, fmt.Errorf("enrollment: sign: %w", ierr)
	}
	certPEM = pem
	fingerprint, _ = crt.Fingerprint() // the blocklist key (M7.1)
	return ip, certPEM, fingerprint, notAfter, nil
}

// buildBundle assembles + signs the config bundle (3.6). Returns nil if no
// config-signing backend is configured.
func (c *Consumer) buildBundle(ctx context.Context, deviceName, ip string, groups []string, certPEM []byte, notAfter time.Time, goos, goarch string) ([]byte, error) {
	if c.cfg.ConfigBackend == nil {
		return nil, nil
	}
	nebVer, nebSHA, nebURL := c.cfg.NebulaVersion, c.cfg.NebulaSHA256, c.cfg.NebulaURL
	if c.cfg.NebulaReleaseFor != nil {
		nebVer, nebSHA, nebURL = c.cfg.NebulaReleaseFor(ctx, goos, goarch)
	}
	pilotVer, pilotSHA, pilotURL := c.cfg.PilotVersion, c.cfg.PilotSHA256, c.cfg.PilotURL
	if c.cfg.PilotReleaseFor != nil {
		pilotVer, pilotSHA, pilotURL = c.cfg.PilotReleaseFor(ctx, goos, goarch)
	}
	b := bundle.Bundle{
		BundleVersion: 1,
		IssuedAt:      c.now().UTC().Format(time.RFC3339),
		Device:        bundle.Device{Name: deviceName, OverlayIP: ip, Groups: groups},
		Certificate:   string(certPEM),
		CABundle:      []string{string(c.cfg.CABundlePEM)},
		Firewall:      bundle.CompileFirewall(c.cfg.Policy, groups),
		Lighthouses:   c.lighthouses(ctx),
		Blocklist:     c.blocklist(ctx),
		TunDev:        c.cfg.TunDev,
		ListenPort:    c.cfg.ListenPort,
		NebulaVersion: nebVer,
		NebulaSHA256:  nebSHA,
		NebulaURL:     nebURL,
		PilotVersion:  pilotVer,
		PilotSHA256:   pilotSHA,
		PilotURL:      pilotURL,
		NotAfter:      notAfter.UTC().Format(time.RFC3339),
	}
	return bundle.Sign(c.cfg.ConfigBackend, c.cfg.ConfigKeyID, b)
}

// blocklist returns the fleet's active revoked-cert fingerprints for a bundle
// (7.1) when a source is configured, else nil. A failed read falls back to an
// empty blocklist: an enrollment must not fail because the revocation store is
// briefly unreadable, and peers still enforce their own blocklists (§4.7).
func (c *Consumer) blocklist(ctx context.Context) []string {
	if c.cfg.BlocklistSource == nil {
		return nil
	}
	fps, err := c.cfg.BlocklistSource(ctx)
	if err != nil {
		return nil
	}
	return fps
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
	// A pending-approval result must outlive the operator-paced, unbounded manual-approval
	// wait, so it gets NO expiry — epoch (UnixNano 0) is the store's never-expire sentinel
	// (queue GetResult skips the expiry check when ExpiresAt == 0). issued/denied carry a
	// finite delivery TTL: the host has that long to fetch before the row is reaped.
	expiresAt := time.Unix(0, 0) // never-expire sentinel (pending awaiting approval)
	if status != StatusPending {
		ttl := c.cfg.ResultTTL
		if ttl <= 0 {
			ttl = time.Hour
		}
		expiresAt = c.now().Add(ttl)
	}
	_ = c.cfg.Results.PutResult(ctx, enrollmentID, status, secretHash, bundleJWS, reason, expiresAt)
}

// evidence carries cloud-attestation facts captured (from the cloud provider, never the
// host) for an attested enrollment. Zero value for token enrollments.
type evidence struct {
	provider, account, principal, region string
	verifiedAt                           int64
}

// record persists the enrollment row (the control plane's authoritative record of
// an issued/pending/denied decision). Callers MUST check the returned error and,
// on failure, NOT deliver a result — returning a non-terminal error so the queue
// redelivers: on redelivery existing() short-circuits a duplicate, or verify()'s
// consumed nonce yields a terminal ErrReplay. This keeps a cert from ever being
// handed to a host the control plane has no record of (which would be invisible to
// blocklist/fleet/audit). ephemeral records whether the host joined via an ephemeral
// join key (false for cloud-sigv4 / SSO).
func (c *Consumer) record(ctx context.Context, enrollmentID string, req wire.EnrollRequest, pubBytes []byte, joinKeyID int64, groups, subRange, status string, certPEM []byte, ip, fingerprint string, ev evidence, ephemeral bool) error {
	e := Enrollment{
		EnrollmentID:    enrollmentID,
		DeviceName:      deviceName(req, wire.PubkeyHash(pubBytes)),
		PubkeyHash:      wire.PubkeyHash(pubBytes),
		Pubkey:          pubBytes,
		Method:          req.Method,
		JoinKeyID:       joinKeyID,
		Groups:          groups,
		DesiredGroups:   groups, // desired == issued at enrollment; generations stay 0 (not pending re-issue)
		SubRange:        subRange,
		Status:          status,
		CertPEM:         certPEM,
		OverlayIP:       ip,
		Fingerprint:     fingerprint,
		Ephemeral:       ephemeral,
		CreatedAt:       c.now().UnixNano(),
		AttestProvider:  ev.provider,
		AttestAccount:   ev.account,
		AttestPrincipal: ev.principal,
		AttestRegion:    ev.region,
		VerifiedAt:      ev.verifiedAt,
		GOOS:            req.Client.OS,
		GOARCH:          req.Client.Arch,
	}
	if status != StatusPending {
		e.DecidedAt = c.now().UnixNano()
	}
	return c.cfg.Store.DB.WithContext(ctx).Create(&e).Error
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
