package signer

// AWS KMS backend (pure Go, no cgo / build tag — unlike PKCS#11). The CA / config-signing
// private key is a non-exportable ECC_NIST_P256 KMS key; Harbor only ever hands KMS a
// digest to sign ("our logic, their guarantees"). This is the production path for a full
// AWS install; SoftHSM/PKCS#11 remains the minimal self-hosted / debug path and the
// software backend is for tests + throwaway dev.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// kmsAPI is the slice of the KMS client the backend uses, so tests inject a fake without
// touching AWS. *kms.Client satisfies it.
type kmsAPI interface {
	GetPublicKey(context.Context, *kms.GetPublicKeyInput, ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error)
	Sign(context.Context, *kms.SignInput, ...func(*kms.Options)) (*kms.SignOutput, error)
}

// KMSConfig builds a KMSBackend. KeyID is a KMS key id / ARN / alias for an
// ECC_NIST_P256, SIGN_VERIFY key.
type KMSConfig struct {
	KeyID   string
	Region  string        // optional; else the default chain (env / instance role)
	Timeout time.Duration // per-call timeout (0 -> 10s) so a hung KMS call can't wedge issuance
}

// KMSBackend signs with a non-exportable AWS KMS P256 key. It implements signer.Backend:
// SignDigest returns KMS's ASN.1-DER ECDSA signature unchanged (exactly what the contract
// + Nebula's SignerLambda want), and PublicKey converts KMS's DER SPKI to the 65-byte
// uncompressed point Nebula encodes.
type KMSBackend struct {
	api     kmsAPI
	keyID   string
	timeout time.Duration

	mu  sync.Mutex
	pub []byte // cached uncompressed point (the key is immutable)
}

// NewKMSBackend builds a backend over the real AWS KMS client (region/credentials from the
// default chain unless Region is set). It does NOT touch the key here — the first
// PublicKey()/SignDigest() does (and signer.New then verifies the pubkey matches the CA
// cert, so a wrong KeyID fails fast).
func NewKMSBackend(ctx context.Context, cfg KMSConfig) (*KMSBackend, error) {
	if cfg.KeyID == "" {
		return nil, errors.New("signer: KMS KeyID is required")
	}
	var opts []func(*awsconfig.LoadOptions) error
	if cfg.Region != "" {
		opts = append(opts, awsconfig.WithRegion(cfg.Region))
	}
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("signer: load AWS config: %w", err)
	}
	return newKMSBackend(kms.NewFromConfig(awsCfg), cfg.KeyID, cfg.Timeout), nil
}

// newKMSBackend is the injectable constructor (tests pass a fake kmsAPI).
func newKMSBackend(api kmsAPI, keyID string, timeout time.Duration) *KMSBackend {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &KMSBackend{api: api, keyID: keyID, timeout: timeout}
}

func (b *KMSBackend) callCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), b.timeout)
}

// PublicKey returns the CA signing public key as a 65-byte uncompressed P256 point.
// Cached after the first success (the key never changes).
func (b *KMSBackend) PublicKey() ([]byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.pub != nil {
		return append([]byte(nil), b.pub...), nil
	}
	ctx, cancel := b.callCtx()
	defer cancel()
	out, err := b.api.GetPublicKey(ctx, &kms.GetPublicKeyInput{KeyId: aws.String(b.keyID)})
	if err != nil {
		return nil, fmt.Errorf("signer: KMS GetPublicKey %s: %w", b.keyID, err)
	}
	if out.KeySpec != types.KeySpecEccNistP256 {
		return nil, fmt.Errorf("signer: KMS key %s is %s, want ECC_NIST_P256", b.keyID, out.KeySpec)
	}
	// A P256 key can be created for KEY_AGREEMENT (ECDH) — it would yield a valid point here
	// but reject ECDSA Sign later. Require SIGN_VERIFY so a misconfigured key id fails at the
	// genesis ceremony (cheap) rather than at the first runtime signature.
	if out.KeyUsage != types.KeyUsageTypeSignVerify {
		return nil, fmt.Errorf("signer: KMS key %s usage is %s, want SIGN_VERIFY", b.keyID, out.KeyUsage)
	}
	// out.PublicKey is DER SubjectPublicKeyInfo; convert to the uncompressed point.
	pk, err := x509.ParsePKIXPublicKey(out.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("signer: parse KMS public key %s: %w", b.keyID, err)
	}
	ec, ok := pk.(*ecdsa.PublicKey)
	if !ok || ec.Curve != elliptic.P256() {
		return nil, fmt.Errorf("signer: KMS key %s public key is not P256 ECDSA", b.keyID)
	}
	ek, err := ec.ECDH()
	if err != nil {
		return nil, fmt.Errorf("signer: export KMS public key %s: %w", b.keyID, err)
	}
	b.pub = ek.Bytes()
	return append([]byte(nil), b.pub...), nil
}

// SignDigest signs a 32-byte SHA-256 digest with the KMS key and returns the ASN.1 DER
// ECDSA signature (KMS returns DER, which is exactly what the Backend contract expects).
func (b *KMSBackend) SignDigest(digest []byte) ([]byte, error) {
	if len(digest) != 32 {
		return nil, fmt.Errorf("signer: KMS SignDigest wants a 32-byte SHA-256 digest, got %d", len(digest))
	}
	ctx, cancel := b.callCtx()
	defer cancel()
	out, err := b.api.Sign(ctx, &kms.SignInput{
		KeyId:            aws.String(b.keyID),
		Message:          digest,
		MessageType:      types.MessageTypeDigest,
		SigningAlgorithm: types.SigningAlgorithmSpecEcdsaSha256,
	})
	if err != nil {
		return nil, fmt.Errorf("signer: KMS Sign %s: %w", b.keyID, err)
	}
	if len(out.Signature) == 0 {
		return nil, fmt.Errorf("signer: KMS Sign %s returned an empty signature", b.keyID)
	}
	return out.Signature, nil
}
