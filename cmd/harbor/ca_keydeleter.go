package main

import (
	"context"
	"fmt"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"

	"github.com/jeks313/nebula-control-plane/internal/ca"
)

// caKeyDeleter picks the M8.4 key-deletion backend for a `harbor ca schedule/cancel-key-deletion`
// run: the real AWS KMS driver for a KMS install, else the software no-op (dev / PKCS#11, where key
// destruction is a manual HSM op). The KMS path is WIRED for the poc but validated only against real
// AWS — the local flow + guardrails are exercised through ca.NoopKeyDeleter.
func caKeyDeleter(ctx context.Context, backend, kmsRegion string) (ca.KeyDeleter, error) {
	if backend == "kms" {
		return newKMSKeyDeleter(ctx, kmsRegion)
	}
	return ca.NoopKeyDeleter{}, nil
}

// kmsDeleteAPI is the slice of the KMS client the deleter uses (so it stays swappable/testable).
type kmsDeleteAPI interface {
	ScheduleKeyDeletion(context.Context, *kms.ScheduleKeyDeletionInput, ...func(*kms.Options)) (*kms.ScheduleKeyDeletionOutput, error)
	CancelKeyDeletion(context.Context, *kms.CancelKeyDeletionInput, ...func(*kms.Options)) (*kms.CancelKeyDeletionOutput, error)
}

// kmsKeyDeleter is the production ca.KeyDeleter: it drives AWS KMS ScheduleKeyDeletion /
// CancelKeyDeletion on a CA's non-exportable signing key. The pending window (7-30 days) is enforced
// by KMS; during it CancelKeyDeletion restores the key. Never exports or reads the key material (P2).
type kmsKeyDeleter struct {
	api     kmsDeleteAPI
	timeout time.Duration
}

func newKMSKeyDeleter(ctx context.Context, region string) (*kmsKeyDeleter, error) {
	var opts []func(*awsconfig.LoadOptions) error
	if region != "" {
		opts = append(opts, awsconfig.WithRegion(region))
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("kms key deleter: load AWS config: %w", err)
	}
	return &kmsKeyDeleter{api: kms.NewFromConfig(cfg), timeout: 15 * time.Second}, nil
}

// ScheduleDeletion schedules kmsKeyID for deletion after pendingDays and returns KMS's deletion date.
func (d *kmsKeyDeleter) ScheduleDeletion(ctx context.Context, kmsKeyID string, pendingDays int32) (time.Time, error) {
	cctx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()
	out, err := d.api.ScheduleKeyDeletion(cctx, &kms.ScheduleKeyDeletionInput{
		KeyId: &kmsKeyID, PendingWindowInDays: &pendingDays,
	})
	if err != nil {
		return time.Time{}, err
	}
	if out.DeletionDate == nil {
		return time.Time{}, fmt.Errorf("kms: ScheduleKeyDeletion returned no deletion date")
	}
	return *out.DeletionDate, nil
}

// CancelDeletion aborts a pending deletion of kmsKeyID, restoring the key to usable.
func (d *kmsKeyDeleter) CancelDeletion(ctx context.Context, kmsKeyID string) error {
	cctx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()
	_, err := d.api.CancelKeyDeletion(cctx, &kms.CancelKeyDeletionInput{KeyId: &kmsKeyID})
	return err
}
