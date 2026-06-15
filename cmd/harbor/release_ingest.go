package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/binverify"
)

// resolveReleaseArgs turns the `add` flags into the (sha256, url) to register, shared by
// `harbor nebula add` and `harbor pilot add` (ADR 0003 ingest, Phase A). It is the
// pointer model's convenience: with -file it reads the LOCAL binary and computes its
// sha256 (the integrity anchor) so the operator never hand-copies a 64-hex digest;
// without -file it uses the supplied -sha256. -file and -sha256 are mutually exclusive.
// A `{version}` token in the url is substituted, so one URL template serves every
// release. Harbor never stores the bytes — they live in the operator's store (S3/CDN),
// and the signed-bundle sha makes that store untrusted.
func resolveReleaseArgs(file, version, sha, url string) (resolvedSHA, resolvedURL string, err error) {
	switch {
	case file != "" && sha != "":
		return "", "", fmt.Errorf("-file and -sha256 are mutually exclusive (give one)")
	case file != "":
		s, e := binverify.FileSHA256(file)
		if e != nil {
			return "", "", fmt.Errorf("hash %s: %w", file, e)
		}
		sha = s
	}
	return sha, strings.ReplaceAll(url, "{version}", version), nil
}

// reportReleaseURL best-effort HEADs the resolved url at `add` time and prints a
// reachability/size note. It is ADVISORY and never blocks: registering before uploading
// the bytes is a valid flow, so an unreachable url is a reminder, not an error. When a
// local -file was given, a served Content-Length that differs from the hashed file's size
// flags a likely wrong/stale object at the url before a rollout stalls on it.
func reportReleaseURL(ctx context.Context, file, url string) {
	var localSize int64
	if file != "" {
		if fi, err := os.Stat(file); err == nil {
			localSize = fi.Size()
		}
	}
	if msg, ok := checkReleaseURL(ctx, url, localSize); ok {
		fmt.Printf("  url: %s\n", msg)
	} else {
		fmt.Printf("  WARNING: %s\n", msg)
	}
}

// checkReleaseURL HEADs url and returns a human note + whether it looked OK. localSize>0
// (from a -file) enables a Content-Length cross-check. The pilot still verifies the sha on
// fetch, so this only catches operator mistakes early — it is not a security control.
func checkReleaseURL(ctx context.Context, url string, localSize int64) (string, bool) {
	c := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, http.NoBody)
	if err != nil {
		return fmt.Sprintf("url check skipped: %v", err), false
	}
	resp, err := c.Do(req)
	if err != nil {
		return fmt.Sprintf("url not reachable yet (%v) — upload the binary before `release`", err), false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Sprintf("url returned HTTP %d — upload the binary before `release`, or fix the url", resp.StatusCode), false
	}
	if localSize > 0 && resp.ContentLength >= 0 && resp.ContentLength != localSize {
		return fmt.Sprintf("reachable but serves %d bytes, not the %d-byte file you hashed — wrong object at the url?", resp.ContentLength, localSize), false
	}
	return fmt.Sprintf("reachable (%d bytes)", resp.ContentLength), true
}
