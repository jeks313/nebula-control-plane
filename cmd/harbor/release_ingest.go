package main

import (
	"fmt"
	"strings"

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
