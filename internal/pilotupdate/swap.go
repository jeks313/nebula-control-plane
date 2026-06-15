package pilotupdate

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"

	"github.com/jeks313/nebula-control-plane/internal/binverify"
)

// swap atomically replaces the binary at path with data, first preserving the current
// binary at lastGood via a COPY (non-destructive: path always holds a runnable binary
// even if a step fails or we crash mid-swap — never the "old moved out, new not yet in"
// gap). data is written + sha-verified off to the side, then renamed into place.
// Mirrors nebulaupdate's crash-safe install; the brick-risk here (a missing pilot
// binary) is exactly what must never happen.
func swap(path, lastGood string, data []byte) error {
	tmp := path + ".new"
	if err := os.WriteFile(tmp, data, 0o755); err != nil {
		return fmt.Errorf("pilotupdate: write %s: %w", tmp, err)
	}
	if err := os.Chmod(tmp, 0o755); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("pilotupdate: chmod %s: %w", tmp, err)
	}
	sum := sha256.Sum256(data)
	if err := binverify.SHA256(tmp, hex.EncodeToString(sum[:])); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("pilotupdate: post-write verify: %w", err)
	}
	if _, err := os.Stat(path); err == nil {
		if err := copyFile(path, lastGood); err != nil {
			_ = os.Remove(tmp)
			return fmt.Errorf("pilotupdate: keep last-good: %w", err)
		}
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp) // path still holds the prior binary; nothing moved out
		return fmt.Errorf("pilotupdate: install: %w", err)
	}
	return nil
}

// restore copies lastGood back over path (atomically), for the revert path. It errors
// (changing nothing destructive) when there is no last-good to revert to.
func restore(lastGood, path string) error {
	if _, err := os.Stat(lastGood); err != nil {
		return fmt.Errorf("no last-good binary to revert to: %w", err)
	}
	return copyFile(lastGood, path)
}

// restoreRetry restores lastGood over path, retrying a few times to ride out a
// transient fs error (the revert is the brick-prevention path; give it more than one
// shot before giving up).
func restoreRetry(lastGood, path string) error {
	var err error
	for i := 0; i < 3; i++ {
		if err = restore(lastGood, path); err == nil {
			return nil
		}
	}
	return err
}

// sameContents reports whether two files have the same SHA-256 — used to detect that a
// revert already happened (path == last-good) so CheckRevert doesn't loop when it
// couldn't clear the marker.
func sameContents(a, b string) (bool, error) {
	sa, err := binverify.FileSHA256(a)
	if err != nil {
		return false, err
	}
	sb, err := binverify.FileSHA256(b)
	if err != nil {
		return false, err
	}
	return sa == sb, nil
}

// copyFile copies src to dst (mode 0o755) crash-safely: stage to dst+".tmp", then
// atomically rename into place — dst is never a partial file.
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dst + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Chmod(tmp, 0o755); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}
