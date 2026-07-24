package bundle

import (
	"crypto/ecdsa"
	"encoding/json"
	"os"

	"github.com/slackhq/nebula/cert"

	"github.com/jeks313/nebula-control-plane/internal/jws"
)

// TrustFile is Pilot's on-disk record of the config-signing keys it has LEARNED from a verified
// bundle during a config-key rotation (M8.5). It is written next to bundle.json (paths.Layout
// .ConfigSigningTrust) on every successful apply and re-read at every verify, so a long-running pilot
// starts trusting the newly-staged key mid-run (no restart) and keeps trusting it across reboots. The
// permanent pin (config-signing.pub) is ALWAYS trusted in addition to these — a rotation never
// un-pins the root online (that is 8.6's out-of-band re-pin). Version is monotonic (the registry
// generation) so a replayed OLD bundle cannot regress the learned set / re-introduce a retired key.
type TrustFile struct {
	Version int64    `json:"config_key_version"`
	Keys    []string `json:"keys"` // config-signing PUBLIC-key PEM blocks (from the bundle's config_signing_keys)
}

// ParsePubPEMs parses config-signing PUBLIC-key PEM blocks into ecdsa keys, skipping any that do not
// parse as a P256 point (fail-SAFE: a single corrupt learned key must never brick verification of a
// bundle a good key in the set can still verify). Returns the keys it could parse.
func ParsePubPEMs(pems []string) []*ecdsa.PublicKey {
	out := make([]*ecdsa.PublicKey, 0, len(pems))
	for _, p := range pems {
		pub, _, curve, err := cert.UnmarshalPublicKeyFromPEM([]byte(p))
		if err != nil || curve != cert.Curve_P256 {
			continue
		}
		k, err := jws.ParseP256PublicPoint(pub)
		if err != nil {
			continue
		}
		out = append(out, k)
	}
	return out
}

// LoadTrustFile reads Pilot's learned config-signing trust file and returns its version + parsed
// keys. A missing/unreadable/corrupt file yields (0, nil) — the caller then trusts only its permanent
// pin (fail-SAFE: never accept-all, never empty-and-brick).
func LoadTrustFile(path string) (version int64, pubs []*ecdsa.PublicKey) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, nil
	}
	var tf TrustFile
	if err := json.Unmarshal(raw, &tf); err != nil {
		return 0, nil
	}
	return tf.Version, ParsePubPEMs(tf.Keys)
}

// PersistTrustFile atomically records the learned config-signing keys IF this is not a rollback:
// it writes {version, keyPEMs} only when version >= the currently-recorded version and keyPEMs is
// non-empty (a legacy bundle with no config_signing_keys, or an older ConfigKeyVersion, is a no-op —
// fail-SAFE anti-rollback that keeps the last-good set rather than regressing it). Atomic via
// temp+rename so a crash never leaves a half-written trust file.
func PersistTrustFile(path string, version int64, keyPEMs []string) error {
	if len(keyPEMs) == 0 {
		return nil // legacy / no rotation advertised — leave any existing set untouched
	}
	if cur, _ := LoadTrustFile(path); version < cur {
		return nil // anti-rollback: a replayed OLDER bundle must not regress the learned set
	}
	raw, err := json.Marshal(TrustFile{Version: version, Keys: keyPEMs})
	if err != nil {
		return err
	}
	// Write durably (fsync before rename) so a power loss can't leave the learned trust set behind
	// the applied bundle.json — after a completed rotation the permanent pin no longer signs, so a
	// LOST trust file (unlike a lagging one) collapses the verify set to pin-only and the host can no
	// longer verify the active key's bundles (recoverable only by re-enroll or the 8.6 re-pin). fsync
	// keeps that window as small as the OS allows.
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(raw); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// TrustedSet is Pilot's live config-signing trust set for verifying a bundle (M8.5): its permanent
// pin(s) UNION the keys learned in trustFilePath, deduplicated. Re-read from disk at EVERY verify so
// a running pilot picks up a newly-staged key the moment it has applied a bundle advertising it (no
// restart), while the pin is always present so a missing/corrupt trust file falls back to the pin —
// never to empty (which would reject everything) and never to accept-all.
//
// Fail-SAFE caveat: pin-only fallback keeps verifying DURING an overlap (the pin still signs), but
// after a rotation COMPLETES (the pinned key retired, signing fully on the new key) a LOST trust file
// leaves pin-only, which can no longer verify the active key's bundles — that host recovers only by
// re-enroll or an 8.6 out-of-band re-pin. PersistTrustFile fsyncs to keep that window minimal.
func TrustedSet(pins []*ecdsa.PublicKey, trustFilePath string) []*ecdsa.PublicKey {
	out := make([]*ecdsa.PublicKey, 0, len(pins)+2)
	out = append(out, pins...)
	_, learned := LoadTrustFile(trustFilePath)
	for _, k := range learned {
		if k == nil || containsKey(out, k) {
			continue
		}
		out = append(out, k)
	}
	return out
}

func containsKey(set []*ecdsa.PublicKey, k *ecdsa.PublicKey) bool {
	for _, x := range set {
		if x != nil && x.Equal(k) {
			return true
		}
	}
	return false
}
