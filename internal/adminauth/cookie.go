package adminauth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// cookieSigner makes short-lived login-state cookies tamper-evident with
// HMAC-SHA256 under a per-process random key. These cookies carry values the
// server later TRUSTS to bind a login: the OIDC nonce + PKCE verifier, and the
// SAML AuthnRequest ID (matched as InResponseTo). An unsigned cookie lets an
// attacker forge those — e.g. an empty SAML RequestID defeats the request binding
// and admits unsolicited assertions, and a chosen RequestID enables replay of a
// captured assertion. The key is ephemeral: in-flight logins (~10 min) do not
// survive a restart, which is fine.
type cookieSigner struct{ key []byte }

func newCookieSigner() (cookieSigner, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return cookieSigner{}, fmt.Errorf("adminauth: cookie signer key: %w", err)
	}
	return cookieSigner{key: key}, nil
}

// encode serializes v and appends an HMAC tag: base64(json).base64(mac).
func (c cookieSigner) encode(v any) (string, error) {
	payload, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(payload) + "." +
		base64.RawURLEncoding.EncodeToString(c.mac(payload)), nil
}

// decode verifies the HMAC (constant-time) before unmarshaling. A tampered or
// unsigned value fails closed (returns false).
func (c cookieSigner) decode(s string, v any) bool {
	body, sig, ok := strings.Cut(s, ".")
	if !ok {
		return false
	}
	payload, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return false
	}
	gotMAC, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		return false
	}
	if !hmac.Equal(gotMAC, c.mac(payload)) {
		return false
	}
	return json.Unmarshal(payload, v) == nil
}

func (c cookieSigner) mac(payload []byte) []byte {
	h := hmac.New(sha256.New, c.key)
	h.Write(payload)
	return h.Sum(nil)
}
