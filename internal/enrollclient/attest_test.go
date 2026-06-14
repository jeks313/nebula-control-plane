package enrollclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jeks313/nebula-control-plane/internal/awsattest"
	"github.com/jeks313/nebula-control-plane/internal/wire"
)

// mockIMDS serves the IMDSv2 flow FetchInstanceCredentials drives.
func mockIMDS(t *testing.T) *httptest.Server {
	t.Helper()
	const role = "ncp-node"
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "PUT" && r.URL.Path == "/latest/api/token":
			_, _ = w.Write([]byte("tok"))
		case r.Header.Get("X-aws-ec2-metadata-token") == "":
			w.WriteHeader(http.StatusUnauthorized)
		case r.URL.Path == "/latest/meta-data/placement/region":
			_, _ = w.Write([]byte("ca-central-1"))
		case r.URL.Path == "/latest/meta-data/iam/security-credentials/":
			_, _ = w.Write([]byte(role))
		case r.URL.Path == "/latest/meta-data/iam/security-credentials/"+role:
			_, _ = w.Write([]byte(`{"AccessKeyId":"AKID","SecretAccessKey":"sek","Token":"sesh"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

// TestEnrollCredentialAWSSigV4: the attestation path fetches instance creds and
// returns a presigned STS request bound to THIS enrollment's nonce + pubkey.
func TestEnrollCredentialAWSSigV4(t *testing.T) {
	imds := mockIMDS(t)
	defer imds.Close()
	p := Params{AWSSigV4: true, Now: func() time.Time { return time.Unix(1_700_000_000, 0).UTC() }, imds: awsattest.IMDSConfig{BaseURL: imds.URL}}

	method, cred, err := p.enrollCredential(context.Background(), "nonce-abc", "pubhash-xyz")
	if err != nil {
		t.Fatalf("enrollCredential: %v", err)
	}
	if method != wire.MethodAWSSigV4 {
		t.Fatalf("method = %q, want %q", method, wire.MethodAWSSigV4)
	}
	var pres awsattest.PresignedRequest
	if err := json.Unmarshal(cred, &pres); err != nil {
		t.Fatalf("credential is not a PresignedRequest: %v", err)
	}
	if !strings.Contains(pres.URL, "sts.") || !strings.HasPrefix(pres.URL, "https://") {
		t.Errorf("presigned URL is not an https STS host: %q", pres.URL)
	}
	// The Harbor binding (nonce + pubkey) must be carried in the signed request.
	body := string(cred)
	if !strings.Contains(body, "nonce-abc") || !strings.Contains(body, "pubhash-xyz") {
		t.Errorf("presigned request not bound to the nonce+pubkey: %s", body)
	}
}

// TestEnrollCredentialToken: the join-key path is unchanged.
func TestEnrollCredentialToken(t *testing.T) {
	p := Params{JoinKey: "njk_secret"}
	method, cred, err := p.enrollCredential(context.Background(), "n", "p")
	if err != nil {
		t.Fatal(err)
	}
	if method != wire.MethodToken {
		t.Fatalf("method = %q, want token", method)
	}
	var c struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(cred, &c); err != nil || c.Token != "njk_secret" {
		t.Fatalf("token credential = %s (%v)", cred, err)
	}
}

// TestEnrollCredentialNeither: no join key and no attestation is an error (the CLI
// also guards this, but the client must fail closed regardless).
func TestEnrollCredentialNeither(t *testing.T) {
	p := Params{}
	if _, _, err := p.enrollCredential(context.Background(), "n", "p"); err == nil {
		t.Fatal("expected an error when neither a join key nor AWSSigV4 is set")
	}
}
