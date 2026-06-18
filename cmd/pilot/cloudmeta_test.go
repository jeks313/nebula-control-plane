package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// fakeAWSIMDS mirrors internal/awsattest's fake-IMDS approach: an IMDSv2 token PUT
// gates every GET, then serves the instance-identity document + IAM role listing.
func fakeAWSIMDS(t *testing.T, role string) *httptest.Server {
	t.Helper()
	const idoc = `{
	  "accountId": "123456789012",
	  "region": "us-east-1",
	  "instanceId": "i-0abc123def456",
	  "instanceType": "t3.micro",
	  "imageId": "ami-0deadbeef"
	}`
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPut && r.URL.Path == "/latest/api/token":
			_, _ = w.Write([]byte("imds-token"))
		case r.Header.Get("X-aws-ec2-metadata-token") != "imds-token":
			w.WriteHeader(http.StatusUnauthorized) // IMDSv2: GETs require the token
		case r.URL.Path == "/latest/dynamic/instance-identity/document":
			_, _ = w.Write([]byte(idoc))
		case r.URL.Path == "/latest/meta-data/iam/security-credentials/":
			_, _ = w.Write([]byte(role))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

// TestDetectAWS: a fake EC2 IMDS yields the identity doc, the IAM role, and the
// derived assumed-role ARN + cloudtrust hint.
func TestDetectAWS(t *testing.T) {
	srv := fakeAWSIMDS(t, "web-role")
	defer srv.Close()

	m := detectAWS(context.Background(), srv.URL, srv.Client())
	if m == nil {
		t.Fatal("detectAWS returned nil on a valid fake IMDS")
	}
	if m.AccountID != "123456789012" || m.Region != "us-east-1" || m.InstanceID != "i-0abc123def456" {
		t.Fatalf("identity doc mis-parsed: %+v", m)
	}
	if m.InstanceType != "t3.micro" || m.ImageID != "ami-0deadbeef" {
		t.Fatalf("instance type/image mis-parsed: %+v", m)
	}
	if len(m.Roles) != 1 || m.Roles[0] != "web-role" {
		t.Fatalf("roles = %v, want [web-role]", m.Roles)
	}
	wantARN := "arn:aws:sts::123456789012:assumed-role/web-role/i-0abc123def456"
	if m.AssumedRoleARN != wantARN {
		t.Fatalf("assumed-role ARN = %q, want %q", m.AssumedRoleARN, wantARN)
	}
	wantPat := "arn:aws:sts::123456789012:assumed-role/web-role/*"
	if m.CloudtrustARNPattern != wantPat {
		t.Fatalf("cloudtrust pattern = %q, want %q", m.CloudtrustARNPattern, wantPat)
	}
}

// TestDetectAWSNoRole: an instance with no IAM role still reports identity, but the
// ARN derivation is skipped (sigv4 enrollment would have nothing to attest with).
func TestDetectAWSNoRole(t *testing.T) {
	srv := fakeAWSIMDS(t, "") // empty role listing
	defer srv.Close()

	m := detectAWS(context.Background(), srv.URL, srv.Client())
	if m == nil {
		t.Fatal("detectAWS returned nil")
	}
	if len(m.Roles) != 0 {
		t.Fatalf("roles = %v, want none", m.Roles)
	}
	if m.AssumedRoleARN != "" || m.CloudtrustARNPattern != "" {
		t.Fatalf("ARN/pattern should be empty with no role: %+v", m)
	}
}

// TestDetectAWSOffCloud: no IMDS at the endpoint -> nil (the laptop/CI path), and no
// error escapes (the command must still complete).
func TestDetectAWSOffCloud(t *testing.T) {
	// A server that refuses the token PUT (e.g. a non-EC2 box answering 404).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	if m := detectAWS(context.Background(), srv.URL, srv.Client()); m != nil {
		t.Fatalf("expected nil off-cloud (no token), got %+v", m)
	}

	// A dead address (transport error) is also off-cloud, not a panic.
	if m := detectAWS(context.Background(), "http://127.0.0.1:1", &http.Client{}); m != nil {
		t.Fatalf("expected nil for unreachable IMDS, got %+v", m)
	}
}

// TestDetectAWSTokenButNoDoc: a half-emulated metadata service that answers the token
// PUT but has no identity document is treated as off-cloud (not a real EC2 IMDS).
func TestDetectAWSTokenButNoDoc(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut && r.URL.Path == "/latest/api/token" {
			_, _ = w.Write([]byte("t"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	if m := detectAWS(context.Background(), srv.URL, srv.Client()); m != nil {
		t.Fatalf("expected nil when identity doc absent, got %+v", m)
	}
}

// fakeAzureIMDS serves the Azure instance metadata document (Metadata: true header
// required) and, optionally, a managed-identity token.
func fakeAzureIMDS(t *testing.T, withIdentity bool) *httptest.Server {
	t.Helper()
	const doc = `{
	  "compute": {
	    "subscriptionId": "00000000-1111-2222-3333-444444444444",
	    "resourceGroupName": "rg-prod",
	    "name": "vm-edge-01",
	    "vmId": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
	    "location": "eastus"
	  }
	}`
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Metadata") != "true" {
			w.WriteHeader(http.StatusBadRequest) // Azure IMDS requires the header
			return
		}
		switch r.URL.Path {
		case "/metadata/instance":
			_, _ = w.Write([]byte(doc))
		case "/metadata/identity/oauth2/token":
			if withIdentity {
				_, _ = w.Write([]byte(`{"access_token":"x"}`))
			} else {
				w.WriteHeader(http.StatusBadRequest)
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

// TestDetectAzure: a fake Azure IMDS yields the compute block + managed-identity flag.
func TestDetectAzure(t *testing.T) {
	srv := fakeAzureIMDS(t, true)
	defer srv.Close()

	m := detectAzure(context.Background(), srv.URL, srv.Client())
	if m == nil {
		t.Fatal("detectAzure returned nil on a valid fake IMDS")
	}
	if m.SubscriptionID != "00000000-1111-2222-3333-444444444444" || m.ResourceGroup != "rg-prod" {
		t.Fatalf("subscription/rg mis-parsed: %+v", m)
	}
	if m.VMName != "vm-edge-01" || m.VMID != "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" || m.Location != "eastus" {
		t.Fatalf("vm fields mis-parsed: %+v", m)
	}
	if !m.ManagedIdentity {
		t.Fatal("managed identity should be true (token endpoint answered 200)")
	}
}

// TestDetectAzureNoIdentity: no managed identity -> ManagedIdentity false, still
// reports the VM facts.
func TestDetectAzureNoIdentity(t *testing.T) {
	srv := fakeAzureIMDS(t, false)
	defer srv.Close()
	m := detectAzure(context.Background(), srv.URL, srv.Client())
	if m == nil {
		t.Fatal("detectAzure returned nil")
	}
	if m.ManagedIdentity {
		t.Fatal("managed identity should be false (token endpoint refused)")
	}
}

// TestDetectAzureOffCloud: no Azure IMDS -> nil, no error.
func TestDetectAzureOffCloud(t *testing.T) {
	// An AWS-style IMDS (no Azure compute block) is off-cloud for Azure.
	srv := fakeAWSIMDS(t, "web-role")
	defer srv.Close()
	if m := detectAzure(context.Background(), srv.URL, srv.Client()); m != nil {
		t.Fatalf("AWS IMDS must not parse as Azure, got %+v", m)
	}
	if m := detectAzure(context.Background(), "http://127.0.0.1:1", &http.Client{}); m != nil {
		t.Fatalf("unreachable IMDS must be nil, got %+v", m)
	}
}

// TestCloudtrustHintFormatting pins the exact account + ARN-pattern strings an operator
// pastes into Harbor's cloudtrust config — the onboarding contract.
func TestCloudtrustHintFormatting(t *testing.T) {
	const acct, role, inst = "123456789012", "edge-fleet", "i-0123456789abcdef0"

	if got := AssumedRoleARN(acct, role, inst); got != "arn:aws:sts::123456789012:assumed-role/edge-fleet/i-0123456789abcdef0" {
		t.Fatalf("assumed-role ARN = %q", got)
	}
	if got := CloudtrustARNPattern(acct, role); got != "arn:aws:sts::123456789012:assumed-role/edge-fleet/*" {
		t.Fatalf("cloudtrust pattern = %q", got)
	}
	// Empty instance id (rare) widens the session to '*' so the ARN is still well-formed.
	if got := AssumedRoleARN(acct, role, ""); got != "arn:aws:sts::123456789012:assumed-role/edge-fleet/*" {
		t.Fatalf("ARN with empty instance id = %q", got)
	}
}

// TestGatherCloudPrecedence: AWS is detected first; when only Azure metadata is present
// the provider is azure; off-cloud is "none".
func TestGatherCloudPrecedence(t *testing.T) {
	aws := fakeAWSIMDS(t, "web-role")
	defer aws.Close()
	if c := gatherCloud(context.Background(), aws.URL, aws.Client()); c.Provider != "aws" || c.AWS == nil {
		t.Fatalf("aws path: provider=%q aws=%v", c.Provider, c.AWS)
	}

	az := fakeAzureIMDS(t, false)
	defer az.Close()
	if c := gatherCloud(context.Background(), az.URL, az.Client()); c.Provider != "azure" || c.Azure == nil {
		t.Fatalf("azure path: provider=%q azure=%v", c.Provider, c.Azure)
	}

	off := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer off.Close()
	if c := gatherCloud(context.Background(), off.URL, off.Client()); c.Provider != "none" || c.AWS != nil || c.Azure != nil {
		t.Fatalf("off-cloud path: provider=%q", c.Provider)
	}
}
