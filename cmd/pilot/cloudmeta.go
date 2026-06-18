package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// cloudmeta.go probes the local instance-metadata service (IMDS) to discover the
// cloud identity this node would present when it attests to Harbor. It mirrors the
// IMDSv2 token->GET pattern in internal/awsattest (the enroll path), but reads the
// instance-identity document + IAM role NAME(s) rather than signing credentials —
// `pilot info` is a read-only diagnostic, not an attestation.
//
// Every probe is short-timeout and fails gracefully (returns nil, no error) so the
// command works off-cloud (a laptop, a CI box) where 169.254.169.254 is unreachable
// or simply absent.

// imdsTimeout caps each cloud-metadata probe. IMDS is link-local (a single hop), so a
// real instance answers in milliseconds; a non-cloud host either refuses fast or has
// nothing on 169.254.169.254 and we want to fall through quickly, not hang the command.
const imdsTimeout = 1500 * time.Millisecond

// AWSMeta is the AWS instance identity `pilot info` reports. It is derived entirely
// from IMDS (no STS call) — enough to onboard the node's account/role into Harbor's
// cloudtrust config.
type AWSMeta struct {
	AccountID    string   `json:"account_id"`
	Region       string   `json:"region"`
	InstanceID   string   `json:"instance_id"`
	InstanceType string   `json:"instance_type,omitempty"`
	ImageID      string   `json:"image_id,omitempty"`
	Roles        []string `json:"roles"`
	// AssumedRoleARN is the sts:GetCallerIdentity ARN this instance's role
	// credentials resolve to — what Harbor's awsattest.Verify sees in the STS
	// response. Derived from account + role + instance-id (the standard EC2
	// assumed-role session-name convention).
	AssumedRoleARN string `json:"assumed_role_arn,omitempty"`
	// CloudtrustARNPattern is a copy-pasteable ARN glob (the instance-id widened to
	// `*`) an operator adds to Harbor's per-mesh cloudtrust ARNPatterns to trust this
	// role across all instances that assume it.
	CloudtrustARNPattern string `json:"cloudtrust_arn_pattern,omitempty"`
}

// AzureMeta is the Azure instance identity `pilot info` reports. Azure attestation is
// NOT yet supported by Harbor (AWS SigV4 only), so this is informational — it helps an
// operator see what an Azure VM would present once Harbor grows an Azure verifier.
type AzureMeta struct {
	SubscriptionID  string `json:"subscription_id"`
	ResourceGroup   string `json:"resource_group"`
	VMName          string `json:"vm_name"`
	VMID            string `json:"vm_id"`
	Location        string `json:"location"`
	ManagedIdentity bool   `json:"managed_identity"`
}

// imdsGetter is a small IMDSv2 GET helper: PUT a session token once, then issue
// token-gated GETs. baseURL defaults to the link-local IMDS address; tests point it at
// a fake server.
type imdsGetter struct {
	base   string
	token  string
	client *http.Client
}

// newAWSIMDS performs the IMDSv2 token PUT and returns a getter, or nil if the token
// endpoint is unreachable (the off-cloud / IMDS-blocked path). The token PUT is the
// cheap "are we on EC2?" probe.
func newAWSIMDS(ctx context.Context, base string, client *http.Client) *imdsGetter {
	if base == "" {
		base = "http://169.254.169.254"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, base+"/latest/api/token", http.NoBody)
	if err != nil {
		return nil
	}
	req.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "60")
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return &imdsGetter{base: base, token: strings.TrimSpace(string(b)), client: client}
}

// get fetches a metadata path; "" + nil on any non-200 / transport error so callers can
// treat a missing field as simply absent.
func (g *imdsGetter) get(ctx context.Context, path string) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, g.base+path, http.NoBody)
	if err != nil {
		return ""
	}
	if g.token != "" {
		req.Header.Set("X-aws-ec2-metadata-token", g.token)
	}
	resp, err := g.client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	return strings.TrimSpace(string(b))
}

// detectAWS reads the instance-identity document + IAM role(s) over IMDSv2 and derives
// the attestation ARN + cloudtrust hint. Returns nil off-cloud (not on EC2, or IMDS
// blocked) — never an error, so `pilot info` always completes.
func detectAWS(ctx context.Context, base string, client *http.Client) *AWSMeta {
	if client == nil {
		client = &http.Client{Timeout: imdsTimeout}
	}
	g := newAWSIMDS(ctx, base, client)
	if g == nil {
		return nil
	}

	doc := g.get(ctx, "/latest/dynamic/instance-identity/document")
	if doc == "" {
		// On EC2 the identity doc is always present; its absence means this isn't a
		// genuine EC2 IMDS (e.g. a half-emulated metadata service) — treat as off-cloud.
		return nil
	}
	var idoc struct {
		AccountID    string `json:"accountId"`
		Region       string `json:"region"`
		InstanceID   string `json:"instanceId"`
		InstanceType string `json:"instanceType"`
		ImageID      string `json:"imageId"`
	}
	if err := json.Unmarshal([]byte(doc), &idoc); err != nil {
		return nil
	}

	m := &AWSMeta{
		AccountID:    idoc.AccountID,
		Region:       idoc.Region,
		InstanceID:   idoc.InstanceID,
		InstanceType: idoc.InstanceType,
		ImageID:      idoc.ImageID,
	}

	// IAM role name(s): the security-credentials/ listing is newline-separated role
	// names (usually exactly one for an EC2 instance profile).
	if list := g.get(ctx, "/latest/meta-data/iam/security-credentials/"); list != "" {
		for _, r := range strings.Split(list, "\n") {
			if r = strings.TrimSpace(r); r != "" {
				m.Roles = append(m.Roles, r)
			}
		}
	}

	// Derive the assumed-role ARN + cloudtrust hint from the first role. EC2's instance
	// profile makes the assumed-role session name the instance id, so STS returns
	// arn:aws:sts::<account>:assumed-role/<role>/<instance-id>.
	if len(m.Roles) > 0 && m.AccountID != "" {
		m.AssumedRoleARN = AssumedRoleARN(m.AccountID, m.Roles[0], m.InstanceID)
		m.CloudtrustARNPattern = CloudtrustARNPattern(m.AccountID, m.Roles[0])
	}
	return m
}

// AssumedRoleARN is the sts:GetCallerIdentity ARN an EC2 instance role resolves to:
// arn:aws:sts::<account>:assumed-role/<role>/<session>, where EC2 sets the session name
// to the instance id. This is exactly the Arn Harbor's awsattest.Verify reads from STS.
func AssumedRoleARN(account, role, instanceID string) string {
	session := instanceID
	if session == "" {
		session = "*"
	}
	return fmt.Sprintf("arn:aws:sts::%s:assumed-role/%s/%s", account, role, session)
}

// CloudtrustARNPattern is the onboarding hint: the assumed-role ARN with the per-session
// (instance-id) component widened to `*`, so it matches every instance that assumes the
// role. It is the literal value an operator adds to a mesh's cloudtrust ARNPatterns
// (awsattest.Policy.ARNPatterns, glob-matched), trusting the whole role scope.
func CloudtrustARNPattern(account, role string) string {
	return fmt.Sprintf("arn:aws:sts::%s:assumed-role/%s/*", account, role)
}

// detectAzure reads the Azure instance metadata document. Returns nil off-cloud (not on
// Azure, or IMDS blocked) — never an error. Azure attestation is informational only
// (Harbor verifies AWS SigV4 only); see the note `pilot info` prints.
func detectAzure(ctx context.Context, base string, client *http.Client) *AzureMeta {
	if client == nil {
		client = &http.Client{Timeout: imdsTimeout}
	}
	if base == "" {
		base = "http://169.254.169.254"
	}
	url := base + "/metadata/instance?api-version=2021-02-01&format=json"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil
	}
	req.Header.Set("Metadata", "true")
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<18))

	var doc struct {
		Compute struct {
			SubscriptionID    string `json:"subscriptionId"`
			ResourceGroupName string `json:"resourceGroupName"`
			Name              string `json:"name"`
			VMID              string `json:"vmId"`
			Location          string `json:"location"`
		} `json:"compute"`
	}
	if err := json.Unmarshal(b, &doc); err != nil || doc.Compute.VMID == "" {
		// No compute block / unparseable -> not a genuine Azure IMDS response.
		return nil
	}
	m := &AzureMeta{
		SubscriptionID: doc.Compute.SubscriptionID,
		ResourceGroup:  doc.Compute.ResourceGroupName,
		VMName:         doc.Compute.Name,
		VMID:           doc.Compute.VMID,
		Location:       doc.Compute.Location,
	}
	// Best-effort managed-identity probe: a token endpoint that answers (even with an
	// error body) means an identity is assignable. A 400 "identity not found" means none.
	m.ManagedIdentity = azureHasManagedIdentity(ctx, base, client)
	return m
}

// azureHasManagedIdentity probes the IMDS token endpoint; a 200 means a managed identity
// is present + usable. Any other outcome (400 no-identity, transport error) -> false.
func azureHasManagedIdentity(ctx context.Context, base string, client *http.Client) bool {
	url := base + "/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return false
	}
	req.Header.Set("Metadata", "true")
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}
