package adminapi_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/jeks313/nebula-control-plane/internal/adminapi"
	"github.com/jeks313/nebula-control-plane/internal/joinkey"
	"github.com/jeks313/nebula-control-plane/internal/lighthouse"
	"github.com/jeks313/nebula-control-plane/internal/rollout"
	"github.com/jeks313/nebula-control-plane/internal/store"
	"github.com/jeks313/nebula-control-plane/internal/store/migrate"
)

// loadSpec parses + validates the embedded OpenAPI document (catches spec typos).
func loadSpec(t *testing.T) *openapi3.T {
	t.Helper()
	loader := openapi3.NewLoader()
	doc, err := loader.LoadFromData(adminapi.Spec())
	if err != nil {
		t.Fatalf("load spec: %v", err)
	}
	if err := doc.Validate(loader.Context); err != nil {
		t.Fatalf("invalid OpenAPI spec: %v", err)
	}
	return doc
}

// newSrv builds a seeded admin server and returns the *Server (for Routes) and a
// live test server.
func newSrv(t *testing.T) (*adminapi.Server, *httptest.Server) {
	t.Helper()
	s, err := store.Open(store.Config{Driver: "sqlite", DSN: store.DefaultSQLiteDSN(t.TempDir() + "/c.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	if err := migrate.Up(s.DB); err != nil {
		t.Fatal(err)
	}
	audit := func(ctx context.Context, a, ac, tgt, d string) error {
		_, e := s.AppendAudit(ctx, a, ac, tgt, d)
		return e
	}
	now := time.Unix(1_700_000_000, 0).UTC()
	hbInsert(t, s.DB, "100.64.0.2", "web-1", now.Add(30*24*time.Hour), now, "ok")
	hbInsert(t, s.DB, "100.64.0.3", "ec2-1", now.Add(30*24*time.Hour), now, "ok")
	// Populated provenance so the response-conformance visitor exercises a fully
	// populated Device body (attest_* + join_key_name + groups) against the schema.
	_, jk, jerr := joinkey.Create(context.Background(), s, joinkey.Params{Name: "fleet-key", Groups: []string{"web"}}, now)
	if jerr != nil {
		t.Fatal(jerr)
	}
	issued(t, s, "c-token", "100.64.0.2", jk.ID, "", "", "", "", []string{"web"})
	issued(t, s, "c-aws", "100.64.0.3", 0, "aws", "111122223333", "arn:aws:sts::111122223333:assumed-role/web/i-1", "eu-central-1", []string{"fleet", "db"})
	_, _ = s.AppendAudit(context.Background(), "alice", "policy-publish", "fw", "")
	reg := lighthouse.New(s.DB, audit)
	_, _ = reg.Add(context.Background(), "100.64.0.1", "lh1", []string{"1.2.3.4:4242"}, "op")

	srv := adminapi.New(adminapi.Config{
		Store: s, Identity: adminapi.DevHeaderProvider{},
		Rollout: rollout.New(s.DB, audit), Lighthouses: reg,
		Now: func() time.Time { return now },
	})
	return srv, httptest.NewServer(srv.Handler())
}

// TestOpenAPISpecValid: the embedded spec is well-formed.
func TestOpenAPISpecValid(t *testing.T) { loadSpec(t) }

// TestNo500Enumerated locks in the error convention: a 500 is abnormal operation
// (the server failed), not a defined result, so it must never be enumerated as a
// per-operation response. Operations document only the contract's deterministic,
// client-actionable outcomes — the 4xx codes, plus the deliberate mode/state
// signals 501 ("issuance not configured") and 503 ("audit check unavailable").
// This guards against a reviewer/codegen tool re-adding "500" per endpoint.
func TestNo500Enumerated(t *testing.T) {
	doc := loadSpec(t)
	for path, item := range doc.Paths.Map() {
		for method, op := range item.Operations() {
			if op.Responses == nil {
				continue
			}
			for code := range op.Responses.Map() {
				if code == "500" {
					t.Errorf("%s %s enumerates 500 — a 500 is abnormal operation, not a documented response (see the spec's error convention)", method, path)
				}
			}
		}
	}
}

// TestOpenAPIServedUnauthenticated: the contract is reachable without auth (it's
// public contract info, no fleet data) so UI codegen/tooling can fetch it.
func TestOpenAPIServedUnauthenticated(t *testing.T) {
	_, ts := newSrv(t)
	defer ts.Close()
	resp, err := http.Get(ts.URL + "/admin/v1/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("openapi.yaml status = %d, want 200 (no auth required)", resp.StatusCode)
	}
}

// TestRoutesMatchSpec: the documented operations exactly equal the served routes
// — neither an undocumented endpoint nor a documented-but-unrouted one.
func TestRoutesMatchSpec(t *testing.T) {
	doc := loadSpec(t)
	srv, ts := newSrv(t)
	defer ts.Close()

	specOps := map[string]bool{}
	for path, item := range doc.Paths.Map() {
		for method := range item.Operations() {
			specOps[method+" "+path] = true
		}
	}
	routes := map[string]bool{}
	for _, r := range srv.Routes() {
		routes[r] = true
	}

	for r := range routes {
		if !specOps[r] {
			t.Errorf("route %q is served but NOT documented in the OpenAPI spec", r)
		}
	}
	for op := range specOps {
		if !routes[op] {
			t.Errorf("operation %q is documented but NOT served (dead spec entry)", op)
		}
	}
	if t.Failed() {
		t.Logf("served=%v", sortedKeys(routes))
		t.Logf("spec  =%v", sortedKeys(specOps))
	}
}

// TestResponsesConformToSpec: every GET endpoint's live 200 body validates
// against its documented response schema (the anti-drift guarantee).
func TestResponsesConformToSpec(t *testing.T) {
	doc := loadSpec(t)
	srv, ts := newSrv(t)
	defer ts.Close()

	for _, r := range srv.Routes() {
		method, path := splitRoute(r)
		// Generic conformance covers GET endpoints with no path params; POST
		// (mutations) and parameterized paths are exercised by dedicated flow tests.
		if method != "GET" || strings.Contains(path, "{") {
			continue
		}
		t.Run(r, func(t *testing.T) {
			schema := responseSchema(t, doc, method, path, 200)

			req, _ := http.NewRequest(method, ts.URL+path, nil)
			req.Header.Set("X-Harbor-Dev-Actor", "alice")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != 200 {
				t.Fatalf("status = %d, want 200", resp.StatusCode)
			}
			var body any
			if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if err := schema.VisitJSON(body, openapi3.VisitAsResponse()); err != nil {
				t.Fatalf("response for %s does not conform to its OpenAPI schema: %v\nbody: %v", path, err, body)
			}
		})
	}
}

func responseSchema(t *testing.T, doc *openapi3.T, method, path string, code int) *openapi3.Schema {
	t.Helper()
	item := doc.Paths.Find(path)
	if item == nil {
		t.Fatalf("spec has no path %q", path)
	}
	op := item.GetOperation(method)
	if op == nil {
		t.Fatalf("spec path %q has no %s", path, method)
	}
	respRef := op.Responses.Status(code)
	if respRef == nil || respRef.Value == nil {
		t.Fatalf("spec %s %s has no %d response", method, path, code)
	}
	mt := respRef.Value.Content["application/json"]
	if mt == nil || mt.Schema == nil || mt.Schema.Value == nil {
		t.Fatalf("spec %s %s %d has no application/json schema", method, path, code)
	}
	return mt.Schema.Value
}

func splitRoute(r string) (method, path string) {
	for i := 0; i < len(r); i++ {
		if r[i] == ' ' {
			return r[:i], r[i+1:]
		}
	}
	return r, ""
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
