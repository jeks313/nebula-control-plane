package adminauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

// GitHubOptions configures the GitHub OAuth authenticator. GitHub is OAuth 2.0,
// NOT OIDC: there is no ID token. Identity comes from GET /user and authority from
// org/team membership (GET /user/teams) — which is exactly why the Authenticator
// seam is identity-shaped, not token-shaped. APIBase/Endpoint are overridable for
// GitHub Enterprise Server (and for tests).
type GitHubOptions struct {
	Name         string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string        // default ["read:org", "user:email"]
	APIBase      string          // default "https://api.github.com"
	Endpoint     oauth2.Endpoint // default github.Endpoint (github.com)
	HTTPClient   *http.Client    // override transport (tests / proxies)
}

// GitHubAuthenticator logs a human in via GitHub and maps their org/team
// membership to groups ("org" and "org/team") for the RoleMapper.
type GitHubAuthenticator struct {
	name       string
	oauth      oauth2.Config
	apiBase    string
	httpClient *http.Client
}

// NewGitHub builds the GitHub authenticator.
func NewGitHub(opts GitHubOptions) *GitHubAuthenticator {
	scopes := opts.Scopes
	if len(scopes) == 0 {
		scopes = []string{"read:org", "user:email"}
	}
	ep := opts.Endpoint
	if ep.AuthURL == "" {
		ep = github.Endpoint
	}
	return &GitHubAuthenticator{
		name: orDefault(opts.Name, "github"),
		oauth: oauth2.Config{
			ClientID: opts.ClientID, ClientSecret: opts.ClientSecret,
			Endpoint: ep, RedirectURL: opts.RedirectURL, Scopes: scopes,
		},
		apiBase:    orDefault(opts.APIBase, "https://api.github.com"),
		httpClient: opts.HTTPClient,
	}
}

// Name implements Authenticator.
func (a *GitHubAuthenticator) Name() string { return a.name }

// AuthURL builds the GitHub authorize redirect. GitHub has no ID-token nonce; the
// random state value protects the flow. forceReauth is ignored: GitHub OAuth does
// not surface an MFA signal, so a GitHub session never satisfies step-up MFA
// anyway (its Subject.MFAAt is always nil) — by design, not a silent gap.
func (a *GitHubAuthenticator) AuthURL(state, nonce, verifier string, forceReauth bool) string {
	return a.oauth.AuthCodeURL(state)
}

// Exchange swaps the code for a token, then reads identity + org/team membership.
func (a *GitHubAuthenticator) Exchange(ctx context.Context, code, nonce, verifier string) (Subject, error) {
	if a.httpClient != nil {
		ctx = context.WithValue(ctx, oauth2.HTTPClient, a.httpClient)
	}
	tok, err := a.oauth.Exchange(ctx, code)
	if err != nil {
		return Subject{}, fmt.Errorf("adminauth: github exchange: %w", err)
	}
	client := a.oauth.Client(ctx, tok)

	var u struct {
		Login string `json:"login"`
		ID    int64  `json:"id"`
		Name  string `json:"name"`
	}
	if err := a.getJSON(ctx, client, "/user", &u); err != nil {
		return Subject{}, err
	}
	// /user.email is the user's self-set, UNVERIFIED public profile address — unsafe
	// as the audit principal. Use the verified primary from /user/emails instead
	// (best-effort: if the user:email scope is absent we leave it empty and the
	// Principal falls back to the GitHub-attested login).
	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	verifiedEmail := ""
	if err := a.getJSON(ctx, client, "/user/emails", &emails); err == nil {
		for _, e := range emails {
			if e.Primary && e.Verified {
				verifiedEmail = e.Email
				break
			}
		}
	}
	var teams []struct {
		Slug string `json:"slug"`
		Org  struct {
			Login string `json:"login"`
		} `json:"organization"`
	}
	if err := a.getJSON(ctx, client, "/user/teams", &teams); err != nil {
		return Subject{}, err
	}
	groups := []string{}
	seenOrg := map[string]bool{}
	for _, t := range teams {
		if t.Org.Login == "" {
			continue
		}
		groups = append(groups, t.Org.Login+"/"+t.Slug) // map a specific team
		if !seenOrg[t.Org.Login] {
			groups = append(groups, t.Org.Login) // or a whole org
			seenOrg[t.Org.Login] = true
		}
	}
	return Subject{
		ID:     fmt.Sprintf("github:%d", u.ID),
		Name:   orDefault(u.Name, u.Login),
		Email:  verifiedEmail,
		Groups: groups,
	}, nil
}

func (a *GitHubAuthenticator) getJSON(ctx context.Context, client *http.Client, path string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.apiBase+path, http.NoBody)
	if err != nil {
		return fmt.Errorf("adminauth: github %s: %w", path, err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("adminauth: github %s: %w", path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("adminauth: github %s: status %d: %s", path, resp.StatusCode, body)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(v); err != nil {
		return fmt.Errorf("adminauth: github %s decode: %w", path, err)
	}
	return nil
}
