// Package autotls obtains and auto-renews public Let's Encrypt certificates via the ACME
// DNS-01 challenge (Cloudflare DNS), returning a *tls.Config the control-plane HTTP servers
// (gateway, core-api, console) terminate TLS with — so every hop is encrypted end to end,
// including load-balancer→application (the NLBs are L4 passthrough; the app owns its TLS).
//
// DNS-01 (not HTTP-01 / TLS-ALPN-01) because:
//   - the public origin sits behind Cloudflare's proxy, so an HTTP/ALPN challenge to the
//     hostname hits Cloudflare, not us; DNS-01 proves control via a TXT record regardless;
//   - it works for mesh-only services (harbor) that are not publicly reachable at all.
//
// The Cloudflare API token only needs Zone.DNS:Edit on the relevant zone — it manages the
// transient _acme-challenge TXT records, nothing else.
package autotls

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/caddyserver/certmagic"
	"github.com/libdns/cloudflare"
)

// Flags is the shared `-acme-*` flag set, so the gateway, core-api, and console wire
// auto-TLS identically.
type Flags struct {
	Domain  *string
	Token   *string
	Cache   *string
	Email   *string
	Staging *bool
}

// RegisterFlags adds the -acme-* flags to fs. defaultCache is the per-binary cert-storage
// directory (must persist across restarts).
func RegisterFlags(fs *flag.FlagSet, defaultCache string) *Flags {
	return &Flags{
		Domain:  fs.String("acme-domain", "", "obtain a Let's Encrypt cert for this hostname via ACME DNS-01 (Cloudflare) and serve HTTPS with it"),
		Token:   fs.String("acme-cloudflare-token-file", "", "path to the Cloudflare API token (Zone.DNS:Edit); or set $"+TokenEnv),
		Cache:   fs.String("acme-cache", defaultCache, "directory to persist the ACME account + certs (MUST survive restarts)"),
		Email:   fs.String("acme-email", "", "ACME account email (expiry/recovery notices)"),
		Staging: fs.Bool("acme-staging", false, "use the Let's Encrypt STAGING CA (untrusted, no rate limits) for testing"),
	}
}

// Enabled reports whether auto-TLS is configured (a domain was given).
func (f *Flags) Enabled() bool { return f != nil && *f.Domain != "" }

// Apply obtains/renews a Let's Encrypt cert (blocking on the first issuance) and sets it
// on srv.TLSConfig so httpserve.Serve serves HTTPS — when Enabled; otherwise a no-op. It
// fails closed if a domain is set without a Cloudflare token.
func (f *Flags) Apply(ctx context.Context, srv *http.Server) error {
	if !f.Enabled() {
		return nil
	}
	token, err := Token(*f.Token)
	if err != nil {
		return err
	}
	if token == "" {
		return fmt.Errorf("autotls: -acme-domain set but no Cloudflare token (set $%s or -acme-cloudflare-token-file)", TokenEnv)
	}
	tlsCfg, err := TLSConfig(ctx, Config{
		Domains: []string{*f.Domain}, CloudflareToken: token,
		Email: *f.Email, CacheDir: *f.Cache, Staging: *f.Staging,
	})
	if err != nil {
		return err
	}
	srv.TLSConfig = tlsCfg
	return nil
}

// TokenEnv is the environment variable the Cloudflare API token is read from — the
// natural fit for a Secrets-Manager-injected ECS env var or a systemd EnvironmentFile.
const TokenEnv = "NCP_ACME_CLOUDFLARE_TOKEN"

// Token resolves the Cloudflare API token: the TokenEnv environment variable first (so
// the token never appears on a command line / in `ps`), else the contents of tokenFile.
// Returns "" when neither is set.
func Token(tokenFile string) (string, error) {
	if t := strings.TrimSpace(os.Getenv(TokenEnv)); t != "" {
		return t, nil
	}
	if tokenFile != "" {
		b, err := os.ReadFile(tokenFile)
		if err != nil {
			return "", fmt.Errorf("autotls: read Cloudflare token file %s: %w", tokenFile, err)
		}
		return strings.TrimSpace(string(b)), nil
	}
	return "", nil
}

// Config builds the auto-TLS manager.
type Config struct {
	// Domains are the hostnames to obtain + renew certificates for (>= 1).
	Domains []string
	// CloudflareToken is a scoped Cloudflare API token with Zone.DNS:Edit on the zone(s)
	// owning Domains. Used only to write the ACME DNS-01 challenge TXT records.
	CloudflareToken string
	// Email is the ACME account contact (expiry / recovery notices). Optional but advised.
	Email string
	// CacheDir is certmagic's storage path for the ACME account + issued certs. It MUST
	// persist across restarts (else every restart re-issues and trips Let's Encrypt rate
	// limits) — a durable volume on a persistent host, or shared storage for an ephemeral one.
	CacheDir string
	// Staging uses the Let's Encrypt STAGING CA (untrusted certs, no rate limits) for
	// testing. Leave false for real, publicly-trusted certs.
	Staging bool
}

// TLSConfig provisions certificates for cfg.Domains (blocking until the first issuance) and
// returns a *tls.Config whose GetCertificate serves + transparently renews them. Wire it to
// an http.Server's TLSConfig and serve with ListenAndServeTLS("", "").
//
// Call it ONCE per process: it starts a background renewal goroutine (tied to the process,
// not to ctx — so renewals outlive a signal-scoped ctx) that lives for the program's
// lifetime; there is intentionally no stop (a control-plane server runs until it exits).
func TLSConfig(ctx context.Context, cfg Config) (*tls.Config, error) {
	if len(cfg.Domains) == 0 {
		return nil, errors.New("autotls: at least one domain is required")
	}
	if cfg.CloudflareToken == "" {
		return nil, errors.New("autotls: a Cloudflare API token is required (ACME DNS-01 writes the challenge TXT)")
	}
	if cfg.CacheDir == "" {
		return nil, errors.New("autotls: a cache dir is required — cert storage must persist across restarts")
	}

	ca := certmagic.LetsEncryptProductionCA
	if cfg.Staging {
		ca = certmagic.LetsEncryptStagingCA
	}

	// certmagic.New needs a cache whose GetConfigForCert returns the Config — the usual
	// closure-captured-var dance to break the chicken-and-egg.
	var magic *certmagic.Config
	cache := certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(certmagic.Certificate) (*certmagic.Config, error) { return magic, nil },
	})
	magic = certmagic.New(cache, certmagic.Config{
		Storage: &certmagic.FileStorage{Path: cfg.CacheDir},
	})

	magic.Issuers = []certmagic.Issuer{
		certmagic.NewACMEIssuer(magic, certmagic.ACMEIssuer{
			CA:     ca,
			Email:  cfg.Email,
			Agreed: true,
			// DNS-01 only — never fall back to HTTP/ALPN (which can't reach a proxied or
			// mesh-only origin).
			DisableHTTPChallenge:    true,
			DisableTLSALPNChallenge: true,
			DNS01Solver: &certmagic.DNS01Solver{
				DNSManager: certmagic.DNSManager{
					DNSProvider: &cloudflare.Provider{APIToken: cfg.CloudflareToken},
				},
			},
		}),
	}

	if err := magic.ManageSync(ctx, cfg.Domains); err != nil {
		return nil, fmt.Errorf("autotls: obtain/manage certificates for %v: %w", cfg.Domains, err)
	}

	tlsCfg := magic.TLSConfig()
	tlsCfg.MinVersion = tls.VersionTLS12
	return tlsCfg, nil
}
