-- admin_tokens: non-interactive machine credentials for the admin API (A0.8).
-- The human path is an IdP session (OIDC/SAML); automation/CI/scripts instead
-- present `Authorization: Bearer <token>`. A token carries scoped roles and binds
-- audit/sign-offs to a "token:<name>" principal. It is deliberately MFA-incapable
-- (no mfa_satisfied_at), so a token can never perform the step-up-gated dual-control
-- actions (approve / policy publish) — those require two distinct humans with MFA.
-- The cookie carries a random token; this table stores only its SHA-256 (id), so a
-- DB read never yields a usable credential.
CREATE TABLE admin_tokens (
    id           TEXT    PRIMARY KEY,        -- hex(sha256(token)); never the raw token
    name         TEXT    NOT NULL,           -- human label
    principal    TEXT    NOT NULL,           -- identity bound to audit/sign-offs
    roles        TEXT    NOT NULL DEFAULT '[]', -- JSON array of role names (scope)
    created_by   TEXT    NOT NULL DEFAULT '',   -- who minted it
    created_at   INTEGER NOT NULL,              -- unix ns
    expires_at   INTEGER NOT NULL DEFAULT 0,    -- unix ns; 0 = never
    last_used_at INTEGER NOT NULL DEFAULT 0,    -- unix ns; 0 = never used
    revoked_at   INTEGER NOT NULL DEFAULT 0     -- unix ns; 0 = active
);

CREATE INDEX idx_admin_tokens_name ON admin_tokens(name);
