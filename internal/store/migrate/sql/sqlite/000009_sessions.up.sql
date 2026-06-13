-- sessions: Harbor's own server-side admin sessions (2.11 admin SSO). After ANY
-- IdP login (OIDC, GitHub OAuth, the in-process mock, or the dev seam) Harbor
-- mints one of these and sets an httpOnly cookie holding the opaque token; every
-- request then authenticates by looking the session up here. The session is
-- Harbor's, not the IdP's — that is what makes the IdP bring-your-own (the
-- protocol only matters at login). The cookie carries a random token; this table
-- stores only its SHA-256 (id), so a DB read never yields a usable cookie.
CREATE TABLE sessions (
    id          TEXT    PRIMARY KEY,          -- hex(sha256(cookie token)); never the raw token
    principal   TEXT    NOT NULL,             -- display identity bound to sign-offs/audit
    roles       TEXT    NOT NULL DEFAULT '[]', -- JSON array of role names
    idp         TEXT    NOT NULL,             -- oidc | github | mock | dev
    subject     TEXT    NOT NULL DEFAULT '',   -- the IdP's stable subject id
    email       TEXT    NOT NULL DEFAULT '',
    name        TEXT    NOT NULL DEFAULT '',
    csrf_token  TEXT    NOT NULL,             -- double-submit CSRF secret for this session
    mfa_at      INTEGER NOT NULL DEFAULT 0,    -- unix ns the IdP asserted MFA (0 = none)
    created_at  INTEGER NOT NULL,             -- unix ns
    expires_at  INTEGER NOT NULL              -- unix ns; absolute cap, refreshed on use
);

CREATE INDEX idx_sessions_expires_at ON sessions(expires_at);
