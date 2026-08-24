-- Migration 0012 — the strong-authentication wave (TODO.identity-sso/02
-- passkeys + /03 the factor registry): passkeys (WebAuthn credentials),
-- TOTP authenticator apps, recovery codes, the one-time ceremony state
-- (WebAuthn challenges + the pending second-factor sign-in row), and the
-- authentication provenance (amr, RFC 8176) riding sessions → codes →
-- access tokens into the ID token.
-- schema.sql carries the same end state for fresh databases —
-- src/__tests__/d1-store.test.ts pins the UNION of every migration to
-- schema.sql's CREATE set.

-- The sign-in provenance (the session's amr list, a JSON array of RFC
-- 8176 values — 'pwd', 'otp', 'webauthn', 'hwk', plus the OP-private
-- 'recovery' for a recovery-code entry). NULL = no OP-side credential
-- event recorded (an upstream-provider sign-in).
ALTER TABLE sessions ADD COLUMN amr TEXT;
-- The consenting session's provenance, stamped on the one-time code so
-- the token endpoint emits the ID token's amr; carried onto the access
-- token so userinfo answers the same truth.
ALTER TABLE oidc_codes ADD COLUMN amr TEXT;
ALTER TABLE oidc_access_tokens ADD COLUMN amr TEXT;

-- The passkeys (wave 02). credential_id is the authenticator's own
-- (base64url); public_key is the COSE key bytes (base64url) as the
-- attestation carried them; sign_count is the authenticator's signature
-- counter (a REGRESSED count on assertion is the clone signal — the
-- advance is a guarded UPDATE, the regression refuses + audits);
-- aaguid + transports record what the browser declared (attestation is
-- 'none' at this assurance level — display hints, never proof).
CREATE TABLE IF NOT EXISTS webauthn_credentials (
  credential_id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  name TEXT NOT NULL,
  public_key TEXT NOT NULL,
  sign_count INTEGER NOT NULL DEFAULT 0,
  aaguid TEXT,
  transports TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  last_used_at TEXT,
  last_ip TEXT
);
CREATE INDEX IF NOT EXISTS idx_webauthn_credentials_user ON webauthn_credentials (user_id);

-- The TOTP authenticator apps (RFC 6238, 30 s step, 6 digits, HMAC-SHA-1).
-- verified_at NULL = the PENDING enrollment: it activates ONLY on the
-- first valid code, and the enrollment verify carries a hard throttle
-- (fail_count + last_failure_at — the six-digit window invites brute
-- force). The secret is base32 and never leaves the server after the
-- enrollment answer.
CREATE TABLE IF NOT EXISTS totp_secrets (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  name TEXT NOT NULL,
  secret TEXT NOT NULL,
  fail_count INTEGER NOT NULL DEFAULT 0,
  last_failure_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  verified_at TEXT,
  last_used_at TEXT,
  last_ip TEXT
);
CREATE INDEX IF NOT EXISTS idx_totp_secrets_user ON totp_secrets (user_id);

-- The recovery codes: generated at the first factor's enrollment, shown
-- once, stored HASHED (SHA-256 of the normalized code — 80 bits of
-- random per code, so an unsalted hash resists the offline attack), one
-- time each (consumed_at flips atomically). Regeneration REPLACES the
-- account's set (batch marks the generation; the old set is deleted with
-- the audit event).
CREATE TABLE IF NOT EXISTS recovery_codes (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  batch TEXT NOT NULL,
  code_hash TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  consumed_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_recovery_codes_user ON recovery_codes (user_id);

-- The one-time WebAuthn ceremony challenges (the database-is-the-proof
-- doctrine, the sso_states/enrollment_tokens pattern): short TTL,
-- consumed atomically. user_id binds the registration + the second-factor
-- assertion to the account; the PASSWORDLESS assertion's row carries NULL
-- (the asserted credential id resolves the account).
CREATE TABLE IF NOT EXISTS webauthn_challenges (
  challenge TEXT PRIMARY KEY,
  user_id TEXT REFERENCES users(id),
  kind TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at TEXT NOT NULL,
  consumed_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_webauthn_challenges_user ON webauthn_challenges (user_id);

-- The pending second-factor sign-in: the password verified, the account
-- holds factors, the session waits on the factor. One-time (consumed at
-- completion), short TTL, and the per-account throttle rides the row:
-- fail_count + last_failure_at give the backoff ladder, and the cap
-- burns the attempt (audit + the account's lockout email).
CREATE TABLE IF NOT EXISTS mfa_pending (
  token TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  amr TEXT NOT NULL,
  fail_count INTEGER NOT NULL DEFAULT 0,
  last_failure_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at TEXT NOT NULL,
  consumed_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_mfa_pending_user ON mfa_pending (user_id);
