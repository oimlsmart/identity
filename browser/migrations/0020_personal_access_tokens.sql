-- Migration 0020 — the personal access tokens (TODO.identity-features/08,
-- the GitHub fine-grained pattern mapped to the estate): an ACCOUNT-minted
-- developer credential that NEVER rides a request directly — it exchanges
-- at the OP's token endpoint (the RFC 8693 grant, subject_token_type
-- urn:oimlsmart:params:oauth:token-type:pat) for a short-lived OP JWT, so
-- every relying party keeps validating the one token shape.
--
-- The store doctrines (the recovery codes' precedent, migration 0012):
--   - the plaintext shows ONCE at mint; the row holds only the SHA-256 of
--     the presented token (256 bits of random — an unsalted hash resists
--     the offline attack), and token_hash IS the exchange's lookup key
--     (UNIQUE doubles as its index);
--   - token_prefix is the display fragment ('ospt_' + the leading
--     characters — the console's row label, GitHub's list convention),
--     never enough to authenticate;
--   - expiration is MANDATORY (expires_at NOT NULL — the fine-grained
--     lesson: no permanent tokens);
--   - the audit chain rides the row conservatively: last_used_at +
--     last_exchange_audit_at carry the exchange path's THROTTLED
--     heartbeat (never a write per exchange), expiry_notified_at the
--     expiry-soon mailer's one-shot mark;
--   - revocation flips revoked_at/revoked_by (the row stays — the audit
--     + the org inventory carry the history); the account erasure removes
--     the rows outright (a dead account's tokens die with it).
-- schema.sql carries the same end state for fresh databases —
-- test/migrations.test.ts pins the UNION of every migration to
-- schema.sql's CREATE set.

CREATE TABLE IF NOT EXISTS personal_access_tokens (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  name TEXT NOT NULL,
  token_hash TEXT NOT NULL,
  token_prefix TEXT NOT NULL,
  -- The granted scope set (JSON array of '<service>:<action-class>' — the
  -- kernel's PAT grammar; narrowing-only against the holder's standing).
  scopes TEXT NOT NULL DEFAULT '[]',
  -- The org context the token was minted under (the console session's
  -- active org — the token acts within the account's active-org
  -- visibility, never wider). NULL = the account's primary context.
  org_context TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at TEXT NOT NULL,
  last_used_at TEXT,
  last_exchange_audit_at TEXT,
  expiry_notified_at TEXT,
  revoked_at TEXT,
  revoked_by TEXT,
  UNIQUE (token_hash)
);
CREATE INDEX IF NOT EXISTS idx_personal_access_tokens_user ON personal_access_tokens (user_id);
