-- Migration 0036 — the RFC 8628 device authorization grant
-- (TODO.ai-platform/10): the user-attended flow that lets a CLI act AS
-- the account holder with no secret paste — the client asks for the
-- device/user code pair, the holder approves at the console page, the
-- token endpoint's device_code leg mints the personal access token
-- through the one tokens.ts path (the audit names the device grant).
--
-- The store doctrines (the personal_access_tokens precedent, 0020):
--   - both codes store as SHA-256 hashes ONLY (the entropy licenses the
--     unsalted hash); the device_code plaintext crosses the wire once
--     (the §3.2 answer), the user_code shows once (the same answer);
--   - the status machine is pending → approved | denied, and the token
--     leg flips approved → consumed ATOMICALLY (a re-presented code
--     answers invalid_grant);
--   - the poll judgment rides last_poll_at + interval_seconds (RFC 8628
--     §3.5's slow_down: a poll inside the interval bumps the interval);
--   - expires_at is mandatory (the codes die fast — the approval is a
--     live act, never a standing one);
--   - the approving account + the org-context pin land AT APPROVAL (the
--     request is account-free by construction);
--   - the account erasure removes the rows outright.
-- schema.sql carries the same end state for fresh databases —
-- test/migrations.test.ts pins the UNION of every migration to
-- schema.sql's CREATE set.

CREATE TABLE IF NOT EXISTS device_authorizations (
  id TEXT PRIMARY KEY,
  device_code_hash TEXT NOT NULL,
  user_code_hash TEXT NOT NULL,
  client_id TEXT NOT NULL,
  -- The requested scope set (JSON array of '<service>:<action-class>' —
  -- the PAT grammar; the approval re-judges it against the approving
  -- account's live standing).
  scopes TEXT NOT NULL DEFAULT '[]',
  -- pending | approved | denied | consumed (the one-time flip at the
  -- token leg).
  status TEXT NOT NULL DEFAULT 'pending',
  -- The approving account (NULL until the decision).
  user_id TEXT REFERENCES users(id),
  -- The approving session's active-org context (the PAT mint's pin).
  org_context TEXT,
  interval_seconds INTEGER NOT NULL DEFAULT 5,
  last_poll_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at TEXT NOT NULL,
  decided_at TEXT,
  UNIQUE (device_code_hash),
  UNIQUE (user_code_hash)
);
CREATE INDEX IF NOT EXISTS idx_device_authorizations_user ON device_authorizations (user_id);
