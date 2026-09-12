-- Migration 0009 — the account-holder console (TODO.identity/06).
-- (The 0009 prefix is shared with 0009_sso_states.sql (TODO.identity/04);
-- the D1 migrations journal keys on the FILE NAME — the double-0003
-- precedent — and the two touch disjoint tables/columns. The name must
-- stay exactly this: the shared preview D1 applied it under this name,
-- and a rename re-runs the ALTERs there into duplicate-column errors.)
--   users.email_verified_at      — the primary address's verification state
--   sessions.user_agent / ip / last_seen_at — the sign-in context the
--                                  sessions section lists
--   email_change_tokens          — the verify-new-email ceremony (one-time,
--                                  24 h, atomically consumed; delivered_by
--                                  records the mailer vs on-screen channel)
-- schema.sql carries the same end state for fresh databases —
-- src/__tests__/d1-store.test.ts pins the UNION of every migration to
-- schema.sql's CREATE set.

ALTER TABLE users ADD COLUMN email_verified_at TEXT;

ALTER TABLE sessions ADD COLUMN user_agent TEXT;
ALTER TABLE sessions ADD COLUMN ip TEXT;
ALTER TABLE sessions ADD COLUMN last_seen_at TEXT;

CREATE TABLE IF NOT EXISTS email_change_tokens (
  token TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  new_email TEXT NOT NULL,
  delivered_by TEXT NOT NULL DEFAULT 'shown',
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at TEXT NOT NULL,
  consumed_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_email_change_tokens_user ON email_change_tokens (user_id);
