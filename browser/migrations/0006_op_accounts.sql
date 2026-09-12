-- Migration 0006 — the OP's account model (TODO.identity/02).
-- Adds the password credentials (apart from the users row, so no
-- SELECT * ever reads credential material) and the invite-only
-- enrollment tokens (one-time, 24 h, atomically consumed). The linked
-- identities table itself landed with 0005_upstream_providers (08's
-- flows consume it); this migration adds the per-user index on it.
-- schema.sql carries the same end state for fresh databases —
-- src/__tests__/d1-store.test.ts pins the UNION of every migration to
-- schema.sql's CREATE set.

CREATE TABLE IF NOT EXISTS passwords (
  user_id TEXT PRIMARY KEY REFERENCES users(id),
  hash TEXT NOT NULL,
  set_at TEXT NOT NULL DEFAULT (datetime('now')),
  set_by TEXT
);

CREATE TABLE IF NOT EXISTS enrollment_tokens (
  token TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  created_by TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at TEXT NOT NULL,
  consumed_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_enrollment_tokens_user ON enrollment_tokens (user_id);

CREATE INDEX IF NOT EXISTS idx_identity_links_user ON identity_links (user_id);
