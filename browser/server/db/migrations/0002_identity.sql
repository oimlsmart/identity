-- Migration 0002 — identity federation (TODO.federation/10).
-- Adds the RP-initiated-logout hint to sessions and the SSO approval
-- queue. schema.sql carries the same end state for fresh databases —
-- src/__tests__/d1-store.test.ts pins the UNION of every migration to
-- schema.sql's CREATE set.

ALTER TABLE sessions ADD COLUMN id_token_hint TEXT;

CREATE TABLE IF NOT EXISTS identity_approvals (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL,
  name TEXT NOT NULL,
  issuer TEXT NOT NULL,
  sub TEXT NOT NULL,
  claims_json TEXT,
  status TEXT NOT NULL DEFAULT 'pending',
  decided_role TEXT,
  decided_org TEXT,
  decided_by TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  last_seen TEXT,
  decided_at TEXT,
  UNIQUE (issuer, sub)
);
