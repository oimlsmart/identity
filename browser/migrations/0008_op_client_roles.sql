-- Migration 0008 — the central user registry's PER-CLIENT role
-- assignments (TODO.identity/03). One row per (user, client): the ID
-- token issued to that client carries these roles (filtered by the
-- client's claims-policy role allowlist); no row = the account's
-- OP-side role set is the federation-wide default (the pre-03
-- behavior); roles='[]' = explicitly no roles on this client.
-- schema.sql carries the same end state for fresh databases —
-- src/__tests__/d1-store.test.ts pins the UNION of every migration to
-- schema.sql's CREATE set.

CREATE TABLE IF NOT EXISTS op_client_roles (
  user_id TEXT NOT NULL REFERENCES users(id),
  client_id TEXT NOT NULL,
  roles TEXT NOT NULL,
  assigned_by TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT,
  PRIMARY KEY (user_id, client_id)
);
