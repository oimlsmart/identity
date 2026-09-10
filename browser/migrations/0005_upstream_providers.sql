-- Migration 0005 — the upstream provider registry (TODO.identity/08).
-- Adds the OP's upstream sign-in registry (identity_providers: GitHub +
-- Google + Apple + Entra + generic OIDC rows, secrets by env reference)
-- and the linked identities (identity_links — TODO.identity/02's shape,
-- landed additively here because 08's flows consume them; THE MATCH
-- RULE: resolve by (provider, provider_account_id), never by email).
-- schema.sql carries the same end state for fresh databases —
-- src/__tests__/d1-store.test.ts pins the UNION of every migration to
-- schema.sql's CREATE set.

CREATE TABLE IF NOT EXISTS identity_providers (
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  display_name TEXT NOT NULL,
  brand_mark TEXT,
  issuer TEXT,
  client_id TEXT NOT NULL,
  client_secret_ref TEXT,
  scopes TEXT,
  enabled INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  created_by TEXT,
  updated_at TEXT
);

CREATE TABLE IF NOT EXISTS identity_links (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  provider TEXT NOT NULL,
  provider_account_id TEXT NOT NULL,
  linked_at TEXT NOT NULL DEFAULT (datetime('now')),
  linked_by TEXT,
  UNIQUE (provider, provider_account_id)
);
