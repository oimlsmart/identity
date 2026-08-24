-- Migration 0004 — the OIDC Provider (TODO.identity/01).
-- Adds the OP's D1-backed state: the client registry, the pending
-- authorizations, the one-time codes, the access tokens, and the
-- signing-key rotation history (public halves only). schema.sql carries
-- the same end state for fresh databases — src/__tests__/d1-store.test.ts
-- pins the UNION of every migration to schema.sql's CREATE set.

CREATE TABLE IF NOT EXISTS oidc_clients (
  client_id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  secret_hash TEXT,
  redirect_uris TEXT NOT NULL,
  claims_policy TEXT,
  status TEXT NOT NULL DEFAULT 'active',
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  created_by TEXT
);

CREATE TABLE IF NOT EXISTS oidc_authorizations (
  id TEXT PRIMARY KEY,
  client_id TEXT NOT NULL,
  redirect_uri TEXT NOT NULL,
  scope TEXT NOT NULL,
  state TEXT NOT NULL,
  nonce TEXT,
  code_challenge TEXT NOT NULL,
  user_id TEXT,
  decision TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS oidc_codes (
  code TEXT PRIMARY KEY,
  client_id TEXT NOT NULL,
  redirect_uri TEXT NOT NULL,
  scope TEXT NOT NULL,
  nonce TEXT,
  code_challenge TEXT NOT NULL,
  user_id TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at TEXT NOT NULL,
  consumed_at TEXT
);

CREATE TABLE IF NOT EXISTS oidc_access_tokens (
  token TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  client_id TEXT NOT NULL,
  scope TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS oidc_keys (
  kid TEXT PRIMARY KEY,
  public_jwk TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active',
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  retired_at TEXT
);
