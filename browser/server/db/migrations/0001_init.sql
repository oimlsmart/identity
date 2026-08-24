-- Migration 0001 — the platform schema (TODO.cs-e2e/14).
-- Mirrors server/db/schema.sql STATEMENT-FOR-STATEMENT (the node
-- posture applies schema.sql at boot; the D1 posture applies this
-- migration via `wrangler d1 migrations apply`). When schema.sql
-- changes, add the next migration here AND keep schema.sql current —
-- src/__tests__/d1-store.test.ts pins the two to the same CREATE set.
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  name TEXT NOT NULL,
  avatar_url TEXT,
  provider TEXT NOT NULL DEFAULT 'demo',
  provider_account_id TEXT,
  role TEXT NOT NULL DEFAULT 'user',
  -- Organization linkage: manufacturer id (applicant), IA oiml_code (ia_officer),
  -- TL oiml_id (tl_operator); NULL for cs_admin/admin/viewer.
  org_id TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  last_login TEXT
);

CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  token TEXT UNIQUE NOT NULL,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- The workflow entity store (TODO.ops/07 — server-side persistence):
-- one JSON document per entity, keyed by (store, id) — the same shape
-- the browser's IndexedDB stores hold, so the two repository backends
-- are contract-identical. org_id carries the scoping column when the
-- entity declares one (server-side enforcement for org-bound roles).
CREATE TABLE IF NOT EXISTS entities (
  store TEXT NOT NULL,
  id TEXT NOT NULL,
  org_id TEXT,
  data TEXT NOT NULL,
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (store, id)
);
CREATE INDEX IF NOT EXISTS idx_entities_store_org ON entities (store, org_id);

-- The change journal: every write appends (seq, store, type, id) —
-- the SSE stream tails it (each client filters its stores).
CREATE TABLE IF NOT EXISTS entity_changes (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  store TEXT NOT NULL,
  type TEXT NOT NULL,
  id TEXT NOT NULL,
  at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- The evidence store (TODO.ops/09 — the monitor daemon's durable
-- streams): append-only records across restarts. The adapter contract
-- (src/evidence-store/adapter.ts) is tiny: append, query, getByIds,
-- counts.
CREATE TABLE IF NOT EXISTS evidence_records (
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  twin_id TEXT,
  monitor_id TEXT,
  at TEXT NOT NULL,
  data TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_evidence_kind_at ON evidence_records (kind, at);
CREATE INDEX IF NOT EXISTS idx_evidence_twin ON evidence_records (twin_id, at);
CREATE INDEX IF NOT EXISTS idx_evidence_monitor ON evidence_records (monitor_id, at);
