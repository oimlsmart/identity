-- Migration 0003 — federation peers (TODO.federation/04).
-- The peer registry: pinned counterparty instances (descriptor + trust
-- posture). schema.sql carries the same end state for fresh databases —
-- src/__tests__/d1-store.test.ts pins the UNION of every migration to
-- schema.sql's CREATE set.

CREATE TABLE IF NOT EXISTS federation_peers (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  roles TEXT NOT NULL,
  descriptor_url TEXT,
  descriptor_json TEXT NOT NULL,
  pinned_via TEXT NOT NULL DEFAULT 'url',
  connectivity TEXT NOT NULL DEFAULT 'verified',
  status TEXT NOT NULL DEFAULT 'active',
  added_at TEXT NOT NULL DEFAULT (datetime('now')),
  added_by TEXT,
  refreshed_at TEXT,
  revoked_at TEXT,
  revoked_by TEXT
);
