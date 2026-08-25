-- Migration 0013 — the organization registry (TODO.identity-features/05:
-- organizations as first-class citizens of the identity plane). One row
-- per organization: the stable SLUG id (for a participant org the OIML
-- code IS the id — the platform resolves the org claim against its own
-- participant registry directly, the mapping is identity, never a lookup
-- table), the display data, the OPTIONAL participant_ref annotation (the
-- link's documentation, never a key), and the lifecycle state.
--
-- Removal is DISABLE honestly (the route's act: the org's active
-- memberships disable, its members' per-org roles stop carrying; the
-- audit trail keeps the history); the erasure-adjacent hard delete
-- exists only for an org that never held a membership (the route
-- refuses it while a membership or a join request references the org).
--
-- The membership graph (org_memberships, migration 0011) references the
-- org by id WITHOUT a foreign key, deliberately: the scheme-side
-- participants register and this identity-side registry never merge
-- (the spec's §4), and a membership row's honesty (its lifecycle state)
-- never depends on a join.
--
-- No backfill, honestly: the production registry starts EMPTY and the
-- identity administrator adds the organizations deliberately (the wave's
-- whole point); the memberships reference org ids as plain strings, so
-- nothing breaks at the SQL level, and every read degrades to the raw
-- id until the admin curates the row. The dev/e2e posture seeds the
-- demonstration register's rows (server/seed-org-register.ts).
-- schema.sql carries the same end state for fresh databases —
-- src/__tests__/d1-store.test.ts pins the UNION of every migration to
-- schema.sql's CREATE set.

CREATE TABLE IF NOT EXISTS org_registry (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  short_name TEXT,
  -- The participant kind (the OIML-CS program's four); NULL = a
  -- non-participant org (the estate operator's own org, a consumer).
  kind TEXT,
  country TEXT,
  -- The contacts (a JSON array of { name, email }; a malformed entry is
  -- skipped on read, never trusted).
  contacts TEXT NOT NULL DEFAULT '[]',
  -- The participant-link annotation (which participant record the org
  -- mirrors); documentation only.
  participant_ref TEXT,
  state TEXT NOT NULL DEFAULT 'active',
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  created_by TEXT,
  updated_at TEXT,
  updated_by TEXT,
  disabled_at TEXT,
  disabled_by TEXT
);
CREATE INDEX IF NOT EXISTS idx_org_registry_state ON org_registry (state);
