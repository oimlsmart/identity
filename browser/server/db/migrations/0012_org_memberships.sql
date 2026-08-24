-- Migration 0012 — the multi-organization membership model
-- (TODO.identity/11). An account can belong to SEVERAL organizations and
-- acts AS one at a time (the GitHub context-switch pattern): the
-- org_memberships table carries the account × org × per-org role set with
-- the lifecycle state (invited → active ⇄ disabled); the session's
-- active_org stamp names the context the account acts under; the OIDC
-- code + access token carry the context the consent was given under (the
-- token endpoint re-judges it against the live membership, so a
-- membership disabled mid-flow never emits a dead org's claims).
--
-- THE DUAL-READ DOCTRINE: the users row's org_id/roles columns stay the
-- BACKWARD-COMPATIBLE read — the PRIMARY membership's mirror — until
-- every consumer reads the memberships. The backfill below (idempotent;
-- the stores' defensive ensures carry its twin for pre-migration dev
-- databases) creates every org-bound account's primary membership from
-- the legacy columns, so the legacy read and the membership read agree
-- from the first request.
-- schema.sql carries the same end state for fresh databases —
-- src/__tests__/d1-store.test.ts pins the UNION of every migration to
-- schema.sql's CREATE set.

CREATE TABLE IF NOT EXISTS org_memberships (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  org_id TEXT NOT NULL,
  -- The per-org role set (JSON array): the roles the account's tokens
  -- carry when it acts AS this org.
  roles TEXT NOT NULL DEFAULT '[]',
  state TEXT NOT NULL DEFAULT 'active',
  -- The PRIMARY membership mirrors the users row's org_id/roles (the
  -- dual-read doctrine; one per account).
  is_primary INTEGER NOT NULL DEFAULT 0,
  invited_by TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  activated_at TEXT,
  disabled_at TEXT,
  disabled_by TEXT,
  UNIQUE (user_id, org_id)
);
CREATE INDEX IF NOT EXISTS idx_org_memberships_org ON org_memberships (org_id, state);
CREATE INDEX IF NOT EXISTS idx_org_memberships_user ON org_memberships (user_id, state);

ALTER TABLE sessions ADD COLUMN active_org TEXT;
ALTER TABLE oidc_codes ADD COLUMN context_org TEXT;
ALTER TABLE oidc_access_tokens ADD COLUMN context_org TEXT;

-- The backfill: every org-bound account's primary membership, mirrored
-- from the legacy columns (the full legacy role set, or the primary role
-- when the set column is NULL). Idempotent (INSERT OR IGNORE + the
-- deterministic id), so the stores' defensive twin never duplicates.
INSERT OR IGNORE INTO org_memberships (id, user_id, org_id, roles, state, is_primary, activated_at)
SELECT 'mbr-' || id, id, org_id,
       CASE WHEN roles IS NOT NULL AND roles != '' THEN roles ELSE json_array(role) END,
       'active', 1, COALESCE(last_login, created_at)
FROM users WHERE org_id IS NOT NULL;
