-- TODO.identity/10 — delegated organization administration: the
-- self-service join requests. org_id set = a registered participant
-- org's queue (its org admin decides); org_id NULL + org_name_text =
-- the "my organization is not listed" path (BIML's new-organizations
-- queue). The decision is atomic on status='pending'; approval records
-- the invited account (invited_user_id).
-- schema.sql carries the same end state for fresh databases —
-- src/__tests__/d1-store.test.ts pins the UNION of every migration to
-- schema.sql's CREATE set.

CREATE TABLE IF NOT EXISTS org_join_requests (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  email TEXT NOT NULL,
  org_id TEXT,
  org_name_text TEXT,
  requested_role TEXT NOT NULL,
  note TEXT,
  status TEXT NOT NULL DEFAULT 'pending',
  decided_by TEXT,
  decided_at TEXT,
  refusal_reason TEXT,
  invited_user_id TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_org_join_requests_org ON org_join_requests (org_id, status);
