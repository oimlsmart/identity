-- The persona-assumption journal (the account chooser's grant-based
-- assumption — the demonstration cast's Google-Workspace "sign in as
-- user" posture): one row per assumption — WHO assumed which persona,
-- when, for which client. The grant gate decides who MAY assume; this
-- journal is the proof of who DID (the operator's audit trail — the
-- assumption mints a real session for the persona, so the trail is the
-- only place the acting identity survives). Expand-only per the
-- migration contract; schema.sql's mirror lands in the same commit.
CREATE TABLE IF NOT EXISTS op_assumptions (
  id TEXT PRIMARY KEY,
  actor_user_id TEXT NOT NULL,
  actor_email TEXT NOT NULL,
  persona_user_id TEXT NOT NULL,
  persona_email TEXT NOT NULL,
  client_id TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_op_assumptions_persona ON op_assumptions (persona_user_id, created_at);
CREATE INDEX IF NOT EXISTS idx_op_assumptions_actor ON op_assumptions (actor_user_id, created_at);
