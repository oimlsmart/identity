-- The pushed authorization requests (TODO.modern/11, RFC 9126): one
-- row per client-authenticated push — the authorize parameter set as
-- JSON (never the front channel), the owning client (the consume is
-- client-bound), the 90 s expiry, and the consumed flag (the consume
-- is SINGLE-USE — the UPDATE's WHERE carries not-consumed +
-- not-expired + the client binding). Identical end state to
-- schema.sql's CREATE IF NOT EXISTS (the lockstep the migrations
-- test pins).
CREATE TABLE IF NOT EXISTS pushed_authorization_requests (
  uri TEXT PRIMARY KEY,
  client_id TEXT NOT NULL,
  params TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  consumed INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
