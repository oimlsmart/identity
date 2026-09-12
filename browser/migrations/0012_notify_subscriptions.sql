-- TODO.notify/02 — the subscriptions store (the notification system's
-- per-user rules, the GitHub shape; TODO.notify/00's contract). Three
-- tables:
--
--   notify_rules: the per-user rule rows (mode subscribe|mute) on a key
--   pattern in the catalog's grammar (application/**, certificate/**/
--   issued, test-run/asg-…-001/**, or an exact key). The pattern's
--   pinned legs are SPLIT into columns (domain is always pinned;
--   entity_id/action NULL = the wild leg) so the recipient
--   resolution's REVERSE match — every user's rules covering one event —
--   resolves in SQL (WHERE domain = ? AND (entity_id IS NULL OR
--   entity_id = ?) AND (action IS NULL OR action = ?)), never a string
--   scan. channel_overrides is the subscribe row's per-rule email
--   override (JSON; NULL = the category preference rules on); a mute
--   row never carries one.
CREATE TABLE IF NOT EXISTS notify_rules (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  pattern TEXT NOT NULL,
  domain TEXT NOT NULL,
  entity_id TEXT,
  action TEXT,
  mode TEXT NOT NULL,
  channel_overrides TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE (user_id, pattern)
);
CREATE INDEX IF NOT EXISTS idx_notify_rules_user ON notify_rules (user_id);
CREATE INDEX IF NOT EXISTS idx_notify_rules_event ON notify_rules (domain, entity_id, action);

--   notify_entity_mutes: the thread-level mutes (the entity-page bell's
--   Muted state; the email footer's one-click unsubscribe — TODO.notify/
--   04 — sets the same row). A mute wins over every candidate class,
--   subscriptions included; the access is unchanged.
CREATE TABLE IF NOT EXISTS notify_entity_mutes (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  domain TEXT NOT NULL,
  entity_id TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE (user_id, domain, entity_id)
);
CREATE INDEX IF NOT EXISTS idx_notify_entity_mutes_entity ON notify_entity_mutes (domain, entity_id);

--   notify_preferences: one row per user — the per-category (the event
--   catalog's domains) email posture as a JSON map { "<domain>":
--   "immediate"|"digest"|"off" }. A domain ABSENT falls back to the
--   catalog row's own email default; the inbox always carries the
--   event. No row at all = every category on its catalog default.
CREATE TABLE IF NOT EXISTS notify_preferences (
  user_id TEXT PRIMARY KEY REFERENCES users(id),
  channels TEXT NOT NULL DEFAULT '{}',
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- The d1-store suite's drift tripwire pins this migration set's end
-- state to schema.sql (packages/platform-server/src/store/sqlite).
