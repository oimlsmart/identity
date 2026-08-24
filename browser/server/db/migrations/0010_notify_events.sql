-- TODO.notify/01 — the platform event store (the notification system's
-- source of truth): one row per DECLARED notifiable act (the catalog,
-- browser/src/notify/catalog.ts, is deliberate — not every write is an
-- event). The hierarchical key <domain>/<entity-id>/<action> is SPLIT
-- into columns so the subscription grammar's prefixes resolve in SQL
-- (WHERE domain = ? AND entity_id = ?), never a string scan; the
-- composed key is derived at read. payload is the catalog row's JSON
-- envelope (the summary line, the deep link, the actors, the entity's
-- store for the read-time visibility gate). seq is the feed cursor;
-- written inside the acting request's envelope, never blocking the
-- triggering flow (the mailer doctrine). The d1-store suite's drift
-- tripwire pins this migration set's end state to schema.sql.
CREATE TABLE IF NOT EXISTS events (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  id TEXT UNIQUE NOT NULL,
  domain TEXT NOT NULL,
  entity_id TEXT NOT NULL,
  action TEXT NOT NULL,
  payload TEXT NOT NULL,
  at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_events_domain_entity ON events (domain, entity_id);
CREATE INDEX IF NOT EXISTS idx_events_domain_action ON events (domain, action);
