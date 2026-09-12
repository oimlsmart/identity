-- TODO.notify/04 — the email channel's delivery store (migration 0018
-- in the shared numbering; 0017 is the cones wave's — identity-features
-- /09). One row per (event, recipient) — the fan-out's record of WHO
-- the event reached and on WHICH channel mark (TODO.notify/00: "the
-- delivery lands on the audit/notification store (a notification row
-- per recipient with the channel marks)"):
--
--   reason        the resolution's STRONGEST reason (subscribed /
--                 assigned / author / actor / role-default) — every
--                 notification carries its why, the delivery row
--                 included;
--   email         the resolved email posture (immediate | digest | off)
--                 — the channel split's outcome (the inbox is the
--                 constant, never a column);
--   email_status  NULL when email = 'off'; else the email leg's state:
--                 sent | failed | rate_limited for the immediate leg,
--                 digest_pending → digest_sent | digest_failed for the
--                 daily rollup, digest_dropped when the event left the
--                 store before the rollup, 'unavailable' when the
--                 instance carries NO mailer (the honest degradation:
--                 nothing queues — a console-posture instance marks the
--                 row unavailable at event time and the digest never
--                 accumulates);
--   email_at      the terminal stamp (the send / the drop), NULL while
--                 pending.
--
-- The rows name the user + the event WITHOUT foreign keys (the
-- subscriptions store's own posture, migration 0014's: the user's
-- delivery record is their own, never the workflow's) — the demo reset
-- and the retention sweep delete events while a delivery row simply
-- never joins. The UNIQUE (event_id, user_id) makes the fan-out
-- idempotent (a re-driven event updates, never duplicates). The
-- mailer's own audit (entity_type 'email') stands alongside — this
-- table is the PER-RECIPIENT notification record, the audit trail the
-- per-SEND one. The package's migrations test pins this set's end state
-- to schema.sql (src/store/sqlite) in lockstep.
CREATE TABLE IF NOT EXISTS notify_deliveries (
  id TEXT PRIMARY KEY,
  event_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  reason TEXT NOT NULL,
  email TEXT NOT NULL,
  email_status TEXT,
  email_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE (event_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_notify_deliveries_event ON notify_deliveries (event_id);
CREATE INDEX IF NOT EXISTS idx_notify_deliveries_user ON notify_deliveries (user_id);
-- The digest rollup + the retry sweep read by status.
CREATE INDEX IF NOT EXISTS idx_notify_deliveries_status ON notify_deliveries (email_status);
