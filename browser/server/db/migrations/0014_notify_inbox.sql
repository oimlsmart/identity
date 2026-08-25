-- TODO.notify/03 — the inbox state (migration 0014 in the shared
-- numbering; 0013 is the org registry's, identity-features/05 merged
-- via #194 while this wave was in flight — the D1 migrations journal
-- keys on the FILE NAME, so the rename is the renumber). The
-- notification system's per-user per-event read markers
-- (TODO.notify/00's contract: "the inbox state
-- (D1): per-user per-event state (read / done / saved) written lazily at
-- read; the feed itself is COMPUTED at read"). One row per (user, event),
-- created at the first act on the row:
--
--   read_at  the mark-read stamp (NULL = unread; the unread filter and
--            the unread count read it);
--   done_at  the done stamp (NULL = in the inbox; done is the archive —
--            the row leaves the feed, the marker keeps the state honest).
--
-- 'saved' joins with wave 05 (the GitHub polish). The rows name the
-- user + the event WITHOUT foreign keys, deliberately: the demo reset
-- (and wave 04's retention sweep) deletes events while the user's
-- markers stay — the subscriptions store's own posture (the user's
-- state is their own, never the workflow's); a marker on a wiped event
-- simply never joins. The write path's guard is the integrity (a marker
-- lands only on an event that exists, is visible and is the caller's —
-- server/notify-inbox.ts's inboxEventVisibleTo), and the dev-reset's
-- OIDC-user wipe never blocks on a marker either. The d1-store suite's
-- drift tripwire pins this migration set's end state to schema.sql.
CREATE TABLE IF NOT EXISTS notify_inbox_state (
  user_id TEXT NOT NULL,
  event_id TEXT NOT NULL,
  read_at TEXT,
  done_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (user_id, event_id)
);
CREATE INDEX IF NOT EXISTS idx_notify_inbox_state_user ON notify_inbox_state (user_id);
