-- The webhook delivery journal's retention (TODO.modern/08's TTL
-- follow-up): the deliveries table joins the nightly TTL sweep —
-- expires_at is stamped at insert (recorded_at + 90 days, the store's
-- retention policy) and backfilled here from recorded_at for the rows
-- the pre-0034 writers left NULL (datetime() parses both recorded_at
-- formats — the ISO strings and the datetime('now') defaults — the
-- 0033 lesson's julianday sibling). Expand-only per the migration
-- contract; schema.sql's mirror lands in the same commit. The
-- dead-letter bodies (0033) ride the same expiry — 90 days of
-- redelivery context, then gone.
ALTER TABLE webhook_deliveries ADD COLUMN expires_at TEXT;
UPDATE webhook_deliveries SET expires_at = datetime(recorded_at, '+90 days') WHERE expires_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_expires ON webhook_deliveries (expires_at);
