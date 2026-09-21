-- The webhook dead-letter redelivery (TODO.modern/08's edition 2 —
-- the cron pass): a dead letter may carry its envelope body (the act's
-- own no-secrets projection — the same data the journal already
-- holds), and redelivered_at stamps the ONE bounded redelivery pass
-- (a letter never re-enters the pool; the subscriber dedupes by the
-- envelope id). body stays NULL on delivered rows (the digest-only
-- privacy posture unchanged on the success path) and on legacy dead
-- letters (which the pass retires without a fetch — nothing to
-- re-sign). Expand-only per the migration contract; schema.sql's
-- mirror lands in the same commit.
ALTER TABLE webhook_deliveries ADD COLUMN body TEXT;
ALTER TABLE webhook_deliveries ADD COLUMN redelivered_at TEXT;
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_redelivery
  ON webhook_deliveries (delivered, redelivered_at, recorded_at);
