-- The outbound webhooks (TODO.modern/08): an account's event
-- subscriptions and the delivery log. events is the JSON array of the
-- JOURNAL ACTION names (WEBHOOK_EVENTS — server/webhooks/events.ts,
-- the SSOT whitelist); secret is the SHARED HMAC signing key (we sign,
-- the subscriber verifies the copy shown once at creation — never a
-- credential presented to us, so plaintext is the correct posture).
-- Revocation flips active; deliveries record the bounded ladder's
-- outcome with the body's SHA-256 digest ONLY (privacy + size — the
-- support conversation's dedup key, never the payload). Identical end
-- state to schema.sql's CREATE IF NOT EXISTS entries (the lockstep
-- the migrations test pins).
CREATE TABLE IF NOT EXISTS webhook_subscriptions (
  id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL REFERENCES users(id),
  url TEXT NOT NULL,
  events TEXT NOT NULL DEFAULT '[]',
  secret TEXT NOT NULL,
  active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_webhook_subscriptions_account ON webhook_subscriptions (account_id);

CREATE TABLE IF NOT EXISTS webhook_deliveries (
  id TEXT PRIMARY KEY,
  subscription_id TEXT NOT NULL,
  account_id TEXT NOT NULL,
  event TEXT NOT NULL,
  url TEXT NOT NULL,
  attempts INTEGER NOT NULL,
  last_status INTEGER NOT NULL,
  delivered INTEGER NOT NULL,
  body_digest TEXT NOT NULL,
  recorded_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_account ON webhook_deliveries (account_id, recorded_at);
