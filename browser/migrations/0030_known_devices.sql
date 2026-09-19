-- The known-device record (TODO.modern/06's risk signals): one row
-- per (account, device hash) — the device hash is SHA-256 of the
-- normalized user agent + the sign-in IP (the recognition key, never
-- a tracking artifact across accounts). first/last country + seen
-- instants carry the impossible-travel advisory's prior state (the
-- audit's countryChanged flag reads the pre-update row). Identical
-- end state to schema.sql's CREATE IF NOT EXISTS (the lockstep the
-- migrations test pins).
CREATE TABLE IF NOT EXISTS known_devices (
  id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL REFERENCES users(id),
  device_hash TEXT NOT NULL,
  user_agent TEXT,
  ip TEXT,
  first_country TEXT,
  last_country TEXT,
  first_seen_at TEXT NOT NULL DEFAULT (datetime('now')),
  last_seen_at TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE (account_id, device_hash)
);
CREATE INDEX IF NOT EXISTS idx_known_devices_account ON known_devices (account_id);
