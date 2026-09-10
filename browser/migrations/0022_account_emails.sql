-- Migration 0022 — multiple emails per account (TODO.identity-features/01):
-- the account gains a primary + additional addresses, each verified
-- independently, the sign-in and the recovery paths resolving by ANY
-- verified one.
--
-- The model:
--   - the PRIMARY address stays users.email (+ users.email_verified_at):
--     the OIDC `email` claim never changes shape, every existing reader
--     (the claims, the registry, the audit chain) is undisturbed, and the
--     claims keep carrying the primary on a switch;
--   - account_emails carries the ADDITIONAL addresses only — one row per
--     (account, address), verified_at NULL until the per-address ceremony
--     proves the mailbox. An address is globally unique across the estate
--     of addresses: the unique index keys it here, and the store's writes
--     check BOTH tables (an additional on account A blocks the address as
--     a primary or an additional anywhere else);
--   - the "primary" attribute is represented by WHERE the address lives
--     (the users row vs account_emails), never a flag to keep in sync —
--     the store's setPrimaryAccountEmail swaps the two residences with
--     their verification stamps;
--   - email_change_tokens gains `kind`: 'change' (the pre-0022 primary
--     replacement — the default, so existing rows read honestly) and
--     'add' (the per-address verification of an account_emails row; the
--     row lands unverified at the request and the token's completion
--     stamps verified_at). The same one-time, 24 h, atomically-consumed
--     doctrine carries both.
-- schema.sql carries the same end state for fresh databases —
-- test/migrations.test.ts pins the UNION of every migration to
-- schema.sql's CREATE set.

CREATE TABLE IF NOT EXISTS account_emails (
  user_id TEXT NOT NULL REFERENCES users(id),
  email TEXT NOT NULL,
  verified_at TEXT,
  added_by TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (user_id, email)
);
-- An address names at most ONE account across the estate (the sign-in
-- and recovery resolutions depend on it); the users.email UNIQUE covers
-- the primaries, this index the additionals, and the store's writes
-- check across both.
CREATE UNIQUE INDEX IF NOT EXISTS idx_account_emails_email ON account_emails (email);

ALTER TABLE email_change_tokens ADD COLUMN kind TEXT NOT NULL DEFAULT 'change';
