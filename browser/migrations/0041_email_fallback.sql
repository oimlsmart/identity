-- The 2026-10-10 lockout's way back (the email sign-in fallback).
-- An account whose only reachable second factor is a passkey left on
-- another device had NO honest path in: the password opened the
-- second-factor challenge and nothing could answer it. The industry's
-- answer (Microsoft's Temporary Access Pass, Auth0's email OTP, Okta's
-- admin factor reset) mapped onto this OP's doctrine:
--
--   users.email_fallback_until  the ALLOWANCE: while live, the sign-in
--                               challenge offers the email OTP as a
--                               second factor. Two doors set it — the
--                               administrator's grant (time-boxed,
--                               revocable) and the password-reset
--                               completion (the mailed one-time link
--                               already proved the mailbox; one hour
--                               covers the next sign-in). NULL = the
--                               method is never offered.
--   mfa_pending.email_code_*    the mailed code rides the challenge
--                               row (a fresh sign-in mints a fresh
--                               challenge): the SHA-256 of the six
--                               digits (the recovery-code posture),
--                               the expiry (the challenge's own), the
--                               sent-at stamp (the resend window).
-- Expand-only per the migration contract; schema.sql's mirror lands in
-- the same commit.
ALTER TABLE users ADD COLUMN email_fallback_until TEXT;
ALTER TABLE mfa_pending ADD COLUMN email_code_hash TEXT;
ALTER TABLE mfa_pending ADD COLUMN email_code_expires_at TEXT;
ALTER TABLE mfa_pending ADD COLUMN email_code_sent_at TEXT;
