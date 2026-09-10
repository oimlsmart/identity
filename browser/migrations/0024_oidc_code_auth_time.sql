-- Migration 0024 — the SSO wave-A tail (TODO.identity-sso: RP-initiated
-- logout + prompt=login): the one-time code carries the consenting
-- session's authentication instant (sessions.created_at, verbatim), so
-- the token endpoint emits the ID token's auth_time — the forced
-- re-authentication's freshness proof the RP verifies. NULL = no
-- instant recorded (a code minted before this wave).
-- schema.sql carries the same end state for fresh databases —
-- src/__tests__/d1-store.test.ts pins the UNION of every migration to
-- schema.sql's CREATE set.
ALTER TABLE oidc_codes ADD COLUMN auth_time TEXT;
