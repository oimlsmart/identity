-- Migration 0021 — the remembered consent grants (TODO.identity-features/12):
-- the OP remembers the account holder's "Allow" per (user, client, scope
-- set), so a repeat authorization the grant COVERS skips the consent page
-- (the OIDC-correct behavior — the page shows again only when the request
-- carries prompt=consent, when the granted set no longer covers the asked
-- scopes, or when the holder revoked the access from the account console).
--
-- The doctrines:
--   - ONE LIVE grant per (user_id, client_id, scope): the partial unique
--     index keys the live rows only (a live grant = revoked_at IS NULL) —
--     a revoked triple's re-allow lands a FRESH row and the history keeps
--     the revoked one;
--   - scope is the CANONICAL spelling (the scope SET, space-joined,
--     deduped, sorted — store.ts's normalizeOidcScopeSet): 'profile openid'
--     and 'openid profile' are the same grant, so the unique triple holds
--     honestly;
--   - the skip check's COVERAGE math (the granted set ⊇ the requested set)
--     is the store's (consentGrantCovers over the live rows), never a LIKE
--     scan in SQL;
--   - revocation flips revoked_at (the row STAYS — the audit chain carries
--     the grant + the revoke, the row is their resolvable record); the
--     account erasure removes the rows outright (a dead account's grants
--     die with it — the personal_access_tokens doctrine, migration 0020).
-- schema.sql carries the same end state for fresh databases —
-- test/migrations.test.ts pins the UNION of every migration to
-- schema.sql's CREATE set.

CREATE TABLE IF NOT EXISTS oidc_consent_grants (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  client_id TEXT NOT NULL,
  -- The granted scope set, the canonical space-joined spelling
  -- (normalizeOidcScopeSet).
  scope TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  revoked_at TEXT
);
-- One LIVE grant per (user, client, scope set) — the predicate keeps the
-- revoked rows out of the index, so the re-allow after a revoke inserts
-- cleanly.
CREATE UNIQUE INDEX IF NOT EXISTS idx_oidc_consent_grants_live
  ON oidc_consent_grants (user_id, client_id, scope) WHERE revoked_at IS NULL;
-- The account console's "apps they can access" read.
CREATE INDEX IF NOT EXISTS idx_oidc_consent_grants_user ON oidc_consent_grants (user_id);
