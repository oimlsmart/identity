-- Migration 0025 — the SSO wave-C token surface (TODO.identity-sso: the
-- refresh-token grant with rotation + revocation): the OP's refresh
-- tokens. A refresh token is the offline half of the remembered consent
-- (the Relying Party keeps the authorization while the holder is away),
-- so the row carries the granting code's full provenance: the canonical
-- scope spelling, the context_org, the amr, and the ORIGINAL
-- authentication instant (auth_time never advances on a refresh — the
-- refreshed ID token proves the original authentication, never a new
-- one).
--
-- The doctrines:
--   - ONE-TIME, atomically consumed (the oidc_codes / email_change_tokens
--     posture): the exchange's UPDATE … WHERE consumed_at IS NULL flips
--     exactly once — a replay loses the race;
--   - the FAMILY: every rotation descends from the first mint and carries
--     its family_id. A presented CONSUMED token is the theft signal
--     (RFC 6819 §5.2.2.3): the whole family dies (DELETE WHERE
--     family_id), so the attacker's copy and the holder's legitimate
--     chain both end;
--   - the consumed row STAYS (the reuse detector reads it) until the
--     family's end: revocation (RFC 7009, client-bound — a client revokes
--     only its own, and revoking one refresh token revokes the family),
--     the consent's revocation, the deactivation sweep, and the account
--     erasure remove the rows outright (the personal_access_tokens
--     doctrine);
--   - expiry is per row (the consumer passes ttlMs at each mint; a
--     rotation slides the window forward on the NEW row). An expired
--     present is consumed anyway — never a second chance.
-- schema.sql carries the same end state for fresh databases —
-- test/migrations.test.ts pins the UNION of every migration to
-- schema.sql's CREATE set.

CREATE TABLE IF NOT EXISTS oidc_refresh_tokens (
  token TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  client_id TEXT NOT NULL,
  -- The granted scope set, the canonical space-joined spelling
  -- (normalizeOidcScopeSet) — a refresh never widens it (the route's
  -- math), the row is the grant's record.
  scope TEXT NOT NULL,
  -- The granting code's context — a refreshed access token answers the
  -- SAME claims the original carried.
  context_org TEXT,
  -- The authorizing authentication's amr provenance (a JSON array; NULL =
  -- none recorded).
  amr TEXT,
  -- The ORIGINAL authentication instant (verbatim from the consenting
  -- session; NULL = none recorded) — carried into every refreshed ID
  -- token's auth_time.
  auth_time TEXT,
  -- The rotation lineage: the first mint's generated id, inherited by
  -- every rotation. Reuse of a consumed row kills the family.
  family_id TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  expires_at TEXT NOT NULL,
  consumed_at TEXT
);
-- The deactivation/erasure sweeps + the account console's per-app read.
CREATE INDEX IF NOT EXISTS idx_oidc_refresh_tokens_user ON oidc_refresh_tokens (user_id);
-- The reuse-kill + the RFC 7009 family revocation.
CREATE INDEX IF NOT EXISTS idx_oidc_refresh_tokens_family ON oidc_refresh_tokens (family_id);
