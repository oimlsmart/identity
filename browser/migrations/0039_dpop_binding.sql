-- TODO.sota/09 (RFC 9449), the first slice — the sender-constrained
-- opaque access tokens. The binding column: the proof key's JKT the
-- token was minted under; NULL = the ordinary Bearer posture (a proof
-- never rode the token request — the default surface is unchanged).
-- The replay cache: one row per seen proof jti, expiring at the
-- freshness window; the TTL sweep (TTL_TABLES) reaps the spent rows.
-- Expand-only per the migration contract; schema.sql's mirror lands
-- in the same commit.
ALTER TABLE oidc_access_tokens ADD COLUMN dpop_jkt TEXT;
CREATE TABLE IF NOT EXISTS dpop_jtis (
  jti TEXT PRIMARY KEY,
  expires_at TEXT NOT NULL
);
