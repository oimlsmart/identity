-- Migration 0031 — the personal access tokens' PERMISSIONS column
-- (TODO.openapi/03, the identity-service half): a PAT may carry, beside
-- its scope set, a JSON array of the TARGET INSTANCE's permissions-
-- catalog ids (`<group>.<resource>.<verb>` — the instance serves its
-- own catalog at GET /api/openapi.json under x-oiml-permissions-catalog;
-- the OP NEVER holds a copy). The OP validates at mint/edit against the
-- scoped service's served catalog (fail closed) and echoes the ids
-- verbatim at introspection — the enforcement lives with the instance,
-- the row is the pinned grant.
--
-- Expand-only (the migration contract): an ALTER on the 0020 table, no
-- renumber, no rewrite. '[]' = no catalog permissions — the token
-- exchanges exactly as before (backward compatible). schema.sql carries
-- the same end state for fresh databases —
-- src/__tests__/migrations.test.ts pins the UNION of every migration to
-- schema.sql's CREATE set.

ALTER TABLE personal_access_tokens ADD COLUMN permissions TEXT NOT NULL DEFAULT '[]';
