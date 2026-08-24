-- Migration 0011 — the SSO home's launch metadata on the OIDC client
-- registry (the identity service's post-login launcher: the spec is
-- TODO.identity-extract/02a's "post-login landing"). One set of columns
-- per client: the launch URL (the service's sign-in start; NULL = the
-- client never appears on the launcher), the icon glyph's name, the
-- one-line description, and the visibility rule for an account the
-- computed role set does not admit ('roles' hides the card, 'request'
-- shows it with the plain request-access state, 'open' never gates).
-- Numbering: 0010 is the platform's notify wave; the identity repo's
-- byte-identical set continues the shared numbering here.
-- schema.sql carries the same end state for fresh databases —
-- src/__tests__/d1-store.test.ts pins the UNION of every migration to
-- schema.sql's CREATE set.

ALTER TABLE oidc_clients ADD COLUMN launch_url TEXT;
ALTER TABLE oidc_clients ADD COLUMN launch_icon TEXT;
ALTER TABLE oidc_clients ADD COLUMN launch_description TEXT;
ALTER TABLE oidc_clients ADD COLUMN launch_visibility TEXT NOT NULL DEFAULT 'roles';
