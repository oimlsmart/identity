-- The authorization row's response mode (TODO.modern/12, RFC 9150):
-- JARM's response_mode=jwt must survive the sign-in hop (the consent
-- flow's decide re-derives the redirect from the row), so the mode
-- rides the oidc_authorizations row. NULL = the default query mode —
-- every existing row and every existing RP stays byte-identical.
-- Expand-only (the migration contract): an ALTER, no renumber.
ALTER TABLE oidc_authorizations ADD COLUMN response_mode TEXT;
