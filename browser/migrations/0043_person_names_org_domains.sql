-- 0043 — structured person names + the orgs' pre-approved email domains
-- (2026-10-13, the doors pass): the public intake collects GIVEN NAMES
-- and FAMILY NAME (the OIDC claims' own vocabulary) instead of one
-- "Full name" string, and the join queue carries them through to the
-- account; the org registry carries the VERIFIED email domain list per
-- organization (the member-domains pipeline's artifact) — the join
-- page shows the pre-approved domain and flags the mismatch honestly.
-- ADDITIVE: both columns nullable, every existing row reads as before.
ALTER TABLE users ADD COLUMN given_name TEXT;
ALTER TABLE users ADD COLUMN family_name TEXT;
ALTER TABLE org_join_requests ADD COLUMN given_name TEXT;
ALTER TABLE org_join_requests ADD COLUMN family_name TEXT;
ALTER TABLE org_registry ADD COLUMN email_domains TEXT;
