-- Migration 0019 — the OIML Member category (TODO.identity-features/10,
-- the taxonomy correction): the org_registry gains the two designation
-- LINK columns and the CS status facet.
--
-- The corrected model: the Utilizer/Associate are DESIGNATED BODIES
-- (their own organization rows, signing the Declaration per PD-08),
-- never statuses on a member; "OIML Member" is the category with the
-- member-state / corresponding-member kinds. The links:
--
--   designated_by  the designating body: a Utilizer's is its MEMBER
--                  STATE, an Associate's its CORRESPONDING MEMBER, a
--                  Test Laboratory's its associated ISSUING AUTHORITY
--                  (the participants model's designated_by:
--                  issuing_authority);
--   proposed_by    an Issuing Authority's proposing MEMBER STATE (a
--                  member state participates in the OIML-CS by
--                  PROPOSING an IA and DESIGNATING a Utilizer);
--   cs_status      the designated bodies' Declaration standing
--                  (signed-active / suspended / withdrawn — the CS
--                  layer's fact projected onto the identity plane).
--
-- Expand-only, and deliberately NULL-defaulted: the kind enforcement of
-- the links (which kind may point at which) is the PROGRAM's write path
-- (the store keeps the kind column opaque by doctrine), and a legacy
-- row — a utilizer/associate curated before this migration — keeps its
-- home untouched: the links read NULL ("not recorded"), never a
-- destructive move. The journals' discipline holds.
-- schema.sql carries the same end state for fresh databases —
-- test/migrations.test.ts pins the UNION of every migration to
-- schema.sql's CREATE set.

ALTER TABLE org_registry ADD COLUMN designated_by TEXT;
ALTER TABLE org_registry ADD COLUMN proposed_by TEXT;
ALTER TABLE org_registry ADD COLUMN cs_status TEXT;
