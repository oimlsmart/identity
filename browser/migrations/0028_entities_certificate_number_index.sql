-- The public register's certificate-number lookup (the ServerStore
-- seam's findCertificatesByNumber): the smart side's verify surfaces
-- (/api/verify/status?number=, the credential verify's register
-- cross-check) full-scanned listEntities('certificates') and
-- JSON-parsed every row to case-fold certificate_number — O(store
-- rows) read per lookup. The guarded expression index (migration
-- 0023's spelling) makes the keyed read an index walk: (store, the
-- certificate_number out of the data JSON) — COLLATE NOCASE because
-- the register's number match is case-insensitive (the ASCII fold;
-- certificate numbers are ASCII by the number grammar).
--
-- The json_valid GUARD is load-bearing (0023's lesson): an unguarded
-- json_extract index expression would raise on the INSERT of a corrupt
-- entities row; the guard keeps a corrupt row writable.
--
-- CREATE INDEX IF NOT EXISTS is the idempotent guard (the migration
-- contract's expand-only discipline; a consumer that already carries
-- the index converges). schema.sql's mirror lands in the same commit.
CREATE INDEX IF NOT EXISTS idx_entities_store_certificate_number ON entities (
  store,
  json_extract(CASE WHEN json_valid(data) THEN data ELSE '{}' END, '$.certificate_number') COLLATE NOCASE
);
