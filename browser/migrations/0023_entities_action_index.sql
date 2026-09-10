-- The 2026-09-06 performance audit's audit-chain read: the OP console's
-- last-sign-in-per-account read (lastAccountSignIns) string-matched
-- EVERY auditEvents row's data blob (two data LIKE '%…%' clauses —
-- O(journal) per call, degrading as the journal grows). The auditEvents
-- rows are entities rows whose data JSON carries the typed legs
-- (action, entity_id, timestamp), so the read compiles to json_extract
-- equality — and this expression index makes it a walk over the
-- (store, action) slice instead of the journal: only the sign-in rows
-- are ever visited.
--
-- The json_valid GUARD is load-bearing: an unguarded json_extract index
-- expression RAISES 'malformed JSON' on any corrupt entities row —
-- the corrupt row would become unwritable, and the unguarded query
-- would throw where the retired LIKE fold skipped. The CASE guard
-- lands the corrupt row's legs at NULL (indexed, never matched); the
-- query spells the identical expression so the planner proves the
-- index applies. Expand-only per the migration contract; schema.sql's
-- mirror lands in the same commit.
CREATE INDEX IF NOT EXISTS idx_entities_store_action ON entities (
  store,
  json_extract(CASE WHEN json_valid(data) THEN data ELSE '{}' END, '$.action'),
  json_extract(CASE WHEN json_valid(data) THEN data ELSE '{}' END, '$.entity_id'),
  json_extract(CASE WHEN json_valid(data) THEN data ELSE '{}' END, '$.timestamp')
);
