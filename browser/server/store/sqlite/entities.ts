// ═══════════════════════════════════════════════════════════════════
// The workflow entity store (TODO.ops/07 — server-side persistence).
// One JSON document per entity keyed by (store, id) — the same shape
// the browser's IndexedDB stores hold, so the two repository backends
// are contract-identical. Every write journals into entity_changes —
// the SSE stream tails it.
//
// TODO.cs-e2e/14: the PURE vocabulary (row/change types, ORG_FIELDS,
// CATALOG_STORES, orgIdOf) lives in ./backend — the worker-safe seam
// both store implementations share. This module keeps the SQLite
// (better-sqlite3, node-only) sync implementation and re-exports the
// vocabulary so existing importers are undisturbed.
// ═══════════════════════════════════════════════════════════════════

import { getDb } from './store'
import { PUT_ENTITIES_CHUNK, orgIdOf } from '../../store'

export type { EntityRow, EntityChange } from '../../store'
export { ORG_FIELDS, CATALOG_STORES, orgIdOf } from '../../store'

import type { EntityRow, EntityChange, EntityListOptions, EntityWriteInput, JournalAppend } from '../../store'

/** The journal fan-out's ISOLATE-scope registry (the seam's
 *  onJournalAppend, the D1 half's twin): one module-scope set — a
 *  registration through any store instance hears every journal append
 *  landing in this process. */
const journalListeners = new Set<(appends: readonly JournalAppend[]) => void>()

/** Fires the registry with one write's appended triples, AFTER the
 *  write stands (the transaction committed). A listener's throw is
 *  swallowed per listener — the write path never breaks for a
 *  listener. */
function emitJournalAppends(appends: readonly JournalAppend[]): void {
  if (appends.length === 0 || journalListeners.size === 0) return
  for (const listener of [...journalListeners]) {
    try {
      listener(appends)
    } catch { /* a listener never breaks the write path */ }
  }
}

/** The entity write's two statements, ONE textual source for putEntity
 *  and putEntities alike (the multi-row write must land each row
 *  byte-identically to the single-row verb — the upsert, then its
 *  journal entry). */
const ENTITY_UPSERT_SQL = `INSERT INTO entities (store, id, org_id, data, updated_at) VALUES (?, ?, ?, ?, datetime('now'))
       ON CONFLICT (store, id) DO UPDATE SET org_id = excluded.org_id, data = excluded.data, updated_at = datetime('now')`
const ENTITY_CHANGE_SQL = 'INSERT INTO entity_changes (store, type, id) VALUES (?, ?, ?)'

/** The register's number lookup (the seam's findCertificatesByNumber,
 *  the D1 half's CERTIFICATE_NUMBER_SQL's twin): the keyed read against
 *  idx_entities_store_certificate_number (migration 0028) — the
 *  json_valid-guarded extract's exact spelling, COLLATE NOCASE for the
 *  register's case-insensitive number match. INDEXED BY pins the walk:
 *  without it the planner prefers idx_entities_store_org for the ORDER
 *  BY (org_id, rowid) — the seam's list order, kept so the first match
 *  IS the retiring listEntities scan's first match — and the "index"
 *  would walk the whole store. */
const CERTIFICATE_NUMBER_SQL = `SELECT store, id, org_id, data, updated_at
       FROM entities INDEXED BY idx_entities_store_certificate_number
       WHERE store = 'certificates'
         AND json_extract(CASE WHEN json_valid(data) THEN data ELSE '{}' END, '$.certificate_number') COLLATE NOCASE = ?
       ORDER BY org_id, rowid`

export function listEntities(store: string, options?: EntityListOptions): EntityRow[] {
  // The ORDER BY is the seam's contract (the 0.2.3 pin, the D1 half's
  // twin): (org_id, rowid) — the read's observable order since
  // migration 0001's idx_entities_store_org walk, made planner-proof
  // when migration 0023's expression index offered a second
  // store-prefixed plan.
  // options.orgId narrows the candidate set (the seam's EntityListOptions
  // — the portal-load audit's R3-fix3): the kept groups (NULL stamps,
  // then the named org) are the two lowest org_id buckets, so the
  // filtered ORDER BY is the unfiltered order's restriction to the
  // candidates — a gate-driven projection of either answer is
  // byte-identical.
  if (options?.orgId) {
    return getDb()
      .prepare('SELECT store, id, org_id, data, updated_at FROM entities WHERE store = ? AND (org_id = ? OR org_id IS NULL) ORDER BY org_id, rowid')
      .all(store, options.orgId) as EntityRow[]
  }
  return getDb()
    .prepare('SELECT store, id, org_id, data, updated_at FROM entities WHERE store = ? ORDER BY org_id, rowid')
    .all(store) as EntityRow[]
}

export function getEntity(store: string, id: string): EntityRow | undefined {
  return getDb()
    .prepare('SELECT store, id, org_id, data, updated_at FROM entities WHERE store = ? AND id = ?')
    .get(store, id) as EntityRow | undefined
}

export function putEntity(store: string, id: string, orgId: string | null, data: string): void {
  const db = getDb()
  const write = db.transaction(() => {
    db.prepare(ENTITY_UPSERT_SQL).run(store, id, orgId, data)
    db.prepare(ENTITY_CHANGE_SQL).run(store, 'persist', id)
  })
  write()
  emitJournalAppends([{ store, type: 'persist', id }])
}

export function deleteEntity(store: string, id: string): boolean {
  const db = getDb()
  let gone = false
  const write = db.transaction(() => {
    const res = db.prepare('DELETE FROM entities WHERE store = ? AND id = ?').run(store, id)
    if (res.changes > 0) {
      db.prepare('INSERT INTO entity_changes (store, type, id) VALUES (?, ?, ?)').run(store, 'remove', id)
      gone = true
    }
  })
  write()
  if (gone) emitJournalAppends([{ store, type: 'remove', id }])
  return gone
}
