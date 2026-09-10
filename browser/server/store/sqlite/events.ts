// ═══════════════════════════════════════════════════════════════════
// The platform event store (TODO.notify/01) — the SQLite (better-
// sqlite3, node-only) sync implementation, the entities.ts pattern:
// one row per declared notifiable act, the key SPLIT into columns
// (domain, entity_id, action) so the subscription grammar's prefixes
// resolve in SQL. The D1 store (../d1.ts) runs the SAME statements
// against the binding; the d1-store suite's tripwire pins the two
// schemas in lockstep.
// ═══════════════════════════════════════════════════════════════════

import { getDb } from './store'
import { APPEND_EVENTS_CHUNK, EVENTS_BULK_KEY_CHUNK, EVENTS_ID_CHUNK, type EventEntityKey, type EventKeyFilter, type EventWriteInput, type PlatformEvent } from '../../store'

interface EventRow {
  seq: number
  id: string
  domain: string
  entity_id: string
  action: string
  payload: string
  mentions: string | null
  at: string
}

function toPlatformEvent(row: EventRow): PlatformEvent {
  return {
    seq: row.seq,
    id: row.id,
    domain: row.domain,
    entityId: row.entity_id,
    action: row.action,
    payload: row.payload,
    mentions: row.mentions,
    at: row.at,
  }
}

/** The event append's INSERT … RETURNING * — ONE textual source for
 *  appendEvent and appendEvents alike (the D1 half's EVENT_INSERT_SQL's
 *  twin; the stored row answers off the write itself). The mentions
 *  column (migration 0027) lands from the input, NULL when absent. */
const EVENT_INSERT_SQL = 'INSERT INTO events (id, domain, entity_id, action, payload, mentions) VALUES (?, ?, ?, ?, ?, ?) RETURNING *'

export function appendEvent(input: EventWriteInput): PlatformEvent {
  // ONE statement: RETURNING answers the stored row (seq + the default
  // at) off the INSERT itself — the same halving as the D1 half.
  return toPlatformEvent(
    getDb().prepare(EVENT_INSERT_SQL)
      .get(input.id, input.domain, input.entityId, input.action, input.payload, input.mentions ?? null) as EventRow,
  )
}

/** The bulk append (the seam's appendEvents, the 2026-09-07 audit's
 *  chain half): each event lands exactly as appendEvent would land it —
 *  the INSERT … RETURNING * answers the stored row off the write itself —
 *  the answer rows in INPUT order (their seqs strictly increase in it),
 *  one transaction per APPEND_EVENTS_CHUNK rows. The chunk is the atomic
 *  unit, matching the D1 batch's all-or-nothing; a failed chunk throws
 *  with its events unlanded, earlier chunks standing, later chunks never
 *  issued. The chunks run serially, so the events' seq order IS the
 *  input order. */
export function appendEvents(events: readonly EventWriteInput[]): PlatformEvent[] {
  if (events.length === 0) return []
  const db = getDb()
  const insert = db.prepare(EVENT_INSERT_SQL)
  const out: PlatformEvent[] = []
  for (let i = 0; i < events.length; i += APPEND_EVENTS_CHUNK) {
    const chunk = events.slice(i, i + APPEND_EVENTS_CHUNK)
    db.transaction(() => {
      for (const e of chunk) {
        out.push(toPlatformEvent(insert.get(e.id, e.domain, e.entityId, e.action, e.payload, e.mentions ?? null) as EventRow))
      }
    })()
  }
  return out
}

/** The feed's raw leg: events past the cursor, seq-ordered. */
export function eventsAfter(seq: number, limit = 500): PlatformEvent[] {
  const rows = getDb()
    .prepare('SELECT * FROM events WHERE seq > ? ORDER BY seq LIMIT ?')
    .all(seq, limit) as EventRow[]
  return rows.map(toPlatformEvent)
}

export function latestEventSeq(): number {
  const row = getDb().prepare('SELECT MAX(seq) AS seq FROM events').get() as { seq: number | null }
  return row.seq ?? 0
}

/** The by-id read (the inbox state write's guard). */
export function getEvent(id: string): PlatformEvent | null {
  const row = getDb().prepare('SELECT * FROM events WHERE id = ?').get(id) as EventRow | undefined
  return row ? toPlatformEvent(row) : null
}

/** The BULK by-id read (the notify digest's event join): every id
 *  resolves in ONE statement per EVENTS_ID_CHUNK ids — the IN walk
 *  against the id UNIQUE index, the same chunking as the D1 half, so
 *  the backends stay answer-identical. The answer is INPUT-ALIGNED:
 *  position i carries the row for ids[i], null where no event carries
 *  the id (the per-id getEvent loop's exact answers; a duplicate id
 *  answers its row at every position). An empty list answers []
 *  without issuing a statement. */
export function getEvents(ids: readonly string[]): (PlatformEvent | null)[] {
  if (ids.length === 0) return []
  const byId = new Map<string, PlatformEvent>()
  for (let i = 0; i < ids.length; i += EVENTS_ID_CHUNK) {
    const chunk = ids.slice(i, i + EVENTS_ID_CHUNK)
    const marks = chunk.map(() => '?').join(', ')
    const rows = getDb()
      .prepare(`SELECT * FROM events WHERE id IN (${marks})`)
      .all(...chunk) as EventRow[]
    for (const row of rows) byId.set(row.id, toPlatformEvent(row))
  }
  return ids.map(id => byId.get(id) ?? null)
}

/** The subscription grammar's SQL resolution: the pinned columns match
 *  by equality; the free legs stay out of the WHERE. The BULK form (the
 *  2026-09-06 audit's notify-inbox seam) resolves every pinned (domain,
 *  entityId) pair in ONE statement per EVENTS_BULK_KEY_CHUNK keys — the
 *  same chunking as the D1 half, so the backends stay answer-identical —
 *  and answers the MERGED set, seq-ordered, limit-truncated after the
 *  merge. */
export function eventsMatching(filter: EventKeyFilter | { keys: readonly EventEntityKey[] }, limit = 500): PlatformEvent[] {
  if ('keys' in filter) {
    if (filter.keys.length === 0) return []
    const merged: PlatformEvent[] = []
    for (let i = 0; i < filter.keys.length; i += EVENTS_BULK_KEY_CHUNK) {
      const chunk = filter.keys.slice(i, i + EVENTS_BULK_KEY_CHUNK)
      const where = chunk.map(() => '(domain = ? AND entity_id = ?)').join(' OR ')
      const args = chunk.flatMap(k => [k.domain, k.entityId])
      const rows = getDb()
        .prepare(`SELECT * FROM events WHERE ${where} ORDER BY seq LIMIT ?`)
        .all(...args, limit) as EventRow[]
      merged.push(...rows.map(toPlatformEvent))
    }
    merged.sort((a, b) => a.seq - b.seq)
    return merged.slice(0, limit)
  }
  const where: string[] = []
  const args: unknown[] = []
  if (filter.domain !== undefined) { where.push('domain = ?'); args.push(filter.domain) }
  if (filter.entityId !== undefined) { where.push('entity_id = ?'); args.push(filter.entityId) }
  if (filter.action !== undefined) { where.push('action = ?'); args.push(filter.action) }
  const sql = `SELECT * FROM events${where.length ? ` WHERE ${where.join(' AND ')}` : ''} ORDER BY seq LIMIT ?`
  const rows = getDb().prepare(sql).all(...args, limit) as EventRow[]
  return rows.map(toPlatformEvent)
}
