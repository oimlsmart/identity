// TODO.restructure/28 workstream A (TODO.restructure/27 item 4) — the
// audit journal's retention, proven against a REAL SQLite store (the
// route-level tests' posture: temp DATABASE_PATH bound before the
// store module evaluates; real instances, never mocks/doubles):
//
//   1. the cutoff math — events strictly older than the window are
//      selected, the boundary row (exactly N days) and everything
//      newer are kept; undated/malformed rows are NEVER purgeable; a
//      row in another store is never touched;
//   2. the no-op default — AUDIT_RETENTION_DAYS unset = the disabled
//      run: the report says nothing to purge, and ZERO deletes land;
//   3. the dry-run — the purgeable are counted, nothing is deleted;
//   4. the remote leg's SQL agrees with the in-memory selection row
//      for row on the same file (D1 and the node store are both
//      SQLite — the repo's own one-dialect claim);
//   5. the dashboard's retention statement stays honest under both
//      flag states — unset answers the pre-2026-09 text
//      byte-identically, set answers the window.

import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import Database from 'better-sqlite3'
import {
  auditEventTimestamp,
  printRetentionRun,
  remotePageSelectSql,
  remotePurgeableCountSql,
  runLocalRetention,
  selectAuditPurge,
} from '../../scripts/op-audit-retention'
import { auditCutoffIso, auditRetentionStatement, parseAuditRetentionDays } from '../../server/audit-retention'

// The store's DB path binds at module evaluation — set it before any
// dynamic import touches server/store/sqlite.
const TMP = mkdtempSync(join(tmpdir(), 'op-audit-retention-'))
process.env.DATABASE_PATH = join(TMP, 'identity.db')

// A pinned now: the cutoff math asserts exact instants, never the
// wall clock's.
const NOW = new Date('2026-09-12T12:00:00.000Z')
const DAY = 86_400_000
const iso = (msAgo: number): string => new Date(NOW.getTime() - msAgo).toISOString()

let store: import('../../server/store').ServerStore

async function seedAuditEvent(id: string, payload: Record<string, unknown> | string): Promise<void> {
  await store.putEntity('auditEvents', id, null, typeof payload === 'string' ? payload : JSON.stringify({
    id,
    entity_type: 'account',
    entity_id: 'u-1',
    action: 'account.sign_in',
    ...payload,
  }))
}

beforeAll(async () => {
  const { installSqliteStore } = await import('../../server/store/sqlite')
  store = installSqliteStore()
})

afterAll(() => {
  rmSync(TMP, { recursive: true, force: true })
})

describe('parseAuditRetentionDays (the owners var, never a code default)', () => {
  it('unset and empty answer null — the no-purge posture', () => {
    expect(parseAuditRetentionDays(undefined)).toBeNull()
    expect(parseAuditRetentionDays('')).toBeNull()
    expect(parseAuditRetentionDays('   ')).toBeNull()
  })

  it('a whole number of days >= 1 answers the window', () => {
    expect(parseAuditRetentionDays('30')).toBe(30)
    expect(parseAuditRetentionDays(' 365 ')).toBe(365)
  })

  it('a malformed window refuses loudly, never guesses', () => {
    for (const bad of ['0', '-5', '2.5', 'abc', '30days']) {
      expect(() => parseAuditRetentionDays(bad)).toThrow(/AUDIT_RETENTION_DAYS/)
    }
  })
})

describe('auditCutoffIso (the strict-older rule)', () => {
  it('the cutoff is exactly N days before now', () => {
    expect(auditCutoffIso(NOW, 30)).toBe('2026-08-13T12:00:00.000Z')
  })

  it('events strictly older than the cutoff are selected; the boundary row is not', () => {
    const cutoff = auditCutoffIso(NOW, 30)
    expect(iso(30 * DAY + 1) < cutoff).toBe(true)
    expect(iso(30 * DAY) < cutoff).toBe(false)
    expect(iso(30 * DAY - 1) < cutoff).toBe(false)
  })
})

describe('the retention run over a real SQLite store', () => {
  const cutoff = auditCutoffIso(NOW, 30)

  beforeAll(async () => {
    await seedAuditEvent('evt-old-40', { timestamp: iso(40 * DAY) })
    await seedAuditEvent('evt-old-31', { timestamp: iso(31 * DAY) })
    await seedAuditEvent('evt-boundary-30', { timestamp: iso(30 * DAY) })
    await seedAuditEvent('evt-new-29', { timestamp: iso(29 * DAY) })
    await seedAuditEvent('evt-now', { timestamp: iso(0) })
    await seedAuditEvent('evt-undated', { action: 'account.link_on_behalf' })
    await seedAuditEvent('evt-malformed', 'not json {')
    // A row in ANOTHER store, older than the cutoff: the purge is the
    // journal's, never the entities table's at large.
    await store.putEntity('orgEndorsements', 'endo-old', null, JSON.stringify({ timestamp: iso(99 * DAY) }))
  })

  it('the disabled default (unset var) touches nothing: no store read, zero deletes', async () => {
    const run = await runLocalRetention(store, {}, { apply: true, now: NOW })
    expect(run.status).toBe('disabled')
    expect(printRetentionRun(run, 'the spec store', NOW))
      .toContain('nothing to purge')
    for (const id of ['evt-old-40', 'evt-old-31', 'evt-boundary-30', 'evt-new-29', 'evt-now', 'evt-undated', 'evt-malformed']) {
      expect(await store.getEntity('auditEvents', id)).toBeDefined()
    }
  })

  it('a malformed window refuses before any read', async () => {
    await expect(runLocalRetention(store, { AUDIT_RETENTION_DAYS: 'soon' }, { apply: true, now: NOW }))
      .rejects.toThrow(/AUDIT_RETENTION_DAYS/)
    expect(await store.getEntity('auditEvents', 'evt-old-40')).toBeDefined()
  })

  it('the selection: strictly older only — the boundary, the undated, and the malformed are kept', async () => {
    const selection = await selectAuditPurge(store, cutoff)
    expect(selection.scanned).toBe(7)
    expect(selection.purgeableIds).toEqual(['evt-old-40', 'evt-old-31'])
    expect(selection.kept).toBe(5)
    expect(auditEventTimestamp('{"timestamp":"2026-09-01T00:00:00.000Z"}')).toBe('2026-09-01T00:00:00.000Z')
    expect(auditEventTimestamp('not json {')).toBeNull()
    expect(auditEventTimestamp('{"action":"x"}')).toBeNull()
  })

  it('the dry-run counts, never deletes', async () => {
    const run = await runLocalRetention(store, { AUDIT_RETENTION_DAYS: '30' }, { apply: false, now: NOW })
    expect(run).toMatchObject({ status: 'dry-run', report: { scanned: 7, purgeable: 2, purged: 0, kept: 5 } })
    expect(await store.getEntity('auditEvents', 'evt-old-40')).toBeDefined()
    expect(await store.getEntity('auditEvents', 'evt-old-31')).toBeDefined()
  })

  it('the remote-leg SQL agrees with the in-memory selection on the same file', () => {
    // D1 and the node store are both SQLite (the op-access-review
    // claim): the wrangler-driven predicate must select exactly what
    // the seam-driven selection selected, row for row — including the
    // malformed row (NULL extracts compare false: kept by BOTH legs).
    const db = new Database(process.env.DATABASE_PATH!)
    try {
      const count = db.prepare(remotePurgeableCountSql(cutoff)).get() as { n: number }
      expect(count.n).toBe(2)
      const ids = (db.prepare(remotePageSelectSql(cutoff, 500)).all() as Array<{ id: string }>).map(r => r.id)
      expect(ids).toEqual(['evt-old-40', 'evt-old-31'])
    } finally {
      db.close()
    }
  })

  it('the applied run purges the old, keeps the rest, never touches another store', async () => {
    const run = await runLocalRetention(store, { AUDIT_RETENTION_DAYS: '30' }, { apply: true, now: NOW })
    expect(run).toMatchObject({ status: 'applied', report: { scanned: 7, purgeable: 2, purged: 2, kept: 5 } })
    expect(await store.getEntity('auditEvents', 'evt-old-40')).toBeUndefined()
    expect(await store.getEntity('auditEvents', 'evt-old-31')).toBeUndefined()
    for (const id of ['evt-boundary-30', 'evt-new-29', 'evt-now', 'evt-undated', 'evt-malformed']) {
      expect(await store.getEntity('auditEvents', id)).toBeDefined()
    }
    expect(await store.getEntity('orgEndorsements', 'endo-old')).toBeDefined()
    // The purgeable are gone; a second run finds nothing (idempotent).
    const again = await runLocalRetention(store, { AUDIT_RETENTION_DAYS: '30' }, { apply: true, now: NOW })
    expect(again).toMatchObject({ status: 'applied', report: { purgeable: 0, purged: 0 } })
  })
})

describe('the dashboard retention statement stays honest under both flag states', () => {
  it('unset answers the pre-2026-09 text byte-identically', () => {
    expect(auditRetentionStatement({})).toBe(
      'The audit journal is retained for the life of the registry (no automated purge). '
      + 'The heartbeat history is retained by GitHub Actions under its own policy. '
      + 'The dashboard computes its counters at request time and stores nothing.',
    )
    expect(auditRetentionStatement({ AUDIT_RETENTION_DAYS: '' })).toBe(auditRetentionStatement({}))
  })

  it('set answers the owners window', () => {
    const text = auditRetentionStatement({ AUDIT_RETENTION_DAYS: '365' })
    expect(text).toContain('purged of events older than 365 days')
    expect(text).toContain('AUDIT_RETENTION_DAYS=365')
    expect(text).toContain('The dashboard computes its counters at request time and stores nothing.')
  })

  it('a malformed window refuses rather than misstate the posture', () => {
    expect(() => auditRetentionStatement({ AUDIT_RETENTION_DAYS: 'x' })).toThrow(/AUDIT_RETENTION_DAYS/)
  })
})
