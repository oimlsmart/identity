// ─────────────────────────────────────────────────────────────────────
// op-audit-retention.ts — the audit journal's retention run
// (TODO.restructure/27 item 4: auditEvents grows unbounded; the
// operating plan is docs/deployment/identity-operations.md). The window
// is the OWNER's decision, carried by AUDIT_RETENTION_DAYS; UNSET (or
// empty) = the no-purge posture — this script answers "nothing to
// purge" and touches no store, byte-identical to the pre-2026-09
// behavior. A set-but-malformed value refuses loudly (exit 1), never
// guesses a window.
//
// Postures (the repo's ops-script convention, op-access-review.ts):
//   --remote (default)  the live D1: pages through auditEvents rows
//                       older than the cutoff via `wrangler d1 execute
//                       --remote` (the operator's / CI's Cloudflare
//                       credentials; the D1 name overridable with --d1).
//   --db <path>         a local SQLite file through the STORE SEAM
//                       (installSqliteStore — the same verbs the server
//                       runs; the rehearsal + unit-leg posture).
//
// Both postures are DRY-RUN by default: they report what WOULD be
// purged and delete nothing; --apply performs the deletes.
//
// Store discipline (the repo's doctrine, verbatim): reads may batch in
// parallel, WRITES stay serial — the deletes issue one at a time, in
// page order, never concurrently.
//
// Output: plain lines on stdout, and ONLY stdout (counts + the cutoff,
// never event payloads — the public-job-log discipline). Purged rows
// survive in the nightly R2 snapshots (the 23:41 export precedes this
// run; the bucket's lifecycle keeps 30 nights).
//
// Usage (from browser/):
//   AUDIT_RETENTION_DAYS=365 npx tsx scripts/op-audit-retention.ts --remote           (dry-run)
//   AUDIT_RETENTION_DAYS=365 npx tsx scripts/op-audit-retention.ts --remote --apply
//   AUDIT_RETENTION_DAYS=30 npx tsx scripts/op-audit-retention.ts --db .cache/id-01/identity.db
// ─────────────────────────────────────────────────────────────────────

import { spawnSync } from 'node:child_process'
import { resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import type { EntityRow, ServerStore } from '../server/store'
import { auditCutoffIso, parseAuditRetentionDays } from '../server/audit-retention'

const DEFAULT_D1 = 'oiml-smart-platform-identity'

/** The remote leg's page: one wrangler round trip's worth of ids
 *  (SELECT page + its DELETE). Bounds each statement's IN-list and each
 *  read's payload; the loop walks pages until a short page ends the
 *  run. */
export const REMOTE_PAGE_SIZE = 500

// ── the selection (pure over the seam's rows) ────────────────────────

/** One journal row's timestamp (the writers' new Date().toISOString()),
 *  or null when the row is malformed or undated — an undated row is
 *  NEVER purgeable (the purge never deletes what it cannot date). */
export function auditEventTimestamp(data: string): string | null {
  try {
    const parsed = JSON.parse(data) as { timestamp?: unknown }
    return typeof parsed?.timestamp === 'string' ? parsed.timestamp : null
  } catch {
    return null
  }
}

export interface AuditPurgeSelection {
  /** Every auditEvents row the read saw. */
  scanned: number
  /** The rows strictly older than the cutoff, in the seam's declared
   *  order — the delete order (serial, same order). */
  purgeableIds: string[]
  /** Everything kept: younger rows, the boundary row itself (strictly
   *  older is the rule), and undated/malformed rows. */
  kept: number
}

/** Page through the journal and select the purgeable ids: the read is
 *  the seam's own listEntities (the same read every dashboard surface
 *  makes); the selection is the cutoff compare (auditCutoffIso's
 *  strict-older rule). */
export async function selectAuditPurge(store: ServerStore, cutoffIso: string): Promise<AuditPurgeSelection> {
  const rows = await store.listEntities('auditEvents')
  const purgeableIds: string[] = []
  for (const row of rows) {
    const ts = auditEventTimestamp(row.data)
    if (ts !== null && ts < cutoffIso) purgeableIds.push(row.id)
  }
  return { scanned: rows.length, purgeableIds, kept: rows.length - purgeableIds.length }
}

/** The writes: one deleteEntity per row, strictly serial (the doctrine
 *  — writes never batch, never race). Answers how many rows actually
 *  deleted (deleteEntity's honest boolean, summed). */
export async function deleteAuditEventsSerial(store: ServerStore, ids: string[]): Promise<number> {
  let purged = 0
  for (const id of ids) {
    if (await store.deleteEntity('auditEvents', id)) purged += 1
  }
  return purged
}

export interface AuditPurgeReport {
  retentionDays: number
  cutoffIso: string
  scanned: number
  purgeable: number
  purged: number
  kept: number
}

export type AuditRetentionRun =
  | { status: 'disabled' }
  | { status: 'dry-run'; report: AuditPurgeReport }
  | { status: 'applied'; report: AuditPurgeReport }

/** The local posture's whole run, env-resolved (the unit legs drive
 *  this over a real SQLite store): UNSET = disabled — no store call at
 *  all; the malformed var throws from parseAuditRetentionDays before
 *  any read. */
export async function runLocalRetention(
  store: ServerStore,
  env: { AUDIT_RETENTION_DAYS?: string },
  opts: { apply: boolean; now?: Date },
): Promise<AuditRetentionRun> {
  const retentionDays = parseAuditRetentionDays(env.AUDIT_RETENTION_DAYS)
  if (retentionDays === null) return { status: 'disabled' }
  const cutoffIso = auditCutoffIso(opts.now ?? new Date(), retentionDays)
  const selection = await selectAuditPurge(store, cutoffIso)
  const purged = opts.apply ? await deleteAuditEventsSerial(store, selection.purgeableIds) : 0
  const report: AuditPurgeReport = {
    retentionDays,
    cutoffIso,
    scanned: selection.scanned,
    purgeable: selection.purgeableIds.length,
    purged,
    kept: selection.kept,
  }
  return { status: opts.apply ? 'applied' : 'dry-run', report }
}

// ── the report (stdout only; counts, never payloads) ─────────────────

export function printRetentionRun(run: AuditRetentionRun, source: string, now = new Date()): string {
  const lines: string[] = []
  lines.push(`# Audit-journal retention — ${source}`)
  lines.push(`Generated ${now.toISOString()}.`)
  if (run.status === 'disabled') {
    lines.push('AUDIT_RETENTION_DAYS is unset — the no-purge posture; nothing to purge (zero deletes).')
    return lines.join('\n') + '\n'
  }
  const r = run.report
  lines.push(`AUDIT_RETENTION_DAYS=${r.retentionDays}; the cutoff is ${r.cutoffIso} (strictly older).`)
  lines.push(`scanned ${r.scanned} audit events: ${r.purgeable} purgeable, ${r.kept} kept.`)
  lines.push(run.status === 'applied'
    ? `purged ${r.purged} row(s).`
    : `dry-run — nothing deleted (re-run with --apply to purge the ${r.purgeable} row(s)).`)
  return lines.join('\n') + '\n'
}

// ── the remote leg (the live D1 through wrangler; one SQL dialect —
//    D1 and the node store are both SQLite) ──────────────────────────

const sqlLiteral = (value: string): string => `'${value.replaceAll("'", "''")}'`

/** The purge predicate, one source for both remote statements: the
 *  json_valid guard spells the existing indexes' expression discipline
 *  (lastAccountSignIns' shape) — a malformed row extracts NULL, NULL
 *  compares false, the row is kept, so the SQL leg and
 *  auditEventTimestamp agree row for row. */
function olderThanWhere(cutoffIso: string): string {
  return ` WHERE store = 'auditEvents'`
    + ` AND json_extract(CASE WHEN json_valid(data) THEN data ELSE '{}' END, '$.timestamp') < ${sqlLiteral(cutoffIso)}`
}

/** The page SELECT: ids of auditEvents rows strictly older than the
 *  cutoff, in rowid order. */
export function remotePageSelectSql(cutoffIso: string, limit: number): string {
  return `SELECT id FROM entities${olderThanWhere(cutoffIso)} ORDER BY rowid LIMIT ${limit}`
}

/** The dry-run's count: the same predicate, counted (no paging —
 *  without the deletes the pages would never advance). */
export function remotePurgeableCountSql(cutoffIso: string): string {
  return `SELECT COUNT(*) AS n FROM entities${olderThanWhere(cutoffIso)}`
}

/** The page DELETE: exactly the selected ids (the delete never widens
 *  past the page the read reported — an event written between the
 *  SELECT and the DELETE is never touched). */
export function remotePageDeleteSql(ids: string[]): string {
  return `DELETE FROM entities WHERE store = 'auditEvents' AND id IN (${ids.map(sqlLiteral).join(', ')})`
}

/** One `wrangler d1 execute --remote` round trip: answers its parsed
 *  result set (SELECT) or its changes count (DELETE). */
function d1Execute(d1Name: string, command: string): { results: Array<Record<string, unknown>>; changes: number } {
  const run = spawnSync('npx', ['wrangler', 'd1', 'execute', d1Name, '--remote', '--json', '--command', command], {
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
  })
  if (run.status !== 0) {
    throw new Error(`wrangler d1 execute failed: ${(run.stderr || run.stdout || '').slice(0, 400)}`)
  }
  const parsed = JSON.parse(run.stdout) as Array<{ results?: Array<Record<string, unknown>>; meta?: { changes?: number } }>
  return { results: parsed[0]?.results ?? [], changes: Number(parsed[0]?.meta?.changes ?? 0) }
}

/** The remote posture's whole run: page through the purgeable rows,
 *  deleting page by page. Every wrangler call is spawnSync — the pages
 *  and their deletes are serial by construction (the writes doctrine).
 *  The dry-run counts the same predicate once instead of paging: the
 *  pages advance only because each one's deletes land. */
async function runRemoteRetention(
  d1Name: string,
  env: { AUDIT_RETENTION_DAYS?: string },
  opts: { apply: boolean; now?: Date },
): Promise<AuditRetentionRun> {
  const retentionDays = parseAuditRetentionDays(env.AUDIT_RETENTION_DAYS)
  if (retentionDays === null) return { status: 'disabled' }
  const cutoffIso = auditCutoffIso(opts.now ?? new Date(), retentionDays)
  const scanned = Number(
    d1Execute(d1Name, `SELECT COUNT(*) AS n FROM entities WHERE store = 'auditEvents'`).results[0]?.n ?? 0,
  )
  if (!opts.apply) {
    const purgeableCount = Number(d1Execute(d1Name, remotePurgeableCountSql(cutoffIso)).results[0]?.n ?? 0)
    return {
      status: 'dry-run',
      report: { retentionDays, cutoffIso, scanned, purgeable: purgeableCount, purged: 0, kept: scanned - purgeableCount },
    }
  }
  let purgeable = 0
  let purged = 0
  while (true) {
    const ids = d1Execute(d1Name, remotePageSelectSql(cutoffIso, REMOTE_PAGE_SIZE))
      .results.map(r => String(r.id)).filter(Boolean)
    purgeable += ids.length
    purged += d1Execute(d1Name, remotePageDeleteSql(ids)).changes
    if (ids.length < REMOTE_PAGE_SIZE) break
  }
  return {
    status: 'applied',
    report: { retentionDays, cutoffIso, scanned, purgeable, purged, kept: scanned - purgeable },
  }
}

// ── the CLI ──────────────────────────────────────────────────────────

async function main(): Promise<void> {
  const args = process.argv.slice(2)
  const flag = (name: string): string | undefined => {
    const i = args.indexOf(`--${name}`)
    return i >= 0 ? args[i + 1] : undefined
  }
  const dbPath = flag('db')
  const d1Name = flag('d1') ?? DEFAULT_D1
  const remote = args.includes('--remote') || !dbPath
  const apply = args.includes('--apply')

  const now = new Date()
  let run: AuditRetentionRun
  let source: string
  if (remote) {
    run = await runRemoteRetention(d1Name, process.env, { apply, now })
    source = `the live D1 \`${d1Name}\` (wrangler --remote)`
  } else {
    // The local posture: the REAL store seam over the named SQLite
    // file. DATABASE_PATH binds at the store module's evaluation — set
    // before the dynamic import (the import-org-registry pattern).
    process.env.DATABASE_PATH = resolve(dbPath!)
    const { installSqliteStore } = await import('../server/store/sqlite')
    const store = installSqliteStore()
    run = await runLocalRetention(store, process.env, { apply, now })
    source = `the local registry \`${dbPath}\``
  }
  process.stdout.write(printRetentionRun(run, source, now))
}

const isMain = process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))
if (isMain) {
  main().catch(e => {
    console.error(`op-audit-retention failed: ${e instanceof Error ? e.message : String(e)}`)
    process.exit(1)
  })
}
