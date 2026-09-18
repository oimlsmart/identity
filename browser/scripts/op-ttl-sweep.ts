// ─────────────────────────────────────────────────────────────────────
// op-ttl-sweep.ts — the TTL tables' expired-row sweep (the 2026-09-18
// improvement wave, item 2 — retention part 2; the doctrine lives in
// server/store.ts's TTL_TABLES). An expired session, code, token, or
// one-time challenge is DEAD BY DEFINITION; one never presented again
// (the abandoned-flow common case) otherwise lingers forever. This is
// HYGIENE, not policy: unlike the audit journal's owner-set window,
// expiry is already declared by every row itself — the sweep needs no
// configuration and ships ungated.
//
// Postures (the repo's ops-script convention, op-audit-retention.ts):
//   --remote (default)  the live D1 through `wrangler d1 execute
//                       --remote` (the D1 name overridable with --d1),
//                       the same rowid-IN paged DELETE the store verb
//                       runs, paged per table.
//   --db <path>         a local SQLite file through the STORE SEAM —
//                       the rehearsal + unit-leg posture
//                       (store.purgeExpiredTtlRows itself).
//
// Both postures are DRY-RUN by default; --apply performs the deletes.
// Writes stay serial (the store doctrine, verbatim). Output: counts
// only on stdout (the public-job-log discipline).
//
// Usage (from browser/):
//   npx tsx scripts/op-ttl-sweep.ts --remote            (dry-run)
//   npx tsx scripts/op-ttl-sweep.ts --remote --apply
//   npx tsx scripts/op-ttl-sweep.ts --db .cache/id-01/identity.db --apply
// ─────────────────────────────────────────────────────────────────────

import { spawnSync } from 'node:child_process'
import { TTL_TABLES, type ServerStore } from '../server/store'

const DEFAULT_D1 = 'oiml-smart-platform-identity'
const PAGE = 500

/** One `wrangler d1 execute --remote` round trip. */
function d1(d1Name: string, command: string): Array<Record<string, unknown>> {
  const run = spawnSync('npx', ['wrangler', 'd1', 'execute', d1Name, '--remote', '--json', '--command', command], {
    encoding: 'utf8', cwd: new URL('..', import.meta.url).pathname,
  })
  if (run.status !== 0) {
    throw new Error(`wrangler d1 execute failed: ${(run.stderr || run.stdout || '').slice(0, 400)}`)
  }
  try {
    return (JSON.parse(run.stdout)[0] as { results: Array<Record<string, unknown>> }).results ?? []
  } catch {
    throw new Error(`wrangler d1 execute answered unparseable output: ${run.stdout.slice(0, 200)}`)
  }
}

/** The count of expired rows in one table (the dry-run's census and
 *  the loop's termination check — one SELECT per table per pass). */
function expiredCount(d1Name: string, table: string, cutoffIso: string): number {
  const rows = d1(d1Name, `SELECT COUNT(*) AS n FROM ${table} WHERE expires_at < '${cutoffIso}'`)
  return Number(rows[0]?.n ?? 0)
}

async function main(): Promise<void> {
  const args = process.argv.slice(2)
  const apply = args.includes('--apply')
  const dbFlag = args.indexOf('--db')
  const d1Flag = args.indexOf('--d1')
  const d1Name = d1Flag >= 0 ? args[d1Flag + 1] : DEFAULT_D1
  const cutoffIso = new Date().toISOString()

  const tally: Record<string, number> = {}
  const report = (prefix: string): void => {
    const total = Object.values(tally).reduce((a, b) => a + b, 0)
    console.log(`${prefix} ${total} expired TTL row(s)${Object.entries(tally).filter(([, n]) => n > 0).map(([t, n]) => ` — ${t}: ${n}`).join('')}`)
  }

  if (dbFlag >= 0) {
    process.env.DATABASE_PATH = args[dbFlag + 1]!
    const { installSqliteStore } = await import('../server/store/sqlite')
    const store: ServerStore = installSqliteStore()
    if (!apply) {
      // The census rides the same verb at limit 0? No — the SELECT
      // would be the verb's DELETE; the dry-run counts via one verb
      // pass at limit 0 is meaningless. Use the local count directly.
      for (const table of TTL_TABLES) {
        const n = (store as unknown as { db: import('better-sqlite3').Database }).db
          .prepare(`SELECT COUNT(*) AS n FROM ${table} WHERE expires_at < ?`).get(cutoffIso) as { n: number }
        tally[table] = n.n
      }
      report('would purge')
      return
    }
    let swept = true
    while (swept) {
      swept = false
      const counts = await store.purgeExpiredTtlRows(cutoffIso, PAGE)
      for (const [table, n] of Object.entries(counts)) {
        tally[table] = (tally[table] ?? 0) + n
        if (n > 0) swept = true
      }
    }
    report('purged')
    return
  }

  for (const table of TTL_TABLES) {
    let n = expiredCount(d1Name, table, cutoffIso)
    if (!apply) {
      tally[table] = n
      continue
    }
    let done = 0
    while (n > 0) {
      d1(d1Name, `DELETE FROM ${table} WHERE rowid IN (SELECT rowid FROM ${table} WHERE expires_at < '${cutoffIso}' LIMIT ${PAGE})`)
      done += Math.min(n, PAGE)
      n = expiredCount(d1Name, table, cutoffIso)
    }
    tally[table] = done
  }
  report(apply ? 'purged' : 'would purge')
}

main().catch(err => {
  console.error(String(err))
  process.exit(1)
})
