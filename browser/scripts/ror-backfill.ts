// ─────────────────────────────────────────────────────────────────────
// ror-backfill.ts — the ROR enrichment's backfill CLI (TODO.sota/05's
// curation loop): sweeps the vendored member-domains artifact's ROR ids
// onto the EXISTING org_registry rows. The rows born of the
// self-registration materialization carry their id at birth; every row
// predating the enrichment (the bootstrap import, the production
// registry's 147) reaches its id through THIS plan. When the owner's
// GAPS curation lands upstream (member-domains#4) and the artifact
// re-vendors, the same run delivers the new ids.
//
// Postures (the repo's ops-script convention, import-org-registry.ts):
//   --db <path>         a local/scratch SQLite file. DRY-RUN by default;
//                       --execute applies through the store seam.
//   --remote [--d1 <n>] the live D1 (default oiml-smart-platform-identity):
//                       READS the current org_registry through wrangler,
//                       plans against it, prints the plan, and emits the
//                       apply SQL to --emit-sql. NEVER writes the live
//                       database — the write is the operator's deliberate
//                       act (docs/deployment/identity-operations.md).
//
// Usage (from browser/):
//   npx tsx scripts/ror-backfill.ts --db .cache/bootstrap-proof/identity.db
//   npx tsx scripts/ror-backfill.ts --db .cache/bootstrap-proof/identity.db --execute
//   npx tsx scripts/ror-backfill.ts --remote
// ─────────────────────────────────────────────────────────────────────

import { writeFileSync, mkdirSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { spawnSync } from 'node:child_process'
import { loadDomains } from '../server/auth/op/member-domains'
import { actionToSql, planRorBackfill } from '../server/ror-backfill'

const DEFAULT_D1 = 'oiml-smart-platform-identity'
const DEFAULT_SQL_OUT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '.cache', 'ror-backfill.sql')
const ACTOR = 'ror-backfill'

interface Row {
  id: string
  name: string
  country: string | null
  ror_id: string | null
}

/** Read the live org_registry through wrangler (the operator's
 *  CLOUDFLARE_* credentials ride the environment — the secret-free read
 *  path, same as import-org-registry.ts). */
function readRemoteRows(d1Name: string): Row[] {
  const run = spawnSync('npx', ['wrangler', 'd1', 'execute', d1Name, '--remote', '--json', '--command',
    'SELECT id, name, country, ror_id FROM org_registry'], {
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
  })
  if (run.status !== 0) {
    throw new Error(`wrangler d1 execute failed: ${(run.stderr || run.stdout || '').slice(0, 400)}`)
  }
  const parsed = JSON.parse(run.stdout) as Array<{ results?: Row[] }>
  return parsed[0]?.results ?? []
}

function printPlan(plan: ReturnType<typeof planRorBackfill>, source: string): void {
  const out: string[] = []
  out.push(`ROR backfill plan — against ${source}`)
  out.push(`  actions: ${plan.actions.length}, unchanged: ${plan.unchanged}, unmatched: ${plan.unmatched.length}`)
  for (const a of plan.actions) {
    out.push(`    ${a.id}: ${a.from ?? '∅'} → ${a.to} (${a.basis})`)
  }
  if (plan.unmatched.length) {
    out.push('  unmatched (reported, never touched):')
    for (const id of plan.unmatched) out.push(`    ${id}`)
  }
  process.stdout.write(out.join('\n') + '\n')
}

async function main(): Promise<void> {
  const args = process.argv.slice(2)
  const remote = args.includes('--remote')
  const execute = args.includes('--execute')
  const emitIdx = args.indexOf('--emit-sql')
  const emitPath = emitIdx >= 0 ? args[emitIdx + 1]! : DEFAULT_SQL_OUT
  const dbIdx = args.indexOf('--db')
  const dbPath = dbIdx >= 0 ? args[dbIdx + 1]! : undefined
  const d1Idx = args.indexOf('--d1')
  const d1Name = d1Idx >= 0 ? args[d1Idx + 1]! : DEFAULT_D1

  if (!remote && !dbPath) {
    process.stderr.write('usage: npx tsx scripts/ror-backfill.ts (--db <path> [--execute] | --remote [--d1 <name>] [--emit-sql <path>])\n')
    process.exit(2)
  }

  const catalog = loadDomains()
  if (remote) {
    const rows = readRemoteRows(d1Name)
    const plan = planRorBackfill(rows.map(r => ({ id: r.id, name: r.name, country: r.country, rorId: r.ror_id })), catalog)
    printPlan(plan, `the live D1 (${d1Name})`)
    if (!plan.actions.length) {
      process.stdout.write('nothing to apply — the registry\'s ids agree with the artifact\n')
      return
    }
    const sql = plan.actions.map(a => actionToSql(a, ACTOR)).join('\n') + '\n'
    mkdirSync(dirname(emitPath), { recursive: true })
    writeFileSync(emitPath, sql)
    process.stdout.write(`\nthe apply SQL (${plan.actions.length} statements) → ${emitPath}\n`)
    process.stdout.write('the live database is NEVER written by this script — review, then run it with `wrangler d1 execute --remote --file` (the deliberate act).\n')
    return
  }

  // The local posture: the REAL SQLite store over the scratch file.
  process.env.DATABASE_PATH = dbPath
  const { installSqliteStore } = await import('../server/store/sqlite')
  const store = installSqliteStore()
  const rows = await store.listOrgRegistryOrgs()
  const plan = planRorBackfill(rows.map(r => ({ id: r.id, name: r.name, country: r.country, rorId: r.rorId })), catalog)
  printPlan(plan, `the local store (${dbPath})`)
  if (!execute) {
    process.stdout.write('\ndry-run — pass --execute to apply through the store seam\n')
    return
  }
  let applied = 0
  for (const a of plan.actions) {
    const landed = await store.updateOrgRegistryOrg(a.id, { rorId: a.to }, ACTOR)
    if (landed) applied += 1
  }
  process.stdout.write(`\napplied ${applied}/${plan.actions.length} through the store seam\n`)
}

main().catch((e: unknown) => {
  process.stderr.write(`ror-backfill failed: ${e instanceof Error ? e.message : String(e)}\n`)
  process.exit(1)
})
