// ─────────────────────────────────────────────────────────────────────
// import-org-registry.ts — the production participant bootstrap's CLI
// (TODO.identity-features/10, consequence 5): applies the authoritative
// OIML directory (browser/data/org-registry.bootstrap.yaml) to the
// organization registry through the importer (server/
// import-org-registry.ts — the server's own validateOrgLinks over the
// projected registry, upsert semantics, dependency-ordered).
//
// Postures (the repo's ops-script convention, op-access-review.ts):
//   --db <path>         a local/scratch SQLite file (the rehearsal +
//                       the unit legs' posture). DRY-RUN by default;
//                       --execute applies through the store seam.
//   --remote [--d1 <n>] the live D1 (default oiml-smart-platform-identity):
//                       READS the current org_registry through wrangler,
//                       plans against it, prints the plan, and emits the
//                       apply SQL to --emit-sql (default
//                       browser/.cache/org-registry.bootstrap.sql).
//                       NEVER writes the live database — the write is the
//                       operator's deliberate act (the runbook's wrangler
//                       command, docs/deployment/identity-operations.md).
//   --dataset <path>    the dataset (default browser/data/org-registry.bootstrap.yaml).
//
// Usage (from browser/):
//   npx tsx scripts/import-org-registry.ts --db .cache/bootstrap-proof/identity.db
//   npx tsx scripts/import-org-registry.ts --db .cache/bootstrap-proof/identity.db --execute
//   npx tsx scripts/import-org-registry.ts --remote
// ─────────────────────────────────────────────────────────────────────

import { readFileSync, writeFileSync, mkdirSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { spawnSync } from 'node:child_process'
import type { ServerStore } from '@oimlsmart/platform-server/store'
import {
  applyOrgRegistryPlan,
  parseBootstrapDataset,
  planOrgRegistryBootstrap,
  planToSql,
  type BootstrapPlan,
} from '../server/import-org-registry'

const DEFAULT_D1 = 'oiml-smart-platform-identity'
const DEFAULT_DATASET = resolve(dirname(fileURLToPath(import.meta.url)), '..', 'data', 'org-registry.bootstrap.yaml')
const DEFAULT_SQL_OUT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '.cache', 'org-registry.bootstrap.sql')

// ── the live-D1 read (the planning input) ────────────────────────────
// The org_registry rows as the store projects them. The planner only
// reads (listOrgRegistryOrgs / getOrgRegistryOrg); the facade below
// answers exactly that slice over the wrangler query's results.

interface OrgRegistryDbRow {
  id: string; name: string; short_name: string | null; kind: string | null
  country: string | null; contacts: string | null; participant_ref: string | null
  designated_by: string | null; proposed_by: string | null; cs_status: string | null
  state: 'active' | 'disabled'
  created_at: string; created_by: string | null; updated_at: string | null; updated_by: string | null
  disabled_at: string | null; disabled_by: string | null
}

/** Read the live org_registry through wrangler (the operator's
 *  CLOUDFLARE_* credentials ride the environment; the secret-free read
 *  path, same as op-access-review.ts). */
export function readRemoteOrgRegistry(d1Name: string): OrgRegistryDbRow[] {
  const run = spawnSync('npx', ['wrangler', 'd1', 'execute', d1Name, '--remote', '--json', '--command',
    'SELECT id, name, short_name, kind, country, contacts, participant_ref, designated_by, proposed_by, cs_status, state, created_at, created_by, updated_at, updated_by, disabled_at, disabled_by FROM org_registry'], {
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
  })
  if (run.status !== 0) {
    throw new Error(`wrangler d1 execute failed: ${(run.stderr || run.stdout || '').slice(0, 400)}`)
  }
  const parsed = JSON.parse(run.stdout) as Array<{ results?: OrgRegistryDbRow[] }>
  return parsed[0]?.results ?? []
}

/** The planning facade over the read rows: the planner's whole store
 *  surface is listOrgRegistryOrgs + getOrgRegistryOrg (its validation
 *  facade is its own); every other method throws honestly if reached. */
function facadeOverRows(rows: OrgRegistryDbRow[]): ServerStore {
  const parseContacts = (json: string | null): Array<{ name: string | null; email: string }> => {
    try {
      const parsed = json ? JSON.parse(json) : []
      return Array.isArray(parsed) ? parsed : []
    } catch { return [] }
  }
  const projected = rows.map(r => ({
    id: r.id, name: r.name, shortName: r.short_name, kind: r.kind, country: r.country,
    contacts: parseContacts(r.contacts), participantRef: r.participant_ref,
    designatedBy: r.designated_by ?? null, proposedBy: r.proposed_by ?? null, csStatus: r.cs_status ?? null,
    state: r.state, createdAt: r.created_at, createdBy: r.created_by,
    updatedAt: r.updated_at, updatedBy: r.updated_by, disabledAt: r.disabled_at, disabledBy: r.disabled_by,
  }))
  return {
    listOrgRegistryOrgs: async () => projected,
    getOrgRegistryOrg: async (id: string) => projected.find(r => r.id === id) ?? null,
  } as unknown as ServerStore
}

// ── the report ───────────────────────────────────────────────────────

function printPlan(plan: BootstrapPlan, source: string): void {
  const out: string[] = []
  out.push(`Participant bootstrap plan — against ${source}`)
  out.push(`  actions: ${plan.counts.create} create, ${plan.counts.update} update, ${plan.counts.unchanged} unchanged`)
  const byKind = new Map<string, { create: number; update: number; unchanged: number }>()
  for (const a of plan.actions) {
    const k = byKind.get(a.kind) ?? { create: 0, update: 0, unchanged: 0 }
    k[a.action] += 1
    byKind.set(a.kind, k)
  }
  for (const [kind, k] of [...byKind.entries()].sort()) {
    out.push(`    ${kind}: ${k.create} create / ${k.update} update / ${k.unchanged} unchanged`)
  }
  const noted = plan.actions.filter(a => a.notes.length || (a.action === 'update' && a.changes.length))
  if (noted.length) {
    out.push('  the rows the review should see:')
    for (const a of noted.slice(0, 40)) {
      out.push(`    ${a.id}: ${a.action}${a.changes.length ? ` (${a.changes.join(', ')})` : ''}${a.notes.length ? ` — ${a.notes.join('; ')}` : ''}`)
    }
    if (noted.length > 40) out.push(`    … and ${noted.length - 40} more`)
  }
  if (plan.errors.length) {
    out.push(`  VALIDATION REFUSALS (${plan.errors.length}) — the plan is not applicable:`)
    for (const e of plan.errors) out.push(`    ${e}`)
  }
  process.stdout.write(out.join('\n') + '\n')
}

// ── the CLI ──────────────────────────────────────────────────────────

async function main(): Promise<void> {
  const args = process.argv.slice(2)
  const flag = (name: string): string | undefined => {
    const i = args.indexOf(`--${name}`)
    return i >= 0 ? args[i + 1] : undefined
  }
  const dbPath = flag('db')
  const remote = args.includes('--remote')
  const execute = args.includes('--execute')
  const d1Name = flag('d1') ?? DEFAULT_D1
  const datasetPath = resolve(flag('dataset') ?? DEFAULT_DATASET)
  const emitSql = flag('emit-sql') === undefined ? DEFAULT_SQL_OUT : resolve(flag('emit-sql')!)

  if (!dbPath && !remote) {
    process.stderr.write('usage: import-org-registry.ts [--dataset <path>] (--db <path> [--execute] | --remote [--d1 <name>]) [--emit-sql <path>]\n')
    process.exit(2)
  }

  const dataset = parseBootstrapDataset(readFileSync(datasetPath, 'utf-8'))
  process.stdout.write(`dataset: ${datasetPath} — ${dataset.rows.length} rows\n`)

  if (dbPath) {
    // The local/scratch posture: the REAL store seam over the named
    // SQLite file. DATABASE_PATH binds at the store module's evaluation
    // — set before the dynamic import.
    process.env.DATABASE_PATH = resolve(dbPath)
    const { installSqliteStore } = await import('@oimlsmart/platform-server/store/sqlite')
    const store = installSqliteStore()
    const plan = await planOrgRegistryBootstrap(store, dataset)
    printPlan(plan, `the local registry ${dbPath}`)
    if (!execute) {
      process.stdout.write('dry-run — no writes (re-run with --execute to apply through the store seam).\n')
      process.exit(plan.errors.length ? 1 : 0)
    }
    const applied = await applyOrgRegistryPlan(store, plan)
    process.stdout.write(`applied: ${applied.created} created, ${applied.updated} updated, ${applied.unchanged} unchanged.\n`)
    process.exit(0)
  }

  // The remote posture: read the live registry, plan, emit the SQL —
  // never write (the runbook's wrangler command is the deliberate act).
  const rows = readRemoteOrgRegistry(d1Name)
  process.stdout.write(`remote: ${rows.length} org_registry rows on ${d1Name} (the planning input)\n`)
  const plan = await planOrgRegistryBootstrap(facadeOverRows(rows), dataset)
  printPlan(plan, `the live D1 ${d1Name}`)
  if (plan.errors.length) process.exit(1)
  const statements = planToSql(plan)
  mkdirSync(dirname(emitSql), { recursive: true })
  writeFileSync(emitSql, statements.join('\n') + '\n')
  process.stdout.write(`the apply SQL (${statements.length} statements) → ${emitSql}\n`)
  process.stdout.write(`NOTHING was written to the live database. The apply is the operator's act:\n`)
  process.stdout.write(`  npx wrangler d1 execute ${d1Name} --remote --config wrangler.toml --env identity --file ${emitSql}\n`)
}

main().catch(e => {
  process.stderr.write(`import-org-registry failed: ${e instanceof Error ? e.message : String(e)}\n`)
  process.exit(1)
})
