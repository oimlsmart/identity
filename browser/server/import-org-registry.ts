// ═══════════════════════════════════════════════════════════════════
// The production participant bootstrap's importer
// (TODO.identity-features/10, consequence 5): the authoritative OIML
// directory (data/org-registry.bootstrap.yaml — 63 member states, 66
// corresponding members, 14 issuing authorities, 32 test-laboratory
// associations, 31 utilizers, 11 associates, fetched from oiml.org
// 2026-08-29) onto the organization registry on the corrected member
// model.
//
// THE HONEST WRITE PATH: the importer drives the SERVER'S OWN
// validation — every row passes validateOrgLinks (the designation-link
// kind enforcement, auth/org-registry.ts) against the PROJECTED
// registry (the live rows + the plan's earlier rows), so a wrong-kind
// or dangling designation refuses exactly as the console's add act
// would. The writes ride the store seam (createOrgRegistryOrg /
// updateOrgRegistryOrg), never raw SQL — the remote apply emits the
// SQL equivalent of the plan (planToSql) for `wrangler d1 execute`,
// and the unit legs prove the two paths land the same rows.
//
// THE SEMANTICS:
//   - UPSERT, keyed on the stable slug id: a missing row is created;
//     an existing row is patched on the dataset-managed fields only
//     (name, short_name, kind, country, participant_ref, the
//     designation links, cs_status) — CONTACTS ARE NEVER TOUCHED on an
//     update (the dataset carries none — oiml.org gates them behind a
//     login — and the administrator's curated contacts are their own
//     act, never the import's to wipe);
//   - the LIFECYCLE is the administrator's: a dataset row lands ACTIVE
//     on create; an existing DISABLED row stays disabled (reported,
//     never silently resurrected);
//   - rows ABSENT from the dataset are left alone (the bootstrap never
//     deletes — a removal is the administrator's deliberate act);
//   - DRY-RUN is the same plan without the writes (planOrgRegistryBootstrap
//     never writes; applyOrgRegistryPlan executes a validated plan).
//
// The rows apply in dependency order (the designator before the
// designated), so a fresh registry validates link-by-link exactly like
// the hand-driven console flow.
//
// WORKER-SAFE: the store seam + js-yaml only, no node built-ins.
// ═══════════════════════════════════════════════════════════════════

import { load as parseYaml } from 'js-yaml'
import type { ServerStore } from '@oimlsmart/platform-server/store'
import { isRegistryOrgKind, validateOrgLinks, type RegistryOrgKind } from './auth/org-registry'

// ── the dataset shape ────────────────────────────────────────────────

/** One bootstrap row (the YAML's per-collection entries, flattened).
 *  `provenance` documents the source (never projected into the
 *  registry row — the registry has no field for it; the dataset file
 *  is its home). */
export interface BootstrapOrgRow {
  id: string
  kind: RegistryOrgKind
  name: string
  shortName: string | null
  country: string | null
  participantRef: string | null
  designatedBy: string | null
  proposedBy: string | null
  csStatus: string | null
  provenance: { source: string | null; detail: string | null; note: string | null }
}

export interface BootstrapDataset {
  rows: BootstrapOrgRow[]
}

/** The stable slug's shape (the add route's own rule, routes/
 *  op-registry.ts): letters, digits, dot/dash/underscore, starting
 *  with a letter or digit — the participant org's OIML code rides it. */
const ORG_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/

/** Parse + validate the bootstrap dataset (a YAML document or the
 *  parsed object). Throws honestly on a malformed document — a
 *  misdeclared bootstrap must fail the import, never guess. The four
 *  collections mirror the demonstration snapshot's layout: `members`
 *  (the OIML Member category), `organizations` (IAs + TLs),
 *  `utilizers`, `associates`. */
export function parseBootstrapDataset(source: string | Record<string, unknown>): BootstrapDataset {
  const doc = typeof source === 'string' ? (parseYaml(source) as Record<string, unknown>) : source
  if (!doc || typeof doc !== 'object') throw new Error('the bootstrap dataset must be a YAML mapping of collections')
  const rows: BootstrapOrgRow[] = []
  const seen = new Set<string>()
  // The collections and the kinds each carries: the members collection
  // is the OIML Member category only, organizations the IAs + their
  // TLs, the utilizers/associates their fixed designated-body kind.
  const collections: Array<[string, string | null, ReadonlySet<string>]> = [
    ['members', null, new Set(['member-state', 'corresponding-member'])],
    ['organizations', null, new Set(['issuing-authority', 'test-laboratory'])],
    ['utilizers', 'utilizer', new Set(['utilizer'])],
    ['associates', 'associate', new Set(['associate'])],
  ]
  for (const [collection, fixedKind, admitted] of collections) {
    const list = doc[collection]
    if (list === undefined) continue
    if (!Array.isArray(list)) throw new Error(`the bootstrap dataset's '${collection}' must be a list`)
    for (const [i, raw] of list.entries()) {
      const rec = raw as Record<string, unknown>
      const at = `${collection}[${i}]`
      if (!rec || typeof rec !== 'object') throw new Error(`${at}: a row must be a mapping`)
      const id = typeof rec.id === 'string' || typeof rec.id === 'number' ? String(rec.id) : ''
      if (!ORG_ID_PATTERN.test(id)) throw new Error(`${at}: the id '${id || '(missing)'}' is not the stable slug shape (letters, digits, dot/dash/underscore)`)
      if (seen.has(id)) throw new Error(`${at}: duplicate id '${id}'`)
      seen.add(id)
      if (typeof rec.name !== 'string' || !rec.name.trim()) throw new Error(`${at} (${id}): name is required`)
      const kind = fixedKind ?? rec.kind
      if (!isRegistryOrgKind(kind)) throw new Error(`${at} (${id}): kind must be one of the registry kinds (member-state, corresponding-member, issuing-authority, test-laboratory, utilizer, associate, manufacturer)`)
      if (fixedKind && typeof rec.kind === 'string' && rec.kind !== fixedKind) {
        throw new Error(`${at} (${id}): the '${collection}' collection carries the ${fixedKind} kind only`)
      }
      if (!admitted.has(kind)) {
        throw new Error(`${at} (${id}): the '${collection}' collection carries ${[...admitted].join(' / ')} rows only — a ${kind} row never lands there`)
      }
      const str = (key: string): string | null => {
        const v = rec[key]
        if (v === undefined || v === null) return null
        if (typeof v !== 'string') throw new Error(`${at} (${id}): ${key} must be a string`)
        return v
      }
      const prov = (rec.provenance ?? {}) as Record<string, unknown>
      rows.push({
        id,
        kind,
        name: rec.name.trim(),
        shortName: str('short_name'),
        country: str('country'),
        participantRef: str('participant_ref'),
        designatedBy: str('designated_by'),
        proposedBy: str('proposed_by'),
        csStatus: str('cs_status'),
        provenance: {
          source: typeof prov.source === 'string' ? prov.source : null,
          detail: typeof prov.detail === 'string' ? prov.detail : null,
          note: typeof prov.note === 'string' ? prov.note : null,
        },
      })
    }
  }
  if (!rows.length) throw new Error('the bootstrap dataset carries no rows')
  return { rows }
}

// ── the plan ─────────────────────────────────────────────────────────

export interface BootstrapAction {
  id: string
  kind: RegistryOrgKind
  action: 'create' | 'update' | 'unchanged'
  /** The differing dataset-managed fields (the update act's patch). */
  changes: string[]
  /** The honesty notes (a disabled row's lifecycle stands, …). */
  notes: string[]
  row: BootstrapOrgRow
}

export interface BootstrapPlan {
  actions: BootstrapAction[]
  /** The validation refusals — a non-empty list FAILS the apply. */
  errors: string[]
  counts: { create: number; update: number; unchanged: number }
}

/** The dataset-managed fields (contacts deliberately EXCLUDED — see the
 *  header). The desired value of each, as the store row projects it. */
function managedFields(row: BootstrapOrgRow): Record<string, string | null> {
  return {
    name: row.name,
    shortName: row.shortName,
    kind: row.kind,
    country: row.country,
    participantRef: row.participantRef,
    designatedBy: row.designatedBy,
    proposedBy: row.proposedBy,
    csStatus: row.csStatus,
  }
}

/** The dependency order: a designator/proposer lands before its
 *  designated/proposed rows, so the projected registry validates each
 *  link against an already-present target (the console's own flow).
 *  A designation cycle is a data error and throws. */
function dependencyOrder(rows: BootstrapOrgRow[]): BootstrapOrgRow[] {
  const byId = new Map(rows.map(r => [r.id, r]))
  const depthOf = (row: BootstrapOrgRow, seen: Set<string>): number => {
    if (seen.has(row.id)) throw new Error(`a designation cycle reaches '${row.id}' — the chain never loops`)
    const target = row.designatedBy ?? row.proposedBy
    if (!target) return 0
    const t = byId.get(target)
    if (!t) return 0 // the dangling target is validateOrgLinks' refusal, not the ordering's
    return 1 + depthOf(t, new Set([...seen, row.id]))
  }
  return [...rows].sort((a, b) => depthOf(a, new Set()) - depthOf(b, new Set()) || a.id.localeCompare(b.id))
}

/** Plan the bootstrap against the current registry. READS the store,
 *  NEVER writes: the projected registry (the live rows + the plan's
 *  earlier rows) feeds validateOrgLinks — the server's own write-path
 *  validation — per row. The plan is the apply's whole truth. */
export async function planOrgRegistryBootstrap(store: ServerStore, dataset: BootstrapDataset): Promise<BootstrapPlan> {
  // The projected registry: the live rows, then each planned row as it
  // lands. validateOrgLinks reads through this facade (its only store
  // touch is getOrgRegistryOrg).
  const projected = new Map<string, { id: string; kind: string | null; state: 'active' | 'disabled' }>()
  for (const row of await store.listOrgRegistryOrgs()) projected.set(row.id, { id: row.id, kind: row.kind, state: row.state })
  const facade = {
    getOrgRegistryOrg: async (id: string) => {
      const row = projected.get(id)
      return row ? { ...row } as never : null
    },
  } as unknown as ServerStore

  const actions: BootstrapAction[] = []
  const errors: string[] = []
  for (const row of dependencyOrder(dataset.rows)) {
    // The server's own validation over the merged envelope.
    const refusal = await validateOrgLinks(facade, {
      kind: row.kind,
      designatedBy: row.designatedBy,
      proposedBy: row.proposedBy,
      csStatus: row.csStatus,
    })
    if (refusal) errors.push(`${row.id}: ${refusal}`)

    const existing = await store.getOrgRegistryOrg(row.id)
    const desired = managedFields(row)
    if (!existing) {
      actions.push({ id: row.id, kind: row.kind, action: 'create', changes: [], notes: [], row })
      projected.set(row.id, { id: row.id, kind: row.kind, state: 'active' })
      continue
    }
    const changes = Object.keys(desired).filter(key => {
      const want = desired[key]!
      const have = (existing as unknown as Record<string, unknown>)[key] ?? null
      return want !== have
    })
    const notes: string[] = []
    if (existing.state === 'disabled') {
      notes.push('the live row is DISABLED — the import patches the data but leaves the lifecycle (the administrator’s disable is a deliberate act; re-enable is theirs)')
    } else {
      // The projected registry sees the patched row's kind/state.
      projected.set(row.id, { id: row.id, kind: row.kind, state: 'active' })
    }
    if (existing.contacts.length) notes.push('the curated contacts stay (the import never touches contacts)')
    actions.push({ id: row.id, kind: row.kind, action: changes.length ? 'update' : 'unchanged', changes, notes, row })
  }
  return {
    actions,
    errors,
    counts: {
      create: actions.filter(a => a.action === 'create').length,
      update: actions.filter(a => a.action === 'update').length,
      unchanged: actions.filter(a => a.action === 'unchanged').length,
    },
  }
}

// ── the apply ────────────────────────────────────────────────────────

export const BOOTSTRAP_ACTOR = 'the participant bootstrap (TODO.identity-features/10)'

/** Execute a validated plan through the store seam. REFUSES to run on
 *  a plan with validation errors — the dry-run is the review, the
 *  apply never overrides it. Answers the applied counts. */
export async function applyOrgRegistryPlan(
  store: ServerStore,
  plan: BootstrapPlan,
  actor: string = BOOTSTRAP_ACTOR,
): Promise<{ created: number; updated: number; unchanged: number }> {
  if (plan.errors.length) {
    throw new Error(`the bootstrap plan carries ${plan.errors.length} validation refusal(s) — fix the dataset, never force the write:\n  ${plan.errors.join('\n  ')}`)
  }
  let created = 0
  let updated = 0
  let unchanged = 0
  for (const action of plan.actions) {
    if (action.action === 'unchanged') { unchanged += 1; continue }
    const row = action.row
    if (action.action === 'create') {
      const landed = await store.createOrgRegistryOrg({
        id: row.id,
        name: row.name,
        shortName: row.shortName,
        kind: row.kind,
        country: row.country,
        contacts: [],
        participantRef: row.participantRef,
        designatedBy: row.designatedBy,
        proposedBy: row.proposedBy,
        csStatus: row.csStatus,
        createdBy: actor,
      })
      if (!landed) throw new Error(`the create of '${row.id}' hit the id conflict the plan did not see — the registry moved under the import; re-plan`)
      created += 1
      continue
    }
    // The update: the differing dataset-managed fields only. The store's
    // patch semantics apply exactly the named fields (contacts excluded).
    const patch: Record<string, string | null> = {}
    const desired = managedFields(row)
    for (const key of action.changes) patch[key] = desired[key]!
    const landed = await store.updateOrgRegistryOrg(row.id, patch, actor)
    if (!landed) throw new Error(`the update of '${row.id}' found no row — the registry moved under the import; re-plan`)
    updated += 1
  }
  return { created, updated, unchanged }
}

// ── the remote apply's SQL (the wrangler D1 path) ────────────────────
// The production D1 is written by `wrangler d1 execute --file` (the
// operator's deliberate act — the runbook's commands). The statements
// mirror the kernel store's own SQL (INSERT OR IGNORE on create; the
// patch UPDATE with updated_at/updated_by stamps on update), so the
// remote apply lands EXACTLY what the store-seam apply lands — the
// unit legs prove the equivalence over two scratch databases.

/** The SQL literal (the '' escape — the only rule SQLite needs). */
function sqlString(value: string | null): string {
  return value === null ? 'NULL' : `'${value.replace(/'/g, "''")}'`
}

/** The plan as SQL statements (the actions in order; the unchanged rows
 *  emit nothing). The statements are the kernel's own shapes:
 *  createOrgRegistryOrg's INSERT OR IGNORE and updateOrgRegistryOrg's
 *  stamped patch UPDATE. */
export function planToSql(plan: BootstrapPlan, actor: string = BOOTSTRAP_ACTOR): string[] {
  if (plan.errors.length) {
    throw new Error(`the bootstrap plan carries ${plan.errors.length} validation refusal(s) — the SQL is never emitted from a refusing plan`)
  }
  const statements: string[] = []
  for (const action of plan.actions) {
    if (action.action === 'unchanged') continue
    const row = action.row
    if (action.action === 'create') {
      statements.push(
        'INSERT OR IGNORE INTO org_registry (id, name, short_name, kind, country, contacts, participant_ref, designated_by, proposed_by, cs_status, created_by) VALUES ('
        + [sqlString(row.id), sqlString(row.name), sqlString(row.shortName), sqlString(row.kind), sqlString(row.country),
           sqlString('[]'), sqlString(row.participantRef), sqlString(row.designatedBy), sqlString(row.proposedBy), sqlString(row.csStatus), sqlString(actor)].join(', ')
        + ');',
      )
      continue
    }
    const columns: Record<string, string> = {
      name: 'name', shortName: 'short_name', kind: 'kind', country: 'country',
      participantRef: 'participant_ref', designatedBy: 'designated_by', proposedBy: 'proposed_by', csStatus: 'cs_status',
    }
    const desired = managedFields(row)
    const sets = action.changes.map(key => `${columns[key]!} = ${sqlString(desired[key]!)}`)
    sets.push("updated_at = datetime('now')", `updated_by = ${sqlString(actor)}`)
    statements.push(`UPDATE org_registry SET ${sets.join(', ')} WHERE id = ${sqlString(row.id)};`)
  }
  return statements
}
