// ─────────────────────────────────────────────────────────────────────
// TODO.identity-features/10, consequence 5 — the production participant
// bootstrap, proven in-process: the REAL dataset (data/
// org-registry.bootstrap.yaml — the authoritative OIML directory,
// fetched 2026-08-29), the REAL importer (server/import-org-registry.ts)
// over a REAL temp SQLite store, and the REAL registry aggregates
// (routes/op-registry.ts) rendering the designation chains.
//
// Covered:
//   THE DATASET'S INTEGRITY — the pinned counts (63 member states + 66
//     corresponding members + 14 issuing authorities + 32
//     test-laboratory associations + 31 utilizers + 11 associates =
//     217 rows), unique slug ids, every designation link resolving to
//     the required kind WITHIN the dataset, the CS status riding the
//     designated bodies only, provenance on every row;
//   THE IMPORT — all 217 rows land ACTIVE with their links on a fresh
//     registry (the members first, the designations validating against
//     the projected registry — the server's own validateOrgLinks);
//   THE IDEMPOTENCY — the re-run's plan is 217 unchanged / 0 writes;
//   THE UPSERT — a drifted row re-converges (update on the managed
//     fields only), and the curated CONTACTS are never the import's;
//   THE HONEST REFUSALS — a wrong-kind designator fails the plan (never
//     the apply), and the apply refuses a refusing plan;
//   THE SQL PATH — planToSql's statements land the same rows as the
//     store-seam apply (the remote wrangler path's equivalence);
//   THE CHAIN RENDERING — the registry aggregates carry the real
//     directory's chains (ms-de proposes DE1 + designates ut-de; DE1
//     names its proposer + its six associated TLs).
// ─────────────────────────────────────────────────────────────────────

import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import Database from 'better-sqlite3'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

// The store's DB path binds at module evaluation — set before any import
// below touches @oimlsmart/platform-server/store/sqlite (all dynamic).
const TMP = mkdtempSync(join(tmpdir(), 'oiml-participant-bootstrap-'))
process.env.DATABASE_PATH = join(TMP, 'test.db')
process.env.OP_ISSUER = 'http://op.test'

const ORIGIN = 'http://op.test'
const DATASET_PATH = join(__dirname, '..', '..', 'data', 'org-registry.bootstrap.yaml')

let app: import('hono').Hono
let store: ReturnType<typeof import('@oimlsmart/platform-server/store').getStore>
let dataset: ReturnType<typeof import('../../server/import-org-registry').parseBootstrapDataset>
let admin: string

async function demoLogin(email: string): Promise<string> {
  const res = await app.request(`${ORIGIN}/api/auth/demo`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password: 'demo2026' }),
  })
  expect(res.ok, `demo login ${email}`).toBe(true)
  return res.headers.get('set-cookie')!.split(';')[0]!
}

async function json(res: Response, status: number): Promise<any> {
  expect(res.status, `${res.url} → ${status}`).toBe(status)
  return res.json()
}

beforeAll(async () => {
  const { installSqliteStore } = await import('@oimlsmart/platform-server/store/sqlite')
  store = installSqliteStore()
  const profileMod = await import('@oimlsmart/platform-server/profile')
  profileMod.installInstanceProfile(profileMod.parseInstanceProfile(`
identity:
  org_id: oimlsmart-id
  org_name: OIML SMART Identity
  role_codes: [identity]
roles: [identity]
branding: { name: OIML SMART Identity }
demo_personas: true
`))
  const { Hono } = await import('hono')
  const { createAuthLeanRouter } = await import('../../server/routes/auth-lean')
  const { createOpRegistryRouter } = await import('../../server/routes/op-registry')
  const root = new Hono()
  root.route('/api/auth', createAuthLeanRouter({ autoSeedDemo: true }))
  root.route('/', createOpRegistryRouter())
  app = root

  const { parseBootstrapDataset } = await import('../../server/import-org-registry')
  dataset = parseBootstrapDataset(readFileSync(DATASET_PATH, 'utf-8'))
  admin = await demoLogin('admin@oiml.org')
})

afterAll(async () => {
  const { resetInstanceProfileForTest } = await import('@oimlsmart/platform-server/profile')
  resetInstanceProfileForTest()
  rmSync(TMP, { recursive: true, force: true })
  delete process.env.DATABASE_PATH
  delete process.env.OP_ISSUER
})

// ── the dataset's integrity ──────────────────────────────────────────

describe('the dataset’s integrity', () => {
  it('carries the authoritative directory’s counts — 217 rows on the corrected member model', () => {
    const byKind = new Map<string, number>()
    for (const row of dataset.rows) byKind.set(row.kind, (byKind.get(row.kind) ?? 0) + 1)
    expect(Object.fromEntries(byKind)).toEqual({
      'member-state': 63,
      'corresponding-member': 66,
      'issuing-authority': 14,
      'test-laboratory': 32,
      'utilizer': 31,
      'associate': 11,
    })
    expect(dataset.rows.length).toBe(217)
  })

  it('every designation link resolves to the required kind WITHIN the dataset — no dangling, no wrong-kind', () => {
    const kindOf = new Map(dataset.rows.map(r => [r.id, r.kind]))
    const rules: Record<string, string> = {
      'utilizer': 'member-state',
      'associate': 'corresponding-member',
      'test-laboratory': 'issuing-authority',
      'issuing-authority': 'member-state',
    }
    for (const row of dataset.rows) {
      const link = row.designatedBy ?? row.proposedBy
      const required = rules[row.kind]
      if (required) {
        expect(link, `${row.id} carries its designation`).not.toBeNull()
        expect(kindOf.get(link!), `${row.id} → ${link}`).toBe(required)
      } else {
        // The member kinds designate — they are never designated.
        expect(row.designatedBy).toBeNull()
        expect(row.proposedBy).toBeNull()
      }
      // The CS status rides the designated bodies only, and every listed
      // utilizer/associate is a signed, active Declaration holder.
      if (row.kind === 'utilizer' || row.kind === 'associate') {
        expect(row.csStatus, row.id).toBe('signed-active')
      } else {
        expect(row.csStatus, row.id).toBeNull()
      }
      // Provenance rides every row.
      expect(row.provenance.source, row.id).toMatch(/^https:\/\/www\.oiml\.org\//)
    }
  })
})

// ── the import over the real store ───────────────────────────────────

describe('the import', () => {
  it('the dry-run plans 217 creates against an empty registry and writes NOTHING', async () => {
    const { planOrgRegistryBootstrap } = await import('../../server/import-org-registry')
    const plan = await planOrgRegistryBootstrap(store, dataset)
    expect(plan.errors).toEqual([])
    expect(plan.counts).toEqual({ create: 217, update: 0, unchanged: 0 })
    expect(await store.listOrgRegistryOrgs()).toEqual([]) // the plan never writes
  })

  it('the apply lands every row ACTIVE with its designation links', async () => {
    const { planOrgRegistryBootstrap, applyOrgRegistryPlan } = await import('../../server/import-org-registry')
    const plan = await planOrgRegistryBootstrap(store, dataset)
    const applied = await applyOrgRegistryPlan(store, plan)
    expect(applied).toEqual({ created: 217, updated: 0, unchanged: 0 })
    const rows = await store.listOrgRegistryOrgs()
    expect(rows.length).toBe(217)
    expect(rows.every(r => r.state === 'active')).toBe(true)

    const { resolveRegistryOrg } = await import('../../server/auth/org-registry')
    // The layered chain, the real directory's shape: Germany proposes
    // its IA (DE1), the IA associates its own TL, and designates a
    // utilizer that carries the Declaration's standing.
    expect((await resolveRegistryOrg(store, 'DE1'))!.proposedBy).toBe('ms-de')
    expect((await resolveRegistryOrg(store, 'tl-de1-ptb'))!.designatedBy).toBe('DE1')
    const utDe = (await resolveRegistryOrg(store, 'ut-de'))!
    expect(utDe.designatedBy).toBe('ms-de')
    expect(utDe.csStatus).toBe('signed-active')
    expect(utDe.standing).toBe('participant')
    // The corresponding member's associate.
    const asAo = (await resolveRegistryOrg(store, 'as-ao'))!
    expect(asAo.designatedBy).toBe('cm-ao')
    expect(asAo.csStatus).toBe('signed-active')
    // The member rows: the Convention's fact, never the participant
    // posture; the read/access role bound.
    const msDe = (await resolveRegistryOrg(store, 'ms-de'))!
    expect(msDe.standing).toBe('member')
    expect(msDe.registered).toBe(false)
    expect(msDe.roles).toEqual(['viewer'])
    expect((await resolveRegistryOrg(store, 'cm-ae'))!.kind).toBe('corresponding-member')
  })

  it('the re-run is a no-op — 217 unchanged, zero writes (the idempotency)', async () => {
    const { planOrgRegistryBootstrap, applyOrgRegistryPlan } = await import('../../server/import-org-registry')
    const plan = await planOrgRegistryBootstrap(store, dataset)
    expect(plan.errors).toEqual([])
    expect(plan.counts).toEqual({ create: 0, update: 0, unchanged: 217 })
    expect(await applyOrgRegistryPlan(store, plan)).toEqual({ created: 0, updated: 0, unchanged: 217 })
  })

  it('the upsert re-converges the managed fields and NEVER touches the curated contacts or the administrator’s lifecycle', async () => {
    const { planOrgRegistryBootstrap, applyOrgRegistryPlan } = await import('../../server/import-org-registry')
    // Drift a row: rename + the administrator curated a contact.
    await store.updateOrgRegistryOrg('DE1', { name: 'Drifted Name', contacts: [{ name: 'The PTB desk', email: 'oiml@ptb.de' }] }, 'the test')
    // …and a deliberate disable the import must not resurrect.
    await store.setOrgRegistryOrgState('ms-mc', 'disabled', 'the administrator')
    const plan = await planOrgRegistryBootstrap(store, dataset)
    expect(plan.counts.create).toBe(0)
    expect(plan.counts.update).toBe(1)
    const de1 = plan.actions.find(a => a.id === 'DE1')!
    expect(de1.changes).toEqual(['name'])
    const mc = plan.actions.find(a => a.id === 'ms-mc')!
    expect(mc.action).toBe('unchanged')
    expect(mc.notes.join(' ')).toContain('DISABLED')
    await applyOrgRegistryPlan(store, plan)
    const row = (await store.getOrgRegistryOrg('DE1'))!
    expect(row.name).toBe('Physikalisch-Technische Bundesanstalt')
    expect(row.contacts).toEqual([{ name: 'The PTB desk', email: 'oiml@ptb.de' }]) // the curation stands
    expect((await store.getOrgRegistryOrg('ms-mc'))!.state).toBe('disabled') // the lifecycle is the administrator's
    // …and the next plan is clean again (the disabled member reports unchanged-with-note).
    const after = await planOrgRegistryBootstrap(store, dataset)
    expect(after.counts.update).toBe(0)
    // Restore the shared store for the later legs.
    await store.setOrgRegistryOrgState('ms-mc', 'active', 'the test')
  })

  it('a wrong-kind designator fails the PLAN — and the apply refuses a refusing plan', async () => {
    const { parseBootstrapDataset, planOrgRegistryBootstrap, applyOrgRegistryPlan } = await import('../../server/import-org-registry')
    const tampered = parseBootstrapDataset({
      members: [{ id: 'cm-x', kind: 'corresponding-member', name: 'X', provenance: { source: 'https://www.oiml.org/x' } }],
      utilizers: [{ id: 'ut-x', name: 'X Utilizer', designated_by: 'cm-x', cs_status: 'signed-active', provenance: { source: 'https://www.oiml.org/x' } }],
    })
    const plan = await planOrgRegistryBootstrap(store, tampered)
    expect(plan.errors.length).toBe(1)
    expect(plan.errors[0]).toContain('ut-x')
    expect(plan.errors[0]).toContain('member-state')
    await expect(applyOrgRegistryPlan(store, plan)).rejects.toThrow('validation refusal')
    expect(await store.getOrgRegistryOrg('ut-x')).toBeNull() // nothing landed
  })

  it('the dataset’s own validation refuses the malformed shapes honestly', async () => {
    const { parseBootstrapDataset } = await import('../../server/import-org-registry')
    expect(() => parseBootstrapDataset({ members: [{ id: 'bad id!', kind: 'member-state', name: 'X' }] })).toThrow('stable slug')
    expect(() => parseBootstrapDataset({ members: [{ id: 'ms-x', kind: 'manufacturer', name: 'X' }] })).toThrow('collection carries')
    expect(() => parseBootstrapDataset({ members: [{ id: 'ms-x', kind: 'member-state', name: 'X' }, { id: 'ms-x', kind: 'member-state', name: 'Y' }] })).toThrow('duplicate id')
    expect(() => parseBootstrapDataset({ members: [] })).toThrow('no rows')
  })
})

// ── the SQL path (the remote wrangler apply's equivalence) ──────────

describe('the SQL emission', () => {
  it('planToSql lands the same rows as the store-seam apply', async () => {
    const { planOrgRegistryBootstrap, planToSql, applyOrgRegistryPlan } = await import('../../server/import-org-registry')
    // DB-A: the store-seam apply (the suite's own imported store).
    const planA = await planOrgRegistryBootstrap(store, dataset)
    expect(planA.counts.unchanged).toBe(217)
    // The create-shaped plan against an empty facade, then its SQL onto
    // a scratch database.
    const emptyStore = {
      listOrgRegistryOrgs: async () => [],
      getOrgRegistryOrg: async () => null,
    } as never
    const planB = await planOrgRegistryBootstrap(emptyStore, dataset)
    expect(planB.counts).toEqual({ create: 217, update: 0, unchanged: 0 })
    const statements = planToSql(planB)
    expect(statements.length).toBe(217)
    // Apply the SQL onto a scratch database carrying the org_registry
    // table (the kernel's 0013 + 0019 column set).
    const raw = new Database(join(TMP, 'sql-path.db'))
    raw.exec(`CREATE TABLE org_registry (
      id TEXT PRIMARY KEY, name TEXT NOT NULL, short_name TEXT, kind TEXT, country TEXT,
      contacts TEXT NOT NULL DEFAULT '[]', participant_ref TEXT,
      designated_by TEXT, proposed_by TEXT, cs_status TEXT,
      state TEXT NOT NULL DEFAULT 'active', created_at TEXT NOT NULL DEFAULT (datetime('now')),
      created_by TEXT, updated_at TEXT, updated_by TEXT, disabled_at TEXT, disabled_by TEXT
    )`)
    for (const stmt of statements) raw.exec(stmt)
    const sqlRows = raw.prepare('SELECT id, name, short_name, kind, country, contacts, participant_ref, designated_by, proposed_by, cs_status, state, created_by FROM org_registry ORDER BY id').all() as Array<Record<string, unknown>>
    raw.close()
    // The store-side answer, the same columns (timestamps excluded — the
    // two paths stamp their own; the store listing is name-ordered, so
    // both sides re-key on the id). The store carries the earlier legs'
    // curated contact on DE1 — the SQL path lands the dataset's empty
    // contacts on CREATE and never touches them on update, so contacts
    // compare per-row: the SQL side is the dataset's truth ('[]'
    // everywhere), the store side proves the non-touch.
    const storeById = new Map((await store.listOrgRegistryOrgs()).map(r => [r.id, r]))
    expect(sqlRows.length).toBe(217)
    for (const sqlRow of sqlRows) {
      const storeRow = storeById.get(sqlRow.id as string)
      expect(storeRow, `the store carries ${sqlRow.id}`).toBeTruthy()
      expect({
        name: sqlRow.name,
        shortName: sqlRow.short_name,
        kind: sqlRow.kind,
        country: sqlRow.country,
        participantRef: sqlRow.participant_ref,
        designatedBy: sqlRow.designated_by,
        proposedBy: sqlRow.proposed_by,
        csStatus: sqlRow.cs_status,
        state: sqlRow.state,
        createdBy: sqlRow.created_by,
      }).toEqual({
        name: storeRow!.name,
        shortName: storeRow!.shortName,
        kind: storeRow!.kind,
        country: storeRow!.country,
        participantRef: storeRow!.participantRef,
        designatedBy: storeRow!.designatedBy,
        proposedBy: storeRow!.proposedBy,
        csStatus: storeRow!.csStatus,
        state: storeRow!.state,
        createdBy: storeRow!.createdBy,
      })
      expect(sqlRow.contacts).toBe('[]') // the dataset carries no contacts
    }
  })
})

// ── the chain rendering through the registry aggregates ─────────────

describe('the designation chains through the registry aggregates', () => {
  it('the real directory’s chains render: ms-de proposes DE1 + designates ut-de; DE1 names its proposer and its six TLs', async () => {
    const member = await json(await app.request(`${ORIGIN}/api/op/registry/orgs/ms-de`, { headers: { cookie: admin } }), 200)
    expect(member.org.kind).toBe('member-state')
    expect(member.org.standing).toBe('member')
    expect(member.linkedBy).toEqual(expect.arrayContaining([
      { id: 'DE1', name: 'Physikalisch-Technische Bundesanstalt', kind: 'issuing-authority', via: 'proposed_by' },
      { id: 'ut-de', name: 'Physikalisch-Technische Bundesanstalt', kind: 'utilizer', via: 'designated_by' },
    ]))

    const ia = await json(await app.request(`${ORIGIN}/api/op/registry/orgs/DE1`, { headers: { cookie: admin } }), 200)
    expect(ia.links.proposedBy).toEqual({ id: 'ms-de', name: 'Germany' })
    const tlIds = ia.linkedBy.filter((l: any) => l.via === 'designated_by').map((l: any) => l.id).sort()
    expect(tlIds).toEqual(['tl-de1-awtx', 'tl-de1-endress-hauser-flowtec', 'tl-de1-mettler-toledo', 'tl-de1-ptb', 'tl-de1-sartorius', 'tl-de1-sensus'])

    const associate = await json(await app.request(`${ORIGIN}/api/op/registry/orgs/as-ao`, { headers: { cookie: admin } }), 200)
    expect(associate.links.designatedBy).toEqual({ id: 'cm-ao', name: 'Angola' })
    expect(associate.org.csStatus).toBe('signed-active')

    // The list's chain counts: Germany's layered engagement reads whole.
    const list = await json(await app.request(`${ORIGIN}/api/op/registry/orgs`, { headers: { cookie: admin } }), 200)
    const msDe = list.find((r: any) => r.id === 'ms-de')
    expect(msDe.chain).toEqual({ proposedIas: 1, designatedBodies: 1, associatedTls: 0 })
    const nl = list.find((r: any) => r.id === 'ms-nl')
    expect(nl.chain.proposedIas).toBe(2) // NL1 NMi + NL3 KEMA
    expect(list.length).toBe(217)
  })
})
