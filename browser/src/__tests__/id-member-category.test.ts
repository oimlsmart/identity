// ─────────────────────────────────────────────────────────────────────
// TODO.identity-features/10 — the OIML Member category (the taxonomy
// correction), proven in-process: the REAL org-registry resolver, the
// REAL join-request + registry routers over a REAL temp SQLite store,
// and the REAL migration set (the kernel package's canonical
// migrations/, the staged-application re-home proof).
//
// THE MODEL (the authoritative correction): "OIML Member" is the
// CATEGORY — the member-state (ratified the OIML Convention) and
// corresponding-member kinds — and the Utilizer/Associate are
// DESIGNATED BODIES (their own org rows, signing the Declaration per
// PD-08), never statuses on a member. A member state participates in
// the OIML-CS by PROPOSING an issuing authority (the IA row's
// proposed_by) and DESIGNATING a utilizer (the utilizer row's
// designated_by); a corresponding member designates an associate; a
// test laboratory carries its IA association (designated_by → the IA).
// The designated bodies carry the CS status facet (the Declaration's
// standing). The same legal body may hold several roles — each its own
// LINKED row, never merged.
//
// Covered:
//   THE MEMBER KINDS' ROLE BOUNDS — orgKindRoles(member kinds) is the
//     read/access posture (the plain member's viewer), NEVER workflow
//     authority; the standing reads 'member' (never the participant
//     posture), and the join intake admits the active member org;
//   THE DESIGNATION-LINK ENFORCEMENT — a utilizer's designator is a
//     member state, an associate's a corresponding member, a TL's its
//     IA, an IA's proposer a member state; the wrong kind, the dangling
//     target, the link on a linkless kind, and the CS status off the
//     designated bodies all refuse (the REAL add/edit routes);
//   THE CHAIN RENDERING — the registry aggregates carry the resolved
//     links + the reverse chain (the member's row lists its proposed
//     IAs + its designated bodies; the IA's its associated TLs);
//   THE JOIN INTAKE'S MEMBER PATH — the selector offers the member
//     org, the member's personnel file for the viewer role (a workflow
//     role refuses), the approval lands the membership;
//   THE MIGRATION'S RE-HOME (0019) — a pre-0019 database's legacy
//     utilizer row keeps its home across the expand-only ALTERs (the
//     kind intact, the links NULL — "not recorded", never a
//     destructive move), and the legacy row reads correctly through
//     the store afterwards.
// ─────────────────────────────────────────────────────────────────────

import { mkdtempSync, readdirSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { createRequire } from 'node:module'
import Database from 'better-sqlite3'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

// The store's DB path is read at module evaluation — set it before any
// import below touches @oimlsmart/platform-server/store/sqlite (the imports are dynamic).
const TMP = mkdtempSync(join(tmpdir(), 'oiml-member-category-'))
process.env.DATABASE_PATH = join(TMP, 'test.db')
process.env.OP_ISSUER = 'http://op.test'

const ORIGIN = 'http://op.test'

// The kernel package's canonical migration set (TODO.repos/01), resolved
// WITHOUT evaluating the store module — its DB path binds at import time
// and must see the env set above. createRequire resolves, never loads.
const MIGRATIONS_DIR = join(
  dirname(createRequire(import.meta.url).resolve('@oimlsmart/platform-server/package.json')),
  'migrations',
)

let app: import('hono').Hono
let store: ReturnType<typeof import('@oimlsmart/platform-server/store').getStore>

async function demoLogin(email: string): Promise<string> {
  const res = await app.request(`${ORIGIN}/api/auth/demo`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password: 'demo2026' }),
  })
  expect(res.ok, `demo login ${email}`).toBe(true)
  return res.headers.get('set-cookie')!.split(';')[0]!
}

/** The JSON body of a request, asserting the status first. */
async function json(res: Response, status: number): Promise<any> {
  expect(res.status, `${res.url} → ${status}`).toBe(status)
  return res.json()
}

let admin: string

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
  const { createUsersRouter } = await import('../../server/routes/users')
  const { createOpJoinRouter } = await import('../../server/routes/op-join')
  const { createOpRegistryRouter } = await import('../../server/routes/op-registry')
  const { createOpAccountsRouter } = await import('../../server/routes/op-accounts')
  const root = new Hono()
  root.route('/api/auth', createAuthLeanRouter({ autoSeedDemo: true }))
  root.route('/api/users', createUsersRouter())
  root.route('/', createOpJoinRouter())
  root.route('/', createOpRegistryRouter())
  root.route('/', createOpAccountsRouter())
  app = root

  // The registry cast: the LAYERED member (ms-example with its proposed
  // IA + its designated utilizer), the corresponding member with its
  // associate, a DISABLED member state (the join gate's negative leg),
  // and the LEGACY utilizer (no designation recorded — the pre-0019
  // shape's honest read).
  await store.createOrgRegistryOrg({ id: 'ms-example', name: 'Example Member Body', shortName: 'EMB', kind: 'member-state', country: 'Example Member State', contacts: [{ name: 'Ms. Ingrid Halvorsen', email: 'oiml@emb.example.org' }] })
  await store.createOrgRegistryOrg({ id: 'ms-dormant', name: 'Dormant Member Body', kind: 'member-state', country: null, contacts: [] })
  await store.setOrgRegistryOrgState('ms-dormant', 'disabled', 'the test seed')
  await store.createOrgRegistryOrg({ id: 'cm-demo', name: 'Demo Corresponding Member Institute', shortName: 'DCMI', kind: 'corresponding-member', country: 'Demo Corresponding Economy', contacts: [{ name: 'Ms. Amara Diallo', email: 'contact@dcmi.example.org' }] })
  await store.createOrgRegistryOrg({ id: 'EX1', name: 'Example Issuing Authority', shortName: 'EIA', kind: 'issuing-authority', country: 'Example Member State', contacts: [{ name: null, email: 'office@eia.example.org' }], participantRef: 'EX1', proposedBy: 'ms-example' })
  await store.createOrgRegistryOrg({ id: '21', name: 'Example Test Laboratory', shortName: 'ETL', kind: 'test-laboratory', country: 'Example Member State', contacts: [{ name: null, email: 'lab@etl.example.org' }], participantRef: '21', designatedBy: 'EX1' })
  await store.createOrgRegistryOrg({ id: 'ut-example', name: 'Example Market Surveillance Authority', shortName: 'EMSA', kind: 'utilizer', country: 'Example Member State', contacts: [{ name: null, email: 'oiml-cs@emsa.example.org' }], participantRef: 'ut-example', designatedBy: 'ms-example', csStatus: 'signed-active' })
  await store.createOrgRegistryOrg({ id: 'as-demo', name: 'Demo Inspection Body', shortName: 'DIB', kind: 'associate', country: 'Demo Corresponding Economy', contacts: [{ name: null, email: 'oiml-cs@dib.example.org' }], participantRef: 'as-demo', designatedBy: 'cm-demo', csStatus: 'signed-active' })
  await store.createOrgRegistryOrg({ id: 'ut-legacy', name: 'Legacy Utilizer (no designation recorded)', kind: 'utilizer', country: 'Legacy Member State', contacts: [{ name: null, email: 'office@legacy.example.org' }], participantRef: 'ut-legacy' })

  admin = await demoLogin('admin@oiml.org')
})

afterAll(async () => {
  const { resetInstanceProfileForTest } = await import('@oimlsmart/platform-server/profile')
  resetInstanceProfileForTest()
  rmSync(TMP, { recursive: true, force: true })
  delete process.env.DATABASE_PATH
  delete process.env.OP_ISSUER
})

// ── the member kinds' role bounds + the standing (the resolver) ──────

describe('the member kinds (the resolver)', () => {
  it('bounds the member kinds to the READ/ACCESS posture — the plain member’s viewer, never workflow authority', async () => {
    const { orgKindRoles, isRegistryOrgKind } = await import('../../server/auth/org-registry')
    for (const kind of ['member-state', 'corresponding-member'] as const) {
      expect(orgKindRoles(kind)).toEqual(['viewer'])
      // Never workflow authority: no CS role, no applicant, no admin.
      expect(orgKindRoles(kind).some(r => r.startsWith('ia_') || r.startsWith('tl_') || r === 'admin' || r === 'cs_admin' || r === 'scheme_participant' || r === 'applicant' || r === 'org_admin')).toBe(false)
      expect(isRegistryOrgKind(kind)).toBe(true)
    }
    // The designated-body kinds REMAIN (they are designated bodies,
    // never the member's identity).
    expect(isRegistryOrgKind('utilizer')).toBe(true)
    expect(isRegistryOrgKind('associate')).toBe(true)
  })

  it('projects the member standing + the links honestly — the member NEVER reads as a CS participant', async () => {
    const { resolveRegistryOrg, admitsJoinFlow, onJoinSelector } = await import('../../server/auth/org-registry')
    const ms = (await resolveRegistryOrg(store, 'ms-example'))!
    expect(ms.kind).toBe('member-state')
    expect(ms.standing).toBe('member') // the Convention's fact
    expect(ms.registered).toBe(false) // never the PD-03 participant posture
    expect(ms.roles).toEqual(['viewer'])
    expect(admitsJoinFlow(ms)).toBe(true) // the member path's intake
    expect(onJoinSelector(ms)).toBe(true)

    const cm = (await resolveRegistryOrg(store, 'cm-demo'))!
    expect(cm.standing).toBe('member')
    expect(cm.registered).toBe(false)

    // The layered member's links land on the DESIGNATED bodies, never on
    // the member: the IA names its proposer, the TL its IA, the utilizer
    // its member state, and the CS status rides the Declaration.
    const ia = (await resolveRegistryOrg(store, 'EX1'))!
    expect(ia.proposedBy).toBe('ms-example')
    expect(ia.designatedBy).toBeNull()
    expect(ia.standing).toBe('participant')
    const tl = (await resolveRegistryOrg(store, '21'))!
    expect(tl.designatedBy).toBe('EX1')
    const ut = (await resolveRegistryOrg(store, 'ut-example'))!
    expect(ut.designatedBy).toBe('ms-example')
    expect(ut.csStatus).toBe('signed-active')
    const as = (await resolveRegistryOrg(store, 'as-demo'))!
    expect(as.designatedBy).toBe('cm-demo')

    // The legacy utilizer (no designation recorded): the kind + the
    // participant standing intact, the links NULL — "not recorded".
    const legacy = (await resolveRegistryOrg(store, 'ut-legacy'))!
    expect(legacy.kind).toBe('utilizer')
    expect(legacy.registered).toBe(true)
    expect(legacy.designatedBy).toBeNull()
    expect(legacy.proposedBy).toBeNull()
    expect(legacy.csStatus).toBeNull()

    // The disabled member: the standing label never resurrects the row;
    // the join gate closes.
    const dormant = (await resolveRegistryOrg(store, 'ms-dormant'))!
    expect(dormant.standing).toBe('member')
    expect(admitsJoinFlow(dormant)).toBe(false)
    expect(onJoinSelector(dormant)).toBe(false)
  })
})

// ── the designation-link enforcement (the REAL write path) ───────────

describe('the designation-link kind enforcement', () => {
  it('a utilizer’s designator is a MEMBER STATE — a corresponding member (or anything else) refuses', async () => {
    const ok = await app.request(`${ORIGIN}/api/op/registry/orgs`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie: admin },
      body: JSON.stringify({ id: 'ut-second', name: 'Second Utilizer', kind: 'utilizer', designated_by: 'ms-example', cs_status: 'signed-active' }),
    })
    expect(ok.status).toBe(201)

    const wrongKind = await app.request(`${ORIGIN}/api/op/registry/orgs`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie: admin },
      body: JSON.stringify({ id: 'ut-wrong', name: 'Wrongly Designated', kind: 'utilizer', designated_by: 'cm-demo' }),
    })
    expect(wrongKind.status).toBe(400)
    expect((await wrongKind.json()).error).toContain("the designator of the utilizer row must be a member-state organization")
    expect(await store.getOrgRegistryOrg('ut-wrong')).toBeNull()

    const dangling = await app.request(`${ORIGIN}/api/op/registry/orgs`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie: admin },
      body: JSON.stringify({ id: 'ut-dangling', name: 'Dangling Designation', kind: 'utilizer', designated_by: 'no-such-org' }),
    })
    expect(dangling.status).toBe(400)
    expect((await dangling.json()).error).toContain('not on the organization registry')

    const disabledTarget = await app.request(`${ORIGIN}/api/op/registry/orgs`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie: admin },
      body: JSON.stringify({ id: 'ut-dormant', name: 'Dormant Designated', kind: 'utilizer', designated_by: 'ms-dormant' }),
    })
    expect(disabledTarget.status).toBe(400)
    expect((await disabledTarget.json()).error).toContain('is disabled')
  })

  it('an associate’s designator is a CORRESPONDING MEMBER — a member state refuses', async () => {
    const wrongKind = await app.request(`${ORIGIN}/api/op/registry/orgs`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie: admin },
      body: JSON.stringify({ id: 'as-wrong', name: 'Wrongly Associated', kind: 'associate', designated_by: 'ms-example' }),
    })
    expect(wrongKind.status).toBe(400)
    expect((await wrongKind.json()).error).toContain("the designator of the associate row must be a corresponding-member organization")
    expect(await store.getOrgRegistryOrg('as-wrong')).toBeNull()
  })

  it('the IA carries proposed_by → a member state; the TL carries designated_by → its IA; the other column refuses', async () => {
    const iaWrong = await app.request(`${ORIGIN}/api/op/registry/orgs`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie: admin },
      body: JSON.stringify({ id: 'EX2', name: 'Second IA', kind: 'issuing-authority', proposed_by: 'cm-demo' }),
    })
    expect(iaWrong.status).toBe(400)
    expect((await iaWrong.json()).error).toContain("the proposer of the issuing-authority row must be a member-state organization")

    const iaDesignated = await app.request(`${ORIGIN}/api/op/registry/orgs`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie: admin },
      body: JSON.stringify({ id: 'EX2', name: 'Second IA', kind: 'issuing-authority', designated_by: 'ms-example' }),
    })
    expect(iaDesignated.status).toBe(400)
    expect((await iaDesignated.json()).error).toContain('carries no designated_by link')

    const tlOk = await app.request(`${ORIGIN}/api/op/registry/orgs`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie: admin },
      body: JSON.stringify({ id: '22', name: 'Second TL', kind: 'test-laboratory', designated_by: 'EX1' }),
    })
    expect(tlOk.status).toBe(201)
    const tlWrong = await app.request(`${ORIGIN}/api/op/registry/orgs`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie: admin },
      body: JSON.stringify({ id: '23', name: 'Third TL', kind: 'test-laboratory', designated_by: 'ms-example' }),
    })
    expect(tlWrong.status).toBe(400)
    expect((await tlWrong.json()).error).toContain("the designator of the test-laboratory row must be an issuing-authority organization")
  })

  it('a link on a linkless kind refuses (a member state DESIGNATES — it is never designated), and the CS status rides the designated bodies only', async () => {
    const memberLinked = await app.request(`${ORIGIN}/api/op/registry/orgs`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie: admin },
      body: JSON.stringify({ id: 'ms-linked', name: 'Self-Designating Member', kind: 'member-state', designated_by: 'ms-example' }),
    })
    expect(memberLinked.status).toBe(400)
    expect((await memberLinked.json()).error).toContain('a member state or corresponding member DESIGNATES, it is never designated')

    const memberCs = await app.request(`${ORIGIN}/api/op/registry/orgs`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie: admin },
      body: JSON.stringify({ id: 'ms-cs', name: 'CS-Claiming Member', kind: 'member-state', cs_status: 'signed-active' }),
    })
    expect(memberCs.status).toBe(400)
    expect((await memberCs.json()).error).toContain('the CS status facet rides the designated bodies only')

    const badStatus = await app.request(`${ORIGIN}/api/op/registry/orgs`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie: admin },
      body: JSON.stringify({ id: 'ut-bad-status', name: 'Bad Status', kind: 'utilizer', cs_status: 'banana' }),
    })
    expect(badStatus.status).toBe(400)
    expect((await badStatus.json()).error).toContain('signed-active, suspended, withdrawn')

    const legacyOk = await app.request(`${ORIGIN}/api/op/registry/orgs`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie: admin },
      body: JSON.stringify({ id: 'ut-third', name: 'Third Utilizer (undesignated)', kind: 'utilizer' }),
    })
    expect(legacyOk.status).toBe(201) // NULL links are always admitted — "not recorded"
  })

  it('the edit act validates the MERGED row — a kind change meets the standing links', async () => {
    // The IA carries proposed_by → ms-example; re-kinding it to a
    // manufacturer keeps the link on the merged row, and refuses.
    const rekind = await app.request(`${ORIGIN}/api/op/registry/orgs/EX1`, {
      method: 'PUT', headers: { 'content-type': 'application/json', cookie: admin },
      body: JSON.stringify({ kind: 'manufacturer' }),
    })
    expect(rekind.status).toBe(400)
    expect((await rekind.json()).error).toContain('carries no proposed_by link')

    // The CS status transition lands on the designated body honestly.
    const suspend = await json(await app.request(`${ORIGIN}/api/op/registry/orgs/ut-example`, {
      method: 'PUT', headers: { 'content-type': 'application/json', cookie: admin },
      body: JSON.stringify({ cs_status: 'suspended' }),
    }), 200)
    expect(suspend.csStatus).toBe('suspended')
    const restore = await app.request(`${ORIGIN}/api/op/registry/orgs/ut-example`, {
      method: 'PUT', headers: { 'content-type': 'application/json', cookie: admin },
      body: JSON.stringify({ cs_status: 'signed-active' }),
    })
    expect(restore.status).toBe(200)
  })
})

// ── the chain rendering (the registry aggregates) ────────────────────

describe('the designation chain’s rendering', () => {
  it('the member’s row lists its proposed IAs + its designated bodies; the IA’s its proposer + its TLs', async () => {
    const member = await json(await app.request(`${ORIGIN}/api/op/registry/orgs/ms-example`, { headers: { cookie: admin } }), 200)
    expect(member.org.kind).toBe('member-state')
    expect(member.org.standing).toBe('member')
    expect(member.links).toEqual({ designatedBy: null, proposedBy: null })
    expect(member.linkedBy).toEqual(expect.arrayContaining([
      { id: 'EX1', name: 'Example Issuing Authority', kind: 'issuing-authority', via: 'proposed_by' },
      { id: 'ut-example', name: 'Example Market Surveillance Authority', kind: 'utilizer', via: 'designated_by' },
    ]))
    // The edit form's eligible targets ride the aggregate.
    expect(member.linkTargets.memberStates.map((o: any) => o.id)).toContain('ms-example')
    expect(member.linkTargets.correspondingMembers.map((o: any) => o.id)).toContain('cm-demo')

    const ia = await json(await app.request(`${ORIGIN}/api/op/registry/orgs/EX1`, { headers: { cookie: admin } }), 200)
    expect(ia.links.proposedBy).toEqual({ id: 'ms-example', name: 'Example Member Body' })
    expect(ia.linkedBy).toEqual(expect.arrayContaining([
      { id: '21', name: 'Example Test Laboratory', kind: 'test-laboratory', via: 'designated_by' },
    ]))

    const utilizer = await json(await app.request(`${ORIGIN}/api/op/registry/orgs/ut-example`, { headers: { cookie: admin } }), 200)
    expect(utilizer.links.designatedBy).toEqual({ id: 'ms-example', name: 'Example Member Body' })
    expect(utilizer.org.csStatus).toBe('signed-active')
  })

  it('the list rows carry the chain counts + the CS status honestly', async () => {
    const list = await json(await app.request(`${ORIGIN}/api/op/registry/orgs`, { headers: { cookie: admin } }), 200)
    const ms = list.find((r: any) => r.id === 'ms-example')
    // The layered member: EX1 proposed; ut-example + ut-second (the
    // enforcement leg's add) designated.
    expect(ms.chain).toEqual({ proposedIas: 1, designatedBodies: 2, associatedTls: 0 })
    const ia = list.find((r: any) => r.id === 'EX1')
    expect(ia.proposedBy).toBe('ms-example')
    // The TLs 21 (the seed) + 22 (the enforcement leg's add).
    expect(ia.chain.associatedTls).toBe(2)
    const legacy = list.find((r: any) => r.id === 'ut-legacy')
    expect(legacy.designatedBy).toBeNull()
    expect(legacy.csStatus).toBeNull()
  })
})

// ── the join intake's member path ────────────────────────────────────

describe('the join intake’s member path', () => {
  it('the selector offers the member orgs with the read/access roles — never the disabled member', async () => {
    const feed = await json(await app.request(`${ORIGIN}/api/op/organizations`), 200)
    const ids = feed.map((o: any) => o.id)
    expect(ids).toContain('ms-example')
    expect(ids).toContain('cm-demo')
    expect(ids).toContain('EX1')
    expect(ids).not.toContain('ms-dormant')
    const ms = feed.find((o: any) => o.id === 'ms-example')
    expect(ms.kind).toBe('member-state')
    expect(ms.roles).toEqual(['viewer'])
  })

  it('the member state’s personnel request accounts against their member org — a workflow role refuses', async () => {
    const workflowRole = await app.request(`${ORIGIN}/api/op/join-requests`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ name: 'Ambitious Member', email: 'ambitious@emb.example.org', org_id: 'ms-example', requested_role: 'ia_officer' }),
    })
    expect(workflowRole.status).toBe(400)
    expect((await workflowRole.json()).error).toContain("is not one a member-state organization's staff holds")

    const filed = await json(await app.request(`${ORIGIN}/api/op/join-requests`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ name: 'Ingrid Halvorsen', email: 'ingrid@emb.example.org', org_id: 'ms-example', requested_role: 'viewer' }),
    }), 201)
    expect(filed.orgId).toBe('ms-example')
    expect(filed.requestedRole).toBe('viewer')

    // The approval lands the membership with the read/access posture.
    const approved = await json(await app.request(`${ORIGIN}/api/op/join-requests/${filed.id}/approve`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie: admin }, body: '{}',
    }), 200)
    expect(approved.status).toBe('approved')
    const member = await store.findUserByEmail('ingrid@emb.example.org')
    expect(member!.orgId).toBe('ms-example')
    expect(member!.role).toBe('viewer')
  })

  it('the disabled member org refuses the intake honestly', async () => {
    const res = await app.request(`${ORIGIN}/api/op/join-requests`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ name: 'Early Member', email: 'early@dormant.example.org', org_id: 'ms-dormant', requested_role: 'viewer' }),
    })
    expect(res.status).toBe(400)
    expect((await res.json()).error).toContain('not an active participant on the identity service')
  })
})

// ── the migration's re-home (0019, the staged application) ───────────

describe('the migration’s re-home (0019)', () => {
  it('a pre-0019 legacy utilizer row keeps its home across the expand-only ALTERs — never a destructive move', () => {
    // The pre-0019 state on a scratch database, then the real file.
    const scratch = new Database(':memory:')
    const files = readdirSync(MIGRATIONS_DIR).filter(f => f.endsWith('.sql')).sort()
    expect(files.some(f => f.startsWith('0019'))).toBe(true)
    for (const f of files.filter(f => !f.startsWith('0019'))) scratch.exec(readFileSync(join(MIGRATIONS_DIR, f), 'utf-8'))

    // The legacy row: written with the PRE-0019 column set (the columns
    // do not exist yet — the insert naming them would fail).
    scratch.prepare(
      "INSERT INTO org_registry (id, name, kind, country, contacts, participant_ref) VALUES ('ut-legacy', 'Legacy Utilizer', 'utilizer', 'Legacy Member State', '[]', 'ut-legacy')",
    ).run()
    const preCols = scratch.prepare('PRAGMA table_info(org_registry)').all() as Array<{ name: string }>
    expect(preCols.some(col => col.name === 'designated_by')).toBe(false)

    // The migration lands expand-only: the three columns appear, the row
    // keeps its home — kind intact, links NULL ("not recorded").
    scratch.exec(readFileSync(join(MIGRATIONS_DIR, '0019_org_member_category.sql'), 'utf-8'))
    const postCols = scratch.prepare('PRAGMA table_info(org_registry)').all() as Array<{ name: string }>
    for (const col of ['designated_by', 'proposed_by', 'cs_status']) {
      expect(postCols.some(c => c.name === col)).toBe(true)
    }
    const row = scratch.prepare('SELECT * FROM org_registry WHERE id = ?').get('ut-legacy') as Record<string, unknown>
    expect(row.kind).toBe('utilizer')
    expect(row.designated_by).toBeNull()
    expect(row.proposed_by).toBeNull()
    expect(row.cs_status).toBeNull()
    expect(row.participant_ref).toBe('ut-legacy')
    scratch.close()
  })

  it('the legacy row reads correctly through the STORE post-migration (the resolver’s honest projection)', async () => {
    // The suite's own seeded legacy row (no designation recorded) reads
    // as it always did — the participant kind + standing intact, the
    // links honestly absent.
    const { resolveRegistryOrg } = await import('../../server/auth/org-registry')
    const legacy = (await resolveRegistryOrg(store, 'ut-legacy'))!
    expect(legacy.kind).toBe('utilizer')
    expect(legacy.registered).toBe(true)
    expect(legacy.standing).toBe('participant')
    expect(legacy.designatedBy).toBeNull()
    expect(legacy.csStatus).toBeNull()
    // …and the join selector still offers it (a designation never
    // recorded is not a deregistration).
    const feed = await json(await app.request(`${ORIGIN}/api/op/organizations`), 200)
    expect(feed.map((o: any) => o.id)).toContain('ut-legacy')
  })
})
