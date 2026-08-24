// ─────────────────────────────────────────────────────────────────────
// TODO.identity/10 — delegated organization administration, proven
// in-process: the REAL users router (server/routes/users.ts) and the
// REAL join-request router (server/routes/op-join.ts) over a REAL temp
// SQLite store, with a seeded participants register (the entity store).
//
// Covered:
//   THE ORG-SCOPING HONESTY — an org admin provably cannot touch another
//     org's users: the list is scoped, cross-org reads/writes are 404,
//     a body naming another org is 403, roles outside the org kind's
//     bounded set are 403, org_admin is never assignable/scopable, and
//     the org's own administrator account is the scheme operator's;
//   THE ELIGIBILITY RULE — org_admin (and the delegated flow's accounts)
//     exist only for a REGISTERED participant org (PD-03 / B 18 §10.2):
//     the unregistered org and the mid-pipeline org are refused;
//   THE JOIN FLOW — the selector feed (registered orgs only, with the
//     kind-bounded roles), the submit (registry path + the not-listed
//     path + the duplicate guard), the two queues (the org admin's own
//     slice; BIML's new-organizations queue), the approve → the invite
//     (the 02 seam) + the atomic double-decide, the refuse with a
//     reason, the email-domain hint, and the module gate.
// ─────────────────────────────────────────────────────────────────────

import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

// The store's DB path is read at module evaluation — set it before any
// import below touches @oimlsmart/platform-server/store/sqlite (the imports are dynamic).
const TMP = mkdtempSync(join(tmpdir(), 'oiml-org-admin-'))
process.env.DATABASE_PATH = join(TMP, 'test.db')

const ORIGIN = 'http://op.test'

let app: import('hono').Hono
let store: ReturnType<typeof import('@oimlsmart/platform-server/store').getStore>

// ── the seeded participants register ────────────────────────────────
// EX1: a REGISTERED IA (signed Declaration); 21: a REGISTERED TL (the
// ACTIVE participation case — TLs sign no Declaration); XX1: a
// MID-PIPELINE IA (draft Declaration, DECLARATION_PENDING case — NOT
// registered); ut-nmi-nl: a REGISTERED Utilizer (signed Declaration).
const ORGS = [
  { id: 'EX1', kind: 'issuing-authority', name: 'Example Issuing Authority', short_name: 'EIA', country: 'Example Member State', contact: { email: 'office@eia.example.org' } },
  { id: '21', kind: 'test-laboratory', name: 'Example Test Laboratory', short_name: 'ETL', contact: { email: 'lab@etl.example.org' } },
  { id: 'XX1', kind: 'issuing-authority', name: 'Demo Issuing Authority', short_name: 'DIA', contact: { email: 'office@dia.example.org' } },
]
const UTILIZERS = [
  { id: 'ut-nmi-nl', name: 'Example Metrology Authority (Netherlands)', short_name: 'EMA-NL', country: 'Netherlands', contact: { email: 'oiml-cs@nmi.example.org' } },
]
const DECLARATIONS = [
  { id: 'decl-ia-ex1', participant_id: 'EX1', status: 'signed' },
  { id: 'decl-ia-xx1', participant_id: 'XX1', status: 'draft' },
  { id: 'decl-ut-nl', participant_id: 'ut-nmi-nl', status: 'signed' },
]
const APPLICATIONS = [
  { id: 'app-tl-21', applicant_organization_id: '21', status: 'ACTIVE' },
  { id: 'app-ia-xx1', applicant_organization_id: 'XX1', status: 'DECLARATION_PENDING' },
]

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
  const root = new Hono()
  root.route('/api/auth', createAuthLeanRouter({ autoSeedDemo: true }))
  root.route('/api/users', createUsersRouter())
  root.route('/', createOpJoinRouter())
  app = root

  // The participants register (the entity store, the seeded-registry
  // posture) + the org admin accounts the legs need.
  for (const org of ORGS) await store.putEntity('organizations', org.id, null, JSON.stringify(org))
  for (const u of UTILIZERS) await store.putEntity('utilizers', u.id, null, JSON.stringify(u))
  for (const d of DECLARATIONS) await store.putEntity('participantDeclarations', d.id, null, JSON.stringify(d))
  for (const a of APPLICATIONS) await store.putEntity('participantApplications', a.id, null, JSON.stringify(a))

  // The Utilizer's org admin (BIML created it — the eligibility rule's
  // positive leg) and a second org's admin for the cross-org proofs.
  await store.createLocalUser({ email: 'admin@nmi.example.org', name: 'NL Admin', role: 'org_admin', roles: ['org_admin'], orgId: 'ut-nmi-nl' })
  await store.createLocalUser({ email: 'admin@eia.example.org', name: 'IA Admin', role: 'org_admin', roles: ['org_admin'], orgId: 'EX1' })
  // The Utilizer's staff member (the org slice's content) + another
  // org's user (the cross-org target).
  await store.createLocalUser({ email: 'reviewer@nmi.example.org', name: 'NL Reviewer', role: 'viewer', roles: ['viewer'], orgId: 'ut-nmi-nl' })
  await store.createLocalUser({ email: 'officer@eia.example.org', name: 'IA Officer', role: 'ia_officer', roles: ['ia_officer'], orgId: 'EX1' })
})

afterAll(async () => {
  const { resetInstanceProfileForTest } = await import('@oimlsmart/platform-server/profile')
  resetInstanceProfileForTest()
  rmSync(TMP, { recursive: true, force: true })
  delete process.env.DATABASE_PATH
})

// ── the registry resolver (the eligibility rule + the kind bounding) ──

describe('the participants-register resolver', () => {
  it('marks the signed-Declaration orgs and the ACTIVE-case TL registered; the mid-pipeline org is not', async () => {
    const { listRegistryOrganizations, isRegisteredParticipant } = await import('../../server/auth/org-registry')
    const orgs = await listRegistryOrganizations(store)
    const byId = new Map(orgs.map(o => [o.id, o]))
    expect(byId.get('EX1')?.registered).toBe(true)
    expect(byId.get('EX1')?.kind).toBe('issuing-authority')
    expect(byId.get('21')?.registered).toBe(true) // the TL: ACTIVE case, no Declaration
    expect(byId.get('ut-nmi-nl')?.registered).toBe(true)
    expect(byId.get('ut-nmi-nl')?.kind).toBe('utilizer')
    expect(byId.get('XX1')?.registered).toBe(false) // mid-pipeline
    expect(await isRegisteredParticipant(store, 'no-such-org')).toBe(false)
  })

  it('bounds the assignable roles by the org kind', async () => {
    const { orgKindRoles } = await import('../../server/auth/org-registry')
    expect(orgKindRoles('issuing-authority')).toContain('ia_officer')
    expect(orgKindRoles('issuing-authority')).toContain('certification_officer')
    expect(orgKindRoles('test-laboratory')).toEqual(['tl_operator', 'viewer'])
    // TODO.adoption/10 — the acceptance participants' staff: the read-only
    // viewer + the ANR-declaring scheme_participant (TODO.adoption/11).
    expect(orgKindRoles('utilizer')).toEqual(['viewer', 'scheme_participant'])
    expect(orgKindRoles('associate')).toEqual(['viewer', 'scheme_participant'])
    // org_admin is NEVER kind-assignable (BIML creates it, one per org).
    for (const kind of ['issuing-authority', 'test-laboratory', 'utilizer', 'associate'] as const) {
      expect(orgKindRoles(kind)).not.toContain('org_admin')
    }
  })

  it('the email-domain hint matches, mismatches, and abstains honestly', async () => {
    const { emailDomainHint, resolveRegistryOrg } = await import('../../server/auth/org-registry')
    const nl = (await resolveRegistryOrg(store, 'ut-nmi-nl'))!
    expect(emailDomainHint(nl, 'jane@nmi.example.org')).toBe(true)
    expect(emailDomainHint(nl, 'jane@elsewhere.example.org')).toBe(false)
    const tl = (await resolveRegistryOrg(store, '21'))!
    expect(tl.emailDomain).toBe('etl.example.org')
    expect(emailDomainHint({ ...tl, emailDomain: null }, 'a@b.c')).toBeNull()
  })
})

// ── the org-scoped users API (THE ORG-SCOPING HONESTY) ───────────────

describe('the org-scoped users API (org.users.manage)', () => {
  it('lists ONLY the org’s own users — the demo cast and every other org stay invisible', async () => {
    const cookie = await demoLogin('admin@nmi.example.org')
    const rows = await json(await app.request(`${ORIGIN}/api/users`, { headers: { cookie } }), 200)
    // The demo Utilizer officer (utilizer@oiml.org) is BOUND to the NL
    // Utilizer org (TODO.adoption/10 — the register link), so the org
    // admin's slice carries it.
    expect(rows.map((u: any) => u.email).sort()).toEqual(['admin@nmi.example.org', 'reviewer@nmi.example.org', 'utilizer@oiml.org'])
  })

  it('answers ONLY the roles the org’s kind bounds (a Utilizer’s staff: viewer + scheme_participant)', async () => {
    const cookie = await demoLogin('admin@nmi.example.org')
    const map = await json(await app.request(`${ORIGIN}/api/users/roles`, { headers: { cookie } }), 200)
    expect(Object.keys(map)).toEqual(['viewer', 'scheme_participant'])
    // The IA admin's bounded map is the IA desk family.
    const iaCookie = await demoLogin('admin@eia.example.org')
    const iaMap = await json(await app.request(`${ORIGIN}/api/users/roles`, { headers: { cookie: iaCookie } }), 200)
    expect(Object.keys(iaMap).sort()).toEqual(['case_officer', 'certification_officer', 'ia_officer', 'signatory', 'viewer'])
  })

  it('refuses a cross-org role write (404 — the other org’s account is not in the slice)', async () => {
    const cookie = await demoLogin('admin@nmi.example.org')
    const target = (await store.listUsers()).find(u => u.email === 'officer@eia.example.org')!
    const res = await app.request(`${ORIGIN}/api/users/${target.id}/roles`, {
      method: 'PUT', headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ role: 'viewer' }),
    })
    expect(res.status).toBe(404)
    // …and the account's roles stand untouched.
    expect((await store.getUserById(target.id))!.role).toBe('ia_officer')
  })

  it('refuses a cross-org deactivation the same way', async () => {
    const cookie = await demoLogin('admin@nmi.example.org')
    const target = (await store.listUsers()).find(u => u.email === 'officer@eia.example.org')!
    const res = await app.request(`${ORIGIN}/api/users/${target.id}/active`, {
      method: 'PUT', headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ active: false }),
    })
    expect(res.status).toBe(404)
  })

  it('pins creates to the org — a body naming another org is refused; a role outside the kind is refused', async () => {
    const cookie = await demoLogin('admin@nmi.example.org')
    // Another org's id in the body → 403, no account.
    const cross = await app.request(`${ORIGIN}/api/users`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ email: 'mole@nmi.example.org', name: 'Mole', role: 'viewer', orgId: 'EX1' }),
    })
    expect(cross.status).toBe(403)
    expect(await store.findUserByEmail('mole@nmi.example.org')).toBeNull()
    // A role the Utilizer kind does not carry → 403 naming the bound.
    const role = await app.request(`${ORIGIN}/api/users`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ email: 'officer@nmi.example.org', name: 'NL Officer', role: 'ia_officer' }),
    })
    expect(role.status).toBe(403)
    expect(await json(role.clone(), 403)).toMatchObject({})
    // The valid create lands IN the org.
    const ok = await app.request(`${ORIGIN}/api/users`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ email: 'colleague@nmi.example.org', name: 'NL Colleague', role: 'viewer' }),
    })
    const created = await json(ok, 201)
    expect(created.orgId).toBe('ut-nmi-nl')
    expect(created.roles).toEqual(['viewer'])
  })

  it('never assigns org_admin through the scoped grant, and never touches the org’s administrator account', async () => {
    const cookie = await demoLogin('admin@nmi.example.org')
    const create = await app.request(`${ORIGIN}/api/users`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ email: 'second-admin@nmi.example.org', name: 'Second Admin', role: 'org_admin' }),
    })
    expect(create.status).toBe(403)
    expect((await create.json()).error).toContain('BIML')
    // The org's own administrator account is the scheme operator's —
    // the scoped grant cannot re-role or deactivate it.
    const self = (await store.listUsers()).find(u => u.email === 'admin@nmi.example.org')!
    const roles = await app.request(`${ORIGIN}/api/users/${self.id}/roles`, {
      method: 'PUT', headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ role: 'viewer' }),
    })
    expect(roles.status).toBe(403)
    const active = await app.request(`${ORIGIN}/api/users/${self.id}/active`, {
      method: 'PUT', headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ active: false }),
    })
    // The org-admin guard fires before the self-deactivation guard would
    // matter (the account is the operator's either way).
    expect([400, 403]).toContain(active.status)
    expect((await store.getUserById(self.id))!.role).toBe('org_admin')
  })

  it('an org-less org admin gets the honest 403 (the grant requires the org binding)', async () => {
    await store.createLocalUser({ email: 'lost-admin@example.org', name: 'Lost Admin', role: 'org_admin', roles: ['org_admin'], orgId: null })
    const cookie = await demoLogin('lost-admin@example.org')
    const res = await app.request(`${ORIGIN}/api/users`, { headers: { cookie } })
    expect(res.status).toBe(403)
    expect((await res.json()).error).toContain('bound to an organization')
  })

  it('a staff account without the grant is refused (the missing permission, named)', async () => {
    const cookie = await demoLogin('reviewer@nmi.example.org')
    const res = await app.request(`${ORIGIN}/api/users`, { headers: { cookie } })
    expect(res.status).toBe(403)
    expect((await res.json()).error).toContain('users.manage')
  })
})

// ── the eligibility rule (the wide grant's org_admin assignment) ─────

describe('the eligibility rule (users.manage assigning org_admin)', () => {
  it('creates the org admin for a REGISTERED org…', async () => {
    const cookie = await demoLogin('admin@oiml.org')
    const res = await app.request(`${ORIGIN}/api/users`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ email: 'admin@etl.example.org', name: 'TL Admin', role: 'org_admin', orgId: '21' }),
    })
    const created = await json(res, 201)
    expect(created.roles).toEqual(['org_admin'])
    expect(created.orgId).toBe('21')
  })

  it('…and refuses the unregistered, the mid-pipeline, and the org-less binding', async () => {
    const cookie = await demoLogin('admin@oiml.org')
    // XX1 is mid-pipeline (draft Declaration) — not registered.
    const mid = await app.request(`${ORIGIN}/api/users`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ email: 'admin@dia.example.org', name: 'DIA Admin', role: 'org_admin', orgId: 'XX1' }),
    })
    expect(mid.status).toBe(400)
    expect((await mid.json()).error).toContain('not a registered participant')
    // An org the register does not carry at all.
    const unknown = await app.request(`${ORIGIN}/api/users`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ email: 'admin@fake.example.org', name: 'Fake Admin', role: 'org_admin', orgId: 'fake-org' }),
    })
    expect(unknown.status).toBe(400)
    // No org binding at all.
    const homeless = await app.request(`${ORIGIN}/api/users`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ email: 'admin@nowhere.example.org', name: 'Nowhere Admin', role: 'org_admin' }),
    })
    expect(homeless.status).toBe(400)
    expect((await homeless.json()).error).toContain('bound to its organization')
  })

  it('the roles reassignment applies the rule too (org_admin onto an unregistered org’s account is refused)', async () => {
    const cookie = await demoLogin('admin@oiml.org')
    // officer@eia.example.org sits in EX1 (registered) — fine…
    const iaTarget = (await store.listUsers()).find(u => u.email === 'officer@eia.example.org')!
    const ok = await app.request(`${ORIGIN}/api/users/${iaTarget.id}/roles`, {
      method: 'PUT', headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ role: 'ia_officer', roles: ['ia_officer', 'org_admin'] }),
    })
    expect(ok.status).toBe(200)
    // …but the demo cast's biml@oiml.org has NO org — org_admin there is refused.
    const noOrg = (await store.listUsers()).find(u => u.email === 'biml@oiml.org')!
    const refused = await app.request(`${ORIGIN}/api/users/${noOrg.id}/roles`, {
      method: 'PUT', headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ role: 'biml_officer', roles: ['biml_officer', 'org_admin'] }),
    })
    expect(refused.status).toBe(400)
    // restore the fixture state for the other legs
    await store.setUserRoles(iaTarget.id, 'ia_officer', ['ia_officer'])
  })
})

// ── the join flow ────────────────────────────────────────────────────

describe('the join flow (the org selector + the queues)', () => {
  it('the selector feed answers the REGISTERED orgs only, with the kind-bounded roles', async () => {
    const orgs = await json(await app.request(`${ORIGIN}/api/op/organizations`), 200)
    const byId = new Map(orgs.map((o: any) => [o.id, o]))
    expect(byId.has('EX1')).toBe(true)
    expect(byId.has('21')).toBe(true)
    expect(byId.has('ut-nmi-nl')).toBe(true)
    expect(byId.has('XX1')).toBe(false) // mid-pipeline — never offered
    expect((byId.get('ut-nmi-nl') as any).roles).toEqual(['viewer', 'scheme_participant'])
    expect((byId.get('EX1') as any).roles).toContain('ia_officer')
  })

  it('a request naming a REGISTERED org lands in ITS queue; the domain hint rides along', async () => {
    const res = await app.request(`${ORIGIN}/api/op/join-requests`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ name: 'Sanne Reviewer', email: 'sanne@nmi.example.org', org_id: 'ut-nmi-nl', requested_role: 'viewer', note: 'I review R 60 certificates.' }),
    })
    const created = await json(res, 201)
    expect(created.orgId).toBe('ut-nmi-nl')
    expect(created.requestedRole).toBe('viewer')
    expect(created.status).toBe('pending')

    // The org admin's queue carries it — with the domain hint true.
    const cookie = await demoLogin('admin@nmi.example.org')
    const queue = await json(await app.request(`${ORIGIN}/api/op/join-requests`, { headers: { cookie } }), 200)
    expect(queue.grant).toBe('org')
    expect(queue.orgId).toBe('ut-nmi-nl')
    const row = queue.requests.find((r: any) => r.id === created.id)
    expect(row).toBeTruthy()
    expect(row.emailDomainMatch).toBe(true)
  })

  it('refuses an unregistered org id, a role outside the kind, and a duplicate pending email', async () => {
    // An unregistered org id (never selectable in the UI; the server re-checks).
    const unregistered = await app.request(`${ORIGIN}/api/op/join-requests`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ name: 'Early Bird', email: 'early@dia.example.org', org_id: 'XX1', requested_role: 'ia_officer' }),
    })
    expect(unregistered.status).toBe(400)
    expect((await unregistered.json()).error).toContain('not on the OIML-CS participants register')
    // A role the Utilizer kind does not carry.
    const role = await app.request(`${ORIGIN}/api/op/join-requests`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ name: 'Ambitious', email: 'ambitious@nmi.example.org', org_id: 'ut-nmi-nl', requested_role: 'ia_officer' }),
    })
    expect(role.status).toBe(400)
    // The duplicate guard: sanne@ has a pending request from the leg above.
    const dup = await app.request(`${ORIGIN}/api/op/join-requests`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ name: 'Sanne Again', email: 'sanne@nmi.example.org', org_id: 'ut-nmi-nl', requested_role: 'viewer' }),
    })
    expect(dup.status).toBe(409)
  })

  it('the not-listed path lands in BIML’s queue (requested_role is honestly org_admin)', async () => {
    const res = await app.request(`${ORIGIN}/api/op/join-requests`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ name: 'New Org Contact', email: 'contact@new-nmi.example.org', org_name_text: 'Metrology Institute of Nowhere' }),
    })
    const created = await json(res, 201)
    expect(created.orgId).toBeNull()
    expect(created.orgNameText).toBe('Metrology Institute of Nowhere')
    expect(created.requestedRole).toBe('org_admin')

    // The org admin's queue does NOT carry it (the org slice only)…
    const orgCookie = await demoLogin('admin@nmi.example.org')
    const orgQueue = await json(await app.request(`${ORIGIN}/api/op/join-requests?scope=unregistered`, { headers: { cookie: orgCookie } }), 200)
    expect(orgQueue.requests.every((r: any) => r.orgId === 'ut-nmi-nl')).toBe(true)
    // …and BIML's unregistered queue does.
    const bimlCookie = await demoLogin('admin@oiml.org')
    const bimlQueue = await json(await app.request(`${ORIGIN}/api/op/join-requests?scope=unregistered`, { headers: { cookie: bimlCookie } }), 200)
    expect(bimlQueue.grant).toBe('wide')
    expect(bimlQueue.requests.map((r: any) => r.id)).toContain(created.id)
  })

  it('the org admin approves → the invite is issued (the account created with the org binding); the double decide loses', async () => {
    const cookie = await demoLogin('admin@nmi.example.org')
    const queue = await json(await app.request(`${ORIGIN}/api/op/join-requests`, { headers: { cookie } }), 200)
    const row = queue.requests.find((r: any) => r.email === 'sanne@nmi.example.org')
    const res = await app.request(`${ORIGIN}/api/op/join-requests/${row.id}/approve`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie }, body: '{}',
    })
    const decided = await json(res, 200)
    expect(decided.status).toBe('approved')
    // The invite is 02's REAL enrollment: an OP password account + the
    // one-time 24 h setup link (the seam landed against its spec, then
    // bound to its machinery when it merged).
    expect(decided.invite.delivery).toBe('enrollment-link')
    expect(decided.invite.setupUrl).toContain('/op/setup?token=')
    const account = await store.findUserByEmail('sanne@nmi.example.org')
    expect(account).toBeTruthy()
    expect(account!.orgId).toBe('ut-nmi-nl')
    expect(account!.role).toBe('viewer')
    // The enrollment token exists, is unused, and the account has no
    // password yet (the setup link sets it — one-time).
    const token = decided.invite.setupUrl.split('token=')[1]!
    const enrollment = await store.getEnrollmentToken(decodeURIComponent(token))
    expect(enrollment).toBeTruthy()
    expect(enrollment!.userId).toBe(account!.id)
    expect(enrollment!.consumedAt).toBeNull()
    expect((await store.countSignInMethods(account!.id)).password).toBe(false)
    // The atomic double-decide: a second approval is the honest 409.
    const again = await app.request(`${ORIGIN}/api/op/join-requests/${row.id}/approve`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie }, body: '{}',
    })
    expect(again.status).toBe(409)
  })

  it('the org admin refuses with a reason (a reasonless refusal is a 400)', async () => {
    await app.request(`${ORIGIN}/api/op/join-requests`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ name: 'Stranger', email: 'stranger@elsewhere.example.org', org_id: 'ut-nmi-nl', requested_role: 'viewer' }),
    })
    const cookie = await demoLogin('admin@nmi.example.org')
    const queue = await json(await app.request(`${ORIGIN}/api/op/join-requests`, { headers: { cookie } }), 200)
    const row = queue.requests.find((r: any) => r.email === 'stranger@elsewhere.example.org')
    expect(row.emailDomainMatch).toBe(false) // the hint: the domain is not the org's

    const reasonless = await app.request(`${ORIGIN}/api/op/join-requests/${row.id}/refuse`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie }, body: '{}',
    })
    expect(reasonless.status).toBe(400)
    const res = await app.request(`${ORIGIN}/api/op/join-requests/${row.id}/refuse`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ reason: 'We cannot place you — contact the NL office manager.' }),
    })
    const decided = await json(res, 200)
    expect(decided.status).toBe('refused')
    expect(decided.refusalReason).toContain('NL office manager')
    expect(await store.findUserByEmail('stranger@elsewhere.example.org')).toBeNull()
  })

  it('the org admin cannot decide another org’s request (404 — not in the slice)', async () => {
    await app.request(`${ORIGIN}/api/op/join-requests`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ name: 'IA Joiner', email: 'joiner@eia.example.org', org_id: 'EX1', requested_role: 'ia_officer' }),
    })
    const nlCookie = await demoLogin('admin@nmi.example.org')
    const iaRequest = (await store.listOrgJoinRequests({ scope: 'org', orgId: 'EX1' }))[0]!
    const res = await app.request(`${ORIGIN}/api/op/join-requests/${iaRequest.id}/approve`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie: nlCookie }, body: '{}',
    })
    expect(res.status).toBe(404)
    expect((await store.getOrgJoinRequest(iaRequest.id))!.status).toBe('pending')
  })

  it('BIML approves the not-listed request onto the NOW-REGISTERED org — the org admin is created; an unregistered target is refused', async () => {
    const cookie = await demoLogin('admin@oiml.org')
    const queue = await json(await app.request(`${ORIGIN}/api/op/join-requests?scope=unregistered`, { headers: { cookie } }), 200)
    const row = queue.requests.find((r: any) => r.email === 'contact@new-nmi.example.org')

    // The eligibility rule fires on the approval too: an org the register
    // still does not carry is refused.
    const premature = await app.request(`${ORIGIN}/api/op/join-requests/${row.id}/approve`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ org_id: 'no-such-org' }),
    })
    expect(premature.status).toBe(400)
    expect((await premature.json()).error).toContain('not a registered participant')

    // Once the participation IS registered, the approval creates the org admin.
    const res = await app.request(`${ORIGIN}/api/op/join-requests/${row.id}/approve`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ org_id: 'EX1' }),
    })
    const decided = await json(res, 200)
    expect(decided.status).toBe('approved')
    const account = await store.findUserByEmail('contact@new-nmi.example.org')
    expect(account!.role).toBe('org_admin')
    expect(account!.orgId).toBe('EX1')
  })

  it('the queues refuse a plain staff account (no grant)', async () => {
    const cookie = await demoLogin('reviewer@nmi.example.org')
    const res = await app.request(`${ORIGIN}/api/op/join-requests`, { headers: { cookie } })
    expect(res.status).toBe(403)
  })
})

// ── the direct org invites (the console's invite forms, the 02 seam) ──

describe('the org invites (POST /api/op/org-invites)', () => {
  it('the org admin invites a colleague inside its org — the enrollment link is issued once', async () => {
    const cookie = await demoLogin('admin@nmi.example.org')
    const res = await app.request(`${ORIGIN}/api/op/org-invites`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ name: 'NL Colleague Two', email: 'colleague-two@nmi.example.org', role: 'viewer' }),
    })
    const created = await json(res, 201)
    expect(created.user.orgId).toBe('ut-nmi-nl')
    expect(created.user.provider).toBe('password') // the OP account, never the demo provider
    expect(created.invite.delivery).toBe('enrollment-link')
    expect(created.invite.setupUrl).toContain('/op/setup?token=')
    const account = await store.findUserByEmail('colleague-two@nmi.example.org')
    expect(account!.orgId).toBe('ut-nmi-nl')
  })

  it('the org admin cannot invite into another org, nor with a role outside the kind, nor org_admin', async () => {
    const cookie = await demoLogin('admin@nmi.example.org')
    const crossOrg = await app.request(`${ORIGIN}/api/op/org-invites`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ name: 'Mole', email: 'mole@nmi.example.org', role: 'viewer', org_id: 'EX1' }),
    })
    expect(crossOrg.status).toBe(403)
    const outsideKind = await app.request(`${ORIGIN}/api/op/org-invites`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ name: 'Ambitious Two', email: 'ambitious2@nmi.example.org', role: 'ia_officer' }),
    })
    expect(outsideKind.status).toBe(400)
    const admin = await app.request(`${ORIGIN}/api/op/org-invites`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ name: 'Self Made', email: 'selfmade@nmi.example.org', role: 'org_admin' }),
    })
    expect(admin.status).toBe(403)
    expect(await store.findUserByEmail('mole@nmi.example.org')).toBeNull()
    expect(await store.findUserByEmail('ambitious2@nmi.example.org')).toBeNull()
    expect(await store.findUserByEmail('selfmade@nmi.example.org')).toBeNull()
  })

  it('BIML creates the org admin for a REGISTERED org through the same seam (the eligibility rule holds)', async () => {
    const cookie = await demoLogin('admin@oiml.org')
    // The unregistered target is refused…
    const refused = await app.request(`${ORIGIN}/api/op/org-invites`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ name: 'Early Admin', email: 'admin@dia.example.org', role: 'org_admin', org_id: 'XX1' }),
    })
    expect(refused.status).toBe(400)
    expect((await refused.json()).error).toContain('not a registered participant')
    // …and the registered one issues the enrollment link.
    const res = await app.request(`${ORIGIN}/api/op/org-invites`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ name: 'TL Admin Two', email: 'admin-two@etl.example.org', role: 'org_admin', org_id: '21' }),
    })
    const created = await json(res, 201)
    expect(created.user.roles).toContain('org_admin')
    expect(created.user.orgId).toBe('21')
    expect(created.invite.setupUrl).toContain('/op/setup?token=')
    // A duplicate email is the honest 409, never a second account.
    const dup = await app.request(`${ORIGIN}/api/op/org-invites`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ name: 'Again', email: 'admin-two@etl.example.org', role: 'org_admin', org_id: '21' }),
    })
    expect(dup.status).toBe(409)
  })

  it('a staff account holds no invite grant', async () => {
    const cookie = await demoLogin('reviewer@nmi.example.org')
    const res = await app.request(`${ORIGIN}/api/op/org-invites`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ name: 'Nobody', email: 'nobody@nmi.example.org', role: 'viewer' }),
    })
    expect(res.status).toBe(403)
  })
})

// ── the module gate ──────────────────────────────────────────────────

describe('the identity-module gate', () => {
  it('a non-identity profile answers 404 on the join surface', async () => {
    const profileMod = await import('@oimlsmart/platform-server/profile')
    profileMod.installInstanceProfile(profileMod.parseInstanceProfile(`
identity: { org_id: biml, org_name: BIML, role_codes: [hub] }
roles: [hub]
`))
    try {
      for (const path of ['/api/op/organizations', '/api/op/join-requests']) {
        const res = await app.request(`${ORIGIN}${path}`)
        expect(res.status, path).toBe(404)
      }
    } finally {
      profileMod.installInstanceProfile(profileMod.parseInstanceProfile(`
identity:
  org_id: oimlsmart-id
  org_name: OIML SMART Identity
  role_codes: [identity]
roles: [identity]
branding: { name: OIML SMART Identity }
demo_personas: true
`))
    }
  })
})
