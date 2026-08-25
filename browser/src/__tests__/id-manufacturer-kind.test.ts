// ─────────────────────────────────────────────────────────────────────
// TODO.register/01 — the manufacturer org kind, proven in-process: the
// REAL org-registry resolver, the REAL join-request router
// (server/routes/op-join.ts), the REAL endorsement router
// (server/routes/op-endorsements.ts), the REAL registry + users routers
// over a REAL temp SQLite store.
//
// THE DOCTRINE (TODO.register/00): a manufacturer org is NOT a PD-03
// participant — no peer assessment, no scope accreditation. Its standing
// is DECLARED on self-registration (the founder's work email declares
// the domain hint) and upgrades to IA-ENDORSED when an issuing
// authority confirms the relationship; it NEVER carries the participant
// standing. The kind bounds the roles.
//
// Covered:
//   THE KIND'S BOUNDS — orgKindRoles('manufacturer') is the
//     applicant-facing set (never org_admin, never ia_*/tl_*); the
//     org-scoped users grant refuses a role outside the bound;
//   THE STANDING — declared by default, ia-endorsed on the IA's
//     confirmation, back to declared on the withdrawal; a manufacturer
//     row NEVER reads registered (the participant posture stays the
//     scheme's);
//   THE JOIN FLOW'S MANUFACTURER BRANCH — the self-registration creates
//     the org (the audit chain carries the act), the email-domain match
//     joins the existing org instead, the founder's org_admin ask lands
//     with BIML and the member's applicant ask with the org's own
//     administrator, and the approve gate admits the active manufacturer
//     org while refusing the disabled one;
//   THE ENDORSEMENT ACTS — the grant (the IA's own officers / its org
//     admin / the registry operator), the duplicate + wrong-kind +
//     not-an-IA refusals, the cross-IA revocation refusal, and the audit
//     chain carrying every act.
// ─────────────────────────────────────────────────────────────────────

import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

// The store's DB path is read at module evaluation — set it before any
// import below touches @oimlsmart/platform-server/store/sqlite (the imports are dynamic).
const TMP = mkdtempSync(join(tmpdir(), 'oiml-mfr-kind-'))
process.env.DATABASE_PATH = join(TMP, 'test.db')
process.env.OP_ISSUER = 'http://op.test'

const ORIGIN = 'http://op.test'

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

/** The audit chain's parsed rows (the store directly). */
async function journal(): Promise<Array<{ action: string; entity_type: string; entity_id: string; user_name?: string; metadata?: Record<string, unknown> }>> {
  return (await store.listEntities('auditEvents'))
    .map(row => JSON.parse(row.data) as never)
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
  const { createOpEndorsementsRouter } = await import('../../server/routes/op-endorsements')
  const { createOpRegistryRouter } = await import('../../server/routes/op-registry')
  const { createOpAccountsRouter } = await import('../../server/routes/op-accounts')
  const root = new Hono()
  root.route('/api/auth', createAuthLeanRouter({ autoSeedDemo: true }))
  root.route('/api/users', createUsersRouter())
  root.route('/', createOpJoinRouter())
  root.route('/', createOpEndorsementsRouter())
  root.route('/', createOpRegistryRouter())
  root.route('/', createOpAccountsRouter())
  app = root

  // The registry: EX1 the demo IA (active — the endorsement's actor),
  // EX9 a second active IA (the operator's curating act), mfr-acme the
  // demo cast's manufacturer (TODO.register/01 — the platform's sample
  // id resolvable on the OP), mfr-dormant a DISABLED manufacturer (the
  // join gate's negative leg), and estate a kind-NULL non-participant.
  await store.createOrgRegistryOrg({ id: 'EX1', name: 'Example Issuing Authority', shortName: 'EIA', kind: 'issuing-authority', country: 'Example Member State', contacts: [{ name: null, email: 'office@eia.example.org' }], participantRef: 'EX1' })
  await store.createOrgRegistryOrg({ id: 'EX9', name: 'Second Example Issuing Authority', shortName: 'EIA-2', kind: 'issuing-authority', country: 'Example Member State', contacts: [{ name: null, email: 'office@eia2.example.org' }], participantRef: 'EX9' })
  await store.createOrgRegistryOrg({ id: 'mfr-acme', name: 'ACME (the demonstration manufacturer)', shortName: 'ACME', kind: 'manufacturer', country: 'Example Member State', contacts: [{ name: 'ACME Applicant', email: 'applicant@oiml.org' }], participantRef: null })
  await store.createOrgRegistryOrg({ id: 'mfr-dormant', name: 'Dormant Instruments', shortName: null, kind: 'manufacturer', country: null, contacts: [{ name: null, email: 'office@dormant.example.org' }], participantRef: null })
  await store.setOrgRegistryOrgState('mfr-dormant', 'disabled', 'the test seed')
  await store.createOrgRegistryOrg({ id: 'estate', name: 'The Estate Operator', shortName: null, kind: null, country: null, contacts: [], participantRef: null })
})

afterAll(async () => {
  const { resetInstanceProfileForTest } = await import('@oimlsmart/platform-server/profile')
  resetInstanceProfileForTest()
  rmSync(TMP, { recursive: true, force: true })
  delete process.env.DATABASE_PATH
  delete process.env.OP_ISSUER
})

// ── the kind + its bounds + the standing (the resolver) ──────────────

describe('the manufacturer kind (the resolver)', () => {
  it('bounds the assignable roles to the applicant-facing set — never org_admin, never ia_*/tl_*', async () => {
    const { orgKindRoles, isRegistryOrgKind } = await import('../../server/auth/org-registry')
    expect(orgKindRoles('manufacturer')).toEqual(['applicant', 'viewer'])
    expect(orgKindRoles('manufacturer')).not.toContain('org_admin')
    expect(orgKindRoles('manufacturer').some(r => r.startsWith('ia_') || r.startsWith('tl_') || r === 'admin' || r === 'cs_admin')).toBe(false)
    expect(isRegistryOrgKind('manufacturer')).toBe(true)
  })

  it('projects the standing per kind — and a manufacturer NEVER reads registered', async () => {
    const { resolveRegistryOrg, admitsJoinFlow } = await import('../../server/auth/org-registry')
    const mfr = (await resolveRegistryOrg(store, 'mfr-acme'))!
    expect(mfr.kind).toBe('manufacturer')
    expect(mfr.registered).toBe(false) // the participant posture is the scheme’s
    expect(mfr.standing).toBe('declared')
    expect(mfr.roles).toEqual(['applicant', 'viewer'])
    expect(mfr.emailDomain).toBe('oiml.org') // the demo contact declares the hint
    expect(admitsJoinFlow(mfr)).toBe(true)

    const ia = (await resolveRegistryOrg(store, 'EX1'))!
    expect(ia.registered).toBe(true)
    expect(ia.standing).toBe('participant')

    const plain = (await resolveRegistryOrg(store, 'estate'))!
    expect(plain.standing).toBe('non-participant')
    expect(plain.registered).toBe(false)
    expect(admitsJoinFlow(plain)).toBe(false)

    // The disabled manufacturer: the standing label never resurrects the
    // row (the lifecycle state is orthogonal) and the join gate closes.
    const dormant = (await resolveRegistryOrg(store, 'mfr-dormant'))!
    expect(dormant.standing).toBe('declared')
    expect(dormant.state).toBe('disabled')
    expect(admitsJoinFlow(dormant)).toBe(false)
  })

  it('the standing transitions: declared → ia-endorsed on the confirmation, back on the withdrawal — the row keeps the history', async () => {
    const { resolveRegistryOrg, createOrgEndorsement, revokeOrgEndorsement, listOrgEndorsements } = await import('../../server/auth/org-registry')
    const created = await createOrgEndorsement(store, { orgId: 'mfr-acme', iaOrgId: 'EX1', note: 'R 60 application on file', createdBy: 'officer@eia.example.org' })
    const endorsed = (await resolveRegistryOrg(store, 'mfr-acme'))!
    expect(endorsed.standing).toBe('ia-endorsed')
    expect(endorsed.endorsedBy).toEqual(['EX1'])
    expect(endorsed.registered).toBe(false) // NEVER the participant standing

    const revoked = await revokeOrgEndorsement(store, created.id, 'officer@eia.example.org')
    expect(revoked!.revokedAt).toBeTruthy()
    const after = (await resolveRegistryOrg(store, 'mfr-acme'))!
    expect(after.standing).toBe('declared')
    expect(after.endorsedBy).toEqual([])
    // The revocation keeps the row (the stamps, never a delete).
    const rows = await listOrgEndorsements(store, 'mfr-acme')
    expect(rows).toHaveLength(1)
    expect(rows[0]!.revokedBy).toBe('officer@eia.example.org')
  })

  it('mints the stable slug from the display name under the mfr- prefix, deduplicated', async () => {
    const { mintManufacturerOrgId } = await import('../../server/auth/org-registry')
    expect(await mintManufacturerOrgId(store, 'Minted Widgets')).toBe('mfr-minted-widgets')
    await store.createOrgRegistryOrg({ id: 'mfr-minted-widgets', name: 'Minted Widgets', kind: 'manufacturer', contacts: [] })
    expect(await mintManufacturerOrgId(store, 'Minted Widgets')).toBe('mfr-minted-widgets-2')
    expect(await mintManufacturerOrgId(store, '—')).toBe('mfr-organization')
  })
})

// ── the role bound rides the org-scoped grant (the rolesRefusal
//    machinery, routes/users.ts) ───────────────────────────────────────

describe('the manufacturer org’s people management (the kind’s bound enforced)', () => {
  it('the org-scoped manufacturer admin answers only the bound’s roles and cannot assign outside it', async () => {
    // The scheme operator's delegation (the eligibility rule: an ACTIVE
    // registry org — any kind — the demo-provider cast account signs in).
    await store.createLocalUser({ email: 'admin@acme.example.org', name: 'ACME Admin', role: 'org_admin', roles: ['org_admin'], orgId: 'mfr-acme' })
    const cookie = await demoLogin('admin@acme.example.org')

    // The bounded role map is exactly the manufacturer set.
    const map = await json(await app.request(`${ORIGIN}/api/users/roles`, { headers: { cookie } }), 200)
    expect(Object.keys(map)).toEqual(['applicant', 'viewer'])

    // A role outside the bound is the honest 403 naming it…
    const outside = await app.request(`${ORIGIN}/api/users`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ email: 'officer@acme.example.org', name: 'Ambitious', role: 'ia_officer' }),
    })
    expect(outside.status).toBe(403)
    expect(await store.findUserByEmail('officer@acme.example.org')).toBeNull()
    // …org_admin is never assignable through the scoped grant…
    const selfMade = await app.request(`${ORIGIN}/api/users`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ email: 'second-admin@acme.example.org', name: 'Self Made', role: 'org_admin' }),
    })
    expect(selfMade.status).toBe(403)
    // …and the bound's own roles land IN the org.
    const ok = await json(await app.request(`${ORIGIN}/api/users`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ email: 'colleague@acme.example.org', name: 'ACME Colleague', role: 'applicant' }),
    }), 201)
    expect(ok.orgId).toBe('mfr-acme')
    expect(ok.roles).toEqual(['applicant'])
  })
})

// ── the join flow's manufacturer branch (TODO.register/01) ───────────

describe('the join flow’s manufacturer branch', () => {
  it('the self-registration CREATES the org with the declared standing; the audit chain carries the act', async () => {
    const res = await app.request(`${ORIGIN}/api/op/join-requests`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        name: 'Sofia Founder', email: 'sofia@acme-sensors.example.org',
        org_kind: 'manufacturer', org_name_text: 'ACME Sensors', country: 'Example Member State',
        note: 'We manufacture load cells.',
      }),
    })
    const created = await json(res, 201)
    expect(created.orgId).toBe('mfr-acme-sensors')
    expect(created.requestedRole).toBe('org_admin') // the founder's ask, fixed honestly
    expect(created.organization).toEqual({ id: 'mfr-acme-sensors', name: 'ACME Sensors', created: true })

    // The org row IS the self-registration: the manufacturer kind, the
    // DECLARED standing, the founder's work email declaring the domain
    // hint — and NEVER the participant posture.
    const { resolveRegistryOrg } = await import('../../server/auth/org-registry')
    const org = (await resolveRegistryOrg(store, 'mfr-acme-sensors'))!
    expect(org.kind).toBe('manufacturer')
    expect(org.standing).toBe('declared')
    expect(org.registered).toBe(false)
    expect(org.country).toBe('Example Member State')
    expect(org.emailDomain).toBe('acme-sensors.example.org')
    expect(org.contacts).toEqual([{ name: 'Sofia Founder', email: 'sofia@acme-sensors.example.org' }])
    expect(org.createdBy).toBe('sofia@acme-sensors.example.org')

    const chain = await journal()
    const added = chain.find(e => e.action === 'organization.added' && e.entity_id === 'mfr-acme-sensors')
    expect(added).toBeTruthy()
    expect(added!.metadata).toMatchObject({ kind: 'manufacturer', self_registered: true, email: 'sofia@acme-sensors.example.org' })
    expect(added!.user_name).toBe('Sofia Founder')
  })

  it('refuses a participant kind on the self-service intake (the doctrine named) and a nameless org', async () => {
    const kind = await app.request(`${ORIGIN}/api/op/join-requests`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ name: 'Ambitious', email: 'ambitious@acme-sensors.example.org', org_kind: 'issuing-authority', org_name_text: 'ACME Authority' }),
    })
    expect(kind.status).toBe(400)
    expect((await kind.json()).error).toContain('the self-service intake declares only the manufacturer kind')
    const nameless = await app.request(`${ORIGIN}/api/op/join-requests`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ name: 'Ambitious', email: 'ambitious@acme-sensors.example.org', org_kind: 'manufacturer' }),
    })
    expect(nameless.status).toBe(400)
  })

  it('the email-domain match JOINS the existing org instead of creating a second one (the member’s applicant ask)', async () => {
    const res = await app.request(`${ORIGIN}/api/op/join-requests`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        name: 'Chen Colleague', email: 'chen@acme-sensors.example.org',
        org_kind: 'manufacturer', org_name_text: 'Acme Sensors', // the case differs — the domain decides
      }),
    })
    const created = await json(res, 201)
    expect(created.orgId).toBe('mfr-acme-sensors')
    expect(created.requestedRole).toBe('applicant') // the member's role, the kind's bound
    expect(created.organization).toEqual({ id: 'mfr-acme-sensors', name: 'ACME Sensors', created: false })
    // No second org row.
    expect(await store.getOrgRegistryOrg('mfr-acme-sensors-2')).toBeNull()

    // The deciding admin sees the kind + the domain hint honestly.
    const biml = await demoLogin('admin@oiml.org')
    const queue = await json(await app.request(`${ORIGIN}/api/op/join-requests`, { headers: { cookie: biml } }), 200)
    const row = queue.requests.find((r: any) => r.email === 'chen@acme-sensors.example.org')
    expect(row.orgKind).toBe('manufacturer')
    expect(row.orgName).toBe('ACME Sensors')
    expect(row.emailDomainMatch).toBe(true)
  })

  it('the duplicate guard covers the manufacturer path; the selector feed never lists a manufacturer org', async () => {
    const dup = await app.request(`${ORIGIN}/api/op/join-requests`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ name: 'Sofia Again', email: 'sofia@acme-sensors.example.org', org_kind: 'manufacturer', org_name_text: 'ACME Sensors' }),
    })
    expect(dup.status).toBe(409)

    const feed = await json(await app.request(`${ORIGIN}/api/op/organizations`), 200)
    const ids = feed.map((o: any) => o.id)
    expect(ids).toContain('EX1') // the participant orgs ride the intake
    expect(ids).not.toContain('mfr-acme')
    expect(ids).not.toContain('mfr-acme-sensors')
  })

  it('the submit gate refuses a disabled manufacturer org’s explicit id honestly', async () => {
    const res = await app.request(`${ORIGIN}/api/op/join-requests`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ name: 'Early Bird', email: 'early@dormant.example.org', org_id: 'mfr-dormant', requested_role: 'applicant' }),
    })
    expect(res.status).toBe(400)
    expect((await res.json()).error).toContain('not an active participant on the identity service')
  })

  it('BIML approves the founder (the extended gate admits the active manufacturer org); the enrolled founder decides the colleague’s ask', async () => {
    const biml = await demoLogin('admin@oiml.org')
    const queue = await json(await app.request(`${ORIGIN}/api/op/join-requests?scope=pending`, { headers: { cookie: biml } }), 200)
    const founderRow = queue.requests.find((r: any) => r.email === 'sofia@acme-sensors.example.org')
    expect(founderRow.requestedRole).toBe('org_admin')

    const res = await app.request(`${ORIGIN}/api/op/join-requests/${founderRow.id}/approve`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie: biml }, body: '{}',
    })
    const decided = await json(res, 200)
    expect(decided.status).toBe('approved')
    expect(decided.invite.setupUrl).toContain('/op/setup?token=')
    const founder = await store.findUserByEmail('sofia@acme-sensors.example.org')
    expect(founder!.orgId).toBe('mfr-acme-sensors')
    expect(founder!.role).toBe('org_admin')

    // The founder completes the enrollment (02's seam) and signs in…
    const token = new URL(decided.invite.setupUrl).searchParams.get('token')!
    const done = await app.request(`${ORIGIN}/api/op/enroll/${token}`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ password: 'sofia founder passphrase 2026' }),
    })
    expect(done.status).toBe(200)
    const login = await app.request(`${ORIGIN}/api/op/login`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: 'sofia@acme-sensors.example.org', password: 'sofia founder passphrase 2026' }),
    })
    expect(login.status).toBe(200)
    const founderCookie = login.headers.get('set-cookie')!.split(';')[0]!

    // …and her org's queue carries the colleague's applicant ask — the
    // manufacturer org admin decides its own people like any org's.
    const orgQueue = await json(await app.request(`${ORIGIN}/api/op/join-requests`, { headers: { cookie: founderCookie } }), 200)
    expect(orgQueue.grant).toBe('org')
    expect(orgQueue.orgId).toBe('mfr-acme-sensors')
    const colleagueRow = orgQueue.requests.find((r: any) => r.email === 'chen@acme-sensors.example.org')
    expect(colleagueRow.orgKind).toBe('manufacturer') // the kind, honestly

    const approved = await json(await app.request(`${ORIGIN}/api/op/join-requests/${colleagueRow.id}/approve`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie: founderCookie }, body: '{}',
    }), 200)
    expect(approved.status).toBe('approved')
    const colleague = await store.findUserByEmail('chen@acme-sensors.example.org')
    expect(colleague!.orgId).toBe('mfr-acme-sensors')
    expect(colleague!.role).toBe('applicant')

    // The audit chain carries every act of the arc.
    const chain = await journal()
    const approvals = chain.filter(e => e.action === 'org_join_request.approved')
    expect(approvals.map(e => e.metadata?.email)).toEqual(expect.arrayContaining(['sofia@acme-sensors.example.org', 'chen@acme-sensors.example.org']))
  })

  it('the approve gate refuses a DISABLED manufacturer org (the request waits on the lifecycle)', async () => {
    // A fresh self-registration, then the org disabled before the decision.
    await app.request(`${ORIGIN}/api/op/join-requests`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ name: 'Late Founder', email: 'late@acme-instruments.example.org', org_kind: 'manufacturer', org_name_text: 'ACME Instruments' }),
    })
    await store.setOrgRegistryOrgState('mfr-acme-instruments', 'disabled', 'the test seed')
    const biml = await demoLogin('admin@oiml.org')
    const queue = await json(await app.request(`${ORIGIN}/api/op/join-requests?scope=pending`, { headers: { cookie: biml } }), 200)
    const row = queue.requests.find((r: any) => r.email === 'late@acme-instruments.example.org')
    const res = await app.request(`${ORIGIN}/api/op/join-requests/${row.id}/approve`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie: biml }, body: '{}',
    })
    expect(res.status).toBe(400)
    expect((await res.json()).error).toContain('not an active participant on the organization registry')
    expect(await store.findUserByEmail('late@acme-instruments.example.org')).toBeNull()
    // Re-enabled, the same ask approves (the lifecycle's honesty).
    await store.setOrgRegistryOrgState('mfr-acme-instruments', 'active', 'the test seed')
    const retry = await app.request(`${ORIGIN}/api/op/join-requests/${row.id}/approve`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie: biml }, body: '{}',
    })
    expect(retry.status).toBe(200)
  })
})

// ── the endorsement acts (the standing's upgrade) ────────────────────

describe('the IA endorsement acts', () => {
  it('the IA’s own officer confirms the relationship — the standing upgrades to ia-endorsed', async () => {
    const cookie = await demoLogin('ia@oiml.org') // the demo cast's IA officer (EX1)
    const res = await app.request(`${ORIGIN}/api/op/org-endorsements`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ org_id: 'mfr-acme-sensors', ia_org_id: 'EX1', note: 'R 60 application 2026-001 on file' }),
    })
    const created = await json(res, 201)
    expect(created.standing).toBe('ia-endorsed')
    expect(created.endorsement.iaOrgId).toBe('EX1')

    // The resolver + the admin's per-org aggregate agree, honestly.
    const { resolveRegistryOrg } = await import('../../server/auth/org-registry')
    const org = (await resolveRegistryOrg(store, 'mfr-acme-sensors'))!
    expect(org.standing).toBe('ia-endorsed')
    expect(org.endorsedBy).toEqual(['EX1'])
    expect(org.registered).toBe(false) // NEVER the participant standing

    const biml = await demoLogin('admin@oiml.org')
    const view = await json(await app.request(`${ORIGIN}/api/op/registry/orgs/mfr-acme-sensors`, { headers: { cookie: biml } }), 200)
    expect(view.org.standing).toBe('ia-endorsed')
    expect(view.endorsements).toHaveLength(1)
    expect(view.endorsements[0]).toMatchObject({ iaOrgId: 'EX1', iaName: 'Example Issuing Authority', note: 'R 60 application 2026-001 on file' })
    // …and the org's audit slice carries the act.
    expect(view.activity.some((e: any) => e.action === 'organization.endorsed')).toBe(true)

    // The registry list's rows carry the standing too.
    const list = await json(await app.request(`${ORIGIN}/api/op/registry/orgs`, { headers: { cookie: biml } }), 200)
    const row = list.find((r: any) => r.id === 'mfr-acme-sensors')
    expect(row.standing).toBe('ia-endorsed')
    expect(row.endorsedBy).toEqual(['EX1'])
  })

  it('the refusals are honest: the duplicate, the wrong-kind target, the not-an-IA endorser, the anonymous, the outsider', async () => {
    const cookie = await demoLogin('ia@oiml.org')
    const dup = await app.request(`${ORIGIN}/api/op/org-endorsements`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ org_id: 'mfr-acme-sensors', ia_org_id: 'EX1' }),
    })
    expect(dup.status).toBe(409)
    // A participant org's standing is the scheme's — nothing to endorse.
    const wrongKind = await app.request(`${ORIGIN}/api/op/org-endorsements`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ org_id: 'EX9', ia_org_id: 'EX1' }),
    })
    expect(wrongKind.status).toBe(400)
    expect((await wrongKind.json()).error).toContain('MANUFACTURER organizations only')
    // A manufacturer org cannot confirm anything.
    const notIa = await app.request(`${ORIGIN}/api/op/org-endorsements`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ org_id: 'mfr-acme-sensors', ia_org_id: 'mfr-acme' }),
    })
    expect(notIa.status).toBe(400)
    expect((await notIa.json()).error).toContain('not an active issuing authority')
    // Anonymous 401…
    const anon = await app.request(`${ORIGIN}/api/op/org-endorsements`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ org_id: 'mfr-acme-sensors', ia_org_id: 'EX1' }),
    })
    expect(anon.status).toBe(401)
    // …and the manufacturer's own people hold no endorsement grant.
    const outsider = await demoLogin('applicant@oiml.org') // the ACME applicant (mfr-acme)
    const refused = await app.request(`${ORIGIN}/api/op/org-endorsements`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie: outsider },
      body: JSON.stringify({ org_id: 'mfr-acme-sensors', ia_org_id: 'EX1' }),
    })
    expect(refused.status).toBe(403)
  })

  it('the registry operator records an endorsement naming another active IA (the curating act)', async () => {
    const biml = await demoLogin('admin@oiml.org')
    const res = await app.request(`${ORIGIN}/api/op/org-endorsements`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie: biml },
      body: JSON.stringify({ org_id: 'mfr-acme-sensors', ia_org_id: 'EX9', note: 'recorded from the signed letter' }),
    })
    const created = await json(res, 201)
    expect(created.standing).toBe('ia-endorsed')
    const { resolveRegistryOrg } = await import('../../server/auth/org-registry')
    expect((await resolveRegistryOrg(store, 'mfr-acme-sensors'))!.endorsedBy.sort()).toEqual(['EX1', 'EX9'])
  })

  it('the withdrawal keeps the row + the audit; the cross-IA withdrawal is refused; the standing falls back honestly', async () => {
    const cookie = await demoLogin('ia@oiml.org')
    // The IA's officer never withdraws ANOTHER IA's confirmation.
    const cross = await app.request(`${ORIGIN}/api/op/org-endorsements/mfr-acme-sensors/EX9`, {
      method: 'DELETE', headers: { cookie },
    })
    expect(cross.status).toBe(403)

    // EX1 withdraws its own — EX9's stands, so the standing holds.
    const res = await app.request(`${ORIGIN}/api/op/org-endorsements/mfr-acme-sensors/EX1`, {
      method: 'DELETE', headers: { cookie },
    })
    const revoked = await json(res, 200)
    expect(revoked.standing).toBe('ia-endorsed')
    expect(revoked.endorsement.revokedBy).toBe('ia@oiml.org')
    // A second withdrawal finds nothing.
    const gone = await app.request(`${ORIGIN}/api/op/org-endorsements/mfr-acme-sensors/EX1`, {
      method: 'DELETE', headers: { cookie },
    })
    expect(gone.status).toBe(404)

    // The operator withdraws EX9's — the standing falls back to declared.
    const biml = await demoLogin('admin@oiml.org')
    const last = await app.request(`${ORIGIN}/api/op/org-endorsements/mfr-acme-sensors/EX9`, {
      method: 'DELETE', headers: { cookie: biml },
    })
    const final = await json(last, 200)
    expect(final.standing).toBe('declared')
    const { resolveRegistryOrg, listOrgEndorsements } = await import('../../server/auth/org-registry')
    expect((await resolveRegistryOrg(store, 'mfr-acme-sensors'))!.standing).toBe('declared')
    // Both rows kept with their revocation stamps (the history).
    expect((await listOrgEndorsements(store, 'mfr-acme-sensors')).filter(e => e.revokedAt)).toHaveLength(2)

    const chain = await journal()
    const acts = chain.filter(e => e.entity_id === 'mfr-acme-sensors' && e.entity_type === 'organization').map(e => e.action)
    expect(acts).toEqual(expect.arrayContaining([
      'organization.added',
      'organization.endorsed',
      'organization.endorsement_revoked',
    ]))
  })
})

// ── the module gate ──────────────────────────────────────────────────

describe('the identity-module gate', () => {
  it('a non-identity profile answers 404 on the endorsement surface', async () => {
    const profileMod = await import('@oimlsmart/platform-server/profile')
    profileMod.installInstanceProfile(profileMod.parseInstanceProfile(`
identity: { org_id: biml, org_name: BIML, role_codes: [hub] }
roles: [hub]
`))
    try {
      const res = await app.request(`${ORIGIN}/api/op/org-endorsements`, { method: 'POST' })
      expect(res.status).toBe(404)
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
