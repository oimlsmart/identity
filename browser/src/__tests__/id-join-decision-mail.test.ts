// ─────────────────────────────────────────────────────────────────────
// The join decision loop closes by mail (2026-10-14) — proven in-process
// over the REAL op-join router against a REAL temp SQLite store + the
// stub mailer (the id-manufacturer-kind harness, the stub binding from
// id-role-grant-gate):
//
//   FILED     every QUEUE door's filing acks the requester by mail:
//             the register-org and manufacturer-join requests name the
//             organization's administrator; the manufacturer-founding
//             and not-listed requests name the BIML secretariat; every
//             ack carries the "did not file it" line (a filing against
//             a stranger's address tells the stranger, who ignores it
//             safely — nothing proceeds without the invitation only
//             their mailbox can accept);
//   BIML      the BIML door files NO ack — the setup link IS the
//             receipt, and the door's mail is the invite alone;
//   DUP       the duplicate guard answers 409 and mails nothing;
//   REFUSED   the refusal mails the requester the decision and the
//             required reason — email is the only channel that reaches
//             an account that does not exist yet;
//   APPROVED  the approve path keeps its invite mail (the regression
//             guard).
// ─────────────────────────────────────────────────────────────────────

import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

const TMP = mkdtempSync(join(tmpdir(), 'oiml-join-decision-mail-'))
process.env.DATABASE_PATH = join(TMP, 'test.db')
process.env.OP_ISSUER = 'http://op.test'

const ORIGIN = 'http://op.test'

let app: import('hono').Hono
let store: ReturnType<typeof import('../../server/store').getStore>
let stub: import('../../e2e/fixtures/stub-mailer').StubMailer

async function demoLogin(email: string): Promise<string> {
  const res = await app.request(`${ORIGIN}/api/auth/demo`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password: 'demo2026' }),
  })
  expect(res.ok, `demo login ${email}`).toBe(true)
  return res.headers.get('set-cookie')!.split(';')[0]!
}

async function fileRequest(body: Record<string, unknown>): Promise<Response> {
  return await app.request(`${ORIGIN}/api/op/join-requests`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  })
}

beforeAll(async () => {
  const { installSqliteStore } = await import('../../server/store/sqlite')
  store = installSqliteStore()
  // The composition root's own act (server/index.ts installs the map
  // at boot; a harness that skips it inherits whatever the previous
  // suite installed). The identity profile declares no rbac section, so
  // the default map stands — install it explicitly, never inherit.
  const { installRbacMap } = await import('../../server/rbac')
  const { DEFAULT_ROLE_PERMISSIONS } = await import('../../server/vocab/rbac')
  installRbacMap(DEFAULT_ROLE_PERMISSIONS)
  const profileMod = await import('../../server/profile')
  profileMod.installInstanceProfile(profileMod.parseInstanceProfile(`
identity:
  org_id: oimlsmart-id
  org_name: OIML SMART Identity
  role_codes: [identity]
roles: [identity]
branding: { name: OIML SMART Identity }
demo_personas: true
`))

  const { startStubMailer } = await import('../../e2e/fixtures/stub-mailer')
  stub = await startStubMailer({ expectedKey: 'stub-mail-key' })
  process.env.EMAIL_FROM = 'OIML SMART Identity <no-reply@oimlsmart.org>'
  process.env.MAIL_PROVIDER_URL = `${stub.baseUrl}/emails`
  process.env.MAIL_PROVIDER_KEY = 'stub-mail-key'
  const mailerMod = await import('../../server/mailer')
  mailerMod.resetMailerForTest()

  const { Hono } = await import('hono')
  const { createAuthLeanRouter } = await import('../../server/routes/auth-lean')
  const { createOpJoinRouter } = await import('../../server/routes/op-join')
  const root = new Hono()
  root.route('/api/auth', createAuthLeanRouter({ autoSeedDemo: true }))
  root.route('/', createOpJoinRouter())
  app = root

  // The register: one active IA (the register door's target) + its
  // organization administrator (the queue's decider).
  await store.createOrgRegistryOrg({ id: 'EX1', name: 'Example Issuing Authority', shortName: 'EIA', kind: 'issuing-authority', country: 'Example Member State', contacts: [{ name: null, email: 'office@eia.example.org' }], participantRef: 'EX1' })
  const created = await store.createOpAccount({ email: 'gatekeeper@eia.example', name: 'Gate Keeper', role: 'org_admin', roles: ['org_admin'], orgId: 'EX1', emailVerified: true })
  expect(created, 'the org admin seeds').toBeTruthy()
  // The demo cast seeds on the first AUTH request in production — the
  // doorbell legs file before any login, so the wide deciders must
  // exist here.
  await store.seedDemoAccounts()
})

afterAll(async () => {
  await stub.close()
  for (const k of ['EMAIL_FROM', 'MAIL_PROVIDER_URL', 'MAIL_PROVIDER_KEY']) delete process.env[k]
  const mailerMod = await import('../../server/mailer')
  mailerMod.resetMailerForTest()
  const { resetInstanceProfileForTest } = await import('../../server/profile')
  resetInstanceProfileForTest()
  const { installRbacMap: resetRbac } = await import('../../server/rbac')
  resetRbac(null)
  rmSync(TMP, { recursive: true, force: true })
  delete process.env.DATABASE_PATH
  delete process.env.OP_ISSUER
})

describe('the join decision loop closes by mail', () => {
  it('FILED: the register-org door acks the requester — the org name, its administrator, the ignore line', async () => {
    stub.reset()
    const res = await fileRequest({ given_name: 'Rita', family_name: 'Register', email: 'rita@eia.example', org_id: 'EX1', requested_role: 'ia_officer' })
    expect(res.status, 'the filing answers 201').toBe(201)
    const acks = stub.messages.filter(m => m.to === 'rita@eia.example')
    expect(acks.length, 'exactly one ack').toBe(1)
    expect(acks[0]!.subject).toContain('received')
    expect(acks[0]!.text).toContain('Example Issuing Authority')
    expect(acks[0]!.text).toContain("organization's administrator")
    expect(acks[0]!.text).toContain('did not file')
    // THE DOORBELL: the org's decider learns a request waits.
    const bells = stub.messages.filter(m => m.to === 'gatekeeper@eia.example')
    expect(bells.length, 'exactly one decider notice').toBe(1)
    expect((bells[0]!.subject ?? '')).toContain('awaits review')
    expect(bells[0]!.text).toContain('Example Issuing Authority')
    expect(bells[0]!.text).toContain('Rita')
    expect(bells[0]!.text).toContain('ia_officer')
    expect(bells[0]!.text).toContain('review')
  })

  it('FILED: the not-listed door acks — the BIML secretariat decides', async () => {
    stub.reset()
    const res = await fileRequest({ given_name: 'Nora', family_name: 'Notlisted', email: 'nora@new-institute.example', org_name_text: 'New Metrology Institute' })
    expect(res.status).toBe(201)
    const acks = stub.messages.filter(m => m.to === 'nora@new-institute.example')
    expect(acks.length, 'exactly one ack').toBe(1)
    expect(acks[0]!.text).toContain('New Metrology Institute')
    expect(acks[0]!.text).toContain('BIML secretariat')
    expect(acks[0]!.text).toContain('did not file')
    // The secretariat queue's deciders (the users.manage holders) hear
    // the doorbell too.
    const bells = stub.messages.filter(m => m.to === 'admin@oimlsmart.org')
    expect(bells.length, 'the wide decider is rung').toBe(1)
    expect(bells[0]!.text).toContain('New Metrology Institute')
  })

  it('FILED: the manufacturer founding acks — the BIML secretariat confirms', async () => {
    stub.reset()
    const res = await fileRequest({ given_name: 'Fiona', family_name: 'Founder', email: 'fiona@fresh-instruments.example', org_kind: 'manufacturer', org_name_text: 'Fresh Instruments Ltd.', country: 'Lilliput' })
    expect(res.status).toBe(201)
    const acks = stub.messages.filter(m => m.to === 'fiona@fresh-instruments.example')
    expect(acks.length, 'exactly one ack').toBe(1)
    expect(acks[0]!.text).toContain('Fresh Instruments Ltd.')
    expect(acks[0]!.text).toContain('BIML secretariat')
  })

  it('FILED: the BIML door mails the invite only — no ack on top', async () => {
    stub.reset()
    const res = await fileRequest({ given_name: 'Bea', family_name: 'Bureau', email: 'bea@oiml.org', org_kind: 'biml' })
    expect(res.status).toBe(201)
    const mails = stub.messages.filter(m => m.to === 'bea@oiml.org')
    expect(mails.length, 'the invite alone (the link is the receipt)').toBe(1)
    expect(mails[0]!.text).toContain('setup')
  })

  it('DUP: the duplicate guard answers 409 and mails nothing', async () => {
    stub.reset()
    const res = await fileRequest({ given_name: 'Rita', family_name: 'Register', email: 'rita@eia.example', org_id: 'EX1', requested_role: 'viewer' })
    expect(res.status).toBe(409)
    expect(stub.messages.filter(m => m.to === 'rita@eia.example')).toHaveLength(0)
  })

  it('REFUSED: the refusal mails the requester the decision and the required reason', async () => {
    const filed = await fileRequest({ given_name: 'Rex', family_name: 'Refused', email: 'rex@eia.example', org_id: 'EX1', requested_role: 'viewer' })
    expect(filed.status).toBe(201)
    const request = await filed.json() as { id: string }
    const admin = await demoLogin('admin@oimlsmart.org')
    stub.reset()

    const refused = await app.request(`${ORIGIN}/api/op/join-requests/${request.id}/refuse`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: admin },
      body: JSON.stringify({ reason: 'ask your team lead to file with their address' }),
    })
    expect(refused.status, 'the refusal lands').toBe(200)

    const notices = stub.messages.filter(m => m.to === 'rex@eia.example')
    expect(notices.length, 'exactly one refusal notice').toBe(1)
    expect((notices[0]!.subject ?? '').toLowerCase()).toContain('declined')
    expect(notices[0]!.text).toContain('Example Issuing Authority')
    expect(notices[0]!.text).toContain('ask your team lead to file with their address')
  })

  it('APPROVED: the approve path keeps its invite mail', async () => {
    const filed = await fileRequest({ given_name: 'Ada', family_name: 'Approved', email: 'ada@eia.example', org_id: 'EX1', requested_role: 'viewer' })
    expect(filed.status).toBe(201)
    const request = await filed.json() as { id: string }
    const admin = await demoLogin('admin@oimlsmart.org')
    stub.reset()

    const approved = await app.request(`${ORIGIN}/api/op/join-requests/${request.id}/approve`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: admin },
      body: JSON.stringify({ role: 'viewer' }),
    })
    expect(approved.status).toBe(200)
    const invites = stub.messages.filter(m => m.to === 'ada@eia.example')
    expect(invites.length, 'the invite mail rides the approval').toBe(1)
    expect(invites[0]!.text).toContain('setup')
  })
})
