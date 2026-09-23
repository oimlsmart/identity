// ─────────────────────────────────────────────────────────────────────
// TODO.identity-sso/04 (the account lifecycle discipline, the tail) —
// the VERIFICATION GATE on the role grants, proven in-process over the
// REAL op-accounts + users routers against a REAL temp SQLite store
// (the id-registry / id-org-admin posture):
//
//   REFUSED    a non-empty per-client grant to a never-verified account
//              answers 409 naming the unverified primary + journals
//              account.client_roles_refused — and nothing was written;
//   EMPTY SET  the explicit-none assignment ([] grants nothing) stays
//              allowed on the same account — the corrective direction;
//   VERIFIED   the enrollment's completion (the mailbox proof) lifts the
//              gate: the same grant answers 200, audits
//              account.client_roles, and mails client_roles_granted;
//   USERS      PUT /api/users/:id/roles answers the same 409 (audit
//              user.roles_refused) for a privileged set on an unverified
//              OP account, while a demotion to the plain 'viewer'
//              baseline stays allowed (it restores the invariant);
//   CARVE-OUTS the demo cast (fictional mailboxes, unverified by design)
//              keeps its standing behavior, and the INVITE's own
//              client_roles land at invite time (the setup link IS the
//              verification channel) — the account verifies when the
//              link completes.
//
// The lifecycle: invited (unverified, unprivileged) → active — the
// registry never lets the first state carry a grant.
// ─────────────────────────────────────────────────────────────────────

import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

// The store's DB path is read at module evaluation — set it before any
// import below touches the store (the imports are dynamic).
const TMP = mkdtempSync(join(tmpdir(), 'oiml-role-grant-gate-'))
process.env.DATABASE_PATH = join(TMP, 'test.db')

const ISSUER = 'http://op.test'
process.env.OP_ISSUER = ISSUER

// The registry's bootstrap seed: the assignable client of the grant legs
// (the claims policy carries roles, no allowlist bounds them).
const CONFIDENTIAL = {
  client_id: 'hub-instance',
  name: 'OIML SMART platform hub',
  secret: 'hub-secret-123',
  redirect_uris: ['https://hub.example/api/auth/callback/oidc'],
  claims_policy: { claims: ['roles', 'groups', 'org'] },
}
process.env.OP_CLIENT_SEED = JSON.stringify([CONFIDENTIAL])

import { resetMailerForTest } from '../../server/mailer'
import { startStubMailer, type StubMailer } from '../../e2e/fixtures/stub-mailer'

let app: import('hono').Hono
let store: ReturnType<typeof import('../../server/store').getStore>
let stub: StubMailer

const PRODUCT = 'OIML SMART Identity'

function bindStubProvider(): void {
  process.env.EMAIL_FROM = 'OIML SMART Identity <no-reply@oimlsmart.org>'
  process.env.MAIL_PROVIDER_URL = `${stub.baseUrl}/emails`
  process.env.MAIL_PROVIDER_KEY = 'stub-mail-key'
  resetMailerForTest()
}

async function demoLogin(email: string): Promise<string> {
  const res = await app.request('/api/auth/demo', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password: 'demo2026' }),
  })
  expect(res.ok, `demo login ${email}`).toBe(true)
  return res.headers.get('set-cookie')!.split(';')[0]!
}

/** The bare invite (NO enrollment — the account stays unverified);
 *  answers the account id + the setup URL. */
async function inviteAccount(email: string, name: string, body: Record<string, unknown> = {}): Promise<{ id: string; setupUrl: string }> {
  const admin = await demoLogin('admin@oimlsmart.org')
  const res = await app.request('/api/op/accounts', {
    method: 'POST',
    headers: { 'content-type': 'application/json', cookie: admin },
    body: JSON.stringify({ email, name, ...body }),
  })
  expect(res.status, `the invite of ${email}`).toBe(201)
  const { account, setupUrl } = await res.json() as { account: { id: string }; setupUrl: string }
  return { id: account.id, setupUrl }
}

/** Complete the one-time setup link (the mailbox proof — stamps
 *  emailVerifiedAt; signs the account in). */
async function enroll(setupUrl: string, password: string): Promise<void> {
  const token = new URL(setupUrl).searchParams.get('token')!
  const res = await app.request(`/api/op/enroll/${token}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ password }),
  })
  expect(res.status, 'the enrollment completes').toBe(200)
}

/** The audit journal, parsed (the id-admin-dashboard helper's shape). */
async function auditRows(): Promise<Array<{ action: string; entity_type: string; entity_id: string; metadata?: Record<string, unknown> }>> {
  return (await store.listEntities('auditEvents')).map(row => JSON.parse(row.data) as never)
}

beforeAll(async () => {
  // The simulated deployment declares its signing key (the id-op-core posture).
  const { generateSuccessorPair } = await import('../../scripts/op-key-rotate')
  process.env.OP_SIGNING_KEY = (await generateSuccessorPair()).privateJwkJson

  const { installSqliteStore } = await import('../../server/store/sqlite')
  store = installSqliteStore()
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

  stub = await startStubMailer({ expectedKey: 'stub-mail-key' })
  bindStubProvider()

  const { Hono } = await import('hono')
  const { createAuthLeanRouter } = await import('../../server/routes/auth-lean')
  const { createOpAccountsRouter } = await import('../../server/routes/op-accounts')
  const { createUsersRouter } = await import('../../server/routes/users')
  const root = new Hono()
  root.route('/api/auth', createAuthLeanRouter({ autoSeedDemo: true }))
  root.route('/', createOpAccountsRouter())
  root.route('/api/users', createUsersRouter())
  app = root

  await demoLogin('admin@oimlsmart.org') // the bootstrap seed lands on the first OP request
})

afterAll(async () => {
  await stub.close()
  for (const k of ['EMAIL_FROM', 'MAIL_PROVIDER_URL', 'MAIL_PROVIDER_KEY']) delete process.env[k]
  resetMailerForTest()
  rmSync(TMP, { recursive: true, force: true })
  for (const k of ['OP_ISSUER', 'OP_SIGNING_KEY', 'OP_CLIENT_SEED', 'DATABASE_PATH']) delete process.env[k]
  const profileMod = await import('../../server/profile')
  profileMod.resetInstanceProfileForTest()
})

describe('TODO.identity-sso/04 (the lifecycle tail) — the role grants refuse the unverified account', () => {
  it('REFUSED: a non-empty per-client grant to the never-verified account is the honest 409 + the audit event', async () => {
    const admin = await demoLogin('admin@oimlsmart.org')
    const { id } = await inviteAccount('greta@example.org', 'Greta Grant')
    expect((await store.getUserById(id))?.emailVerifiedAt ?? null, 'the invited account is unverified').toBeNull()

    stub.reset()
    const grant = await app.request(`/api/op/accounts/${id}/client-roles/hub-instance`, {
      method: 'PUT',
      headers: { 'content-type': 'application/json', cookie: admin },
      body: JSON.stringify({ roles: ['ia_officer'] }),
    })
    expect(grant.status).toBe(409)
    const body = await grant.json() as { error: string }
    expect(body.error).toContain('has not verified its primary email address')
    expect(body.error).toContain('greta@example.org')

    // Nothing was written; the refusal journals its own event.
    expect(await store.getOpClientRoles(id, 'hub-instance'), 'the refused grant never lands').toBeNull()
    const audit = await auditRows()
    const refusal = audit.find(e => e.action === 'account.client_roles_refused' && e.entity_id === id)
    expect(refusal, 'the refusal is on the audit chain').toBeTruthy()
    expect(refusal!.metadata).toMatchObject({ client_id: 'hub-instance', roles: ['ia_officer'], reason: 'email_unverified' })
    expect(audit.some(e => e.action === 'account.client_roles' && e.entity_id === id), 'no grant event rides the refusal').toBe(false)
    // …and the refusal never mails a "roles granted" notice.
    expect(stub.messages.filter(m => m.subject === `New access was granted on your ${PRODUCT} account`)).toHaveLength(0)
  })

  it('EMPTY SET: the explicit-none assignment stays allowed on the unverified account (it grants nothing)', async () => {
    const admin = await demoLogin('admin@oimlsmart.org')
    const id = (await store.findUserByEmail('greta@example.org'))!.id
    const emptied = await app.request(`/api/op/accounts/${id}/client-roles/hub-instance`, {
      method: 'PUT',
      headers: { 'content-type': 'application/json', cookie: admin },
      body: JSON.stringify({ roles: [] }),
    })
    expect(emptied.status, 'the empty set is the corrective direction, never refused').toBe(200)
  })

  it('VERIFIED: the enrollment lifts the gate — the same grant lands, audits, and mails the holder', async () => {
    const admin = await demoLogin('admin@oimlsmart.org')
    const account = (await store.findUserByEmail('greta@example.org'))!
    // A fresh setup link (the invite's is still valid, but the re-issue is
    // the admin's standing act — either proves the mailbox at completion).
    const inviteRow = await app.request(`/api/op/accounts/${account.id}/enrollment`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: admin },
    })
    const { setupUrl } = await inviteRow.json() as { setupUrl: string }
    await enroll(setupUrl, 'greta has a proper passphrase')
    expect((await store.getUserById(account.id))?.emailVerifiedAt, 'the completion stamped the mailbox proof').toBeTruthy()

    stub.reset()
    const grant = await app.request(`/api/op/accounts/${account.id}/client-roles/hub-instance`, {
      method: 'PUT',
      headers: { 'content-type': 'application/json', cookie: admin },
      body: JSON.stringify({ roles: ['ia_officer'] }),
    })
    expect(grant.status).toBe(200)
    expect(await store.getOpClientRoles(account.id, 'hub-instance')).toEqual(['ia_officer'])
    const audit = await auditRows()
    expect(audit.some(e => e.action === 'account.client_roles' && e.entity_id === account.id)).toBe(true)
    const notices = stub.messages.filter(m => m.subject === `New access was granted on your ${PRODUCT} account`)
    expect(notices).toHaveLength(1)
    expect(notices[0]!.to).toBe('greta@example.org')
  })

  it('USERS: the roles reassignment refuses the privileged set on the unverified OP account (409 + audit)', async () => {
    const admin = await demoLogin('admin@oimlsmart.org')
    const { id } = await inviteAccount('ursula@example.org', 'Ursula Users')

    const grant = await app.request(`/api/users/${id}/roles`, {
      method: 'PUT',
      headers: { 'content-type': 'application/json', cookie: admin },
      body: JSON.stringify({ role: 'ia_officer', roles: ['ia_officer'] }),
    })
    expect(grant.status).toBe(409)
    expect(((await grant.json()) as { error: string }).error).toContain('has not verified its primary email address')
    const audit = await auditRows()
    const refusal = audit.find(e => e.action === 'user.roles_refused' && e.entity_id === id)
    expect(refusal, 'the users-route refusal journals its own event').toBeTruthy()
    expect(refusal!.metadata).toMatchObject({ role: 'ia_officer', reason: 'email_unverified' })
    expect((await store.getUserById(id))!.roles, 'the refused reassignment never lands').toEqual(['viewer'])
  })

  it('USERS: the demotion to the viewer baseline stays allowed on the unverified account', async () => {
    const admin = await demoLogin('admin@oimlsmart.org')
    // The invite's own roles land unprivileged-or-not (the carve-out) —
    // this one carries ia_officer; the corrective act removes it while
    // the account is STILL unverified.
    const { id, setupUrl } = await inviteAccount('victor@example.org', 'Victor Demote', { roles: ['viewer', 'ia_officer'] })
    expect((await store.getUserById(id))!.roles).toContain('ia_officer')

    const demote = await app.request(`/api/users/${id}/roles`, {
      method: 'PUT',
      headers: { 'content-type': 'application/json', cookie: admin },
      body: JSON.stringify({ role: 'viewer', roles: ['viewer'] }),
    })
    expect(demote.status, 'the demotion restores the invariant — never refused').toBe(200)
    expect((await store.getUserById(id))!.roles).toEqual(['viewer'])

    // …and once the mailbox is proven, the privileged reassignment stands.
    await enroll(setupUrl, 'victor has a proper passphrase')
    const grant = await app.request(`/api/users/${id}/roles`, {
      method: 'PUT',
      headers: { 'content-type': 'application/json', cookie: admin },
      body: JSON.stringify({ role: 'ia_officer', roles: ['ia_officer'] }),
    })
    expect(grant.status).toBe(200)
    expect((await store.getUserById(id))!.roles).toEqual(['ia_officer'])
  })

  it('CARVE-OUT: the demo cast (fictional mailboxes, unverified by design) keeps its standing behavior', async () => {
    const admin = await demoLogin('admin@oimlsmart.org')
    const biml = (await store.listUsers()).find(u => u.email === 'biml@oimlsmart.org')!
    expect(biml.provider, 'the demo cast is the demo provider').toBe('demo')
    expect(biml.emailVerifiedAt ?? null, 'the fictional mailbox never verifies').toBeNull()
    const before = biml.roles

    const grant = await app.request(`/api/users/${biml.id}/roles`, {
      method: 'PUT',
      headers: { 'content-type': 'application/json', cookie: admin },
      body: JSON.stringify({ role: 'biml_officer', roles: ['biml_officer'] }),
    })
    expect(grant.status, 'the verification gate is the OP password accounts\', never the demo cast\'s').toBe(200)
    await store.setUserRoles(biml.id, before[0] ?? 'biml_officer', before) // restore the fixture state
  })

  it('CARVE-OUT: the invite\'s own client_roles land at invite time; the account verifies at the setup link\'s completion', async () => {
    const { id, setupUrl } = await inviteAccount('ingrid@example.org', 'Ingrid Invite', {
      client_roles: [{ client_id: 'hub-instance', roles: ['ia_officer'] }],
    })
    expect(await store.getOpClientRoles(id, 'hub-instance'), 'the invite-time grant stands (the setup link is the verification channel)')
      .toEqual(['ia_officer'])
    expect((await store.getUserById(id))?.emailVerifiedAt ?? null, '…while the account is still unverified').toBeNull()

    await enroll(setupUrl, 'ingrid has a proper passphrase')
    expect((await store.getUserById(id))?.emailVerifiedAt, 'the completion stamps the verification').toBeTruthy()
  })
})
