// ─────────────────────────────────────────────────────────────────────
// TODO.identity-features/01 — multiple emails per account, proven
// in-process over the REAL op-accounts router against a REAL temp SQLite
// store (the id-account-console.test.ts posture; the mail legs ride the
// stub provider like id-mail.test.ts's section 4):
//
//   ADD            the address lands UNVERIFIED (the emails block in the
//                  context); the honest validations (malformed / own
//                  primary / another account's address OR additional);
//                  the no-mailer deployment answers 'unavailable' —
//                  never a fake ceremony;
//   UNVERIFIED     never sign-in-usable (the login refuses), never the
//                  reset's resolution, never a notice's target;
//   VERIFY         the per-address ceremony (the kind 'add' token):
//                  the context names the kind, the mailed completion
//                  verifies, the audit lands (account.email_verified);
//   SIGN-IN        the password login answers to ANY verified address
//                  (the secondary included), and so does the
//                  self-service reset (the link rides the NAMED
//                  address);
//   PRIMARY        the switch promotes a VERIFIED additional (the
//                  unverified refuses honestly), the context carries
//                  the new primary, the old primary keeps signing in;
//   REMOVE         an additional goes (sign-in by it dies); the
//                  PRIMARY refuses honestly (promote another first);
//   NOTICES        the new-sign-in notification fans out to the
//                  primary PLUS every verified additional (the stub
//                  captures both); the verification mail names the ADD;
//   ERASURE        the admin's delete carries every address out.
// ─────────────────────────────────────────────────────────────────────

import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

// The store's DB path is read at module evaluation — set it before any
// import below touches @oimlsmart/platform-server/store/sqlite (the imports are dynamic).
const TMP = mkdtempSync(join(tmpdir(), 'oiml-account-emails-'))
process.env.DATABASE_PATH = join(TMP, 'test.db')

const ISSUER = 'http://op.test'
process.env.OP_ISSUER = ISSUER

import { resetMailerForTest } from '@oimlsmart/platform-server/mailer'
import { startStubMailer, type StubMailer } from '../../e2e/fixtures/stub-mailer'

let app: import('hono').Hono
let store: ReturnType<typeof import('@oimlsmart/platform-server/store').getStore>
let stub: StubMailer

const MAIL_ENV = ['EMAIL_FROM', 'MAIL_PROVIDER_URL', 'MAIL_PROVIDER_KEY', 'MAIL_RATE_LIMIT_CAPACITY', 'MAIL_LOCALE'] as const

function clearMailEnv(): void {
  for (const k of MAIL_ENV) delete process.env[k]
  resetMailerForTest()
}

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

/** Invite + enroll an account; answers { id, cookie }. */
async function enrollAccount(email: string, name: string, password = 'a perfectly good passphrase'): Promise<{ id: string; cookie: string }> {
  const admin = await demoLogin('admin@oiml.org')
  const invite = await app.request('/api/op/accounts', {
    method: 'POST',
    headers: { 'content-type': 'application/json', cookie: admin },
    body: JSON.stringify({ email, name }),
  })
  expect(invite.status).toBe(201)
  const { account, setupUrl } = await invite.json() as { account: { id: string }; setupUrl: string }
  const token = new URL(setupUrl).searchParams.get('token')!
  const res = await app.request(`/api/op/enroll/${token}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ password }),
  })
  expect(res.status).toBe(200)
  return { id: account.id, cookie: res.headers.get('set-cookie')!.split(';')[0]! }
}

async function passwordLogin(email: string, password: string): Promise<Response> {
  return app.request('/api/op/login', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password }),
  })
}

interface EmailRow { email: string; isPrimary: boolean; verifiedAt: string | null; createdAt: string }

async function emailsOf(cookie: string): Promise<EmailRow[]> {
  const res = await app.request('/api/op/account', { headers: { cookie } })
  expect(res.status).toBe(200)
  return ((await res.json()) as { emails: EmailRow[] }).emails
}

/** The account's own audit actions (the activity feed's source). */
async function auditActions(userId: string): Promise<string[]> {
  return (await store.listEntities('auditEvents'))
    .map(r => JSON.parse(r.data) as { entity_id: string; action: string })
    .filter(e => e.entity_id === userId)
    .map(e => e.action)
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

  stub = await startStubMailer({ expectedKey: 'stub-mail-key' })
  clearMailEnv()

  const { Hono } = await import('hono')
  const { createAuthLeanRouter } = await import('../../server/routes/auth-lean')
  const { createOpAccountsRouter } = await import('../../server/routes/op-accounts')
  const root = new Hono()
  root.route('/api/auth', createAuthLeanRouter({ autoSeedDemo: true }))
  root.route('/', createOpAccountsRouter())
  app = root
  await demoLogin('admin@oiml.org')
})

afterAll(async () => {
  await stub.close()
  clearMailEnv()
  rmSync(TMP, { recursive: true, force: true })
  delete process.env.OP_ISSUER
  delete process.env.DATABASE_PATH
  const profileMod = await import('@oimlsmart/platform-server/profile')
  profileMod.resetInstanceProfileForTest()
})

describe('the additional-address add', () => {
  it('lands the address UNVERIFIED in the context; the no-mailer delivery is honest', async () => {
    const { cookie } = await enrollAccount('anna@example.org', 'Anna Example')
    expect((await emailsOf(cookie)).map(e => `${e.email}:${e.isPrimary}:${e.verifiedAt === null ? 'unverified' : 'verified'}`))
      .toEqual(['anna@example.org:true:verified']) // the enrollment verified the primary

    const res = await app.request('/api/op/account/emails', {
      method: 'POST', headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ email: ' Anna.Alias@Example.ORG ' }),
    })
    expect(res.status).toBe(201)
    expect(await res.json()).toMatchObject({ email: 'anna.alias@example.org', verified: false, delivery: 'unavailable' })

    const list = await emailsOf(cookie)
    expect(list.length).toBe(2)
    expect(list[1]).toMatchObject({ email: 'anna.alias@example.org', isPrimary: false, verifiedAt: null })
  })

  it('validates honestly: malformed, the own primary, another account\'s address, another account\'s additional', async () => {
    const { cookie } = await enrollAccount('boris@example.org', 'Boris Example')
    await app.request('/api/op/account/emails', {
      method: 'POST', headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ email: 'boris.alias@example.org' }),
    })
    const other = await enrollAccount('cora@example.org', 'Cora Example')

    const ask = (email: string, as = cookie) => app.request('/api/op/account/emails', {
      method: 'POST', headers: { 'content-type': 'application/json', cookie: as },
      body: JSON.stringify({ email }),
    })
    expect((await ask('not-an-address')).status).toBe(400)
    expect((await ask('boris@example.org')).status).toBe(400) // its own primary
    expect((await ask('cora@example.org')).status).toBe(409) // another account's primary
    expect((await ask('boris.alias@example.org', other.cookie)).status).toBe(409) // another account's additional
    expect((await ask('admin@oiml.org')).status).toBe(409) // a demo-cast address
    // The idempotent re-add of the account's OWN row: 201 again, one row only.
    expect((await ask('boris.alias@example.org')).status).toBe(201)
    expect((await emailsOf(cookie)).length).toBe(2)
  })

  it('the unverified additional never signs in and never resolves the reset', async () => {
    const { cookie } = await enrollAccount('dana@example.org', 'Dana Example')
    await app.request('/api/op/account/emails', {
      method: 'POST', headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ email: 'dana.alias@example.org' }),
    })
    const login = await passwordLogin('dana.alias@example.org', 'a perfectly good passphrase')
    expect(login.status).toBe(401)

    // The reset answers the same 200 either way (never an oracle)…
    bindStubProvider()
    stub.reset()
    const reset = await app.request('/api/op/login/reset', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: 'dana.alias@example.org' }),
    })
    expect(reset.status).toBe(200)
    // …but NO reset mail rides an unproven address.
    expect(stub.messages.length).toBe(0)
    clearMailEnv()
  })

  it('the resend refuses honestly without a mailer (503), and the already-verified refuses', async () => {
    const { id, cookie } = await enrollAccount('elia@example.org', 'Elia Example')
    await app.request('/api/op/account/emails', {
      method: 'POST', headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ email: 'elia.alias@example.org' }),
    })
    const resend = await app.request('/api/op/account/emails/elia.alias%40example.org/verification', {
      method: 'POST', headers: { cookie },
    })
    expect(resend.status).toBe(503)
    expect(await resend.json()).toMatchObject({ mailAvailable: false })

    // The verified additional refuses the resend.
    await store.markAccountEmailVerified(id, 'elia.alias@example.org')
    const again = await app.request('/api/op/account/emails/elia.alias%40example.org/verification', {
      method: 'POST', headers: { cookie },
    })
    expect(again.status).toBe(409)
  })
})

describe('the per-address verification ceremony (the kind add link)', () => {
  it('the mailed link verifies; the context names the kind; the sign-in follows; the audit lands', async () => {
    const { id, cookie } = await enrollAccount('fiona@example.org', 'Fiona Example')
    await app.request('/api/op/account/emails', {
      method: 'POST', headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ email: 'fiona.alias@example.org' }),
    })

    // The mailer-delivered link (the store seam stands in for 09's send —
    // the id-account-console posture; the full send leg is below).
    const { mintEnrollmentToken } = await import('../../server/auth/op/accounts')
    const token = mintEnrollmentToken()
    await store.createEmailChangeToken({
      token, userId: id, newEmail: 'fiona.alias@example.org', deliveredBy: 'mailer', kind: 'add', ttlMs: 60_000,
    })

    // The public context names the ceremony, nothing more.
    const context = await app.request(`/api/op/email-change/${token}`)
    expect(context.status).toBe(200)
    const body = await context.json() as Record<string, unknown>
    expect(body).toMatchObject({ name: 'Fiona Example', email: 'fiona@example.org', newEmail: 'fiona.alias@example.org', kind: 'add' })
    expect(Object.keys(body).sort()).toEqual(['email', 'expiresAt', 'kind', 'name', 'newEmail'])

    const complete = await app.request(`/api/op/email-change/${token}`, { method: 'POST' })
    expect(complete.status).toBe(200)
    expect(await complete.json()).toMatchObject({ ok: true, email: 'fiona.alias@example.org', verified: true, kind: 'add' })
    // One-time means one-time.
    expect((await app.request(`/api/op/email-change/${token}`, { method: 'POST' })).status).toBe(410)

    // The secondary signs in now; the primary still does.
    const login = await passwordLogin('fiona.alias@example.org', 'a perfectly good passphrase')
    expect(login.status).toBe(200)
    expect((await login.json() as { email: string }).email).toBe('fiona@example.org') // the claims' source: the primary
    expect((await passwordLogin('fiona@example.org', 'a perfectly good passphrase')).status).toBe(200)

    // The audit chain carries the add + the verify.
    const actions = await auditActions(id)
    expect(actions).toContain('account.email_added')
    expect(actions).toContain('account.email_verified')
  })

  it('the add route SENDS the verification when a mailer is bound (the stub captures it, the link completes)', async () => {
    bindStubProvider()
    stub.reset()
    const { id } = await enrollAccount('gwen@example.org', 'Gwen Example')
    const admin = await demoLogin('admin@oiml.org')
    void admin
    const cookie = (await passwordLogin('gwen@example.org', 'a perfectly good passphrase')).headers.get('set-cookie')!.split(';')[0]!

    const res = await app.request('/api/op/account/emails', {
      method: 'POST', headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ email: 'gwen.alias@example.org' }),
    })
    expect(res.status).toBe(201)
    expect(await res.json()).toMatchObject({ email: 'gwen.alias@example.org', verified: false, delivery: 'mailer' })

    // The stub captured the add's verification exactly once: to the
    // ADDED address, the add's own subject (never the "account is
    // moving" copy). The earlier legs of this test (the invite, the
    // sign-in notice) mailed too — the filter names THIS message.
    const verificationMails = stub.messages.filter(m => m.to === 'gwen.alias@example.org')
    expect(verificationMails.length).toBe(1)
    const mail = verificationMails[0]!
    expect(mail.to).toBe('gwen.alias@example.org')
    expect(mail.subject).toContain('added')
    const link = mail.text!.match(/https?:\/\/\S+/)![0]
    expect(link).toContain('/op/email-change?token=')

    // The mailed link verifies; the sign-in notification fans out to
    // BOTH proven addresses.
    const token = new URL(link).searchParams.get('token')!
    expect((await app.request(`/api/op/email-change/${token}`, { method: 'POST' })).status).toBe(200)
    stub.reset()
    expect((await passwordLogin('gwen.alias@example.org', 'a perfectly good passphrase')).status).toBe(200)
    const signinMails = stub.messages.filter(m => m.subject?.includes('New sign-in'))
    expect(signinMails.map(m => m.to).sort()).toEqual(['gwen.alias@example.org', 'gwen@example.org'])

    // The audit chain carries the add (the mailer delivery).
    expect(await auditActions(id)).toContain('account.email_added')
    clearMailEnv()
  })

  it('the reset resolves a VERIFIED additional and rides the NAMED address', async () => {
    const { id } = await enrollAccount('hugo@example.org', 'Hugo Example')
    await store.addAccountEmail(id, 'hugo.alias@example.org')
    await store.markAccountEmailVerified(id, 'hugo.alias@example.org')

    bindStubProvider()
    stub.reset()
    const reset = await app.request('/api/op/login/reset', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: 'hugo.alias@example.org' }),
    })
    expect(reset.status).toBe(200)
    expect(stub.messages.length).toBe(1)
    expect(stub.messages[0]!.to).toBe('hugo.alias@example.org')
    expect(stub.messages[0]!.text).toContain('/op/setup?token=')
    clearMailEnv()
  })
})

describe('the primary switch + the removal', () => {
  it('promotes only a VERIFIED additional; the old primary keeps signing in; the context carries the switch', async () => {
    const { id, cookie } = await enrollAccount('iris@example.org', 'Iris Example')
    await app.request('/api/op/account/emails', {
      method: 'POST', headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ email: 'iris.alias@example.org' }),
    })

    const promote = () => app.request('/api/op/account/emails/primary', {
      method: 'POST', headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ email: 'iris.alias@example.org' }),
    })
    expect((await promote()).status).toBe(409) // unverified refuses honestly

    await store.markAccountEmailVerified(id, 'iris.alias@example.org')
    const ok = await promote()
    expect(ok.status).toBe(200)
    expect(await ok.json()).toMatchObject({ ok: true, email: 'iris.alias@example.org' })

    // The context carries the new primary (the claims' source moved);
    // the old primary stands as a VERIFIED additional.
    const after = await app.request('/api/op/account', { headers: { cookie } })
    const body = await after.json() as { account: { email: string; emailVerifiedAt: string | null }; emails: EmailRow[] }
    expect(body.account.email).toBe('iris.alias@example.org')
    expect(body.account.emailVerifiedAt).not.toBeNull()
    expect(body.emails.map(e => `${e.email}:${e.isPrimary}:${e.verifiedAt === null ? 'unverified' : 'verified'}`))
      .toEqual(['iris.alias@example.org:true:verified', 'iris@example.org:false:verified'])

    // Both addresses sign in.
    expect((await passwordLogin('iris@example.org', 'a perfectly good passphrase')).status).toBe(200)
    expect((await passwordLogin('iris.alias@example.org', 'a perfectly good passphrase')).status).toBe(200)

    expect(await auditActions(id)).toContain('account.email_primary_changed')
  })

  it('removes an additional (sign-in by it dies); the PRIMARY refuses honestly; the unknown 404s', async () => {
    const { id, cookie } = await enrollAccount('jules@example.org', 'Jules Example')
    await app.request('/api/op/account/emails', {
      method: 'POST', headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ email: 'jules.alias@example.org' }),
    })
    await store.markAccountEmailVerified(id, 'jules.alias@example.org')
    expect((await passwordLogin('jules.alias@example.org', 'a perfectly good passphrase')).status).toBe(200)

    const removePrimary = await app.request('/api/op/account/emails/jules%40example.org', {
      method: 'DELETE', headers: { cookie },
    })
    expect(removePrimary.status).toBe(409) // the primary is never removed
    expect((await removePrimary.json() as { error: string }).error).toContain('primary')

    const unknown = await app.request('/api/op/account/emails/never%40example.org', {
      method: 'DELETE', headers: { cookie },
    })
    expect(unknown.status).toBe(404)

    const remove = await app.request('/api/op/account/emails/jules.alias%40example.org', {
      method: 'DELETE', headers: { cookie },
    })
    expect(remove.status).toBe(200)
    expect((await emailsOf(cookie)).length).toBe(1)
    expect((await passwordLogin('jules.alias@example.org', 'a perfectly good passphrase')).status).toBe(401)

    expect(await auditActions(id)).toContain('account.email_removed')
  })

  it('another account\'s rows are never reachable through the session', async () => {
    const { cookie } = await enrollAccount('kara@example.org', 'Kara Example')
    const other = await enrollAccount('liam@example.org', 'Liam Example')
    await store.addAccountEmail(other.id, 'liam.alias@example.org')

    const remove = await app.request('/api/op/account/emails/liam.alias%40example.org', {
      method: 'DELETE', headers: { cookie },
    })
    expect(remove.status).toBe(404)
    const resend = await app.request('/api/op/account/emails/liam.alias%40example.org/verification', {
      method: 'POST', headers: { cookie },
    })
    expect(resend.status).toBe(404)
    const promote = await app.request('/api/op/account/emails/primary', {
      method: 'POST', headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ email: 'liam.alias@example.org' }),
    })
    expect(promote.status).toBe(404)
  })
})

describe('the erasure', () => {
  it('the admin\'s delete carries every address out', async () => {
    const { id } = await enrollAccount('mona@example.org', 'Mona Example')
    await store.addAccountEmail(id, 'mona.alias@example.org')
    await store.markAccountEmailVerified(id, 'mona.alias@example.org')
    expect((await passwordLogin('mona.alias@example.org', 'a perfectly good passphrase')).status).toBe(200)

    const admin = await demoLogin('admin@oiml.org')
    const erase = await app.request(`/api/op/accounts/${id}`, { method: 'DELETE', headers: { cookie: admin } })
    expect(erase.status).toBe(200)

    expect(await store.findUserByAnyEmail('mona.alias@example.org')).toBeNull()
    expect((await passwordLogin('mona.alias@example.org', 'a perfectly good passphrase')).status).toBe(401)
    expect((await passwordLogin('mona@example.org', 'a perfectly good passphrase')).status).toBe(401)
  })
})
