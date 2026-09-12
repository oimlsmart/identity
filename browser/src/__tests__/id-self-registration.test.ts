// ─────────────────────────────────────────────────────────────────────
// TODO.restructure/05 — the public self-registration, proven in-process
// over the REAL op-accounts router against a REAL temp SQLite store
// (the id-email-verification round-trip posture):
//
//   THE ARC      register → 201 'mailed' + the verify link captured by
//                the stub mailer → the password signs in AT ONCE with
//                email_verified honest-false → the emailed link
//                completes → the stamp stands;
//   THE DUP      a second register on the same address answers the
//                honest 409 (the sign-in/reset pointer);
//   THE POLICY   a short password is refused before any row lands;
//   NO MAILER    a console-posture deployment answers 503 and creates
//                NOTHING (an unprovable mailbox never strands an
//                account in the unverified state).
// ─────────────────────────────────────────────────────────────────────

import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

const TMP = mkdtempSync(join(tmpdir(), 'oiml-self-registration-'))
process.env.DATABASE_PATH = join(TMP, 'test.db')

const ISSUER = 'http://op.test'
process.env.OP_ISSUER = ISSUER

import { resetMailerForTest } from '../../server/mailer'
import { startStubMailer, type StubMailer } from '../../e2e/fixtures/stub-mailer'

let app: import('hono').Hono
let store: ReturnType<typeof import('../../server/store').getStore>
let stub: StubMailer

const APPLICANT = {
  email: 'applicant@example.org',
  name: 'Applicant Example',
  password: 'a long enough passphrase',
}
const SECOND = { email: 'second.applicant@example.org', name: 'Second Applicant', password: 'another proper passphrase 12+' }

/** Bind the stub provider (the mailer posture turns live). */
function bindStubProvider(): void {
  process.env.EMAIL_FROM = 'OIML SMART Identity <no-reply@oimlsmart.org>'
  process.env.MAIL_PROVIDER_URL = `${stub.baseUrl}/emails`
  process.env.MAIL_PROVIDER_KEY = 'stub-mail-key'
  resetMailerForTest()
}

/** Drop the mailer env (the console posture). */
function unbindMailer(): void {
  for (const k of ['EMAIL_FROM', 'MAIL_PROVIDER_URL', 'MAIL_PROVIDER_KEY']) delete process.env[k]
  resetMailerForTest()
}

async function register(payload: Record<string, unknown>): Promise<Response> {
  return app.request('/api/op/register', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(payload),
  })
}

async function passwordLogin(email: string, password: string): Promise<Response> {
  return app.request('/api/op/login', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password }),
  })
}

/** The one link line of a captured email's text body. */
function linkFromEmailText(text: string | undefined): string {
  const link = (text ?? '').split('\n').map(l => l.trim()).find(l => l.startsWith('http'))
  expect(link, 'the email text carries its action link').toBeTruthy()
  return link!
}

beforeAll(async () => {
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

  const oidc = await import('../../server/oidc')
  oidc.clearOidcCaches()

  stub = await startStubMailer({ expectedKey: 'stub-mail-key' })

  const { Hono } = await import('hono')
  const { createAuthLeanRouter } = await import('../../server/routes/auth-lean')
  const { createOpRouter } = await import('../../server/routes/op')
  const { createOpAccountsRouter } = await import('../../server/routes/op-accounts')
  const root = new Hono()
  root.route('/api/auth', createAuthLeanRouter({ autoSeedDemo: true }))
  root.route('/', createOpRouter())
  root.route('/', createOpAccountsRouter())
  app = root
  await app.request('/api/auth/demo', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ email: 'admin@oiml.org', password: 'demo2026' }) })
})

afterAll(async () => {
  await stub.close()
  unbindMailer()
  rmSync(TMP, { recursive: true, force: true })
  delete process.env.OP_ISSUER
  delete process.env.OP_SIGNING_KEY
  delete process.env.DATABASE_PATH
  const profileMod = await import('../../server/profile')
  profileMod.resetInstanceProfileForTest()
})

describe('TODO.restructure/05 — the public self-registration', () => {
  it('NO MAILER: the console posture answers 503 and creates NOTHING', async () => {
    unbindMailer()
    const res = await register(SECOND)
    expect(res.status, 'the honest refusal').toBe(503)
    expect(await store.findUserByEmail(SECOND.email)).toBeNull()
  })

  it('THE POLICY: a short password is refused before any row lands', async () => {
    bindStubProvider()
    const res = await register({ name: 'Short P. Word', email: 'short@example.org', password: 'short' })
    expect(res.status).toBe(400)
    expect(await store.findUserByEmail('short@example.org')).toBeNull()
  })

  it('THE ARC: register → the mailed verify link → sign-in now, verified after the link', async () => {
    stub.reset()
    const res = await register(APPLICANT)
    expect(res.status, 'the account stands').toBe(201)
    expect(await res.json()).toMatchObject({ email: APPLICANT.email, verification: 'mailed' })

    // The verify link rode the mail — never the answer body.
    const mails = stub.messages.filter(m => m.to === APPLICANT.email)
    expect(mails.length, 'the verify mail was sent').toBe(1)
    const verifyUrl = linkFromEmailText(mails[0]!.text)
    expect(verifyUrl).toContain('/op/email-change?token=')

    // The audit chain carries the act.
    const events = await store.listEntities('auditEvents')
    expect(JSON.stringify(events)).toContain('account.self_registered')

    // The password signs in AT ONCE — the address reads unverified.
    const signIn = await passwordLogin(APPLICANT.email, APPLICANT.password)
    expect(signIn.status, 'the fresh credential signs in').toBe(200)
    const cookie = signIn.headers.get('set-cookie')!.split(';')[0]!
    const context = await app.request('/api/op/account', { headers: { cookie } })
    const { account } = await context.json() as { account: { emailVerifiedAt: string | null } }
    expect(account.emailVerifiedAt, 'the unproven mailbox reads unverified').toBeNull()

    // The emailed link completes — the stamp stands.
    const token = new URL(verifyUrl).searchParams.get('token')!
    const complete = await app.request(`/api/op/email-change/${encodeURIComponent(token)}`, { method: 'POST' })
    expect(complete.status, 'the link completes').toBe(200)
    const after = await app.request('/api/op/account', { headers: { cookie } })
    const { account: verifiedAccount } = await after.json() as { account: { emailVerifiedAt: string | null } }
    expect(verifiedAccount.emailVerifiedAt, 'the mailbox proof stamps the address').toBeTruthy()
  })

  it('THE DUP: the same address again answers the honest 409', async () => {
    const res = await register(APPLICANT)
    expect(res.status).toBe(409)
    expect(((await res.json()) as { error: string }).error).toContain('already exists')
  })
})
