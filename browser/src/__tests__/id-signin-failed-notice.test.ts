// ─────────────────────────────────────────────────────────────────────
// The failed-sign-in notice (2026-10-14, the GitHub parity) — proven
// in-process over the REAL op-accounts router against a REAL temp
// SQLite store + the stub mailer:
//
//   FAILED    a known address with a wrong password answers the uniform
//             401 AND mails the holder one failed-attempt notice (the
//             subject, the reset pointer); the send never touches the
//             answer's shape or timing contract;
//   THROTTLED the notice rides a per-account marker — a second failure
//             inside the hour mails nothing; an hour-old marker lets
//             the next failure mail again;
//   SILENT    an unknown address (no account behind it) and a correct
//             password mail nothing — the notice can never become an
//             enumeration oracle or a success-side noise.
// ─────────────────────────────────────────────────────────────────────

import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest'

const TMP = mkdtempSync(join(tmpdir(), 'oiml-signin-failed-'))
process.env.DATABASE_PATH = join(TMP, 'test.db')
process.env.OP_ISSUER = 'http://op.test'

const ORIGIN = 'http://op.test'

let app: import('hono').Hono
let store: ReturnType<typeof import('../../server/store').getStore>
let stub: import('../../e2e/fixtures/stub-mailer').StubMailer

const VICTIM = 'holda@example.org'
const PASS = 'holda has a proper passphrase'

async function demoLogin(email: string): Promise<string> {
  const res = await app.request(`${ORIGIN}/api/auth/demo`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password: 'demo2026' }),
  })
  expect(res.ok, `demo login ${email}`).toBe(true)
  return res.headers.get('set-cookie')!.split(';')[0]!
}

async function login(email: string, password: string): Promise<Response> {
  return app.request(`${ORIGIN}/api/op/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password }),
  })
}

function failedNotices(): Array<{ to?: string; subject?: string; text?: string }> {
  return stub.messages.filter(m => (m.subject ?? '').toLowerCase().includes('failed sign-in'))
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

  const { startStubMailer } = await import('../../e2e/fixtures/stub-mailer')
  stub = await startStubMailer({ expectedKey: 'stub-mail-key' })
  process.env.EMAIL_FROM = 'OIML SMART Identity <no-reply@oimlsmart.org>'
  process.env.MAIL_PROVIDER_URL = `${stub.baseUrl}/emails`
  process.env.MAIL_PROVIDER_KEY = 'stub-mail-key'
  const mailerMod = await import('../../server/mailer')
  mailerMod.resetMailerForTest()

  const { Hono } = await import('hono')
  const { createAuthLeanRouter } = await import('../../server/routes/auth-lean')
  const { createOpAccountsRouter } = await import('../../server/routes/op-accounts')
  const root = new Hono()
  root.route('/api/auth', createAuthLeanRouter({ autoSeedDemo: true }))
  root.route('/', createOpAccountsRouter())
  app = root

  // The holder: a REAL password account (the invite + the enrollment).
  const admin = await demoLogin('admin@oimlsmart.org')
  const invited = await app.request(`${ORIGIN}/api/op/accounts`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', cookie: admin },
    body: JSON.stringify({ email: VICTIM, name: 'Holda Holder' }),
  })
  expect(invited.status).toBe(201)
  const { setupUrl } = await invited.json() as { setupUrl: string }
  const token = new URL(setupUrl).searchParams.get('token')!
  const enrolled = await app.request(`${ORIGIN}/api/op/enroll/${token}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ password: PASS }),
  })
  expect(enrolled.status, 'the enrollment completes').toBe(200)
  stub.reset()
})

afterAll(async () => {
  await stub.close()
  for (const k of ['EMAIL_FROM', 'MAIL_PROVIDER_URL', 'MAIL_PROVIDER_KEY']) delete process.env[k]
  const mailerMod = await import('../../server/mailer')
  mailerMod.resetMailerForTest()
  const { resetInstanceProfileForTest } = await import('../../server/profile')
  resetInstanceProfileForTest()
  rmSync(TMP, { recursive: true, force: true })
  for (const k of ['DATABASE_PATH', 'OP_ISSUER', 'OP_SIGNING_KEY']) delete process.env[k]
})

describe('the failed-sign-in notice (the GitHub parity, throttled per account)', () => {
  it('FAILED: a known address + wrong password mails exactly one notice; the answer stays the uniform 401', async () => {
    const res = await login(VICTIM, 'not the passphrase')
    expect(res.status, 'the uniform 401').toBe(401)
    expect(((await res.json()) as { error: string }).error).toBe('Invalid email or password')
    // The notice is fire-and-forget (the timing-uniformity contract) —
    // wait for the in-flight send to reach the stub.
    await vi.waitFor(() => expect(failedNotices().length, 'exactly one notice').toBe(1), { timeout: 5_000 })
    const notices = failedNotices()
    expect(notices[0]!.to).toBe(VICTIM)
    expect(notices[0]!.text).toContain('reset')
    // The marker row stands (the throttle's record).
    expect(await store.getEntity('opSignInFailedNotice', VICTIM)).toBeTruthy()
  })

  it('THROTTLED: a second failure inside the hour mails nothing', { timeout: 120_000 }, async () => {
    const res = await login(VICTIM, 'still not the passphrase')
    expect(res.status).toBe(401)
    expect(failedNotices().length, 'the hour owns one notice').toBe(1)
  })

  it('THROTTLED: an hour-old marker lets the next failure mail again', { timeout: 120_000 }, async () => {
    const stale = new Date(Date.now() - 2 * 3_600_000).toISOString()
    await store.putEntity('opSignInFailedNotice', VICTIM, null, JSON.stringify({ sentAt: stale }))
    const res = await login(VICTIM, 'nope again')
    expect(res.status).toBe(401)
    await vi.waitFor(() => expect(failedNotices().length, 'the window passed — one more notice').toBe(2), { timeout: 5_000 })
  })

  it('SILENT: an unknown address mails nothing', { timeout: 120_000 }, async () => {
    const res = await login('stranger@elsewhere.example', 'whatever')
    expect(res.status).toBe(401)
    expect(((await res.json()) as { error: string }).error).toBe('Invalid email or password')
    expect(failedNotices().length, 'no account, no notice').toBe(2)
  })

  it('SILENT: the correct password mails nothing; the audit names WHAT and WHERE', { timeout: 120_000 }, async () => {
    const res = await login(VICTIM, PASS)
    expect(res.status).toBe(200)
    expect(failedNotices().length, 'the holder entering is not a notice').toBe(2)
    // 2026-10-14: the sign_in audit carries the device summary, the IP
    // and the resolved country — the console's activity feed renders
    // the same what/where the notices carry.
    const accountId = (await store.findUserByEmail(VICTIM))!.id
    const rows = (await store.listEntities('auditEvents'))
      .map(row => JSON.parse(row.data) as { action: string; entity_id: string; metadata?: Record<string, unknown> })
      .filter(e => e.action === 'account.sign_in' && e.entity_id === accountId)
    const mine = rows.at(-1)
    expect(mine, 'the success lands on the chain').toBeTruthy()
    expect(mine!.metadata).toMatchObject({
      method: 'password',
      fromDevice: expect.stringContaining('unrecognized'),
      fromIp: expect.any(String),
    })
  })
})
