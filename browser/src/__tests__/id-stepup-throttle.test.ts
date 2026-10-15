// ─────────────────────────────────────────────────────────────────────
// The step-up's throttle (2026-10-15) — the password comparison on
// /api/op/step-up sits on the SAME ladder as the login: a wrong
// password pays the owed wait, climbs the rung, fires the throttled
// failed-signin notice, and a success clears the ladder outright.
// Without this the step-up was a password oracle OUTSIDE every control
// — no backoff, no notice, invisible to the holder.
// ─────────────────────────────────────────────────────────────────────

import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest'

const TMP = mkdtempSync(join(tmpdir(), 'oiml-stepup-throttle-'))
process.env.DATABASE_PATH = join(TMP, 'test.db')
process.env.OP_ISSUER = 'http://op.test'
process.env.OP_LOGIN_BACKOFF_BASE_MS = '800'

const ORIGIN = 'http://op.test'

let app: import('hono').Hono
let store: ReturnType<typeof import('../../server/store').getStore>
let stub: import('../../e2e/fixtures/stub-mailer').StubMailer

const WILLA = { email: 'throttle-willa@example.org', name: 'Willa Throttle', password: 'willa has a proper passphrase' }

async function demoLogin(email: string): Promise<string> {
  const res = await app.request(`${ORIGIN}/api/auth/demo`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password: 'demo2026' }),
  })
  expect(res.ok).toBe(true)
  return res.headers.get('set-cookie')!.split(';')[0]!
}

async function login(email: string, password: string): Promise<string> {
  const res = await app.request(`${ORIGIN}/api/op/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password }),
  })
  expect(res.status).toBe(200)
  return res.headers.get('set-cookie')!.split(';')[0]!
}

async function stepUp(cookie: string, password: string): Promise<Response> {
  return app.request(`${ORIGIN}/api/op/step-up`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', cookie },
    body: JSON.stringify({ password }),
  })
}

function failedNotices(): Array<{ to?: string }> {
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

  // The holder: enrolled.
  const admin = await demoLogin('admin@oimlsmart.org')
  const invited = await app.request(`${ORIGIN}/api/op/accounts`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', cookie: admin },
    body: JSON.stringify({ email: WILLA.email, name: WILLA.name }),
  })
  expect(invited.status).toBe(201)
  const { setupUrl } = await invited.json() as { setupUrl: string }
  const token = new URL(setupUrl).searchParams.get('token')!
  expect((await app.request(`${ORIGIN}/api/op/enroll/${token}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ password: WILLA.password }),
  })).status).toBe(200)
  stub.reset()
})

afterAll(async () => {
  await stub.close()
  for (const k of ['EMAIL_FROM', 'MAIL_PROVIDER_URL', 'MAIL_PROVIDER_KEY', 'OP_LOGIN_BACKOFF_BASE_MS']) delete process.env[k]
  const mailerMod = await import('../../server/mailer')
  mailerMod.resetMailerForTest()
  const { resetInstanceProfileForTest } = await import('../../server/profile')
  resetInstanceProfileForTest()
  rmSync(TMP, { recursive: true, force: true })
  for (const k of ['DATABASE_PATH', 'OP_ISSUER', 'OP_SIGNING_KEY']) delete process.env[k]
})

describe('the step-up sits on the login ladder', () => {
  it('the wrong password climbs the rung — the ladder row proves it', { timeout: 120_000 }, async () => {
    const cookie = await login(WILLA.email, WILLA.password)
    for (let i = 1; i <= 3; i++) {
      const res = await stepUp(cookie, 'guess-' + i)
      expect(res.status, `guess ${i}`).toBe(403)
      const row = await store.getEntity('opLoginThrottle', WILLA.email)
      expect(row, `the rung after guess ${i}`).toBeTruthy()
      const parsed = JSON.parse(row!.data) as { failCount: number }
      expect(parsed.failCount).toBe(i)
    }
  })

  it('the fourth attempt pays the owed wait, and the holder is told once', { timeout: 120_000 }, async () => {
    const cookie = await login(WILLA.email, WILLA.password)
    // This leg owns its rungs (the login's own success clears the
    // ladder — the previous leg's climb does not survive the fresh
    // sign-in).
    for (let i = 1; i <= 3; i++) {
      expect((await stepUp(cookie, 'warm-' + i)).status).toBe(403)
    }
    const started = Date.now()
    const res = await stepUp(cookie, 'guess-4')
    const elapsed = Date.now() - started
    expect(res.status).toBe(403)
    expect(elapsed, 'the ladder\'s wait lands in the answer').toBeGreaterThanOrEqual(700)
    // The throttled notice (the marker: one per hour).
    await vi.waitFor(() => expect(failedNotices().length).toBe(1), { timeout: 5_000 })
    expect(failedNotices()[0]!.to).toBe(WILLA.email)
  })

  it('the correct password mints the stamp AND clears the ladder outright', { timeout: 120_000 }, async () => {
    const cookie = await login(WILLA.email, WILLA.password)
    expect((await stepUp(cookie, 'warm-1')).status).toBe(403)
    const res = await stepUp(cookie, WILLA.password)
    expect(res.status).toBe(200)
    expect(await store.getEntity('opLoginThrottle', WILLA.email)).toBeUndefined()
    expect(failedNotices().length, 'the holder proving themselves is not a notice').toBe(1)
  })
})
