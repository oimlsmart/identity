// ─────────────────────────────────────────────────────────────────────
// TODO.identity/09 — the transactional email, proven in four layers:
//
//   1. THE POSTURE LADDER (pure): resolveMailerConfig — the send_email
//      binding posture, the HTTPS provider posture, the honest console
//      no-op, and every misconfiguration naming its problem.
//   2. THE TRANSPORT + THE GUARDS: createMailer over a fake binding, the
//      stub HTTPS provider (e2e/fixtures/stub-mailer.ts — real HTTP),
//      the console posture's logged message, the never-throws rule, the
//      per-recipient rate limit (injected clock), and the audit events
//      every send writes (read back from a REAL temp SQLite store).
//   3. THE TEMPLATES: renderOpMail — EN/FR lockstep copy, the {param}
//      interpolation, the HTML shell's escaping + the action link, the
//      instance-profile branding.
//   4. THE ROUTES, in-process: the REAL op-accounts router over the REAL
//      store — the invite email carrying a WORKING setup link end to
//      end, the console posture's honest fallback response, the
//      password-reset send, the sign-in notification, the rate-limit
//      surface, and the French locale.
// ─────────────────────────────────────────────────────────────────────

import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest'

// The store's DB path is read at module evaluation — set it before any
// import below touches @oimlsmart/platform-server/store/sqlite (the imports are dynamic).
const TMP = mkdtempSync(join(tmpdir(), 'oiml-op-mail-'))
process.env.DATABASE_PATH = join(TMP, 'test.db')

const ISSUER = 'http://op.test'
process.env.OP_ISSUER = ISSUER

import {
  createMailer,
  mailerFor,
  resetMailerForTest,
  resolveMailerConfig,
  MAIL_RATE_LIMIT_DEFAULTS,
  type SendEmailBinding,
} from '@oimlsmart/platform-server/mailer'
import { renderOpMail, resolveMailLocale, sendOpMail } from '../../server/auth/op/mail'
import { startStubMailer, type StubMailer } from '../../e2e/fixtures/stub-mailer'

let store: ReturnType<typeof import('@oimlsmart/platform-server/store').getStore>

/** The email audit events, parsed (the mailer's journal). */
async function emailAudits(): Promise<Array<{ action: string; entity_id: string; metadata: Record<string, unknown> }>> {
  const rows = await store.listEntities('auditEvents')
  return rows
    .map(r => JSON.parse(r.data) as { action: string; entity_id: string; metadata: Record<string, unknown> })
    .filter(e => e.action.startsWith('email.'))
}

/** A fake send_email binding: records every message; `throws` turns it
 *  into the failing-transport leg. */
function fakeBinding(): SendEmailBinding & { sent: Array<Record<string, unknown>>; throws: boolean } {
  const rec = { sent: [] as Array<Record<string, unknown>>, throws: false }
  return Object.assign(rec, {
    async send(message: Record<string, unknown>): Promise<void> {
      if (rec.throws) throw new Error('the binding rejected the message')
      rec.sent.push(message)
    },
  })
}

beforeAll(async () => {
  const { installSqliteStore } = await import('@oimlsmart/platform-server/store/sqlite')
  store = installSqliteStore()
})

afterAll(async () => {
  rmSync(TMP, { recursive: true, force: true })
  delete process.env.DATABASE_PATH
  delete process.env.OP_ISSUER
  resetMailerForTest()
  const profileMod = await import('@oimlsmart/platform-server/profile')
  profileMod.resetInstanceProfileForTest()
})

// ── 1. the posture ladder (pure) ─────────────────────────────────────

describe('resolveMailerConfig — the three postures', () => {
  it('console when nothing is configured, with the problem named', () => {
    const config = resolveMailerConfig({})
    expect(config.posture).toBe('console')
    expect(config.problems.join(' ')).toContain('no mail provider is configured')
  })

  it('console when only EMAIL_FROM is set (a sender is not a provider)', () => {
    const config = resolveMailerConfig({ EMAIL_FROM: 'no-reply@oimlsmart.org' })
    expect(config.posture).toBe('console')
    expect(config.problems.join(' ')).toContain('no mail provider is configured')
  })

  it('send_email when the binding + EMAIL_FROM are present', () => {
    const binding = fakeBinding()
    const config = resolveMailerConfig({ EMAIL: binding, EMAIL_FROM: 'no-reply@oimlsmart.org' })
    expect(config.posture).toBe('send_email')
    expect(config.from).toBe('no-reply@oimlsmart.org')
    expect(config.problems).toEqual([])
  })

  it('the binding without EMAIL_FROM is skipped honestly (the problem named)', () => {
    const config = resolveMailerConfig({ EMAIL: fakeBinding() })
    expect(config.posture).toBe('console')
    expect(config.problems.join(' ')).toContain('EMAIL_FROM is unset')
  })

  it('a non-binding EMAIL value is not the binding', () => {
    const config = resolveMailerConfig({ EMAIL: 'not-a-binding', EMAIL_FROM: 'no-reply@oimlsmart.org' })
    expect(config.posture).toBe('console')
    expect(config.binding).toBeNull()
  })

  it('https when MAIL_PROVIDER_URL + MAIL_PROVIDER_KEY + EMAIL_FROM are set', () => {
    const config = resolveMailerConfig({
      MAIL_PROVIDER_URL: 'https://api.resend.com/emails',
      MAIL_PROVIDER_KEY: 're_test',
      EMAIL_FROM: 'no-reply@oimlsmart.org',
    })
    expect(config.posture).toBe('https')
    expect(config.problems).toEqual([])
  })

  it('a half-configured provider is skipped honestly (the pair rule, the missing sender)', () => {
    expect(resolveMailerConfig({ MAIL_PROVIDER_URL: 'https://api.resend.com/emails' }).problems.join(' '))
      .toContain('must be set together')
    expect(resolveMailerConfig({ MAIL_PROVIDER_URL: 'https://api.resend.com/emails', MAIL_PROVIDER_KEY: 're_test' }).problems.join(' '))
      .toContain('EMAIL_FROM is unset')
  })

  it('the binding wins when both real postures are configured', () => {
    const config = resolveMailerConfig({
      EMAIL: fakeBinding(),
      EMAIL_FROM: 'no-reply@oimlsmart.org',
      MAIL_PROVIDER_URL: 'https://api.resend.com/emails',
      MAIL_PROVIDER_KEY: 're_test',
    })
    expect(config.posture).toBe('send_email')
  })

  it('invalid rate-limit values fall back to the defaults, named', () => {
    const config = resolveMailerConfig({ MAIL_RATE_LIMIT_CAPACITY: 'five', MAIL_RATE_LIMIT_WINDOW_MS: '0' })
    expect(config.rateLimit).toEqual(MAIL_RATE_LIMIT_DEFAULTS)
    expect(config.problems.join(' ')).toContain('MAIL_RATE_LIMIT_CAPACITY')
    expect(config.problems.join(' ')).toContain('MAIL_RATE_LIMIT_WINDOW_MS')
  })
})

// ── 2. the transport + the guards ────────────────────────────────────

describe('createMailer — the transport and the guards', () => {
  it('send_email: the binding carries the message; the result is sent', async () => {
    const binding = fakeBinding()
    const mailer = createMailer(resolveMailerConfig({ EMAIL: binding, EMAIL_FROM: 'no-reply@oimlsmart.org' }))
    const result = await mailer.send({ to: 'willa@example.org', subject: 's', text: 'the body', html: '<p>the body</p>' }, { template: 'invite' })
    expect(result).toEqual({ ok: true, posture: 'send_email' })
    expect(binding.sent).toEqual([{ from: 'no-reply@oimlsmart.org', to: 'willa@example.org', subject: 's', text: 'the body', html: '<p>the body</p>' }])
    const audits = await emailAudits()
    expect(audits.at(-1)).toMatchObject({ action: 'email.sent', entity_id: 'willa@example.org', metadata: { template: 'invite', posture: 'send_email', error: null } })
  })

  it('send: a throwing transport is the honest failure result, never an exception', async () => {
    const binding = fakeBinding()
    binding.throws = true
    const mailer = createMailer(resolveMailerConfig({ EMAIL: binding, EMAIL_FROM: 'no-reply@oimlsmart.org' }))
    const result = await mailer.send({ to: 'willa@example.org', subject: 's', text: 'b' })
    expect(result).toMatchObject({ ok: false, posture: 'send_email', error: 'the binding rejected the message' })
    expect((await emailAudits()).at(-1)).toMatchObject({ action: 'email.failed', entity_id: 'willa@example.org' })
  })

  it('https: the provider receives the Resend-shaped POST with the Bearer key', async () => {
    const stub = await startStubMailer({ expectedKey: 're_test' })
    try {
      const mailer = createMailer(resolveMailerConfig({
        MAIL_PROVIDER_URL: `${stub.baseUrl}/emails`,
        MAIL_PROVIDER_KEY: 're_test',
        EMAIL_FROM: 'OIML SMART Identity <no-reply@oimlsmart.org>',
      }))
      const result = await mailer.send({ to: 'willa@example.org', subject: 'the subject', text: 'the body', html: '<p>the body</p>' }, { template: 'reset' })
      expect(result).toEqual({ ok: true, posture: 'https' })
      expect(stub.messages).toHaveLength(1)
      expect(stub.messages[0]).toMatchObject({
        from: 'OIML SMART Identity <no-reply@oimlsmart.org>',
        to: 'willa@example.org',
        subject: 'the subject',
        text: 'the body',
        html: '<p>the body</p>',
        authorization: 'Bearer re_test',
      })
    } finally {
      await stub.close()
    }
  })

  it('https: the provider’s refusal is the honest failure (the status + the bounded body)', async () => {
    const stub = await startStubMailer({ expectedKey: 're_test' })
    try {
      const mailer = createMailer(resolveMailerConfig({
        MAIL_PROVIDER_URL: `${stub.baseUrl}/emails`,
        MAIL_PROVIDER_KEY: 're_WRONG',
        EMAIL_FROM: 'no-reply@oimlsmart.org',
      }))
      const result = await mailer.send({ to: 'willa@example.org', subject: 's', text: 'b' })
      expect(result.ok).toBe(false)
      expect(result.error).toContain('401')
      expect(result.error).toContain('API key is invalid')
      expect(stub.messages).toHaveLength(0)
      expect((await emailAudits()).at(-1)).toMatchObject({ action: 'email.failed', entity_id: 'willa@example.org' })
    } finally {
      await stub.close()
    }
  })

  it('console: the message is logged in full, the result says not-sent, the audit says logged', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    try {
      const mailer = createMailer(resolveMailerConfig({}))
      const result = await mailer.send({ to: 'willa@example.org', subject: 'the subject', text: 'the body\nwith the link' }, { template: 'invite' })
      expect(result).toMatchObject({ ok: false, posture: 'console', error: 'no mail provider is configured on this deployment' })
      const logged = warn.mock.calls.map(c => String(c[0])).join('\n')
      expect(logged).toContain('willa@example.org')
      expect(logged).toContain('the subject')
      expect(logged).toContain('with the link')
      expect((await emailAudits()).at(-1)).toMatchObject({ action: 'email.logged', entity_id: 'willa@example.org' })
    } finally {
      warn.mockRestore()
    }
  })

  it('the per-recipient rate limit: the window trips and resets (the injected clock)', async () => {
    let at = 1_000_000
    const mailer = createMailer(
      resolveMailerConfig({ MAIL_RATE_LIMIT_CAPACITY: '2', MAIL_RATE_LIMIT_WINDOW_MS: '60000' }),
      { now: () => at },
    )
    const msg = { to: 'willa@example.org', subject: 's', text: 'b' }
    expect((await mailer.send(msg)).ok).toBe(false) // the console posture: not delivered, but NOT rate-limited
    expect((await mailer.send(msg)).rateLimited).toBeUndefined()
    const third = await mailer.send(msg)
    expect(third).toMatchObject({ ok: false, rateLimited: true })
    expect(third.error).toContain('rate limited')
    // Another recipient is unaffected.
    expect((await mailer.send({ ...msg, to: 'other@example.org' })).rateLimited).toBeUndefined()
    // The window's end refills the bucket.
    at += 61_000
    expect((await mailer.send(msg)).rateLimited).toBeUndefined()
    expect((await emailAudits()).some(e => e.action === 'email.rate_limited' && e.entity_id === 'willa@example.org')).toBe(true)
  })

  it('capacity 0 disables the limiter honestly', async () => {
    const mailer = createMailer(resolveMailerConfig({ MAIL_RATE_LIMIT_CAPACITY: '0' }))
    const msg = { to: 'willa@example.org', subject: 's', text: 'b' }
    for (let i = 0; i < 7; i++) expect((await mailer.send(msg)).rateLimited).toBeUndefined()
  })

  it('mailerFor caches per configuration (the rate-limit buckets survive requests) and rebuilds on change', async () => {
    resetMailerForTest()
    const env = { MAIL_RATE_LIMIT_CAPACITY: '1' }
    const first = mailerFor(env)
    expect(mailerFor(env)).toBe(first) // the same mailer — the buckets persist
    const msg = { to: 'willa@example.org', subject: 's', text: 'b' }
    await first.send(msg)
    expect((await mailerFor(env).send(msg)).rateLimited).toBe(true) // the shared bucket
    const rebuilt = mailerFor({ MAIL_RATE_LIMIT_CAPACITY: '2' })
    expect(rebuilt).not.toBe(first) // a changed configuration rebuilds
    expect((await rebuilt.send(msg)).rateLimited).toBeUndefined()
    resetMailerForTest()
  })
})

// ── 3. the templates ─────────────────────────────────────────────────

describe('renderOpMail — the EN/FR templates', () => {
  const params = {
    name: 'Willa Example',
    product: 'OIML SMART Identity',
    issuer: 'https://id.oimlsmart.org',
    setupUrl: 'https://id.oimlsmart.org/op/setup?token=abc123',
    hours: 24,
  }

  it('the invite renders EN with every placeholder filled and the footer', () => {
    const mail = renderOpMail('invite', 'en', params)
    expect(mail.subject).toBe('Your OIML SMART Identity account is ready to set up')
    expect(mail.text).toContain('Hello Willa Example,')
    expect(mail.text).toContain(params.setupUrl)
    expect(mail.text).toContain('24 hours')
    expect(mail.text).toContain('Sent by OIML SMART Identity (https://id.oimlsmart.org)')
    expect(mail.text).not.toContain('{')
  })

  it('the invite renders FR (the catalogs in lockstep)', () => {
    const mail = renderOpMail('invite', 'fr', params)
    expect(mail.subject).toBe('Votre compte OIML SMART Identity est prêt à être configuré')
    expect(mail.text).toContain('Bonjour Willa Example,')
    expect(mail.text).toContain(params.setupUrl)
    expect(mail.text).toContain('Envoyé par OIML SMART Identity')
  })

  it('the HTML shell escapes the params and lifts the action link', () => {
    const mail = renderOpMail('invite', 'en', { ...params, name: 'Willa <script>alert(1)</script>' })
    expect(mail.html).toContain('Willa &lt;script&gt;')
    expect(mail.html).not.toContain('<script>alert')
    expect(mail.html).toContain('Set your password') // the action label
    expect(mail.html).toContain(`href="${params.setupUrl}"`)
    expect(mail.html).toContain('OIML SMART Identity') // the branding
  })

  it('the reset + verify_email + signin templates render their own copy', () => {
    const reset = renderOpMail('reset', 'en', params)
    expect(reset.subject).toBe('Your OIML SMART Identity password reset link')
    expect(reset.text).toContain('your current password stays unchanged')
    expect(reset.html).toContain('Choose a new password')
    const verify = renderOpMail('verify_email', 'en', { ...params, verifyUrl: 'https://id.oimlsmart.org/op/verify?token=x' })
    expect(verify.text).toContain('https://id.oimlsmart.org/op/verify?token=x')
    expect(verify.html).toContain('Confirm the new address')
    const signin = renderOpMail('signin', 'en', { name: 'Willa', product: 'P', issuer: 'i', when: '2026-08-17 03:08', method: 'GitHub' })
    expect(signin.subject).toBe('New sign-in to your P account')
    expect(signin.text).toContain('at 2026-08-17 03:08 UTC by GitHub')
  })

  it('resolveMailLocale: MAIL_LOCALE honored, unknown values fall back honestly', () => {
    expect(resolveMailLocale({}).locale).toBe('en')
    expect(resolveMailLocale({ MAIL_LOCALE: 'fr' }).locale).toBe('fr')
    const bad = resolveMailLocale({ MAIL_LOCALE: 'de' })
    expect(bad.locale).toBe('en')
    expect(bad.problem).toContain("'de'")
  })
})

// ── 4. the routes, in-process ────────────────────────────────────────

describe('the OP routes with the mailer bound', () => {
  let app: import('hono').Hono
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

  interface InviteResponse {
    account: { id: string; email: string; name: string }
    setupUrl: string
    expiresAt: string
    mail: { posture: string; sent: boolean; error: string | null }
  }

  async function invite(email: string, name: string): Promise<InviteResponse> {
    const admin = await demoLogin('admin@oiml.org')
    const res = await app.request('/api/op/accounts', {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: admin },
      body: JSON.stringify({ email, name }),
    })
    expect(res.status, `invite ${email}`).toBe(201)
    return res.json() as Promise<InviteResponse>
  }

  beforeAll(async () => {
    clearMailEnv()
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
    const { createOpAccountsRouter } = await import('../../server/routes/op-accounts')
    const root = new Hono()
    root.route('/api/auth', createAuthLeanRouter({ autoSeedDemo: true }))
    root.route('/', createOpAccountsRouter())
    app = root
    stub = await startStubMailer({ expectedKey: 'stub-mail-key' })
    await demoLogin('admin@oiml.org') // the demo cast lands on the first auth request
  })

  afterAll(async () => {
    clearMailEnv()
    await stub?.close()
  })

  it('the console posture: the invite answers the link + the honest not-sent block (never a silent drop)', async () => {
    clearMailEnv()
    const body = await invite('console-posture@example.org', 'Console Posture')
    expect(body.mail).toEqual({ posture: 'console', sent: false, error: 'no mail provider is configured on this deployment' })
    expect(body.setupUrl).toContain('/op/setup?token=') // the link still answers — the copy path
    expect((await emailAudits()).some(e => e.action === 'email.logged' && e.entity_id === 'console-posture@example.org')).toBe(true)
  })

  it('the https posture: the invite EMAIL carries a working setup link end to end', async () => {
    bindStubProvider()
    stub.reset()
    const body = await invite('willa@example.org', 'Willa Example')
    expect(body.mail).toEqual({ posture: 'https', sent: true, error: null })

    // The captured message IS the email: to the invitee, the EN invite
    // copy, and the SAME one-time link the API answered.
    expect(stub.messages).toHaveLength(1)
    const mail = stub.messages[0]!
    expect(mail.to).toBe('willa@example.org')
    expect(mail.from).toBe('OIML SMART Identity <no-reply@oimlsmart.org>')
    expect(mail.subject).toBe('Your OIML SMART Identity account is ready to set up')
    expect(mail.text).toContain('Hello Willa Example,')
    expect(mail.text).toContain(body.setupUrl)
    expect(mail.html).toContain('Set your password')
    const emailedUrl = mail.text!.split('\n').find(l => l.startsWith('http'))!
    expect(emailedUrl).toBe(body.setupUrl)

    // The emailed link works: the setup completes with it (the email is
    // not decorative — it carries the enrollment).
    const token = new URL(emailedUrl).searchParams.get('token')!
    const res = await app.request(`/api/op/enroll/${token}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ password: 'willa has a proper passphrase' }),
    })
    expect(res.status, 'the emailed link enrolls').toBe(200)
    expect((await emailAudits()).some(e => e.action === 'email.sent' && e.entity_id === 'willa@example.org' && e.metadata.template === 'invite')).toBe(true)

    // …and the sign-in notification rides the same channel (the method
    // label defaults to the localized password wording).
    stub.reset()
    const login = await app.request('/api/op/login', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: 'willa@example.org', password: 'willa has a proper passphrase' }),
    })
    expect(login.ok).toBe(true)
    expect(stub.messages).toHaveLength(1)
    expect(stub.messages[0]!.to).toBe('willa@example.org')
    expect(stub.messages[0]!.subject).toBe('New sign-in to your OIML SMART Identity account')
    expect(stub.messages[0]!.text).toContain('by the password sign-in')
  })

  it('the password reset: the fresh enrollment link goes by email (the reset template)', async () => {
    bindStubProvider()
    stub.reset()
    const accountId = (await store.findUserByEmail('willa@example.org'))!.id
    const admin = await demoLogin('admin@oiml.org')
    const res = await app.request(`/api/op/accounts/${accountId}/enrollment`, {
      method: 'POST',
      headers: { cookie: admin },
    })
    expect(res.status).toBe(201)
    const body = await res.json() as { setupUrl: string; mail: { posture: string; sent: boolean } }
    expect(body.mail).toMatchObject({ posture: 'https', sent: true })
    const mail = stub.messages.find(m => m.subject === 'Your OIML SMART Identity password reset link')!
    expect(mail.to).toBe('willa@example.org')
    expect(mail.text).toContain(body.setupUrl)
    expect(mail.text).toContain('your current password stays unchanged')
  })

  it('the rate limit surfaces honestly: the link still answers, the block says why', async () => {
    bindStubProvider()
    process.env.MAIL_RATE_LIMIT_CAPACITY = '1'
    resetMailerForTest()
    stub.reset()
    try {
      const accountId = (await store.findUserByEmail('willa@example.org'))!.id
      const admin = await demoLogin('admin@oiml.org')
      const first = await app.request(`/api/op/accounts/${accountId}/enrollment`, { method: 'POST', headers: { cookie: admin } })
      expect((await first.json() as { mail: { sent: boolean } }).mail.sent).toBe(true)
      const second = await app.request(`/api/op/accounts/${accountId}/enrollment`, { method: 'POST', headers: { cookie: admin } })
      const body = await second.json() as { setupUrl: string; mail: { sent: boolean; error: string | null } }
      expect(body.mail.sent).toBe(false)
      expect(body.mail.error).toContain('rate limited')
      expect(body.setupUrl).toContain('/op/setup?token=') // the link always answers
      expect(stub.messages).toHaveLength(1) // exactly the first send left
    } finally {
      delete process.env.MAIL_RATE_LIMIT_CAPACITY
      resetMailerForTest()
    }
  })

  it('the French locale: MAIL_LOCALE=fr renders the invite in French', async () => {
    bindStubProvider()
    process.env.MAIL_LOCALE = 'fr'
    resetMailerForTest()
    stub.reset()
    try {
      const body = await invite('francois@example.org', 'François Exemple')
      expect(body.mail.sent).toBe(true)
      const mail = stub.messages[0]!
      expect(mail.subject).toBe('Votre compte OIML SMART Identity est prêt à être configuré')
      expect(mail.text).toContain('Bonjour François Exemple,')
      expect(mail.text).toContain(body.setupUrl)
    } finally {
      delete process.env.MAIL_LOCALE
      resetMailerForTest()
    }
  })

  it('the provider’s failure never fails the invite: 201, the link, and the honest error', async () => {
    bindStubProvider()
    process.env.MAIL_PROVIDER_KEY = 'the-wrong-key' // the stub refuses
    resetMailerForTest()
    try {
      const body = await invite('failing@example.org', 'Failing Provider')
      expect(body.mail.sent).toBe(false)
      expect(body.mail.posture).toBe('https')
      expect(body.mail.error).toContain('401')
      expect(body.setupUrl).toContain('/op/setup?token=') // the copy path stays
      expect((await emailAudits()).some(e => e.action === 'email.failed' && e.entity_id === 'failing@example.org')).toBe(true)
    } finally {
      clearMailEnv()
    }
  })

  // The SELF-SERVICE reset (POST /api/op/login/reset — the login page's
  // "Forgot your password?"): the mailed half. The no-mailer posture's
  // honest 503 is proven in id-accounts.test.ts.
  it('the self-service reset: the constant answer, the emailed link completes, and no address is an oracle', async () => {
    bindStubProvider()
    stub.reset()

    // A known account: the constant 200 (no existence hint in the
    // response), exactly one captured reset email, and the emailed link
    // drives a REAL password change through /op/setup's machinery.
    const res = await app.request('/api/op/login/reset', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: 'willa@example.org' }),
    })
    expect(res.status).toBe(200)
    const body = await res.json() as { ok: boolean; message: string }
    expect(body.ok).toBe(true)
    expect(body.message).toContain('If an account exists')
    expect(JSON.stringify(body)).not.toContain('setupUrl') // the link NEVER rides the response
    expect(stub.messages).toHaveLength(1)
    const mail = stub.messages[0]!
    expect(mail.subject).toBe('Your OIML SMART Identity password reset link')
    expect(mail.to).toBe('willa@example.org')
    const emailedUrl = mail.text!.split('\n').find(l => l.startsWith('http'))!
    expect(emailedUrl).toContain('/op/setup?token=')
    const token = new URL(emailedUrl).searchParams.get('token')!
    const complete = await app.request(`/api/op/enroll/${token}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ password: 'willa has a fresh passphrase 2026' }),
    })
    expect(complete.status, 'the emailed reset link completes').toBe(200)
    // The new password signs in, the old one refuses.
    const fresh = await app.request('/api/op/login', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ email: 'willa@example.org', password: 'willa has a fresh passphrase 2026' }) })
    expect(fresh.ok).toBe(true)
    const stale = await app.request('/api/op/login', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ email: 'willa@example.org', password: 'willa has a proper passphrase' }) })
    expect(stale.status).toBe(401)
    // The account's own activity feed names the request (the holder
    // learns of it, whoever asked).
    const accountAudits = (await store.listEntities('auditEvents')).map(r => JSON.parse(r.data) as { action: string; entity_id: string })
    const willaId = (await store.findUserByEmail('willa@example.org'))!.id
    expect(accountAudits.some(e => e.action === 'account.password_reset' && e.entity_id === willaId)).toBe(true)

    // The oracle legs: an unknown address, a DEACTIVATED account, and a
    // non-OP (demo cast) address all answer the SAME 200 — and send
    // NOTHING.
    const admin = await demoLogin('admin@oiml.org')
    const invited = await invite('dormant@example.org', 'Dormant Account')
    await app.request(`/api/op/accounts/${invited.account.id}/status`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: admin },
      body: JSON.stringify({ active: false }),
    })
    stub.reset()
    for (const target of ['ghost@example.org', 'dormant@example.org', 'admin@oiml.org']) {
      const r = await app.request('/api/op/login/reset', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ email: target }),
      })
      expect(r.status, target).toBe(200)
      const b = await r.json() as { message: string }
      expect(b.message, target).toContain('If an account exists')
    }
    expect(stub.messages).toHaveLength(0)
  })
})
