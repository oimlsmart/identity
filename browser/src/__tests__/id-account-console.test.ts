// ─────────────────────────────────────────────────────────────────────
// TODO.identity/06 — the account-holder console, proven in-process over
// the REAL op-accounts + op-upstream routers against a REAL temp SQLite
// store (the id-accounts.test.ts posture):
//
//   PROFILE      the display-name edit (validation, the live-name read);
//   EMAIL        the verify-new-email ceremony: request (validation, the
//                taken-address 409, the no-mailer honest 'shown'
//                delivery), one pending link only (a fresh request voids
//                the earlier one), the public context, the completion
//                (email moves, the old address refuses, a SHOWN link
//                never verifies the mailbox, a MAILER-delivered one
//                does), the expired/used/conflict exits;
//   METHODS      the at-least-one-method guard BOTH ways (the password
//                removal and the upstream unlink refuse when they would
//                strand the account);
//   PASSWORD     the change revokes every OTHER session (the count is
//                named); the sessions section's revoke-others;
//   SESSIONS     the sign-in context (user agent / IP at creation, the
//                throttled last-active stamp);
//   ACTIVITY     the account's own audit events, newest first, never
//                another account's, never credential material.
// ─────────────────────────────────────────────────────────────────────

import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

// The store's DB path is read at module evaluation — set it before any
// import below touches @oimlsmart/platform-server/store/sqlite (the imports are dynamic).
const TMP = mkdtempSync(join(tmpdir(), 'oiml-account-console-'))
process.env.DATABASE_PATH = join(TMP, 'test.db')

const ISSUER = 'http://op.test'
process.env.OP_ISSUER = ISSUER

import { hashPassword } from '../../server/auth/passwords'
import { mintEnrollmentToken } from '../../server/auth/op/accounts'

let app: import('hono').Hono
let store: ReturnType<typeof import('@oimlsmart/platform-server/store').getStore>

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
  const { createOpAccountsRouter } = await import('../../server/routes/op-accounts')
  const { createOpUpstreamRouter } = await import('../../server/routes/op-upstream')
  const root = new Hono()
  root.route('/api/auth', createAuthLeanRouter({ autoSeedDemo: true }))
  root.route('/', createOpAccountsRouter())
  root.route('/', createOpUpstreamRouter())
  app = root
  await demoLogin('admin@oiml.org')
})

afterAll(async () => {
  rmSync(TMP, { recursive: true, force: true })
  delete process.env.OP_ISSUER
  delete process.env.DATABASE_PATH
  const profileMod = await import('@oimlsmart/platform-server/profile')
  profileMod.resetInstanceProfileForTest()
})

// ── the profile section ──────────────────────────────────────────────

describe('the profile edit', () => {
  it('renames the account (the next read carries it), validates honestly, and audits', async () => {
    const { id, cookie } = await enrollAccount('pia@example.org', 'Pia Example')

    const empty = await app.request('/api/op/account/profile', {
      method: 'POST', headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ name: '   ' }),
    })
    expect(empty.status).toBe(400)

    const ok = await app.request('/api/op/account/profile', {
      method: 'POST', headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ name: 'Pia Actual' }),
    })
    expect(ok.status).toBe(200)
    expect(await ok.json()).toMatchObject({ ok: true, name: 'Pia Actual' })

    // The session join is live: the next context read carries the name.
    const context = await app.request('/api/op/account', { headers: { cookie } })
    expect((await context.json() as { account: { name: string } }).account.name).toBe('Pia Actual')

    // …and the audit chain carries the act (the activity feed's source).
    const events = (await store.listEntities('auditEvents'))
      .map(r => JSON.parse(r.data) as { entity_id: string; action: string })
    expect(events.some(e => e.entity_id === id && e.action === 'account.profile')).toBe(true)
  })
})

// ── the email change ceremony ────────────────────────────────────────

describe('the verify-new-email ceremony', () => {
  it('validates the request (malformed, same address, taken address)', async () => {
    const { cookie } = await enrollAccount('quinn@example.org', 'Quinn Example')
    const ask = (email: string) => app.request('/api/op/account/email', {
      method: 'POST', headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ email }),
    })
    expect((await ask('not-an-address')).status).toBe(400)
    expect((await ask('quinn@example.org')).status).toBe(400)
    expect((await ask('admin@oiml.org')).status).toBe(409)
  })

  it('without a mailer the link is SHOWN honestly; the pending change rides the context', async () => {
    const { cookie } = await enrollAccount('ruth@example.org', 'Ruth Example')
    const res = await app.request('/api/op/account/email', {
      method: 'POST', headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ email: 'ruth.new@example.org' }),
    })
    expect(res.status).toBe(201)
    const body = await res.json() as { delivery: string; verificationUrl?: string; newEmail: string }
    expect(body.delivery).toBe('shown') // no mailer on the OP yet (09's seam)
    expect(body.verificationUrl).toContain('/op/email-change?token=')

    const context = await app.request('/api/op/account', { headers: { cookie } })
    const pending = (await context.json() as { pendingEmailChange: { newEmail: string; delivery: string } | null }).pendingEmailChange
    expect(pending).toMatchObject({ newEmail: 'ruth.new@example.org', delivery: 'shown' })
  })

  it('a fresh request voids the earlier link (only the newest works)', async () => {
    const { cookie } = await enrollAccount('sam@example.org', 'Sam Example')
    const ask = async (email: string) => {
      const res = await app.request('/api/op/account/email', {
        method: 'POST', headers: { 'content-type': 'application/json', cookie },
        body: JSON.stringify({ email }),
      })
      return (await res.json() as { verificationUrl: string }).verificationUrl
    }
    const first = await ask('sam.one@example.org')
    const second = await ask('sam.two@example.org')
    const firstToken = new URL(first).searchParams.get('token')!
    const context = await app.request(`/api/op/email-change/${firstToken}`)
    expect(context.status).toBe(410) // voided by the newer request
    expect(await context.json()).toMatchObject({ error: 'used' })
    const secondContext = await app.request(`/api/op/email-change/${new URL(second).searchParams.get('token')}`)
    expect(secondContext.status).toBe(200)
  })

  it('the public context names the account and the from/to addresses, nothing more', async () => {
    const { cookie } = await enrollAccount('tess@example.org', 'Tess Example')
    const res = await app.request('/api/op/account/email', {
      method: 'POST', headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ email: 'tess.new@example.org' }),
    })
    const { verificationUrl } = await res.json() as { verificationUrl: string }
    const token = new URL(verificationUrl).searchParams.get('token')!
    // No cookie: the link is the proof (it may arrive by mail later).
    const context = await app.request(`/api/op/email-change/${token}`)
    expect(context.status).toBe(200)
    const body = await context.json() as Record<string, unknown>
    expect(body).toMatchObject({ name: 'Tess Example', email: 'tess@example.org', newEmail: 'tess.new@example.org', kind: 'change' })
    // TODO.identity-features/01: the context names the ceremony's kind
    // ('change' here — the legacy primary replacement).
    expect(Object.keys(body).sort()).toEqual(['email', 'expiresAt', 'kind', 'name', 'newEmail'])
    const unknown = await app.request('/api/op/email-change/nope')
    expect(unknown.status).toBe(404)
  })

  it('completion moves the address; the SHOWN link leaves it unverified; the sign-in follows', async () => {
    const { cookie } = await enrollAccount('uma@example.org', 'Uma Example')
    // Enrolled through the invite ceremony: the address on file is verified.
    const before = await (await app.request('/api/op/account', { headers: { cookie } })).json() as { account: { emailVerifiedAt: string | null } }
    expect(before.account.emailVerifiedAt).not.toBeNull()

    const res = await app.request('/api/op/account/email', {
      method: 'POST', headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ email: 'uma.new@example.org' }),
    })
    const { verificationUrl } = await res.json() as { verificationUrl: string }
    const token = new URL(verificationUrl).searchParams.get('token')!
    const done = await app.request(`/api/op/email-change/${token}`, { method: 'POST' })
    expect(done.status).toBe(200)
    // The honest bit: nothing proved the new mailbox, so verified=false.
    expect(await done.json()).toMatchObject({ ok: true, email: 'uma.new@example.org', verified: false })

    const after = await (await app.request('/api/op/account', { headers: { cookie } })).json() as { account: { email: string; emailVerifiedAt: string | null } }
    expect(after.account.email).toBe('uma.new@example.org')
    expect(after.account.emailVerifiedAt).toBeNull()

    expect((await passwordLogin('uma.new@example.org', 'a perfectly good passphrase')).status).toBe(200)
    expect((await passwordLogin('uma@example.org', 'a perfectly good passphrase')).status).toBe(401)
  })

  it('a MAILER-delivered link verifies the address at completion', async () => {
    const { id } = await enrollAccount('vera@example.org', 'Vera Example')
    // The store seam directly: 09's mailer path stamps delivered_by='mailer'.
    const token = mintEnrollmentToken()
    await store.createEmailChangeToken({ token, userId: id, newEmail: 'vera.new@example.org', deliveredBy: 'mailer', ttlMs: 60_000 })
    const done = await app.request(`/api/op/email-change/${token}`, { method: 'POST' })
    expect(done.status).toBe(200)
    expect(await done.json()).toMatchObject({ ok: true, verified: true })
    const user = await store.getUserById(id)
    expect(user?.email).toBe('vera.new@example.org')
    expect(user?.emailVerifiedAt).not.toBeNull()
  })

  it("an ADMIN-SET address (03's registry edit) resets the verification state honestly", async () => {
    const { id } = await enrollAccount('otto2@example.org', 'Otto Two')
    // Enrolled through the invite ceremony: verified.
    expect((await store.getUserById(id))?.emailVerifiedAt).not.toBeNull()
    const admin = await demoLogin('admin@oiml.org')
    const edit = await app.request(`/api/op/accounts/${id}`, {
      method: 'PUT', headers: { 'content-type': 'application/json', cookie: admin },
      body: JSON.stringify({ email: 'otto2.edited@example.org' }),
    })
    expect(edit.status).toBe(200)
    // The admin-set address never saw the ceremony: back to unverified.
    expect((await store.getUserById(id))?.email).toBe('otto2.edited@example.org')
    expect((await store.getUserById(id))?.emailVerifiedAt).toBeNull()
  })

  it('the expired, the used, and the taken-meantime exits are honest', async () => {
    const { id } = await enrollAccount('walt@example.org', 'Walt Example')

    // Expired: minted already-dead, burned on presentation.
    const dead = mintEnrollmentToken()
    await store.createEmailChangeToken({ token: dead, userId: id, newEmail: 'walt.dead@example.org', deliveredBy: 'shown', ttlMs: -1 })
    expect((await app.request(`/api/op/email-change/${dead}`)).status).toBe(410)
    expect((await app.request(`/api/op/email-change/${dead}`, { method: 'POST' })).status).toBe(410)
    expect((await store.getUserById(id))?.email).toBe('walt@example.org')

    // Taken meantime: another account claims the address after the request.
    const live = mintEnrollmentToken()
    await store.createEmailChangeToken({ token: live, userId: id, newEmail: 'walt.taken@example.org', deliveredBy: 'shown', ttlMs: 60_000 })
    await enrollAccount('walt.taken@example.org', 'The Other Walt')
    const conflict = await app.request(`/api/op/email-change/${live}`, { method: 'POST' })
    expect(conflict.status).toBe(409)
    // …and the link is burned (a replay never completes later).
    expect((await app.request(`/api/op/email-change/${live}`, { method: 'POST' })).status).toBe(410)
  })
})

// ── the sign-in methods' guard ───────────────────────────────────────

describe('the at-least-one-method guard', () => {
  it('the password removal refuses when it is the only way in, succeeds with a link present', async () => {
    const { id, cookie } = await enrollAccount('xenia@example.org', 'Xenia Example')
    const refused = await app.request('/api/op/account/password', { method: 'DELETE', headers: { cookie } })
    expect(refused.status).toBe(409)
    expect(await refused.json()).toMatchObject({ error: expect.stringContaining('only way to sign in') })

    await store.createIdentityLink({ userId: id, provider: 'github', providerAccountId: 'gh-xenia', linkedBy: 'test' })
    const ok = await app.request('/api/op/account/password', { method: 'DELETE', headers: { cookie } })
    expect(ok.status).toBe(200)
    expect((await passwordLogin('xenia@example.org', 'a perfectly good passphrase')).status).toBe(401)
    // …and with no password left, removing the LAST link refuses too.
    const unlink = await app.request('/api/op/account/links/github', { method: 'DELETE', headers: { cookie } })
    expect(unlink.status).toBe(409)
    expect(await unlink.json()).toMatchObject({ error: expect.stringContaining('only way to sign in') })
    expect(await store.findIdentityLink('github', 'gh-xenia')).not.toBeNull()
  })
})

// ── the password change's session revocation ─────────────────────────

describe('the password change and the sessions', () => {
  it('changing the password revokes every OTHER session and names the count', async () => {
    const { cookie: cookie1 } = await enrollAccount('yuri@example.org', 'Yuri Example', 'yuri has a proper passphrase')
    const login2 = await passwordLogin('yuri@example.org', 'yuri has a proper passphrase')
    const cookie2 = login2.headers.get('set-cookie')!.split(';')[0]!

    const change = await app.request('/api/op/account/password', {
      method: 'POST', headers: { 'content-type': 'application/json', cookie: cookie1 },
      body: JSON.stringify({ current: 'yuri has a proper passphrase', next: 'yuri has a NEW proper passphrase' }),
    })
    expect(change.status).toBe(200)
    expect(await change.json()).toMatchObject({ ok: true, otherSessionsRevoked: 1 })

    // The other session is dead; the changing session stands.
    expect((await app.request('/api/auth/session', { headers: { cookie: cookie2 } })).status).toBe(401)
    expect((await app.request('/api/auth/session', { headers: { cookie: cookie1 } })).status).toBe(200)
    expect((await passwordLogin('yuri@example.org', 'yuri has a NEW proper passphrase')).status).toBe(200)
  })

  it('revoke-others signs out everywhere else (the current session stands)', async () => {
    const { cookie: cookie1 } = await enrollAccount('zelda@example.org', 'Zelda Example', 'zelda has a proper passphrase')
    const cookie2 = (await passwordLogin('zelda@example.org', 'zelda has a proper passphrase')).headers.get('set-cookie')!.split(';')[0]!
    const cookie3 = (await passwordLogin('zelda@example.org', 'zelda has a proper passphrase')).headers.get('set-cookie')!.split(';')[0]!

    const res = await app.request('/api/op/account/sessions/revoke-others', { method: 'POST', headers: { cookie: cookie1 } })
    expect(res.status).toBe(200)
    expect(await res.json()).toMatchObject({ ok: true, revoked: 2 })
    expect((await app.request('/api/auth/session', { headers: { cookie: cookie1 } })).status).toBe(200)
    expect((await app.request('/api/auth/session', { headers: { cookie: cookie2 } })).status).toBe(401)
    expect((await app.request('/api/auth/session', { headers: { cookie: cookie3 } })).status).toBe(401)
  })

  it('the session rows carry the sign-in context (user agent, IP, last-active)', async () => {
    const { cookie } = await enrollAccount('otto@example.org', 'Otto Example', 'otto has a proper passphrase')
    const login = await app.request('/api/op/login', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'user-agent': 'ConsoleTest/1.0 (the second browser)',
        'x-forwarded-for': '203.0.113.10, 10.0.0.1',
      },
      body: JSON.stringify({ email: 'otto@example.org', password: 'otto has a proper passphrase' }),
    })
    expect(login.status).toBe(200)
    const otherCookie = login.headers.get('set-cookie')!.split(';')[0]!
    // Resolve the session once: the throttled last-active stamp lands.
    expect((await app.request('/api/auth/session', { headers: { cookie: otherCookie } })).status).toBe(200)

    const context = await app.request('/api/op/account', { headers: { cookie } })
    const { sessions } = await context.json() as { sessions: Array<{ userAgent: string | null; ip: string | null; lastSeenAt: string | null; current: boolean }> }
    expect(sessions.length).toBe(2)
    const other = sessions.find(s => !s.current)!
    expect(other.userAgent).toBe('ConsoleTest/1.0 (the second browser)')
    expect(other.ip).toBe('203.0.113.10')
    expect(other.lastSeenAt).not.toBeNull()
  })
})

// ── the activity feed ────────────────────────────────────────────────

describe('the activity feed', () => {
  it('lists the account’s own sign-in and security events, newest first, scoped and clean', async () => {
    const { id, cookie } = await enrollAccount('anna@example.org', 'Anna Example', 'anna has a proper passphrase')
    await passwordLogin('anna@example.org', 'anna has a proper passphrase')
    await app.request('/api/op/account/profile', {
      method: 'POST', headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ name: 'Anna Actual' }),
    })
    await app.request('/api/op/account/password', {
      method: 'POST', headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ current: 'anna has a proper passphrase', next: 'anna has a NEW proper passphrase' }),
    })

    const res = await app.request('/api/op/account/activity', { headers: { cookie } })
    expect(res.status).toBe(200)
    const events = await res.json() as Array<{ id: string; timestamp: string; action: string; metadata: Record<string, unknown> }>
    const actions = events.map(e => e.action)
    expect(actions).toContain('account.enrolled')
    expect(actions).toContain('account.sign_in')
    expect(actions).toContain('account.profile')
    expect(actions).toContain('account.password')
    // Newest first.
    const stamps = events.map(e => e.timestamp)
    expect(stamps).toEqual([...stamps].sort().reverse())
    expect(events[0]!.action).toBe('account.password')
    // Scoped: another account's events never appear.
    expect(events.every(e => !JSON.stringify(e.metadata).includes('yuri'))).toBe(true)
    const ids = new Set(events.map(e => e.id))
    const otherAccountEvents = (await store.listEntities('auditEvents'))
      .map(r => JSON.parse(r.data) as { id: string; entity_id: string })
      .filter(e => e.entity_id !== id && (e.entity_id ?? '').length > 10)
    expect(otherAccountEvents.some(e => ids.has(e.id))).toBe(false)
    // Never credential material.
    expect(JSON.stringify(events)).not.toContain('pbkdf2')
    expect(JSON.stringify(events)).not.toContain('anna has a')

    // An anonymous call is refused.
    expect((await app.request('/api/op/account/activity')).status).toBe(401)
  })
})
