// ─────────────────────────────────────────────────────────────────────
// TODO.identity/02 — the OP's account model, proven in two layers:
//
//   1. THE PURE PIECES: the PBKDF2 hashing (round-trip, wrong-password,
//      malformed-store, and the login path's TIMING SHAPE — an unknown
//      account pays one full-cost verify too), the password policy and
//      the honest meter, and the OP_ACCOUNT_SEED parse.
//   2. THE ROUTES, in-process: the REAL op-accounts router over a REAL
//      temp SQLite store:
//
//      invite → the setup context → policy refusal (the link is NOT
//      burned) → the password set → the sign-in. Plus the guards: the
//      enrollment link's one-time + expiry + re-issue, the deactivated
//      account's honest refusal, the session listing + revocation, the
//      admin gate, and the module gate.
//
// The LINKED sign-in methods (GitHub/OIDC upstreams — the link flow, the
// match rule "never by email", the honest not-linked refusal) are
// TODO.identity/08's registry-driven surface, proven in
// id-upstream.test.ts + d1-store.test.ts's links legs.
// ─────────────────────────────────────────────────────────────────────

import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

// The store's DB path is read at module evaluation — set it before any
// import below touches @oimlsmart/platform-server/store/sqlite (the imports are dynamic).
const TMP = mkdtempSync(join(tmpdir(), 'oiml-op-accounts-'))
process.env.DATABASE_PATH = join(TMP, 'test.db')

const ISSUER = 'http://op.test'
process.env.OP_ISSUER = ISSUER

import {
  hashPassword,
  passwordPolicy,
  passwordStrength,
  verifyPassword,
  verifyPasswordLogin,
  PASSWORD_PBKDF2_ITERATIONS,
} from '../../server/auth/passwords'
import {
  mintEnrollmentToken,
  parseOpAccountSeed,
} from '../../server/auth/op/accounts'

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

/** Invite an account as the admin; answers the API payload (the account
 *  + the one-time setup link). */
async function invite(email: string, name: string, role = 'viewer'): Promise<{ account: { id: string; email: string }; setupUrl: string }> {
  const admin = await demoLogin('admin@oiml.org')
  const res = await app.request('/api/op/accounts', {
    method: 'POST',
    headers: { 'content-type': 'application/json', cookie: admin },
    body: JSON.stringify({ email, name, role }),
  })
  expect(res.status, `invite ${email}`).toBe(201)
  return res.json() as Promise<{ account: { id: string; email: string }; setupUrl: string }>
}

/** Set the account's password through the enrollment link; answers the
 *  session cookie (the completion signs the account in). */
async function enroll(setupUrl: string, password: string): Promise<string> {
  const token = new URL(setupUrl).searchParams.get('token')!
  const res = await app.request(`/api/op/enroll/${token}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ password }),
  })
  expect(res.status, 'the enrollment completes').toBe(200)
  return res.headers.get('set-cookie')!.split(';')[0]!
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
  const root = new Hono()
  root.route('/api/auth', createAuthLeanRouter({ autoSeedDemo: true }))
  root.route('/', createOpAccountsRouter())
  app = root
  // The demo cast lands on the first auth request (ensureInit).
  await demoLogin('admin@oiml.org')
})

afterAll(async () => {
  rmSync(TMP, { recursive: true, force: true })
  delete process.env.OP_ISSUER
  delete process.env.DATABASE_PATH
  const profileMod = await import('@oimlsmart/platform-server/profile')
  profileMod.resetInstanceProfileForTest()
})

// ── the hashing ──────────────────────────────────────────────────────

describe('the password hashing (PBKDF2 over WebCrypto)', () => {
  it('round-trips: the right password verifies, the wrong one does not', async () => {
    const stored = await hashPassword('a correct horse battery staple')
    expect(stored.startsWith(`pbkdf2:${PASSWORD_PBKDF2_ITERATIONS}:`)).toBe(true)
    expect(await verifyPassword('a correct horse battery staple', stored)).toBe(true)
    expect(await verifyPassword('a correct horse battery staple!', stored)).toBe(false)
    // Two hashes of the same password differ (fresh salt).
    expect(await hashPassword('a correct horse battery staple')).not.toBe(stored)
  }, 30_000)

  it('the cost factor never exceeds the workerd PBKDF2 cap (100,000) — the deployment runtime', () => {
    // 2026-08-16: 600,000 (the OWASP recommendation) threw
    // NotSupportedError on Workers and 500'd every password path.
    expect(PASSWORD_PBKDF2_ITERATIONS).toBeLessThanOrEqual(100_000)
  })

  it('an over-cap stored hash fails with the named error, never a 500', async () => {
    const overCap = `pbkdf2:600000:c2FsdA==:aGFzaA==`
    await expect(verifyPassword('anything', overCap)).rejects.toThrow(/PBKDF2 cap/)
  })

  it('a malformed stored value never verifies (fail closed)', async () => {
    expect(await verifyPassword('whatever-whatever', 'pbkdf2:not-a-number:aa:bb')).toBe(false)
    expect(await verifyPassword('whatever-whatever', 'bcrypt:100000:aa:bb')).toBe(false)
    expect(await verifyPassword('whatever-whatever', 'garbage')).toBe(false)
  })

  it('the login path is timing-shaped: an unknown account pays one full-cost verify too', async () => {
    const stored = await hashPassword('the real account password')
    const t0 = performance.now()
    const knownWrong = await verifyPasswordLogin('the wrong password!!', stored)
    const t1 = performance.now()
    const unknownAccount = await verifyPasswordLogin('the wrong password!!', null)
    const t2 = performance.now()
    expect(knownWrong).toBe(false)
    expect(unknownAccount).toBe(false)
    // The timing shape: BOTH paths run a full PBKDF2 — the no-credential
    // path is the same order of magnitude as the real one (never a fast
    // bail, which would be a user-enumeration oracle). The bound is
    // generous (CI hosts vary); the SHAPE is what is pinned.
    expect(t2 - t1).toBeGreaterThan((t1 - t0) / 10)
  }, 30_000)
})

describe('the password policy + the honest meter', () => {
  it('gates on length ≥ 12, nothing else', () => {
    expect(passwordPolicy('short').ok).toBe(false)
    expect(passwordPolicy('short').problems[0]).toContain('12')
    expect(passwordPolicy('exactlytwelve')).toEqual({ ok: true, problems: [] })
    // No invented complexity rules: a lowercase-only 12+ passes the gate.
    expect(passwordPolicy('a simple long lowercase passphrase').ok).toBe(true)
    expect(passwordPolicy('x'.repeat(2000)).ok).toBe(false)
  })

  it('the meter classes are honest and monotone in length', () => {
    expect(passwordStrength('short').score).toBe(0)
    expect(passwordStrength('short').hint).toContain('12')
    expect(passwordStrength('twelvecharsok').score).toBe(1)
    expect(passwordStrength('twelve chars ok!').score).toBe(2)
    expect(passwordStrength('a genuinely long and varied passphrase 2026').score).toBe(3)
  })
})

// ── the enrollment store semantics ───────────────────────────────────

describe('the enrollment link (one-time, 24 h)', () => {
  it('the context answers the account (name + email, nothing more)', async () => {
    const { setupUrl } = await invite('carol@example.org', 'Carol Example')
    const token = new URL(setupUrl).searchParams.get('token')!
    const res = await app.request(`/api/op/enroll/${token}`)
    expect(res.status).toBe(200)
    const body = await res.json() as Record<string, unknown>
    expect(body).toMatchObject({ name: 'Carol Example', email: 'carol@example.org' })
    expect(Object.keys(body).sort()).toEqual(['email', 'expiresAt', 'name'])
  })

  it('a policy-refused password does NOT burn the link', async () => {
    const { setupUrl } = await invite('dave@example.org', 'Dave Example')
    const token = new URL(setupUrl).searchParams.get('token')!
    const refused = await app.request(`/api/op/enroll/${token}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ password: 'tooshort' }),
    })
    expect(refused.status).toBe(400)
    expect(await refused.json()).toMatchObject({ error: expect.stringContaining('12') })
    // …and the link still works.
    const cookie = await enroll(setupUrl, 'dave has a proper password')
    expect(cookie).toContain('oiml-session=')
  })

  it('one-time means one-time: a used link never completes again', async () => {
    const { setupUrl } = await invite('erin@example.org', 'Erin Example')
    const token = new URL(setupUrl).searchParams.get('token')!
    await enroll(setupUrl, 'erin has a proper password')
    const replay = await app.request(`/api/op/enroll/${token}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ password: 'a second try at the link' }),
    })
    expect(replay.status).toBe(410)
    const context = await app.request(`/api/op/enroll/${token}`)
    expect(context.status).toBe(410)
    expect(await context.json()).toMatchObject({ error: 'used' })
  })

  it('an expired link is burned on presentation (never redeemed later)', async () => {
    const { account } = await invite('frank@example.org', 'Frank Example')
    // A token minted already-expired (the store takes the ttl honestly).
    const token = mintEnrollmentToken()
    await store.createEnrollmentToken({ token, userId: account.id, createdBy: 'test', ttlMs: -1 })
    const context = await app.request(`/api/op/enroll/${token}`)
    expect(context.status).toBe(410)
    expect(await context.json()).toMatchObject({ error: 'expired' })
    const complete = await app.request(`/api/op/enroll/${token}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ password: 'frank has a proper password' }),
    })
    expect(complete.status).toBe(410)
    // The account holds NO credential (the expired link never set one).
    expect(await store.getPasswordLogin('frank@example.org')).toBeNull()
  })

  it('the admin can re-issue a fresh link when one expires', async () => {
    const admin = await demoLogin('admin@oiml.org')
    const { account } = await invite('grace@example.org', 'Grace Example')
    const fresh = await app.request(`/api/op/accounts/${account.id}/enrollment`, {
      method: 'POST',
      headers: { cookie: admin },
    })
    expect(fresh.status).toBe(201)
    const { setupUrl } = await fresh.json() as { setupUrl: string }
    const cookie = await enroll(setupUrl, 'grace has a proper password')
    expect(cookie).toContain('oiml-session=')
  })
})

// ── the password sign-in ─────────────────────────────────────────────

describe('the password sign-in', () => {
  it('signs the account in; the wrong password and the unknown email refuse identically', async () => {
    await enroll((await invite('heidi@example.org', 'Heidi Example')).setupUrl, 'heidi has a proper password')
    const ok = await passwordLogin('heidi@example.org', 'heidi has a proper password')
    expect(ok.status).toBe(200)
    expect(ok.headers.get('set-cookie')).toContain('oiml-session=')
    expect(await ok.json()).toMatchObject({ email: 'heidi@example.org', name: 'Heidi Example' })

    const wrong = await passwordLogin('heidi@example.org', 'heidi has a WRONG password')
    expect(wrong.status).toBe(401)
    expect(await wrong.json()).toEqual({ error: 'Invalid email or password' })
    const unknown = await passwordLogin('nobody@example.org', 'heidi has a proper password')
    expect(unknown.status).toBe(401)
    expect(await unknown.json()).toEqual({ error: 'Invalid email or password' })
    // The email lookup normalizes (the invite lowercases too).
    const mixed = await passwordLogin('Heidi@Example.ORG', 'heidi has a proper password')
    expect(mixed.status).toBe(200)
  })

  it('an account without a credential refuses (the dummy verify stands in)', async () => {
    await invite('ivan@example.org', 'Ivan Example') // invited, never enrolled
    const res = await passwordLogin('ivan@example.org', 'ivan has a proper password')
    expect(res.status).toBe(401)
  })

  it('a deactivated account with the RIGHT password gets the honest refusal', async () => {
    const { account, setupUrl } = await invite('judy@example.org', 'Judy Example')
    await enroll(setupUrl, 'judy has a proper password')
    await store.setUserActive(account.id, false)
    const res = await passwordLogin('judy@example.org', 'judy has a proper password')
    expect(res.status).toBe(403)
    expect(await res.json()).toMatchObject({ error: expect.stringContaining('deactivated') })
    await store.setUserActive(account.id, true)
  })

  it('the password change requires the CURRENT password when one is set', async () => {
    const cookie = await enroll((await invite('kim@example.org', 'Kim Example')).setupUrl, 'kim has a proper password')
    // A wrong current password is refused (one full-cost verify either way).
    const wrong = await app.request('/api/op/account/password', {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ current: 'not kim password at all', next: 'kim has a NEW proper password' }),
    })
    expect(wrong.status).toBe(403)
    const ok = await app.request('/api/op/account/password', {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ current: 'kim has a proper password', next: 'kim has a NEW proper password' }),
    })
    expect(ok.status).toBe(200)
    // …and the new password signs in.
    expect((await passwordLogin('kim@example.org', 'kim has a NEW proper password')).status).toBe(200)
  })
})

// ── the account page's sessions ──────────────────────────────────────

describe('the account sessions', () => {
  it('lists the live sessions (current marked, tokens never exposed) and revokes', async () => {
    const cookie1 = await enroll((await invite('noah@example.org', 'Noah Example')).setupUrl, 'noah has a proper password')
    // A second session (another browser).
    const login = await passwordLogin('noah@example.org', 'noah has a proper password')
    const cookie2 = login.headers.get('set-cookie')!.split(';')[0]!

    const account = await app.request('/api/op/account', { headers: { cookie: cookie1 } })
    const body = await account.json() as { sessions: Array<{ id: string; current: boolean }> }
    expect(body.sessions.length).toBe(2)
    expect(body.sessions.filter(s => s.current)).toHaveLength(1)
    // The token never leaves the store.
    expect(JSON.stringify(body)).not.toContain(cookie1.split('=')[1]!.slice(0, 12))

    // Revoke the OTHER session: it stops resolving; the current one stands.
    const other = body.sessions.find(s => !s.current)!
    const revoked = await app.request(`/api/op/account/sessions/${other.id}/revoke`, { method: 'POST', headers: { cookie: cookie1 } })
    expect(revoked.status).toBe(200)
    const after = await app.request('/api/auth/session', { headers: { cookie: cookie2 } })
    expect(after.status).toBe(401)
    const mine = await app.request('/api/auth/session', { headers: { cookie: cookie1 } })
    expect(mine.status).toBe(200)

    // A session id that is not the account's is a no-op 404.
    const foreign = await app.request(`/api/op/account/sessions/${other.id}/revoke`, { method: 'POST', headers: { cookie: cookie1 } })
    expect(foreign.status).toBe(404)
  })
})

// ── the admin surface + the module gate ──────────────────────────────

describe('the invite surface', () => {
  it('anonymous and non-admin sessions are refused; the duplicate email answers 409', async () => {
    const anon = await app.request('/api/op/accounts', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ email: 'x@y.org', name: 'X' }) })
    expect(anon.status).toBe(401)
    const viewer = await demoLogin('viewer@oiml.org')
    const notAdmin = await app.request('/api/op/accounts', { method: 'POST', headers: { 'content-type': 'application/json', cookie: viewer }, body: JSON.stringify({ email: 'x@y.org', name: 'X' }) })
    expect(notAdmin.status).toBe(403)

    const admin = await demoLogin('admin@oiml.org')
    const dupe = await app.request('/api/op/accounts', { method: 'POST', headers: { 'content-type': 'application/json', cookie: admin }, body: JSON.stringify({ email: 'heidi@example.org', name: 'Heidi Again' }) })
    expect(dupe.status).toBe(409)
    // The invite payload never carries credential material.
    const invited = await app.request('/api/op/accounts', { method: 'POST', headers: { 'content-type': 'application/json', cookie: admin }, body: JSON.stringify({ email: 'olivia@example.org', name: 'Olivia Example' }) })
    expect(invited.status).toBe(201)
    const body = await invited.json() as Record<string, unknown>
    expect(body.setupUrl).toContain('/op/setup?token=')
    expect(JSON.stringify(body)).not.toContain('password')
  })

  it('the account list answers the sign-in posture (never credentials)', async () => {
    const admin = await demoLogin('admin@oiml.org')
    const list = await app.request('/api/op/accounts', { headers: { cookie: admin } })
    expect(list.status).toBe(200)
    const rows = await list.json() as Array<{ email: string; passwordSet: boolean; links: unknown[] }>
    const heidi = rows.find(r => r.email === 'heidi@example.org')!
    expect(heidi.passwordSet).toBe(true)
    expect(rows.find(r => r.email === 'olivia@example.org')!.passwordSet).toBe(false)
    expect(JSON.stringify(rows)).not.toContain('pbkdf2')
  })
})

// ── the self-service password reset (the forgot-password path) ───────
// The no-mailer posture is what THIS harness carries (no MAIL_* envs):
// the route's honest 503. The mailed half (the enumeration-blind answer,
// the captured reset email completing at /op/setup) lives in
// id-mail.test.ts, over the stub provider.

describe('the self-service password reset', () => {
  it('a malformed address refuses with the validation error', async () => {
    const res = await app.request('/api/op/login/reset', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: 'not-an-address' }),
    })
    expect(res.status).toBe(400)
  })

  it('no mail provider: the honest 503 (the reset link never shows on screen)', async () => {
    for (const target of ['heidi@example.org', 'nobody@example.org']) {
      const res = await app.request('/api/op/login/reset', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ email: target }),
      })
      expect(res.status, target).toBe(503)
      const body = await res.json() as { error: string; mailAvailable: boolean }
      expect(body.mailAvailable).toBe(false)
      expect(body.error).toContain('cannot send email')
      expect(body.error).toContain('administrator')
    }
  })
})

// ── the avatar (the console's upload, size-capped + type-allowlisted) ─

describe('the avatar upload', () => {
  // A 1x1 transparent PNG (67 bytes), a minimal GIF89a header, and a
  // WebP RIFF header — real magic bytes for the sniff legs.
  const PNG = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==', 'base64')
  const GIF = Buffer.concat([Buffer.from('GIF89a', 'ascii'), Buffer.from([1, 0, 1, 0, 0, 0, 0])])
  const WEBP = Buffer.concat([Buffer.from('RIFF', 'ascii'), Buffer.from([4, 0, 0, 0]), Buffer.from('WEBP', 'ascii')])

  /** The in-memory BlobStore for these legs (the seam's honest 503 is
   *  proven first, with nothing installed). */
  function memoryBlobs() {
    const map = new Map<string, { data: ArrayBuffer; contentType: string | null }>()
    return {
      map,
      async put(key: string, data: ArrayBuffer, contentType: string | null) { map.set(key, { data, contentType }) },
      async get(key: string) {
        const hit = map.get(key)
        return hit ? { data: hit.data, contentType: hit.contentType, size: hit.data.byteLength } : null
      },
      async delete(key: string) { map.delete(key) },
    }
  }

  async function accountContext(cookie: string): Promise<{ account: { avatarUrl: string | null }; features: { avatarUploads: boolean; avatarMaxBytes: number } }> {
    const res = await app.request('/api/op/account', { headers: { cookie } })
    expect(res.status).toBe(200)
    return res.json() as Promise<{ account: { avatarUrl: string | null }; features: { avatarUploads: boolean; avatarMaxBytes: number } }>
  }

  it('no blob store bound: the context says unavailable and every avatar route answers the honest 503', async () => {
    const { uninstallBlobStoreForTest } = await import('../../server/blobs')
    uninstallBlobStoreForTest()
    const cookie = await enroll((await invite('marco@example.org', 'Marco Avatar')).setupUrl, 'marco has a proper passphrase')
    const context = await accountContext(cookie)
    expect(context.features.avatarUploads).toBe(false)
    expect(context.features.avatarMaxBytes).toBe(2 * 1024 * 1024) // the default 2 MiB cap, named
    for (const [method, path] of [['PUT', '/api/op/account/avatar'], ['GET', '/api/op/account/avatar'], ['DELETE', '/api/op/account/avatar']] as const) {
      const res = await app.request(path, { method, headers: { cookie, 'content-type': 'image/png' }, body: method === 'PUT' ? PNG : undefined })
      expect(res.status, `${method} ${path}`).toBe(503)
    }
  })

  it('the full circle: upload → the context carries it → the serve → replace → remove', async () => {
    const blobsMod = await import('../../server/blobs')
    const mem = memoryBlobs()
    blobsMod.installBlobStore(mem)
    try {
      const cookie = await enroll((await invite('nina@example.org', 'Nina Avatar')).setupUrl, 'nina has a proper passphrase')
      expect((await accountContext(cookie)).features.avatarUploads).toBe(true)

      // The upload: raw PNG bytes with their declared type.
      const put = await app.request('/api/op/account/avatar', { method: 'PUT', headers: { cookie, 'content-type': 'image/png' }, body: PNG })
      expect(put.status).toBe(200)
      const putBody = await put.json() as { avatarUrl: string; size: number; type: string }
      expect(putBody).toMatchObject({ avatarUrl: '/api/op/account/avatar', size: PNG.byteLength, type: 'image/png' })
      expect((await accountContext(cookie)).account.avatarUrl).toBe('/api/op/account/avatar')

      // The serve: the same bytes, the stored type, the no-sniff header.
      const got = await app.request('/api/op/account/avatar', { headers: { cookie } })
      expect(got.status).toBe(200)
      expect(got.headers.get('content-type')).toBe('image/png')
      expect(got.headers.get('x-content-type-options')).toBe('nosniff')
      expect(Buffer.from(await got.arrayBuffer()).equals(PNG)).toBe(true)

      // The replace: a GIF upload retires the PNG key.
      const replace = await app.request('/api/op/account/avatar', { method: 'PUT', headers: { cookie, 'content-type': 'image/gif' }, body: GIF })
      expect(replace.status).toBe(200)
      expect(mem.map.has('avatars/' + (await store.findUserByEmail('nina@example.org'))!.id + '/avatar.png')).toBe(false)
      const gotGif = await app.request('/api/op/account/avatar', { headers: { cookie } })
      expect(gotGif.headers.get('content-type')).toBe('image/gif')

      // The remove: the context drops the URL, the serve 404s.
      const del = await app.request('/api/op/account/avatar', { method: 'DELETE', headers: { cookie } })
      expect(del.status).toBe(200)
      expect((await accountContext(cookie)).account.avatarUrl).toBeNull()
      const gone = await app.request('/api/op/account/avatar', { headers: { cookie } })
      expect(gone.status).toBe(404)
      expect([...mem.map.keys()].filter(k => k.includes('/avatar.'))).toHaveLength(0)
    } finally {
      blobsMod.uninstallBlobStoreForTest()
    }
  })

  it('the caps + the allowlist: oversize (declared AND actual), the wrong type, the mislabeled bytes — all refused, nothing stored', async () => {
    const blobsMod = await import('../../server/blobs')
    const mem = memoryBlobs()
    blobsMod.installBlobStore(mem)
    try {
      const cookie = await enroll((await invite('omar@example.org', 'Omar Caps')).setupUrl, 'omar has a proper passphrase')

      // The declared length over the cap refuses before the body is read
      // (a constructed bodyless Request keeps the header the client sent).
      const declaredReq = new Request('http://localhost/api/op/account/avatar', {
        method: 'PUT',
        headers: { cookie, 'content-type': 'image/png', 'content-length': String(3 * 1024 * 1024) },
      })
      const declared = await app.request(declaredReq)
      expect(declared.status).toBe(413)
      expect((await declared.json() as { error: string }).error).toContain('2 MB')

      // The actual bytes over the cap refuse after the read (the declared
      // length never gets the last word).
      const big = Buffer.alloc(2 * 1024 * 1024 + 1)
      PNG.copy(big) // a real PNG header, then bulk
      const actual = await app.request('/api/op/account/avatar', { method: 'PUT', headers: { cookie, 'content-type': 'image/png' }, body: big })
      expect(actual.status).toBe(413)

      // SVG is NOT an avatar type (an image channel never becomes a
      // script channel).
      const svg = await app.request('/api/op/account/avatar', { method: 'PUT', headers: { cookie, 'content-type': 'image/svg+xml' }, body: Buffer.from('<svg xmlns="http://www.w3.org/2000/svg"/>') })
      expect(svg.status).toBe(415)

      // The bytes must match the label: a JPEG declared as PNG refuses.
      const mislabeled = await app.request('/api/op/account/avatar', { method: 'PUT', headers: { cookie, 'content-type': 'image/png' }, body: WEBP })
      expect(mislabeled.status).toBe(415)

      expect(mem.map.size).toBe(0) // nothing was stored
      expect((await accountContext(cookie)).account.avatarUrl).toBeNull()
    } finally {
      blobsMod.uninstallBlobStoreForTest()
    }
  })

  it('the audit chain records the upload and the removal', async () => {
    const blobsMod = await import('../../server/blobs')
    const mem = memoryBlobs()
    blobsMod.installBlobStore(mem)
    try {
      const cookie = await enroll((await invite('petra@example.org', 'Petra Audit')).setupUrl, 'petra has a proper passphrase')
      await app.request('/api/op/account/avatar', { method: 'PUT', headers: { cookie, 'content-type': 'image/png' }, body: PNG })
      await app.request('/api/op/account/avatar', { method: 'DELETE', headers: { cookie } })
      const feed = await app.request('/api/op/account/activity', { headers: { cookie } })
      const actions = (await feed.json() as Array<{ action: string }>).map(e => e.action)
      expect(actions).toContain('account.avatar')
      expect(actions).toContain('account.avatar_removed')
    } finally {
      blobsMod.uninstallBlobStoreForTest()
    }
  })
})

// ── the avatar fallback (the public route's generated initials) ──────

describe('the generated-initials fallback (auth/op/avatars.ts)', () => {
  it('the initials rule mirrors the console exactly', async () => {
    const { avatarInitials } = await import('../../server/auth/op/avatars')
    expect(avatarInitials('Nina Avatar')).toBe('NA')
    expect(avatarInitials('Madonna')).toBe('MM') // the console's rule: first + last word, one word twice
    expect(avatarInitials('  spaced   out   name ')).toBe('SN')
    expect(avatarInitials('')).toBe('?')
    expect(avatarInitials('   ')).toBe('?')
    expect(avatarInitials('lower case')).toBe('LC')
  })

  it('the SVG is inert and carries the initials (escaped) in the brand palette', async () => {
    const { initialsAvatarSvg } = await import('../../server/auth/op/avatars')
    const svg = initialsAvatarSvg('Nina Avatar')
    expect(svg).toContain('>NA</text>')
    expect(svg).toContain('#dde9fc') // brand-100, the console chip's light scheme
    expect(svg).toContain('#003a78') // brand-700
    expect(svg).not.toContain('<script')
    // A hostile name never breaks out of the markup.
    const evil = initialsAvatarSvg('<script>')
    expect(evil).not.toContain('<script>')
    expect(evil).toContain('&lt;')
  })
})

// ── the erasure (the offboarding runbook's delete path) ──────────────

describe('the account erasure (DELETE /api/op/accounts/:id)', () => {
  it('anonymous and non-admin sessions are refused; the unknown id 404s', async () => {
    const anon = await app.request('/api/op/accounts/nope', { method: 'DELETE' })
    expect(anon.status).toBe(401)
    const viewer = await demoLogin('viewer@oiml.org')
    const notAdmin = await app.request('/api/op/accounts/nope', { method: 'DELETE', headers: { cookie: viewer } })
    expect(notAdmin.status).toBe(403)
    const admin = await demoLogin('admin@oiml.org')
    const unknown = await app.request('/api/op/accounts/nope', { method: 'DELETE', headers: { cookie: admin } })
    expect(unknown.status).toBe(404)
  })

  it('you cannot erase your own account (the lockout guard)', async () => {
    const invited = await invite('second-admin@example.org', 'Second Admin', 'admin')
    const cookie = await enroll(invited.setupUrl, 'second admin has a passphrase')
    const res = await app.request(`/api/op/accounts/${invited.account.id}`, { method: 'DELETE', headers: { cookie } })
    expect(res.status).toBe(400)
    expect((await res.json() as { error: string }).error).toContain('your own account')
  })

  it('the full erasure: every credential, link-token and grant goes; the row is an anonymized tombstone; the email is free again', async () => {
    const admin = await demoLogin('admin@oiml.org')
    const invited = await invite('quentin@example.org', 'Quentin Erased')
    const cookie = await enroll(invited.setupUrl, 'quentin has a proper passphrase')
    const id = invited.account.id

    const res = await app.request(`/api/op/accounts/${id}`, { method: 'DELETE', headers: { cookie: admin } })
    expect(res.status).toBe(200)

    // Sign-ins refuse (the credential is gone) and the session is dead.
    const login = await passwordLogin('quentin@example.org', 'quentin has a proper passphrase')
    expect(login.status).toBe(401)
    const deadSession = await app.request('/api/op/account', { headers: { cookie } })
    expect(deadSession.status).toBe(401)

    // The registry list no longer carries the account…
    const list = await app.request('/api/op/accounts', { headers: { cookie: admin } })
    const rows = await list.json() as Array<{ id: string; email: string }>
    expect(rows.some(r => r.id === id)).toBe(false)

    // …but the tombstone row stands, anonymized, for the audit chain.
    const row = (await store.listUsers()).find(u => u.id === id)!
    expect(row.name).toBe('Deleted account')
    expect(row.email).toBe(`deleted-${id}@erased.invalid`)
    expect(row.provider).toBe('erased')
    expect(row.active).toBe(false)
    expect(row.orgId).toBeNull()

    // A second erasure 404s (the account is gone from the registry's
    // surface), and the freed email invites again.
    const again = await app.request(`/api/op/accounts/${id}`, { method: 'DELETE', headers: { cookie: admin } })
    expect(again.status).toBe(404)
    const reinvited = await app.request('/api/op/accounts', { method: 'POST', headers: { 'content-type': 'application/json', cookie: admin }, body: JSON.stringify({ email: 'quentin@example.org', name: 'Quentin New' }) })
    expect(reinvited.status).toBe(201)

    // The audit event names the act + the actor (the journal stands).
    const audits = (await store.listEntities('auditEvents')).map(r => JSON.parse(r.data) as { action: string; entity_id: string; user_name?: string })
    const del = audits.find(e => e.action === 'account.deleted' && e.entity_id === id)!
    expect(del.user_name).toBe('OIML Admin')
  })
})

describe('the module gate', () => {
  it('a non-identity profile answers 404 on the account routes', async () => {
    const profileMod = await import('@oimlsmart/platform-server/profile')
    profileMod.resetInstanceProfileForTest() // the hub default (no identity module)
    try {
      for (const [method, path] of [
        ['POST', '/api/op/login'],
        ['POST', '/api/op/accounts'],
        ['GET', '/api/op/enroll/whatever'],
        ['GET', '/api/op/account'],
      ] as const) {
        const res = await app.request(`${ISSUER}${path}`, { method })
        expect(res.status, `${method} ${path}`).toBe(404)
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

// ── the seed parse (the pure piece) ──────────────────────────────────

describe('the OP_ACCOUNT_SEED declaration', () => {
  it('parses the valid shape and refuses the malformed ones honestly', () => {
    expect(parseOpAccountSeed('[{"email":"root@oimlsmart.org","name":"Root","role":"admin"}]')).toEqual([
      { email: 'root@oimlsmart.org', name: 'Root', role: 'admin' },
    ])
    expect(() => parseOpAccountSeed('{"email":"x@y.org"}')).toThrow('JSON array')
    expect(() => parseOpAccountSeed('[{"name":"No email"}]')).toThrow('email is required')
    expect(() => parseOpAccountSeed('[{"email":"x@y.org"}]')).toThrow('name is required')
  })
})
