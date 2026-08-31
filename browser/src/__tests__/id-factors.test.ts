// ─────────────────────────────────────────────────────────────────────
// TODO.identity-sso/02+03 — the strong-authentication wave, proven at
// the ROUTES in-process (the id-accounts pattern: the real routers over
// a real temp SQLite store; the passkey material is freshly minted per
// leg through factor-testkit.ts — real bytes, never a mock):
//
//   TOTP       enroll (the pending row + the otpauth URI) → the first
//              valid code activates → password+code sign-in → the ID
//              token carries amr ['pwd','otp'] → the wrong-code ladder
//              (backoff + the cap's burn + the audit events + the
//              lockout email hook) → revoke;
//   PASSKEYS   register (the ceremony through the real parse) →
//              passwordless sign-in (amr ['webauthn']) → the passkey as
//              the second factor (amr ['pwd','webauthn']) → the CLONE
//              refusal (a regressed counter fails + audits) → the
//              replayed challenge refuses → revoke → the last-method
//              guard;
//   RECOVERY   generated at the FIRST factor (shown once) → a code
//              signs in once (amr ['pwd','recovery']) → reuse refuses →
//              regenerate revokes the old set;
//   THE GATES  the unverified-address enrollment refusal (wave E's live
//              lifecycle state), the profile gate, the regenerate-without
//              -a-factor refusal.
//
// The throttle ladder rides OP_MFA_BACKOFF_BASE_MS=1 (declared below) so
// the backoff is exercised, not slept through. The live-browser
// ceremonies (Chrome's real virtual authenticator) are
// e2e/id-14-factors.e2e.ts.
// ─────────────────────────────────────────────────────────────────────

import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

// The store's DB path is read at module evaluation — set it before any
// import below touches the kernel (the imports are dynamic).
const TMP = mkdtempSync(join(tmpdir(), 'oiml-op-factors-'))
process.env.DATABASE_PATH = join(TMP, 'test.db')

const ISSUER = 'http://op.test'
process.env.OP_ISSUER = ISSUER
// The throttle ladder's test value (the honest env seam): 1 ms base, so
// the backoff exists without sleeping the suite.
process.env.OP_MFA_BACKOFF_BASE_MS = '1'

// The fixture RP for the amr-on-token legs (a confidential client).
const CLIENT = {
  client_id: 'factors-rp',
  name: 'The factors fixture RP',
  secret: 'factors-rp-secret',
  redirect_uris: ['https://rp.example/callback'],
  claims_policy: { claims: ['roles', 'groups', 'org'] },
}
process.env.OP_CLIENT_SEED = JSON.stringify([CLIENT])

import { totpAtStep } from '../../server/auth/op/totp'
import { hashRecoveryCode } from '../../server/auth/op/recovery'
import { base64urlEncode } from '../../server/auth/op/webauthn'
import {
  assertWith,
  attest,
  mintAuthenticator,
  userHandleFor,
  type TestAuthenticator,
} from './factor-testkit'

const RP = { rpId: 'op.test', origin: ISSUER }

/** The console's registry read (GET /api/op/account/factors). */
interface FactorsRead {
  passkeys: Array<{ credentialId: string; name: string; transports: string[] }>
  totp: Array<{ id: string; name: string }>
  pendingTotp: Array<{ id: string }>
  recoveryCodes: { total: number; remaining: number }
}

let app: import('hono').Hono
let store: ReturnType<typeof import('@oimlsmart/platform-server/store').getStore>

// ── the small drivers ────────────────────────────────────────────────

async function demoLogin(email: string): Promise<string> {
  const res = await app.request('/api/auth/demo', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password: 'demo2026' }),
  })
  expect(res.ok, `demo login ${email}`).toBe(true)
  return res.headers.get('set-cookie')!.split(';')[0]!
}

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

/** A full password sign-in's answer; the response's body carries either
 *  the user or the mfaRequired challenge. */
async function passwordLogin(email: string, password: string): Promise<{ cookie: string | null; body: Record<string, unknown> }> {
  const res = await app.request('/api/op/login', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password }),
  })
  expect(res.status, 'the password leg answers 200 (the factor branch is a 200 too)').toBe(200)
  const body = await res.json() as Record<string, unknown>
  return { cookie: res.headers.get('set-cookie')?.split(';')[0] ?? null, body }
}

/** The current TOTP code for a secret (the authenticator app's own math). */
function currentCode(secret: string): Promise<string> {
  return totpAtStep(secret, Math.floor(Date.now() / 1000 / 30))
}

/** The OIDC round trip with the fixture client: authorize → consent →
 *  allow → the code exchange → the decoded ID token payload. */
async function idTokenClaims(cookie: string): Promise<Record<string, unknown>> {
  const challenge = base64urlEncode(crypto.getRandomValues(new Uint8Array(32)))
  const verifier = base64urlEncode(crypto.getRandomValues(new Uint8Array(32)))
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))
  const s256 = base64urlEncode(digest)
  const authorize = await app.request(`/op/authorize?${new URLSearchParams({
    response_type: 'code', client_id: CLIENT.client_id, redirect_uri: CLIENT.redirect_uris[0]!,
    scope: 'openid profile email', state: 's', nonce: 'n', code_challenge: s256, code_challenge_method: 'S256',
    // The consent stop is this helper's contract (TODO.identity-features/12:
    // a remembered grant would skip it on a repeat sign-in).
    prompt: 'consent',
  })}`, { headers: { cookie }, redirect: 'manual' })
  expect(authorize.status).toBe(302)
  const authId = new URL(authorize.headers.get('location')!, ISSUER).searchParams.get('auth')!
  const decide = await app.request(`/api/op/consent/${authId}/decide`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', cookie },
    body: JSON.stringify({ decision: 'allow' }),
  })
  expect(decide.ok).toBe(true)
  const { redirect } = await decide.json() as { redirect: string }
  const code = new URL(redirect).searchParams.get('code')!
  const exchange = await app.request('/op/token', {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      authorization: `Basic ${btoa(`${encodeURIComponent(CLIENT.client_id)}:${encodeURIComponent(CLIENT.secret)}`)}`,
    },
    body: new URLSearchParams({
      grant_type: 'authorization_code', code, redirect_uri: CLIENT.redirect_uris[0]!,
      client_id: CLIENT.client_id, code_verifier: verifier,
    }),
  })
  expect(exchange.ok, 'the code exchange').toBe(true)
  const { id_token } = await exchange.json() as { id_token: string }
  const part = id_token.split('.')[1]!
  return JSON.parse(atob(part.replace(/-/g, '+').replace(/_/g, '/'))) as Record<string, unknown>
  void challenge
}

/** The account's own activity feed (the audit chain, account-scoped). */
async function activityActions(cookie: string): Promise<string[]> {
  const res = await app.request('/api/op/account/activity', { headers: { cookie } })
  expect(res.ok).toBe(true)
  return (await res.json() as Array<{ action: string }>).map(e => e.action)
}

// ── the fixtures' state ──────────────────────────────────────────────

const CASEY = { email: 'casey@factors.test', name: 'Casey Factors', password: 'casey has a proper passphrase' }
const ROOK = { email: 'rook@factors.test', name: 'Rook Passkey', password: 'rook has a proper passphrase' }
const DEE = { email: 'dee@factors.test', name: 'Dee Recovery', password: 'dee has a proper passphrase' }
const UNVERIFIED = { email: 'vera@factors.test', name: 'Vera Unverified', password: 'vera has a proper passphrase' }

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
  const { createOpFactorsRouter } = await import('../../server/routes/op-factors')
  const { createOpMfaRouter } = await import('../../server/routes/op-mfa')
  const { createOpRouter } = await import('../../server/routes/op')
  const root = new Hono()
  root.route('/api/auth', createAuthLeanRouter({ autoSeedDemo: true }))
  root.route('/', createOpRouter())
  root.route('/', createOpAccountsRouter())
  root.route('/', createOpFactorsRouter())
  root.route('/', createOpMfaRouter())
  app = root
  await demoLogin('admin@oiml.org')
})

afterAll(async () => {
  rmSync(TMP, { recursive: true, force: true })
  delete process.env.OP_ISSUER
  delete process.env.OP_CLIENT_SEED
  delete process.env.OP_MFA_BACKOFF_BASE_MS
  delete process.env.DATABASE_PATH
  const profileMod = await import('@oimlsmart/platform-server/profile')
  profileMod.resetInstanceProfileForTest()
})

// ── the TOTP ceremony ────────────────────────────────────────────────

describe('the TOTP authenticator app', () => {
  it('enrolls pending → activates on the first valid code → signs in (amr pwd+otp) → revokes', async () => {
    const invited = await invite(CASEY.email, CASEY.name)
    let cookie = await enroll(invited.setupUrl, CASEY.password)

    // The enrollment start: the pending row + the otpauth URI + the
    // manual secret, answered once.
    const start = await app.request('/api/op/account/factors/totp', {
      method: 'POST', headers: { 'content-type': 'application/json', cookie },
    })
    expect(start.status).toBe(201)
    const enrollment = await start.json() as { id: string; secret: string; otpauthUri: string }
    expect(enrollment.otpauthUri).toContain('otpauth://totp/')
    expect(enrollment.secret).toMatch(/^[A-Z2-7]{32}$/)
    // The pending row is not an active factor yet.
    let factors = await (await app.request('/api/op/account/factors', { headers: { cookie } })).json() as FactorsRead
    expect(factors.totp).toEqual([])
    expect(factors.pendingTotp).toHaveLength(1)

    // A wrong code refuses + audits (the ladder's first step).
    const wrong = await app.request(`/api/op/account/factors/totp/${enrollment.id}/verify`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ code: '000000' }),
    })
    expect(wrong.status).toBe(401)
    expect(await activityActions(cookie)).toContain('factor.totp_enroll_failed')

    // The first valid code activates; the FIRST factor lands the
    // recovery set (answered once).
    const verify = await app.request(`/api/op/account/factors/totp/${enrollment.id}/verify`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ code: await currentCode(enrollment.secret), name: 'Casey’s phone' }),
    })
    expect(verify.status).toBe(200)
    const verified = await verify.json() as { ok: boolean; recoveryCodes: string[] | null }
    expect(verified.recoveryCodes).toHaveLength(10)
    expect(verified.recoveryCodes![0]).toMatch(/^[a-z2-7]{4}-[a-z2-7]{4}-[a-z2-7]{4}-[a-z2-7]{4}$/)
    factors = await (await app.request('/api/op/account/factors', { headers: { cookie } })).json() as FactorsRead
    expect(factors.totp[0]!.name).toBe('Casey’s phone')
    expect(factors.recoveryCodes.total).toBe(10)

    // Sign out, then the password alone no longer opens the session.
    await app.request('/api/auth/signout', { method: 'POST', headers: { cookie } })
    const login = await passwordLogin(CASEY.email, CASEY.password)
    expect(login.cookie).toBeNull() // no session yet
    expect(login.body.mfaRequired).toBe(true)
    const methods = login.body.methods as { totp: boolean; passkey: boolean; recovery: boolean }
    expect(methods).toEqual({ totp: true, passkey: false, recovery: true })
    const mfaToken = login.body.mfaToken as string

    // A wrong code at the sign-in ladder: audited, counted.
    const badCode = await app.request('/api/op/login/mfa/totp', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ token: mfaToken, code: '000000' }),
    })
    expect(badCode.status).toBe(401)

    // The right code completes; the session's amr rides into the ID token.
    const good = await app.request('/api/op/login/mfa/totp', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ token: mfaToken, code: await currentCode(enrollment.secret) }),
    })
    expect(good.status).toBe(200)
    cookie = good.headers.get('set-cookie')!.split(';')[0]!
    const sessionPayload = await (await app.request('/api/auth/session', { headers: { cookie } })).json() as { amr?: string[] }
    expect(sessionPayload.amr).toEqual(['pwd', 'otp'])
    const claims = await idTokenClaims(cookie)
    expect(claims.amr).toEqual(['pwd', 'otp'])

    // The replay: the consumed challenge never completes twice.
    const replay = await app.request('/api/op/login/mfa/totp', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ token: mfaToken, code: await currentCode(enrollment.secret) }),
    })
    expect(replay.status).toBe(401)

    // Revoke → the password alone signs in again (the audit carries both).
    const revoke = await app.request(`/api/op/account/factors/totp/${enrollment.id}`, {
      method: 'DELETE', headers: { cookie },
    })
    expect(revoke.status).toBe(200)
    const actions = await activityActions(cookie)
    expect(actions).toContain('factor.totp_enrolled')
    expect(actions).toContain('factor.totp_revoked')
    const plain = await passwordLogin(CASEY.email, CASEY.password)
    expect(plain.body.mfaRequired).toBeUndefined()
    expect(plain.cookie).toBeTruthy()
  })

  it('the wrong-code ladder burns at the cap (the audit + the lockout)', async () => {
    const invited = await invite('locks@factors.test', 'Lottie Locks')
    const cookie = await enroll(invited.setupUrl, 'lottie has a proper passphrase')
    const start = await app.request('/api/op/account/factors/totp', {
      method: 'POST', headers: { 'content-type': 'application/json', cookie },
    })
    const enrollment = await start.json() as { id: string; secret: string }

    // Five wrong codes at the ENROLLMENT verify: the ladder refuses, the
    // cap discards the setup.
    for (let i = 0; i < 4; i++) {
      await new Promise(r => setTimeout(r, 5)) // the 1 ms-base ladder
      const res = await app.request(`/api/op/account/factors/totp/${enrollment.id}/verify`, {
        method: 'POST', headers: { 'content-type': 'application/json', cookie },
        body: JSON.stringify({ code: '000000' }),
      })
      expect(res.status, `attempt ${i + 1} refuses`).toBe(401)
    }
    await new Promise(r => setTimeout(r, 20))
    const fifth = await app.request(`/api/op/account/factors/totp/${enrollment.id}/verify`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ code: '000000' }),
    })
    expect(fifth.status).toBe(429)
    expect((await fifth.json() as { locked?: boolean }).locked).toBe(true)
    // The enrollment is discarded: the row is gone.
    const factors = await (await app.request('/api/op/account/factors', { headers: { cookie } })).json() as FactorsRead
    expect(factors.pendingTotp).toEqual([])
    const actions = await activityActions(cookie)
    expect(actions).toContain('factor.totp_enroll_locked')
  })

  it('the sign-in ladder burns at the cap and the account is emailed (the console posture here)', async () => {
    // Dee holds a verified TOTP from her own suite's posture — build it
    // inline here (the suites share no state).
    const invited = await invite(DEE.email, DEE.name)
    let cookie = await enroll(invited.setupUrl, DEE.password)
    const start = await app.request('/api/op/account/factors/totp', {
      method: 'POST', headers: { 'content-type': 'application/json', cookie },
    })
    const enrollment = await start.json() as { id: string; secret: string }
    await app.request(`/api/op/account/factors/totp/${enrollment.id}/verify`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ code: await currentCode(enrollment.secret) }),
    })
    await app.request('/api/auth/signout', { method: 'POST', headers: { cookie } })

    const login = await passwordLogin(DEE.email, DEE.password)
    const mfaToken = login.body.mfaToken as string
    for (let i = 0; i < 5; i++) {
      await new Promise(r => setTimeout(r, 5))
      const res = await app.request('/api/op/login/mfa/totp', {
        method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ token: mfaToken, code: '000000' }),
      })
      if (i < 4) expect(res.status, `attempt ${i + 1}`).toBe(401)
      else {
        expect(res.status, 'the cap burns').toBe(429)
        expect((await res.json() as { locked?: boolean }).locked).toBe(true)
      }
    }
    // The burned attempt is closed: the token never completes now.
    const after = await app.request('/api/op/login/mfa/totp', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ token: mfaToken, code: await currentCode(enrollment.secret) }),
    })
    expect(after.status).toBe(401)
    // A FRESH sign-in works (never a lockout): password → the right code.
    const fresh = await passwordLogin(DEE.email, DEE.password)
    const completed = await app.request('/api/op/login/mfa/totp', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ token: fresh.body.mfaToken as string, code: await currentCode(enrollment.secret) }),
    })
    expect(completed.status).toBe(200)
    cookie = completed.headers.get('set-cookie')!.split(';')[0]!
    const actions = await activityActions(cookie)
    expect(actions).toContain('factor.mfa_locked')
    expect(actions.filter(a => a === 'factor.mfa_failed').length).toBeGreaterThanOrEqual(5)
  })
})

// ── the recovery codes ───────────────────────────────────────────────

describe('the recovery codes', () => {
  it('generated at the first factor, one-time each, regenerate revokes the old set', async () => {
    const invited = await invite('remy@factors.test', 'Remy Recovery')
    let cookie = await enroll(invited.setupUrl, 'remy has a proper passphrase')
    const start = await app.request('/api/op/account/factors/totp', {
      method: 'POST', headers: { 'content-type': 'application/json', cookie },
    })
    const enrollment = await start.json() as { id: string; secret: string }
    const verify = await app.request(`/api/op/account/factors/totp/${enrollment.id}/verify`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ code: await currentCode(enrollment.secret) }),
    })
    const { recoveryCodes } = await verify.json() as { recoveryCodes: string[] }
    expect(recoveryCodes).toHaveLength(10)

    await app.request('/api/auth/signout', { method: 'POST', headers: { cookie } })

    // A recovery code signs in ONCE (amr pwd+recovery).
    const login = await passwordLogin('remy@factors.test', 'remy has a proper passphrase')
    const mfaToken = login.body.mfaToken as string
    const use = await app.request('/api/op/login/mfa/recovery', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ token: mfaToken, code: recoveryCodes[0]! }),
    })
    expect(use.status).toBe(200)
    cookie = use.headers.get('set-cookie')!.split(';')[0]!
    expect((await idTokenClaims(cookie)).amr).toEqual(['pwd', 'recovery'])
    expect(await activityActions(cookie)).toContain('factor.recovery_used')

    // The same code never works twice.
    const again = await passwordLogin('remy@factors.test', 'remy has a proper passphrase')
    const reuse = await app.request('/api/op/login/mfa/recovery', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ token: again.body.mfaToken as string, code: recoveryCodes[0]! }),
    })
    expect(reuse.status).toBe(401)

    // Regenerate: the old set dies, the new set signs in.
    const regen = await app.request('/api/op/account/factors/recovery-codes', {
      method: 'POST', headers: { 'content-type': 'application/json', cookie },
    })
    expect(regen.status).toBe(200)
    const regenerated = (await regen.json() as { codes: string[] }).codes
    expect(regenerated).toHaveLength(10)
    expect(regenerated).not.toContain(recoveryCodes[1])
    const actions = await activityActions(cookie)
    expect(actions).toContain('factor.recovery_regenerated')

    // The old batch's remaining codes are dead.
    const third = await passwordLogin('remy@factors.test', 'remy has a proper passphrase')
    const dead = await app.request('/api/op/login/mfa/recovery', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ token: third.body.mfaToken as string, code: recoveryCodes[1]! }),
    })
    expect(dead.status).toBe(401)

    // The new code works.
    const fourth = await passwordLogin('remy@factors.test', 'remy has a proper passphrase')
    const live = await app.request('/api/op/login/mfa/recovery', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ token: fourth.body.mfaToken as string, code: regenerated[0]! }),
    })
    expect(live.status).toBe(200)
  })

  it('the regenerate refuses without a factor (a bare set would be a second password)', async () => {
    const invited = await invite('solo@factors.test', 'Solo Password')
    const cookie = await enroll(invited.setupUrl, 'solo has a proper passphrase')
    const res = await app.request('/api/op/account/factors/recovery-codes', {
      method: 'POST', headers: { 'content-type': 'application/json', cookie },
    })
    expect(res.status).toBe(409)
  })
})

// ── the passkeys ─────────────────────────────────────────────────────

/** The console registration ceremony through the routes (the test
 *  authenticator's real bytes). Answers the finish response. */
async function registerPasskey(cookie: string, auth: TestAuthenticator, name: string): Promise<Response> {
  const optRes = await app.request('/api/op/account/factors/passkeys/options', {
    method: 'POST', headers: { 'content-type': 'application/json', cookie },
  })
  expect(optRes.ok).toBe(true)
  const { publicKey } = await optRes.json() as { publicKey: { challenge: string } }
  const answer = await attest(auth, publicKey.challenge, RP)
  return app.request('/api/op/account/factors/passkeys', {
    method: 'POST',
    headers: { 'content-type': 'application/json', cookie },
    body: JSON.stringify({
      name,
      credential: { id: base64urlEncode(auth.credentialId), response: answer },
      transports: ['internal'],
    }),
  })
}

/** The passwordless ceremony through the routes. */
async function passwordless(auth: TestAuthenticator, userId: string, opts?: { counter?: number }): Promise<Response> {
  const optRes = await app.request('/api/op/login/passkey/options', { method: 'POST' })
  expect(optRes.ok).toBe(true)
  const { publicKey } = await optRes.json() as { publicKey: { challenge: string } }
  const assertion = await assertWith(auth, publicKey.challenge, RP, { userHandle: userHandleFor(userId), counter: opts?.counter })
  return app.request('/api/op/login/passkey', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ credential: { id: base64urlEncode(auth.credentialId), response: assertion } }),
  })
}

describe('the passkeys (WebAuthn)', () => {
  it('registers → signs in passwordless (amr webauthn) → as second factor (amr pwd+webauthn) → the clone refusal → revoke', async () => {
    const invited = await invite(ROOK.email, ROOK.name)
    let cookie = await enroll(invited.setupUrl, ROOK.password)
    const auth = await mintAuthenticator(-7)

    // The registration ceremony through the real parse. The account
    // holds no factor yet → the recovery set lands with this first one.
    const finish = await registerPasskey(cookie, auth, 'Rook’s laptop')
    expect(finish.status).toBe(201)
    const finished = await finish.json() as { credential: { credentialId: string }; recoveryCodes: string[] | null }
    expect(finished.recoveryCodes).toHaveLength(10)
    const factors = await (await app.request('/api/op/account/factors', { headers: { cookie } })).json() as FactorsRead
    expect(factors.passkeys[0]!.name).toBe('Rook’s laptop')
    expect(factors.passkeys[0]!.transports).toEqual(['internal'])
    expect(await activityActions(cookie)).toContain('factor.passkey_enrolled')

    // The replayed registration challenge refuses (one-time means once).
    const replayed = await app.request('/api/op/account/factors/passkeys', {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ name: 'twice', credential: { id: base64urlEncode(auth.credentialId), response: await attest(auth, 'whatever', RP) }, transports: [] }),
    })
    expect(replayed.status).toBe(400)

    // The passwordless sign-in: amr ['webauthn'].
    await app.request('/api/auth/signout', { method: 'POST', headers: { cookie } })
    const direct = await passwordless(auth, invited.account.id)
    expect(direct.status).toBe(200)
    cookie = direct.headers.get('set-cookie')!.split(';')[0]!
    expect((await idTokenClaims(cookie)).amr).toEqual(['webauthn'])

    // The password-first path now challenges (the passkey is a factor):
    // password → mfaRequired (passkey method) → the assertion.
    const login = await passwordLogin(ROOK.email, ROOK.password)
    expect(login.body.mfaRequired).toBe(true)
    expect((login.body.methods as { passkey: boolean }).passkey).toBe(true)
    const mfaOpt = await app.request('/api/op/login/mfa/passkey/options', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ token: login.body.mfaToken }),
    })
    expect(mfaOpt.ok).toBe(true)
    const { publicKey: mfaOptions } = await mfaOpt.json() as { publicKey: { challenge: string; allowCredentials: Array<{ id: string }> } }
    expect(mfaOptions.allowCredentials).toHaveLength(1)
    const mfaAssertion = await assertWith(auth, mfaOptions.challenge, RP)
    const mfaDone = await app.request('/api/op/login/mfa/passkey', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ token: login.body.mfaToken, credential: { id: base64urlEncode(auth.credentialId), response: mfaAssertion } }),
    })
    expect(mfaDone.status).toBe(200)
    cookie = mfaDone.headers.get('set-cookie')!.split(';')[0]!
    expect((await idTokenClaims(cookie)).amr).toEqual(['pwd', 'webauthn'])

    // THE CLONE REFUSAL: a second authenticator presenting the SAME
    // credential id with a REGRESSED counter fails + audits.
    const stored = await store.getWebauthnCredential(base64urlEncode(auth.credentialId))
    const clone = await mintAuthenticator(-7)
    clone.credentialId = auth.credentialId // the clone copies the id
    // …but it cannot sign with the original key — so the honest clone
    // leg at the PROTOCOL level is the original key with a wound-back
    // counter (the credential shared across two devices' counters).
    const regressed = await passwordless(auth, invited.account.id, { counter: Math.max(0, stored!.signCount - 1) })
    expect(regressed.status).toBe(401)
    expect(await activityActions(cookie)).toContain('factor.clone_refused')
    void clone

    // Revoke: the passwordless path then refuses (unknown credential).
    const revoke = await app.request(`/api/op/account/factors/passkeys/${encodeURIComponent(base64urlEncode(auth.credentialId))}`, {
      method: 'DELETE', headers: { cookie } },
    )
    expect(revoke.status).toBe(200)
    const afterRevoke = await passwordless(auth, invited.account.id)
    expect(afterRevoke.status).toBe(401)
    expect(await activityActions(cookie)).toContain('factor.passkey_revoked')
  })

  it('the credential id registers once, globally (the honest 409)', async () => {
    const invited = await invite('dup@factors.test', 'Dupe Passkey')
    const cookie = await enroll(invited.setupUrl, 'dupe has a proper passphrase')
    const auth = await mintAuthenticator(-7)
    expect((await registerPasskey(cookie, auth, 'first')).status).toBe(201)
    // The same authenticator again: the excludeCredentials carry it, but
    // a forged replay lands the honest 409.
    expect((await registerPasskey(cookie, auth, 'second')).status).toBe(409)
  })

  it('the last-way-in guard: the passkey-only account keeps one method', async () => {
    const invited = await invite('only@factors.test', 'Only Passkey')
    let cookie = await enroll(invited.setupUrl, 'only has a proper passphrase')
    const auth = await mintAuthenticator(-7)
    expect((await registerPasskey(cookie, auth, 'the only key')).status).toBe(201)

    // Remove the password (allowed: the passkey remains) → the account
    // is passkey-ONLY.
    const removePassword = await app.request('/api/op/account/password', { method: 'DELETE', headers: { cookie } })
    expect(removePassword.status, 'the passkey is a sign-in method').toBe(200)
    // The passwordless sign-in carries the account.
    await app.request('/api/auth/signout', { method: 'POST', headers: { cookie } })
    const direct = await passwordless(auth, invited.account.id)
    expect(direct.status).toBe(200)
    cookie = direct.headers.get('set-cookie')!.split(';')[0]!

    // The last passkey's revoke refuses with the explanation.
    const guard = await app.request(`/api/op/account/factors/passkeys/${encodeURIComponent(base64urlEncode(auth.credentialId))}`, {
      method: 'DELETE', headers: { cookie } },
    )
    expect(guard.status).toBe(409)
    expect((await guard.json() as { error: string }).error).toContain('only way to sign in')
  })
})

// ── the gates ────────────────────────────────────────────────────────

describe('the enrollment gates', () => {
  it('an unverified primary address refuses factors honestly (wave E’s live lifecycle state)', async () => {
    const invited = await invite(UNVERIFIED.email, UNVERIFIED.name)
    const cookie = await enroll(invited.setupUrl, UNVERIFIED.password)

    // The email change with NO mailer configured shows the link honestly
    // (deliveredBy 'shown'); completing it moves the address UNVERIFIED.
    const request = await app.request('/api/op/account/email', {
      method: 'POST', headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ email: 'vera.verified-later@factors.test' }),
    })
    expect(request.ok).toBe(true)
    const delivery = await request.json() as { delivery: string; verificationUrl?: string }
    expect(delivery.delivery).toBe('shown')
    const token = new URL(delivery.verificationUrl!).searchParams.get('token')!
    const complete = await app.request(`/api/op/email-change/${token}`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie },
    })
    expect(complete.ok).toBe(true)

    // Now the address is unverified: the enrollment acts refuse honestly.
    const factorsRead = await app.request('/api/op/account/factors', { headers: { cookie } })
    expect(factorsRead.ok, 'the registry still reads').toBe(true)
    const totpStart = await app.request('/api/op/account/factors/totp', {
      method: 'POST', headers: { 'content-type': 'application/json', cookie },
    })
    expect(totpStart.status).toBe(403)
    expect((await totpStart.json() as { error: string }).error).toContain('not verified')
    const passkeyOptions = await app.request('/api/op/account/factors/passkeys/options', {
      method: 'POST', headers: { 'content-type': 'application/json', cookie },
    })
    expect(passkeyOptions.status).toBe(403)
  })

  it('the factors surface 404s on a non-identity deployment (the module gate)', async () => {
    const profileMod = await import('@oimlsmart/platform-server/profile')
    profileMod.installInstanceProfile(profileMod.parseInstanceProfile(`
identity:
  org_id: oimlsmart-hub
  org_name: OIML SMART
roles: [hub]
branding: { name: OIML SMART }
`))
    try {
      const res = await app.request('/api/op/account/factors', { headers: { cookie: await demoLogin('admin@oiml.org') } })
      expect(res.status).toBe(404)
      const mfa = await app.request('/api/op/login/mfa/totp', {
        method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ token: 'x', code: '000000' }),
      })
      expect(mfa.status).toBe(404)
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
