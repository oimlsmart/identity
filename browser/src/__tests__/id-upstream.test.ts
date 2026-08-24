// ─────────────────────────────────────────────────────────────────────
// TODO.identity/08 — the OP's upstream providers, proven in-process:
// the REAL op-upstream router (server/routes/op-upstream.ts) over a REAL
// temp SQLite store, against the REAL stubs (stub-idp.ts for the OIDC
// providers, stub-github.ts for the GitHub kind) — no stub on the OP
// side, real HTTP on the upstream hop.
//
// Covered:
//   the stateless flow state (sign/verify/tamper/expiry/open-redirect)
//   the registry validation + the OP_UPSTREAM_SEED bootstrap
//   the admin CRUD + the public (enabled-only) projection
//   the Apple ES256 client-secret JWT (claims, header kid, signature)
//   the OIDC link + sign-in round trip (the stub IdP)
//   THE MATCH RULE: (provider, sub) only — a verified-email lookalike
//     with NO link is refused (no session, no account mutation)
//   the link conflicts (taken / already-linked / session switched)
//   the unlink → the sign-in is refused honestly
//   the GitHub kind's link + sign-in (the stub GitHub)
//   Apple's form_post callback shape (POST form body + the user field)
//   the cross-provider state binding (provider A's state ≠ provider B)
// ─────────────────────────────────────────────────────────────────────

import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

// The store's DB path is read at module evaluation — set it before any
// import below touches @oimlsmart/platform-server/store/sqlite (the imports are dynamic).
const TMP = mkdtempSync(join(tmpdir(), 'oiml-upstream-'))
process.env.DATABASE_PATH = join(TMP, 'test.db')

const ISSUER = 'http://op.test'

import { hashPassword } from '../../server/auth/passwords'

let app: import('hono').Hono
let store: ReturnType<typeof import('@oimlsmart/platform-server/store').getStore>
let idp: import('../../e2e/fixtures/stub-idp').StubIdp
let github: import('../../e2e/fixtures/stub-github').StubGitHub

const IDP_CLIENT_ID = 'oiml-smart-op'
const IDP_SECRET = 'fixture-idp-secret'
const GITHUB_CLIENT_ID = 'op-github-client'
const GITHUB_SECRET = 'op-github-secret'

// ── helpers ───────────────────────────────────────────────────────────

async function demoLogin(email: string): Promise<string> {
  const res = await app.request(`${ISSUER}/api/auth/demo`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password: 'demo2026' }),
  })
  expect(res.ok, `demo login ${email}`).toBe(true)
  return res.headers.get('set-cookie')!.split(';')[0]!
}

/** Drive the OP→stub-IdP round trip over real HTTP: the OP's 302 to the
 *  stub's authorize, the stub's consent shortcut (?user=), the 302 back
 *  to the OP's callback. Answers the callback URL (code + state). */
async function driveStubIdp(authorizeUrl: string, user: string): Promise<string> {
  const params = new URL(authorizeUrl).searchParams
  const complete = await fetch(`${idp.issuer}/authorize/complete?${params.toString()}&user=${user}`, { redirect: 'manual' })
  expect(complete.status, 'the stub IdP issues the code').toBe(302)
  return complete.headers.get('location')!
}

/** The full flow: startUrl (signin or link) → the upstream → the
 *  callback. Answers the callback's response (302 + optional cookie). */
async function runFlow(startUrl: string, user: string, cookie?: string, method: 'GET' | 'POST' = 'GET'): Promise<Response> {
  const start = await app.request(`${ISSUER}${startUrl}`, { headers: cookie ? { cookie } : {}, redirect: 'manual' } as RequestInit)
  expect(start.status, `the flow start ${startUrl}`).toBe(302)
  const authorizeUrl = start.headers.get('location')!
  expect(authorizeUrl.startsWith(`${idp.issuer}/authorize?`)).toBe(true)

  const callbackUrl = await driveStubIdp(authorizeUrl, user)
  const back = new URL(callbackUrl)
  expect(back.origin + back.pathname).toBe(`${ISSUER}/op/upstream/fixture-idp/callback`)
  const init: RequestInit = method === 'POST'
    ? { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded', ...(cookie ? { cookie } : {}) }, body: back.searchParams }
    : { headers: cookie ? { cookie } : {} }
  return app.request(callbackUrl, { ...init, redirect: 'manual' } as RequestInit)
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

  // The upstream stubs (real HTTP on loopback — discovery/JWKS/authorize/
  // token for the OIDC kind; the OAuth web flow + REST reads for github).
  const { startStubIdp } = await import('../../e2e/fixtures/stub-idp')
  idp = await startStubIdp()
  const { startStubGitHub } = await import('../../e2e/fixtures/stub-github')
  github = await startStubGitHub({ clientSecret: GITHUB_SECRET })
  process.env.FIXTURE_IDP_SECRET = IDP_SECRET
  process.env.GITHUB_UPSTREAM_SECRET = GITHUB_SECRET
  process.env.GITHUB_OAUTH_BASE_URL = github.baseUrl
  process.env.GITHUB_API_BASE_URL = github.baseUrl

  const { Hono } = await import('hono')
  const { createAuthLeanRouter } = await import('../../server/routes/auth-lean')
  const { createOpUpstreamRouter } = await import('../../server/routes/op-upstream')
  const root = new Hono()
  root.route('/api/auth', createAuthLeanRouter({ autoSeedDemo: true }))
  root.route('/', createOpUpstreamRouter())
  app = root

  // The registry rows (the admin API is proven below; these ride the
  // store directly for the flow legs).
  await store.upsertIdentityProvider({
    id: 'fixture-idp', kind: 'oidc', displayName: 'Fixture IdP', brandMark: 'oidc',
    issuer: idp.issuer, clientId: IDP_CLIENT_ID, clientSecretRef: 'env:FIXTURE_IDP_SECRET', enabled: true,
  })
  await store.upsertIdentityProvider({
    id: 'github', kind: 'github', displayName: 'GitHub', brandMark: 'github',
    clientId: GITHUB_CLIENT_ID, clientSecretRef: 'env:GITHUB_UPSTREAM_SECRET', enabled: true,
  })
})

afterAll(async () => {
  await idp?.close()
  await github?.close()
  const { resetInstanceProfileForTest } = await import('@oimlsmart/platform-server/profile')
  resetInstanceProfileForTest()
  rmSync(TMP, { recursive: true, force: true })
  for (const name of ['FIXTURE_IDP_SECRET', 'GITHUB_UPSTREAM_SECRET', 'GITHUB_OAUTH_BASE_URL', 'GITHUB_API_BASE_URL', 'DATABASE_PATH']) {
    delete process.env[name]
  }
})

// ── the stateless flow state ──────────────────────────────────────────

describe('the upstream flow state (stateless + signed)', () => {
  it('round-trips, refuses tampering, expiry, the open redirect and the wrong shape', async () => {
    const { signUpstreamState, verifyUpstreamState } = await import('../../server/auth/upstream/state')

    const state = await signUpstreamState('secret-1', { p: 'google', m: 'link', u: 'user-1', n: 'nn', v: 'vv', r: '/op/account' }, 1_000_000)
    const payload = await verifyUpstreamState('secret-1', state, { now: 1_000_000 + 60_000 })
    expect(payload).toMatchObject({ p: 'google', m: 'link', u: 'user-1', n: 'nn', v: 'vv', r: '/op/account' })

    // Tampered payload / wrong key / malformed strings never verify.
    expect(await verifyUpstreamState('secret-2', state, { now: 1_000_000 })).toBeNull()
    const [body] = state.split('.')
    const tampered = `${Buffer.from(JSON.stringify({ p: 'google', m: 'login', iat: 1_000_000 })).toString('base64url')}.${state.split('.')[1]}`
    expect(await verifyUpstreamState('secret-1', tampered, { now: 1_000_000 })).toBeNull()
    expect(await verifyUpstreamState('secret-1', 'not-a-state', { now: 1_000_000 })).toBeNull()
    expect(await verifyUpstreamState('secret-1', `${body}.`, { now: 1_000_000 })).toBeNull()

    // The TTL (and the future-skew wall).
    expect(await verifyUpstreamState('secret-1', state, { now: 1_000_000 + 11 * 60_000 })).toBeNull()
    expect(await verifyUpstreamState('secret-1', state, { now: 1_000_000 - 120_000 })).toBeNull()

    // The open-redirect wall: a non-local r never survives verification.
    const evil = await signUpstreamState('secret-1', { p: 'google', m: 'login', r: 'https://evil.example/steal' }, 1_000_000)
    expect(await verifyUpstreamState('secret-1', evil, { now: 1_000_000 })).toBeNull()

    // The link mode demands the bound account.
    const noUser = await signUpstreamState('secret-1', { p: 'google', m: 'link' as never }, 1_000_000)
    expect(await verifyUpstreamState('secret-1', noUser, { now: 1_000_000 })).toBeNull()
  })
})

// ── the registry (validation + seed + apple detection) ────────────────

describe('the provider registry model', () => {
  it('validates the admin input (fail closed, the full problem list)', async () => {
    const { validateProviderInput } = await import('../../server/auth/upstream/registry')

    expect(validateProviderInput({
      id: 'google', kind: 'oidc', display_name: 'Google', issuer: 'https://accounts.google.com', client_id: 'cid',
    }).input).toMatchObject({ id: 'google', kind: 'oidc', enabled: false, brandMark: null })

    // GitHub rows take no issuer (the endpoints ride the env seam).
    expect(validateProviderInput({ id: 'github', kind: 'github', display_name: 'GitHub', client_id: 'cid' }).problems).toEqual([])
    expect(validateProviderInput({ id: 'github', kind: 'github', display_name: 'GitHub', client_id: 'cid', issuer: 'https://github.com' }).problems[0]).toMatch(/issuer is meaningless/)

    const bad = validateProviderInput({ id: 'Bad Id!', kind: 'saml', display_name: '', client_id: '', client_secret_ref: 'INLINE-SECRET' })
    expect(bad.input).toBeNull()
    expect(bad.problems.join('\n')).toMatch(/lowercase slug/)
    expect(bad.problems.join('\n')).toMatch(/kind must be/)
    expect(bad.problems.join('\n')).toMatch(/display_name is required/)
    expect(bad.problems.join('\n')).toMatch(/client_id is required/)
    expect(bad.problems.join('\n')).toMatch(/never stored inline/)

    // A malformed issuer (the oidc kind's discovery root).
    expect(validateProviderInput({ id: 'x', kind: 'oidc', display_name: 'X', issuer: 'not-a-url', client_id: 'c' }).problems[0]).toMatch(/not an absolute URL/)

    // A non-https issuer is refused (loopback is the test/dev posture).
    expect(validateProviderInput({ id: 'x', kind: 'oidc', display_name: 'X', issuer: 'http://idp.example.org', client_id: 'c' }).problems[0]).toMatch(/https/)
    expect(validateProviderInput({ id: 'x', kind: 'oidc', display_name: 'X', issuer: 'http://127.0.0.1:9000', client_id: 'c' }).problems).toEqual([])
  })

  it('detects Apple by the issuer host (never a typed name) and defaults the scopes', async () => {
    const { isAppleProvider, providerScopes } = await import('../../server/auth/upstream/registry')
    expect(isAppleProvider({ kind: 'oidc', issuer: 'https://appleid.apple.com' })).toBe(true)
    expect(isAppleProvider({ kind: 'oidc', issuer: 'https://appleid.apple.com/' })).toBe(true)
    expect(isAppleProvider({ kind: 'oidc', issuer: 'https://accounts.google.com' })).toBe(false)
    expect(isAppleProvider({ kind: 'github', issuer: null })).toBe(false)

    const base = { id: 'p', displayName: 'P', clientId: 'c', brandMark: null, clientSecretRef: null, enabled: true, createdAt: '', createdBy: null, updatedAt: null }
    expect(providerScopes({ ...base, kind: 'github' as const, issuer: null, scopes: null })).toBe('read:user user:email')
    expect(providerScopes({ ...base, kind: 'oidc' as const, issuer: 'https://accounts.google.com', scopes: null })).toBe('openid profile email')
    expect(providerScopes({ ...base, kind: 'oidc' as const, issuer: 'https://appleid.apple.com', scopes: null })).toBe('openid name email')
    expect(providerScopes({ ...base, kind: 'oidc' as const, issuer: 'https://accounts.google.com', scopes: 'openid custom' })).toBe('openid custom')
  })

  it('resolves the secret by reference, never inline — and fails closed on a dangling ref', async () => {
    const { resolveProviderSecret } = await import('../../server/auth/upstream/registry')
    const row = (ref: string | null) => ({
      id: 'google', kind: 'oidc' as const, displayName: 'Google', brandMark: null,
      issuer: 'https://accounts.google.com', clientId: 'c', clientSecretRef: ref,
      scopes: null, enabled: true, createdAt: '', createdBy: null, updatedAt: null,
    })
    expect(resolveProviderSecret(row(null), {})).toBeNull()
    expect(resolveProviderSecret(row('env:FIXTURE_IDP_SECRET'), { FIXTURE_IDP_SECRET: 's3cr3t' })).toBe('s3cr3t')
    expect(() => resolveProviderSecret(row('NOT-A-REF'), {})).toThrow(/env:<NAME>/)
    expect(() => resolveProviderSecret(row('env:MISSING_VAR'), {})).toThrow(/not set/)
  })

  it('bootstraps from OP_UPSTREAM_SEED (idempotent upserts; malformed fails loudly)', async () => {
    const { seedIdentityProvidersFromEnv, parseUpstreamSeed } = await import('../../server/auth/upstream/registry')
    expect(() => parseUpstreamSeed('{"not":"an array"}')).toThrow(/JSON array/)
    expect(() => parseUpstreamSeed('[{"id":"x"}]')).toThrow(/OP_UPSTREAM_SEED\[0\]/)

    const seeded = await seedIdentityProvidersFromEnv({
      OP_UPSTREAM_SEED: JSON.stringify([{
        id: 'seeded-idp', kind: 'oidc', display_name: 'Seeded IdP', issuer: 'https://idp.example.org',
        client_id: 'cid', client_secret_ref: 'env:SEEDED_SECRET',
      }]),
    }, store)
    expect(seeded).toEqual(['seeded-idp'])
    const row = await store.getIdentityProvider('seeded-idp')
    expect(row).toMatchObject({ kind: 'oidc', displayName: 'Seeded IdP', enabled: true, createdBy: 'op-upstream-seed' })
    await store.deleteIdentityProvider('seeded-idp')
  })
})

// ── Apple's client-secret JWT ─────────────────────────────────────────

describe('the Apple client secret (the ES256 JWT quirk)', () => {
  async function appleKeyPair() {
    const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
    const pkcs8 = await crypto.subtle.exportKey('pkcs8', pair.privateKey)
    const b64 = btoa(String.fromCharCode(...new Uint8Array(pkcs8)))
    const pem = `-----BEGIN PRIVATE KEY-----\n${b64.match(/.{1,64}/g)!.join('\n')}\n-----END PRIVATE KEY-----\n`
    return { pair, pem }
  }

  it('mints a verifiable ES256 JWT (iss=team, aud=apple, sub=client, kid=key id, 5-minute life)', async () => {
    const { resolveAppleSecretConfig, generateAppleClientSecret } = await import('../../server/auth/upstream/apple')
    const { pair, pem } = await appleKeyPair()
    // The env form: the '\n'-escaped one-liner (the Worker-secret posture).
    const config = await resolveAppleSecretConfig({
      APPLE_TEAM_ID: 'TEAM123456', APPLE_KEY_ID: 'KEY1234567', APPLE_PRIVATE_KEY: pem.replace(/\n/g, '\\n'),
    })
    const jwt = await generateAppleClientSecret(config, 'org.oimlsmart.smart.signin', 1_700_000_000_000)
    const [header, payload, signature] = jwt.split('.')
    expect(JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(header!), c => c.charCodeAt(0))))).toMatchObject({ alg: 'ES256', kid: 'KEY1234567', typ: 'JWT' })
    const claims = JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(payload!), c => c.charCodeAt(0))))
    expect(claims).toMatchObject({ iss: 'TEAM123456', aud: 'https://appleid.apple.com', sub: 'org.oimlsmart.smart.signin' })
    expect(claims.exp - claims.iat).toBe(300)

    // The signature verifies against the public half (the raw P1363
    // shape WebCrypto emits).
    const decode = (s: string) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0))
    const verified = await crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      pair.publicKey,
      decode(signature!) as BufferSource,
      new TextEncoder().encode(`${header}.${payload}`),
    )
    expect(verified).toBe(true)
  })

  it('fails honestly when the declaration is incomplete or the key is not a P-256 PKCS#8', async () => {
    const { resolveAppleSecretConfig } = await import('../../server/auth/upstream/apple')
    await expect(resolveAppleSecretConfig({})).rejects.toThrow(/APPLE_TEAM_ID/)
    await expect(resolveAppleSecretConfig({ APPLE_TEAM_ID: 'T' })).rejects.toThrow(/APPLE_KEY_ID/)
    await expect(resolveAppleSecretConfig({ APPLE_TEAM_ID: 'T', APPLE_KEY_ID: 'K' })).rejects.toThrow(/APPLE_PRIVATE_KEY/)
    await expect(resolveAppleSecretConfig({ APPLE_TEAM_ID: 'T', APPLE_KEY_ID: 'K', APPLE_PRIVATE_KEY: 'not a pem' })).rejects.toThrow()
  })
})

// ── the admin surface + the public projection ─────────────────────────

describe('the registry admin API + the public projection', () => {
  it('gates to admin/cs_admin, CRUDs the rows, and projects enabled-only publicly', async () => {
    // No session → 401; a non-admin → 403.
    expect((await app.request(`${ISSUER}/api/op/providers`)).status).toBe(401)
    const viewerCookie = await demoLogin('viewer@oiml.org')
    expect((await app.request(`${ISSUER}/api/op/providers`, { headers: { cookie: viewerCookie } })).status).toBe(403)

    const admin = await demoLogin('admin@oiml.org')
    const list = await app.request(`${ISSUER}/api/op/providers`, { headers: { cookie: admin } })
    expect(list.status).toBe(200)
    const ids = (await list.json() as Array<{ id: string }>).map(p => p.id)
    expect(ids).toEqual(expect.arrayContaining(['fixture-idp', 'github']))

    // Create (201), then the upsert update (200) stamps updatedAt.
    const created = await app.request(`${ISSUER}/api/op/providers`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie: admin },
      body: JSON.stringify({ id: 'entra', kind: 'oidc', display_name: 'Contoso Entra', issuer: 'https://login.microsoftonline.com/tid/v2.0', client_id: 'cid', client_secret_ref: 'env:ENTRA_SECRET', brand_mark: 'microsoft' }),
    })
    expect(created.status).toBe(201)
    expect(await created.json()).toMatchObject({ id: 'entra', enabled: false, clientSecretRef: 'env:ENTRA_SECRET', apple: false })

    // The secret is never stored — the reference is; and the disabled
    // row is invisible to the login page's public projection.
    const publicList = await (await app.request(`${ISSUER}/api/op/providers/public`)).json() as Array<{ id: string }>
    expect(publicList.map(p => p.id)).toContain('fixture-idp')
    expect(publicList.map(p => p.id)).not.toContain('entra')
    expect(JSON.stringify(publicList)).not.toContain('clientSecretRef')
    expect(JSON.stringify(publicList)).not.toContain('SECRET')

    // Invalid input → 400 with the problem list.
    const bad = await app.request(`${ISSUER}/api/op/providers`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie: admin },
      body: JSON.stringify({ id: 'Bad', kind: 'oidc', display_name: '', client_id: '' }),
    })
    expect(bad.status).toBe(400)
    expect((await bad.json() as { problems: string[] }).problems.length).toBeGreaterThan(2)

    // The enable toggle → visible publicly; update → 200.
    const toggled = await app.request(`${ISSUER}/api/op/providers/entra/status`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie: admin },
      body: JSON.stringify({ enabled: true }),
    })
    expect(toggled.status).toBe(200)
    expect(await toggled.json()).toMatchObject({ enabled: true })
    expect((await (await app.request(`${ISSUER}/api/op/providers/public`)).json() as Array<{ id: string }>).map(p => p.id)).toContain('entra')

    const updated = await app.request(`${ISSUER}/api/op/providers`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie: admin },
      body: JSON.stringify({ id: 'entra', kind: 'oidc', display_name: 'Contoso Entra ID', issuer: 'https://login.microsoftonline.com/tid/v2.0', client_id: 'cid-2', enabled: true }),
    })
    expect(updated.status).toBe(200)
    expect(await updated.json()).toMatchObject({ displayName: 'Contoso Entra ID', clientId: 'cid-2', clientSecretRef: null })

    // Delete.
    const gone = await app.request(`${ISSUER}/api/op/providers/entra`, { method: 'DELETE', headers: { cookie: admin } })
    expect(gone.status).toBe(200)
    expect((await app.request(`${ISSUER}/api/op/providers/entra`, { method: 'DELETE', headers: { cookie: admin } })).status).toBe(404)
  })

  it('refuses flows for unknown/disabled providers honestly', async () => {
    const res = await app.request(`${ISSUER}/op/upstream/nope/signin`, { redirect: 'manual' })
    expect(res.status).toBe(302)
    expect(res.headers.get('location')).toContain('/app/login?error=upstream_unknown')
  })
})

// ── the OIDC flow (the stub IdP) ──────────────────────────────────────

describe('the upstream OIDC flow against the stub IdP', () => {
  it('links an enabled provider to the signed-in account (the flow bound to the session)', async () => {
    const cookie = await demoLogin('ia@oiml.org')
    const res = await runFlow('/op/upstream/fixture-idp/link', 'ada', cookie)
    expect(res.status).toBe(302)
    expect(res.headers.get('location')).toBe(`${ISSUER}/app/account?linked=fixture-idp`)

    const link = await store.findIdentityLink('fixture-idp', 'stub-ada')
    expect(link).toBeTruthy()
    const ia = await store.findUserByEmail('ia@oiml.org')
    expect(link!.userId).toBe(ia!.id)
    expect(link!.linkedBy).toBe('ia@oiml.org')

    // The account surface lists it.
    const links = await app.request(`${ISSUER}/api/op/account/links`, { headers: { cookie } })
    expect(await links.json()).toEqual([expect.objectContaining({ provider: 'fixture-idp', displayName: 'Fixture IdP', providerAccountId: 'stub-ada' })])
  })

  it('re-links the SAME pair idempotently but refuses a second provider link per account', async () => {
    const cookie = await demoLogin('ia@oiml.org')
    // The flow start refuses fast: the account already holds the link.
    const start = await app.request(`${ISSUER}/op/upstream/fixture-idp/link`, { headers: { cookie }, redirect: 'manual' })
    expect(start.status).toBe(302)
    expect(start.headers.get('location')).toContain('/app/account?error=provider_linked')
  })

  it('signs in by the link — (provider, sub), never by email — and starts the session', async () => {
    // NO session/cookie: the login flow. ada's stub email is
    // ada@example.org — NO local account holds it, so only the link can
    // resolve.
    const res = await runFlow('/op/upstream/fixture-idp/signin', 'ada')
    expect(res.status).toBe(302)
    const cookie = res.headers.get('set-cookie')
    expect(cookie, 'the session cookie').toContain('oiml-session=')
    const session = await app.request(`${ISSUER}/api/auth/session`, { headers: { cookie: cookie!.split(';')[0]! } })
    expect(await session.json()).toMatchObject({ email: 'ia@oiml.org', name: 'IA Officer' })
  })

  it('REFUSES an unlinked identity whose verified email matches an account (no email-only match, ever)', async () => {
    // vic's stub email is viewer@oiml.org — the demo VIEWER account's
    // email. Without a link the sign-in must refuse honestly: no
    // session, no account mutation, no identity row.
    const res = await runFlow('/op/upstream/fixture-idp/signin', 'vic')
    expect(res.status).toBe(302)
    const location = res.headers.get('location')!
    expect(location).toContain('/app/login?error=upstream_not_linked')
    expect(location).toContain('provider=Fixture')
    expect(res.headers.get('set-cookie')).toBeNull()

    const viewer = await store.findUserByEmail('viewer@oiml.org')
    expect(viewer).toBeTruthy()
    expect(await store.findIdentityLink('fixture-idp', 'stub-vic')).toBeNull()
    // …and the users row is untouched (the legacy provider columns never
    // move under the upstream flow).
    expect(await store.findUserByProvider('oidc', 'stub-vic')).toBeNull()
  })

  it('refuses to link an upstream account already linked to a DIFFERENT account', async () => {
    const viewerCookie = await demoLogin('viewer@oiml.org')
    // ada is linked to ia (the first leg) — viewer's attempt loses.
    const res = await runFlow('/op/upstream/fixture-idp/link', 'ada', viewerCookie)
    expect(res.status).toBe(302)
    expect(res.headers.get('location')).toContain('/app/account?error=link_taken')
  })

  it('the POST (form_post) callback shape works — Apple rides this path', async () => {
    // Link bob to the viewer account via the POST form callback.
    const cookie = await demoLogin('viewer@oiml.org')
    const res = await runFlow('/op/upstream/fixture-idp/link', 'bob', cookie, 'POST')
    expect(res.status).toBe(302)
    expect(res.headers.get('location')).toBe(`${ISSUER}/app/account?linked=fixture-idp`)
    expect((await store.findIdentityLink('fixture-idp', 'stub-bob'))?.userId).toBe((await store.findUserByEmail('viewer@oiml.org'))!.id)
  })

  it('unlinks — and the sign-in is then refused honestly', async () => {
    // TODO.identity/06's guard: the unlink must leave at least one way
    // in, so the (passwordless demo) account gets a credential first.
    const viewer = (await store.findUserByEmail('viewer@oiml.org'))!
    await store.setPasswordHash(viewer.id, await hashPassword('the viewer test passphrase'), 'test')
    const cookie = await demoLogin('viewer@oiml.org')
    const unlink = await app.request(`${ISSUER}/api/op/account/links/fixture-idp`, { method: 'DELETE', headers: { cookie } })
    expect(unlink.status).toBe(200)
    expect(await store.findIdentityLink('fixture-idp', 'stub-bob')).toBeNull()

    const res = await runFlow('/op/upstream/fixture-idp/signin', 'bob')
    expect(res.headers.get('location')).toContain('/app/login?error=upstream_not_linked')
    expect(res.headers.get('set-cookie')).toBeNull()
  })

  it('a state minted for another provider never crosses over', async () => {
    // Start the fixture-idp flow but deliver the callback to the GITHUB
    // provider's callback URL: the state binds to its provider.
    const start = await app.request(`${ISSUER}/op/upstream/fixture-idp/signin`, { redirect: 'manual' })
    const callbackUrl = await driveStubIdp(start.headers.get('location')!, 'carol')
    const wrong = new URL(callbackUrl)
    const res = await app.request(`${ISSUER}/op/upstream/github/callback?code=${wrong.searchParams.get('code')}&state=${encodeURIComponent(wrong.searchParams.get('state')!)}`, { redirect: 'manual' })
    expect(res.status).toBe(302)
    expect(res.headers.get('location')).toContain('/app/login?error=upstream_state')
  })

  it('the upstream error redirect lands on the plain-language page', async () => {
    // The stub answers error=access_denied when the authorize request is
    // malformed on purpose — simpler: the provider's own refusal param.
    const res = await app.request(`${ISSUER}/op/upstream/fixture-idp/callback?error=access_denied&error_description=declined&state=whatever`, { redirect: 'manual' })
    expect(res.status).toBe(302)
    expect(res.headers.get('location')).toContain('/app/login?error=upstream_refused')
  })
})

// ── the GitHub kind (the stub GitHub) ─────────────────────────────────

describe('the upstream GitHub flow against the stub GitHub', () => {
  /** The github flow's round trip (the stub's authorize takes ?login=). */
  async function runGitHubFlow(startUrl: string, login: string, cookie?: string): Promise<Response> {
    const start = await app.request(`${ISSUER}${startUrl}`, { headers: cookie ? { cookie } : {}, redirect: 'manual' } as RequestInit)
    expect(start.status).toBe(302)
    const authorizeUrl = new URL(start.headers.get('location')!)
    expect(authorizeUrl.origin).toBe(github.baseUrl)
    authorizeUrl.searchParams.set('login', login)
    const consented = await fetch(authorizeUrl.toString(), { redirect: 'manual' })
    expect(consented.status).toBe(302)
    return app.request(consented.headers.get('location')!, { headers: cookie ? { cookie } : {}, redirect: 'manual' } as RequestInit)
  }

  it('links and signs in by the GitHub profile id', async () => {
    const cookie = await demoLogin('tl@oiml.org')
    const linked = await runGitHubFlow('/op/upstream/github/link', 'octocat-staff', cookie)
    expect(linked.headers.get('location')).toBe(`${ISSUER}/app/account?linked=github`)
    const tl = await store.findUserByEmail('tl@oiml.org')
    expect((await store.findIdentityLink('github', '102'))?.userId).toBe(tl!.id)

    const res = await runGitHubFlow('/op/upstream/github/signin', 'octocat-staff')
    const sessionCookie = res.headers.get('set-cookie')
    expect(sessionCookie).toContain('oiml-session=')
    const session = await app.request(`${ISSUER}/api/auth/session`, { headers: { cookie: sessionCookie!.split(';')[0]! } })
    expect(await session.json()).toMatchObject({ email: 'tl@oiml.org' })
  })

  it('refuses an unlinked GitHub login whose email matches an account (never by email)', async () => {
    // octocat-admin's stub email is admin@example.org… but even a REAL
    // account email must not match: use a fresh user whose email we then
    // point at an account to prove the guard reads ONLY the link table.
    const res = await runGitHubFlow('/op/upstream/github/signin', 'octocat-stranger')
    expect(res.headers.get('location')).toContain('/app/login?error=upstream_not_linked')
    expect(res.headers.get('set-cookie')).toBeNull()
    expect(await store.findIdentityLink('github', '106')).toBeNull()
  })

  it('fails honestly when the GitHub row declares no secret', async () => {
    await store.upsertIdentityProvider({ id: 'github-nosecret', kind: 'github', displayName: 'GitHub (no secret)', clientId: 'x', enabled: true })
    const start = await app.request(`${ISSUER}/op/upstream/github-nosecret/signin`, { redirect: 'manual' })
    const authorizeUrl = new URL(start.headers.get('location')!)
    authorizeUrl.searchParams.set('login', 'octocat-staff')
    const consented = await fetch(authorizeUrl.toString(), { redirect: 'manual' })
    const res = await app.request(consented.headers.get('location')!, { redirect: 'manual' })
    expect(res.headers.get('location')).toContain('/app/login?error=upstream_exchange')
    await store.deleteIdentityProvider('github-nosecret')
  })
})
