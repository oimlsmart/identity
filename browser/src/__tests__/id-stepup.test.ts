// ─────────────────────────────────────────────────────────────────────
// TODO.modern/06 — the step-up core, in-process: the OIDC max_age
// freshness enforcement on authorize, the achieved acr (derived from
// the session's amr) in the ID token, and the discovery
// advertisement. The REAL op router over a REAL temp SQLite store.
// ─────────────────────────────────────────────────────────────────────

import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

const TMP = mkdtempSync(join(tmpdir(), 'oiml-stepup-'))
process.env.DATABASE_PATH = join(TMP, 'test.db')
const ISSUER = 'http://op.test'
process.env.OP_ISSUER = ISSUER

const CONFIDENTIAL = {
  client_id: 'hub-instance',
  name: 'OIML SMART platform hub',
  secret: 'hub-secret-123',
  redirect_uris: ['https://hub.example/api/auth/callback/oidc'],
}
process.env.OP_CLIENT_SEED = JSON.stringify([CONFIDENTIAL])

let app: import('hono').Hono
let generatePkce: typeof import('../../server/oidc').generatePkce
let resetProfile: () => void

async function demoLogin(email: string): Promise<string> {
  const res = await app.request('/api/auth/demo', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password: 'demo2026' }),
  })
  expect(res.ok, `demo login ${email}`).toBe(true)
  return res.headers.get('set-cookie')!.split(';')[0]!
}

interface IdTokenClaims {
  acr?: string
  amr?: string[]
  auth_time?: number
  sub?: string
}

/** authorize → consent → allow → exchange; the decoded ID token. */
async function driveToIdToken(cookie: string): Promise<IdTokenClaims> {
  const pkce = await generatePkce()
  const query = new URLSearchParams({
    response_type: 'code',
    client_id: CONFIDENTIAL.client_id,
    redirect_uri: CONFIDENTIAL.redirect_uris[0]!,
    scope: 'openid profile',
    state: 'st-1',
    nonce: 'nn-1',
    code_challenge: pkce.challenge,
    code_challenge_method: 'S256',
  })
  const authorize = await app.request(`${ISSUER}/op/authorize?${query}`, { headers: { cookie } })
  expect(authorize.status).toBe(302)
  const consentUrl = new URL(authorize.headers.get('location')!, ISSUER)
  expect(consentUrl.pathname).toBe('/op/consent')
  const authId = consentUrl.searchParams.get('auth')!
  const decide = await app.request(`${ISSUER}/api/op/consent/${authId}/decide`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', cookie },
    body: JSON.stringify({ decision: 'allow' }),
  })
  const { redirect } = await decide.json() as { redirect: string }
  const code = new URL(redirect).searchParams.get('code')!
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    redirect_uri: CONFIDENTIAL.redirect_uris[0]!,
    client_id: CONFIDENTIAL.client_id,
    code_verifier: pkce.verifier,
  })
  const token = await app.request(`${ISSUER}/op/token`, {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      authorization: `Basic ${btoa(`${CONFIDENTIAL.client_id}:${CONFIDENTIAL.secret}`)}`,
    },
    body,
  })
  expect(token.status, 'the exchange answers').toBe(200)
  const payload = await token.json() as { id_token: string }
  const [, claimsB64] = payload.id_token.split('.')
  return JSON.parse(atob(claimsB64!.replace(/-/g, '+').replace(/_/g, '/'))) as IdTokenClaims
}

beforeAll(async () => {
  const { generateSuccessorPair } = await import('../../scripts/op-key-rotate')
  process.env.OP_SIGNING_KEY = (await generateSuccessorPair()).privateJwkJson

  const { installSqliteStore } = await import('../../server/store/sqlite')
  installSqliteStore()
  const profileMod = await import('../../server/profile')
  resetProfile = profileMod.resetInstanceProfileForTest
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
  generatePkce = oidc.generatePkce

  const { Hono } = await import('hono')
  const { createAuthLeanRouter } = await import('../../server/routes/auth-lean')
  const { createOpRouter } = await import('../../server/routes/op')
  const root = new Hono()
  root.route('/api/auth', createAuthLeanRouter({ autoSeedDemo: true }))
  root.route('/', createOpRouter())
  app = root

  const probe = await app.request(`${ISSUER}/.well-known/openid-configuration`)
  expect(probe.status).toBe(200)
})

afterAll(() => {
  resetProfile()
  rmSync(TMP, { recursive: true, force: true })
  delete process.env.OP_ISSUER
  delete process.env.OP_SIGNING_KEY
  delete process.env.OP_CLIENT_SEED
  delete process.env.DATABASE_PATH
})

describe('the step-up module (the pure seam)', () => {
  it('the acr ladder maps the amr honestly', async () => {
    const { acrOf, ACR_LEVELS } = await import('../../server/auth/op/step-up')
    expect(acrOf(null)).toBe('urn:oimlsmart:acr:single-factor')
    expect(acrOf([])).toBe('urn:oimlsmart:acr:single-factor')
    expect(acrOf(['pwd'])).toBe('urn:oimlsmart:acr:single-factor')
    expect(acrOf(['webauthn'])).toBe('urn:oimlsmart:acr:single-factor')
    expect(acrOf(['pwd', 'webauthn'])).toBe('urn:oimlsmart:acr:multi-factor')
    expect(acrOf(['webauthn', 'hwk'])).toBe('urn:oimlsmart:acr:multi-factor')
    expect(ACR_LEVELS).toContain('urn:oimlsmart:acr:multi-factor')
  })

  it('max_age staleness: fresh passes, stale and unprovable refuse', async () => {
    const { sessionMeetsMaxAge } = await import('../../server/auth/op/step-up')
    const now = new Date().toISOString()
    expect(sessionMeetsMaxAge(now, null)).toBe(true)
    expect(sessionMeetsMaxAge(now, 600)).toBe(true)
    expect(sessionMeetsMaxAge(new Date(Date.now() - 1200_000).toISOString(), 600)).toBe(false)
    // max_age=0: the RP wants a fresh authentication every time.
    expect(sessionMeetsMaxAge(now, 0)).toBe(false)
    // No recorded instant = no provable freshness = refuse (honestly).
    expect(sessionMeetsMaxAge(null, 600)).toBe(false)
    expect(sessionMeetsMaxAge(null, null)).toBe(true)
  })
})

describe('the authorize freshness gate (max_age)', () => {
  it('a fresh session passes its max_age and reaches consent', async () => {
    const cookie = await demoLogin('ia@oimlsmart.org')
    const pkce = await generatePkce()
    const query = new URLSearchParams({
      response_type: 'code',
      client_id: CONFIDENTIAL.client_id,
      redirect_uri: CONFIDENTIAL.redirect_uris[0]!,
      scope: 'openid',
      code_challenge: pkce.challenge,
      code_challenge_method: 'S256',
      max_age: '600',
    })
    const res = await app.request(`${ISSUER}/op/authorize?${query}`, { headers: { cookie } })
    expect(res.status).toBe(302)
    expect(new URL(res.headers.get('location')!, ISSUER).pathname).toBe('/op/consent')
  })

  it('max_age=0 demands a fresh authentication even with a live session', async () => {
    const cookie = await demoLogin('tl@oimlsmart.org')
    const pkce = await generatePkce()
    const query = new URLSearchParams({
      response_type: 'code',
      client_id: CONFIDENTIAL.client_id,
      redirect_uri: CONFIDENTIAL.redirect_uris[0]!,
      scope: 'openid',
      code_challenge: pkce.challenge,
      code_challenge_method: 'S256',
      max_age: '0',
    })
    const res = await app.request(`${ISSUER}/op/authorize?${query}`, { headers: { cookie } })
    expect(res.status).toBe(302)
    const back = new URL(res.headers.get('location')!, ISSUER)
    // The sign-in surface, carrying THIS request as the destination —
    // the re-entry (fresh session) satisfies the gate.
    expect(back.pathname).toBe('/')
    expect(back.searchParams.get('redirect')).toContain('/op/authorize')
  })

  it('a malformed max_age refuses the redirect-shaped way', async () => {
    const cookie = await demoLogin('ia@oimlsmart.org')
    const pkce = await generatePkce()
    const query = new URLSearchParams({
      response_type: 'code',
      client_id: CONFIDENTIAL.client_id,
      redirect_uri: CONFIDENTIAL.redirect_uris[0]!,
      scope: 'openid',
      code_challenge: pkce.challenge,
      code_challenge_method: 'S256',
      max_age: 'soon',
    })
    const res = await app.request(`${ISSUER}/op/authorize?${query}`, { headers: { cookie } })
    expect(res.status).toBe(302)
    const back = new URL(res.headers.get('location')!, ISSUER)
    expect(back.searchParams.get('error')).toBe('invalid_request')
  })
})

describe('the achieved acr rides the ID token', () => {
  it('a password session answers the single-factor acr with its auth_time', async () => {
    const cookie = await demoLogin('ia@oimlsmart.org')
    const claims = await driveToIdToken(cookie)
    expect(claims.acr).toBe('urn:oimlsmart:acr:single-factor')
    expect(claims.amr).toEqual(['pwd'])
    expect(typeof claims.auth_time).toBe('number')
  })
})

describe('the discovery advertisement', () => {
  it('names the acr ladder', async () => {
    const res = await app.request(`${ISSUER}/.well-known/openid-configuration`)
    const meta = await res.json() as Record<string, unknown>
    expect(meta.acr_values_supported).toEqual([
      'urn:oimlsmart:acr:multi-factor',
      'urn:oimlsmart:acr:single-factor',
    ])
  })
})
