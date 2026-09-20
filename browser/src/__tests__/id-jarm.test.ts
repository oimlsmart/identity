// ─────────────────────────────────────────────────────────────────────
// TODO.modern/12 — JARM (RFC 9150), in-process: response_mode=jwt
// wraps EVERY redirect back to the RP — the error refusals AND the
// code mint — into redirect_uri?response=<JWT> (ES256 via the OP's
// own key, iss + aud + the response parameters verbatim). The default
// (absent response_mode) stays the plain query — byte-identical for
// every existing RP.
// ─────────────────────────────────────────────────────────────────────

import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

const TMP = mkdtempSync(join(tmpdir(), 'oiml-jarm-'))
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

const basic = `Basic ${btoa(`${CONFIDENTIAL.client_id}:${CONFIDENTIAL.secret}`)}`
const REDIRECT = CONFIDENTIAL.redirect_uris[0]!

interface JwtClaims {
  code?: string
  state?: string
  error?: string
  iss?: string
  aud?: string
}

function decodeJwt(param: string): JwtClaims {
  const [, payload] = param.split('.')
  expect(payload, 'the response parameter is a JWT').toBeTruthy()
  return JSON.parse(atob(payload!.replace(/-/g, '+').replace(/_/g, '/'))) as JwtClaims
}

beforeAll(async () => {
  const { generateSuccessorPair } = await import('../../scripts/op-key-rotate')
  process.env.OP_SIGNING_KEY = (await generateSuccessorPair()).privateJwkJson

  const { installSqliteStore } = await import('../../server/store/sqlite')
  installSqliteStore()
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
  generatePkce = oidc.generatePkce
  oidc.clearOidcCaches()

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
  rmSync(TMP, { recursive: true, force: true })
  delete process.env.OP_ISSUER
  delete process.env.OP_SIGNING_KEY
  delete process.env.OP_CLIENT_SEED
  delete process.env.DATABASE_PATH
})

async function login(email = 'ia@oiml.org'): Promise<string> {
  const res = await app.request('/api/auth/demo', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password: 'demo2026' }),
  })
  expect(res.ok).toBe(true)
  return res.headers.get('set-cookie')!.split(';')[0]!
}

describe('the discovery advertisement', () => {
  it('names the response modes', async () => {
    const meta = await (await app.request(`${ISSUER}/.well-known/openid-configuration`)).json() as Record<string, unknown>
    expect(meta.response_modes_supported).toEqual(['query', 'jwt'])
  })
})

describe('the signed response (response_mode=jwt)', () => {
  it('the FULL round trip: the response JWT carries code/state/iss/aud; the decoded code exchanges', async () => {
    const cookie = await login()
    const pkce = await generatePkce()
    const query = new URLSearchParams({
      response_type: 'code', client_id: CONFIDENTIAL.client_id, redirect_uri: REDIRECT,
      scope: 'openid profile', state: 'st-jarm', nonce: 'nn-jarm',
      code_challenge: pkce.challenge, code_challenge_method: 'S256',
      response_mode: 'jwt', prompt: 'consent',
    })
    const authorize = await app.request(`${ISSUER}/op/authorize?${query}`, { headers: { cookie } })
    expect(authorize.status).toBe(302)
    const authId = new URL(authorize.headers.get('location')!, ISSUER).searchParams.get('auth')!
    const decide = await app.request(`${ISSUER}/api/op/consent/${authId}/decide`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ decision: 'allow' }),
    })
    const { redirect } = await decide.json() as { redirect: string }
    const back = new URL(redirect)
    expect(back.origin + back.pathname).toBe(REDIRECT)
    expect(back.searchParams.get('code'), 'no plain code in the query').toBeNull()
    const claims = decodeJwt(back.searchParams.get('response')!)
    expect(claims.state).toBe('st-jarm')
    expect(claims.iss).toBe(ISSUER)
    expect(claims.aud).toBe(CONFIDENTIAL.client_id)
    expect(claims.code).toBeTruthy()

    // The DECODED code exchanges normally.
    const token = await app.request(`${ISSUER}/op/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', authorization: basic },
      body: new URLSearchParams({
        grant_type: 'authorization_code', code: claims.code!, redirect_uri: REDIRECT,
        client_id: CONFIDENTIAL.client_id, code_verifier: pkce.verifier,
      }),
    })
    expect(token.status).toBe(200)
  })

  it('the ERROR refusal is signed too (invalid_scope with the mode)', async () => {
    const cookie = await login()
    const query = new URLSearchParams({
      response_type: 'code', client_id: CONFIDENTIAL.client_id, redirect_uri: REDIRECT,
      scope: 'profile', code_challenge: 'a'.repeat(43), code_challenge_method: 'S256',
      response_mode: 'jwt',
    })
    const res = await app.request(`${ISSUER}/op/authorize?${query}`, { headers: { cookie } })
    expect(res.status).toBe(302)
    const back = new URL(res.headers.get('location')!, ISSUER)
    expect(back.origin + back.pathname).toBe(REDIRECT)
    const claims = decodeJwt(back.searchParams.get('response')!)
    expect(claims.error).toBe('invalid_scope')
  })

  it('form_post refuses the redirect-shaped way (the mode is unsupported)', async () => {
    const cookie = await login()
    const query = new URLSearchParams({
      response_type: 'code', client_id: CONFIDENTIAL.client_id, redirect_uri: REDIRECT,
      scope: 'openid', code_challenge: 'b'.repeat(43), code_challenge_method: 'S256',
      response_mode: 'form_post',
    })
    const res = await app.request(`${ISSUER}/op/authorize?${query}`, { headers: { cookie } })
    expect(res.status).toBe(302)
    const back = new URL(res.headers.get('location')!, ISSUER)
    expect(back.searchParams.get('error')).toBe('invalid_request')
  })

  it('the PUSHED response_mode rides the PAR path (the regression the e2e leg caught: the mode was silently dropped)', async () => {
    const cookie = await login()
    const push = await app.request(`${ISSUER}/op/par`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', authorization: basic },
      body: new URLSearchParams({
        response_type: 'code', client_id: CONFIDENTIAL.client_id, redirect_uri: REDIRECT,
        scope: 'openid', code_challenge: 'd'.repeat(43), code_challenge_method: 'S256',
        response_mode: 'jwt', prompt: 'consent', state: 'st-pushed-mode',
      }),
    })
    expect(push.status).toBe(201)
    const pushed = await push.json() as { request_uri: string }
    const authorize = await app.request(`${ISSUER}/op/authorize?request_uri=${encodeURIComponent(pushed.request_uri)}`, { headers: { cookie } })
    expect(authorize.status).toBe(302)
    const authId = new URL(authorize.headers.get('location')!, ISSUER).searchParams.get('auth')!
    const decide = await app.request(`${ISSUER}/api/op/consent/${authId}/decide`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ decision: 'allow' }),
    })
    const { redirect } = await decide.json() as { redirect: string }
    const back = new URL(redirect)
    expect(back.searchParams.get('code'), 'the PUSHED mode wraps — no plain code').toBeNull()
    const claims = decodeJwt(back.searchParams.get('response')!)
    expect(claims.state).toBe('st-pushed-mode')
  })

  it('the default stays the plain query (byte-identical for existing RPs)', async () => {
    const cookie = await login()
    const query = new URLSearchParams({
      response_type: 'code', client_id: CONFIDENTIAL.client_id, redirect_uri: REDIRECT,
      scope: 'openid', code_challenge: 'c'.repeat(43), code_challenge_method: 'S256',
      state: 'plain-st',
    })
    const res = await app.request(`${ISSUER}/op/authorize?${query}`, { headers: { cookie } })
    expect(res.status).toBe(302)
    const back = new URL(res.headers.get('location')!, ISSUER)
    expect(back.searchParams.get('response')).toBeNull()
    expect(back.searchParams.get('state')).toBe('plain-st')
  })
})
