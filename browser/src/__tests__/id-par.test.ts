// ─────────────────────────────────────────────────────────────────────
// TODO.modern/11 — PAR (RFC 9126), in-process: the push (client-
// authenticated, the redirect wall at PAR time), the authorize leg
// (the pushed params REPLACE the query — single-use, client-bound),
// and the FULL round trip through a pushed request. The REAL op
// router + the REAL store; the stub-RP exchange consumes the code.
// ─────────────────────────────────────────────────────────────────────

import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

const TMP = mkdtempSync(join(tmpdir(), 'oiml-par-'))
process.env.DATABASE_PATH = join(TMP, 'test.db')
const ISSUER = 'http://op.test'
process.env.OP_ISSUER = ISSUER

const CONFIDENTIAL = {
  client_id: 'hub-instance',
  name: 'OIML SMART platform hub',
  secret: 'hub-secret-123',
  redirect_uris: ['https://hub.example/api/auth/callback/oidc'],
}
const OTHER = {
  client_id: 'other-rp',
  name: 'Another RP',
  secret: 'other-secret-456',
  redirect_uris: ['https://other.example/cb'],
}
process.env.OP_CLIENT_SEED = JSON.stringify([CONFIDENTIAL, OTHER])

let app: import('hono').Hono
let generatePkce: typeof import('../../server/oidc').generatePkce

const basic = (id: string, secret: string) =>
  `Basic ${btoa(`${encodeURIComponent(id)}:${encodeURIComponent(secret)}`)}`

interface PushAnswer { request_uri: string; expires_in: number }

async function push(params: Record<string, string>, auth: string = basic(CONFIDENTIAL.client_id, CONFIDENTIAL.secret)): Promise<Response> {
  return app.request(`${ISSUER}/op/par`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', authorization: auth },
    body: new URLSearchParams(params).toString(),
  })
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

describe('the push (POST /op/par)', () => {
  it('answers 201 with the request_uri + the expiry', async () => {
    const res = await push({
      response_type: 'code',
      redirect_uri: CONFIDENTIAL.redirect_uris[0]!,
      scope: 'openid profile',
      state: 'st-par-1',
      code_challenge: 'a'.repeat(43),
      code_challenge_method: 'S256',
    })
    expect(res.status).toBe(201)
    const body = await res.json() as PushAnswer
    expect(body.request_uri).toMatch(/^urn:ietf:params:oauth:request_uri:/)
    expect(body.expires_in).toBe(90)
  })

  it('the wrong secret refuses 401 invalid_client; the unregistered redirect wall fires at PAR time', async () => {
    const badSecret = await push({ response_type: 'code', redirect_uri: CONFIDENTIAL.redirect_uris[0]!, scope: 'openid' }, basic(CONFIDENTIAL.client_id, 'nope'))
    expect(badSecret.status).toBe(401)
    expect(((await badSecret.json()) as { error: string }).error).toBe('invalid_client')

    const evilRedirect = await push({ response_type: 'code', redirect_uri: 'https://evil.example/cb', scope: 'openid' })
    expect(evilRedirect.status).toBe(400)
  })
})

describe('the authorize leg through a pushed request', () => {
  async function loginAndConsent(cookie: string, authorizeUrl: string): Promise<string> {
    const authorize = await app.request(authorizeUrl, { headers: { cookie } })
    expect(authorize.status, 'authorize proceeds to consent').toBe(302)
    const consentUrl = new URL(authorize.headers.get('location')!, ISSUER)
    expect(consentUrl.pathname).toBe('/op/consent')
    const decide = await app.request(`${ISSUER}/api/op/consent/${consentUrl.searchParams.get('auth')!}/decide`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ decision: 'allow' }),
    })
    const { redirect } = await decide.json() as { redirect: string }
    return redirect
  }

  it('the pushed params drive the FULL round trip; the query is IGNORED', async () => {
    const login = await app.request('/api/auth/demo', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: 'ia@oimlsmart.org', password: 'demo2026' }),
    })
    const cookie = login.headers.get('set-cookie')!.split(';')[0]!
    const pkce = await generatePkce()

    const pushed = await (await push({
      response_type: 'code', redirect_uri: CONFIDENTIAL.redirect_uris[0]!,
      scope: 'openid profile', state: 'st-par-rt', nonce: 'nn-par-rt',
      code_challenge: pkce.challenge, code_challenge_method: 'S256',
    })).json() as PushAnswer

    // The query carries GARBAGE alongside the request_uri — ignored.
    const redirect = await loginAndConsent(cookie,
      `${ISSUER}/op/authorize?request_uri=${encodeURIComponent(pushed.request_uri)}&scope=openid&response_type=code&state=hijack`)
    const back = new URL(redirect)
    expect(back.searchParams.get('code')).toBeTruthy()
    expect(back.searchParams.get('state')).toBe('st-par-rt')

    // The exchange consumes the pushed request's code normally.
    const token = await app.request(`${ISSUER}/op/token`, {
      method: 'POST',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        authorization: basic(CONFIDENTIAL.client_id, CONFIDENTIAL.secret),
      },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code: back.searchParams.get('code')!,
        redirect_uri: CONFIDENTIAL.redirect_uris[0]!,
        client_id: CONFIDENTIAL.client_id,
        code_verifier: pkce.verifier,
      }),
    })
    expect(token.status).toBe(200)
    const payload = await token.json() as { id_token: string }
    expect(payload.id_token).toBeTruthy()
  })

  it('single-use: the second authorize on the same request_uri refuses', async () => {
    const login = await app.request('/api/auth/demo', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: 'tl@oimlsmart.org', password: 'demo2026' }),
    })
    const cookie = login.headers.get('set-cookie')!.split(';')[0]!
    const pushed = await (await push({
      response_type: 'code', redirect_uri: CONFIDENTIAL.redirect_uris[0]!,
      scope: 'openid', code_challenge: 'b'.repeat(43), code_challenge_method: 'S256',
    })).json() as PushAnswer

    await loginAndConsent(cookie, `${ISSUER}/op/authorize?request_uri=${encodeURIComponent(pushed.request_uri)}`)
    // The consumed request has NO validated redirect left to error to —
    // the in-place refusal page is the only safe answer (the wall).
    const second = await app.request(`${ISSUER}/op/authorize?request_uri=${encodeURIComponent(pushed.request_uri)}`, { headers: { cookie } })
    expect(second.status).toBe(400)
  })

  it('a cross-client request_uri refuses (the binding)', async () => {
    const pushed = await (await push({
      response_type: 'code', redirect_uri: CONFIDENTIAL.redirect_uris[0]!,
      scope: 'openid', code_challenge: 'c'.repeat(43), code_challenge_method: 'S256',
    })).json() as PushAnswer
    const res = await app.request(`${ISSUER}/op/authorize?request_uri=${encodeURIComponent(pushed.request_uri)}&client_id=${OTHER.client_id}`)
    expect(res.status).toBe(400)
  })

  it('an unknown request_uri refuses in place (no safe redirect exists)', async () => {
    const res = await app.request(`${ISSUER}/op/authorize?request_uri=${encodeURIComponent('urn:ietf:params:oauth:request_uri:missing')}`)
    expect(res.status).toBe(400)
  })
})

describe('the discovery advertisement', () => {
  it('names the PAR endpoint', async () => {
    const res = await app.request(`${ISSUER}/.well-known/openid-configuration`)
    const meta = await res.json() as Record<string, unknown>
    expect(meta.pushed_authorization_request_endpoint).toBe(`${ISSUER}/op/par`)
  })
})
