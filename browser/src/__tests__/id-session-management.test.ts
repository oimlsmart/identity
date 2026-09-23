// ─────────────────────────────────────────────────────────────────────
// TODO.modern/03 — the OIDC session management surface, in-process:
// the discovery advertisement (check_session_iframe), the check
// iframe's poll protocol, the state digest endpoint (live-session
// bound, 401 without), and the authorize answer's session_state.
// The REAL op router over a REAL temp SQLite store — no stubs.
// ─────────────────────────────────────────────────────────────────────

import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

const TMP = mkdtempSync(join(tmpdir(), 'oiml-session-mgmt-'))
process.env.DATABASE_PATH = join(TMP, 'test.db')

const ISSUER = 'http://op.test'
process.env.OP_ISSUER = ISSUER

const CONFIDENTIAL = {
  client_id: 'hub-instance',
  name: 'OIML SMART platform hub',
  secret: 'hub-secret-123',
  redirect_uris: ['https://hub.example/api/auth/callback/oidc'],
  claims_policy: { claims: ['roles', 'groups', 'org'] },
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

describe('the discovery advertisement', () => {
  it('names the check_session_iframe on the issuer', async () => {
    const res = await app.request(`${ISSUER}/.well-known/openid-configuration`)
    const meta = await res.json() as Record<string, unknown>
    expect(meta.check_session_iframe).toBe(`${ISSUER}/op/session/check`)
  })
})

describe('the check iframe', () => {
  it('serves the poll page: frameable, no-store, message-driven, fail-closed', async () => {
    const res = await app.request(`${ISSUER}/op/session/check?client_id=hub-instance`)
    expect(res.status).toBe(200)
    expect(res.headers.get('content-type')).toContain('text/html')
    expect(res.headers.get('cache-control')).toContain('no-store')
    expect(res.headers.get('content-security-policy')).toContain('frame-ancestors')
    const html = await res.text()
    expect(html).toContain('addEventListener("message"')
    expect(html).toContain('postMessage')
    expect(html).toContain('"changed"')
    expect(html).toContain('"unchanged"')
  })

  it('refuses a request that names no client', async () => {
    const res = await app.request(`${ISSUER}/op/session/check`)
    expect(res.status).toBe(400)
  })
})

describe('the state digest endpoint', () => {
  const url = `${ISSUER}/op/session/state?client_id=hub-instance&origin=${encodeURIComponent('https://hub.example')}`

  it('answers 401 without a session', async () => {
    const res = await app.request(url)
    expect(res.status).toBe(401)
    const body = await res.json() as { session_state?: string }
    expect(body.session_state).toBeUndefined()
  })

  it('answers the live digest: deterministic, bound to client + origin', async () => {
    const { computeSessionState } = await import('../../server/auth/op/session-state')
    const cookie = await demoLogin('ia@oimlsmart.org')
    const token = cookie.split('=')[1]!

    const res = await app.request(url, { headers: { cookie } })
    expect(res.status).toBe(200)
    const { session_state: first } = await res.json() as { session_state: string }
    expect(first).toBeTruthy()

    const again = await app.request(url, { headers: { cookie } })
    const { session_state: second } = await again.json() as { session_state: string }
    expect(second).toBe(first)

    const expected = await computeSessionState('hub-instance', 'https://hub.example', token)
    expect(first).toBe(expected)

    const other = await app.request(
      `${ISSUER}/op/session/state?client_id=other-rp&origin=${encodeURIComponent('https://hub.example')}`,
      { headers: { cookie } },
    )
    const { session_state: forOther } = await other.json() as { session_state: string }
    expect(forOther).not.toBe(first)
  })

  it('goes 401 the moment the session is gone (the honest changed)', async () => {
    const cookie = await demoLogin('tl@oimlsmart.org')
    const signout = await app.request('/api/auth/signout', { method: 'POST', headers: { cookie } })
    expect(signout.ok).toBe(true)
    const res = await app.request(url, { headers: { cookie } })
    expect(res.status).toBe(401)
  })

  it('refuses an incomplete binding', async () => {
    const cookie = await demoLogin('ia@oimlsmart.org')
    const noOrigin = await app.request(`${ISSUER}/op/session/state?client_id=hub-instance`, { headers: { cookie } })
    expect(noOrigin.status).toBe(400)
  })
})

describe('the authorize answer carries session_state', () => {
  it('the minted redirect binds the digest for the RP', async () => {
    const { computeSessionState } = await import('../../server/auth/op/session-state')
    const cookie = await demoLogin('ia@oimlsmart.org')
    const token = cookie.split('=')[1]!
    const pkce = await generatePkce()

    const query = new URLSearchParams({
      response_type: 'code',
      client_id: CONFIDENTIAL.client_id,
      redirect_uri: CONFIDENTIAL.redirect_uris[0]!,
      scope: 'openid profile email',
      state: 'st-ss-1',
      nonce: 'nn-ss-1',
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
    expect(decide.status).toBe(200)
    const { redirect } = await decide.json() as { redirect: string }

    const back = new URL(redirect)
    expect(back.searchParams.get('code')).toBeTruthy()
    const expected = await computeSessionState(
      CONFIDENTIAL.client_id,
      new URL(CONFIDENTIAL.redirect_uris[0]!).origin,
      token,
    )
    expect(back.searchParams.get('session_state')).toBe(expected)
  })
})
