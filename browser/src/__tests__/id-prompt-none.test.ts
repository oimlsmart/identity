// ─────────────────────────────────────────────────────────────────────
// prompt=none (the OIDC-correct silent probe): a sessionless request
// answers the client's redirect_uri with error=login_required (with
// state) — NEVER the login page. A sessionful request rides the normal
// flow unchanged.
// ─────────────────────────────────────────────────────────────────────

import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

const TMP = mkdtempSync(join(tmpdir(), 'oiml-prompt-none-'))
process.env.DATABASE_PATH = join(TMP, 'test.db')
const ISSUER = 'http://op.test'
process.env.OP_ISSUER = ISSUER

const RP = {
  client_id: 'hub-instance',
  name: 'OIML SMART platform hub',
  secret: 'hub-secret-123',
  redirect_uris: ['https://hub.example/api/auth/callback/oidc'],
}
process.env.OP_CLIENT_SEED = JSON.stringify([RP])

let app: import('hono').Hono
let generatePkce: typeof import('../../server/oidc').generatePkce

function authorizeQuery(extra: Record<string, string> = {}): URLSearchParams {
  return new URLSearchParams({
    response_type: 'code', client_id: RP.client_id, redirect_uri: RP.redirect_uris[0]!,
    scope: 'openid', code_challenge: 'e'.repeat(43), code_challenge_method: 'S256',
    state: 'the-probe-state',
    ...extra,
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
  oidc.clearOidcCaches()
  generatePkce = oidc.generatePkce
  const { Hono } = await import('hono')
  const { createAuthLeanRouter } = await import('../../server/routes/auth-lean')
  const { createOpRouter } = await import('../../server/routes/op')
  const root = new Hono()
  root.route('/api/auth', createAuthLeanRouter({ autoSeedDemo: true }))
  root.route('/', createOpRouter())
  app = root
})

afterAll(() => {
  rmSync(TMP, { recursive: true, force: true })
  for (const key of ['OP_ISSUER', 'OP_SIGNING_KEY', 'OP_CLIENT_SEED', 'DATABASE_PATH']) delete process.env[key]
})

describe('prompt=none (the silent probe)', () => {
  it('a sessionless request answers login_required at the redirect_uri, with state', async () => {
    const pkce = await generatePkce()
    const res = await app.request(`${ISSUER}/op/authorize?${authorizeQuery({ prompt: 'none', code_challenge: pkce.challenge })}`, { redirect: 'manual' })
    expect(res.status).toBe(302)
    const back = new URL(res.headers.get('location')!, ISSUER)
    expect(back.origin + back.pathname).toBe(RP.redirect_uris[0]!)
    expect(back.searchParams.get('error')).toBe('login_required')
    expect(back.searchParams.get('error_description')).toBeTruthy()
    expect(back.searchParams.get('state')).toBe('the-probe-state')
  })

  it('a sessionless prompt=none NEVER lands on the login page', async () => {
    const pkce = await generatePkce()
    const res = await app.request(`${ISSUER}/op/authorize?${authorizeQuery({ prompt: 'none', code_challenge: pkce.challenge })}`, { redirect: 'manual' })
    expect(new URL(res.headers.get('location')!, ISSUER).pathname).not.toBe('/')
  })

  it('a sessionful prompt=none rides the normal flow (no error)', async () => {
    const pkce = await generatePkce()
    const login = await app.request('/api/auth/demo', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: 'ia@oimlsmart.org', password: 'demo2026' }),
    })
    expect(login.ok, `the demo sign-in → ${login.status}`).toBe(true)
    const cookie = login.headers.get('set-cookie')!.split(';')[0]!
    const res = await app.request(`${ISSUER}/op/authorize?${authorizeQuery({ prompt: 'none', code_challenge: pkce.challenge })}`, { redirect: 'manual', headers: { cookie } })
    expect(res.status).toBe(302)
    const back = new URL(res.headers.get('location')!, ISSUER)
    expect(back.searchParams.get('error')).toBeNull()
  })
})
