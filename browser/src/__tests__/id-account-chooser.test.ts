// ─────────────────────────────────────────────────────────────────────
// TODO.modern/17 — the account chooser's honest form: prompt=
// select_account suppresses the remembered grant (the holder confirms
// the acting identity), login_hint lands in the sign-in redirect, and
// both ride the PAR source. The default flow stays byte-identical.
// ─────────────────────────────────────────────────────────────────────

import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

const TMP = mkdtempSync(join(tmpdir(), 'oiml-chooser-'))
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
let store: ReturnType<typeof import('../../server/store').getStore>

async function login(email = 'ia@oimlsmart.org'): Promise<string> {
  const res = await app.request('/api/auth/demo', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password: 'demo2026' }),
  })
  expect(res.ok).toBe(true)
  return res.headers.get('set-cookie')!.split(';')[0]!
}

function authorizeQuery(extra: Record<string, string> = {}): URLSearchParams {
  return new URLSearchParams({
    response_type: 'code', client_id: RP.client_id, redirect_uri: RP.redirect_uris[0]!,
    scope: 'openid', code_challenge: 'e'.repeat(43), code_challenge_method: 'S256',
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
  generatePkce = oidc.generatePkce
  oidc.clearOidcCaches()
  const { Hono } = await import('hono')
  const { createAuthLeanRouter } = await import('../../server/routes/auth-lean')
  const { createOpRouter } = await import('../../server/routes/op')
  const root = new Hono()
  root.route('/api/auth', createAuthLeanRouter({ autoSeedDemo: true }))
  root.route('/', createOpRouter())
  app = root
  store = (await import('../../server/store')).getStore()
})

afterAll(() => {
  rmSync(TMP, { recursive: true, force: true })
  delete process.env.OP_ISSUER
  delete process.env.OP_SIGNING_KEY
  delete process.env.OP_CLIENT_SEED
  delete process.env.DATABASE_PATH
})

describe('prompt=select_account (the chooser confirmation)', () => {
  it('suppresses the remembered grant — the consent page shows even with a live grant', async () => {
    const cookie = await login()
    // First: consent + allow, creating the remembered grant.
    const first = await app.request(`${ISSUER}/op/authorize?${authorizeQuery()}`, { headers: { cookie } })
    const authId = new URL(first.headers.get('location')!, ISSUER).searchParams.get('auth')!
    await app.request(`${ISSUER}/api/op/consent/${authId}/decide`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ decision: 'allow' }),
    })
    const grant = await store.getConsentGrant((await store.findUserByEmail('ia@oimlsmart.org'))!.id, RP.client_id, 'openid')
    expect(grant, 'the remembered grant exists').toBeTruthy()

    // The plain repeat: the grant skips the page (the code redirect).
    const plain = await app.request(`${ISSUER}/op/authorize?${authorizeQuery()}`, { headers: { cookie } })
    expect(new URL(plain.headers.get('location')!, ISSUER).pathname).not.toBe('/op/consent')

    // select_account: the CHOOSER page shows DESPITE the grant (the
    // earlier wave's surface — the holder confirms the acting identity).
    const chosen = await app.request(`${ISSUER}/op/authorize?${authorizeQuery({ prompt: 'select_account' })}`, { headers: { cookie } })
    expect(chosen.status).toBe(302)
    const chooser = new URL(chosen.headers.get('location')!, ISSUER)
    expect(chooser.pathname).toBe('/op/choose-account')
    expect(chooser.searchParams.get('continue')).toContain('/op/authorize')
  })
})

describe('login_hint (the sign-in prefill)', () => {
  it('rides the sign-in redirect for the unsigned-in session', async () => {
    const res = await app.request(`${ISSUER}/op/authorize?${authorizeQuery({ login_hint: 'ia@oimlsmart.org' })}`)
    expect(res.status).toBe(302)
    const back = new URL(res.headers.get('location')!, ISSUER)
    expect(back.pathname).toBe('/')
    expect(back.searchParams.get('login_hint')).toBe('ia@oimlsmart.org')
  })

  it('the default flow carries no login_hint (byte-identical posture)', async () => {
    const res = await app.request(`${ISSUER}/op/authorize?${authorizeQuery()}`)
    const back = new URL(res.headers.get('location')!, ISSUER)
    expect(back.searchParams.get('login_hint')).toBeNull()
  })
})
