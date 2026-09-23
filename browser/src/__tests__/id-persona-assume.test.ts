// ─────────────────────────────────────────────────────────────────────
// The demo personas' GRANT-BASED ASSUMPTION (the account chooser's
// Google-Workspace "sign in as user" posture):
//
//   — the declared grant set (OP_DEMO_ASSUME_GRANTS) names the REAL
//     accounts allowed to assume; a grant-holder's chooser LISTS the
//     declared personas, an ungranted account never sees them;
//   — the assumption mints a session AS the persona with NO persona
//     credential presented (amr: ['assumed']) and journals the event
//     (op_assumptions: who, whom, when, which client);
//   — the assumed session rides the ordinary relying-party flow to a
//     code whose ID token names the PERSONA and carries the persona's
//     per-client roles — the containment the declaration declares;
//   — every verdict is the server's: a forged page claim gains nothing.
// ─────────────────────────────────────────────────────────────────────

import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

const TMP = mkdtempSync(join(tmpdir(), 'oiml-persona-assume-'))
process.env.DATABASE_PATH = join(TMP, 'test.db')
const ISSUER = 'http://op.test'
process.env.OP_ISSUER = ISSUER

const RP = {
  client_id: 'oiml-smart-demo',
  name: 'OIML SMART demonstration instance',
  secret: 'demo-secret-123',
  redirect_uris: ['https://demo.oimlsmart.org/api/auth/callback/oidc'],
  claims_policy: { claims: ['roles', 'org'] },
}
process.env.OP_CLIENT_SEED = JSON.stringify([RP])

// The demonstration cast: two declared personas + the grant naming the
// REAL team account (the demo-cast ia@oimlsmart.org stands in for the
// grantee — any live account address grants the same way).
const PERSONAS = [
  {
    email: 'persona-applicant@oimlsmart.org', name: 'ACME Applicant', role: 'user', orgId: 'mfr-acme',
    emailVerified: true, password: 'personas-never-publish-passwords-1',
    clientRoles: { 'oiml-smart-demo': ['applicant'] },
  },
  {
    email: 'persona-cs@oimlsmart.org', name: 'CS Administrator', role: 'user', orgId: 'oiml-cs-demo',
    emailVerified: true, password: 'personas-never-publish-passwords-2',
    clientRoles: { 'oiml-smart-demo': ['cs_admin'] },
  },
]
process.env.OP_ACCOUNT_SEED = JSON.stringify(PERSONAS)
process.env.OP_DEMO_ASSUME_GRANTS = JSON.stringify({
  clientId: 'oiml-smart-demo',
  grantees: ['ia@oimlsmart.org'],
})

let app: import('hono').Hono
let store: ReturnType<typeof import('../../server/store').getStore>

async function login(email = 'ia@oimlsmart.org'): Promise<string> {
  const res = await app.request('/api/auth/demo', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password: 'demo2026' }),
  })
  expect(res.ok).toBe(true)
  return res.headers.get('set-cookie')!.split(';')[0]!
}

/** A browser's cookie jar: the account jar is itself a cookie
 *  (`oiml-accounts`), so the multi-account scenarios need one request
 *  sequence that carries the jar forward. */
function cookieJar() {
  const jar = new Map<string, string>()
  const absorb = (res: Response): void => {
    const lines = typeof (res.headers as unknown as { getSetCookie?: () => string[] }).getSetCookie === 'function'
      ? (res.headers as unknown as { getSetCookie: () => string[] }).getSetCookie()
      : [res.headers.get('set-cookie')].filter((v): v is string => !!v)
    for (const line of lines) {
      const pair = line.split(';')[0]!
      const idx = pair.indexOf('=')
      jar.set(pair.slice(0, idx).trim(), pair.slice(idx + 1).trim())
    }
  }
  return {
    header: (): string => [...jar.entries()].map(([k, v]) => `${k}=${v}`).join('; '),
    absorb,
  }
}

async function loginInto(browser: ReturnType<typeof cookieJar>, email: string): Promise<void> {
  const res = await app.request('/api/auth/demo', {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...(browser.header() ? { cookie: browser.header() } : {}) },
    body: JSON.stringify({ email, password: 'demo2026' }),
  })
  expect(res.ok).toBe(true)
  browser.absorb(res)
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
  const { seedOpAccountsFromEnv } = await import('../../server/auth/op/accounts')
  const oidc = await import('../../server/oidc')
  oidc.clearOidcCaches()
  const { Hono } = await import('hono')
  const { createAuthLeanRouter } = await import('../../server/routes/auth-lean')
  const { createOpRouter } = await import('../../server/routes/op')
  const root = new Hono()
  root.route('/api/auth', createAuthLeanRouter({ autoSeedDemo: true }))
  root.route('/', createOpRouter())
  app = root
  store = (await import('../../server/store')).getStore()
  // The demonstration cast lands BEFORE any chooser read (production's
  // own boot posture — the seed converges before the flows run).
  await seedOpAccountsFromEnv({ OP_ACCOUNT_SEED: JSON.stringify(PERSONAS) }, store, ISSUER)
})

afterAll(() => {
  rmSync(TMP, { recursive: true, force: true })
  for (const key of ['OP_ISSUER', 'OP_SIGNING_KEY', 'OP_CLIENT_SEED', 'OP_ACCOUNT_SEED', 'OP_DEMO_ASSUME_GRANTS', 'DATABASE_PATH']) {
    delete process.env[key]
  }
})

describe('the grant gate (the chooser context)', () => {
  it('the grant-holder sees the declared personas (assumable, badged)', async () => {
    const cookie = await login('ia@oimlsmart.org')
    const res = await app.request('/api/op/choose-account', { headers: { cookie } })
    expect(res.ok).toBe(true)
    const body = await res.json() as { accounts: Array<{ email: string; assumable: boolean; hinted: boolean }> }
    const personas = body.accounts.filter(a => a.assumable)
    expect(personas.map(p => p.email).sort()).toEqual(['persona-applicant@oimlsmart.org', 'persona-cs@oimlsmart.org'])
  })

  it('the login_hint pre-selects the persona row (the Google shape reaches the personas)', async () => {
    const cookie = await login('ia@oimlsmart.org')
    const res = await app.request(`/api/op/choose-account?login_hint=${encodeURIComponent('PERSONA-APPLICANT@oimlsmart.org')}`, { headers: { cookie } })
    const body = await res.json() as { accounts: Array<{ email: string; assumable: boolean; hinted: boolean }> }
    expect(body.accounts.find(a => a.email === 'persona-applicant@oimlsmart.org')?.hinted).toBe(true)
    expect(body.accounts.find(a => a.email === 'persona-cs@oimlsmart.org')?.hinted).toBe(false)
  })

  it('an account without the grant never sees the personas', async () => {
    const cookie = await login('tl@oimlsmart.org')
    const res = await app.request('/api/op/choose-account', { headers: { cookie } })
    expect(res.ok).toBe(true)
    const body = await res.json() as { accounts: Array<{ assumable: boolean }> }
    expect(body.accounts.some(a => a.assumable)).toBe(false)
  })

  it('a malformed grant declaration closes the posture (no personas, never a widening)', async () => {
    process.env.OP_DEMO_ASSUME_GRANTS = 'not-json'
    try {
      const cookie = await login('ia@oimlsmart.org')
      const res = await app.request('/api/op/choose-account', { headers: { cookie } })
      const body = await res.json() as { accounts: Array<{ assumable: boolean }> }
      expect(body.accounts.some(a => a.assumable)).toBe(false)
    } finally {
      process.env.OP_DEMO_ASSUME_GRANTS = JSON.stringify({ clientId: 'oiml-smart-demo', grantees: ['ia@oimlsmart.org'] })
    }
  })
})

describe('the assumption (the grant-holder becomes the persona)', () => {
  let generatePkce: typeof import('../../server/oidc').generatePkce

  it('mints a session AS the persona, journals the event, and rides the flow to a persona ID token', async () => {
    const oidc = await import('../../server/oidc')
    generatePkce = oidc.generatePkce
    const browser = cookieJar()
    await loginInto(browser, 'ia@oimlsmart.org')

    // The RP's flow asks for the chooser (the smart instance's own
    // "Switch account" lands here through prompt=select_account).
    const pkce = await generatePkce()
    const ask = await app.request(
      `${ISSUER}/op/authorize?${authorizeQuery({ scope: 'openid email', prompt: 'select_account', login_hint: 'persona-applicant@oimlsmart.org', code_challenge: pkce.challenge })}`,
      { headers: { cookie: browser.header() } },
    )
    expect(ask.status).toBe(302)
    const chooserUrl = new URL(ask.headers.get('location')!, ISSUER)
    expect(chooserUrl.pathname).toBe('/op/choose-account')
    const continueTarget = chooserUrl.searchParams.get('continue')!

    // The context marks the persona pre-selected; the holder clicks it.
    const ctx = await app.request(`/api/op/choose-account?continue=${encodeURIComponent(continueTarget)}&login_hint=persona-applicant@oimlsmart.org`, { headers: { cookie: browser.header() } })
    const ctxBody = await ctx.json() as { accounts: Array<{ email: string; assumable: boolean; hinted: boolean }> }
    expect(ctxBody.accounts.find(a => a.email === 'persona-applicant@oimlsmart.org')).toMatchObject({ assumable: true, hinted: true })

    const pick = await app.request('/api/op/choose-account', {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: browser.header() },
      body: JSON.stringify({ email: 'persona-applicant@oimlsmart.org', continue: continueTarget }),
    })
    expect(pick.status).toBe(200)
    const answer = await pick.json() as { ok: boolean; redirect?: string }
    expect(answer.ok).toBe(true)
    expect(answer.redirect).toBe(continueTarget)
    browser.absorb(pick)

    // The journal: one event — the actor, the persona, the client.
    const journal = await store.listOpAssumptions({})
    expect(journal).toHaveLength(1)
    expect(journal[0]).toMatchObject({
      actorEmail: 'ia@oimlsmart.org',
      personaEmail: 'persona-applicant@oimlsmart.org',
      clientId: 'oiml-smart-demo',
    })

    // The authorize re-entry runs AS the persona. The persona has no
    // remembered grant, so the consent page shows (the flow's own
    // posture) and the holder allows it — still acting as the persona.
    const resume = await app.request(continueTarget, { headers: { cookie: browser.header() } })
    expect(resume.status).toBe(302)
    const afterResume = new URL(resume.headers.get('location')!, ISSUER)
    if (afterResume.pathname === '/op/consent') {
      const authId = afterResume.searchParams.get('auth')!
      const decided = await app.request(`/api/op/consent/${authId}/decide`, {
        method: 'POST', headers: { 'content-type': 'application/json', cookie: browser.header() },
        body: JSON.stringify({ decision: 'allow' }),
      })
      expect(decided.ok).toBe(true)
      browser.absorb(decided)
    }
    const done = await app.request(continueTarget, { headers: { cookie: browser.header() } })
    expect(done.status).toBe(302)
    const back = new URL(done.headers.get('location')!, ISSUER)
    expect(back.origin + back.pathname).toBe(RP.redirect_uris[0]!)
    const code = back.searchParams.get('code')
    expect(code).toBeTruthy()

    // The exchange: the ID token names the PERSONA — the subject, the
    // address, the amr marker, and the persona's per-client roles. The
    // grantee's identity appears nowhere on the wire.
    const token = await app.request(`${ISSUER}/op/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code', code: code!, redirect_uri: RP.redirect_uris[0]!,
        client_id: RP.client_id, client_secret: RP.secret, code_verifier: pkce.verifier,
      }),
    })
    expect(token.status).toBe(200)
    const grants = await token.json() as { id_token: string }
    const claims = JSON.parse(atob(grants.id_token.split('.')[1]!.replace(/-/g, '+').replace(/_/g, '/'))) as Record<string, unknown>
    expect(claims.email).toBe('persona-applicant@oimlsmart.org')
    const persona = await store.findUserByEmail('persona-applicant@oimlsmart.org')
    expect(claims.sub).toBe(persona!.id)
    expect(claims.roles).toEqual(['applicant'])
    expect(claims.amr).toEqual(['assumed'])
  })
})

describe('the assumption refusals (the server holds every verdict)', () => {
  it('an ungranted presenting account is refused (403), the persona unmentioned', async () => {
    const browser = cookieJar()
    await loginInto(browser, 'tl@oimlsmart.org')
    const pick = await app.request('/api/op/choose-account', {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: browser.header() },
      body: JSON.stringify({ email: 'persona-applicant@oimlsmart.org', continue: '/op/account' }),
    })
    expect(pick.status).toBe(403)
    const body = await pick.json() as { error: string }
    expect(body.error).toContain('not granted')
  })

  it('a signed-out posture reads as the honest login fallback (no grant signal leaks)', async () => {
    const res = await app.request('/api/op/choose-account', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: 'persona-applicant@oimlsmart.org', continue: '/op/account' }),
    })
    expect(res.ok).toBe(true)
    const body = await res.json() as { ok: boolean; login?: string }
    expect(body.ok).toBe(false)
    expect(body.login).toContain('/')
  })

  it('a forged or undeclared address never assumes (the declaration is the only persona set)', async () => {
    const browser = cookieJar()
    await loginInto(browser, 'ia@oimlsmart.org')
    for (const email of ['tl@oimlsmart.org', 'stranger@elsewhere.invalid']) {
      const res = await app.request('/api/op/choose-account', {
        method: 'POST',
        headers: { 'content-type': 'application/json', cookie: browser.header() },
        body: JSON.stringify({ email, continue: '/op/account' }),
      })
      expect(res.ok).toBe(true)
      const body = await res.json() as { ok: boolean }
      expect(body.ok).toBe(false)
    }
    const journal = await store.listOpAssumptions({})
    expect(journal.every(j => j.personaEmail !== 'tl@oimlsmart.org' && j.personaEmail !== 'stranger@elsewhere.invalid')).toBe(true)
  })
})
