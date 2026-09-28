// ─────────────────────────────────────────────────────────────────────
// The demo personas' GRANT-BASED ASSUMPTION (the account chooser's
// Google-Workspace "sign in as user" posture):
//
//   — the declared grant set (OP_DEMO_ASSUME_GRANTS) names the REAL
//     accounts allowed to assume; a grant-holder's chooser LISTS the
//     declared personas, an ungranted account never sees them;
//   — the assumption mints a session AS the persona with NO persona
//     credential presented (amr: ['assumed'], the actor stamped in
//     sessions.assumed_by) and journals the event
//     (op_assumptions: who, whom, when, which client);
//   — the persona→persona CHAIN: an assumed session lists and assumes
//     the other declared personas on the ORIGINAL grantee's standing
//     (the stamp's account), never returning to the personal account
//     first; a chain whose actor holds no grant is refused exactly like
//     an ungranted presenting account;
//   — the personas' consent is PRE-SEEDED at the account seed (the
//     standard scope set per persona per client), so the demonstration's
//     switches never stop at the consent page — and no other account's
//     consent is ever pre-seeded;
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

// The demonstration cast: the declared personas + the grant naming the
// REAL team account (the demo-cast ia@oimlsmart.org stands in for the
// grantee — any live account address grants the same way).
const PERSONAS = [
  {
    email: 'persona-applicant@oimlsmart.org', name: 'ACME Applicant', role: 'user', orgId: 'mfr-acme',
    emailVerified: true, password: 'personas-never-publish-passwords-1',
    clientRoles: { 'oiml-smart-demo': ['applicant'] },
  },
  {
    email: 'persona-ia@oimlsmart.org', name: 'IA Officer', role: 'user', orgId: 'EX1',
    emailVerified: true, password: 'personas-never-publish-passwords-3',
    clientRoles: { 'oiml-smart-demo': ['ia_officer'] },
  },
  {
    email: 'persona-tl@oimlsmart.org', name: 'TL Operator', role: 'user', orgId: '21',
    emailVerified: true, password: 'personas-never-publish-passwords-4',
    clientRoles: { 'oiml-smart-demo': ['tl_operator'] },
  },
  {
    email: 'persona-utilizer@oimlsmart.org', name: 'Utilizer Officer (NL)', role: 'user', orgId: 'ut-nmi-nl',
    emailVerified: true, password: 'personas-never-publish-passwords-5',
    clientRoles: { 'oiml-smart-demo': ['scheme_participant'] },
  },
  {
    email: 'persona-cs@oimlsmart.org', name: 'CS Administrator', role: 'user', orgId: 'oiml-cs-demo',
    emailVerified: true, password: 'personas-never-publish-passwords-2',
    clientRoles: { 'oiml-smart-demo': ['cs_admin'] },
  },
  {
    // The System Administration persona (the owner keeps it; the
    // viewer persona was DROPPED — certificates are public, utilizer@
    // covers authenticated non-public reads): the per-client role key
    // mirrors the smart demo mapping EXACTLY (`admin` = full access)
    // while the OP-side account stays `role: 'user'` (no OP
    // administration reach).
    email: 'persona-admin@oimlsmart.org', name: 'System Administrator', role: 'user',
    emailVerified: true, password: 'personas-never-publish-passwords-6',
    clientRoles: { 'oiml-smart-demo': ['admin'] },
  },
  {
    // The market-surveillance persona (smart's TODO.remain/09): the
    // member-state authority's officer, bound to the same registered
    // Utilizer as the utilizer persona; the per-client role key mirrors
    // the smart demo mapping's market_surveillance rule (the register's
    // authority audience resolves from it).
    email: 'persona-surveillance@oimlsmart.org', name: 'Market Surveillance (NL)', role: 'user', orgId: 'ut-nmi-nl',
    emailVerified: true, password: 'personas-never-publish-passwords-7',
    clientRoles: { 'oiml-smart-demo': ['market_surveillance'] },
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

/** The named cookie's value out of a response's Set-Cookie lines (the
 *  session token the chooser's POST minted — the session-row assertions'
 *  read key). */
function setCookieValue(res: Response, name: string): string | null {
  const lines = typeof (res.headers as unknown as { getSetCookie?: () => string[] }).getSetCookie === 'function'
    ? (res.headers as unknown as { getSetCookie: () => string[] }).getSetCookie()
    : [res.headers.get('set-cookie')].filter((v): v is string => !!v)
  for (const line of lines) {
    const pair = line.split(';')[0]!
    const idx = pair.indexOf('=')
    if (pair.slice(0, idx).trim() === name) return pair.slice(idx + 1).trim()
  }
  return null
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
  // own boot posture — the seed converges before the flows run). The
  // grant declaration rides the seed env: the personas' remembered
  // consent pre-seeds with the roster (the streamlined switching).
  await seedOpAccountsFromEnv({
    OP_ACCOUNT_SEED: JSON.stringify(PERSONAS),
    OP_DEMO_ASSUME_GRANTS: process.env.OP_DEMO_ASSUME_GRANTS,
  }, store, ISSUER)
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
    // The full demonstration cast (SEVEN): applicant, ia, tl, utilizer,
    // cs, the kept System Administration persona (admin = full access),
    // and the market-surveillance officer (smart's TODO.remain/09) —
    // every entry the declaration scopes to the client.
    expect(personas.map(p => p.email).sort()).toEqual([
      'persona-admin@oimlsmart.org',
      'persona-applicant@oimlsmart.org',
      'persona-cs@oimlsmart.org',
      'persona-ia@oimlsmart.org',
      'persona-surveillance@oimlsmart.org',
      'persona-tl@oimlsmart.org',
      'persona-utilizer@oimlsmart.org',
    ])
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

    // The authorize re-entry runs AS the persona. The seed pre-seeded
    // the persona's remembered consent (the streamlined switching
    // posture), so the flow mints the code directly — no consent
    // round-trip, no consent page.
    const resume = await app.request(continueTarget, { headers: { cookie: browser.header() } })
    expect(resume.status).toBe(302)
    const back = new URL(resume.headers.get('location')!, ISSUER)
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

  it('an assumed persona\'s DEAD jar row still re-assumes by userId (the row-derived lookup serves the granted holder)', async () => {
    const browser = cookieJar()
    await loginInto(browser, 'ia@oimlsmart.org')
    // First assumption: the persona joins the jar as an ordinary row.
    const first = await app.request('/api/op/choose-account', {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: browser.header() },
      body: JSON.stringify({ email: 'persona-applicant@oimlsmart.org', continue: '/op/account' }),
    })
    expect(first.ok).toBe(true)
    browser.absorb(first)
    const persona = (await store.findUserByEmail('persona-applicant@oimlsmart.org'))!
    // The presenting session swapped to the persona at assumption time;
    // the holder signs back in as themselves (the persona stays in the
    // jar), and THEN the persona's session dies.
    await loginInto(browser, 'ia@oimlsmart.org')
    const { default: Database } = await import('better-sqlite3')
    const raw = new Database(process.env.DATABASE_PATH!)
    raw.prepare('DELETE FROM sessions WHERE user_id = ?').run(persona.id)
    raw.close()
    // The granted holder clicks the dead row (the page POSTs userId):
    // the re-verdict resolves the persona from the row and re-assumes.
    const again = await app.request('/api/op/choose-account', {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: browser.header() },
      body: JSON.stringify({ userId: persona.id, continue: '/op/account' }),
    })
    expect(again.status).toBe(200)
    const body = await again.json() as { ok: boolean; redirect?: string }
    expect(body.ok).toBe(true)
    expect(body.redirect).toBe('/op/account')
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

  it('a signed-out persona-id probe answers the SAME fallback (no uuid-to-email echo, no persona oracle)', async () => {
    // The persona's id is not a secret (it rides the ID token's sub
    // after any assumption); the SIGNED-OUT answer must not turn an id
    // into an address — and must not distinguish persona from
    // non-persona (the probe answers byte-identically either way).
    const persona = (await store.findUserByEmail('persona-applicant@oimlsmart.org'))!
    const res = await app.request('/api/op/choose-account', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ userId: persona.id, continue: '/op/account' }),
    })
    expect(res.ok).toBe(true)
    const body = await res.json() as { ok: boolean; login?: string }
    expect(body.ok).toBe(false)
    expect(body.login, 'no address may ride the signed-out prefill').toBeTruthy()
    expect(body.login!).not.toContain('persona-applicant')
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

describe('the persona→persona chaining (the streamlined switch)', () => {
  it('an assumed session lists the personas on the ORIGINAL grantee\'s standing and chains to the next persona', async () => {
    const browser = cookieJar()
    await loginInto(browser, 'ia@oimlsmart.org')
    // The first hop: the grant-holder assumes the applicant (the direct
    // posture — the presenting session is the grantee's own).
    const first = await app.request('/api/op/choose-account', {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: browser.header() },
      body: JSON.stringify({ email: 'persona-applicant@oimlsmart.org', continue: '/op/account' }),
    })
    expect(first.ok).toBe(true)
    const firstToken = setCookieValue(first, 'oiml-session')!
    browser.absorb(first)
    // The hop stamped the actor: the session row names the grantee.
    const ia = (await store.findUserByEmail('ia@oimlsmart.org'))!
    const firstSession = await store.getSessionUser(firstToken)
    expect(firstSession?.amr).toEqual(['assumed'])
    expect(firstSession?.assumedBy).toBe(ia.id)

    // The chooser UNDER the assumed session still lists the full cast —
    // the verdict judged the original grantee's grants, and the demo's
    // switch never returns to the personal account first.
    const ctx = await app.request('/api/op/choose-account', { headers: { cookie: browser.header() } })
    expect(ctx.ok).toBe(true)
    const ctxBody = await ctx.json() as { accounts: Array<{ email: string; assumable: boolean }> }
    expect(ctxBody.accounts.filter(a => a.assumable).map(a => a.email).sort()).toEqual([
      'persona-admin@oimlsmart.org',
      'persona-applicant@oimlsmart.org',
      'persona-cs@oimlsmart.org',
      'persona-ia@oimlsmart.org',
      'persona-surveillance@oimlsmart.org',
      'persona-tl@oimlsmart.org',
      'persona-utilizer@oimlsmart.org',
    ])

    // The chain hop: the applicant's session assumes the IA officer
    // directly — the grant re-judges the actor, never the persona.
    const chained = await app.request('/api/op/choose-account', {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: browser.header() },
      body: JSON.stringify({ email: 'persona-ia@oimlsmart.org', continue: '/op/account' }),
    })
    expect(chained.status).toBe(200)
    const answer = await chained.json() as { ok: boolean; redirect?: string }
    expect(answer.ok).toBe(true)
    expect(answer.redirect).toBe('/op/account')
    const chainedToken = setCookieValue(chained, 'oiml-session')!
    browser.absorb(chained)
    // The chained session is the persona's, the marker and the SAME
    // actor carried verbatim.
    const chainedSession = await store.getSessionUser(chainedToken)
    expect(chainedSession?.email).toBe('persona-ia@oimlsmart.org')
    expect(chainedSession?.amr).toEqual(['assumed'])
    expect(chainedSession?.assumedBy).toBe(ia.id)
    // The journal carries both hops under the SAME actor of record —
    // a chain reads identically to a direct assumption.
    const journal = await store.listOpAssumptions({ actorUserId: ia.id })
    expect(journal.map(j => j.personaEmail)).toEqual(expect.arrayContaining(['persona-applicant@oimlsmart.org', 'persona-ia@oimlsmart.org']))
    expect(journal.every(j => j.actorEmail === 'ia@oimlsmart.org')).toBe(true)
  })

  it('a chain whose stamped actor holds no grant is refused (403) and lists no personas', async () => {
    // A hand-minted assumed session whose stamped actor is NOT a grantee
    // (the store seam writes exactly what the assumption mint would,
    // minus the grant — the declaration never names tl).
    const tl = (await store.findUserByEmail('tl@oimlsmart.org'))!
    const applicant = (await store.findUserByEmail('persona-applicant@oimlsmart.org'))!
    const token = await store.createSession(applicant.id, { amr: ['assumed'], assumedBy: tl.id })
    const cookie = `oiml-session=${token}`
    const ctx = await app.request('/api/op/choose-account', { headers: { cookie } })
    expect(ctx.ok).toBe(true)
    const ctxBody = await ctx.json() as { accounts: Array<{ assumable: boolean }> }
    expect(ctxBody.accounts.some(a => a.assumable)).toBe(false)
    const pick = await app.request('/api/op/choose-account', {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ email: 'persona-ia@oimlsmart.org', continue: '/op/account' }),
    })
    expect(pick.status).toBe(403)
    const body = await pick.json() as { error: string }
    expect(body.error).toContain('not granted')
  })

  it('an assumed session minted before the actor stamp closes honestly (no stamp, no chain)', async () => {
    // The legacy row shape (pre-0037): amr carries the marker but no
    // assumed_by — the actor is unprovable, so the chain stays closed
    // (the jar's swap back to the personal account is the way out).
    const applicant = (await store.findUserByEmail('persona-applicant@oimlsmart.org'))!
    const token = await store.createSession(applicant.id, { amr: ['assumed'] })
    const cookie = `oiml-session=${token}`
    const ctx = await app.request('/api/op/choose-account', { headers: { cookie } })
    const ctxBody = await ctx.json() as { accounts: Array<{ assumable: boolean }> }
    expect(ctxBody.accounts.some(a => a.assumable)).toBe(false)
    const pick = await app.request('/api/op/choose-account', {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ email: 'persona-ia@oimlsmart.org', continue: '/op/account' }),
    })
    expect(pick.status).toBe(403)
  })
})

describe('the personas\' pre-seeded consent (the demo never stops at the consent page)', () => {
  it('the seed converged the standard scope grant for every persona, idempotently', async () => {
    for (const p of PERSONAS) {
      const account = (await store.findUserByEmail(p.email))!
      const grant = await store.getConsentGrant(account.id, RP.client_id, 'openid profile email offline_access')
      expect(grant, `${p.email}'s pre-seeded grant`).toBeTruthy()
      // The canonical spelling (normalizeOidcScopeSet) is what lands.
      expect(grant!.scope).toBe('email offline_access openid profile')
    }
    // The convergence is idempotent: a re-seed refreshes the SAME live
    // row (the upsert), never a second grant.
    const { seedOpAccountsFromEnv } = await import('../../server/auth/op/accounts')
    await seedOpAccountsFromEnv({
      OP_ACCOUNT_SEED: JSON.stringify(PERSONAS),
      OP_DEMO_ASSUME_GRANTS: process.env.OP_DEMO_ASSUME_GRANTS,
    }, store, ISSUER)
    const tl = (await store.findUserByEmail('persona-tl@oimlsmart.org'))!
    const live = (await store.listConsentGrants(tl.id)).filter(g => g.clientId === RP.client_id)
    expect(live).toHaveLength(1)
  })

  it('a seeded persona\'s FIRST authorize mints the code with no consent round-trip', async () => {
    const { generatePkce } = await import('../../server/oidc')
    const browser = cookieJar()
    await loginInto(browser, 'ia@oimlsmart.org')
    const assume = await app.request('/api/op/choose-account', {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: browser.header() },
      body: JSON.stringify({ email: 'persona-surveillance@oimlsmart.org', continue: '/op/account' }),
    })
    expect(assume.ok).toBe(true)
    browser.absorb(assume)
    // The FIRST OIDC flow the persona ever rides: the pre-seeded grant
    // covers the standard ask, so the code mints straight into the RP
    // redirect — /op/consent never enters the path.
    const pkce = await generatePkce()
    const ask = await app.request(
      `${ISSUER}/op/authorize?${authorizeQuery({ scope: 'openid profile email offline_access', code_challenge: pkce.challenge })}`,
      { headers: { cookie: browser.header() } },
    )
    expect(ask.status).toBe(302)
    const back = new URL(ask.headers.get('location')!, ISSUER)
    expect(back.origin + back.pathname).toBe(RP.redirect_uris[0]!)
    const code = back.searchParams.get('code')
    expect(code).toBeTruthy()
    // …and the code exchanges exactly like a consented one — the persona's
    // subject, the amr marker, and (offline_access rode the grant) the
    // first refresh token of the family.
    const token = await app.request(`${ISSUER}/op/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code', code: code!, redirect_uri: RP.redirect_uris[0]!,
        client_id: RP.client_id, client_secret: RP.secret, code_verifier: pkce.verifier,
      }),
    })
    expect(token.status).toBe(200)
    const grants = await token.json() as { id_token: string; refresh_token?: string }
    const claims = JSON.parse(atob(grants.id_token.split('.')[1]!.replace(/-/g, '+').replace(/_/g, '/'))) as Record<string, unknown>
    expect(claims.email).toBe('persona-surveillance@oimlsmart.org')
    expect(claims.amr).toEqual(['assumed'])
    expect(grants.refresh_token).toBeTruthy()
  })
})
