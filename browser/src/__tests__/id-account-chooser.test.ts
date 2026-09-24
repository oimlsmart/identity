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

// ── the chooser's login_hint pre-selection (the Google shape) ────────

/** A browser's cookie jar: the account jar is itself a cookie
 *  (`oiml-accounts`), so the multi-account scenarios need one request
 *  sequence that carries the jar forward — separate cookie-less requests
 *  would each remember only their own sign-in. */
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

describe('login_hint on the chooser (the pre-selection)', () => {
  it('the select_account redirect carries the hint to the chooser page', async () => {
    const cookie = await login()
    const res = await app.request(`${ISSUER}/op/authorize?${authorizeQuery({ prompt: 'select_account', login_hint: 'tl@oimlsmart.org' })}`, { headers: { cookie } })
    expect(res.status).toBe(302)
    const chooser = new URL(res.headers.get('location')!, ISSUER)
    expect(chooser.pathname).toBe('/op/choose-account')
    expect(chooser.searchParams.get('login_hint')).toBe('tl@oimlsmart.org')
  })

  it('the context marks the matching entry as the pre-selection (case-insensitive)', async () => {
    const browser = cookieJar()
    await loginInto(browser, 'ia@oimlsmart.org')
    await loginInto(browser, 'tl@oimlsmart.org') // the presenting account; the jar holds both
    const res = await app.request(`/api/op/choose-account?login_hint=${encodeURIComponent('  IA@OIMLSMART.ORG ')}`, { headers: { cookie: browser.header() } })
    expect(res.ok).toBe(true)
    const body = await res.json() as { loginHint: string | null; accounts: Array<{ email: string; hinted: boolean; current: boolean }> }
    expect(body.loginHint).toBe('ia@oimlsmart.org')
    const byEmail = new Map(body.accounts.map(a => [a.email, a]))
    expect(byEmail.get('ia@oimlsmart.org')?.hinted).toBe(true)
    expect(byEmail.get('tl@oimlsmart.org')?.hinted).toBe(false)
    expect(byEmail.get('tl@oimlsmart.org')?.current).toBe(true)
  })

  it('a hint nothing matches still echoes (the page carries it to the fresh sign-in prefill)', async () => {
    const cookie = await login()
    const res = await app.request('/api/op/choose-account?login_hint=stranger%40example.invalid', { headers: { cookie } })
    expect(res.ok).toBe(true)
    const body = await res.json() as { loginHint: string | null; accounts: Array<{ hinted: boolean }> }
    expect(body.loginHint).toBe('stranger@example.invalid')
    expect(body.accounts.every(a => !a.hinted)).toBe(true)
  })

  it('the absent hint reads null (the chooser stands unpreselected)', async () => {
    const cookie = await login()
    const res = await app.request('/api/op/choose-account', { headers: { cookie } })
    const body = await res.json() as { loginHint: string | null; accounts: Array<{ hinted: boolean }> }
    expect(body.loginHint).toBeNull()
    expect(body.accounts.every(a => !a.hinted)).toBe(true)
  })
})

describe('the multi-account chooser surface', () => {
  it('two signed-in accounts list with the presenting one badged (both live)', async () => {
    const browser = cookieJar()
    await loginInto(browser, 'ia@oimlsmart.org')
    await loginInto(browser, 'tl@oimlsmart.org')
    const res = await app.request('/api/op/choose-account', { headers: { cookie: browser.header() } })
    const body = await res.json() as { accounts: Array<{ email: string; userId: string; avatarUrl: string | null; live: boolean; current: boolean }> }
    expect(body.accounts.map(a => a.email).sort()).toEqual(['ia@oimlsmart.org', 'tl@oimlsmart.org'])
    expect(body.accounts.every(a => a.live)).toBe(true)
    expect(body.accounts.find(a => a.email === 'tl@oimlsmart.org')?.current).toBe(true)
    expect(body.accounts.find(a => a.email === 'ia@oimlsmart.org')?.current).toBe(false)
    // THE PHOTO (2026-09-23's report: the chooser showed no profile
    // photos): every jar entry carries its avatar URL — the PUBLIC
    // avatar route (/op/avatar/<id>) which serves the stored photo or
    // the generated-initials SVG, live or not (the route is public by
    // design; the id is already on the page).
    for (const account of body.accounts) {
      expect(account.avatarUrl, `the avatar for ${account.email}`).toBe(`/op/avatar/${account.userId}`)
    }
  })

  it('a DEAD jar entry still carries its avatar URL (the trust posture hides the name/email half, never the public photo)', async () => {
    const browser = cookieJar()
    await loginInto(browser, 'ia@oimlsmart.org')
    await loginInto(browser, 'tl@oimlsmart.org')
    // Kill ONE account's live session (the logout-testing shape): the
    // dead entry renders from the jar — but the photo stays public.
    const dead = (await (await app.request('/api/op/choose-account', { headers: { cookie: browser.header() } })).json() as { accounts: Array<{ email: string; userId: string }> }).accounts.find(a => a.email === 'ia@oimlsmart.org')!
    const { default: Database } = await import('better-sqlite3')
    const raw = new Database(process.env.DATABASE_PATH!)
    raw.prepare('DELETE FROM sessions WHERE user_id = ?').run(dead.userId)
    raw.close()
    const res = await app.request('/api/op/choose-account', { headers: { cookie: browser.header() } })
    const body = await res.json() as { accounts: Array<{ email: string; live: boolean; avatarUrl: string | null }> }
    const entry = body.accounts.find(a => a.email === 'ia@oimlsmart.org')!
    expect(entry.live).toBe(false)
    expect(entry.avatarUrl, 'the dead entry keeps its public avatar URL').toBe(`/op/avatar/${dead.userId}`)
  })
})

describe('the switch preserves the relying-party flow to code issuance', () => {
  function decodeJwt(param: string): Record<string, unknown> {
    return JSON.parse(atob(param.split('.')[1]!.replace(/-/g, '+').replace(/_/g, '/'))) as Record<string, unknown>
  }

  it('the chooser swap hands the flow to the CHOSEN account — its code, its ID token', async () => {
    // ia consents once: the remembered grant belongs to ia.
    const iaBrowser = cookieJar()
    await loginInto(iaBrowser, 'ia@oimlsmart.org')
    const first = await app.request(`${ISSUER}/op/authorize?${authorizeQuery({ scope: 'openid email' })}`, { headers: { cookie: iaBrowser.header() } })
    const authId = new URL(first.headers.get('location')!, ISSUER).searchParams.get('auth')!
    const decided = await app.request(`${ISSUER}/api/op/consent/${authId}/decide`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie: iaBrowser.header() },
      body: JSON.stringify({ decision: 'allow' }),
    })
    expect(decided.ok).toBe(true)
    iaBrowser.absorb(decided)

    // tl signs in on the SAME browser afterwards: the presenting
    // session is tl's, the jar remembers both.
    const tlBrowser = iaBrowser
    await loginInto(tlBrowser, 'tl@oimlsmart.org')

    // The RP asks for the chooser (prompt=select_account).
    const pkce = await generatePkce()
    const query = authorizeQuery({ scope: 'openid email', prompt: 'select_account', code_challenge: pkce.challenge })
    const ask = await app.request(`${ISSUER}/op/authorize?${query}`, { headers: { cookie: tlBrowser.header() } })
    expect(ask.status).toBe(302)
    const chooserUrl = new URL(ask.headers.get('location')!, ISSUER)
    expect(chooserUrl.pathname).toBe('/op/choose-account')
    const continueTarget = chooserUrl.searchParams.get('continue')!

    // The holder picks ia — the PRESENTING session was tl's. The swap
    // answers the navigation target and re-issues the session cookie.
    const pick = await app.request('/api/op/choose-account', {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: tlBrowser.header() },
      body: JSON.stringify({ userId: (await store.findUserByEmail('ia@oimlsmart.org'))!.id, continue: continueTarget }),
    })
    expect(pick.status).toBe(200)
    const answer = await pick.json() as { ok: boolean; redirect?: string }
    expect(answer.ok).toBe(true)
    expect(answer.redirect).toBe(continueTarget)
    tlBrowser.absorb(pick)

    // The authorize re-entry runs as ia now: the remembered grant skips
    // the consent page and the code mints for THE CHOSEN account.
    const resume = await app.request(continueTarget, { headers: { cookie: tlBrowser.header() } })
    expect(resume.status).toBe(302)
    const back = new URL(resume.headers.get('location')!, ISSUER)
    expect(back.origin + back.pathname).toBe(RP.redirect_uris[0]!)
    const code = back.searchParams.get('code')
    expect(code).toBeTruthy()

    // The exchange: the ID token names the chosen account, never the
    // presenting one.
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
    const claims = decodeJwt(grants.id_token)
    expect(claims.email).toBe('ia@oimlsmart.org')
    const iaUser = await store.findUserByEmail('ia@oimlsmart.org')
    expect(claims.sub).toBe(iaUser!.id)
  })

  it('the same flow WITHOUT the chooser shows the consent page (the chooser is the explicit ask)', async () => {
    const browser = cookieJar()
    await loginInto(browser, 'tl@oimlsmart.org')
    const res = await app.request(`${ISSUER}/op/authorize?${authorizeQuery({ scope: 'openid email', code_challenge: 'f'.repeat(43) })}`, { headers: { cookie: browser.header() } })
    expect(res.status).toBe(302)
    const back = new URL(res.headers.get('location')!, ISSUER)
    // No remembered grant for tl: the consent page shows — never the
    // chooser, and never a code without the holder's decision.
    expect(back.pathname).toBe('/op/consent')
  })
})
