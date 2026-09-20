// ─────────────────────────────────────────────────────────────────────
// The account chooser wave — multi-account awareness + prompt=
// select_account, proven in-process: the REAL op + auth-lean routers
// over a REAL temp SQLite store, a REAL node:http backchannel receiver
// (the sign-out-of-all fan-out), the OP's own mint validated against
// its served JWKS. NO stub on the OP side.
//
// Covered:
//   THE JAR SEAM      — the pure halves: the UTF-8-safe cookie codec
//                       (round trip, the corrupt-cookie tolerance), the
//                       LRU add (one entry per account, the capacity
//                       eviction from the tail), the session removal,
//                       the continue-target sanitizer (a protocol-
//                       relative or absolute URL never smuggles the
//                       navigation off-host);
//   THE JAR LIFECYCLE — every demo sign-in remembers the account (the
//     (integration)     `oiml-accounts` cookie rides the sign-in
//                       response), six accounts evict the first (the
//                       capacity), a re-sign-in refreshes to the front
//                       without duplicating;
//   THE CHOOSER       — GET /api/op/choose-account: the jar re-judged
//     CONTEXT          against the live rows (live entries re-project
//                       the store's display truth, dead entries keep
//                       the remembered fields), the presenting account
//                       badged, the org names resolved, the RP's name
//                       from the continue target, the standalone
//                       posture (no/invalid continue) honest;
//   prompt=           — the authorize ALWAYS routes the chooser (a live
//   select_account      session never shortcuts it), the continue sheds
//                       the consumed value (the loop guard) and keeps
//                       the rest (login, consent ride on), an unknown
//                       prompt value keeps today's behavior, prompt=
//                       login + select_account routes the chooser with
//                       the login value carried;
//   THE SWITCH        — POST /api/op/choose-account: the live choice
//     (round trip)      swaps the active session cookie, the authorize
//                       re-entry resumes the ORIGINAL request and mints
//                       for the CHOSEN subject (the ID token's sub),
//                       the other account's session stays alive;
//   THE DEAD FALLBACK — a chosen entry whose session row died answers
//                       the login URL with the flow's re-entry and the
//                       remembered email prefilled;
//   SIGN OUT OF ALL   — POST /api/auth/signout-all: every remembered
//                       session dies, one backchannel logout_token per
//                       DISTINCT account (signature verified), both
//                       cookies clear;
//   THE SESSION       — the end-session drops the ended account's jar
//     ENDINGS          entry and keeps the others.
// ─────────────────────────────────────────────────────────────────────

import { createServer, type Server } from 'node:http'
import type { AddressInfo } from 'node:net'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

// The store's DB path is read at module evaluation — set it before any
// import below touches the sqlite store (the imports are dynamic).
const TMP = mkdtempSync(join(tmpdir(), 'oiml-op-chooser-'))
process.env.DATABASE_PATH = join(TMP, 'test.db')

const ISSUER = 'http://op.test'
process.env.OP_ISSUER = ISSUER

// The registry's bootstrap seed: one confidential application client,
// carrying the full logout block (the receiver's URI lands in beforeAll
// — the port binds there).
const HUB_ID = 'hub-instance'
const HUB_SECRET = 'hub-secret-123'
const HUB_REDIRECT = 'https://hub.example/api/auth/callback/oidc'
const ORG_ID = 'mfr-acme'
const ORG_NAME = 'ACME (the demonstration manufacturer)'

let app: import('hono').Hono
let store: ReturnType<typeof import('../../server/store').getStore>
let receiver: Server
let receiverUrl: string
/** The backchannel receiver's captured POSTs (the raw form bodies). */
const received: Array<{ body: string }> = []
let generatePkce: typeof import('../../server/oidc').generatePkce
let resetProfile: () => void

/** All set-cookie values of a response (the sign-in answers carry TWO —
 *  the active session and the account jar). */
function setCookies(res: Response): string[] {
  const list = (res.headers as Headers & { getSetCookie?: () => string[] }).getSetCookie
  if (typeof list === 'function') return list.call(res.headers)
  const single = res.headers.get('set-cookie')
  return single ? [single] : []
}

/** The sign-in as the browser issues it: the request presents whatever
 *  the browser already holds (the `browser` cookie line), the answer's
 *  set-cookie values replace it (the active session + the refreshed
 *  jar). */
async function demoSignIn(email: string, browser = ''): Promise<string> {
  const res = await app.request('/api/auth/demo', {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...(browser ? { cookie: browser } : {}) },
    body: JSON.stringify({ email, password: 'demo2026' }),
  })
  expect(res.ok, `demo login ${email}`).toBe(true)
  return setCookies(res).map(c => c.split(';')[0]).join('; ')
}

/** The account jar decoded out of a response's set-cookie values (the
 *  cookie is httpOnly, but the test reads the wire). */
function jarOf(res: Response): Array<{ sessionId: string; userId: string; email: string; displayName: string; orgId: string | null }> {
  const raw = setCookies(res).find(c => c.startsWith('oiml-accounts='))
  expect(raw, 'the response carries the account jar').toBeTruthy()
  const value = raw!.split(';')[0]!.slice('oiml-accounts='.length)
  const b64 = value.replace(/-/g, '+').replace(/_/g, '/')
  const json = new TextDecoder().decode(Uint8Array.from(atob(b64), ch => ch.charCodeAt(0)))
  return JSON.parse(json)
}

/** Authorize → the consent decision's allow → the one-time code (the
 *  remembered-grant driver — the grant lets the later authorize skip
 *  the page). */
async function driveGrant(
  cookie: string,
  params: { clientId?: string; redirectUri?: string; challenge: string },
): Promise<void> {
  const query = new URLSearchParams({
    response_type: 'code',
    client_id: params.clientId ?? HUB_ID,
    redirect_uri: params.redirectUri ?? HUB_REDIRECT,
    scope: 'openid profile email',
    state: 'st-1',
    nonce: 'nn-1',
    code_challenge: params.challenge,
    code_challenge_method: 'S256',
    prompt: 'consent',
  })
  const authorize = await app.request(`${ISSUER}/op/authorize?${query}`, { headers: { cookie } })
  expect(authorize.status, 'authorize redirects to the consent page').toBe(302)
  const consentUrl = new URL(authorize.headers.get('location')!, ISSUER)
  expect(consentUrl.pathname).toBe('/op/consent')
  const decide = await app.request(`${ISSUER}/api/op/consent/${consentUrl.searchParams.get('auth')}/decide`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', cookie },
    body: JSON.stringify({ decision: 'allow' }),
  })
  expect(decide.status, 'the allow decision records').toBe(200)
}

/** The code exchange (the confidential client's client_secret_basic). */
async function exchange(params: { code: string; redirectUri?: string; clientId?: string; verifier: string; secret?: string }) {
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code: params.code,
    redirect_uri: params.redirectUri ?? HUB_REDIRECT,
    client_id: params.clientId ?? HUB_ID,
    code_verifier: params.verifier,
  })
  return app.request(`${ISSUER}/op/token`, {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      authorization: `Basic ${btoa(`${encodeURIComponent(params.clientId ?? HUB_ID)}:${encodeURIComponent(params.secret ?? HUB_SECRET)}`)}`,
    },
    body,
  })
}

/** The JWT payload, decoded (never verified here — verification is the
 *  legs' explicit act). */
function decodePayload(token: string): Record<string, unknown> {
  const part = token.split('.')[1]!
  const b64 = part.replace(/-/g, '+').replace(/_/g, '/')
  return JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(b64), ch => ch.charCodeAt(0)))) as Record<string, unknown>
}

/** Poll the receiver until a captured POST count matches (the fan-out
 *  floats — the act's answer never waits on an RP, so the test does). */
async function awaitReceived(count: number, timeoutMs = 5_000): Promise<void> {
  const deadline = Date.now() + timeoutMs
  while (received.length < count && Date.now() < deadline) {
    await new Promise(r => setTimeout(r, 25))
  }
  expect(received.length, `the backchannel receiver saw ${count} POST(s)`).toBe(count)
}

beforeAll(async () => {
  // The backchannel receiver: a REAL node:http server on an ephemeral
  // port, capturing the form POSTs.
  receiver = createServer((req, res) => {
    if (req.method !== 'POST') { res.writeHead(404).end(); return }
    let body = ''
    req.on('data', chunk => { body += chunk })
    req.on('end', () => {
      received.push({ body })
      res.writeHead(200, { 'content-type': 'text/plain' }).end('ok')
    })
  })
  await new Promise<void>((resolveListen) => receiver.listen(0, '127.0.0.1', resolveListen))
  receiverUrl = `http://127.0.0.1:${(receiver.address() as AddressInfo).port}`

  process.env.OP_CLIENT_SEED = JSON.stringify([
    {
      client_id: HUB_ID,
      name: 'OIML SMART platform hub',
      secret: HUB_SECRET,
      redirect_uris: [HUB_REDIRECT],
      claims_policy: { claims: ['roles', 'groups', 'org'] },
      logout: {
        post_logout_redirect_uris: ['https://hub.example/signed-out'],
        backchannel_logout_uri: `${receiverUrl}/backchannel-logout`,
      },
    },
  ])

  // The simulated deployment declares its signing key (identity#7's
  // registration gate).
  const { generateSuccessorPair } = await import('../../scripts/op-key-rotate')
  process.env.OP_SIGNING_KEY = (await generateSuccessorPair()).privateJwkJson

  const { installSqliteStore } = await import('../../server/store/sqlite')
  store = installSqliteStore()
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
  resetProfile = profileMod.resetInstanceProfileForTest

  // The org the applicant account belongs to (the chooser's org display
  // resolves its registry name).
  await store.createOrgRegistryOrg({
    id: ORG_ID,
    name: ORG_NAME,
    shortName: 'ACME',
    kind: 'manufacturer',
    country: 'Example Member State',
    contacts: [],
    participantRef: null,
    createdBy: 'the test seed',
  })

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

  // The bootstrap seed lands on the first REGISTRY request; drive it
  // once, honestly.
  const admin = await demoSignIn('admin@oiml.org')
  expect((await app.request(`${ISSUER}/api/op/clients`, { headers: { cookie: admin } })).status).toBe(200)
})

afterAll(async () => {
  resetProfile()
  await new Promise<void>(r => receiver.close(() => r()))
  rmSync(TMP, { recursive: true, force: true })
  delete process.env.OP_ISSUER
  delete process.env.OP_SIGNING_KEY
  delete process.env.OP_CLIENT_SEED
  delete process.env.DATABASE_PATH
})

describe('the jar seam’s pure halves', () => {
  it('the cookie codec round-trips any script a display name carries; garbage reads as no jar', async () => {
    const { encodeJar, decodeJar } = await import('../../server/auth/op/account-jar')
    const entries = [
      { sessionId: 'tok-1', userId: 'u-1', email: 'one@example.org', displayName: 'Ms. Petra Horvat', orgId: '21' },
      { sessionId: 'tok-2', userId: 'u-2', email: 'deux@example.org', displayName: 'Élodie Brûlé', orgId: null },
      { sessionId: 'tok-3', userId: 'u-3', email: 'san@example.org', displayName: '山田 太郎', orgId: null },
    ]
    expect(decodeJar(encodeJar(entries as never))).toEqual(entries)
    expect(decodeJar(undefined)).toEqual([])
    expect(decodeJar('')).toEqual([])
    expect(decodeJar('not base64!!')).toEqual([])
    expect(decodeJar(btoa('not json'))).toEqual([])
    expect(decodeJar(btoa('"a string"'))).toEqual([])
    // Entries without their spine (session id or user id) drop; the
    // oversized fields cap.
    expect(decodeJar(btoa(JSON.stringify([{ sessionId: 't', userId: 'u', displayName: 'x'.repeat(500) }]))))
      .toEqual([{ sessionId: 't', userId: 'u', email: '', displayName: 'x'.repeat(128), orgId: null }])
  })

  it('the LRU add: one entry per account, the fresh first, the capacity evicts from the tail', async () => {
    const { addJarEntry } = await import('../../server/auth/op/account-jar')
    const e = (sessionId: string, userId: string): import('../../server/auth/op/account-jar').AccountJarEntry =>
      ({ sessionId, userId, email: `${userId}@x`, displayName: userId, orgId: null })
    let jar = [e('t1', 'u1')]
    // A fresh session for a KNOWN account replaces its entry (one per
    // account), and a stale entry naming the same token goes too.
    jar = addJarEntry(jar, e('t2', 'u1'))
    expect(jar.map(x => x.sessionId)).toEqual(['t2'])
    jar = addJarEntry(jar, e('t3', 'u2'))
    jar = addJarEntry(jar, e('t4', 'u3'))
    expect(jar.map(x => x.userId)).toEqual(['u3', 'u2', 'u1']) // fresh first, prior order kept
    // The capacity: five stay, the tail goes.
    jar = addJarEntry(jar, e('t5', 'u4'))
    jar = addJarEntry(jar, e('t6', 'u5'))
    expect(jar.map(x => x.userId)).toEqual(['u5', 'u4', 'u3', 'u2', 'u1'])
    jar = addJarEntry(jar, e('t7', 'u6'))
    expect(jar.map(x => x.userId)).toEqual(['u6', 'u5', 'u4', 'u3', 'u2'])
    expect(jar).toHaveLength(5)
  })

  it('the continue-target sanitizer: relative paths stand, cross-origin shapes fall back to null', async () => {
    const { sanitizeContinueTarget, loginUrlForContinue } = await import('../../server/auth/op/account-jar')
    const good = '/op/authorize?response_type=code&client_id=hub'
    expect(sanitizeContinueTarget(good)).toBe(good)
    expect(sanitizeContinueTarget(`${good}&state=a%20b`)).toBe(`${good}&state=a%20b`)
    expect(sanitizeContinueTarget(undefined)).toBeNull()
    expect(sanitizeContinueTarget('')).toBeNull()
    expect(sanitizeContinueTarget('//evil.example/path')).toBeNull()
    expect(sanitizeContinueTarget('https://evil.example/path')).toBeNull()
    expect(sanitizeContinueTarget('/\\evil.example')).toBeNull()
    expect(sanitizeContinueTarget(`/${'x'.repeat(3000)}`)).toBeNull()
    // The login fallback: the re-entry in its redirect seat, the
    // remembered email prefilled when known.
    expect(loginUrlForContinue(good, 'a@b.c')).toBe(`/?redirect=${encodeURIComponent(good)}&email=a%40b.c`)
    expect(loginUrlForContinue(null)).toBe(`/?redirect=${encodeURIComponent('/op/account')}`)
    expect(loginUrlForContinue(good)).toBe(`/?redirect=${encodeURIComponent(good)}`)
  })
})

describe('the jar lifecycle through the real sign-in', () => {
  it('every sign-in remembers the account; six accounts evict the first; a re-sign-in refreshes to the front', async () => {
    const emails = ['ia@oiml.org', 'tl@oiml.org', 'viewer@oiml.org', 'biml@oiml.org', 'mc@oiml.org', 'cs@oiml.org']
    let jar: Array<{ userId: string; email: string }> = []
    let browser = ''
    for (const email of emails) {
      browser = await demoSignIn(email, browser)
      const res = await app.request('/api/auth/demo', {
        method: 'POST',
        headers: { 'content-type': 'application/json', cookie: browser },
        body: JSON.stringify({ email, password: 'demo2026' }),
      })
      expect(res.ok).toBe(true)
      jar = jarOf(res)
    }
    // The capacity held: the first account (ia) evicted, the rest in
    // most-recent-first order, each entry projecting its account.
    expect(jar.map(e => e.email)).toEqual(['cs@oiml.org', 'mc@oiml.org', 'biml@oiml.org', 'viewer@oiml.org', 'tl@oiml.org'])
    // The jar's display truth is the sign-in moment's projection.
    expect(jar[0]).toMatchObject({ sessionId: expect.any(String), userId: expect.any(String), displayName: 'CS Administrator', orgId: null })

    // A re-sign-in of a remembered account: to the front, no duplicate.
    browser = await demoSignIn('tl@oiml.org', browser)
    const again = await app.request('/api/auth/demo', {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: browser },
      body: JSON.stringify({ email: 'tl@oiml.org', password: 'demo2026' }),
    })
    expect(again.ok).toBe(true)
    const refreshed = jarOf(again)
    expect(refreshed.map(e => e.email)).toEqual(['tl@oiml.org', 'cs@oiml.org', 'mc@oiml.org', 'biml@oiml.org', 'viewer@oiml.org'])
  })

  it('the jar entries carry the account’s org (the chooser’s display resolves its registry name later)', async () => {
    const res = await app.request('/api/auth/demo', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: 'applicant@oiml.org', password: 'demo2026' }),
    })
    expect(res.ok).toBe(true)
    const jar = jarOf(res)
    expect(jar[0]).toMatchObject({ email: 'applicant@oiml.org', orgId: ORG_ID })
  })
})

describe('the chooser context (GET /api/op/choose-account)', () => {
  it('the jar re-judged against the live rows: the presenting account badged, the org named, the RP resolved', async () => {
    // The applicant signs in first (org display), then the viewer (the
    // presenting account) — the second sign-in presents the browser's
    // accumulated cookies, exactly as a real browser would.
    const applicant = await demoSignIn('applicant@oiml.org')
    const viewer = await demoSignIn('viewer@oiml.org', applicant)
    const continueTarget = `/op/authorize?response_type=code&client_id=${HUB_ID}&redirect_uri=${encodeURIComponent(HUB_REDIRECT)}`
    const res = await app.request(`${ISSUER}/api/op/choose-account?continue=${encodeURIComponent(continueTarget)}`, {
      headers: { cookie: viewer },
    })
    expect(res.status).toBe(200)
    const body = await res.json() as {
      continue: string | null
      client: { name: string } | null
      currentUserId: string | null
      accounts: Array<{ userId: string; name: string; email: string; org: string | null; live: boolean; current: boolean }>
    }
    expect(body.continue).toBe(continueTarget)
    expect(body.client).toEqual({ name: 'OIML SMART platform hub' })
    expect(body.accounts.map(a => a.email)).toEqual(['viewer@oiml.org', 'applicant@oiml.org'])
    expect(body.accounts[0]).toMatchObject({ name: 'Viewer', live: true, current: true, org: null })
    expect(body.accounts[1]).toMatchObject({ name: 'ACME Applicant', live: true, current: false, org: ORG_NAME })
    expect(body.accounts.every(a => a.userId && a.userId.length > 0)).toBe(true)
  })

  it('a dead entry keeps the remembered display fields and answers live:false; the standalone posture carries no continue', async () => {
    // A fresh sign-in captures a jar entry, and its session row dies
    // behind the jar's back.
    const jarRes = await app.request('/api/auth/demo', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: 'ia@oiml.org', password: 'demo2026' }),
    })
    const jar = jarOf(jarRes)
    await store.deleteSession(jar[0].sessionId)
    const res = await app.request(ISSUER + '/api/op/choose-account', { headers: { cookie: `oiml-accounts=${jarCookieOf(jar)}` } })
    expect(res.status).toBe(200)
    const body = await res.json() as { continue: string | null; accounts: Array<{ email: string; live: boolean; name: string }> }
    expect(body.continue).toBeNull()
    expect(body.accounts).toHaveLength(1)
    expect(body.accounts[0]).toMatchObject({ email: 'ia@oiml.org', live: false, name: 'IA Officer' })
  })

  it('a corrupt continue target reads as the standalone posture', async () => {
    const cookie = await demoSignIn('viewer@oiml.org')
    const res = await app.request(`${ISSUER}/api/op/choose-account?continue=${encodeURIComponent('//evil.example/x')}`, {
      headers: { cookie },
    })
    expect(res.status).toBe(200)
    expect(((await res.json()) as { continue: string | null }).continue).toBeNull()
  })
})

/** The jar line (oiml-accounts=…) rebuilt from a decoded jar (the dead-
 *  fallback leg presents ONLY the jar — no live session cookie). */
function jarCookieOf(jar: Array<{ sessionId: string }>): string {
  const json = JSON.stringify(jar)
  const bytes = new TextEncoder().encode(json)
  let binary = ''
  for (const b of bytes) binary += String.fromCharCode(b)
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

describe('prompt=select_account on /op/authorize', () => {
  it('a live session NEVER shortcuts the chooser; the continue sheds the consumed value and keeps the rest', async () => {
    const cookie = await demoSignIn('viewer@oiml.org')
    const pkce = await generatePkce()
    const query = new URLSearchParams({
      response_type: 'code',
      client_id: HUB_ID,
      redirect_uri: HUB_REDIRECT,
      scope: 'openid profile email',
      state: 'st-sel',
      nonce: 'nn-sel',
      code_challenge: pkce.challenge,
      code_challenge_method: 'S256',
      prompt: 'select_account',
    })
    const res = await app.request(`${ISSUER}/op/authorize?${query}`, { headers: { cookie } })
    expect(res.status).toBe(302)
    const chooser = new URL(res.headers.get('location')!, ISSUER)
    expect(chooser.pathname).toBe('/op/choose-account')
    const target = chooser.searchParams.get('continue')!
    expect(target.startsWith('/op/authorize?')).toBe(true)
    const reentry = new URL(target, ISSUER)
    // The consumed value is gone; the request's own parameters stand.
    expect(reentry.searchParams.get('prompt')).toBeNull()
    expect(reentry.searchParams.get('client_id')).toBe(HUB_ID)
    expect(reentry.searchParams.get('redirect_uri')).toBe(HUB_REDIRECT)
    expect(reentry.searchParams.get('code_challenge')).toBe(pkce.challenge)
    expect(reentry.searchParams.get('state')).toBe('st-sel')
  })

  it('no session, no jar: the chooser still stands (the fresh-sign-in entry)', async () => {
    const pkce = await generatePkce()
    const query = new URLSearchParams({
      response_type: 'code', client_id: HUB_ID, redirect_uri: HUB_REDIRECT,
      scope: 'openid profile email', state: 's', nonce: 'n',
      code_challenge: pkce.challenge, code_challenge_method: 'S256',
      prompt: 'select_account',
    })
    const res = await app.request(`${ISSUER}/op/authorize?${query}`)
    expect(res.status).toBe(302)
    expect(new URL(res.headers.get('location')!, ISSUER).pathname).toBe('/op/choose-account')
    // The chooser context: zero accounts, the standalone entries only.
    const target = new URL(res.headers.get('location')!, ISSUER).searchParams.get('continue')!
    const ctx = await app.request(`${ISSUER}/api/op/choose-account?continue=${encodeURIComponent(target)}`)
    const body = await ctx.json() as { accounts: unknown[]; client: { name: string } | null }
    expect(body.accounts).toEqual([])
    expect(body.client).toEqual({ name: 'OIML SMART platform hub' })
  })

  it('login + select_account: the chooser carries the login value on (the forced re-auth re-applies on re-entry)', async () => {
    const cookie = await demoSignIn('viewer@oiml.org')
    const pkce = await generatePkce()
    const query = new URLSearchParams({
      response_type: 'code', client_id: HUB_ID, redirect_uri: HUB_REDIRECT,
      scope: 'openid profile email', state: 's', nonce: 'n',
      code_challenge: pkce.challenge, code_challenge_method: 'S256',
      prompt: 'login select_account',
    })
    const res = await app.request(`${ISSUER}/op/authorize?${query}`, { headers: { cookie } })
    expect(res.status).toBe(302)
    const reentry = new URL(new URL(res.headers.get('location')!, ISSUER).searchParams.get('continue')!, ISSUER)
    expect(reentry.searchParams.get('prompt')).toBe('login')
  })

  it('unknown prompt values keep today’s behavior (ignored, the request proceeds)', async () => {
    // The viewer holds a remembered grant from the round-trip leg? No —
    // this leg grants its own, then re-enters with an unknown value.
    const cookie = await demoSignIn('mc@oiml.org')
    let pkce = await generatePkce()
    await driveGrant(cookie, { challenge: pkce.challenge })
    pkce = await generatePkce()
    const query = new URLSearchParams({
      response_type: 'code', client_id: HUB_ID, redirect_uri: HUB_REDIRECT,
      scope: 'openid profile email', state: 'st-unk', nonce: 'nn-unk',
      code_challenge: pkce.challenge, code_challenge_method: 'S256',
      prompt: 'unicorn',
    })
    const res = await app.request(`${ISSUER}/op/authorize?${query}`, { headers: { cookie } })
    expect(res.status).toBe(302)
    const back = new URL(res.headers.get('location')!)
    expect(back.origin + back.pathname).toBe(HUB_REDIRECT)
    expect(back.searchParams.get('code')).toBeTruthy()
  })

  it('prompt=consent keeps forcing the consent page (the semantics unchanged)', async () => {
    const cookie = await demoSignIn('cs@oiml.org')
    const pkce = await generatePkce()
    const query = new URLSearchParams({
      response_type: 'code', client_id: HUB_ID, redirect_uri: HUB_REDIRECT,
      scope: 'openid profile email', state: 's', nonce: 'n',
      code_challenge: pkce.challenge, code_challenge_method: 'S256',
      prompt: 'consent',
    })
    const res = await app.request(`${ISSUER}/op/authorize?${query}`, { headers: { cookie } })
    expect(res.status).toBe(302)
    expect(new URL(res.headers.get('location')!, ISSUER).pathname).toBe('/op/consent')
  })
})

describe('the switch (POST /api/op/choose-account) — the round trip', () => {
  it('two remembered accounts: the choice swaps the active session and the authorize resumes for the CHOSEN subject', async () => {
    // The ia account grants the hub first (the remembered grant the
    // resumed authorize will mint through).
    const ia = await demoSignIn('ia@oiml.org')
    let pkce = await generatePkce()
    await driveGrant(ia, { challenge: pkce.challenge })
    const iaId = (await (await app.request(`${ISSUER}/api/auth/session`, { headers: { cookie: ia } })).json() as { id: string }).id
    // The tl account signs in second (the presenting account), the
    // browser carrying the ia cookies.
    const tl = await demoSignIn('tl@oiml.org', ia)
    const tlId = (await (await app.request(`${ISSUER}/api/auth/session`, { headers: { cookie: tl } })).json() as { id: string }).id
    expect(tlId).not.toBe(iaId)

    // The RP's authorize with prompt=select_account (the tl session).
    pkce = await generatePkce()
    const authorizeQuery = new URLSearchParams({
      response_type: 'code', client_id: HUB_ID, redirect_uri: HUB_REDIRECT,
      scope: 'openid profile email', state: 'st-switch', nonce: 'nn-switch',
      code_challenge: pkce.challenge, code_challenge_method: 'S256',
      prompt: 'select_account',
    })
    const authorize = await app.request(`${ISSUER}/op/authorize?${authorizeQuery}`, { headers: { cookie: tl } })
    const continueTarget = new URL(authorize.headers.get('location')!, ISSUER).searchParams.get('continue')!

    // The context: both accounts live, tl current, ia not.
    const ctx = await app.request(`${ISSUER}/api/op/choose-account?continue=${encodeURIComponent(continueTarget)}`, { headers: { cookie: tl } })
    const context = await ctx.json() as { accounts: Array<{ userId: string; email: string; current: boolean; live: boolean }> }
    expect(context.accounts.map(a => [a.email, a.current, a.live])).toEqual([
      ['tl@oiml.org', true, true],
      ['ia@oiml.org', false, true],
    ])

    // The choice: continue as the IA account.
    const iaUserId = context.accounts.find(a => a.email === 'ia@oiml.org')!.userId
    const select = await app.request(`${ISSUER}/api/op/choose-account`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: tl },
      body: JSON.stringify({ userId: iaUserId, continue: continueTarget }),
    })
    expect(select.status).toBe(200)
    const answer = await select.json() as { ok: boolean; redirect: string }
    expect(answer.ok).toBe(true)
    expect(answer.redirect).toBe(continueTarget)
    // The swap: the answer's set-cookie names the IA session.
    const swapped = setCookies(select).find(c => c.startsWith('oiml-session='))!.split(';')[0]
    const me = await (await app.request(`${ISSUER}/api/auth/session`, { headers: { cookie: swapped } })).json() as { id: string; email: string }
    expect(me.id).toBe(iaId)
    expect(me.email).toBe('ia@oiml.org')
    // The OTHER account's session row stays alive (switching never
    // signs the other account out).
    expect((await app.request(`${ISSUER}/api/auth/session`, { headers: { cookie: tl } })).status).toBe(200)

    // The resumed authorize (the continue target) mints DIRECTLY for
    // the chosen subject — the remembered grant skips the consent page.
    const resumed = await app.request(`${ISSUER}${continueTarget}`, { headers: { cookie: swapped } })
    expect(resumed.status).toBe(302)
    const back = new URL(resumed.headers.get('location')!)
    expect(back.origin + back.pathname).toBe(HUB_REDIRECT)
    expect(back.searchParams.get('state')).toBe('st-switch')
    const token = await exchange({ code: back.searchParams.get('code')!, verifier: pkce.verifier })
    expect(token.status).toBe(200)
    const claims = decodePayload((await token.json() as { id_token: string }).id_token)
    expect(claims.sub).toBe(iaId)
  })

  it('an unknown userId answers the honest fallback without an email; a cross-origin continue falls back to the console', async () => {
    const cookie = await demoSignIn('viewer@oiml.org')
    const select = await app.request(`${ISSUER}/api/op/choose-account`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ userId: 'nobody', continue: 'https://evil.example/x' }),
    })
    expect(select.status).toBe(200)
    const answer = await select.json() as { ok: boolean; login: string }
    expect(answer.ok).toBe(false)
    expect(answer.login.startsWith('/?redirect=%2Fop%2Faccount')).toBe(true)
    expect(answer.login).not.toContain('email=')
  })
})

describe('the dead-session fallback', () => {
  it('a chosen entry whose session row died: the login URL with the flow’s re-entry and the email prefilled', async () => {
    // The tl account signs in, grants, and its session row dies behind
    // the jar's back (the browser kept the cookie; the row is gone).
    const tl = await demoSignIn('tl@oiml.org')
    let pkce = await generatePkce()
    await driveGrant(tl, { challenge: pkce.challenge })
    // A fresh sign-in (the browser presenting its cookies) captures the
    // jar it now holds.
    const second = await app.request('/api/auth/demo', {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: tl },
      body: JSON.stringify({ email: 'tl@oiml.org', password: 'demo2026' }),
    })
    const jar = jarOf(second)
    await store.deleteSession(jar[0].sessionId)
    const jarLine = `oiml-accounts=${jarCookieOf(jar)}`

    // The context marks the entry dead; the remembered fields stand.
    const ctx = await app.request(`${ISSUER}/api/op/choose-account?continue=${encodeURIComponent('/op/account')}`, {
      headers: { cookie: jarLine },
    })
    const context = await ctx.json() as { accounts: Array<{ userId: string; live: boolean; email: string }> }
    expect(context.accounts).toHaveLength(1)
    expect(context.accounts[0].live).toBe(false)
    expect(context.accounts[0].email).toBe('tl@oiml.org')

    // The choice falls back to the login page — the re-entry target in
    // its redirect seat, the remembered email prefilled.
    const select = await app.request(`${ISSUER}/api/op/choose-account`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: jarLine },
      body: JSON.stringify({ userId: context.accounts[0].userId, continue: '/op/authorize?client_id=hub-instance' }),
    })
    expect(select.status).toBe(200)
    const answer = await select.json() as { ok: boolean; login: string }
    expect(answer.ok).toBe(false)
    const login = new URL(answer.login, ISSUER)
    expect(login.pathname).toBe('/')
    expect(login.searchParams.get('redirect')).toBe('/op/authorize?client_id=hub-instance')
    expect(login.searchParams.get('email')).toBe('tl@oiml.org')
  })

  it('a live render-to-click death (the row dies between context and select) falls back the same way', async () => {
    const res = await app.request('/api/auth/demo', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: 'ia@oiml.org', password: 'demo2026' }),
    })
    const cookie = setCookies(res).map(c => c.split(';')[0]).join('; ')
    const jar = jarOf(res)
    const context = await (await app.request(ISSUER + '/api/op/choose-account', { headers: { cookie } })).json() as { accounts: Array<{ userId: string; live: boolean }> }
    expect(context.accounts[0].live).toBe(true)
    // The row dies after the render…
    await store.deleteSession(jar[0].sessionId)
    // …the select still answers honestly.
    const select = await app.request(`${ISSUER}/api/op/choose-account`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ userId: context.accounts[0].userId }),
    })
    expect(((await select.json()) as { ok: boolean }).ok).toBe(false)
  })
})

describe('sign out of all accounts', () => {
  it('every remembered session dies, one backchannel token per distinct account, both cookies clear', async () => {
    const before = received.length
    // Two accounts, each with a live grant (the fan-out's targets); the
    // second sign-in presents the browser's accumulated cookies.
    const ia = await demoSignIn('ia@oiml.org')
    let pkce = await generatePkce()
    await driveGrant(ia, { challenge: pkce.challenge })
    const tl = await demoSignIn('tl@oiml.org', ia)
    pkce = await generatePkce()
    await driveGrant(tl, { challenge: pkce.challenge })
    // The presenting cookie line carries BOTH cookies (the session and
    // the jar — demoLogin joins the sign-in response's set-cookie
    // values), exactly what the browser holds.
    const context = await (await app.request(ISSUER + '/api/op/choose-account', { headers: { cookie: tl } })).json() as { accounts: Array<{ userId: string; live: boolean }> }
    expect(context.accounts.filter(a => a.live).length).toBeGreaterThanOrEqual(2)

    // The act.
    const act = await app.request(`${ISSUER}/api/auth/signout-all`, { method: 'POST', headers: { cookie: tl } })
    expect(act.status).toBe(200)
    const answer = await act.json() as { ok: boolean; ended: number }
    expect(answer.ok).toBe(true)
    expect(answer.ended).toBeGreaterThanOrEqual(2)

    // Both sessions are dead.
    expect((await app.request(`${ISSUER}/api/auth/session`, { headers: { cookie: ia } })).status).toBe(401)
    expect((await app.request(`${ISSUER}/api/auth/session`, { headers: { cookie: tl } })).status).toBe(401)

    // Both cookies clear on the answer.
    const cookies = setCookies(act)
    expect(cookies.find(c => c.startsWith('oiml-accounts=')) ?? '').toMatch(/max-age=0|expires=thu, 01 jan 1970/i)
    expect(cookies.find(c => c.startsWith('oiml-session=')) ?? '').toMatch(/max-age=0|expires=thu, 01 jan 1970/i)

    // The fan-out: one send per DISTINCT account (two), each naming its
    // subject, each verifying against the served JWKS.
    await awaitReceived(before + 2)
    const { keys } = await (await app.request(`${ISSUER}/jwks.json`)).json() as { keys: JsonWebKey[] }
    const { verifyOpIdTokenHint } = await import('../../server/auth/op/logout')
    const subs: string[] = []
    for (const hit of received.slice(before)) {
      const token = new URLSearchParams(hit.body).get('logout_token')!
      const verified = await verifyOpIdTokenHint(keys, ISSUER, token)
      expect(verified).toBeTruthy()
      subs.push(verified!.sub)
    }
    expect(new Set(subs).size).toBe(2)
  })
})

describe('the session endings keep the jar honest', () => {
  it('the end-session drops the ended account’s entry and keeps the others', async () => {
    const ia = await demoSignIn('ia@oiml.org')
    const tl = await demoSignIn('tl@oiml.org', ia)
    // The end-session for the ACTIVE account (tl).
    const res = await app.request(`${ISSUER}/op/endsession`, { headers: { cookie: tl } })
    expect(res.status).toBe(200)
    expect(await res.text()).toContain('data-testid="op-signed-out"')
    // The jar on the answer: tl gone, ia still remembered.
    const jar = jarOf(res)
    expect(jar.map(e => e.email)).toEqual(['ia@oiml.org'])
    // The ia session is untouched.
    expect((await app.request(`${ISSUER}/api/auth/session`, { headers: { cookie: ia } })).status).toBe(200)
  })

  it('the console sign-out drops the active entry too', async () => {
    const res = await app.request('/api/auth/demo', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: 'viewer@oiml.org', password: 'demo2026' }),
    })
    const viewer = setCookies(res).map(c => c.split(';')[0]).join('; ')
    const signout = await app.request(`${ISSUER}/api/auth/signout`, { method: 'POST', headers: { cookie: viewer } })
    expect(signout.status).toBe(200)
    const jarRaw = setCookies(signout).find(c => c.startsWith('oiml-accounts='))
    // The viewer's entry left the jar (the cookie only re-issues when
    // something left — a jar without the viewer names no viewer).
    if (jarRaw) {
      const value = jarRaw.split(';')[0]!.slice('oiml-accounts='.length)
      const json = new TextDecoder().decode(Uint8Array.from(atob(value.replace(/-/g, '+').replace(/_/g, '/')), ch => ch.charCodeAt(0)))
      expect((JSON.parse(json) as Array<{ email: string }>).map(e => e.email)).not.toContain('viewer@oiml.org')
    }
  })
})
