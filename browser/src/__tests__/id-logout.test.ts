// ─────────────────────────────────────────────────────────────────────
// TODO.identity-sso (the wave-A tail) — the OP's LOGOUT cone, proven
// in-process: the REAL op + auth-lean routers over a REAL temp SQLite
// store, a REAL node:http backchannel receiver, and the OP's own mint
// validated against its served JWKS. NO stub on the OP side.
//
// Covered:
//   THE PURE HALVES   — logoutBlockOf's honest derivation, the write-time
//                       validateLogoutBlock refusals, authTimeOf's
//                       space→T+Z UTC fix (the database default's
//                       datetime('now') format parsed as UTC, never
//                       local), the seed parser's logout rules (the
//                       machine classes refuse the block);
//   THE REGISTRY      — the clients API round-trips the logout block
//                       (the seed's and the admin POST's), the wholesale
//                       policy rewrite drops an omitted block, the
//                       machine-class + malformed-URI refusals answer
//                       400;
//   THE END-SESSION   — GET/POST /op/endsession (RP-Initiated Logout
//     (RP-initiated)      1.0): the act ALWAYS lands (the session row +
//                       the cookie die); the redirect fires ONLY to a
//                       registered post_logout_redirect_uri of the
//                       RESOLVED, active client (the hint's aud wins over
//                       the client_id param); every other shape answers
//                       the honest signed-out page (the open-redirector
//                       guard); a garbage hint never blocks the act;
//   prompt=login      — the authorize redirect's shape: the re-entry URL
//                       sheds the 'login' value (the stateless loop
//                       guard), the login page's own prompt flag rides,
//                       the remaining values (consent) survive;
//   auth_time         — the ID token's authentication instant, through
//                       BOTH mint paths (the consent decision's allow AND
//                       the remembered-grant skip), equal to the
//                       session's created_at epoch;
//   THE FAN-OUT       — the OP-initiated backchannel logout: the signout
//     (OP-initiated)    and the end-session both POST a logout_token
//                       (iss/sub/aud/jti/iat/exp + the backchannel-logout
//                       event, NO sid, NO nonce) to each live-grant
//                       client's registered receiver; the token's
//                       signature verifies against the served JWKS; a
//                       disabled client and a client without a receiver
//                       never appear; a failed send never fails the act.
// ─────────────────────────────────────────────────────────────────────

import { createServer, type Server } from 'node:http'
import type { AddressInfo } from 'node:net'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import type { OpLogoutPolicy } from '../../server/auth/op/logout'

// The store's DB path is read at module evaluation — set it before any
// import below touches @oimlsmart/platform-server/store/sqlite (the imports are dynamic).
const TMP = mkdtempSync(join(tmpdir(), 'oiml-op-logout-'))
process.env.DATABASE_PATH = join(TMP, 'test.db')

const ISSUER = 'http://op.test'
process.env.OP_ISSUER = ISSUER

// The registry's bootstrap seed: a confidential application client
// carrying the full logout block (the receiver's URI lands in beforeAll —
// the port binds there), and a plain application client with NO logout
// surface. OP_CLIENT_SEED is set in beforeAll once the receiver's port
// is known (the seed reads the env at the first registry request, never
// at import).
const HUB_ID = 'hub-instance'
const HUB_SECRET = 'hub-secret-123'
const HUB_REDIRECT = 'https://hub.example/api/auth/callback/oidc'
const HUB_POST_LOGOUT = 'https://hub.example/signed-out'
const PLAIN = {
  client_id: 'plain-site',
  name: 'A site with no logout surface',
  redirect_uris: ['https://plain.example/callback'],
}

let app: import('hono').Hono
let store: ReturnType<typeof import('@oimlsmart/platform-server/store').getStore>
let receiver: Server
let receiverUrl: string
/** The backchannel receiver's captured POSTs (the raw form bodies). */
const received: Array<{ contentType: string; body: string }> = []
let generatePkce: typeof import('@oimlsmart/platform-server/oidc').generatePkce
let installIdentityProfile: () => void
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

/** Authorize → the consent decision's allow → the one-time code (the
 *  prompt=consent driver — a remembered grant would skip the page). */
async function driveCode(
  cookie: string,
  params: { clientId: string; redirectUri: string; scope?: string; state?: string; nonce?: string; challenge: string },
): Promise<{ code: string; redirect: string }> {
  const query = new URLSearchParams({
    response_type: 'code',
    client_id: params.clientId,
    redirect_uri: params.redirectUri,
    scope: params.scope ?? 'openid profile email',
    state: params.state ?? 'st-1',
    nonce: params.nonce ?? 'nn-1',
    code_challenge: params.challenge,
    code_challenge_method: 'S256',
    prompt: 'consent',
  })
  const authorize = await app.request(`${ISSUER}/op/authorize?${query}`, { headers: { cookie } })
  expect(authorize.status, 'authorize redirects to the consent page').toBe(302)
  const consentUrl = new URL(authorize.headers.get('location')!, ISSUER)
  expect(consentUrl.pathname).toBe('/op/consent')
  const authId = consentUrl.searchParams.get('auth')!
  const decide = await app.request(`${ISSUER}/api/op/consent/${authId}/decide`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', cookie },
    body: JSON.stringify({ decision: 'allow' }),
  })
  expect(decide.status, 'the allow decision records').toBe(200)
  const { redirect } = await decide.json() as { redirect: string }
  const code = new URL(redirect).searchParams.get('code')
  expect(code, 'the allow carries a code').toBeTruthy()
  return { code: code!, redirect }
}

/** The code exchange (the confidential client's client_secret_basic). */
async function exchange(params: { code: string; redirectUri: string; clientId: string; verifier: string; secret?: string }) {
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code: params.code,
    redirect_uri: params.redirectUri,
    client_id: params.clientId,
    code_verifier: params.verifier,
  })
  const headers: Record<string, string> = { 'content-type': 'application/x-www-form-urlencoded' }
  if (params.secret !== undefined) {
    headers.authorization = `Basic ${btoa(`${encodeURIComponent(params.clientId)}:${encodeURIComponent(params.secret)}`)}`
  }
  return app.request(`${ISSUER}/op/token`, { method: 'POST', headers, body })
}

/** A full sign-in + code + exchange: answers the session cookie and the
 *  raw ID token (the end-session hint's source). */
async function signInAndIdToken(email: string): Promise<{ cookie: string; idToken: string; userId: string }> {
  const cookie = await demoLogin(email)
  const pkce = await generatePkce()
  const { code } = await driveCode(cookie, { clientId: HUB_ID, redirectUri: HUB_REDIRECT, challenge: pkce.challenge })
  const token = await exchange({ code, redirectUri: HUB_REDIRECT, clientId: HUB_ID, verifier: pkce.verifier, secret: HUB_SECRET })
  expect(token.status, 'the code exchange').toBe(200)
  const { id_token } = await token.json() as { id_token: string }
  const session = await (await app.request(`${ISSUER}/api/auth/session`, { headers: { cookie } })).json() as { id: string }
  return { cookie, idToken: id_token, userId: session.id }
}

/** The JWT payload, decoded (never verified here — verification is the
 *  legs' explicit act). */
function decodePayload(token: string): Record<string, unknown> {
  const part = token.split('.')[1]!
  const b64 = part.replace(/-/g, '+').replace(/_/g, '/')
  return JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(b64), ch => ch.charCodeAt(0)))) as Record<string, unknown>
}

/** Poll the receiver until a captured POST matches (the fan-out floats —
 *  the act's answer never waits on an RP, so the test does). */
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
      received.push({ contentType: String(req.headers['content-type'] ?? ''), body })
      res.writeHead(200, { 'content-type': 'text/plain' }).end('ok')
    })
  })
  await new Promise<void>((resolveListen) => receiver.listen(0, '127.0.0.1', resolveListen))
  receiverUrl = `http://127.0.0.1:${(receiver.address() as AddressInfo).port}`

  // The seed now that the receiver's URI is known.
  process.env.OP_CLIENT_SEED = JSON.stringify([
    {
      client_id: HUB_ID,
      name: 'OIML SMART platform hub',
      secret: HUB_SECRET,
      redirect_uris: [HUB_REDIRECT],
      claims_policy: { claims: ['roles', 'groups', 'org'] },
      logout: {
        post_logout_redirect_uris: [HUB_POST_LOGOUT],
        backchannel_logout_uri: `${receiverUrl}/backchannel-logout`,
      },
    },
    PLAIN,
  ])

  // The simulated deployment declares its signing key (identity#7's
  // registration gate: a declared-issuer instance never registers a
  // GENERATED development key into oidc_keys — the id_token_hint
  // validation below reads the registered keyset, exactly the production
  // posture).
  const { generateSuccessorPair } = await import('../../scripts/op-key-rotate')
  process.env.OP_SIGNING_KEY = (await generateSuccessorPair()).privateJwkJson

  const { installSqliteStore } = await import('@oimlsmart/platform-server/store/sqlite')
  store = installSqliteStore()
  const profileMod = await import('@oimlsmart/platform-server/profile')
  installIdentityProfile = () => profileMod.installInstanceProfile(profileMod.parseInstanceProfile(`
identity:
  org_id: oimlsmart-id
  org_name: OIML SMART Identity
  role_codes: [identity]
roles: [identity]
branding: { name: OIML SMART Identity }
demo_personas: true
`))
  resetProfile = profileMod.resetInstanceProfileForTest
  installIdentityProfile()

  const oidc = await import('@oimlsmart/platform-server/oidc')
  generatePkce = oidc.generatePkce
  oidc.clearOidcCaches()

  const { Hono } = await import('hono')
  const { createAuthLeanRouter } = await import('../../server/routes/auth-lean')
  const { createOpRouter } = await import('../../server/routes/op')
  const root = new Hono()
  root.route('/api/auth', createAuthLeanRouter({ autoSeedDemo: true }))
  root.route('/', createOpRouter())
  app = root

  // The bootstrap seed lands on the first REGISTRY request (the discovery
  // document never seeds); drive it once, honestly.
  const admin = await demoLogin('admin@oiml.org')
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

describe('the logout block’s pure halves', () => {
  it('logoutBlockOf derives honestly: a well-formed block stands, anything else reads as NO logout surface', async () => {
    const { logoutBlockOf } = await import('../../server/auth/op/logout')
    // The widened policy shape (the identity-side extension the store
    // seam round-trips opaquely).
    const widened = (p: OpLogoutPolicy) => p
    expect(logoutBlockOf(null)).toBeNull()
    expect(logoutBlockOf({ claims: ['roles'] })).toBeNull()
    expect(logoutBlockOf(widened({
      claims: [],
      logout: { post_logout_redirect_uris: ['https://hub.example/out'], backchannel_logout_uri: 'https://hub.example/bc' },
    }))).toEqual({ post_logout_redirect_uris: ['https://hub.example/out'], backchannel_logout_uri: 'https://hub.example/bc' })
    // The absent backchannel reads as null (the block's honest shape).
    expect(logoutBlockOf(widened({ claims: [], logout: { post_logout_redirect_uris: ['https://hub.example/out'] } })))
      .toEqual({ post_logout_redirect_uris: ['https://hub.example/out'], backchannel_logout_uri: null })
    // The malformed shapes: a non-list redirects, a relative URI in the
    // list, a non-absolute backchannel — ALL read as null (a hand-edited
    // row never becomes a half-shaped allowlist).
    expect(logoutBlockOf({ claims: [], logout: { post_logout_redirect_uris: 'https://hub.example/out' } } as never)).toBeNull()
    expect(logoutBlockOf(widened({ claims: [], logout: { post_logout_redirect_uris: ['/relative'] } }))).toBeNull()
    expect(logoutBlockOf(widened({ claims: [], logout: { post_logout_redirect_uris: [], backchannel_logout_uri: 'not-a-uri' } }))).toBeNull()
    expect(logoutBlockOf(widened({ claims: [], logout: { post_logout_redirect_uris: [], backchannel_logout_uri: 'javascript:alert(1)' } }))).toBeNull()
  })

  it('validateLogoutBlock: the write-time rule — the valid normalizes, the malformed names its refusal', async () => {
    const { validateLogoutBlock } = await import('../../server/auth/op/logout')
    const ok = validateLogoutBlock({
      post_logout_redirect_uris: ['https://hub.example/out ', 'http://localhost:8080/out'],
      backchannel_logout_uri: 'https://hub.example/bc',
    })
    expect(ok.error).toBeNull()
    expect(ok.logout).toEqual({
      post_logout_redirect_uris: ['https://hub.example/out', 'http://localhost:8080/out'],
      backchannel_logout_uri: 'https://hub.example/bc',
    })
    // The all-empty block is VALID (it normalizes to no-write upstream —
    // the tight-write doctrine's input shape).
    const empty = validateLogoutBlock({ post_logout_redirect_uris: [], backchannel_logout_uri: null })
    expect(empty.error).toBeNull()
    expect(empty.logout).toEqual({ post_logout_redirect_uris: [], backchannel_logout_uri: null })
    // The refusals.
    expect(validateLogoutBlock(null).error).toContain('logout must be an object')
    expect(validateLogoutBlock(['https://hub.example/out']).error).toContain('logout must be an object')
    expect(validateLogoutBlock({ post_logout_redirect_uris: 'https://hub.example/out' }).error).toContain('post_logout_redirect_uris')
    expect(validateLogoutBlock({ post_logout_redirect_uris: ['javascript:alert(1)'] }).error).toContain('post_logout_redirect_uris')
    expect(validateLogoutBlock({ post_logout_redirect_uris: [], backchannel_logout_uri: 'ftp://x' }).error).toContain('backchannel_logout_uri')
  })

  it('authTimeOf: the database default’s space format parses as UTC (the bare-Date.parse local-time trap), ISO stands, garbage answers null', async () => {
    const { authTimeOf } = await import('../../server/auth/op/logout')
    const expected = Math.floor(Date.parse('2026-09-07T12:34:56Z') / 1000)
    // THE PIN: the sessions.created_at default (datetime('now')) writes
    // "YYYY-MM-DD HH:MM:SS" — UTC with NO offset marker. The space→T+Z
    // rewrite is what keeps the instant honest.
    expect(authTimeOf('2026-09-07 12:34:56')).toBe(expected)
    expect(authTimeOf('2026-09-07T12:34:56.000Z')).toBe(expected)
    expect(authTimeOf('2026-09-07T12:34:56Z')).toBe(expected)
    expect(authTimeOf('not a timestamp')).toBeNull()
    expect(authTimeOf('')).toBeNull()
    expect(authTimeOf(null)).toBeNull()
    expect(authTimeOf(undefined)).toBeNull()
  })

  it('the seed parser: the application class carries the logout block, the machine classes refuse it, a malformed URI fails the boot', async () => {
    const { parseOpClientSeed } = await import('../../server/auth/op/registry')
    const entries = parseOpClientSeed(JSON.stringify([
      { client_id: 'app-1', name: 'App', redirect_uris: ['https://app.example/cb'], logout: { post_logout_redirect_uris: ['https://app.example/out'], backchannel_logout_uri: null } },
      // The all-empty block normalizes to ABSENT (the tight-write doctrine).
      { client_id: 'app-2', name: 'App 2', redirect_uris: ['https://app2.example/cb'], logout: { post_logout_redirect_uris: [], backchannel_logout_uri: null } },
    ]))
    expect(entries[0]!.logout).toEqual({ post_logout_redirect_uris: ['https://app.example/out'], backchannel_logout_uri: null })
    expect(entries[1]!.logout).toBeUndefined()
    expect(() => parseOpClientSeed(JSON.stringify([
      { client_id: 'dev-1', name: 'Device', class: 'device', device: { id: 'd-1', org: 'o', instrument_model: 'm@1' }, secret: 's', logout: { post_logout_redirect_uris: [] } },
    ]))).toThrow(/no logout surface/)
    expect(() => parseOpClientSeed(JSON.stringify([
      { client_id: 'app-3', name: 'App 3', redirect_uris: ['https://app3.example/cb'], logout: { post_logout_redirect_uris: ['not-a-uri'] } },
    ]))).toThrow(/post_logout_redirect_uris/)
  })
})

describe('the client registry carries the logout block', () => {
  it('the seeded block round-trips the admin view; the plain client reads null', async () => {
    const admin = await demoLogin('admin@oiml.org')
    const list = await app.request(`${ISSUER}/api/op/clients`, { headers: { cookie: admin } })
    expect(list.status).toBe(200)
    const clients = await list.json() as Array<{ clientId: string; logout: unknown }>
    const hub = clients.find(c => c.clientId === HUB_ID)!
    expect(hub.logout).toEqual({
      post_logout_redirect_uris: [HUB_POST_LOGOUT],
      backchannel_logout_uri: `${receiverUrl}/backchannel-logout`,
    })
    expect(clients.find(c => c.clientId === PLAIN.client_id)!.logout).toBeNull()
  })

  it('the admin write validates + stores the block, and the wholesale rewrite drops an omitted one (the policy doctrine)', async () => {
    const admin = await demoLogin('admin@oiml.org')
    const created = await app.request(`${ISSUER}/api/op/clients`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: admin },
      body: JSON.stringify({
        client_id: 'logout-rp',
        name: 'An RP with a logout surface',
        secret: 'logout-rp-secret',
        redirect_uris: ['https://logout-rp.example/callback'],
        logout: { post_logout_redirect_uris: ['https://logout-rp.example/out'], backchannel_logout_uri: 'https://logout-rp.example/bc' },
      }),
    })
    expect(created.status).toBe(201)
    expect((await created.json() as { logout: unknown }).logout).toEqual({
      post_logout_redirect_uris: ['https://logout-rp.example/out'],
      backchannel_logout_uri: 'https://logout-rp.example/bc',
    })

    // The wholesale rewrite: an edit that omits `logout` drops the
    // stored block — exactly as with the claims policy's roles.
    const edited = await app.request(`${ISSUER}/api/op/clients`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: admin },
      body: JSON.stringify({
        client_id: 'logout-rp',
        name: 'An RP with a logout surface',
        secret: 'logout-rp-secret',
        redirect_uris: ['https://logout-rp.example/callback'],
      }),
    })
    expect(edited.status).toBe(200)
    expect((await edited.json() as { logout: unknown }).logout).toBeNull()
  })

  it('the refusals: a machine class never carries a logout surface; a malformed URI answers 400', async () => {
    const admin = await demoLogin('admin@oiml.org')
    // The device binding's org must resolve first (the id-device-clients
    // shape — the org check precedes the logout refusal).
    await store.createOrgRegistryOrg({
      id: 'mfr-acme',
      name: 'ACME (the demonstration manufacturer)',
      shortName: 'ACME',
      kind: 'manufacturer',
      country: 'Example Member State',
      contacts: [],
      participantRef: null,
      createdBy: 'the test seed',
    })
    const device = await app.request(`${ISSUER}/api/op/clients`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: admin },
      body: JSON.stringify({
        client_id: 'device-no-logout',
        name: 'A device',
        class: 'device',
        device: { id: 'dev-x', org: 'mfr-acme', instrument_model: 'acme-lc500@2021' },
        secret: 'device-secret-123',
        logout: { post_logout_redirect_uris: ['https://x.example/out'] },
      }),
    })
    expect(device.status).toBe(400)
    expect((await device.json() as { error: string }).error).toContain('no logout surface')

    const malformed = await app.request(`${ISSUER}/api/op/clients`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: admin },
      body: JSON.stringify({
        client_id: 'bad-logout-rp',
        name: 'A malformed logout block',
        secret: 'bad-secret',
        redirect_uris: ['https://bad.example/callback'],
        logout: { post_logout_redirect_uris: ['javascript:alert(1)'] },
      }),
    })
    expect(malformed.status).toBe(400)
    expect((await malformed.json() as { error: string }).error).toContain('post_logout_redirect_uris')
  })
})

describe('the end-session endpoint (RP-Initiated Logout)', () => {
  it('a valid hint + a registered post_logout_redirect_uri + state → the 302, and the OP session is dead', async () => {
    const { cookie, idToken } = await signInAndIdToken('ia@oiml.org')
    const query = new URLSearchParams({
      id_token_hint: idToken,
      post_logout_redirect_uri: HUB_POST_LOGOUT,
      state: 'logout-state-1',
    })
    const res = await app.request(`${ISSUER}/op/endsession?${query}`, { headers: { cookie } })
    expect(res.status).toBe(302)
    const back = new URL(res.headers.get('location')!)
    expect(back.origin + back.pathname).toBe(HUB_POST_LOGOUT)
    expect(back.searchParams.get('state')).toBe('logout-state-1')
    // The act: the session row is dead and the cookie clears.
    expect((await app.request(`${ISSUER}/api/auth/session`, { headers: { cookie } })).status).toBe(401)
    const cleared = res.headers.get('set-cookie') ?? ''
    expect(cleared).toContain('oiml-session=')
    expect(cleared.toLowerCase()).toMatch(/max-age=0|expires=thu, 01 jan 1970/)
  })

  it('the POST form variant takes the same parameters', async () => {
    const { cookie, idToken } = await signInAndIdToken('ia@oiml.org')
    const res = await app.request(`${ISSUER}/op/endsession`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', cookie },
      body: new URLSearchParams({ id_token_hint: idToken, post_logout_redirect_uri: HUB_POST_LOGOUT }).toString(),
    })
    expect(res.status).toBe(302)
    expect(new URL(res.headers.get('location')!).origin + new URL(res.headers.get('location')!).pathname).toBe(HUB_POST_LOGOUT)
  })

  it('an UNREGISTERED post_logout_redirect_uri never redirects — the honest signed-out page, and the act still lands', async () => {
    const { cookie, idToken } = await signInAndIdToken('ia@oiml.org')
    const query = new URLSearchParams({
      id_token_hint: idToken,
      post_logout_redirect_uri: 'https://evil.example/steal',
    })
    const res = await app.request(`${ISSUER}/op/endsession?${query}`, { headers: { cookie } })
    expect(res.status).toBe(200)
    expect(res.headers.get('location')).toBeNull()
    const html = await res.text()
    expect(html).toContain('data-testid="op-signed-out"')
    expect(html).toContain('data-testid="op-signed-out-home"')
    expect((await app.request(`${ISSUER}/api/auth/session`, { headers: { cookie } })).status).toBe(401)
  })

  it('no parameters at all → the signed-out page; the session ends anyway', async () => {
    const cookie = await demoLogin('tl@oiml.org')
    const res = await app.request(`${ISSUER}/op/endsession`, { headers: { cookie } })
    expect(res.status).toBe(200)
    expect(await res.text()).toContain('data-testid="op-signed-out"')
    expect((await app.request(`${ISSUER}/api/auth/session`, { headers: { cookie } })).status).toBe(401)
  })

  it('a garbage hint never blocks the act — it only narrows the client resolution (no client_id, no redirect)', async () => {
    const cookie = await demoLogin('tl@oiml.org')
    const query = new URLSearchParams({
      id_token_hint: 'not.a.jwt',
      post_logout_redirect_uri: HUB_POST_LOGOUT, // registered, but no client resolves
    })
    const res = await app.request(`${ISSUER}/op/endsession?${query}`, { headers: { cookie } })
    expect(res.status).toBe(200)
    expect(await res.text()).toContain('data-testid="op-signed-out"')
    expect((await app.request(`${ISSUER}/api/auth/session`, { headers: { cookie } })).status).toBe(401)
  })

  it('the hint’s aud wins over the client_id param (the OP’s own mint resolves the client)', async () => {
    const { cookie, idToken } = await signInAndIdToken('ia@oiml.org')
    const query = new URLSearchParams({
      id_token_hint: idToken, // minted for hub-instance
      client_id: PLAIN.client_id, // a client with NO logout surface
      post_logout_redirect_uri: HUB_POST_LOGOUT,
    })
    const res = await app.request(`${ISSUER}/op/endsession?${query}`, { headers: { cookie } })
    expect(res.status).toBe(302)
    expect(new URL(res.headers.get('location')!).origin + new URL(res.headers.get('location')!).pathname).toBe(HUB_POST_LOGOUT)
  })

  it('no live session: the redirect courtesy still fires (the RP’s user IS signed out); a dead cookie clears honestly', async () => {
    const { idToken } = await signInAndIdToken('ia@oiml.org')
    // NO cookie at all.
    const query = new URLSearchParams({ id_token_hint: idToken, post_logout_redirect_uri: HUB_POST_LOGOUT })
    const anon = await app.request(`${ISSUER}/op/endsession?${query}`)
    expect(anon.status).toBe(302)
    // A cookie naming a dead row: the page, and the cookie clears.
    const dead = await app.request(`${ISSUER}/op/endsession`, { headers: { cookie: 'oiml-session=dead-token-value' } })
    expect(dead.status).toBe(200)
    expect(dead.headers.get('set-cookie') ?? '').toContain('oiml-session=')
  })
})

describe('prompt=login (the OIDC forced re-authentication)', () => {
  const AUTHORIZE_PARAMS = {
    response_type: 'code',
    client_id: HUB_ID,
    redirect_uri: HUB_REDIRECT,
    scope: 'openid profile email',
    state: 'st-login',
    nonce: 'nn-login',
    code_challenge_method: 'S256',
  }

  it('a live session + prompt=login takes the login redirect WITH the prompt flag; the re-entry URL sheds the login value (the stateless loop guard)', async () => {
    const cookie = await demoLogin('ia@oiml.org')
    const pkce = await generatePkce()
    const query = new URLSearchParams({ ...AUTHORIZE_PARAMS, code_challenge: pkce.challenge, prompt: 'login' })
    const res = await app.request(`${ISSUER}/op/authorize?${query}`, { headers: { cookie } })
    expect(res.status).toBe(302)
    const login = new URL(res.headers.get('location')!, ISSUER)
    expect(login.pathname).toBe('/')
    expect(login.searchParams.get('prompt')).toBe('login')
    const target = login.searchParams.get('redirect')!
    expect(target.startsWith('/op/authorize?')).toBe(true)
    // The 'login' value is CONSUMED by this redirect — the re-entry
    // request must not force the form again (the loop guard).
    const reentry = new URL(target, ISSUER)
    expect(reentry.searchParams.get('prompt')).toBeNull()
    expect(reentry.searchParams.get('client_id')).toBe(HUB_ID)
  })

  it('prompt=login consent: the remaining values ride on (the re-entry keeps prompt=consent)', async () => {
    const cookie = await demoLogin('ia@oiml.org')
    const pkce = await generatePkce()
    const query = new URLSearchParams({ ...AUTHORIZE_PARAMS, code_challenge: pkce.challenge, prompt: 'login consent' })
    const res = await app.request(`${ISSUER}/op/authorize?${query}`, { headers: { cookie } })
    expect(res.status).toBe(302)
    const login = new URL(res.headers.get('location')!, ISSUER)
    expect(login.searchParams.get('prompt')).toBe('login')
    const reentry = new URL(login.searchParams.get('redirect')!, ISSUER)
    expect(reentry.searchParams.get('prompt')).toBe('consent')
  })

  it('no session + prompt=login: the same login-redirect shape (the flag rides for the form)', async () => {
    const pkce = await generatePkce()
    const query = new URLSearchParams({ ...AUTHORIZE_PARAMS, code_challenge: pkce.challenge, prompt: 'login' })
    const res = await app.request(`${ISSUER}/op/authorize?${query}`)
    expect(res.status).toBe(302)
    const login = new URL(res.headers.get('location')!, ISSUER)
    expect(login.pathname).toBe('/')
    expect(login.searchParams.get('prompt')).toBe('login')
  })
})

describe('auth_time (the authentication instant)', () => {
  it('the consent-minted ID token carries auth_time = the session’s created_at epoch (the space-format fix, end to end)', async () => {
    const cookie = await demoLogin('ia@oiml.org')
    const session = await (await app.request(`${ISSUER}/api/auth/session`, { headers: { cookie } })).json() as { sessionCreatedAt: string }
    expect(session.sessionCreatedAt, 'the session payload projects the authentication instant').toBeTruthy()

    const pkce = await generatePkce()
    const { code } = await driveCode(cookie, { clientId: HUB_ID, redirectUri: HUB_REDIRECT, challenge: pkce.challenge })
    const token = await exchange({ code, redirectUri: HUB_REDIRECT, clientId: HUB_ID, verifier: pkce.verifier, secret: HUB_SECRET })
    expect(token.status).toBe(200)
    const { id_token } = await token.json() as { id_token: string }
    const claims = decodePayload(id_token)
    const { authTimeOf } = await import('../../server/auth/op/logout')
    expect(claims.auth_time).toBe(authTimeOf(session.sessionCreatedAt))
    // …and the instant is REAL (this run, seconds precision).
    expect(Math.abs(Date.now() / 1000 - (claims.auth_time as number))).toBeLessThan(120)
  })

  it('the remembered-grant skip mints auth_time through the SAME path (both call sites carry the instant)', async () => {
    const cookie = await demoLogin('tl@oiml.org')
    const session = await (await app.request(`${ISSUER}/api/auth/session`, { headers: { cookie } })).json() as { sessionCreatedAt: string }

    // The first allow records the grant…
    let pkce = await generatePkce()
    const first = await driveCode(cookie, { clientId: HUB_ID, redirectUri: HUB_REDIRECT, challenge: pkce.challenge })
    expect(first.code).toBeTruthy()

    // …the second authorize SKIPS the consent page (the remembered grant)
    // and mints directly.
    pkce = await generatePkce()
    const query = new URLSearchParams({
      response_type: 'code', client_id: HUB_ID, redirect_uri: HUB_REDIRECT,
      scope: 'openid profile email', state: 'st-skip', nonce: 'nn-skip',
      code_challenge: pkce.challenge, code_challenge_method: 'S256',
    })
    const authorize = await app.request(`${ISSUER}/op/authorize?${query}`, { headers: { cookie } })
    expect(authorize.status).toBe(302)
    const skipped = new URL(authorize.headers.get('location')!)
    expect(skipped.origin + skipped.pathname, 'the remembered grant skips the consent page').toBe(HUB_REDIRECT)
    const code = skipped.searchParams.get('code')!
    const token = await exchange({ code, redirectUri: HUB_REDIRECT, clientId: HUB_ID, verifier: pkce.verifier, secret: HUB_SECRET })
    expect(token.status).toBe(200)
    const { id_token } = await token.json() as { id_token: string }
    const claims = decodePayload(id_token)
    const { authTimeOf } = await import('../../server/auth/op/logout')
    expect(claims.auth_time).toBe(authTimeOf(session.sessionCreatedAt))
  })
})

describe('the backchannel fan-out (OP-initiated logout)', () => {
  it('the signout POSTs the logout_token to every live-grant client with a receiver — and ONLY those', async () => {
    const before = received.length
    // The account signs in + grants BOTH clients (hub-instance has the
    // receiver; plain-site has NO logout surface).
    const cookie = await demoLogin('viewer@oiml.org')
    const me = await (await app.request(`${ISSUER}/api/auth/session`, { headers: { cookie } })).json() as { id: string }
    let pkce = await generatePkce()
    await driveCode(cookie, { clientId: HUB_ID, redirectUri: HUB_REDIRECT, challenge: pkce.challenge })
    pkce = await generatePkce()
    const plainGrant = await driveCode(cookie, {
      clientId: PLAIN.client_id, redirectUri: PLAIN.redirect_uris[0]!, challenge: pkce.challenge,
    })
    expect(plainGrant.code).toBeTruthy()
    expect((await store.listConsentGrants(me.id)).length).toBe(2)

    // The act: the console's sign-out.
    const signout = await app.request(`${ISSUER}/api/auth/signout`, { method: 'POST', headers: { cookie } })
    expect(signout.status).toBe(200)
    expect((await app.request(`${ISSUER}/api/auth/session`, { headers: { cookie } })).status).toBe(401)

    // ONE send — hub-instance only (plain-site registered no receiver).
    await awaitReceived(before + 1)
    const hit = received[received.length - 1]!
    expect(hit.contentType).toContain('application/x-www-form-urlencoded')
    const token = new URLSearchParams(hit.body).get('logout_token')
    expect(token, 'the form carries the logout_token').toBeTruthy()

    // The claims: the spec's set, no more.
    const claims = decodePayload(token!)
    expect(claims.iss).toBe(ISSUER)
    expect(claims.sub).toBe(me.id)
    expect(claims.aud).toBe(HUB_ID)
    expect(typeof claims.jti).toBe('string')
    expect(typeof claims.iat).toBe('number')
    expect((claims.exp as number) - (claims.iat as number)).toBe(120)
    expect(claims.events).toEqual({ 'http://schemas.openid.net/event/backchannel-logout': {} })
    // NO sid (no sid tracking exists — the named gap), NO nonce (the
    // logout token is not an ID token).
    expect(claims.sid).toBeUndefined()
    expect(claims.nonce).toBeUndefined()

    // The signature verifies against the OP's SERVED keyset (the RP's
    // validation posture — never an OP-internal shortcut).
    const { keys } = await (await app.request(`${ISSUER}/jwks.json`)).json() as { keys: JsonWebKey[] }
    const { verifyOpIdTokenHint } = await import('../../server/auth/op/logout')
    const verified = await verifyOpIdTokenHint(keys, ISSUER, token!)
    expect(verified).toEqual({ sub: me.id, aud: HUB_ID })
  })

  it('the end-session fires the fan-out too (the RP-initiated act is a session-ending act)', async () => {
    const before = received.length
    const { cookie, idToken, userId } = await signInAndIdToken('ia@oiml.org')
    const res = await app.request(`${ISSUER}/op/endsession?id_token_hint=${encodeURIComponent(idToken)}`, { headers: { cookie } })
    expect(res.status).toBe(200) // no post_logout param → the honest page
    await awaitReceived(before + 1)
    const claims = decodePayload(new URLSearchParams(received[received.length - 1]!.body).get('logout_token')!)
    expect(claims.sub).toBe(userId)
    expect(claims.aud).toBe(HUB_ID)
  })

  it('the target set’s honesty: a disabled client and a client without a receiver never appear; a revoked grant drops the target', async () => {
    const { collectBackchannelTargets } = await import('../../server/auth/op/logout')
    // A synthetic account with grants on: hub-instance (receiver), the
    // plain site (none), and a disabled client WITH a receiver.
    const user = await store.provisionSsoUser({
      email: 'targets@example.org', name: 'Target Set', provider: 'oidc', providerAccountId: 'targets-1', role: 'viewer', orgId: null,
    })
    const claimsPolicy: OpLogoutPolicy = {
      claims: [],
      logout: { post_logout_redirect_uris: [], backchannel_logout_uri: 'https://disabled.example/bc' },
    }
    await store.upsertOidcClient({
      clientId: 'disabled-rp',
      name: 'A disabled RP with a receiver',
      secretHash: null,
      redirectUris: ['https://disabled.example/cb'],
      claimsPolicy,
      createdBy: 'test',
    })
    await store.setOidcClientStatus('disabled-rp', 'disabled')
    await store.recordConsentGrant({ userId: user.id, clientId: HUB_ID, scope: 'openid' })
    await store.recordConsentGrant({ userId: user.id, clientId: PLAIN.client_id, scope: 'openid' })
    await store.recordConsentGrant({ userId: user.id, clientId: 'disabled-rp', scope: 'openid' })

    const targets = await collectBackchannelTargets(store, user.id)
    expect(targets).toEqual([{ clientId: HUB_ID, uri: `${receiverUrl}/backchannel-logout` }])

    // A revoked grant drops the target (the live-grants doctrine).
    const grants = await store.listConsentGrants(user.id)
    await store.revokeConsentGrant(grants.find(g => g.clientId === HUB_ID)!.id, user.id)
    expect(await collectBackchannelTargets(store, user.id)).toEqual([])
  })

  it('a failed send never fails the act: the per-target outcomes answer honestly (500 → not-ok, unreachable → not-ok)', async () => {
    const { sendBackchannelLogout, BACKCHANNEL_LOGOUT_EVENT } = await import('../../server/auth/op/logout')
    const { resolveOpSigningKey } = await import('../../server/auth/op/keys')
    const key = await resolveOpSigningKey(process.env)
    const seen: string[] = []
    const fetchStub = (async (input: RequestInfo | URL): Promise<Response> => {
      const url = String(input)
      seen.push(url)
      if (url.includes('ok-rp')) return new Response('ok', { status: 200 })
      if (url.includes('sad-rp')) return new Response('nope', { status: 500 })
      throw new Error('connection refused')
    }) as typeof fetch
    const outcomes = await sendBackchannelLogout([
      { clientId: 'ok-rp', uri: 'https://ok-rp.example/bc' },
      { clientId: 'sad-rp', uri: 'https://sad-rp.example/bc' },
      { clientId: 'down-rp', uri: 'https://down-rp.example/bc' },
    ], key, ISSUER, 'user-1', fetchStub)
    expect(outcomes).toEqual([
      { clientId: 'ok-rp', ok: true },
      { clientId: 'sad-rp', ok: false },
      { clientId: 'down-rp', ok: false },
    ])
    expect(seen.length).toBe(3)
    // The delivered token carries the spec's event claim.
    expect(BACKCHANNEL_LOGOUT_EVENT).toBe('http://schemas.openid.net/event/backchannel-logout')
  })
})
