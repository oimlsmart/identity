// ─────────────────────────────────────────────────────────────────────
// TODO.identity-sso (the client-registry governance console) — the
// per-client governance view's unit floor, proven in-process: the REAL
// op + auth-lean + grants + dashboard routers over a REAL temp SQLite
// store (kernel 0.2.10's governance reads), real sign-ins driving real
// consent grants, real refresh rows, and the real audit chain. NO stub
// on the OP side.
//
// Covered:
//   THE GATE        — the admin surface's own rule (the registry
//                     surface's posture): the unauthenticated 401, the
//                     plain account 403, the platform admin AND the
//                     scheme operator admitted; the unknown client
//                     answers the honest 404 (never a 200 of empties);
//   THE ANSWER      — the client slice (the registry truth, the derived
//                     class, never the secret hash); the grants slice
//                     carries the WHOLE consent history — live AND
//                     revoked (the account console hides the revoked
//                     half; the governance view shows it), each account
//                     resolved (name + email) through the ONE users
//                     prefetch; the population counts answer the LIVE
//                     halves (the consent revoke's companion delete
//                     moves the refresh count; the access rows keep
//                     their ≤1 h life); the audit slice carries the
//                     client-side acts ∪ the account-side consent acts
//                     naming the client, newest first;
//   THE SILENCE     — the answer NEVER carries a token value (every
//                     access/refresh token the flow minted is asserted
//                     absent from the response body);
//   THE ISOLATION   — another client's governance answer carries none
//                     of this client's grants, counts, or audit rows.
//
// The endpoint-scaling gate (endpoint-scaling.test.ts) pins the
// store-call invariance separately; this file pins the semantics.
// ─────────────────────────────────────────────────────────────────────

import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

// The store's DB path is read at module evaluation — set it before any
// import below touches @oimlsmart/platform-server/store/sqlite (the imports are dynamic).
const TMP = mkdtempSync(join(tmpdir(), 'oiml-op-client-governance-'))
process.env.DATABASE_PATH = join(TMP, 'test.db')

const ISSUER = 'http://op.test'
process.env.OP_ISSUER = ISSUER

const HUB_ID = 'hub-instance'
const HUB_SECRET = 'hub-secret-123'
const HUB_REDIRECT = 'https://hub.example/api/auth/callback/oidc'
const PLAIN_ID = 'plain-spa'
const PLAIN_REDIRECT = 'https://plain.example/callback'

const PETRA = 'petra.horvat@etl.example.org'
const MARTIN = 'martin.berger@etl.example.org'

let app: import('hono').Hono
let store: ReturnType<typeof import('@oimlsmart/platform-server/store').getStore>
let generatePkce: typeof import('@oimlsmart/platform-server/oidc').generatePkce
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
  params: { clientId: string; redirectUri: string; scope: string; challenge: string },
): Promise<string> {
  const query = new URLSearchParams({
    response_type: 'code',
    client_id: params.clientId,
    redirect_uri: params.redirectUri,
    scope: params.scope,
    state: 'st-1',
    nonce: 'nn-1',
    code_challenge: params.challenge,
    code_challenge_method: 'S256',
    prompt: 'consent',
  })
  const authorize = await app.request(`${ISSUER}/op/authorize?${query}`, { headers: { cookie } })
  expect(authorize.status, 'authorize redirects to the consent page').toBe(302)
  const consentUrl = new URL(authorize.headers.get('location')!, ISSUER)
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
  return code!
}

function clientBasic(clientId: string, secret: string): string {
  return `Basic ${btoa(`${encodeURIComponent(clientId)}:${encodeURIComponent(secret)}`)}`
}

/** A full sign-in + code + exchange (the offline grant when scope carries
 *  offline_access). */
async function signInAndExchange(email: string, scope: string, client: { id: string; redirect: string; secret?: string }): Promise<{
  cookie: string
  userId: string
  accessToken: string
  refreshToken: string | null
}> {
  const cookie = await demoLogin(email)
  const pkce = await generatePkce()
  const code = await driveCode(cookie, { clientId: client.id, redirectUri: client.redirect, scope, challenge: pkce.challenge })
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    redirect_uri: client.redirect,
    client_id: client.id,
    code_verifier: pkce.verifier,
  })
  const headers: Record<string, string> = { 'content-type': 'application/x-www-form-urlencoded' }
  if (client.secret !== undefined) headers.authorization = clientBasic(client.id, client.secret)
  const res = await app.request(`${ISSUER}/op/token`, { method: 'POST', headers, body })
  expect(res.status, 'the code exchange').toBe(200)
  const tokens = await res.json() as { access_token: string; refresh_token?: string }
  const session = await (await app.request(`${ISSUER}/api/auth/session`, { headers: { cookie } })).json() as { id: string }
  return { cookie, userId: session.id, accessToken: tokens.access_token, refreshToken: tokens.refresh_token ?? null }
}

/** The governance answer, typed at the shape the console renders. */
interface GovernanceAnswer {
  generatedAt: string
  retention: string
  client: {
    clientId: string
    name: string
    class: string
    status: string
    confidential: boolean
    createdAt: string
    createdBy: string | null
  }
  grants: Array<{
    id: string
    account: { id: string; name: string | null; email: string | null } | null
    scope: string
    createdAt: string
    revokedAt: string | null
  }>
  tokens: { accessLive: number; refreshLive: number }
  audit: Array<{
    at: string
    action: string
    actor: string | null
    account: { id: string; name: string | null; email: string | null } | null
    metadata: Record<string, unknown>
  }>
}

async function governance(clientId: string, cookie: string): Promise<Response> {
  return app.request(`${ISSUER}/api/op/dashboard/clients/${clientId}/governance`, { headers: { cookie } })
}

beforeAll(async () => {
  process.env.OP_CLIENT_SEED = JSON.stringify([
    {
      client_id: HUB_ID,
      name: 'OIML SMART platform hub',
      secret: HUB_SECRET,
      redirect_uris: [HUB_REDIRECT],
      claims_policy: { claims: ['roles', 'groups', 'org'] },
    },
    { client_id: PLAIN_ID, name: 'A public SPA', redirect_uris: [PLAIN_REDIRECT] },
  ])

  // The declared signing key (identity#7's gate: the registration rides
  // the declared posture, exactly production's shape).
  const { generateSuccessorPair } = await import('../../scripts/op-key-rotate')
  process.env.OP_SIGNING_KEY = (await generateSuccessorPair()).privateJwkJson

  const { installSqliteStore } = await import('@oimlsmart/platform-server/store/sqlite')
  store = installSqliteStore()
  const profileMod = await import('@oimlsmart/platform-server/profile')
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

  const oidc = await import('@oimlsmart/platform-server/oidc')
  generatePkce = oidc.generatePkce
  oidc.clearOidcCaches()

  const { Hono } = await import('hono')
  const { createAuthLeanRouter } = await import('../../server/routes/auth-lean')
  const { createOpRouter } = await import('../../server/routes/op')
  const { createOpGrantsRouter } = await import('../../server/routes/op-grants')
  const { createOpDashboardRouter } = await import('../../server/routes/op-dashboard')
  const root = new Hono()
  root.route('/api/auth', createAuthLeanRouter({ autoSeedDemo: true }))
  root.route('/', createOpRouter())
  root.route('/', createOpGrantsRouter())
  root.route('/', createOpDashboardRouter())
  app = root

  // The bootstrap seed lands on the first REGISTRY request.
  const admin = await demoLogin('admin@oiml.org')
  expect((await app.request(`${ISSUER}/api/op/clients`, { headers: { cookie: admin } })).status).toBe(200)
})

afterAll(() => {
  resetProfile()
  rmSync(TMP, { recursive: true, force: true })
  delete process.env.OP_ISSUER
  delete process.env.OP_SIGNING_KEY
  delete process.env.OP_CLIENT_SEED
  delete process.env.DATABASE_PATH
})

describe('the gate (the registry surface’s own rule)', () => {
  it('admits the platform admin and the scheme operator only; the unknown client 404s', async () => {
    const admin = await demoLogin('admin@oiml.org')
    const csAdmin = await demoLogin('cs@oiml.org')
    const viewer = await demoLogin('viewer@oiml.org')

    expect((await governance(PLAIN_ID, '')).status, 'the unauthenticated ask').toBe(401)
    expect((await governance(PLAIN_ID, viewer)).status, 'the plain account').toBe(403)
    expect((await governance(PLAIN_ID, admin)).status, 'the platform admin').toBe(200)
    expect((await governance(PLAIN_ID, csAdmin)).status, 'the scheme operator').toBe(200)
    expect((await governance('never-registered', admin)).status, 'the unknown client answers the honest 404, never a 200 of empties').toBe(404)
  })
})

describe('the governance answer (the console’s expansion)', () => {
  it('carries the whole consent history, the population counts, and the audit slice — never a token value', async () => {
    const admin = await demoLogin('admin@oiml.org')
    const OFFLINE = 'openid profile offline_access'

    // Two accounts grant the SAME public client (each its own triple).
    const petra = await signInAndExchange(PETRA, OFFLINE, { id: PLAIN_ID, redirect: PLAIN_REDIRECT })
    const martin = await signInAndExchange(MARTIN, OFFLINE, { id: PLAIN_ID, redirect: PLAIN_REDIRECT })
    expect(petra.refreshToken, 'the offline grant mints').toBeTruthy()
    expect(martin.refreshToken, 'the offline grant mints').toBeTruthy()

    const before = await (await governance(PLAIN_ID, admin)).json() as GovernanceAnswer

    // ── the client slice: the registry truth, the derived class ──
    expect(before.client.clientId).toBe(PLAIN_ID)
    expect(before.client.class, 'the public SPA is the application class').toBe('application')
    expect(before.client.confidential, 'no secret hash').toBe(false)
    expect(before.client.status).toBe('active')

    // ── the grants slice: both accounts, resolved, live ──
    expect(before.grants.length).toBe(2)
    const petraGrant = before.grants.find(g => g.account?.email === PETRA)!
    const martinGrant = before.grants.find(g => g.account?.email === MARTIN)!
    expect(petraGrant.account?.name).toBe('Ms. Petra Horvat')
    expect(martinGrant.revokedAt).toBeNull()
    expect(petraGrant.scope).toBe('offline_access openid profile')

    // ── the population counts: the LIVE halves ──
    expect(before.tokens.refreshLive, 'two offline grants stand').toBe(2)
    expect(before.tokens.accessLive, 'the two exchange mints').toBe(2)

    // ── the audit slice: the account-side consent acts naming the
    // client ∪ the client-side issuance acts ──
    const granted = before.audit.filter(e => e.action === 'account.consent_granted')
    expect(granted.length, 'both allows name the client').toBe(2)
    expect(granted.every(e => e.metadata.client === PLAIN_ID)).toBe(true)
    expect(granted.map(e => e.account?.email).sort()).toEqual([MARTIN, PETRA].sort())
    expect(before.audit.filter(e => e.action === 'client.token_issued').length, 'the client-side acts ride the same slice').toBe(2)
    // Newest first.
    expect(before.audit[0]!.at >= before.audit[1]!.at).toBe(true)

    // ── the consent revocation: the history shows it, the offline half dies ──
    const grantsList = await (await app.request(`${ISSUER}/api/op/account/grants`, { headers: { cookie: petra.cookie } })).json() as {
      grants: Array<{ id: string; clientId: string }>
    }
    const petraGrantId = grantsList.grants.find(g => g.clientId === PLAIN_ID)!.id
    const revokeRes = await app.request(`${ISSUER}/api/op/account/grants/${petraGrantId}`, { method: 'DELETE', headers: { cookie: petra.cookie } })
    expect(revokeRes.status, 'the account console’s revoke').toBe(200)

    // ── a refresh on the SURVIVING grant: the audit slice gains the
    // client-side rotation act; the counts move honestly ──
    const refreshBody = new URLSearchParams({ grant_type: 'refresh_token', refresh_token: martin.refreshToken!, client_id: PLAIN_ID })
    const refreshRes = await app.request(`${ISSUER}/op/token`, {
      method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: refreshBody,
    })
    expect(refreshRes.status, 'the surviving grant rotates').toBe(200)
    const rotated = await refreshRes.json() as { access_token: string; refresh_token: string }

    const after = await (await governance(PLAIN_ID, admin)).json() as GovernanceAnswer

    // The revoked grant LISTS — the governance view carries the history
    // the account console hides.
    const revokedRow = after.grants.find(g => g.id === petraGrantId)!
    expect(revokedRow.revokedAt, 'the revoked half carries its stamp').toBeTruthy()
    expect(after.grants.length, 'the history survives the revoke').toBe(2)
    // The counts: the companion delete ended the offline half (2 → 1);
    // the access rows keep their ≤1 h life — Petra's mint still stands,
    // Martin's rotation ADDED one (2 → 3).
    expect(after.tokens.refreshLive, 'the revoke carried the offline half out').toBe(1)
    expect(after.tokens.accessLive, 'the access rows keep their hour; the rotation added one').toBe(3)
    // The audit slice gained the account-side revoke (the account
    // resolved, the client named in metadata) and the client-side
    // rotation.
    const revokedEvt = after.audit.find(e => e.action === 'account.consent_revoked')!
    expect(revokedEvt.account?.email).toBe(PETRA)
    expect(revokedEvt.metadata.client).toBe(PLAIN_ID)
    expect(revokedEvt.metadata.refreshTokens, 'the audit names the count, never a token').toBe(1)
    const rotatedEvt = after.audit.find(e => e.action === 'client.token_refreshed')!
    expect(rotatedEvt.account?.email).toBe(MARTIN)

    // ── THE SILENCE: no token value ever rides the answer ──
    const body = JSON.stringify(after)
    for (const value of [petra.accessToken, martin.accessToken, rotated.access_token, petra.refreshToken, martin.refreshToken, rotated.refresh_token]) {
      expect(value).toBeTruthy()
      expect(body.includes(value!), `a token value never leaks (${value!.slice(0, 8)}…)`).toBe(false)
    }
  })

  it('the per-client isolation: another client’s answer carries none of this client’s rows', async () => {
    const admin = await demoLogin('admin@oiml.org')
    // Petra grants the HUB too (the confidential client, its own triple).
    const petra = await signInAndExchange(PETRA, 'openid profile', { id: HUB_ID, redirect: HUB_REDIRECT, secret: HUB_SECRET })
    expect(petra.refreshToken, 'no offline scope, no refresh row').toBeNull()

    const hub = await (await governance(HUB_ID, admin)).json() as GovernanceAnswer
    expect(hub.client.class).toBe('application')
    expect(hub.client.confidential).toBe(true)
    expect(hub.grants.length, 'only the hub’s own triple').toBe(1)
    expect(hub.grants[0]!.account?.email).toBe(PETRA)
    expect(hub.grants[0]!.revokedAt).toBeNull()
    expect(hub.tokens.refreshLive, 'the hub grant carried no offline_access').toBe(0)
    expect(hub.tokens.accessLive).toBe(1)
    expect(hub.audit.every(e => e.metadata.client !== PLAIN_ID), 'the SPA’s account-side acts never cross').toBe(true)
    expect(hub.audit.filter(e => e.action === 'client.token_issued').length, 'the hub’s own issuance').toBe(1)

    // And the SPA's answer is unchanged by the hub's grant.
    const plain = await (await governance(PLAIN_ID, admin)).json() as GovernanceAnswer
    expect(plain.grants.length, 'the hub’s triple never lists here').toBe(2)
  })
})
