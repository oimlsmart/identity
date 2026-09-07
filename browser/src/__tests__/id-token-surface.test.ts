// ─────────────────────────────────────────────────────────────────────
// TODO.identity-sso (the wave-C token surface) — the refresh grant with
// rotation, the RFC 7009 revocation, the RFC 7662 introspection, proven
// in-process: the REAL op + auth-lean + grants routers over a REAL temp
// SQLite store (kernel 0.2.6's migration 0025), the OP's own JWKS
// verifying the mints. NO stub on the OP side.
//
// Covered:
//   THE CODE        — a granted offline_access scope mints the FIRST
//     EXCHANGE        refresh token of a rotation family (the answer's
//                     refresh_token); a grant without it mints none;
//   THE REFRESH     — the rotation: the presented token consumes
//     GRANT           atomically, the successor mints IN THE SAME FAMILY,
//                     the refreshed ID token proves the ORIGINAL
//                     auth_time (never the refresh's moment) and carries
//                     the amr provenance; the audit chain's
//                     client.token_refreshed; the PUBLIC client's
//                     admission on PKCE standing (the spec's driver);
//                     the machine classes refused before any consume;
//                     the cross-client present burns the token (fail
//                     toward invalidation); the deactivated account's
//                     grant refuses;
//   THE REUSE       — a presented CONSUMED token is the theft signal
//     VERDICT         (RFC 6819 §5.2.2.3): invalid_grant, the audit
//                     chain's client.refresh_reuse_detected names the
//                     family, and the family's LIVE successor is dead
//                     (the legitimate chain and the attacker's copy both
//                     end);
//   THE NARROWING   — RFC 6749 §6: the scope parameter narrows BOTH the
//                     access token and the rotated row; a superset ask
//                     refuses invalid_scope; the narrowed row never
//                     widens back;
//   THE REVOCATION  — RFC 7009: the client-bound 200-indistinguishable
//     ENDPOINT        answer; the access half deletes (userinfo 401s);
//                     the refresh half kills the family; a WRONG
//                     token_type_hint still revokes (the RFC's search
//                     extension); a FOREIGN client's revoke answers 200
//                     and kills nothing; the consent console's "Revoke
//                     access" carries the offline half out with it;
//   THE             — RFC 7662 (identity#47/#42's RS half): the opaque
//     INTROSPECTION   access token answers active + the claim set (the
//                     table read); the machine classes' self-contained
//                     JWTs answer through the SIGNATURE + the named
//                     client's LIVE standing (a disabled machine client
//                     reads inactive — never a table read); a refresh
//                     token, a foreign-signed JWT, and the unknown all
//                     answer the honest { active: false };
//   THE DISCOVERY   — grant_types_supported gains refresh_token,
//                     scopes_supported offline_access, the two endpoints
//                     declared (the byte-shape is the contract golden's,
//                     re-recorded deliberately with this wave).
// ─────────────────────────────────────────────────────────────────────

import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

// The store's DB path is read at module evaluation — set it before any
// import below touches @oimlsmart/platform-server/store/sqlite (the imports are dynamic).
const TMP = mkdtempSync(join(tmpdir(), 'oiml-op-token-surface-'))
process.env.DATABASE_PATH = join(TMP, 'test.db')

const ISSUER = 'http://op.test'
process.env.OP_ISSUER = ISSUER

const HUB_ID = 'hub-instance'
const HUB_SECRET = 'hub-secret-123'
const HUB_REDIRECT = 'https://hub.example/api/auth/callback/oidc'
const PLAIN_ID = 'plain-spa'
const PLAIN_REDIRECT = 'https://plain.example/callback'
const DEVICE_ID = 'device-grant'
const DEVICE_SECRET = 'device-secret-456'

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

/** The code exchange (client_secret_basic for the confidential client,
 *  the bare client_id + PKCE for the public one). */
async function exchange(params: { code: string; redirectUri: string; clientId: string; verifier: string; secret?: string }): Promise<Response> {
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code: params.code,
    redirect_uri: params.redirectUri,
    client_id: params.clientId,
    code_verifier: params.verifier,
  })
  const headers: Record<string, string> = { 'content-type': 'application/x-www-form-urlencoded' }
  if (params.secret !== undefined) headers.authorization = clientBasic(params.clientId, params.secret)
  return app.request(`${ISSUER}/op/token`, { method: 'POST', headers, body })
}

/** The refresh grant. */
async function refresh(params: { token: string; clientId: string; secret?: string; scope?: string }): Promise<Response> {
  const body = new URLSearchParams({ grant_type: 'refresh_token', refresh_token: params.token, client_id: params.clientId })
  if (params.scope !== undefined) body.set('scope', params.scope)
  const headers: Record<string, string> = { 'content-type': 'application/x-www-form-urlencoded' }
  if (params.secret !== undefined) headers.authorization = clientBasic(params.clientId, params.secret)
  return app.request(`${ISSUER}/op/token`, { method: 'POST', headers, body })
}

/** RFC 7009. */
async function revoke(params: { token: string; clientId: string; secret?: string; hint?: string }): Promise<Response> {
  const body = new URLSearchParams({ token: params.token, client_id: params.clientId })
  if (params.hint) body.set('token_type_hint', params.hint)
  const headers: Record<string, string> = { 'content-type': 'application/x-www-form-urlencoded' }
  if (params.secret !== undefined) headers.authorization = clientBasic(params.clientId, params.secret)
  return app.request(`${ISSUER}/op/revoke`, { method: 'POST', headers, body })
}

/** RFC 7662. */
async function introspect(params: { token: string; clientId: string; secret?: string }): Promise<Response> {
  const body = new URLSearchParams({ token: params.token, client_id: params.clientId })
  const headers: Record<string, string> = { 'content-type': 'application/x-www-form-urlencoded' }
  if (params.secret !== undefined) headers.authorization = clientBasic(params.clientId, params.secret)
  return app.request(`${ISSUER}/op/introspect`, { method: 'POST', headers, body })
}

/** A full sign-in + code + exchange (the offline grant when scope carries
 *  offline_access). */
async function signInAndExchange(email: string, scope: string, client: { id: string; redirect: string; secret?: string }): Promise<{
  cookie: string
  userId: string
  accessToken: string
  idToken: string
  idClaims: Record<string, unknown>
  refreshToken: string | null
}> {
  const cookie = await demoLogin(email)
  const pkce = await generatePkce()
  const code = await driveCode(cookie, { clientId: client.id, redirectUri: client.redirect, scope, challenge: pkce.challenge })
  const res = await exchange({ code, redirectUri: client.redirect, clientId: client.id, verifier: pkce.verifier, secret: client.secret })
  expect(res.status, 'the code exchange').toBe(200)
  const body = await res.json() as { access_token: string; id_token: string; refresh_token?: string }
  const session = await (await app.request(`${ISSUER}/api/auth/session`, { headers: { cookie } })).json() as { id: string }
  return {
    cookie,
    userId: session.id,
    accessToken: body.access_token,
    idToken: body.id_token,
    idClaims: decodePayload(body.id_token),
    refreshToken: body.refresh_token ?? null,
  }
}

/** The JWT payload, decoded (verification is the legs' explicit act). */
function decodePayload(token: string): Record<string, unknown> {
  const part = token.split('.')[1]!
  const b64 = part.replace(/-/g, '+').replace(/_/g, '/')
  return JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(b64), ch => ch.charCodeAt(0)))) as Record<string, unknown>
}

/** The audit chain's rows of one action (the store's own read — the
 *  console's activity feeds ride the same table). */
async function auditRows(action: string): Promise<Array<Record<string, unknown>>> {
  const rows = await store.listEntities('auditEvents')
  return rows
    .map(r => JSON.parse(r.data) as Record<string, unknown>)
    .filter(r => r.action === action)
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
    // The PUBLIC application client (the spec's driver — an SPA with
    // PKCE, no secret).
    { client_id: PLAIN_ID, name: 'A public SPA', redirect_uris: [PLAIN_REDIRECT] },
    // The machine cone's fixture (the introspection JWT half + the
    // refresh refusal).
    {
      client_id: DEVICE_ID,
      name: 'The LC-500 twin',
      class: 'device',
      secret: DEVICE_SECRET,
      device: { id: 'acme-lc500-sn-0001', org: 'mfr-acme', instrument_model: 'acme-lc500@2021' },
    },
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
  const root = new Hono()
  root.route('/api/auth', createAuthLeanRouter({ autoSeedDemo: true }))
  root.route('/', createOpRouter())
  root.route('/', createOpGrantsRouter())
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

describe('the discovery document (the wave-C growth)', () => {
  it('declares the refresh grant, offline_access, and the two endpoints', async () => {
    const doc = await (await app.request(`${ISSUER}/.well-known/openid-configuration`)).json() as Record<string, unknown>
    expect(doc.grant_types_supported).toContain('refresh_token')
    expect(doc.grant_types_supported).toContain('authorization_code')
    expect(doc.scopes_supported).toContain('offline_access')
    expect(doc.revocation_endpoint).toBe(`${ISSUER}/op/revoke`)
    expect(doc.introspection_endpoint).toBe(`${ISSUER}/op/introspect`)
  })
})

describe('the code exchange’s offline half', () => {
  it('a granted offline_access mints the first refresh token of a family; without it, none', async () => {
    const offline = await signInAndExchange('ia@oiml.org', 'openid profile email offline_access', { id: HUB_ID, redirect: HUB_REDIRECT, secret: HUB_SECRET })
    expect(offline.refreshToken, 'the offline grant carries the refresh token').toBeTruthy()
    expect(typeof offline.idClaims.auth_time, 'the authentication instant rides the ID token').toBe('number')

    const online = await signInAndExchange('ia@oiml.org', 'openid profile email', { id: HUB_ID, redirect: HUB_REDIRECT, secret: HUB_SECRET })
    expect(online.refreshToken, 'no offline ask, no refresh token').toBeNull()
  })
})

describe('the refresh grant', () => {
  it('rotates: the presented token consumes, the successor mints in the family, the ID token proves the ORIGINAL auth_time', async () => {
    const first = await signInAndExchange('tl@oiml.org', 'openid profile email offline_access', { id: HUB_ID, redirect: HUB_REDIRECT, secret: HUB_SECRET })
    const original = first.idClaims.auth_time as number
    await new Promise(r => setTimeout(r, 1_100)) // cross a second boundary (auth_time is seconds-precision)

    const rotated = await refresh({ token: first.refreshToken!, clientId: HUB_ID, secret: HUB_SECRET })
    expect(rotated.status, 'the rotation exchanges').toBe(200)
    const body = await rotated.json() as { access_token: string; id_token: string; refresh_token: string; scope: string }
    expect(body.refresh_token, 'the successor differs').not.toBe(first.refreshToken)
    expect(body.access_token, 'a fresh access token').not.toBe(first.accessToken)
    expect(body.scope, 'the full granted set when no narrowing was asked').toBe('email offline_access openid profile')

    const claims = decodePayload(body.id_token)
    expect(claims.auth_time, 'the ORIGINAL authentication instant — never the refresh’s moment').toBe(original)
    expect((claims.iat as number) > original, 'the issuance is the refresh’s own moment').toBe(true)
    expect(claims.aud).toBe(HUB_ID)
    expect(claims.email).toBe('tl@oiml.org')

    // The presented token is spent (the one-time doctrine).
    const replay = await refresh({ token: first.refreshToken!, clientId: HUB_ID, secret: HUB_SECRET })
    expect(replay.status).toBe(400)
    // …and that replay was the REUSE verdict — the family died: the
    // SUCCESSOR refuses too (the theft signal's blast radius).
    const successor = await refresh({ token: body.refresh_token, clientId: HUB_ID, secret: HUB_SECRET })
    expect(successor.status, 'the reuse killed the whole family').toBe(400)
    expect(((await successor.json()) as { error: string }).error).toBe('invalid_grant')

    // The audit chain carries both the refresh and the reuse (never the
    // token values).
    const refreshed = await auditRows('client.token_refreshed')
    expect(refreshed.some(r => (r.metadata as { family?: string }).family !== undefined), 'the refresh named the family').toBe(true)
    const reuse = await auditRows('client.refresh_reuse_detected')
    expect(reuse.length, 'the reuse verdict landed on the chain').toBe(1)
    expect((reuse[0]!.metadata as { account?: string }).account).toBe(first.userId)
    expect(JSON.stringify(reuse[0])).not.toContain(first.refreshToken!)
  })

  it('the PUBLIC client refreshes on PKCE standing alone (the spec’s driver)', async () => {
    const first = await signInAndExchange('viewer@oiml.org', 'openid offline_access', { id: PLAIN_ID, redirect: PLAIN_REDIRECT })
    expect(first.refreshToken).toBeTruthy()
    const rotated = await refresh({ token: first.refreshToken!, clientId: PLAIN_ID })
    expect(rotated.status, 'no secret — the client_id binds, the token is the possession proof').toBe(200)
    const body = await rotated.json() as { refresh_token: string }
    expect(body.refresh_token).not.toBe(first.refreshToken)
  })

  it('the cross-client present burns the token (fail toward invalidation) and the holder’s retry dies of the reuse verdict', async () => {
    const first = await signInAndExchange('cs@oiml.org', 'openid offline_access', { id: HUB_ID, redirect: HUB_REDIRECT, secret: HUB_SECRET })
    // PLAIN presents HUB's token: the consume already burned it — the
    // answer refuses, and the legitimate holder's retry reads the reuse
    // verdict (the family dies).
    const foreign = await refresh({ token: first.refreshToken!, clientId: PLAIN_ID })
    expect(foreign.status).toBe(400)
    expect(((await foreign.json()) as { error: string }).error).toBe('invalid_grant')
    const holder = await refresh({ token: first.refreshToken!, clientId: HUB_ID, secret: HUB_SECRET })
    expect(holder.status, 'the burned token’s re-present is the reuse signal').toBe(400)
  })

  it('the machine classes never refresh — refused before any consume', async () => {
    const res = await refresh({ token: 'whatever', clientId: DEVICE_ID, secret: DEVICE_SECRET })
    expect(res.status).toBe(400)
    expect(((await res.json()) as { error: string }).error).toBe('unsupported_grant_type')
  })

  it('a deactivated account’s grant refuses honestly', async () => {
    const first = await signInAndExchange('mc@oiml.org', 'openid offline_access', { id: HUB_ID, redirect: HUB_REDIRECT, secret: HUB_SECRET })
    await store.setUserActive(first.userId, false)
    try {
      const res = await refresh({ token: first.refreshToken!, clientId: HUB_ID, secret: HUB_SECRET })
      expect(res.status).toBe(400)
      expect(((await res.json()) as { error: string }).error).toBe('invalid_grant')
    } finally {
      await store.setUserActive(first.userId, true)
    }
  })

  it('RFC 6749 §6’s narrowing: a subset narrows BOTH halves and never widens back; a superset refuses', async () => {
    const first = await signInAndExchange('biml@oiml.org', 'openid profile email offline_access', { id: HUB_ID, redirect: HUB_REDIRECT, secret: HUB_SECRET })

    // The superset ask refuses (never a silent mint past the grant). The
    // consume runs BEFORE the narrowing math (the kernel's one-read-path
    // doctrine — the present is the read), so the refused ask burned the
    // token: the retry of the SAME token reads the reuse verdict and the
    // family dies. Fail toward invalidation, pinned.
    const wider = await refresh({ token: first.refreshToken!, clientId: HUB_ID, secret: HUB_SECRET, scope: 'openid profile email offline_access groups' })
    expect(wider.status).toBe(400)
    expect(((await wider.json()) as { error: string }).error).toBe('invalid_scope')
    const retry = await refresh({ token: first.refreshToken!, clientId: HUB_ID, secret: HUB_SECRET, scope: 'openid' })
    expect(retry.status, 'the refused ask consumed the token — the retry reads reuse').toBe(400)

    // The clean narrowing arc on a fresh grant: subset → both halves
    // narrow → the rotated row never widens back.
    const second = await signInAndExchange('rc@oiml.org', 'openid profile email offline_access', { id: HUB_ID, redirect: HUB_REDIRECT, secret: HUB_SECRET })
    const narrowed = await refresh({ token: second.refreshToken!, clientId: HUB_ID, secret: HUB_SECRET, scope: 'openid profile' })
    expect(narrowed.status).toBe(200)
    const narrowedBody = await narrowed.json() as { access_token: string; refresh_token: string; scope: string }
    expect(narrowedBody.scope).toBe('openid profile')
    const narrowedAccess = await introspect({ token: narrowedBody.access_token, clientId: HUB_ID, secret: HUB_SECRET })
    expect(((await narrowedAccess.json()) as { scope?: string }).scope, 'the access token carries the narrowed set').toBe('openid profile')
    const widenBack = await refresh({ token: narrowedBody.refresh_token, clientId: HUB_ID, secret: HUB_SECRET, scope: 'openid profile email' })
    expect(widenBack.status, 'the narrowed row never widens back').toBe(400)
    expect(((await widenBack.json()) as { error: string }).error).toBe('invalid_scope')
  })
})

describe('the revocation endpoint (RFC 7009)', () => {
  it('revokes client-bound with the 200-indistinguishable answer; the wrong hint still revokes; a foreign client kills nothing', async () => {
    const grant = await signInAndExchange('ia@oiml.org', 'openid profile offline_access', { id: HUB_ID, redirect: HUB_REDIRECT, secret: HUB_SECRET })

    // The ACCESS half: revoked → userinfo 401s, introspection inactive.
    const accessRevoke = await revoke({ token: grant.accessToken, clientId: HUB_ID, secret: HUB_SECRET, hint: 'access_token' })
    expect(accessRevoke.status).toBe(200)
    const userinfo = await app.request(`${ISSUER}/op/userinfo`, { headers: { authorization: `Bearer ${grant.accessToken}` } })
    expect(userinfo.status, 'the revoked access token never resolves userinfo').toBe(401)

    // The REFRESH half with the WRONG hint (the RFC's search extension):
    // still revokes — the family dies.
    const wrongHint = await revoke({ token: grant.refreshToken!, clientId: HUB_ID, secret: HUB_SECRET, hint: 'access_token' })
    expect(wrongHint.status).toBe(200)
    const dead = await refresh({ token: grant.refreshToken!, clientId: HUB_ID, secret: HUB_SECRET })
    expect(dead.status, 'the revoked family never rotates again').toBe(400)

    // The FOREIGN client's revoke: 200 (the indistinguishability) — and
    // the family STANDS.
    const standing = await signInAndExchange('tl@oiml.org', 'openid offline_access', { id: HUB_ID, redirect: HUB_REDIRECT, secret: HUB_SECRET })
    const foreign = await revoke({ token: standing.refreshToken!, clientId: PLAIN_ID })
    expect(foreign.status).toBe(200)
    const alive = await refresh({ token: standing.refreshToken!, clientId: HUB_ID, secret: HUB_SECRET })
    expect(alive.status, 'the foreign revoke killed nothing').toBe(200)

    // The unknown token answers the same 200; the missing token is the
    // honest 400; the unauthenticated call refuses.
    expect((await revoke({ token: 'never-minted', clientId: HUB_ID, secret: HUB_SECRET })).status).toBe(200)
    const noToken = await app.request(`${ISSUER}/op/revoke`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', authorization: clientBasic(HUB_ID, HUB_SECRET) },
      body: 'client_id=hub-instance',
    })
    expect(noToken.status).toBe(400)
    const noAuth = await app.request(`${ISSUER}/op/revoke`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: 'token=whatever',
    })
    expect(noAuth.status).toBe(401)

    // The audit chain names the kinds found (never the token values).
    const revoked = await auditRows('client.token_revoked')
    const kinds = revoked.map(r => (r.metadata as { kind?: string }).kind)
    expect(kinds).toContain('access')
    expect(kinds).toContain('refresh')
    expect(kinds).toContain('unknown')
  })

  it('the consent console’s "Revoke access" carries the offline half out with it', async () => {
    const grant = await signInAndExchange('cs@oiml.org', 'openid offline_access', { id: HUB_ID, redirect: HUB_REDIRECT, secret: HUB_SECRET })
    const grants = await (await app.request(`${ISSUER}/api/op/account/grants`, { headers: { cookie: grant.cookie } })).json() as { grants: Array<{ id: string; clientId: string }> }
    const row = grantGrant(grants, HUB_ID)
    expect(row, 'the grant lists').toBeTruthy()
    const del = await app.request(`${ISSUER}/api/op/account/grants/${row!.id}`, { method: 'DELETE', headers: { cookie: grant.cookie } })
    expect(del.status).toBe(200)
    const dead = await refresh({ token: grant.refreshToken!, clientId: HUB_ID, secret: HUB_SECRET })
    expect(dead.status, 'the offline half died with the consent').toBe(400)
    // …and the audit named the count.
    const rows = await auditRows('account.consent_revoked')
    const last = rows[rows.length - 1]!
    expect((last.metadata as { refreshTokens?: number }).refreshTokens, 'the count on the chain').toBeGreaterThanOrEqual(1)
  })
})

/** The grant row for one client (the console list's shape — the row
 *  carries clientId, server/auth/op/grants.ts's consentGrantRow). */
function grantGrant(list: { grants: Array<{ id: string; clientId: string }> }, clientId: string) {
  return list.grants.find(g => g.clientId === clientId)
}

describe('the introspection endpoint (RFC 7662)', () => {
  it('the opaque half: a live access token answers active + the claim set; revoked and unknown answer inactive', async () => {
    const grant = await signInAndExchange('ia@oiml.org', 'openid profile offline_access', { id: HUB_ID, redirect: HUB_REDIRECT, secret: HUB_SECRET })
    const live = await introspect({ token: grant.accessToken, clientId: HUB_ID, secret: HUB_SECRET })
    expect(live.status).toBe(200)
    const body = await live.json() as Record<string, unknown>
    expect(body.active).toBe(true)
    expect(body.iss).toBe(ISSUER)
    expect(body.sub).toBe(grant.userId)
    expect(body.aud).toBe(HUB_ID)
    expect(body.client_id).toBe(HUB_ID)
    expect(body.scope, 'the access row carries the granting request’s scope verbatim (the pre-wave-C surface)').toBe('openid profile offline_access')
    expect(body.token_type).toBe('Bearer')
    expect(typeof body.exp, 'the epoch expiry').toBe('number')

    // A REFRESH token introspects inactive (the surface's named scope —
    // the refresh rows serve the token endpoint's rotation only).
    const refreshProbe = await introspect({ token: grant.refreshToken!, clientId: HUB_ID, secret: HUB_SECRET })
    expect(((await refreshProbe.json()) as { active: boolean }).active).toBe(false)

    // After revocation, the honest inactive.
    await revoke({ token: grant.accessToken, clientId: HUB_ID, secret: HUB_SECRET })
    const after = await introspect({ token: grant.accessToken, clientId: HUB_ID, secret: HUB_SECRET })
    expect(((await after.json()) as { active: boolean }).active).toBe(false)

    // The unknown present.
    const unknown = await introspect({ token: 'never-minted', clientId: HUB_ID, secret: HUB_SECRET })
    expect(((await unknown.json()) as { active: boolean }).active).toBe(false)

    // The unauthenticated call refuses; the missing token is the 400.
    const noAuth = await app.request(`${ISSUER}/op/introspect`, {
      method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: 'token=whatever',
    })
    expect(noAuth.status).toBe(401)
    const noToken = await app.request(`${ISSUER}/op/introspect`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', authorization: clientBasic(HUB_ID, HUB_SECRET) },
      body: 'client_id=hub-instance',
    })
    expect(noToken.status).toBe(400)
  })

  it('the machine half: the self-contained JWT answers through the signature + the named client’s LIVE standing', async () => {
    // Mint the device JWT (the machine cone's own grant).
    const minted = await app.request(`${ISSUER}/op/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', authorization: clientBasic(DEVICE_ID, DEVICE_SECRET) },
      body: 'grant_type=client_credentials',
    })
    expect(minted.status).toBe(200)
    const { access_token: machineToken } = await minted.json() as { access_token: string }

    // Active through the SIGNATURE — never a table read (there are no
    // rows for the machine tokens).
    const live = await introspect({ token: machineToken, clientId: HUB_ID, secret: HUB_SECRET })
    const liveBody = await live.json() as Record<string, unknown>
    expect(liveBody.active, 'the device JWT introspects active').toBe(true)
    expect(liveBody.sub).toBe('acme-lc500-sn-0001')
    expect(liveBody.aud).toBe(DEVICE_ID)
    expect(liveBody.token_type).toBe('Bearer')

    // The standing re-judgment: DISABLE the client and the in-flight
    // token goes inactive (the revocation story the rows never had);
    // re-enable and it stands again.
    await store.setOidcClientStatus(DEVICE_ID, 'disabled')
    try {
      const disabled = await introspect({ token: machineToken, clientId: HUB_ID, secret: HUB_SECRET })
      expect(((await disabled.json()) as { active: boolean }).active, 'the disabled client’s token is inactive').toBe(false)
    } finally {
      await store.setOidcClientStatus(DEVICE_ID, 'active')
    }
    const restored = await introspect({ token: machineToken, clientId: HUB_ID, secret: HUB_SECRET })
    expect(((await restored.json()) as { active: boolean }).active).toBe(true)

    // A FOREIGN-signed JWT (three segments, no keyset kid) reads inactive.
    const foreign = `${btoa('{"alg":"ES256","kid":"nobody"}')}.${btoa('{"iss":"http://op.test","sub":"x","exp":9999999999}')}.${btoa('forged')}`
    const forged = await introspect({ token: foreign, clientId: HUB_ID, secret: HUB_SECRET })
    expect(((await forged.json()) as { active: boolean }).active).toBe(false)
  })
})
