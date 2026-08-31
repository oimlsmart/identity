// ─────────────────────────────────────────────────────────────────────
// TODO.identity/01 — the OIDC Provider core, proven in-process: the
// REAL op router (server/routes/op.ts) over a REAL temp SQLite store,
// with the RP's REAL validation path (@oimlsmart/platform-server/oidc's
// validateIdToken — the code our instances run) consuming the OP's ID
// token against the OP's own JWKS. NO stub on either side: the round
// trip is real.
//
// Covered:
//   the discovery document's shape          the client registry's refusals
//   the JWKS key set (ES256, kid)           (unknown client, unregistered
//   authorize → consent → code → token      redirect_uri, disabled client)
//   → userinfo, validated by the RP         one-time codes (replay loses)
//   PKCE verify (wrong verifier loses)      the per-client claims policy
//   the sign-in redirect (no session)       the module gate (a non-identity
//   consent deny (access_denied)            profile answers 404)
//   the registry's admin surface            the public avatar serve (the
//   the picture claim (policy + avatar)     upload / the initials / the 404)
// ─────────────────────────────────────────────────────────────────────

import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

// The store's DB path is read at module evaluation — set it before any
// import below touches @oimlsmart/platform-server/store/sqlite (the imports are dynamic).
const TMP = mkdtempSync(join(tmpdir(), 'oiml-op-core-'))
process.env.DATABASE_PATH = join(TMP, 'test.db')

const ISSUER = 'http://op.test'
process.env.OP_ISSUER = ISSUER

// The registry's bootstrap seed: a confidential client carrying the
// role-claim policy (the hub instance's shape) and a public client
// without one (PKCE only).
const CONFIDENTIAL = {
  client_id: 'hub-instance',
  name: 'OIML SMART platform hub',
  secret: 'hub-secret-123',
  redirect_uris: ['https://hub.example/api/auth/callback/oidc'],
  claims_policy: { claims: ['roles', 'groups', 'org'] },
}
const PUBLIC = {
  client_id: 'tl-public',
  name: 'Example TL instance',
  redirect_uris: ['http://tl.example/callback'],
}
process.env.OP_CLIENT_SEED = JSON.stringify([CONFIDENTIAL, PUBLIC])

let app: import('hono').Hono
let store: ReturnType<typeof import('@oimlsmart/platform-server/store').getStore>
let validateIdToken: typeof import('@oimlsmart/platform-server/oidc').validateIdToken
let generatePkce: typeof import('@oimlsmart/platform-server/oidc').generatePkce
let installIdentityProfile: () => void
let resetProfile: () => void

/** The fetch adapter the RP's validator runs against: the in-process
 *  app itself (discovery/JWKS ride the real routes). */
const appFetch = (async (input: RequestInfo | URL): Promise<Response> => {
  const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url
  return app.request(url)
}) as typeof fetch

interface AuthorizeResult {
  consent: { id: string; client: { id: string; name: string }; scopes: string[]; policyClaims: string[]; account: { name: string; email: string } }
  code: string
  state: string | null
  redirect: string
}

/** Drive authorize → consent-context → decide; answers the minted code
 *  (allow) or null (deny). */
async function driveAuthorize(
  cookie: string,
  params: { clientId: string; redirectUri: string; scope?: string; state?: string; nonce?: string; challenge: string },
  decision: 'allow' | 'deny' = 'allow',
): Promise<AuthorizeResult | { denied: true; redirect: string }> {
  const query = new URLSearchParams({
    response_type: 'code',
    client_id: params.clientId,
    redirect_uri: params.redirectUri,
    scope: params.scope ?? 'openid profile email',
    state: params.state ?? 'st-1',
    nonce: params.nonce ?? 'nn-1',
    code_challenge: params.challenge,
    code_challenge_method: 'S256',
    // The consent flow's driver forces the page (TODO.identity-features/12:
    // a remembered grant would skip it — the grant arc has its own suite,
    // id-consent-grants.test.ts).
    prompt: 'consent',
  })
  const authorize = await app.request(`${ISSUER}/op/authorize?${query}`, { headers: { cookie } })
  expect(authorize.status, 'authorize redirects to the consent page').toBe(302)
  const consentUrl = new URL(authorize.headers.get('location')!, ISSUER)
  expect(consentUrl.pathname).toBe('/op/consent')
  const authId = consentUrl.searchParams.get('auth')!

  const context = await app.request(`${ISSUER}/api/op/consent/${authId}`, { headers: { cookie } })
  expect(context.status, 'the consent context answers').toBe(200)
  const consent = await context.json() as AuthorizeResult['consent']

  const decide = await app.request(`${ISSUER}/api/op/consent/${authId}/decide`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', cookie },
    body: JSON.stringify({ decision }),
  })
  expect(decide.status, 'the decision records').toBe(200)
  const { redirect } = await decide.json() as { redirect: string }
  const back = new URL(redirect)
  if (decision === 'deny') return { denied: true, redirect }
  const code = back.searchParams.get('code')
  expect(code, 'the allow decision carries a code').toBeTruthy()
  return { consent, code: code!, state: back.searchParams.get('state'), redirect }
}

/** The token exchange, the RP's two authentication postures. */
async function exchange(
  params: { code: string; redirectUri: string; clientId: string; verifier: string; secret?: string },
): Promise<Response> {
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
  // The simulated deployment declares its signing key (identity#7's
  // registration gate: a declared-issuer instance never registers a
  // GENERATED development key into oidc_keys — the round trips below
  // validate against the JWKS, so the served key must be the declared
  // one, exactly the production posture).
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
  validateIdToken = oidc.validateIdToken
  generatePkce = oidc.generatePkce
  oidc.clearOidcCaches()

  const { Hono } = await import('hono')
  const { createAuthLeanRouter } = await import('../../server/routes/auth-lean')
  const { createOpRouter } = await import('../../server/routes/op')
  const root = new Hono()
  root.route('/api/auth', createAuthLeanRouter({ autoSeedDemo: true }))
  root.route('/', createOpRouter())
  app = root

  // The bootstrap seed lands on the first OP request; drive it once.
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

describe('the discovery document', () => {
  it('matches the served endpoints', async () => {
    const res = await app.request(`${ISSUER}/.well-known/openid-configuration`)
    expect(res.status).toBe(200)
    const meta = await res.json() as Record<string, unknown>
    expect(meta.issuer).toBe(ISSUER)
    expect(meta.authorization_endpoint).toBe(`${ISSUER}/op/authorize`)
    expect(meta.token_endpoint).toBe(`${ISSUER}/op/token`)
    expect(meta.userinfo_endpoint).toBe(`${ISSUER}/op/userinfo`)
    expect(meta.jwks_uri).toBe(`${ISSUER}/jwks.json`)
    expect(meta.response_types_supported).toEqual(['code'])
    expect(meta.id_token_signing_alg_values_supported).toEqual(['ES256'])
    expect(meta.code_challenge_methods_supported).toEqual(['S256'])
    expect(meta.subject_types_supported).toEqual(['public'])
    expect(meta.claims_supported).toContain('picture')
  })

  it('serves the JWKS: one ES256 key with a kid', async () => {
    const res = await app.request(`${ISSUER}/jwks.json`)
    expect(res.status).toBe(200)
    const { keys } = await res.json() as { keys: Array<Record<string, unknown>> }
    expect(keys.length).toBe(1)
    expect(keys[0]).toMatchObject({ kty: 'EC', crv: 'P-256', alg: 'ES256', use: 'sig' })
    expect(typeof keys[0]!.kid).toBe('string')
    // …and the key is registered in the rotation history.
    const rows = await store.listOidcKeys()
    expect(rows.map(r => r.kid)).toContain(keys[0]!.kid)
  })
})

describe('the full round trip (the RP validator consumes the OP token)', () => {
  it('authorize → consent → code → token → userinfo', async () => {
    const cookie = await demoLogin('ia@oiml.org')
    const pkce = await generatePkce()

    const result = await driveAuthorize(cookie, {
      clientId: CONFIDENTIAL.client_id,
      redirectUri: CONFIDENTIAL.redirect_uris[0]!,
      state: 'state-abc',
      nonce: 'nonce-xyz',
      challenge: pkce.challenge,
    }) as AuthorizeResult

    // The consent context: the client's name, the scopes, the account.
    expect(result.consent.client.name).toBe('OIML SMART platform hub')
    expect(result.consent.scopes).toEqual(['openid', 'profile', 'email'])
    expect(result.consent.policyClaims).toEqual(['roles', 'groups', 'org'])
    expect(result.consent.account.email).toBe('ia@oiml.org')
    expect(result.state).toBe('state-abc')
    expect(new URL(result.redirect).origin + new URL(result.redirect).pathname).toBe(CONFIDENTIAL.redirect_uris[0])

    // The code exchange (client_secret_basic, the RP's confidential posture).
    const token = await exchange({
      code: result.code,
      redirectUri: CONFIDENTIAL.redirect_uris[0]!,
      clientId: CONFIDENTIAL.client_id,
      verifier: pkce.verifier,
      secret: CONFIDENTIAL.secret,
    })
    expect(token.status, 'the code exchange').toBe(200)
    const tokens = await token.json() as { id_token: string; access_token: string; token_type: string; expires_in: number }
    expect(tokens.token_type).toBe('Bearer')

    // THE INTEROP PROOF: the RP's real validator accepts the OP's ID
    // token against the OP's own JWKS.
    const claims = await validateIdToken(tokens.id_token, {
      issuer: ISSUER,
      clientId: CONFIDENTIAL.client_id,
      nonce: 'nonce-xyz',
      jwksUri: `${ISSUER}/jwks.json`,
    }, appFetch)
    expect(claims.iss).toBe(ISSUER)
    expect(claims.aud).toBe(CONFIDENTIAL.client_id)
    expect(claims.email).toBe('ia@oiml.org')
    expect(claims.name).toBe('IA Officer')
    // The client's claims policy drives the role claims.
    expect(claims.roles).toEqual(['ia_officer'])
    expect(claims.groups).toEqual(['ia_officer'])
    expect(claims.org).toBe('EX1')

    // userinfo answers the same account's claims.
    const userinfo = await app.request(`${ISSUER}/op/userinfo`, {
      headers: { authorization: `Bearer ${tokens.access_token}` },
    })
    expect(userinfo.status).toBe(200)
    expect(await userinfo.json()).toMatchObject({
      sub: claims.sub,
      email: 'ia@oiml.org',
      name: 'IA Officer',
      roles: ['ia_officer'],
      org: 'EX1',
    })
  })

  it('a public client (no secret) exchanges with PKCE alone, and carries NO role claims', async () => {
    const cookie = await demoLogin('tl@oiml.org')
    const pkce = await generatePkce()
    const result = await driveAuthorize(cookie, {
      clientId: PUBLIC.client_id,
      redirectUri: PUBLIC.redirect_uris[0]!,
      nonce: 'pub-nonce',
      challenge: pkce.challenge,
    }) as AuthorizeResult
    expect(result.consent.policyClaims).toEqual([])

    const token = await exchange({
      code: result.code,
      redirectUri: PUBLIC.redirect_uris[0]!,
      clientId: PUBLIC.client_id,
      verifier: pkce.verifier,
    })
    expect(token.status).toBe(200)
    const tokens = await token.json() as { id_token: string }
    const claims = await validateIdToken(tokens.id_token, {
      issuer: ISSUER,
      clientId: PUBLIC.client_id,
      nonce: 'pub-nonce',
      jwksUri: `${ISSUER}/jwks.json`,
    }, appFetch)
    expect(claims.email).toBe('tl@oiml.org')
    // The claims policy is a per-client privilege: no policy, no roles.
    expect(claims.roles).toBeUndefined()
    expect(claims.groups).toBeUndefined()
    expect(claims.org).toBeUndefined()
    expect(claims.picture).toBeUndefined()
  })
})

describe('PKCE + the one-time code', () => {
  it('a wrong verifier loses, and the code is spent either way', async () => {
    const cookie = await demoLogin('ia@oiml.org')
    const pkce = await generatePkce()
    const result = await driveAuthorize(cookie, {
      clientId: CONFIDENTIAL.client_id,
      redirectUri: CONFIDENTIAL.redirect_uris[0]!,
      challenge: pkce.challenge,
    }) as AuthorizeResult

    const wrong = await exchange({
      code: result.code,
      redirectUri: CONFIDENTIAL.redirect_uris[0]!,
      clientId: CONFIDENTIAL.client_id,
      verifier: 'wrong-verifier',
      secret: CONFIDENTIAL.secret,
    })
    expect(wrong.status).toBe(400)
    expect(await wrong.json()).toMatchObject({ error: 'invalid_grant' })

    // One-time means one-time: the RIGHT verifier after the failed
    // attempt still loses (the code died with the attempt).
    const retry = await exchange({
      code: result.code,
      redirectUri: CONFIDENTIAL.redirect_uris[0]!,
      clientId: CONFIDENTIAL.client_id,
      verifier: pkce.verifier,
      secret: CONFIDENTIAL.secret,
    })
    expect(retry.status).toBe(400)
    expect(await retry.json()).toMatchObject({ error: 'invalid_grant' })
  })

  it('a replayed code is refused', async () => {
    const cookie = await demoLogin('ia@oiml.org')
    const pkce = await generatePkce()
    const result = await driveAuthorize(cookie, {
      clientId: CONFIDENTIAL.client_id,
      redirectUri: CONFIDENTIAL.redirect_uris[0]!,
      challenge: pkce.challenge,
    }) as AuthorizeResult
    const first = await exchange({
      code: result.code, redirectUri: CONFIDENTIAL.redirect_uris[0]!,
      clientId: CONFIDENTIAL.client_id, verifier: pkce.verifier, secret: CONFIDENTIAL.secret,
    })
    expect(first.status).toBe(200)
    const replay = await exchange({
      code: result.code, redirectUri: CONFIDENTIAL.redirect_uris[0]!,
      clientId: CONFIDENTIAL.client_id, verifier: pkce.verifier, secret: CONFIDENTIAL.secret,
    })
    expect(replay.status).toBe(400)
    expect(await replay.json()).toMatchObject({ error: 'invalid_grant' })
  })

  it('a wrong client secret is refused before the code is touched', async () => {
    const cookie = await demoLogin('ia@oiml.org')
    const pkce = await generatePkce()
    const result = await driveAuthorize(cookie, {
      clientId: CONFIDENTIAL.client_id,
      redirectUri: CONFIDENTIAL.redirect_uris[0]!,
      challenge: pkce.challenge,
    }) as AuthorizeResult
    const bad = await exchange({
      code: result.code, redirectUri: CONFIDENTIAL.redirect_uris[0]!,
      clientId: CONFIDENTIAL.client_id, verifier: pkce.verifier, secret: 'not-the-secret',
    })
    expect(bad.status).toBe(401)
    expect(await bad.json()).toMatchObject({ error: 'invalid_client' })
  })
})

describe('the client registry', () => {
  it('an unknown client_id is refused in place (never a redirect)', async () => {
    const pkce = await generatePkce()
    const query = new URLSearchParams({
      response_type: 'code', client_id: 'ghost', redirect_uri: 'https://ghost.example/cb',
      scope: 'openid', state: 's', nonce: 'n', code_challenge: pkce.challenge, code_challenge_method: 'S256',
    })
    const res = await app.request(`${ISSUER}/op/authorize?${query}`)
    expect(res.status).toBe(400)
    expect(res.headers.get('location')).toBeNull()
    expect(await res.text()).toContain('not registered')
  })

  it('an unregistered redirect_uri is refused in place (the open-redirect wall)', async () => {
    const pkce = await generatePkce()
    const query = new URLSearchParams({
      response_type: 'code', client_id: CONFIDENTIAL.client_id, redirect_uri: 'https://evil.example/steal',
      scope: 'openid', state: 's', nonce: 'n', code_challenge: pkce.challenge, code_challenge_method: 'S256',
    })
    const res = await app.request(`${ISSUER}/op/authorize?${query}`)
    expect(res.status).toBe(400)
    expect(res.headers.get('location')).toBeNull()
  })

  it('a disabled client is refused at authorize', async () => {
    await store.setOidcClientStatus(PUBLIC.client_id, 'disabled')
    try {
      const pkce = await generatePkce()
      const query = new URLSearchParams({
        response_type: 'code', client_id: PUBLIC.client_id, redirect_uri: PUBLIC.redirect_uris[0]!,
        scope: 'openid', state: 's', nonce: 'n', code_challenge: pkce.challenge, code_challenge_method: 'S256',
      })
      const res = await app.request(`${ISSUER}/op/authorize?${query}`)
      expect(res.status).toBe(400)
    } finally {
      await store.setOidcClientStatus(PUBLIC.client_id, 'active')
    }
  })

  it('a missing openid scope redirects back with invalid_scope (the registered URI)', async () => {
    const pkce = await generatePkce()
    const query = new URLSearchParams({
      response_type: 'code', client_id: CONFIDENTIAL.client_id, redirect_uri: CONFIDENTIAL.redirect_uris[0]!,
      scope: 'profile', state: 'st-9', nonce: 'n', code_challenge: pkce.challenge, code_challenge_method: 'S256',
    })
    const res = await app.request(`${ISSUER}/op/authorize?${query}`)
    expect(res.status).toBe(302)
    const back = new URL(res.headers.get('location')!)
    expect(back.origin + back.pathname).toBe(CONFIDENTIAL.redirect_uris[0])
    expect(back.searchParams.get('error')).toBe('invalid_scope')
    expect(back.searchParams.get('state')).toBe('st-9')
  })
})

describe('the sign-in surface + the consent decision', () => {
  it('no session → the login page with the authorize URL as the destination', async () => {
    const pkce = await generatePkce()
    const query = new URLSearchParams({
      response_type: 'code', client_id: CONFIDENTIAL.client_id, redirect_uri: CONFIDENTIAL.redirect_uris[0]!,
      scope: 'openid', state: 's', nonce: 'n', code_challenge: pkce.challenge, code_challenge_method: 'S256',
    })
    const res = await app.request(`${ISSUER}/op/authorize?${query}`)
    expect(res.status).toBe(302)
    const login = new URL(res.headers.get('location')!, ISSUER)
    expect(login.pathname).toBe('/')
    const redirect = login.searchParams.get('redirect')!
    expect(redirect.startsWith('/op/authorize?')).toBe(true)
    expect(redirect).toContain(`client_id=${CONFIDENTIAL.client_id}`)
  })

  it('deny returns error=access_denied to the RP, and no code', async () => {
    const cookie = await demoLogin('ia@oiml.org')
    const pkce = await generatePkce()
    const result = await driveAuthorize(cookie, {
      clientId: CONFIDENTIAL.client_id,
      redirectUri: CONFIDENTIAL.redirect_uris[0]!,
      state: 'deny-state',
      challenge: pkce.challenge,
    }, 'deny')
    expect('denied' in result && result.denied).toBe(true)
    const back = new URL((result as { redirect: string }).redirect)
    expect(back.searchParams.get('error')).toBe('access_denied')
    expect(back.searchParams.get('state')).toBe('deny-state')
    expect(back.searchParams.get('code')).toBeNull()
  })

  it('a different account cannot decide another account’s consent', async () => {
    const ia = await demoLogin('ia@oiml.org')
    const viewer = await demoLogin('viewer@oiml.org')
    const pkce = await generatePkce()

    const query = new URLSearchParams({
      response_type: 'code', client_id: CONFIDENTIAL.client_id, redirect_uri: CONFIDENTIAL.redirect_uris[0]!,
      scope: 'openid', state: 's', nonce: 'n', code_challenge: pkce.challenge, code_challenge_method: 'S256',
      // The consent page must SHOW for the guard to engage (TODO.identity-features/12:
      // the ia account's earlier allows left a remembered grant covering 'openid').
      prompt: 'consent',
    })
    const authorize = await app.request(`${ISSUER}/op/authorize?${query}`, { headers: { cookie: ia } })
    const authId = new URL(authorize.headers.get('location')!, ISSUER).searchParams.get('auth')!

    // The VIEWER's session against the IA officer's pending row.
    const context = await app.request(`${ISSUER}/api/op/consent/${authId}`, { headers: { cookie: viewer } })
    expect(context.status).toBe(403)
    const decide = await app.request(`${ISSUER}/api/op/consent/${authId}/decide`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: viewer },
      body: JSON.stringify({ decision: 'allow' }),
    })
    expect(decide.status).toBe(400)
  })
})

describe('the registry admin surface', () => {
  it('anonymous and non-admin sessions are refused', async () => {
    const anon = await app.request(`${ISSUER}/api/op/clients`)
    expect(anon.status).toBe(401)
    const viewer = await demoLogin('viewer@oiml.org')
    const notAdmin = await app.request(`${ISSUER}/api/op/clients`, { headers: { cookie: viewer } })
    expect(notAdmin.status).toBe(403)
  })

  it('the admin lists and registers clients (the secret never reads back)', async () => {
    const admin = await demoLogin('admin@oiml.org')
    const list = await app.request(`${ISSUER}/api/op/clients`, { headers: { cookie: admin } })
    expect(list.status).toBe(200)
    const clients = await list.json() as Array<{ clientId: string; confidential: boolean }>
    expect(clients.map(c => c.clientId).sort()).toEqual(['hub-instance', 'tl-public'])
    expect(JSON.stringify(clients)).not.toContain('secret')

    const created = await app.request(`${ISSUER}/api/op/clients`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: admin },
      body: JSON.stringify({
        client_id: 'nmi-instance',
        name: 'Example NMI instance',
        secret: 'nmi-secret',
        redirect_uris: ['https://nmi.example/api/auth/callback/oidc'],
        claims_policy: { claims: ['roles', 'org'] },
      }),
    })
    expect(created.status).toBe(201)
    expect(await created.json()).toMatchObject({ clientId: 'nmi-instance', confidential: true, status: 'active' })

    // The registered client round-trips: authorize → token with its secret.
    const cookie = await demoLogin('ia@oiml.org')
    const pkce = await generatePkce()
    const result = await driveAuthorize(cookie, {
      clientId: 'nmi-instance',
      redirectUri: 'https://nmi.example/api/auth/callback/oidc',
      challenge: pkce.challenge,
    }) as AuthorizeResult
    const token = await exchange({
      code: result.code, redirectUri: 'https://nmi.example/api/auth/callback/oidc',
      clientId: 'nmi-instance', verifier: pkce.verifier, secret: 'nmi-secret',
    })
    expect(token.status).toBe(200)
  })
})

describe('the public avatar route (GET /op/avatar/:id)', () => {
  // A 1x1 transparent PNG (the id-accounts fixture's own bytes), as the
  // ArrayBuffer the BlobStore contract takes.
  const PNG_BUF = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==', 'base64')
  const PNG = PNG_BUF.buffer.slice(PNG_BUF.byteOffset, PNG_BUF.byteOffset + PNG_BUF.byteLength) as ArrayBuffer

  /** The in-memory BlobStore (the id-accounts pattern). */
  function memoryBlobs() {
    const map = new Map<string, { data: ArrayBuffer; contentType: string | null }>()
    return {
      map,
      async put(key: string, data: ArrayBuffer, contentType: string | null) { map.set(key, { data, contentType }) },
      async get(key: string) {
        const hit = map.get(key)
        return hit ? { data: hit.data, contentType: hit.contentType, size: hit.data.byteLength } : null
      },
      async delete(key: string) { map.delete(key) },
    }
  }

  it('serves the stored upload publicly: no session, the real type, nosniff, a short public cache', async () => {
    const { installBlobStore, uninstallBlobStoreForTest } = await import('../../server/blobs')
    const { avatarKey } = await import('../../server/auth/op/avatars')
    const mem = memoryBlobs()
    installBlobStore(mem)
    try {
      const ia = (await store.findUserByEmail('ia@oiml.org'))!
      await mem.put(avatarKey(ia.id, 'image/png'), PNG, 'image/png')
      // NO session cookie — the GitHub-avatars posture.
      const res = await app.request(`${ISSUER}/op/avatar/${ia.id}`)
      expect(res.status).toBe(200)
      expect(res.headers.get('content-type')).toBe('image/png')
      expect(res.headers.get('x-content-type-options')).toBe('nosniff')
      expect(res.headers.get('cache-control')).toBe('public, max-age=300')
      expect(Buffer.from(await res.arrayBuffer()).equals(PNG_BUF)).toBe(true)
    } finally {
      uninstallBlobStoreForTest()
    }
  })

  it('a known account without an upload answers the generated initials (never a broken image)', async () => {
    // NO blob store bound at all: the initials still serve.
    const { uninstallBlobStoreForTest } = await import('../../server/blobs')
    uninstallBlobStoreForTest()
    const ia = (await store.findUserByEmail('ia@oiml.org'))!
    const res = await app.request(`${ISSUER}/op/avatar/${ia.id}`)
    expect(res.status).toBe(200)
    expect(res.headers.get('content-type')).toBe('image/svg+xml')
    expect(res.headers.get('x-content-type-options')).toBe('nosniff')
    expect(res.headers.get('content-security-policy')).toBe("default-src 'none'")
    expect(res.headers.get('cache-control')).toBe('public, max-age=300')
    const svg = await res.text()
    expect(svg).toContain('>IO</text>') // IA Officer's initials, the console's own fallback
  })

  it('an unknown or erased account answers the plain 404 (never an error page, never a tombstone picture)', async () => {
    const { uninstallBlobStoreForTest } = await import('../../server/blobs')
    uninstallBlobStoreForTest()
    const unknown = await app.request(`${ISSUER}/op/avatar/${crypto.randomUUID()}`)
    expect(unknown.status).toBe(404)
    expect(unknown.headers.get('content-type')).toContain('application/json')

    // The erasure's promise: the tombstone never serves, even with a
    // surviving blob row (the store-level erase does not touch blobs).
    const gone = await store.provisionSsoUser({
      email: 'gone@example.org', name: 'Gone User', provider: 'oidc', providerAccountId: 'gone-1', role: 'viewer', orgId: null,
    })
    const { installBlobStore, uninstallBlobStoreForTest: uninstall2 } = await import('../../server/blobs')
    const { avatarKey } = await import('../../server/auth/op/avatars')
    const mem = memoryBlobs()
    installBlobStore(mem)
    try {
      await mem.put(avatarKey(gone.id, 'image/png'), PNG, 'image/png')
      expect((await app.request(`${ISSUER}/op/avatar/${gone.id}`)).status).toBe(200) // live: serves
      await store.eraseOpAccount(gone.id)
      const res = await app.request(`${ISSUER}/op/avatar/${gone.id}`)
      expect(res.status).toBe(404)
      expect(res.headers.get('content-type')).toContain('application/json')
    } finally {
      uninstall2()
    }
  })
})

describe('the picture claim (the per-client family)', () => {
  const PICTURE_RP = {
    client_id: 'rag-instance',
    name: 'OIML SMART AI',
    redirect_uris: ['https://rag.example/callback'],
  }

  it('carries the public avatar URL only with the policy AND an uploaded avatar; userinfo matches', async () => {
    const cookie = await demoLogin('ia@oiml.org')
    const ia = (await store.findUserByEmail('ia@oiml.org'))!
    await store.upsertOidcClient({
      clientId: PICTURE_RP.client_id,
      name: PICTURE_RP.name,
      secretHash: null, // a public client: PKCE is the whole credential
      redirectUris: PICTURE_RP.redirect_uris,
      claimsPolicy: { claims: ['picture'] },
      createdBy: 'test',
    })
    const expectedUrl = `${ISSUER}/op/avatar/${ia.id}`

    try {
      // 1. The family WITHOUT an uploaded avatar: no claim anywhere.
      let pkce = await generatePkce()
      let result = await driveAuthorize(cookie, {
        clientId: PICTURE_RP.client_id, redirectUri: PICTURE_RP.redirect_uris[0]!, challenge: pkce.challenge,
      }) as AuthorizeResult
      expect(result.consent.policyClaims).toEqual(['picture'])
      let token = await exchange({ code: result.code, redirectUri: PICTURE_RP.redirect_uris[0]!, clientId: PICTURE_RP.client_id, verifier: pkce.verifier })
      expect(token.status).toBe(200)
      let tokens = await token.json() as { id_token: string; access_token: string }
      let claims = await validateIdToken(tokens.id_token, { issuer: ISSUER, clientId: PICTURE_RP.client_id, nonce: 'nn-1', jwksUri: `${ISSUER}/jwks.json` }, appFetch)
      expect(claims.picture).toBeUndefined()
      let userinfo = await app.request(`${ISSUER}/op/userinfo`, { headers: { authorization: `Bearer ${tokens.access_token}` } })
      expect((await userinfo.json() as Record<string, unknown>).picture).toBeUndefined()

      // 2. The avatar lands (the upload's marker): the claim appears —
      //    the public route's absolute URL under the issuer.
      await store.setUserAvatar(ia.id, '/api/op/account/avatar')
      pkce = await generatePkce()
      result = await driveAuthorize(cookie, {
        clientId: PICTURE_RP.client_id, redirectUri: PICTURE_RP.redirect_uris[0]!, challenge: pkce.challenge,
      }) as AuthorizeResult
      token = await exchange({ code: result.code, redirectUri: PICTURE_RP.redirect_uris[0]!, clientId: PICTURE_RP.client_id, verifier: pkce.verifier })
      tokens = await token.json() as { id_token: string; access_token: string }
      claims = await validateIdToken(tokens.id_token, { issuer: ISSUER, clientId: PICTURE_RP.client_id, nonce: 'nn-1', jwksUri: `${ISSUER}/jwks.json` }, appFetch)
      expect(claims.picture).toBe(expectedUrl)
      userinfo = await app.request(`${ISSUER}/op/userinfo`, { headers: { authorization: `Bearer ${tokens.access_token}` } })
      expect((await userinfo.json() as Record<string, unknown>).picture).toBe(expectedUrl)

      // 3. A client whose policy lacks the family never receives the
      //    claim — avatar or not (the CONFIDENTIAL client: roles/groups/org).
      pkce = await generatePkce()
      result = await driveAuthorize(cookie, {
        clientId: CONFIDENTIAL.client_id, redirectUri: CONFIDENTIAL.redirect_uris[0]!, challenge: pkce.challenge,
      }) as AuthorizeResult
      token = await exchange({
        code: result.code, redirectUri: CONFIDENTIAL.redirect_uris[0]!,
        clientId: CONFIDENTIAL.client_id, verifier: pkce.verifier, secret: CONFIDENTIAL.secret,
      })
      tokens = await token.json() as { id_token: string; access_token: string }
      claims = await validateIdToken(tokens.id_token, { issuer: ISSUER, clientId: CONFIDENTIAL.client_id, nonce: 'nn-1', jwksUri: `${ISSUER}/jwks.json` }, appFetch)
      expect(claims.roles).toEqual(['ia_officer']) // the policy's own families still land
      expect(claims.picture).toBeUndefined()
      userinfo = await app.request(`${ISSUER}/op/userinfo`, { headers: { authorization: `Bearer ${tokens.access_token}` } })
      expect((await userinfo.json() as Record<string, unknown>).picture).toBeUndefined()
    } finally {
      // The avatar marker never leaks into the other suites' posture.
      await store.setUserAvatar(ia.id, null)
    }
  })
})

describe('the module gate', () => {
  it('a non-identity profile answers 404 on every OP path', async () => {
    resetProfile() // the hub default (no identity module)
    try {
      for (const [method, path] of [
        ['GET', '/.well-known/openid-configuration'],
        ['GET', '/jwks.json'],
        ['GET', '/op/authorize?client_id=x'],
        ['POST', '/op/token'],
        ['GET', '/op/userinfo'],
        ['GET', '/op/avatar/some-account-id'],
        ['GET', '/api/op/clients'],
      ] as const) {
        const res = await app.request(`${ISSUER}${path}`, { method })
        expect(res.status, `${method} ${path}`).toBe(404)
      }
    } finally {
      installIdentityProfile()
    }
  })
})
