// ─────────────────────────────────────────────────────────────────────
// TODO.identity-features/12 — the remembered consent grants, proven
// in-process: the REAL op router + the REAL grants console router
// (server/routes/op.ts + op-grants.ts) over a REAL temp SQLite store
// (the kernel's 0.1.7 seam: migration 0021's oidc_consent_grants).
//
// The arc, each leg against the wire:
//   the allow RECORDS the grant (the canonical scope set, the audit
//     event on the account's feed);
//   the SECOND authorize to the same client SKIPS the consent page —
//     the code arrives in the RP redirect directly (the flow's one mint
//     path), and it exchanges + validates exactly like a consented one;
//   the COVERAGE math: a narrower ask rides the wider grant, a wider
//     ask than granted re-prompts;
//   prompt=consent ALWAYS shows the page (the OIDC re-consent signal),
//     and the re-allow refreshes the SAME live row;
//   deny records NOTHING;
//   the console: GET /api/op/account/grants names the client, the
//     revoke flips the row (the guarded 404/409), the next authorize
//     re-prompts — and another account's grants never leak;
//   the audit chain carries account.consent_granted + the revoke.
// ─────────────────────────────────────────────────────────────────────

import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

// The store's DB path is read at module evaluation — set it before any
// import below touches @oimlsmart/platform-server/store/sqlite (the imports are dynamic).
const TMP = mkdtempSync(join(tmpdir(), 'oiml-consent-grants-'))
process.env.DATABASE_PATH = join(TMP, 'test.db')

const ISSUER = 'http://op.test'
process.env.OP_ISSUER = ISSUER

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

const appFetch = (async (input: RequestInfo | URL): Promise<Response> => {
  const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url
  return app.request(url)
}) as typeof fetch

async function demoLogin(email: string): Promise<string> {
  const res = await app.request('/api/auth/demo', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password: 'demo2026' }),
  })
  expect(res.ok, `demo login ${email}`).toBe(true)
  return res.headers.get('set-cookie')!.split(';')[0]!
}

/** The authorize call, raw: the 302's Location decides the leg — the
 *  consent page (/op/consent?auth=…) or the RP's redirect carrying the
 *  code (the remembered-grant skip). */
async function authorize(
  cookie: string,
  params: { clientId: string; redirectUri: string; scope?: string; state?: string; nonce?: string; challenge: string; prompt?: string },
): Promise<{ location: string }> {
  const query = new URLSearchParams({
    response_type: 'code',
    client_id: params.clientId,
    redirect_uri: params.redirectUri,
    scope: params.scope ?? 'openid profile email',
    state: params.state ?? 'st-1',
    nonce: params.nonce ?? 'nn-1',
    code_challenge: params.challenge,
    code_challenge_method: 'S256',
    ...(params.prompt ? { prompt: params.prompt } : {}),
  })
  const res = await app.request(`${ISSUER}/op/authorize?${query}`, { headers: { cookie } })
  expect(res.status, 'authorize redirects').toBe(302)
  return { location: res.headers.get('location')! }
}

/** The consent-page stop: the Location names /op/consent; the decide
 *  answers the RP redirect (the code on allow). */
async function driveConsent(cookie: string, location: string, decision: 'allow' | 'deny'): Promise<{ redirect: string }> {
  const consentUrl = new URL(location, ISSUER)
  expect(consentUrl.pathname, 'the flow stops at the consent page').toBe('/op/consent')
  const authId = consentUrl.searchParams.get('auth')!
  const decide = await app.request(`${ISSUER}/api/op/consent/${authId}/decide`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', cookie },
    body: JSON.stringify({ decision }),
  })
  expect(decide.status, 'the decision records').toBe(200)
  return decide.json() as Promise<{ redirect: string }>
}

/** The code exchange (the confidential client's posture). */
async function exchange(code: string): Promise<Response> {
  return app.request(`${ISSUER}/op/token`, {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      authorization: `Basic ${btoa(`${encodeURIComponent(CONFIDENTIAL.client_id)}:${encodeURIComponent(CONFIDENTIAL.secret)}`)}`,
    },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: CONFIDENTIAL.redirect_uris[0]!,
      client_id: CONFIDENTIAL.client_id,
      code_verifier: VERIFIER,
    }),
  })
}

// The one PKCE pair the file drives (the challenge is the fixed
// verifier's S256 — each code binds its own request's challenge).
const VERIFIER = 'consent-grants-verifier-9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f'
let CHALLENGE = ''

beforeAll(async () => {
  // The declared signing key (identity#7's posture — the round trips
  // validate against the served JWKS).
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

  const oidc = await import('@oimlsmart/platform-server/oidc')
  validateIdToken = oidc.validateIdToken
  oidc.clearOidcCaches()
  CHALLENGE = Buffer.from(
    await crypto.subtle.digest('SHA-256', new TextEncoder().encode(VERIFIER)),
  ).toString('base64url')

  const { Hono } = await import('hono')
  const { createAuthLeanRouter } = await import('../../server/routes/auth-lean')
  const { createOpRouter } = await import('../../server/routes/op')
  const { createOpGrantsRouter } = await import('../../server/routes/op-grants')
  const root = new Hono()
  root.route('/api/auth', createAuthLeanRouter({ autoSeedDemo: true }))
  root.route('/', createOpRouter())
  root.route('/', createOpGrantsRouter())
  app = root

  const probe = await app.request(`${ISSUER}/.well-known/openid-configuration`)
  expect(probe.status).toBe(200)
})

afterAll(async () => {
  const profileMod = await import('@oimlsmart/platform-server/profile')
  profileMod.resetInstanceProfileForTest()
  rmSync(TMP, { recursive: true, force: true })
  delete process.env.OP_ISSUER
  delete process.env.OP_SIGNING_KEY
  delete process.env.OP_CLIENT_SEED
  delete process.env.DATABASE_PATH
})

describe('the remembered consent grants (TODO.identity-features/12)', () => {
  it('the allow records the grant; the second authorize SKIPS the consent page, and its code exchanges + validates', async () => {
    const cookie = await demoLogin('ia@oiml.org')
    const me = await store.findUserByEmail('ia@oiml.org')

    // The first authorize stops at the consent page; the allow mints.
    const first = await authorize(cookie, {
      clientId: CONFIDENTIAL.client_id, redirectUri: CONFIDENTIAL.redirect_uris[0]!, challenge: CHALLENGE,
    })
    const { redirect } = await driveConsent(cookie, first.location, 'allow')
    const firstCode = new URL(redirect).searchParams.get('code')!
    expect(firstCode).toBeTruthy()

    // The grant landed: the canonical scope spelling, the live stamp.
    const grants = await store.listConsentGrants(me!.id)
    expect(grants.length).toBe(1)
    expect(grants[0]!.clientId).toBe(CONFIDENTIAL.client_id)
    expect(grants[0]!.scope).toBe('email openid profile')
    expect(grants[0]!.revokedAt).toBeNull()

    // THE SKIP: the second authorize never names the consent page — the
    // RP's redirect carries the code directly.
    const second = await authorize(cookie, {
      clientId: CONFIDENTIAL.client_id, redirectUri: CONFIDENTIAL.redirect_uris[0]!, challenge: CHALLENGE, state: 'st-2', nonce: 'nn-2',
    })
    const skipped = new URL(second.location)
    expect(skipped.origin + skipped.pathname, 'the redirect goes to the RP, never the consent page').toBe(CONFIDENTIAL.redirect_uris[0])
    const skippedCode = skipped.searchParams.get('code')!
    expect(skippedCode).toBeTruthy()
    expect(skipped.searchParams.get('state')).toBe('st-2')

    // …and the skip-minted code exchanges + validates exactly like a
    // consented one (the RP's real validator against the served JWKS).
    const token = await exchange(skippedCode)
    expect(token.status, 'the skip-minted code exchanges').toBe(200)
    const tokens = await token.json() as { id_token: string }
    const claims = await validateIdToken(tokens.id_token, {
      issuer: ISSUER,
      clientId: CONFIDENTIAL.client_id,
      nonce: 'nn-2',
      jwksUri: `${ISSUER}/jwks.json`,
    }, appFetch)
    expect(claims.email).toBe('ia@oiml.org')
    expect(claims.roles).toEqual(['ia_officer'])
    expect(claims.org).toBe('EX1')

    // The first code still stands on its own (one-time, independent).
    const firstExchange = await exchange(firstCode)
    expect(firstExchange.status).toBe(200)
  })

  it('the coverage math: a narrower ask rides the wider grant; a wider ask than granted re-prompts', async () => {
    const cookie = await demoLogin('tl@oiml.org')
    // Grant 'openid profile email' on the public client via the flow.
    const first = await authorize(cookie, {
      clientId: PUBLIC.client_id, redirectUri: PUBLIC.redirect_uris[0]!, challenge: CHALLENGE,
    })
    await driveConsent(cookie, first.location, 'allow')

    // A narrower ask ('openid profile') is covered → the skip.
    const narrower = await authorize(cookie, {
      clientId: PUBLIC.client_id, redirectUri: PUBLIC.redirect_uris[0]!, challenge: CHALLENGE, scope: 'openid profile',
    })
    expect(new URL(narrower.location).searchParams.get('code'), 'the narrower ask rides the wider grant').toBeTruthy()

    // A wider ask (offline_access joins) is NOT covered → the page.
    const wider = await authorize(cookie, {
      clientId: PUBLIC.client_id, redirectUri: PUBLIC.redirect_uris[0]!, challenge: CHALLENGE, scope: 'openid profile email offline_access',
    })
    expect(new URL(wider.location, ISSUER).pathname, 'the wider ask re-prompts').toBe('/op/consent')
    // …and allowing the wider set re-keys the grant to the wider triple
    // (the narrow grant stands too — the per-triple doctrine).
    await driveConsent(cookie, wider.location, 'allow')
    const me = await store.findUserByEmail('tl@oiml.org')
    expect((await store.listConsentGrants(me!.id)).map(g => g.scope).sort())
      .toEqual(['email offline_access openid profile', 'email openid profile'])
  })

  it('prompt=consent ALWAYS shows the page, and the re-allow refreshes the same live row', async () => {
    const cookie = await demoLogin('viewer@oiml.org')
    const me = await store.findUserByEmail('viewer@oiml.org')
    const first = await authorize(cookie, {
      clientId: PUBLIC.client_id, redirectUri: PUBLIC.redirect_uris[0]!, challenge: CHALLENGE,
    })
    await driveConsent(cookie, first.location, 'allow')
    const granted = (await store.listConsentGrants(me!.id))[0]!

    // The grant covers — yet prompt=consent forces the page.
    const forced = await authorize(cookie, {
      clientId: PUBLIC.client_id, redirectUri: PUBLIC.redirect_uris[0]!, challenge: CHALLENGE, prompt: 'consent',
    })
    expect(new URL(forced.location, ISSUER).pathname, 'prompt=consent defeats the remembered grant').toBe('/op/consent')
    await driveConsent(cookie, forced.location, 'allow')
    const after = await store.listConsentGrants(me!.id)
    expect(after.length, 'the re-allow refreshes — never a duplicate').toBe(1)
    expect(after[0]!.id).toBe(granted.id)
  })

  it('deny records NO grant', async () => {
    const cookie = await demoLogin('admin@oiml.org')
    const me = await store.findUserByEmail('admin@oiml.org')
    const first = await authorize(cookie, {
      clientId: PUBLIC.client_id, redirectUri: PUBLIC.redirect_uris[0]!, challenge: CHALLENGE,
    })
    const { redirect } = await driveConsent(cookie, first.location, 'deny')
    expect(new URL(redirect).searchParams.get('error')).toBe('access_denied')
    expect(await store.listConsentGrants(me!.id), 'a denial is never remembered').toEqual([])
    // …and the next authorize still prompts.
    const again = await authorize(cookie, {
      clientId: PUBLIC.client_id, redirectUri: PUBLIC.redirect_uris[0]!, challenge: CHALLENGE,
    })
    expect(new URL(again.location, ISSUER).pathname).toBe('/op/consent')
  })

  it('the console API: the list names the client; the revoke re-prompts; another account never sees the row', async () => {
    const cookie = await demoLogin('cs@oiml.org')
    const me = await store.findUserByEmail('cs@oiml.org')
    const first = await authorize(cookie, {
      clientId: CONFIDENTIAL.client_id, redirectUri: CONFIDENTIAL.redirect_uris[0]!, challenge: CHALLENGE,
    })
    await driveConsent(cookie, first.location, 'allow')

    // The console list: the client's DISPLAY NAME + the scope set.
    const list = await app.request(`${ISSUER}/api/op/account/grants`, { headers: { cookie } })
    expect(list.status).toBe(200)
    const { grants } = await list.json() as { grants: Array<{ id: string; clientId: string; clientName: string; scopes: string[] }> }
    expect(grants.length).toBe(1)
    expect(grants[0]!.clientName).toBe('OIML SMART platform hub')
    expect(grants[0]!.scopes).toEqual(['email', 'openid', 'profile'])

    // Another account's read is its own (never a leak), and the guarded
    // revoke refuses a foreign row by name (404, not a flip).
    const other = await demoLogin('viewer@oiml.org')
    const otherList = await app.request(`${ISSUER}/api/op/account/grants`, { headers: { cookie: other } })
    const otherGrants = (await otherList.json() as { grants: Array<{ id: string }> }).grants
    expect(otherGrants.some(g => g.id === grants[0]!.id), 'another account never sees this grant').toBe(false)
    const foreign = await app.request(`${ISSUER}/api/op/account/grants/${grants[0]!.id}`, { method: 'DELETE', headers: { cookie: other } })
    expect(foreign.status, 'another account’s grant is a 404, never a flip').toBe(404)
    expect((await store.listConsentGrants(me!.id)).length, 'the row stands').toBe(1)

    // The revoke: the row flips (the audit keeps it), the double-revoke
    // is the honest 409…
    const revoke = await app.request(`${ISSUER}/api/op/account/grants/${grants[0]!.id}`, { method: 'DELETE', headers: { cookie } })
    expect(revoke.status).toBe(200)
    expect(await store.listConsentGrants(me!.id), 'the live list empties').toEqual([])
    const reRevoke = await app.request(`${ISSUER}/api/op/account/grants/${grants[0]!.id}`, { method: 'DELETE', headers: { cookie } })
    expect(reRevoke.status, 'the second revoke names itself').toBe(404)

    // …and the NEXT authorize re-prompts (the re-prompt IS the revoke's
    // observable).
    const reprompt = await authorize(cookie, {
      clientId: CONFIDENTIAL.client_id, redirectUri: CONFIDENTIAL.redirect_uris[0]!, challenge: CHALLENGE,
    })
    expect(new URL(reprompt.location, ISSUER).pathname, 'the revoke re-prompts the consent page').toBe('/op/consent')
    // …and the re-allow lands a FRESH grant row (the revoked half's
    // history stands under it).
    await driveConsent(cookie, reprompt.location, 'allow')
    const refreshed = await store.listConsentGrants(me!.id)
    expect(refreshed.length).toBe(1)
    expect(refreshed[0]!.id).not.toBe(grants[0]!.id)
  })

  it('the audit chain carries the grant + the revoke on the account’s own feed', async () => {
    const me = await store.findUserByEmail('cs@oiml.org')
    const rows = await store.listEntities('auditEvents')
    const actions = rows
      .map(r => JSON.parse(r.data) as { entity_id: string; action: string })
      .filter(e => e.entity_id === me!.id)
      .map(e => e.action)
    expect(actions).toContain('account.consent_granted')
    expect(actions).toContain('account.consent_revoked')
  })

  it('the profile gate: a non-identity deployment answers the grants routes 404', async () => {
    const profileMod = await import('@oimlsmart/platform-server/profile')
    profileMod.resetInstanceProfileForTest()
    profileMod.installInstanceProfile(profileMod.parseInstanceProfile(`
identity:
  org_id: hub-org
  org_name: A plain hub
  role_codes: [hub]
roles: [hub]
branding: { name: A plain hub }
`))
    try {
      const res = await app.request(`${ISSUER}/api/op/account/grants`, { headers: { cookie: 'oiml-session=whatever' } })
      expect(res.status, 'the module gate answers 404, never the data').toBe(404)
      const del = await app.request(`${ISSUER}/api/op/account/grants/some-id`, { method: 'DELETE', headers: { cookie: 'oiml-session=whatever' } })
      expect(del.status).toBe(404)
    } finally {
      // The identity profile returns for the files that share the process.
      profileMod.resetInstanceProfileForTest()
      profileMod.installInstanceProfile(profileMod.parseInstanceProfile(`
identity:
  org_id: oimlsmart-id
  org_name: OIML SMART Identity
  role_codes: [identity]
roles: [identity]
branding: { name: OIML SMART Identity }
demo_personas: true
`))
    }
  })
})
