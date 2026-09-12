// ─────────────────────────────────────────────────────────────────────
// TODO.restructure/20 — the whitelabel FEDERATION verification: a
// tenant instance delegating to the CENTRAL OP, the dance across TWO
// REAL instances of this service (the stub-idp round trip in
// id-upstream.test.ts proves the mechanism against a fake IdP; this
// leg proves it against OURSELVES — a PKCE-required authorize, the
// consent decide, the token endpoint, the JWKS-validated ID token):
//
//   LEG 1 (LINK)     the tenant's signed-in account links its central
//                    identity: tenant /op/upstream/central/link → the
//                    central authorize (PKCE asserted on the wire) →
//                    the consent decide → the tenant callback (the
//                    code exchanged at the REAL central token endpoint,
//                    the ID token validated against the REAL JWKS) →
//                    the link row stands;
//   LEG 2 (SIGN-IN)  the linked identity federates in: the remembered
//                    grant skips the consent, the match rule resolves
//                    (provider, sub) — NEVER the email — the TENANT's
//                    session cookie stands on the TENANT's issuer, and
//                    the two issuers never blur.
//
// Topology (TODO.restructure/28-D, the store instance refactor's
// proof): BOTH instances run in THIS process, each on its own store —
// the tenant on the default instance (installSqliteStore), the central
// on a SECOND store from createSqliteStore (its own database file,
// concurrently open beside the first). Central still serves real HTTP
// on its port (the tenant's OIDC client fetches its discovery/JWKS by
// issuer URL), so each app installs its store + profile per request —
// the Worker composition root's middleware pattern (server/
// cloudflare.ts), node-side. The issuers stay distinct the dev
// posture's way: OP_ISSUER undeclared, each instance's issuer derived
// from its request origin.
// ─────────────────────────────────────────────────────────────────────

import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { serve, type ServerType } from '@hono/node-server'

const CENTRAL_PORT = 3991
const CENTRAL = `http://localhost:${CENTRAL_PORT}`
const TENANT = 'http://ia.example'

const CENTRAL_CLIENT_ID = 'tenant-instance'
const CENTRAL_CLIENT_SECRET = 'tenant-instance-secret'
const CALLBACK = `${TENANT}/op/upstream/central/callback`

// The tenant's own DB is the process's DEFAULT instance; central owns
// its file through createSqliteStore — two instances, one process.
const TMP = mkdtempSync(join(tmpdir(), 'oiml-whitelabel-fed-'))
process.env.DATABASE_PATH = join(TMP, 'tenant.db')
process.env.CENTRAL_CLIENT_SECRET = CENTRAL_CLIENT_SECRET
process.env.OP_UPSTREAM_SEED = JSON.stringify([{
  id: 'central', kind: 'oidc', display_name: 'OIML SMART Identity (central)',
  issuer: CENTRAL, client_id: CENTRAL_CLIENT_ID, client_secret_ref: 'env:CENTRAL_CLIENT_SECRET',
}])

let app: import('hono').Hono
let store: import('../../server/store').ServerStore
let centralServer: ServerType
let centralCookie: string
let tenantCookie: string

beforeAll(async () => {
  // ── CENTRAL: a real instance on its OWN store instance + port, demo
  //    cast ON (a persona's session is the federating user), the
  //    tenant's client registered, the identity profile (the e2e
  //    fixture the spawned posture used to declare).
  const { createSqliteStore, installSqliteStore } = await import('../../server/store/sqlite')
  const centralStore = createSqliteStore(join(TMP, 'central.db'))
  const profileMod = await import('../../server/profile')
  const centralProfile = profileMod.parseInstanceProfile(
    readFileSync(join(import.meta.dirname, '..', '..', 'e2e', 'fixtures', 'instance.profile.identity.yaml'), 'utf-8'),
  )
  const { seedOidcClientsFromEnv } = await import('../../server/auth/op/registry')
  await seedOidcClientsFromEnv({
    OP_CLIENT_SEED: JSON.stringify([{
      client_id: CENTRAL_CLIENT_ID,
      name: 'The IA tenant instance',
      secret: CENTRAL_CLIENT_SECRET,
      redirect_uris: [CALLBACK],
      claims_policy: { claims: ['email'] },
    }]),
  }, centralStore)

  const { installStore, installedStore } = await import('../../server/store')
  const { installedInstanceProfile } = await import('../../server/profile')
  const { Hono } = await import('hono')
  const { createApiApp } = await import('../../server/app')

  /** The per-request install with the save/restore discipline: the
   *  tenant's callback fetches the CENTRAL token endpoint mid-flight
   *  (a nested request through central's own middleware, which installs
   *  central's store), so each install restores the outer request's
   *  store + profile on exit — the slot stays re-entrant. */
  const perInstance = (store_: import('../../server/store').ServerStore, profile_: import('../../server/profile').InstanceProfile) =>
    async (_c: import('hono').Context, next: () => Promise<void>) => {
      const prevStore = installedStore()
      const prevProfile = installedInstanceProfile()
      installStore(store_)
      profileMod.installInstanceProfile(profile_)
      await next()
      if (prevStore) installStore(prevStore)
      if (prevProfile) profileMod.installInstanceProfile(prevProfile)
    }

  const centralApp = createApiApp({
    autoSeedDemo: true,
    instanceProfile: centralProfile,
    middleware: [perInstance(centralStore, centralProfile)],
  })
  await new Promise<void>(resolve => {
    centralServer = serve({ fetch: centralApp.fetch, port: CENTRAL_PORT }, () => resolve())
  })

  // ── TENANT: in-process, the IA whitelabel flavor, its own store —
  //    the process's default instance, re-installed per request (the
  //    same middleware pattern; central's requests must never leak in).
  const tenantStore = installSqliteStore()
  store = tenantStore
  const tenantProfile = profileMod.parseInstanceProfile(`
identity:
  org_id: ex-ia
  org_name: Example Issuing Authority
  role_codes: [ia]
  country: FR
roles: [identity]
branding: { name: Example IA Sign-In }
demo_personas: false
`)
  const { hashPassword } = await import('../../server/auth/passwords')
  const { createOpUpstreamRouter } = await import('../../server/routes/op-upstream')
  app = new Hono()
  app.route('/', createApiApp({
    autoSeedDemo: false,
    instanceProfile: tenantProfile,
    middleware: [perInstance(tenantStore, tenantProfile)],
  }))
  app.route('/', createOpUpstreamRouter())

  // The tenant's federating account (direct provisioning — the register
  // ceremony is id-self-registration's subject, not this leg's).
  const account = await store.createOpAccount({ email: 'ia-officer@ia.example', name: 'IA Officer', role: 'viewer', createdBy: 'test' })
  expect(account).toBeTruthy()
  await store.setPasswordHash(account!.id, await hashPassword('the ia officer passphrase'), 'test')
  const login = await app.request(`${TENANT}/api/op/login`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email: 'ia-officer@ia.example', password: 'the ia officer passphrase' }),
  })
  expect(login.status).toBe(200)
  tenantCookie = login.headers.get('set-cookie')!.split(';')[0]!

  // The central federating user: a demo persona's session over real HTTP.
  const demo = await fetch(`${CENTRAL}/api/auth/demo`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email: 'admin@oiml.org', password: 'demo2026' }),
  })
  expect(demo.status).toBe(200)
  centralCookie = demo.headers.get('set-cookie')!.split(';')[0]!
}, 60_000)

afterAll(async () => {
  await new Promise<void>(resolve => centralServer?.close(() => resolve()))
  rmSync(TMP, { recursive: true, force: true })
  delete process.env.DATABASE_PATH
  delete process.env.CENTRAL_CLIENT_SECRET
  delete process.env.OP_UPSTREAM_SEED
})

/** One full dance leg on the tenant: start → central authorize →
 * (consent decide when the consent page shows) → the tenant callback.
 * Answers the tenant callback's response. */
async function dance(startUrl: string): Promise<Response> {
  const start = await app.request(startUrl, { headers: { cookie: tenantCookie } })
  expect(start.status).toBe(302)
  const authorizeUrl = new URL(start.headers.get('location')!)
  expect(authorizeUrl.origin).toBe(CENTRAL)
  expect(authorizeUrl.pathname).toBe('/op/authorize')
  expect(authorizeUrl.searchParams.get('client_id')).toBe(CENTRAL_CLIENT_ID)
  expect(authorizeUrl.searchParams.get('redirect_uri')).toBe(CALLBACK)
  expect(authorizeUrl.searchParams.get('code_challenge')).toBeTruthy() // PKCE rides
  expect(authorizeUrl.searchParams.get('code_challenge_method')).toBe('S256')

  let location = authorizeUrl
  for (let hop = 0; hop < 3; hop++) {
    const res = await fetch(location, { headers: { cookie: centralCookie }, redirect: 'manual' })
    const next = res.headers.get('location')
    if (!next) break
    const nextUrl = new URL(next, location)
    if (nextUrl.origin === TENANT) {
      // Home — the tenant callback processes the code.
      return app.request(nextUrl.toString(), { headers: { cookie: tenantCookie } })
    }
    if (nextUrl.pathname === '/api/op/consent' || nextUrl.pathname.startsWith('/op/consent')) {
      const authId = nextUrl.searchParams.get('auth')
      expect(authId).toBeTruthy()
      const decide = await fetch(`${CENTRAL}/api/op/consent/${authId}/decide`, {
        method: 'POST', headers: { 'content-type': 'application/json', cookie: centralCookie },
        body: JSON.stringify({ decision: 'allow' }),
      })
      expect(decide.status).toBe(200)
      const { redirect } = await decide.json() as { redirect: string }
      const back = new URL(redirect)
      if (back.origin === TENANT) return app.request(back.toString(), { headers: { cookie: tenantCookie } })
      location = back
      continue
    }
    location = nextUrl
  }
  throw new Error(`the dance never returned to the tenant — last ${location}`)
}

describe('TODO.restructure/20 — the whitelabel federation (tenant → central)', () => {
  it('LEG 1 LINK: the real central dance links the tenant account', async () => {
    const done = await dance(`${TENANT}/op/upstream/central/link`)
    expect(done.status).toBe(302)
    // The link row stands — (provider 'central', the central sub).
    const links = await store.listIdentityLinks(
      (await store.findUserByEmail('ia-officer@ia.example'))!.id,
    )
    expect(links.map(l => l.provider)).toContain('central')
  }, 60_000)

  it('LEG 2 SIGN-IN: the remembered grant, the match rule, the TENANT session', async () => {
    tenantCookie = '' // anonymous — the federated sign-in stands alone
    const done = await dance(`${TENANT}/op/upstream/central/signin`)
    expect(done.status).toBe(302)
    const cookie = done.headers.get('set-cookie')
    expect(cookie, 'the tenant session cookie is set').toContain('oiml-session=')

    // The session answers on the TENANT's issuer, for the linked account.
    const session = await app.request(`${TENANT}/api/auth/session`, { headers: { cookie: cookie!.split(';')[0] } })
    expect(session.status).toBe(200)
    const me = await session.json() as { email: string }
    expect(me.email).toBe('ia-officer@ia.example')

    // The issuers never blur: the tenant's discovery names ITS issuer.
    const discovery = await (await app.request(`${TENANT}/.well-known/openid-configuration`)).json() as { issuer: string }
    expect(discovery.issuer).toBe(TENANT)

    // Exactly ONE link row — the second pass took no duplicate path.
    const links = await store.listIdentityLinks(
      (await store.findUserByEmail('ia-officer@ia.example'))!.id,
    )
    expect(links.filter(l => l.provider === 'central').length).toBe(1)
  }, 60_000)
})
