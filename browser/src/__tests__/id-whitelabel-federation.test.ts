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
// Topology: CENTRAL is a spawned real server (its own process, own
// SQLite, port 3991 — the sqlite cone is a module singleton, so the
// two registries cannot share one process); the TENANT runs in-process
// (the standard unit harness) against the IA whitelabel flavor.
// ─────────────────────────────────────────────────────────────────────

import { mkdtempSync, rmSync } from 'node:fs'
import { spawn, type ChildProcess } from 'node:child_process'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

const BROWSER_DIR = join(import.meta.dirname, '..', '..')

const CENTRAL_PORT = 3991
const CENTRAL = `http://localhost:${CENTRAL_PORT}`
const TENANT = 'http://ia.example'

const CENTRAL_CLIENT_ID = 'tenant-instance'
const CENTRAL_CLIENT_SECRET = 'tenant-instance-secret'
const CALLBACK = `${TENANT}/op/upstream/central/callback`

// The tenant's own DB is the in-process singleton; central owns its process.
const TMP = mkdtempSync(join(tmpdir(), 'oiml-whitelabel-fed-'))
process.env.DATABASE_PATH = join(TMP, 'tenant.db')
process.env.OP_ISSUER = TENANT
process.env.CENTRAL_CLIENT_SECRET = CENTRAL_CLIENT_SECRET
process.env.OP_UPSTREAM_SEED = JSON.stringify([{
  id: 'central', kind: 'oidc', display_name: 'OIML SMART Identity (central)',
  issuer: CENTRAL, client_id: CENTRAL_CLIENT_ID, client_secret_ref: 'env:CENTRAL_CLIENT_SECRET',
}])

import { fixtureOpSigningKey } from '../../e2e/fixtures/op-signing-key'

let app: import('hono').Hono
let store: ReturnType<typeof import('../../server/store/sqlite').createSqliteServerStore>
let central: ChildProcess | undefined
const centralLogs: string[] = []
let centralCookie: string

function killTree(proc: ChildProcess | undefined): void {
  if (!proc || proc.exitCode !== null || proc.pid === undefined) return
  try { process.kill(-proc.pid, 'SIGKILL') } catch { /* group already gone */ }
  try { proc.kill('SIGKILL') } catch { /* already gone */ }
}

async function waitForHttp(url: string, timeoutMs: number): Promise<void> {
  const deadline = Date.now() + timeoutMs
  let lastError = ''
  while (Date.now() < deadline) {
    try {
      const res = await fetch(url)
      if (res.status < 500) return
      lastError = `HTTP ${res.status}`
    } catch (e) { lastError = String(e) }
    await new Promise(r => setTimeout(r, 1_000))
  }
  throw new Error(`timed out waiting for ${url} (${lastError})\n${centralLogs.join('').slice(-3000)}`)
}

beforeAll(async () => {
  // ── CENTRAL: a real instance on its own process/DB, demo cast ON (a
  //    persona's session is the federating user), the tenant's client
  //    registered, the fixture signing key (identity#7).
  central = spawn(join(BROWSER_DIR, 'node_modules', '.bin', 'tsx'), ['server/serve.ts'], {
    cwd: BROWSER_DIR,
    env: {
      ...process.env,
      PORT: String(CENTRAL_PORT),
      DATABASE_PATH: join(TMP, 'central.db'),
      INSTANCE_PROFILE: join(BROWSER_DIR, 'e2e', 'fixtures', 'instance.profile.identity.yaml'),
      OP_ISSUER: CENTRAL,
      OP_SIGNING_KEY: await fixtureOpSigningKey(),
      OP_CLIENT_SEED: JSON.stringify([{
        client_id: CENTRAL_CLIENT_ID,
        name: 'The IA tenant instance',
        secret: CENTRAL_CLIENT_SECRET,
        redirect_uris: [CALLBACK],
        claims_policy: { claims: ['email'] },
      }]),
      OP_UPSTREAM_SEED: '',
      CENTRAL_CLIENT_SECRET: '',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
    detached: true,
  })
  central.stdout?.on('data', d => centralLogs.push(String(d)))
  central.stderr?.on('data', d => centralLogs.push(String(d)))
  await waitForHttp(`${CENTRAL}/api/health`, 120_000)

  // ── TENANT: in-process, the IA whitelabel flavor, its own store.
  const { installSqliteStore } = await import('../../server/store/sqlite')
  store = installSqliteStore()
  const profileMod = await import('../../server/profile')
  profileMod.installInstanceProfile(profileMod.parseInstanceProfile(`
identity:
  org_id: ex-ia
  org_name: Example Issuing Authority
  role_codes: [ia]
  country: FR
roles: [identity]
branding: { name: Example IA Sign-In }
demo_personas: false
`))
  const { hashPassword } = await import('../../server/auth/passwords')
  const { Hono } = await import('hono')
  const { createApiApp } = await import('../../server/app')
  const { createOpUpstreamRouter } = await import('../../server/routes/op-upstream')
  app = new Hono()
  app.route('/', createApiApp({ autoSeedDemo: false }))
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
}, 180_000)

let tenantCookie: string

afterAll(() => {
  killTree(central)
  rmSync(TMP, { recursive: true, force: true })
  delete process.env.OP_ISSUER
  delete process.env.DATABASE_PATH
  delete process.env.CENTRAL_CLIENT_SECRET
  delete process.env.OP_UPSTREAM_SEED
})

/** One full dance leg on the tenant: start → central authorize →
 *  (consent decide when the consent page shows) → the tenant callback.
 *  Answers the tenant callback's response. */
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
  throw new Error(`the dance never returned to the tenant — last ${location}\n${centralLogs.join('').slice(-2000)}`)
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
