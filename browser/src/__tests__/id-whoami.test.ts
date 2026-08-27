// ─────────────────────────────────────────────────────────────────────
// The whoami beacon (GET /op/whoami — the estate's SSO-UX last mile,
// smart's docs/future/07 Part I.3 item 3), proven in-process: the REAL
// whoami router over a REAL temp SQLite store, the demo cast for the
// sessions, and the client registry seeding the CORS allowlist.
//
// Covered:
//   THE CONE        — no session → the signed-out shape (cacheable,
//                     cheap); a session → the minimal projection (name,
//                     the public avatar URL, the admin flag — NEVER
//                     emails, never roles, never orgs; no-store);
//   THE CORS        — the allowed origins DERIVE from the live client
//     POSTURE         registry (the launch URL + redirect URI origins of
//                     the ACTIVE clients — never '*', never a hand
//                     list): an allowlisted origin is reflected with
//                     allow-credentials; a foreign origin gets NO CORS
//                     header; a disabled client drops off the allowlist;
//                     the preflight admits the allowlisted origin only;
//   THE GATE        — a non-identity profile answers 404.
// ─────────────────────────────────────────────────────────────────────

import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

// The store's DB path is read at module evaluation — set it before any
// import below touches @oimlsmart/platform-server/store/sqlite (the imports are dynamic).
const TMP = mkdtempSync(join(tmpdir(), 'oiml-op-whoami-'))
process.env.DATABASE_PATH = join(TMP, 'test.db')

const ISSUER = 'http://op.test'
process.env.OP_ISSUER = ISSUER

// The registry's bootstrap seed: the hub (a launch card + a redirect URI
// — TWO origins on one client) and a second application (redirect URI
// only). The allowlist derives from these.
const HUB = {
  client_id: 'hub-instance',
  name: 'OIML SMART platform hub',
  secret: 'hub-secret-123',
  redirect_uris: ['https://hub.example/api/auth/callback/oidc'],
  launch: { url: 'https://www-hub.example/signin', visibility: 'open' },
}
const PUBS = {
  client_id: 'pubs-site',
  name: 'The publications site',
  redirect_uris: ['https://pubs.example/callback'],
}
process.env.OP_CLIENT_SEED = JSON.stringify([HUB, PUBS])

let app: import('hono').Hono
let store: ReturnType<typeof import('@oimlsmart/platform-server/store').getStore>
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

function whoami(init?: { cookie?: string; origin?: string }) {
  const headers: Record<string, string> = {}
  if (init?.cookie) headers.cookie = init.cookie
  if (init?.origin) headers.origin = init.origin
  return app.request(`${ISSUER}/op/whoami`, { headers })
}

beforeAll(async () => {
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

  const { Hono } = await import('hono')
  const { createAuthLeanRouter } = await import('../../server/routes/auth-lean')
  const { createOpRouter } = await import('../../server/routes/op')
  const { createOpWhoamiRouter } = await import('../../server/routes/op-whoami')
  const root = new Hono()
  root.route('/api/auth', createAuthLeanRouter({ autoSeedDemo: true }))
  root.route('/', createOpRouter())
  root.route('/', createOpWhoamiRouter())
  app = root

  // The bootstrap seed lands on the first REGISTRY request (the discovery
  // document never seeds); drive it once, honestly.
  const admin = await demoLogin('admin@oiml.org') // the demo cast lands
  expect((await app.request(`${ISSUER}/api/op/clients`, { headers: { cookie: admin } })).status).toBe(200)
})

afterAll(() => {
  resetProfile()
  rmSync(TMP, { recursive: true, force: true })
  delete process.env.OP_ISSUER
  delete process.env.OP_CLIENT_SEED
  delete process.env.DATABASE_PATH
})

describe('the whoami beacon', () => {
  it('signed out answers the cheap, cacheable signed-out shape — the allowlisted origin reflected, credentials admitted', async () => {
    const res = await whoami({ origin: 'https://www-hub.example' })
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({ signedIn: false })
    expect(res.headers.get('access-control-allow-origin')).toBe('https://www-hub.example')
    expect(res.headers.get('access-control-allow-credentials')).toBe('true')
    expect(res.headers.get('cache-control')).toBe('public, max-age=60')
    // A cookie-bearing request never takes the anonymous cached answer.
    expect(res.headers.get('vary') ?? '').toContain('Cookie')
    expect(res.headers.get('vary') ?? '').toContain('Origin')
  })

  it('the allowlist derives from the redirect URI origins too, and a foreign origin gets NO CORS header (never *)', async () => {
    // The redirect-URI origin (no launch card involved).
    const pubs = await whoami({ origin: 'https://pubs.example' })
    expect(pubs.headers.get('access-control-allow-origin')).toBe('https://pubs.example')
    // The foreign origin: the answer stands (curl/same-origin read it),
    // the browser blocks the read — NO CORS headers.
    const foreign = await whoami({ origin: 'https://evil.example' })
    expect(foreign.status).toBe(200)
    expect(foreign.headers.get('access-control-allow-origin')).toBeNull()
    expect(foreign.headers.get('access-control-allow-credentials')).toBeNull()
    // No Origin header at all (the same-origin posture): no CORS headers.
    const sameOrigin = await whoami()
    expect(sameOrigin.headers.get('access-control-allow-origin')).toBeNull()
  })

  it('a DISABLED client drops off the allowlist (the live registry is the source)', async () => {
    const admin = await demoLogin('admin@oiml.org')
    const off = await app.request(`${ISSUER}/api/op/clients/pubs-site/status`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie: admin },
      body: JSON.stringify({ status: 'disabled' }),
    })
    expect(off.status).toBe(200)
    const res = await whoami({ origin: 'https://pubs.example' })
    expect(res.headers.get('access-control-allow-origin')).toBeNull()
    // Re-enable for the rest of the suite.
    await app.request(`${ISSUER}/api/op/clients/pubs-site/status`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie: admin },
      body: JSON.stringify({ status: 'active' }),
    })
    expect((await whoami({ origin: 'https://pubs.example' })).headers.get('access-control-allow-origin')).toBe('https://pubs.example')
  })

  it('signed in answers the minimal projection — a face, not a dossier — never cached', async () => {
    const cookie = await demoLogin('admin@oiml.org')
    const res = await whoami({ cookie, origin: 'https://hub.example' })
    expect(res.status).toBe(200)
    const body = await res.json() as Record<string, unknown>
    expect(body.signedIn).toBe(true)
    expect(body.name).toBeTruthy()
    expect(body.picture, 'no avatar upload → null (the chip renders the initials fallback)').toBeNull()
    expect(body.admin, 'the demo administrator holds the admin flag').toBe(true)
    // NEVER the dossier: no email, no roles, no orgs.
    for (const never of ['email', 'role', 'roles', 'groups', 'org', 'orgId', 'id']) {
      expect(body[never], `the projection never carries ${never}`).toBeUndefined()
    }
    expect(JSON.stringify(body)).not.toContain('@')
    expect(res.headers.get('cache-control')).toBe('no-store')
    expect(res.headers.get('access-control-allow-origin')).toBe('https://hub.example')
  })

  it('the admin flag follows the home feed’s ONE rule (a viewer is not an administrator)', async () => {
    const viewer = await demoLogin('viewer@oiml.org')
    const body = await (await whoami({ cookie: viewer })).json() as { signedIn: boolean; admin: boolean }
    expect(body.signedIn).toBe(true)
    expect(body.admin).toBe(false)
  })

  it('the picture names the PUBLIC avatar URL once the account has an upload (and returns to null on removal)', async () => {
    const cookie = await demoLogin('admin@oiml.org')
    const session = await (await app.request(`${ISSUER}/api/auth/session`, { headers: { cookie } })).json() as { id: string }
    await store.setUserAvatar(session.id, '/api/op/account/avatar')
    try {
      const body = await (await whoami({ cookie })).json() as { picture: string | null }
      expect(body.picture).toBe(`${ISSUER}/op/avatar/${session.id}`)
    } finally {
      await store.setUserAvatar(session.id, null)
    }
    expect(((await (await whoami({ cookie })).json()) as { picture: string | null }).picture).toBeNull()
  })

  it('the preflight admits the allowlisted origin’s credentialed GET and answers a foreign origin bare', async () => {
    const ok = await app.request(`${ISSUER}/op/whoami`, {
      method: 'OPTIONS',
      headers: { origin: 'https://hub.example', 'access-control-request-method': 'GET' },
    })
    expect(ok.status).toBe(204)
    expect(ok.headers.get('access-control-allow-origin')).toBe('https://hub.example')
    expect(ok.headers.get('access-control-allow-credentials')).toBe('true')
    expect(ok.headers.get('access-control-allow-methods')).toBe('GET')

    const foreign = await app.request(`${ISSUER}/op/whoami`, {
      method: 'OPTIONS',
      headers: { origin: 'https://evil.example', 'access-control-request-method': 'GET' },
    })
    expect(foreign.status).toBe(204)
    expect(foreign.headers.get('access-control-allow-origin')).toBeNull()
  })

  it('the module gate: a non-identity profile answers 404', async () => {
    resetProfile() // the hub default (no identity module)
    try {
      expect((await whoami()).status).toBe(404)
      expect((await app.request(`${ISSUER}/op/whoami`, { method: 'OPTIONS', headers: { origin: 'https://hub.example' } })).status).toBe(404)
    } finally {
      installIdentityProfile()
    }
  })
})
