// ─────────────────────────────────────────────────────────────────────
// The SSO home (the post-login launcher) — proven in-process: the REAL
// home router (server/routes/op-home.ts), the REAL client-registry
// surface (routes/op.ts) and the REAL accounts router (the per-client
// role grant) over a REAL temp SQLite store, with the launcher feed's
// visibility computed by the ONE rule the token endpoint shares
// (auth/op/claims.ts's roleClaimsForClient).
//
// Covered:
//   THE FEED        — 401 signed out; the launch metadata gates
//                     membership (no launch row → never on the
//                     launcher); a disabled client hides.
//   THE VISIBILITY  — 'open' admits every account; 'roles' hides the
//     COMPUTATION     card the account's computed role set does not
//                     admit; 'request' shows it WITHOUT a working
//                     launch (the leak check: no launchUrl on the
//                     request state); the per-client role grant makes
//                     the card launchable (the audit chain carries the
//                     grant).
//   THE REQUEST     — the intake records account.access_request on the
//     INTAKE          audit chain (the registry's activity feed shape),
//                     idempotent on repeat, refusing the admitted, the
//                     unlisted, and the not-request postures honestly.
//   THE REGISTRY    — the launch write's validation (absolute http(s)
//                     URL, the named icon set, the visibility enum),
//                     the keep-on-omit / clear-on-null semantics, the
//                     audit metadata, and the bootstrap seed carrying
//                     the card.
// ─────────────────────────────────────────────────────────────────────

import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

// The store's DB path is read at module evaluation — set it before any
// import below touches @oimlsmart/platform-server/store/sqlite (the imports are dynamic).
const TMP = mkdtempSync(join(tmpdir(), 'oiml-op-home-'))
process.env.DATABASE_PATH = join(TMP, 'test.db')

const ISSUER = 'http://op.test'
process.env.OP_ISSUER = ISSUER

// The launcher fixture registry: the hub (role-gated, hides when not
// admitted), the TL (the request-access posture), the assistant (open —
// every signed-in account enters), and a machine client (no launch
// metadata — never on the launcher).
const HUB = {
  client_id: 'hub-instance',
  name: 'OIML SMART platform hub',
  secret: 'hub-secret-123',
  redirect_uris: ['https://hub.example/api/auth/callback/oidc'],
  claims_policy: { claims: ['roles', 'groups', 'org'], roles: ['admin', 'cs_admin', 'ia_officer', 'viewer'] },
  launch: { url: 'https://hub.example/api/auth/signin/oidc', icon: 'grid', description: 'The certification hub.', visibility: 'roles' },
}
const TL = {
  client_id: 'tl-instance',
  name: 'Example TL instance',
  redirect_uris: ['https://tl.example/api/auth/callback/oidc'],
  claims_policy: { claims: ['roles', 'groups'], roles: ['tl_operator'] },
  launch: { url: 'https://tl.example/api/auth/signin/oidc', icon: 'flask', description: 'The test laboratory.', visibility: 'request' },
}
const ASSISTANT = {
  client_id: 'pubs-assistant',
  name: 'OIML SMART AI',
  redirect_uris: ['https://ai.example/auth/callback'],
  launch: { url: 'https://ai.example/auth/login', icon: 'chat', description: 'Ask the library.', visibility: 'open' },
}
const MACHINE = {
  client_id: 'machine-relay',
  name: 'A machine-only relay',
  redirect_uris: ['https://relay.example/callback'],
}
process.env.OP_CLIENT_SEED = JSON.stringify([HUB, TL, ASSISTANT, MACHINE])

let app: import('hono').Hono
let store: ReturnType<typeof import('@oimlsmart/platform-server/store').getStore>

async function demoLogin(email: string): Promise<string> {
  const res = await app.request('/api/auth/demo', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password: 'demo2026' }),
  })
  expect(res.ok, `demo login ${email}`).toBe(true)
  return res.headers.get('set-cookie')!.split(';')[0]!
}

/** The launcher feed, signed in as the cookie's account. */
async function homeFeed(cookie: string, status = 200): Promise<any> {
  const res = await app.request(`${ISSUER}/api/op/home`, { headers: { cookie } })
  expect(res.status, `GET /api/op/home → ${status}`).toBe(status)
  return res.json()
}

/** The OP registry's own account (the demo cast is not the registry's —
 *  the per-client grant surface manages OP accounts only): the admin
 *  invites, the invitee completes the one-time setup link (the
 *  no-mailer posture answers it honestly), signed in. */
async function inviteAndEnroll(admin: string, email: string, name: string, password: string): Promise<{ id: string; cookie: string }> {
  const invite = await app.request(`${ISSUER}/api/op/accounts`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', cookie: admin },
    body: JSON.stringify({ email, name }),
  })
  expect(invite.status, `the invite of ${email}`).toBe(201)
  const { account, setupUrl } = await invite.json() as { account: { id: string }; setupUrl: string }
  const token = new URL(setupUrl).searchParams.get('token')!
  const enroll = await app.request(`${ISSUER}/api/op/enroll/${token}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ password }),
  })
  expect(enroll.status, `the enrollment of ${email}`).toBe(200)
  return { id: account.id, cookie: enroll.headers.get('set-cookie')!.split(';')[0]! }
}

/** The per-client role grant (the admin's registry act). */
async function grantClientRoles(admin: string, accountId: string, clientId: string, roles: string[]): Promise<Response> {
  return app.request(`${ISSUER}/api/op/accounts/${accountId}/client-roles/${clientId}`, {
    method: 'PUT',
    headers: { 'content-type': 'application/json', cookie: admin },
    body: JSON.stringify({ roles }),
  })
}

let nadia: { id: string; cookie: string } // the invited OP account (OP-side role: viewer)

beforeAll(async () => {
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

  const { Hono } = await import('hono')
  const { createAuthLeanRouter } = await import('../../server/routes/auth-lean')
  const { createOpRouter } = await import('../../server/routes/op')
  const { createOpAccountsRouter } = await import('../../server/routes/op-accounts')
  const { createOpHomeRouter } = await import('../../server/routes/op-home')
  const root = new Hono()
  root.route('/api/auth', createAuthLeanRouter({ autoSeedDemo: true }))
  root.route('/', createOpRouter())
  root.route('/', createOpAccountsRouter())
  root.route('/', createOpHomeRouter())
  app = root

  // Land the demo cast + the client-registry seed (the seed rides the
  // first op.ts request, the boot posture), then the OP-registry
  // account the grant legs run on.
  const admin = await demoLogin('admin@oiml.org')
  const seeded = await app.request(`${ISSUER}/api/op/clients`, { headers: { cookie: admin } })
  expect(seeded.status).toBe(200)
  nadia = await inviteAndEnroll(admin, 'nadia.newcomer@example.org', 'Ms. Nadia Newcomer', 'nadia has a proper passphrase')
})

afterAll(async () => {
  const profileMod = await import('@oimlsmart/platform-server/profile')
  profileMod.resetInstanceProfileForTest()
  rmSync(TMP, { recursive: true, force: true })
  delete process.env.OP_ISSUER
  delete process.env.OP_CLIENT_SEED
  delete process.env.DATABASE_PATH
})

describe('the launcher feed', () => {
  it('answers 401 signed out', async () => {
    const res = await app.request(`${ISSUER}/api/op/home`)
    expect(res.status).toBe(401)
  })

  it('the bootstrap seed carried the launch metadata', async () => {
    const hub = await store.getOidcClient('hub-instance')
    expect(hub?.launch).toEqual({
      url: 'https://hub.example/api/auth/signin/oidc',
      icon: 'grid',
      description: 'The certification hub.',
      visibility: 'roles',
    })
    const machine = await store.getOidcClient('machine-relay')
    expect(machine?.launch).toBeNull()
  })

  it('a non-identity deployment answers 404 (the profile gate)', async () => {
    const profileMod = await import('@oimlsmart/platform-server/profile')
    profileMod.installInstanceProfile(profileMod.parseInstanceProfile(`
identity: { org_id: plain, org_name: Plain instance, role_codes: [hub] }
roles: [hub]
`))
    const res = await app.request(`${ISSUER}/api/op/home`)
    expect(res.status).toBe(404)
    profileMod.installInstanceProfile(profileMod.parseInstanceProfile(`
identity:
  org_id: oimlsmart-id
  org_name: OIML SMART Identity
  role_codes: [identity]
roles: [identity]
branding: { name: OIML SMART Identity }
demo_personas: true
`))
  })

  it('the admin sees exactly the services her roles admit', async () => {
    const admin = await demoLogin('admin@oiml.org')
    const feed = await homeFeed(admin)
    expect(feed.admin).toBe(true)
    expect(feed.account.email).toBe('admin@oiml.org')
    const byId = Object.fromEntries(feed.services.map((s: any) => [s.clientId, s]))
    // The hub: admin ∈ the allowlist → launchable, with the URL.
    expect(byId['hub-instance'].state).toBe('launch')
    expect(byId['hub-instance'].launchUrl).toBe('https://hub.example/api/auth/signin/oidc')
    // The TL: the admin holds no tl_operator → the request posture, and
    // NEVER a working launch (the leak check).
    expect(byId['tl-instance'].state).toBe('request')
    expect('launchUrl' in byId['tl-instance']).toBe(false)
    // The assistant: 'open' — every account enters.
    expect(byId['pubs-assistant'].state).toBe('launch')
    // The machine client never joined the launcher.
    expect(byId['machine-relay']).toBeUndefined()
  })

  it('the viewer meets the same computation from her own roles', async () => {
    const viewer = await demoLogin('viewer@oiml.org')
    const feed = await homeFeed(viewer)
    expect(feed.admin).toBe(false)
    const byId = Object.fromEntries(feed.services.map((s: any) => [s.clientId, s]))
    expect(byId['hub-instance'].state).toBe('launch') // viewer ∈ the hub's allowlist
    expect(byId['tl-instance'].state).toBe('request')
    expect(byId['pubs-assistant'].state).toBe('launch')
    expect(feed.services).toHaveLength(3)
  })

  it('a per-client role grant makes the card launchable (the audit chain carries the grant)', async () => {
    const before = await homeFeed(nadia.cookie)
    expect(before.services.find((s: any) => s.clientId === 'tl-instance').state).toBe('request')

    const admin = await demoLogin('admin@oiml.org')
    const grant = await grantClientRoles(admin, nadia.id, 'tl-instance', ['tl_operator'])
    expect(grant.status).toBe(200)

    const after = await homeFeed(nadia.cookie)
    const tl = after.services.find((s: any) => s.clientId === 'tl-instance')
    expect(tl.state).toBe('launch')
    expect(tl.launchUrl).toBe('https://tl.example/api/auth/signin/oidc')

    // The grant rides the audit chain (the registry's own event).
    const rows = await store.listEntities('auditEvents')
    const grants = rows
      .map(r => JSON.parse(r.data) as { entity_id?: string; action?: string; metadata?: any })
      .filter(e => e.entity_id === nadia.id && e.action === 'account.client_roles')
    expect(grants.length).toBeGreaterThan(0)
    expect(grants[0]!.metadata).toMatchObject({ client_id: 'tl-instance', roles: ['tl_operator'] })

    // And a grant OUTSIDE the client's allowlist never reaches the card:
    // the write itself is refused (clientRolesRefusal).
    const refused = await grantClientRoles(admin, nadia.id, 'tl-instance', ['admin'])
    expect(refused.status).toBe(400)

    // Clearing the assignment restores the default: the account's
    // OP-side set (viewer) is not in the TL's allowlist — the card
    // returns to the request posture.
    const cleared = await app.request(`${ISSUER}/api/op/accounts/${nadia.id}/client-roles/tl-instance`, {
      method: 'DELETE',
      headers: { cookie: admin },
    })
    expect(cleared.status).toBe(200)
    const restored = await homeFeed(nadia.cookie)
    expect(restored.services.find((s: any) => s.clientId === 'tl-instance').state).toBe('request')
  })

  it('a disabled client leaves the launcher entirely', async () => {
    const admin = await demoLogin('admin@oiml.org')
    const off = await app.request(`${ISSUER}/api/op/clients/tl-instance/status`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: admin },
      body: JSON.stringify({ status: 'disabled' }),
    })
    expect(off.status).toBe(200)
    const viewer = await demoLogin('viewer@oiml.org')
    const feed = await homeFeed(viewer)
    expect(feed.services.find((s: any) => s.clientId === 'tl-instance')).toBeUndefined()
    const on = await app.request(`${ISSUER}/api/op/clients/tl-instance/status`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: admin },
      body: JSON.stringify({ status: 'active' }),
    })
    expect(on.status).toBe(200)
  })
})

describe('the request-access intake', () => {
  it('records the request on the audit chain, idempotent on repeat', async () => {
    const ask = await app.request(`${ISSUER}/api/op/home/requests`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: nadia.cookie },
      body: JSON.stringify({ client_id: 'tl-instance' }),
    })
    expect(ask.status).toBe(201)

    const feed = await homeFeed(nadia.cookie)
    expect(feed.services.find((s: any) => s.clientId === 'tl-instance').requested).toBe(true)

    const again = await app.request(`${ISSUER}/api/op/home/requests`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: nadia.cookie },
      body: JSON.stringify({ client_id: 'tl-instance' }),
    })
    expect(again.status).toBe(200)
    expect((await again.json() as any).already).toBe(true)

    const rows = await store.listEntities('auditEvents')
    const requests = rows
      .map(r => JSON.parse(r.data) as { entity_type?: string; entity_id?: string; action?: string; metadata?: any })
      .filter(e => e.entity_type === 'account' && e.entity_id === nadia.id && e.action === 'account.access_request')
    expect(requests).toHaveLength(1)
    expect(requests[0]!.metadata).toMatchObject({ clientId: 'tl-instance', clientName: 'Example TL instance' })
  })

  it('refuses the dishonest asks plainly', async () => {
    const viewer = await demoLogin('viewer@oiml.org')
    const ask = (body: unknown, cookie = viewer) => app.request(`${ISSUER}/api/op/home/requests`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify(body),
    })
    // The 'roles' posture never takes requests (admitted or not).
    expect((await ask({ client_id: 'hub-instance' })).status).toBe(400)
    // The 'open' service takes no requests (everyone enters).
    expect((await ask({ client_id: 'pubs-assistant' })).status).toBe(400)
    // The unknown + the unlisted (no launch metadata).
    expect((await ask({ client_id: 'nope' })).status).toBe(404)
    expect((await ask({ client_id: 'machine-relay' })).status).toBe(404)
    // The malformed body + the signed-out ask.
    expect((await ask({})).status).toBe(400)
    expect((await ask({ client_id: 'tl-instance' }, '')).status).toBe(401)
    // The admitted-on-a-request-posture client: grant tl_operator, the
    // ask now conflicts (the card is launchable).
    const admin = await demoLogin('admin@oiml.org')
    expect((await grantClientRoles(admin, nadia.id, 'tl-instance', ['tl_operator'])).status).toBe(200)
    const conflict = await app.request(`${ISSUER}/api/op/home/requests`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: nadia.cookie },
      body: JSON.stringify({ client_id: 'tl-instance' }),
    })
    expect(conflict.status).toBe(409)
    await app.request(`${ISSUER}/api/op/accounts/${nadia.id}/client-roles/tl-instance`, {
      method: 'DELETE',
      headers: { cookie: admin },
    })
  })
})

describe('the registry API’s launch writes', () => {
  it('validates the card at write (the same refusal the seed throws)', async () => {
    const admin = await demoLogin('admin@oiml.org')
    const register = (launch: unknown) => app.request(`${ISSUER}/api/op/clients`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: admin },
      body: JSON.stringify({
        client_id: 'check-client',
        name: 'The validation subject',
        redirect_uris: ['https://check.example/callback'],
        launch,
      }),
    })
    expect((await register({ icon: 'grid' })).status).toBe(400) // no URL
    expect((await register({ url: 'not-a-url' })).status).toBe(400)
    expect((await register({ url: 'ftp://check.example/x' })).status).toBe(400)
    expect((await register({ url: 'https://check.example/signin', icon: 'crown' })).status).toBe(400)
    expect((await register({ url: 'https://check.example/signin', visibility: 'maybe' })).status).toBe(400)
    const ok = await register({ url: 'https://check.example/signin', icon: 'scale', description: 'A checked card.', visibility: 'request' })
    expect(ok.status).toBe(201)
    const view = await ok.json() as any
    expect(view.launch).toEqual({ url: 'https://check.example/signin', icon: 'scale', description: 'A checked card.', visibility: 'request' })

    // The audit metadata carried the write.
    const rows = await store.listEntities('auditEvents')
    const writes = rows
      .map(r => JSON.parse(r.data) as { entity_type?: string; entity_id?: string; action?: string; metadata?: any })
      .filter(e => e.entity_type === 'client' && e.entity_id === 'check-client' && e.action === 'client.registered')
    expect(writes).toHaveLength(1)
    expect(writes[0]!.metadata.launch).toMatchObject({ url: 'https://check.example/signin', visibility: 'request' })
  })

  it('an edit that omits launch keeps the card; launch: null takes it off', async () => {
    const admin = await demoLogin('admin@oiml.org')
    // Omit the launch key entirely: the stored card survives the edit.
    const edit = await app.request(`${ISSUER}/api/op/clients`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: admin },
      body: JSON.stringify({
        client_id: 'check-client',
        name: 'The validation subject, renamed',
        redirect_uris: ['https://check.example/callback'],
      }),
    })
    expect(edit.status).toBe(200)
    expect(((await edit.json()) as any).launch).toMatchObject({ url: 'https://check.example/signin' })

    // launch: null — the client leaves the launcher.
    const off = await app.request(`${ISSUER}/api/op/clients`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: admin },
      body: JSON.stringify({
        client_id: 'check-client',
        name: 'The validation subject, renamed',
        redirect_uris: ['https://check.example/callback'],
        launch: null,
      }),
    })
    expect(off.status).toBe(200)
    expect(((await off.json()) as any).launch).toBeNull()
    expect((await store.getOidcClient('check-client'))?.launch).toBeNull()
  })
})
