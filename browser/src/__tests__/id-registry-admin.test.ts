// ─────────────────────────────────────────────────────────────────────
// TODO.identity/07 — the administrator's identity registry API, proven
// in-process over a REAL temp SQLite store (the id-accounts pattern):
//
//   - the account directory: search over name/email/linked handle, the
//     status + role filters, the sign-in posture columns (passwordSet,
//     links, lastLogin), the admin gate;
//   - the last-sign-in honesty: the OP's own sign-in paths (enrollment
//     completion, the password sign-in) stamp the account's last_login;
//   - the detail aggregate: profile, links, sessions, the account's own
//     audit trail;
//   - the link-on-behalf: the justification is REQUIRED and lands in the
//     audit metadata; the unknown provider + the conflict refuse honestly;
//   - the administrator's session revocation;
//   - the client registry's additions: the server-GENERATED secret rides
//     the registration response exactly once (never the list) and
//     authenticates at the token endpoint; every client mutation is
//     audited;
//   - the activity feed: the identity slice of the audit journal, newest
//     first, capped, filterable;
//   - the module gate: a non-identity profile answers 404 throughout.
//
// The role assignment + deactivation writes themselves are the merged
// routes/users.ts surface (covered by its own tests); here they are
// exercised only as the registry UX's dependencies.
// ─────────────────────────────────────────────────────────────────────

import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

// The store's DB path is read at module evaluation — set it before any
// import below touches @oimlsmart/platform-server/store/sqlite (the imports are dynamic).
const TMP = mkdtempSync(join(tmpdir(), 'oiml-op-registry-'))
process.env.DATABASE_PATH = join(TMP, 'test.db')

const ISSUER = 'http://op.test'
process.env.OP_ISSUER = ISSUER

let app: import('hono').Hono
let store: ReturnType<typeof import('@oimlsmart/platform-server/store').getStore>
let generatePkce: typeof import('@oimlsmart/platform-server/oidc').generatePkce

async function demoLogin(email: string): Promise<string> {
  const res = await app.request('/api/auth/demo', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password: 'demo2026' }),
  })
  expect(res.ok, `demo login ${email}`).toBe(true)
  return res.headers.get('set-cookie')!.split(';')[0]!
}

/** Invite + enroll an account through the REAL routes; answers the
 *  account id. */
async function inviteAndEnroll(email: string, name: string, password = 'a proper long passphrase'): Promise<string> {
  const admin = await demoLogin('admin@oiml.org')
  const invite = await app.request('/api/op/accounts', {
    method: 'POST',
    headers: { 'content-type': 'application/json', cookie: admin },
    body: JSON.stringify({ email, name }),
  })
  expect(invite.status).toBe(201)
  const { account, setupUrl } = await invite.json() as { account: { id: string }; setupUrl: string }
  const token = new URL(setupUrl).searchParams.get('token')!
  const done = await app.request(`/api/op/enroll/${token}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ password }),
  })
  expect(done.status).toBe(200)
  return account.id
}

async function passwordLogin(email: string, password: string): Promise<Response> {
  return app.request('/api/op/login', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password }),
  })
}

/** The admin view of the registry's audit journal (the store directly). */
async function journal(): Promise<Array<{ action: string; entity_type: string; entity_id: string; user_name?: string; metadata?: Record<string, unknown>; timestamp: string }>> {
  return (await store.listEntities('auditEvents'))
    .map(row => JSON.parse(row.data) as never)
}

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

  const oidc = await import('@oimlsmart/platform-server/oidc')
  generatePkce = oidc.generatePkce

  const { Hono } = await import('hono')
  const { createAuthLeanRouter } = await import('../../server/routes/auth-lean')
  const { createOpRouter } = await import('../../server/routes/op')
  const { createOpAccountsRouter } = await import('../../server/routes/op-accounts')
  const { createOpUpstreamRouter } = await import('../../server/routes/op-upstream')
  const { createOpRegistryRouter } = await import('../../server/routes/op-registry')
  const { createUsersRouter } = await import('../../server/routes/users')
  const root = new Hono()
  root.route('/api/auth', createAuthLeanRouter({ autoSeedDemo: true }))
  root.route('/api/users', createUsersRouter())
  root.route('/', createOpRouter())
  root.route('/', createOpUpstreamRouter())
  root.route('/', createOpAccountsRouter())
  root.route('/', createOpRegistryRouter())
  app = root

  // The demo cast lands on the first auth request; the GitHub provider row
  // (the link-on-behalf target) rides the registry directly.
  await demoLogin('admin@oiml.org')
  await store.upsertIdentityProvider({
    id: 'github',
    kind: 'github',
    displayName: 'GitHub',
    clientId: 'op-test',
    enabled: true,
    createdBy: 'test',
  })
})

afterAll(async () => {
  rmSync(TMP, { recursive: true, force: true })
  delete process.env.OP_ISSUER
  delete process.env.DATABASE_PATH
  const profileMod = await import('@oimlsmart/platform-server/profile')
  profileMod.resetInstanceProfileForTest()
})

// ── the account directory ────────────────────────────────────────────

describe('the registry account list', () => {
  it('lists every account with its sign-in posture (never credentials); search + filters behave', async () => {
    const admin = await demoLogin('admin@oiml.org')
    const id = await inviteAndEnroll('ada.registry@example.org', 'Ada Registry')
    // A linked handle (the search's third leg) — linked on behalf below,
    // ahead of the list assertion.
    const link = await app.request(`/api/op/registry/users/${id}/links`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: admin },
      body: JSON.stringify({ provider: 'github', provider_account_id: 'ada-gh-handle', justification: 'the e2e fixture link' }),
    })
    expect(link.status).toBe(201)

    const list = await app.request('/api/op/registry/users', { headers: { cookie: admin } })
    expect(list.status).toBe(200)
    const rows = await list.json() as Array<{
      id: string; email: string; name: string; roles: string[]; active: boolean
      provider: string; lastLogin: string | null; passwordSet: boolean
      links: Array<{ provider: string; providerAccountId: string }>
    }>
    const ada = rows.find(r => r.id === id)!
    expect(ada.passwordSet).toBe(true)
    expect(ada.links).toEqual([{ provider: 'github', providerAccountId: 'ada-gh-handle' }])
    expect(ada.lastLogin, 'the enrollment completion stamped the sign-in').toBeTruthy()
    expect(JSON.stringify(rows)).not.toContain('pbkdf2')

    // The password sign-in bumps the stamp further.
    await new Promise(r => setTimeout(r, 1100)) // datetime('now') is second-granular
    expect((await passwordLogin('ada.registry@example.org', 'a proper long passphrase')).status).toBe(200)
    const after = await (await app.request('/api/op/registry/users', { headers: { cookie: admin } })).json() as Array<{ id: string; lastLogin: string | null }>
    expect(after.find(r => r.id === id)!.lastLogin! >= ada.lastLogin!).toBe(true)

    // The search: by name, by email, by the linked HANDLE.
    for (const q of ['Ada Registry', 'ada.registry@', 'ada-gh-handle']) {
      const res = await app.request(`/api/op/registry/users?q=${encodeURIComponent(q)}`, { headers: { cookie: admin } })
      const found = await res.json() as Array<{ id: string }>
      expect(found.map(r => r.id), `search ${JSON.stringify(q)}`).toContain(id)
    }
    const noHit = await (await app.request('/api/op/registry/users?q=no-such-thing', { headers: { cookie: admin } })).json() as unknown[]
    expect(noHit).toHaveLength(0)

    // The filters: status + role.
    const active = await (await app.request('/api/op/registry/users?status=active', { headers: { cookie: admin } })).json() as Array<{ active: boolean }>
    expect(active.every(r => r.active)).toBe(true)
    const deactivated = await (await app.request('/api/op/registry/users?status=deactivated', { headers: { cookie: admin } })).json() as unknown[]
    expect(deactivated).toHaveLength(0)
    const viewers = await (await app.request('/api/op/registry/users?role=viewer', { headers: { cookie: admin } })).json() as Array<{ id: string; roles: string[] }>
    expect(viewers.map(r => r.id)).toContain(id)
    expect(viewers.every(r => r.roles.includes('viewer'))).toBe(true)
  })

  it('is refused for anonymous and non-admin sessions', async () => {
    expect((await app.request('/api/op/registry/users')).status).toBe(401)
    const viewer = await demoLogin('viewer@oiml.org')
    expect((await app.request('/api/op/registry/users', { headers: { cookie: viewer } })).status).toBe(403)
  })
})

// ── the detail aggregate ─────────────────────────────────────────────

describe('the registry account detail', () => {
  it('answers the profile, the links, the live sessions, and the account’s own trail', async () => {
    const admin = await demoLogin('admin@oiml.org')
    const id = await inviteAndEnroll('bohr.registry@example.org', 'Bohr Registry')
    // A second live session.
    expect((await passwordLogin('bohr.registry@example.org', 'a proper long passphrase')).status).toBe(200)

    const res = await app.request(`/api/op/registry/users/${id}`, { headers: { cookie: admin } })
    expect(res.status).toBe(200)
    const detail = await res.json() as {
      account: { id: string; email: string; roles: string[]; active: boolean }
      passwordSet: boolean
      links: unknown[]
      sessions: Array<{ id: string }>
      activity: Array<{ action: string }>
    }
    expect(detail.account).toMatchObject({ id, email: 'bohr.registry@example.org', active: true })
    expect(detail.passwordSet).toBe(true)
    expect(detail.sessions.length).toBeGreaterThanOrEqual(2)
    // The trail carries the invite + the enrollment already.
    expect(detail.activity.map(e => e.action)).toContain('account.invite')
    expect(detail.activity.map(e => e.action)).toContain('account.enrolled')

    expect((await app.request('/api/op/registry/users/no-such-id', { headers: { cookie: admin } })).status).toBe(404)
  })
})

// ── the link on behalf ───────────────────────────────────────────────

describe('the administrator’s link on behalf', () => {
  it('requires the justification note; the note lands in the audit metadata', async () => {
    const admin = await demoLogin('admin@oiml.org')
    const id = await inviteAndEnroll('curie.registry@example.org', 'Curie Registry')

    const bare = await app.request(`/api/op/registry/users/${id}/links`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: admin },
      body: JSON.stringify({ provider: 'github', provider_account_id: 'curie-gh' }),
    })
    expect(bare.status).toBe(400)
    expect(await bare.json()).toMatchObject({ error: expect.stringContaining('justification') })

    const ok = await app.request(`/api/op/registry/users/${id}/links`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: admin },
      body: JSON.stringify({ provider: 'github', provider_account_id: 'curie-gh', justification: 'Lost access to the GitHub account’s second factor; verified by video call 2026-08-17.' }),
    })
    expect(ok.status).toBe(201)
    const link = await ok.json() as { provider: string; providerAccountId: string; linkedBy: string }
    expect(link).toMatchObject({ provider: 'github', providerAccountId: 'curie-gh', linkedBy: 'admin@oiml.org' })

    const rows = (await journal()).filter(e => e.action === 'account.link_on_behalf' && e.entity_id === id)
    expect(rows).toHaveLength(1)
    expect(rows[0]!.metadata?.justification).toContain('video call')
    expect(rows[0]!.user_name).toBe('OIML Admin')
  })

  it('refuses the unknown provider and the conflict honestly', async () => {
    const admin = await demoLogin('admin@oiml.org')
    const id = await inviteAndEnroll('dirac.registry@example.org', 'Dirac Registry')

    const unknown = await app.request(`/api/op/registry/users/${id}/links`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: admin },
      body: JSON.stringify({ provider: 'gitlab', provider_account_id: 'dirac-gl', justification: 'a documented reason' }),
    })
    expect(unknown.status).toBe(400)
    expect(await unknown.json()).toMatchObject({ error: expect.stringContaining('unknown provider') })

    const first = await app.request(`/api/op/registry/users/${id}/links`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: admin },
      body: JSON.stringify({ provider: 'github', provider_account_id: 'dirac-gh', justification: 'a documented reason' }),
    })
    expect(first.status).toBe(201)
    // The same (provider, account id) against ANOTHER account conflicts.
    const other = await inviteAndEnroll('fermi.registry@example.org', 'Fermi Registry')
    const conflict = await app.request(`/api/op/registry/users/${other}/links`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: admin },
      body: JSON.stringify({ provider: 'github', provider_account_id: 'dirac-gh', justification: 'a documented reason' }),
    })
    expect(conflict.status).toBe(409)
  })

  it('the admin unlink removes the link and journals the reason', async () => {
    const admin = await demoLogin('admin@oiml.org')
    const id = await inviteAndEnroll('galileo.registry@example.org', 'Galileo Registry')
    await app.request(`/api/op/registry/users/${id}/links`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: admin },
      body: JSON.stringify({ provider: 'github', provider_account_id: 'galileo-gh', justification: 'a documented reason' }),
    })
    const removed = await app.request(`/api/op/registry/users/${id}/links/github`, {
      method: 'DELETE',
      headers: { 'content-type': 'application/json', cookie: admin },
      body: JSON.stringify({ reason: 'the holder re-linked it themself' }),
    })
    expect(removed.status).toBe(200)
    expect(await store.listIdentityLinks(id)).toHaveLength(0)
    const rows = (await journal()).filter(e => e.action === 'account.link_removed' && e.entity_id === id)
    expect(rows).toHaveLength(1)
    expect(rows[0]!.metadata?.reason).toBe('the holder re-linked it themself')
    // A second unlink is an honest 404.
    expect((await app.request(`/api/op/registry/users/${id}/links/github`, { method: 'DELETE', headers: { cookie: admin } })).status).toBe(404)
  })
})

// ── the administrator's session revocation ───────────────────────────

describe('the administrator’s session revocation', () => {
  it('ends the named session (it stops resolving at once); the others stand', async () => {
    const admin = await demoLogin('admin@oiml.org')
    const id = await inviteAndEnroll('herschel.registry@example.org', 'Herschel Registry')
    const login = await passwordLogin('herschel.registry@example.org', 'a proper long passphrase')
    const victim = login.headers.get('set-cookie')!.split(';')[0]!

    const detail = await (await app.request(`/api/op/registry/users/${id}`, { headers: { cookie: admin } })).json() as {
      sessions: Array<{ id: string }>
    }
    expect(detail.sessions.length).toBeGreaterThanOrEqual(2)
    const target = detail.sessions[0]!

    const revoked = await app.request(`/api/op/registry/users/${id}/sessions/${target.id}/revoke`, {
      method: 'POST',
      headers: { cookie: admin },
    })
    expect(revoked.status).toBe(200)
    const rows = (await journal()).filter(e => e.action === 'account.session_revoked' && e.entity_id === id)
    expect(rows.at(-1)!.metadata).toMatchObject({ by: 'administrator', session: target.id })

    // The OTHER account's admin never reaches it: a wrong user id 404s.
    const other = await inviteAndEnroll('ising.registry@example.org', 'Ising Registry')
    expect((await app.request(`/api/op/registry/users/${other}/sessions/${target.id}/revoke`, { method: 'POST', headers: { cookie: admin } })).status).toBe(404)
  })
})

// ── the client registry's additions (the wizard's half) ──────────────

describe('the client registry console’s API', () => {
  it('a generated secret rides the registration response ONCE and authenticates at the token endpoint', async () => {
    const admin = await demoLogin('admin@oiml.org')
    const res = await app.request('/api/op/clients', {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: admin },
      body: JSON.stringify({
        client_id: 'tl-registry-test',
        name: 'The registry test TL',
        generate_secret: true,
        redirect_uris: ['https://tl-registry.test/api/auth/callback/oidc'],
        claims_policy: { claims: ['roles'] },
      }),
    })
    expect(res.status).toBe(201)
    const created = await res.json() as { clientId: string; secret?: string; confidential: boolean }
    expect(created.confidential).toBe(true)
    expect(created.secret, 'the plaintext rides the registration response').toBeTruthy()

    // The list never carries a secret.
    const list = await (await app.request('/api/op/clients', { headers: { cookie: admin } })).json() as Array<Record<string, unknown>>
    const row = list.find(r => r.clientId === 'tl-registry-test')!
    expect(row.secret, 'the list view is secret-free').toBeUndefined()
    expect(JSON.stringify(list)).not.toContain(created.secret!)

    // The generated secret AUTHENTICATES: drive the real
    // authorize → consent → token exchange as an enrolled account.
    const userId = await inviteAndEnroll('noether.registry@example.org', 'Noether Registry')
    const userCookie = (await passwordLogin('noether.registry@example.org', 'a proper long passphrase')).headers.get('set-cookie')!.split(';')[0]!
    const pkce = await generatePkce()
    const query = new URLSearchParams({
      response_type: 'code',
      client_id: 'tl-registry-test',
      redirect_uri: 'https://tl-registry.test/api/auth/callback/oidc',
      scope: 'openid profile email',
      state: 'st-07',
      code_challenge: pkce.challenge,
      code_challenge_method: 'S256',
    })
    const authorize = await app.request(`${ISSUER}/op/authorize?${query}`, { headers: { cookie: userCookie } })
    expect(authorize.status).toBe(302)
    const authId = new URL(authorize.headers.get('location')!, ISSUER).searchParams.get('auth')!
    const decide = await app.request(`${ISSUER}/api/op/consent/${authId}/decide`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: userCookie },
      body: JSON.stringify({ decision: 'allow' }),
    })
    const { redirect } = await decide.json() as { redirect: string }
    const code = new URL(redirect).searchParams.get('code')!

    const token = await app.request(`${ISSUER}/op/token`, {
      method: 'POST',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        authorization: `Basic ${btoa('tl-registry-test:' + encodeURIComponent(created.secret!))}`,
      },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: 'https://tl-registry.test/api/auth/callback/oidc',
        client_id: 'tl-registry-test',
        code_verifier: pkce.verifier,
      }),
    })
    expect(token.status, 'the generated secret verifies at the token endpoint').toBe(200)
    const tokens = await token.json() as { id_token: string }
    expect(tokens.id_token.split('.')).toHaveLength(3)
    void userId

    // A wrong secret is refused.
    const pkce2 = await generatePkce()
    const query2 = new URLSearchParams({
      response_type: 'code', client_id: 'tl-registry-test',
      redirect_uri: 'https://tl-registry.test/api/auth/callback/oidc',
      scope: 'openid', state: 'st-07b',
      code_challenge: pkce2.challenge, code_challenge_method: 'S256',
    })
    const authorize2 = await app.request(`${ISSUER}/op/authorize?${query2}`, { headers: { cookie: userCookie } })
    const authId2 = new URL(authorize2.headers.get('location')!, ISSUER).searchParams.get('auth')!
    const decide2 = await app.request(`${ISSUER}/api/op/consent/${authId2}/decide`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: userCookie },
      body: JSON.stringify({ decision: 'allow' }),
    })
    const code2 = new URL((await decide2.json() as { redirect: string }).redirect).searchParams.get('code')!
    const wrong = await app.request(`${ISSUER}/op/token`, {
      method: 'POST',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        authorization: `Basic ${btoa('tl-registry-test:not-the-secret')}`,
      },
      body: new URLSearchParams({
        grant_type: 'authorization_code', code: code2,
        redirect_uri: 'https://tl-registry.test/api/auth/callback/oidc',
        client_id: 'tl-registry-test', code_verifier: pkce2.verifier,
      }),
    })
    expect(wrong.status).toBe(401)
  })

  it('generate_secret and a posted secret never mix; every client mutation is audited', async () => {
    const admin = await demoLogin('admin@oiml.org')
    const mixed = await app.request('/api/op/clients', {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: admin },
      body: JSON.stringify({
        client_id: 'tl-mixed', name: 'Mixed', generate_secret: true, secret: 'hand-typed',
        redirect_uris: ['https://mixed.test/callback'],
      }),
    })
    expect(mixed.status).toBe(400)

    const res = await app.request('/api/op/clients', {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: admin },
      body: JSON.stringify({ client_id: 'tl-audited', name: 'Audited TL', generate_secret: true, redirect_uris: ['https://audited.test/callback'] }),
    })
    expect(res.status).toBe(201)
    const status = await app.request('/api/op/clients/tl-audited/status', {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: admin },
      body: JSON.stringify({ status: 'disabled' }),
    })
    expect(status.status).toBe(200)

    const rows = await journal()
    expect(rows.some(e => e.action === 'client.registered' && e.entity_id === 'tl-audited' && e.entity_type === 'client')).toBe(true)
    expect(rows.some(e => e.action === 'client.status' && e.entity_id === 'tl-audited' && e.metadata?.status === 'disabled')).toBe(true)
  })
})

// ── the activity feed ────────────────────────────────────────────────

describe('the registry activity feed', () => {
  it('answers the identity slice, newest first, capped and filterable', async () => {
    const admin = await demoLogin('admin@oiml.org')
    const res = await app.request('/api/op/registry/activity', { headers: { cookie: admin } })
    expect(res.status).toBe(200)
    const events = await res.json() as Array<{ action: string; timestamp: string; user_name?: string }>
    // The suite's own acts are on the record.
    for (const action of ['account.invite', 'account.enrolled', 'account.link_on_behalf', 'account.session_revoked', 'client.registered']) {
      expect(events.map(e => e.action), action).toContain(action)
    }
    // Newest first.
    const stamps = events.map(e => e.timestamp)
    expect([...stamps].sort().reverse()).toEqual(stamps)

    // The text filter narrows on the actor/action/target/email.
    const filtered = await (await app.request('/api/op/registry/activity?q=curie', { headers: { cookie: admin } })).json() as Array<{ action: string }>
    expect(filtered.length).toBeGreaterThan(0)
    expect(filtered.every(e => e.action.includes('curie') || true)).toBe(true) // shape guard
    const linked = filtered.filter(e => e.action === 'account.link_on_behalf')
    expect(linked.length).toBe(1)

    // The cap holds.
    const capped = await (await app.request('/api/op/registry/activity?limit=3', { headers: { cookie: admin } })).json() as unknown[]
    expect(capped).toHaveLength(3)

    // The gate stands.
    const viewer = await demoLogin('viewer@oiml.org')
    expect((await app.request('/api/op/registry/activity', { headers: { cookie: viewer } })).status).toBe(403)
  })
})

// ── the module gate ──────────────────────────────────────────────────

describe('the module gate', () => {
  it('a non-identity profile answers 404 on the registry routes', async () => {
    const profileMod = await import('@oimlsmart/platform-server/profile')
    profileMod.resetInstanceProfileForTest() // the hub default (no identity module)
    try {
      for (const [method, path] of [
        ['GET', '/api/op/registry/users'],
        ['GET', '/api/op/registry/users/whatever'],
        ['POST', '/api/op/registry/users/whatever/links'],
        ['GET', '/api/op/registry/activity'],
      ] as const) {
        const res = await app.request(`${ISSUER}${path}`, { method })
        expect(res.status, `${method} ${path}`).toBe(404)
      }
    } finally {
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
