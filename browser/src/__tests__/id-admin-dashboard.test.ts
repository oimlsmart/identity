// ─────────────────────────────────────────────────────────────────────
// TODO.identity-sso/01 — the admin dashboard's API, proven in-process
// over a REAL temp SQLite store (the id-registry-admin pattern):
//
//   - the overview: lifecycle counts (invited is honest: the password
//     account whose enrollment never completed), the 14-day sign-in
//     series, today's anomaly counters, the live-session count;
//   - the aggregate live sessions: rows across accounts carry the
//     account + the sign-in context, the administrator's own row is
//     marked current, and NO token value ever leaves the store;
//   - the revoke-all light act: the count, the audit event, the other
//     account standing, the revoked cookie stopping resolving;
//   - the sign-in failure audits: wrong password / unknown address /
//     deactivated land account.sign_in_failed with the honest reason,
//     the caller's answers unchanged, the holder's own feed seeing the
//     attempt;
//   - the status probe's recognition (auth/op/probe.ts): the recognized
//     X-OIML-Probe token re-labels the invalid-credentials row
//     account.sign_in_probe (the answer unchanged), the unrecognized
//     header and the unset secret stay ordinary callers, the feeds +
//     the burst signal exclude the probe rows, the raw chain retains
//     them;
//   - the token endpoint's audits: client.token_issued on the exchange,
//     client.token_refused on the wrong secret and the replayed code;
//   - the security signals: the burst threshold, the refusal split, the
//     new links/clients windows;
//   - the queryable audit log: the filters + the CSV export;
//   - the live access review: the privileged holders, the per-client
//     privileged grants, the findings, the posture;
//   - the per-client activity: the issuance series from the journal;
//   - the heartbeat route: the stubbed GitHub API (the green window and
//     the honest unavailable), never a fabricated number;
//   - the gates: 401 anonymous, 403 non-admin, 404 the non-identity
//     profile.
// ─────────────────────────────────────────────────────────────────────

import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createServer, type Server } from 'node:http'
import type { AddressInfo } from 'node:net'
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest'

// The store's DB path is read at module evaluation — set it before any
// import below touches @oimlsmart/platform-server/store/sqlite (the imports are dynamic).
const TMP = mkdtempSync(join(tmpdir(), 'oiml-op-dashboard-'))
process.env.DATABASE_PATH = join(TMP, 'test.db')

const ISSUER = 'http://op.test'
process.env.OP_ISSUER = ISSUER

let app: import('hono').Hono
let store: ReturnType<typeof import('@oimlsmart/platform-server/store').getStore>
let generatePkce: typeof import('@oimlsmart/platform-server/oidc').generatePkce

/** The stubbed GitHub Actions API (the heartbeat route's source). */
let ghStub: Server
let ghStubBase: string

async function demoLogin(email: string): Promise<string> {
  const res = await app.request('/api/auth/demo', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password: 'demo2026' }),
  })
  expect(res.ok, `demo login ${email}`).toBe(true)
  return res.headers.get('set-cookie')!.split(';')[0]!
}

/** Invite through the REAL route; answers the account id + setup token. */
async function invite(email: string, name: string): Promise<{ id: string; setupToken: string }> {
  const admin = await demoLogin('admin@oiml.org')
  const res = await app.request('/api/op/accounts', {
    method: 'POST',
    headers: { 'content-type': 'application/json', cookie: admin },
    body: JSON.stringify({ email, name }),
  })
  expect(res.status).toBe(201)
  const { account, setupUrl } = await res.json() as { account: { id: string }; setupUrl: string }
  return { id: account.id, setupToken: new URL(setupUrl).searchParams.get('token')! }
}

async function enroll(setupToken: string, password = 'a proper long passphrase'): Promise<void> {
  const done = await app.request(`/api/op/enroll/${setupToken}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ password }),
  })
  expect(done.status).toBe(200)
}

async function passwordLogin(email: string, password: string): Promise<Response> {
  return app.request('/api/op/login', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password }),
  })
}

/** The admin view of the audit journal (the store directly). */
async function journal(): Promise<Array<{ action: string; entity_type: string; entity_id: string; user_name?: string; metadata?: Record<string, unknown>; timestamp: string }>> {
  return (await store.listEntities('auditEvents'))
    .map(row => JSON.parse(row.data) as never)
}

/** Drive a real authorize → consent → token exchange; answers the token
 *  response. The client's claims policy is the registration's. */
async function driveCodeExchange(clientId: string, secret: string, userCookie: string): Promise<Response> {
  const pkce = await generatePkce()
  const query = new URLSearchParams({
    response_type: 'code',
    client_id: clientId,
    redirect_uri: 'https://dash-rp.test/callback',
    scope: 'openid profile email',
    state: 'st-dash',
    code_challenge: pkce.challenge,
    code_challenge_method: 'S256',
    // The consent stop is this helper's contract (TODO.identity-features/12:
    // a remembered grant would skip it on a repeat sign-in).
    prompt: 'consent',
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
  return app.request(`${ISSUER}/op/token`, {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      authorization: `Basic ${btoa(`${clientId}:${encodeURIComponent(secret)}`)}`,
    },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: 'https://dash-rp.test/callback',
      client_id: clientId,
      code_verifier: pkce.verifier,
    }),
  })
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
  const { createOpDashboardRouter } = await import('../../server/routes/op-dashboard')
  const { createUsersRouter } = await import('../../server/routes/users')
  const root = new Hono()
  root.route('/api/auth', createAuthLeanRouter({ autoSeedDemo: true }))
  root.route('/api/users', createUsersRouter())
  root.route('/', createOpRouter())
  root.route('/', createOpUpstreamRouter())
  root.route('/', createOpAccountsRouter())
  root.route('/', createOpRegistryRouter())
  root.route('/', createOpDashboardRouter())
  app = root

  await demoLogin('admin@oiml.org')

  // The stubbed GitHub Actions API the heartbeat route reads.
  ghStub = createServer((req, res) => {
    if (req.url?.includes('/actions/workflows/broken.yml/runs')) {
      res.writeHead(500, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ message: 'the stub is red' }))
      return
    }
    res.writeHead(200, { 'content-type': 'application/json' })
    res.end(JSON.stringify({
      workflow_runs: [
        { id: 3, status: 'completed', conclusion: 'success', created_at: '2026-08-24T09:52:00Z', html_url: 'https://github.test/runs/3' },
        { id: 2, status: 'completed', conclusion: 'failure', created_at: '2026-08-24T09:37:00Z', html_url: 'https://github.test/runs/2' },
        { id: 1, status: 'completed', conclusion: 'success', created_at: '2026-08-24T09:22:00Z', html_url: 'https://github.test/runs/1' },
      ],
    }))
  })
  await new Promise<void>(resolve => ghStub.listen(0, '127.0.0.1', resolve))
  ghStubBase = `http://127.0.0.1:${(ghStub.address() as AddressInfo).port}`
  process.env.OP_HEARTBEAT_API_BASE = ghStubBase
})

afterAll(async () => {
  await new Promise<void>(resolve => ghStub.close(() => resolve()))
  rmSync(TMP, { recursive: true, force: true })
  delete process.env.OP_ISSUER
  delete process.env.DATABASE_PATH
  delete process.env.OP_HEARTBEAT_API_BASE
  delete process.env.OP_HEARTBEAT_WORKFLOW
  delete process.env.OP_HEARTBEAT_REPO
  const profileMod = await import('@oimlsmart/platform-server/profile')
  profileMod.resetInstanceProfileForTest()
})

// ── the overview ─────────────────────────────────────────────────────

describe('the dashboard overview', () => {
  it('answers the lifecycle split, the series, the anomaly counters, and the live count', async () => {
    const admin = await demoLogin('admin@oiml.org')
    const before = await (await app.request('/api/op/dashboard/overview', { headers: { cookie: admin } })).json() as {
      accounts: { invited: number }
    }

    // An invited-but-never-enrolled account is the invited tile's unit.
    await invite('invited.dashboard@example.org', 'Invited Dashboard')
    // A succeeded and a failed sign-in land in today's bucket.
    const ada = await invite('ada.dashboard@example.org', 'Ada Dashboard')
    await enroll(ada.setupToken)
    expect((await passwordLogin('ada.dashboard@example.org', 'a proper long passphrase')).status).toBe(200)
    expect((await passwordLogin('ada.dashboard@example.org', 'the wrong passphrase')).status).toBe(401)

    const res = await app.request('/api/op/dashboard/overview', { headers: { cookie: admin } })
    expect(res.status).toBe(200)
    const body = await res.json() as {
      generatedAt: string
      retention: string
      accounts: { total: number; active: number; deactivated: number; invited: number }
      signIns: { days: Array<{ date: string; succeeded: number; failed: number }>; totals: { succeeded: number; failed: number } }
      anomaliesToday: { failedSignIns: number }
      liveSessions: number
    }
    expect(body.accounts.invited, 'the invite without enrollment counts').toBe(before.accounts.invited + 1)
    expect(body.accounts.active).toBeGreaterThan(0)
    expect(body.accounts.total).toBe(body.accounts.active + body.accounts.deactivated)
    expect(body.signIns.days).toHaveLength(14)
    const today = body.signIns.days.at(-1)!
    expect(today.succeeded, 'the password sign-in landed').toBeGreaterThanOrEqual(1)
    expect(today.failed, 'the wrong-password attempt landed').toBeGreaterThanOrEqual(1)
    expect(body.anomaliesToday.failedSignIns).toBeGreaterThanOrEqual(1)
    expect(body.liveSessions, 'the admin and ada hold live sessions').toBeGreaterThanOrEqual(2)
    expect(body.retention).toContain('audit journal')
  })

  it('is refused for anonymous and non-admin sessions', async () => {
    expect((await app.request('/api/op/dashboard/overview')).status).toBe(401)
    const viewer = await demoLogin('viewer@oiml.org')
    expect((await app.request('/api/op/dashboard/overview', { headers: { cookie: viewer } })).status).toBe(403)
  })
})

// ── the aggregate live sessions + the revoke-all ─────────────────────

describe('the aggregate live sessions', () => {
  it('lists every live session with its account, marks the administrator’s own, never a token', async () => {
    const admin = await demoLogin('admin@oiml.org')
    const bohr = await invite('bohr.dashboard@example.org', 'Bohr Dashboard')
    await enroll(bohr.setupToken)
    const bohrCookie = (await passwordLogin('bohr.dashboard@example.org', 'a proper long passphrase')).headers.get('set-cookie')!.split(';')[0]!

    const res = await app.request('/api/op/dashboard/sessions', { headers: { cookie: admin } })
    expect(res.status).toBe(200)
    const body = await res.json() as {
      sessions: Array<{ id: string; account: { id: string; email: string | null }; current: boolean }>
      retention: string
    }
    const bohrRow = body.sessions.find(s => s.account.id === bohr.id)
    expect(bohrRow, 'bohr’s session is in the aggregate').toBeTruthy()
    expect(bohrRow!.account.email).toBe('bohr.dashboard@example.org')
    const mine = body.sessions.find(s => s.current)
    expect(mine, 'the administrator’s own row is marked').toBeTruthy()
    expect(mine!.account.email).toBe('admin@oiml.org')
    expect(JSON.stringify(body), 'no token value leaves the store').not.toContain(bohrCookie.split('=')[1]!)
    expect(JSON.stringify(body)).not.toContain(admin.split('=')[1]!)

    // The gate.
    const viewer = await demoLogin('viewer@oiml.org')
    expect((await app.request('/api/op/dashboard/sessions', { headers: { cookie: viewer } })).status).toBe(403)
  })

  it('the revoke-all light act ends every session of the account, audits, and leaves the others', async () => {
    const admin = await demoLogin('admin@oiml.org')
    const target = await invite('light.dashboard@example.org', 'Light Dashboard')
    await enroll(target.setupToken)
    const c1 = (await passwordLogin('light.dashboard@example.org', 'a proper long passphrase')).headers.get('set-cookie')!.split(';')[0]!
    const c2 = (await passwordLogin('light.dashboard@example.org', 'a proper long passphrase')).headers.get('set-cookie')!.split(';')[0]!
    const bystander = await invite('standing.dashboard@example.org', 'Standing Dashboard')
    await enroll(bystander.setupToken)
    const c3 = (await passwordLogin('standing.dashboard@example.org', 'a proper long passphrase')).headers.get('set-cookie')!.split(';')[0]!

    const res = await app.request(`/api/op/dashboard/accounts/${target.id}/sessions/revoke-all`, {
      method: 'POST',
      headers: { cookie: admin },
    })
    expect(res.status).toBe(200)
    // THREE: the enrollment ceremony itself signs the account in (the
    // setup link's own session) plus the two password logins.
    expect(await res.json()).toMatchObject({ ok: true, revoked: 3 })

    // The revoked cookies stop resolving; the bystander's stands.
    expect((await app.request('/api/auth/session', { headers: { cookie: c1 } })).status).toBe(401)
    expect((await app.request('/api/auth/session', { headers: { cookie: c2 } })).status).toBe(401)
    expect((await app.request('/api/auth/session', { headers: { cookie: c3 } })).status).toBe(200)

    const rows = (await journal()).filter(e => e.action === 'account.sessions_revoked' && e.entity_id === target.id)
    expect(rows).toHaveLength(1)
    expect(rows[0]!.metadata).toMatchObject({ by: 'administrator', count: 3, email: 'light.dashboard@example.org' })
    expect(rows[0]!.user_name).toBe('OIML Admin')

    // The unknown account 404s; the gate stands.
    expect((await app.request('/api/op/dashboard/accounts/no-such/sessions/revoke-all', { method: 'POST', headers: { cookie: admin } })).status).toBe(404)
    const viewer = await demoLogin('viewer@oiml.org')
    expect((await app.request(`/api/op/dashboard/accounts/${target.id}/sessions/revoke-all`, { method: 'POST', headers: { cookie: viewer } })).status).toBe(403)
  })
})

// ── the sign-in failure audits ───────────────────────────────────────

describe('the sign-in failure audits', () => {
  it('the wrong password, the unknown address, and the deactivated account each land honestly', async () => {
    const curie = await invite('curie.dashboard@example.org', 'Curie Dashboard')
    await enroll(curie.setupToken)

    expect((await passwordLogin('curie.dashboard@example.org', 'wrong')).status).toBe(401)
    expect((await passwordLogin('nobody-here@example.org', 'wrong')).status).toBe(401)

    // Deactivate, then the RIGHT password: the honest 403 + the audit.
    const admin = await demoLogin('admin@oiml.org')
    const off = await app.request(`/api/users/${curie.id}/active`, {
      method: 'PUT',
      headers: { 'content-type': 'application/json', cookie: admin },
      body: JSON.stringify({ active: false }),
    })
    expect(off.status).toBe(200)
    expect((await passwordLogin('curie.dashboard@example.org', 'a proper long passphrase')).status).toBe(403)

    const rows = (await journal()).filter(e => e.action === 'account.sign_in_failed')
    const wrongPassword = rows.find(e => e.entity_id === curie.id && e.metadata?.reason === 'invalid_credentials')
    const unknownAddress = rows.find(e => e.entity_id === 'nobody-here@example.org')
    const deactivated = rows.find(e => e.entity_id === curie.id && e.metadata?.reason === 'deactivated')
    expect(wrongPassword, 'the wrong-password attempt is keyed on the account').toBeTruthy()
    expect(unknownAddress, 'the unknown address is keyed on the address itself').toBeTruthy()
    expect(deactivated, 'the deactivated sign-in names its reason').toBeTruthy()
    expect(wrongPassword!.entity_type).toBe('auth')
  })

  it('the account holder’s own feed shows the attempt (the entity_id discipline)', async () => {
    const dirac = await invite('dirac.dashboard@example.org', 'Dirac Dashboard')
    await enroll(dirac.setupToken)
    await passwordLogin('dirac.dashboard@example.org', 'wrong')
    const cookie = (await passwordLogin('dirac.dashboard@example.org', 'a proper long passphrase')).headers.get('set-cookie')!.split(';')[0]!
    const feed = await app.request('/api/op/account/activity', { headers: { cookie } })
    expect(feed.status).toBe(200)
    const events = await feed.json() as Array<{ action: string }>
    expect(events.map(e => e.action)).toContain('account.sign_in_failed')
    expect(events.map(e => e.action)).toContain('account.sign_in')
  })
})

// ── the status probe's honest label (auth/op/probe.ts) ───────────────

describe('the status probe recognition', () => {
  const PROBE_TOKEN = 'the-test-probe-token'

  /** POST /api/op/login with (or without) the probe header. */
  async function probeLogin(email: string, token?: string): Promise<Response> {
    return app.request('/api/op/login', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        ...(token !== undefined ? { 'x-oiml-probe': token } : {}),
      },
      body: JSON.stringify({ email, password: 'probe' }),
    })
  }

  afterEach(() => {
    // The recognition rides the env; an unset secret is the honest
    // default every OTHER leg (and every other file) runs under.
    delete process.env.STATUS_PROBE_TOKEN
  })

  it('the recognized probe lands account.sign_in_probe — the same uniform 401, the same row shape', async () => {
    process.env.STATUS_PROBE_TOKEN = PROBE_TOKEN
    const res = await probeLogin('probe.recognized@example.org', PROBE_TOKEN)
    expect(res.status).toBe(401)
    expect(await res.json()).toEqual({ error: 'Invalid email or password' })

    const rows = (await journal()).filter(e => e.entity_id === 'probe.recognized@example.org')
    expect(rows.map(e => e.action)).toEqual(['account.sign_in_probe'])
    expect(rows[0]!.entity_type).toBe('auth')
    expect(rows[0]!.metadata).toEqual({
      method: 'password',
      email: 'probe.recognized@example.org',
      reason: 'invalid_credentials',
    })
  })

  it('an unrecognized header is a normal caller — the unchanged row, the unchanged answer', async () => {
    process.env.STATUS_PROBE_TOKEN = PROBE_TOKEN
    const res = await probeLogin('probe.stranger@example.org', 'not-the-token')
    expect(res.status).toBe(401)
    expect(await res.json()).toEqual({ error: 'Invalid email or password' })
    const rows = (await journal()).filter(e => e.entity_id === 'probe.stranger@example.org')
    expect(rows.map(e => e.action)).toEqual(['account.sign_in_failed'])

    // No header at all: likewise a normal caller.
    const bare = await probeLogin('probe.bare@example.org')
    expect(bare.status).toBe(401)
    const bareRows = (await journal()).filter(e => e.entity_id === 'probe.bare@example.org')
    expect(bareRows.map(e => e.action)).toEqual(['account.sign_in_failed'])
  })

  it('the secret unset turns the recognition off entirely', async () => {
    delete process.env.STATUS_PROBE_TOKEN
    const res = await probeLogin('probe.nosecret@example.org', PROBE_TOKEN)
    expect(res.status).toBe(401)
    const rows = (await journal()).filter(e => e.entity_id === 'probe.nosecret@example.org')
    expect(rows.map(e => e.action)).toEqual(['account.sign_in_failed'])
  })

  it('the feeds exclude the probe rows by default; the raw chain retains them', async () => {
    process.env.STATUS_PROBE_TOKEN = PROBE_TOKEN
    const fermat = await invite('fermat.probe@example.org', 'Fermat Probe')
    await enroll(fermat.setupToken)
    // The address names an account: the probe row keys on the account id.
    expect((await probeLogin('fermat.probe@example.org', PROBE_TOKEN)).status).toBe(401)
    const probeRows = (await journal()).filter(e => e.entity_id === fermat.id && e.action === 'account.sign_in_probe')
    expect(probeRows).toHaveLength(1)

    // The holder's own feed never shows it (their real sign-in stands).
    const cookie = (await passwordLogin('fermat.probe@example.org', 'a proper long passphrase')).headers.get('set-cookie')!.split(';')[0]!
    const feed = await (await app.request('/api/op/account/activity', { headers: { cookie } })).json() as Array<{ action: string }>
    expect(feed.map(e => e.action)).not.toContain('account.sign_in_probe')
    expect(feed.map(e => e.action)).toContain('account.sign_in')

    // The admin activity feed never shows it (the account's own rows do).
    const admin = await demoLogin('admin@oiml.org')
    const activity = await (await app.request('/api/op/registry/activity?q=fermat.probe', { headers: { cookie: admin } })).json() as Array<{ action: string; metadata?: { email?: string } }>
    expect(activity.length).toBeGreaterThan(0)
    expect(activity.map(e => e.action)).not.toContain('account.sign_in_probe')

    // The raw chain retains it: the queryable audit log carries the row.
    const audit = await (await app.request('/api/op/dashboard/audit?action=account.sign_in_probe', { headers: { cookie: admin } })).json() as { events: Array<{ entity_id: string }> }
    expect(audit.events.some(e => e.entity_id === fermat.id)).toBe(true)
  })

  it('the burst signal + the overview anomaly counter never count the probe cadence', async () => {
    process.env.STATUS_PROBE_TOKEN = PROBE_TOKEN
    const admin = await demoLogin('admin@oiml.org')
    const securityBefore = await (await app.request('/api/op/dashboard/security', { headers: { cookie: admin } })).json() as {
      signals: { failedSignIns: { day: number; week: number; bursts: Array<{ key: string }> } }
    }
    const overviewBefore = await (await app.request('/api/op/dashboard/overview', { headers: { cookie: admin } })).json() as {
      anomaliesToday: { failedSignIns: number }
    }

    // Six recognized probes on one address — past the burst threshold.
    for (let i = 0; i < 6; i++) {
      expect((await probeLogin('probe.burst@example.org', PROBE_TOKEN)).status).toBe(401)
    }

    const security = await (await app.request('/api/op/dashboard/security', { headers: { cookie: admin } })).json() as {
      signals: { failedSignIns: { day: number; week: number; bursts: Array<{ key: string }> } }
    }
    expect(security.signals.failedSignIns.day, 'the probe cadence never counts as a failure').toBe(securityBefore.signals.failedSignIns.day)
    expect(security.signals.failedSignIns.week).toBe(securityBefore.signals.failedSignIns.week)
    expect(security.signals.failedSignIns.bursts.some(b => b.key === 'probe.burst@example.org'), 'no burst on the probe address').toBe(false)

    const overview = await (await app.request('/api/op/dashboard/overview', { headers: { cookie: admin } })).json() as {
      anomaliesToday: { failedSignIns: number }
    }
    expect(overview.anomaliesToday.failedSignIns).toBe(overviewBefore.anomaliesToday.failedSignIns)
  })
})

// ── the token endpoint's audits + the per-client activity ────────────

describe('the token endpoint audits and the per-client activity', () => {
  it('issuance and refusals land on the journal; the clients read answers the series', async () => {
    const admin = await demoLogin('admin@oiml.org')
    const registered = await app.request('/api/op/clients', {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: admin },
      body: JSON.stringify({
        client_id: 'dash-rp',
        name: 'The dashboard fixture RP',
        generate_secret: true,
        redirect_uris: ['https://dash-rp.test/callback'],
      }),
    })
    expect(registered.status).toBe(201)
    const { secret } = await registered.json() as { secret: string }

    const noether = await invite('noether.dashboard@example.org', 'Noether Dashboard')
    await enroll(noether.setupToken)
    const userCookie = (await passwordLogin('noether.dashboard@example.org', 'a proper long passphrase')).headers.get('set-cookie')!.split(';')[0]!

    // A good exchange: the issuance event.
    const token = await driveCodeExchange('dash-rp', secret, userCookie)
    expect(token.status).toBe(200)

    // The wrong secret: invalid_client audited (the code is consumed
    // regardless — the exchange's own discipline).
    const wrong = await driveCodeExchange('dash-rp', 'not-the-secret', userCookie)
    expect(wrong.status).toBe(401)

    const rows = await journal()
    const issued = rows.filter(e => e.action === 'client.token_issued' && e.entity_id === 'dash-rp')
    expect(issued).toHaveLength(1)
    expect(issued[0]!.metadata?.account).toBe(noether.id)
    expect(issued[0]!.metadata?.scope).toBe('openid profile email')
    const refused = rows.filter(e => e.action === 'client.token_refused' && e.entity_id === 'dash-rp')
    expect(refused.some(e => e.metadata?.error === 'invalid_client')).toBe(true)
    // The replayed exchange's second leg: the wrong-secret attempt's
    // consumed code is never reusable — but the refusal above already
    // proves the journal. No token material in the journal, ever.
    expect(JSON.stringify(rows)).not.toContain(secret)

    // The per-client activity: the series carries the issuance.
    const clients = await app.request('/api/op/dashboard/clients', { headers: { cookie: admin } })
    expect(clients.status).toBe(200)
    const body = await clients.json() as {
      clients: Array<{
        clientId: string
        activity: { totalIssued14d: number; lastIssuedAt: string | null; refusals14d: number }
        registryEvents: Array<{ action: string }>
      }>
    }
    const row = body.clients.find(r => r.clientId === 'dash-rp')!
    expect(row.activity.totalIssued14d).toBe(1)
    expect(row.activity.lastIssuedAt).toBeTruthy()
    expect(row.activity.refusals14d).toBeGreaterThanOrEqual(1)
    expect(row.registryEvents.map(e => e.action)).toContain('client.registered')
  })
})

// ── the security signals ─────────────────────────────────────────────

describe('the security signals', () => {
  it('the burst threshold flags the hammered account; the families answer their windows', async () => {
    // Five failed sign-ins in a row on one account: the burst.
    const hammered = await invite('hammered.dashboard@example.org', 'Hammered Dashboard')
    await enroll(hammered.setupToken)
    for (let i = 0; i < 5; i++) {
      expect((await passwordLogin('hammered.dashboard@example.org', 'wrong')).status).toBe(401)
    }
    // A rate-limit trip row (the middleware's own shape; the in-process
    // app does not mount the limiter — the journal row is the contract).
    const tripId = crypto.randomUUID()
    await store.putEntity('auditEvents', tripId, null, JSON.stringify({
      id: tripId,
      timestamp: new Date().toISOString(),
      standard_id: '',
      entity_type: 'op',
      entity_id: '203.0.113.9',
      action: 'rate_limited',
      metadata: { path: '/op/token' },
    }))

    const admin = await demoLogin('admin@oiml.org')
    const res = await app.request('/api/op/dashboard/security', { headers: { cookie: admin } })
    expect(res.status).toBe(200)
    const body = await res.json() as {
      signals: {
        failedSignIns: { day: number; threshold: number; bursts: Array<{ key: string; account: string | null; count24h: number }> }
        tokenRefusals: { week: number; byError: Record<string, number> }
        rateLimited: { day: number; byCaller: Record<string, number> }
        newLinks: { week: number }
        newClients: { week: number; events: Array<{ clientId: string }> }
      }
    }
    const burst = body.signals.failedSignIns.bursts.find(b => b.key === hammered.id)
    expect(burst, 'the hammered account is flagged').toBeTruthy()
    expect(burst!.count24h).toBeGreaterThanOrEqual(5)
    expect(burst!.account, 'the burst resolves the account id to the email').toBe('hammered.dashboard@example.org')
    expect(body.signals.failedSignIns.threshold).toBe(5)
    expect(body.signals.tokenRefusals.byError.invalid_client).toBeGreaterThanOrEqual(1)
    expect(body.signals.rateLimited.day).toBe(1)
    expect(body.signals.rateLimited.byCaller['203.0.113.9']).toBe(1)
    expect(body.signals.newClients.events.map(e => e.clientId)).toContain('dash-rp')

    const viewer = await demoLogin('viewer@oiml.org')
    expect((await app.request('/api/op/dashboard/security', { headers: { cookie: viewer } })).status).toBe(403)
  })
})

// ── the queryable audit log ──────────────────────────────────────────

describe('the queryable audit log', () => {
  it('filters by text, action prefix, entity type and window; the CSV export carries the same view', async () => {
    const admin = await demoLogin('admin@oiml.org')

    const all = await (await app.request('/api/op/dashboard/audit', { headers: { cookie: admin } })).json() as {
      total: number; returned: number; events: Array<{ action: string }>
    }
    expect(all.total).toBeGreaterThan(0)
    expect(all.events.map(e => e.action)).toContain('client.token_issued')

    const signIns = await (await app.request('/api/op/dashboard/audit?action=account.sign_in', { headers: { cookie: admin } })).json() as {
      events: Array<{ action: string }>
    }
    expect(signIns.events.length).toBeGreaterThan(0)
    expect(signIns.events.every(e => e.action.startsWith('account.sign_in'))).toBe(true)

    const clientRows = await (await app.request('/api/op/dashboard/audit?entity_type=client', { headers: { cookie: admin } })).json() as {
      events: Array<{ entity_type: string }>
    }
    expect(clientRows.events.every(e => e.entity_type === 'client')).toBe(true)

    const searched = await (await app.request('/api/op/dashboard/audit?q=hammered.dashboard', { headers: { cookie: admin } })).json() as {
      events: Array<{ action: string }>
    }
    expect(searched.events.length).toBeGreaterThan(0)

    const tomorrow = new Date(Date.now() + 86_400_000).toISOString()
    const windowed = await (await app.request(`/api/op/dashboard/audit?from=${encodeURIComponent(tomorrow)}`, { headers: { cookie: admin } })).json() as {
      total: number
    }
    expect(windowed.total, 'a future window is empty').toBe(0)

    const csv = await app.request('/api/op/dashboard/audit?format=csv&action=client.token_issued', { headers: { cookie: admin } })
    expect(csv.status).toBe(200)
    expect(csv.headers.get('content-type')).toContain('text/csv')
    expect(csv.headers.get('content-disposition')).toContain('attachment')
    const text = await csv.text()
    const lines = text.trim().split('\n')
    expect(lines[0]).toBe('timestamp,action,entity_type,entity_id,user_name,user_id,metadata')
    expect(lines.length).toBeGreaterThan(1)
    expect(lines[1]).toContain('"client.token_issued"')

    expect((await app.request('/api/op/dashboard/audit?format=yaml', { headers: { cookie: admin } })).status).toBe(400)
  })
})

// ── the live access review ───────────────────────────────────────────

describe('the live access review', () => {
  it('answers the privileged holders, the per-client grants, the findings, the posture', async () => {
    const admin = await demoLogin('admin@oiml.org')
    // A per-client privileged grant: cs_admin on the fixture client.
    const grantee = await invite('grantee.dashboard@example.org', 'Grantee Dashboard')
    const grant = await app.request(`/api/op/accounts/${grantee.id}/client-roles/dash-rp`, {
      method: 'PUT',
      headers: { 'content-type': 'application/json', cookie: admin },
      body: JSON.stringify({ roles: ['cs_admin'] }),
    })
    expect(grant.status).toBe(200)

    const res = await app.request('/api/op/dashboard/access-review', { headers: { cookie: admin } })
    expect(res.status).toBe(200)
    const body = await res.json() as {
      source: string
      privilegedHolders: Array<{ email: string; roles: string[]; lastLogin: string | null }>
      perClientPrivileged: Array<{ account: string; clientId: string; roles: string[] }>
      findings: string[]
      posture: { accounts: { total: number }; signingKeys: { history: number } }
    }
    const holder = body.privilegedHolders.find(h => h.email === 'admin@oiml.org')
    expect(holder, 'the demo admin is a privileged holder').toBeTruthy()
    expect(holder!.roles).toContain('admin')
    expect(holder!.lastLogin, 'the admin signed in').toBeTruthy()
    expect(body.perClientPrivileged.some(g => g.account === 'grantee.dashboard@example.org' && g.clientId === 'dash-rp' && g.roles.includes('cs_admin'))).toBe(true)
    // The findings carry the never-signed-in privileged account (the
    // demo cs_admin never signs in inside this suite).
    expect(body.findings.some(f => f.includes('never signed in'))).toBe(true)
    expect(body.posture.accounts.total).toBeGreaterThan(0)
    expect(body.source).toContain('op-access-review')
  })
})

// ── the heartbeat (the SLO panel's data) ─────────────────────────────

describe('the heartbeat read', () => {
  it('the green window computes from the workflow history at its source', async () => {
    process.env.OP_HEARTBEAT_REPO = 'acme/id-green'
    process.env.OP_HEARTBEAT_WORKFLOW = 'identity-heartbeat.yml'
    const admin = await demoLogin('admin@oiml.org')
    const res = await app.request('/api/op/dashboard/heartbeat', { headers: { cookie: admin } })
    expect(res.status).toBe(200)
    const body = await res.json() as {
      available: boolean
      totals: { completed: number; succeeded: number; failed: number; successRate: number }
      lastRun: { conclusion: string }
      failures: Array<{ url: string }>
      source: { runsUrl: string }
    }
    expect(body.available).toBe(true)
    expect(body.totals).toMatchObject({ completed: 3, succeeded: 2, failed: 1 })
    expect(body.totals.successRate).toBeCloseTo(2 / 3, 5)
    expect(body.lastRun.conclusion).toBe('success')
    expect(body.failures).toHaveLength(1)
    expect(body.source.runsUrl).toContain('acme/id-green')
  })

  it('a red source degrades to the honest link, never a fabricated number', async () => {
    process.env.OP_HEARTBEAT_REPO = 'acme/id-red'
    process.env.OP_HEARTBEAT_WORKFLOW = 'broken.yml'
    const admin = await demoLogin('admin@oiml.org')
    const res = await app.request('/api/op/dashboard/heartbeat', { headers: { cookie: admin } })
    expect(res.status).toBe(200)
    const body = await res.json() as { available: boolean; reason?: string; source: { runsUrl: string }; totals?: unknown }
    expect(body.available).toBe(false)
    expect(body.reason).toContain('500')
    expect(body.totals, 'no fabricated window').toBeUndefined()
    expect(body.source.runsUrl).toContain('acme/id-red')
  })
})

// ── the module gate ──────────────────────────────────────────────────

describe('the module gate', () => {
  it('a non-identity profile answers 404 on the dashboard routes', async () => {
    const profileMod = await import('@oimlsmart/platform-server/profile')
    profileMod.resetInstanceProfileForTest() // the hub default (no identity module)
    try {
      for (const [method, path] of [
        ['GET', '/api/op/dashboard/overview'],
        ['GET', '/api/op/dashboard/sessions'],
        ['POST', '/api/op/dashboard/accounts/whatever/sessions/revoke-all'],
        ['GET', '/api/op/dashboard/security'],
        ['GET', '/api/op/dashboard/audit'],
        ['GET', '/api/op/dashboard/access-review'],
        ['GET', '/api/op/dashboard/clients'],
        ['GET', '/api/op/dashboard/heartbeat'],
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
