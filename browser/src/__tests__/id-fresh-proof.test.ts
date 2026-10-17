// ─────────────────────────────────────────────────────────────────────
// The fresh-proof gate on EVERY sensitive console act (2026-10-14, the
// GitHub sudo-mode parity) — proven in-process over the REAL routers
// (op-accounts + op-factors + op-tokens) against a REAL temp SQLite
// store + the stub mailer:
//
//   FRESH     a session born minutes ago acts freely (the holder's
//             ordinary flow never sees the gate);
//   STALE     a backdated session's sensitive acts answer the honest
//             403 {step_up:'required'} — the email ADD (the hijack
//             chain's first step: an attacker address, verified in the
//             attacker's mailbox, promoted, then the reset owns the
//             account), the PAT MINT (a durable credential surviving
//             every session sweep), and the FACTOR REVOKE (stripping
//             the victim's second factors);
//   STEP-UP   the current password mints the stamp and the retry
//             carries the act through (the x-op-step-up header).
// ─────────────────────────────────────────────────────────────────────

import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import Database from 'better-sqlite3'

const TMP = mkdtempSync(join(tmpdir(), 'oiml-fresh-proof-'))
process.env.DATABASE_PATH = join(TMP, 'test.db')
process.env.OP_ISSUER = 'http://op.test'

const ORIGIN = 'http://op.test'

let app: import('hono').Hono
let store: ReturnType<typeof import('../../server/store').getStore>
let stub: import('../../e2e/fixtures/stub-mailer').StubMailer

const WILLA = { email: 'willafresh@example.org', name: 'Willa Fresh', password: 'willa has a proper passphrase' }

async function demoLogin(email: string): Promise<string> {
  const res = await app.request(`${ORIGIN}/api/auth/demo`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password: 'demo2026' }),
  })
  expect(res.ok).toBe(true)
  return res.headers.get('set-cookie')!.split(';')[0]!
}

/** The account's password sign-in cookie (the token value). */
async function login(email: string, password: string): Promise<string> {
  const res = await app.request(`${ORIGIN}/api/op/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password }),
  })
  expect(res.status).toBe(200)
  return res.headers.get('set-cookie')!.split(';')[0]!
}

/** Backdate every session row of the account — the gate reads the
 *  session's age (the sqlite wall clock). */
function backdateSessions(email: string): void {
  const db = new Database(join(TMP, 'test.db'))
  const id = (db.prepare('SELECT id FROM users WHERE email = ?').get(email) as { id: string }).id
  db.prepare("UPDATE sessions SET created_at = datetime('now', '-30 minutes') WHERE user_id = ?").run(id)
  db.close()
}

async function stepUp(cookie: string, password: string): Promise<string> {
  const res = await app.request(`${ORIGIN}/api/op/step-up`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', cookie },
    body: JSON.stringify({ password }),
  })
  expect(res.status).toBe(200)
  return (await res.json() as { stamp: string }).stamp
}

beforeAll(async () => {
  const { generateSuccessorPair } = await import('../../scripts/op-key-rotate')
  process.env.OP_SIGNING_KEY = (await generateSuccessorPair()).privateJwkJson

  const { installSqliteStore } = await import('../../server/store/sqlite')
  store = installSqliteStore()
  const profileMod = await import('../../server/profile')
  profileMod.installInstanceProfile(profileMod.parseInstanceProfile(`
identity:
  org_id: oimlsmart-id
  org_name: OIML SMART Identity
  role_codes: [identity]
roles: [identity]
branding: { name: OIML SMART Identity }
demo_personas: true
`))

  // The PAT scopes' service vocabulary: one registered, active RP.
  process.env.OP_CLIENT_SEED = JSON.stringify([{
    client_id: 'hub-instance',
    name: 'OIML SMART platform hub',
    secret: 'hub-secret-123',
    redirect_uris: ['https://hub.example/api/auth/callback/oidc'],
  }])

  const { startStubMailer } = await import('../../e2e/fixtures/stub-mailer')
  stub = await startStubMailer({ expectedKey: 'stub-mail-key' })
  process.env.EMAIL_FROM = 'OIML SMART Identity <no-reply@oimlsmart.org>'
  process.env.MAIL_PROVIDER_URL = `${stub.baseUrl}/emails`
  process.env.MAIL_PROVIDER_KEY = 'stub-mail-key'
  const mailerMod = await import('../../server/mailer')
  mailerMod.resetMailerForTest()

  const { Hono } = await import('hono')
  const { createAuthLeanRouter } = await import('../../server/routes/auth-lean')
  const { createOpAccountsRouter } = await import('../../server/routes/op-accounts')
  const { createOpFactorsRouter } = await import('../../server/routes/op-factors')
  const { createOpTokensRouter } = await import('../../server/routes/op-tokens')
  const { createOpUpstreamRouter } = await import('../../server/routes/op-upstream')
  const root = new Hono()
  root.route('/api/auth', createAuthLeanRouter({ autoSeedDemo: true }))
  root.route('/', createOpAccountsRouter())
  root.route('/', createOpFactorsRouter())
  root.route('/', createOpTokensRouter())
  root.route('/', createOpUpstreamRouter())
  app = root

  // The link wall's provider row (the link start's round trip never
  // fires in these legs — the gate answers first).
  await store.upsertIdentityProvider({
    id: 'github', kind: 'github', displayName: 'GitHub', brandMark: 'github',
    issuer: null, clientId: 'test-client', clientSecretRef: 'env:GITHUB_UPSTREAM_CLIENT_SECRET',
    scopes: null, enabled: true, createdBy: 'the fresh-proof harness',
  })

  // The holder: enrolled (the credential proves the mailbox).
  const admin = await demoLogin('admin@oimlsmart.org')
  const invited = await app.request(`${ORIGIN}/api/op/accounts`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', cookie: admin },
    body: JSON.stringify({ email: WILLA.email, name: WILLA.name }),
  })
  expect(invited.status).toBe(201)
  const { setupUrl } = await invited.json() as { setupUrl: string }
  const token = new URL(setupUrl).searchParams.get('token')!
  const enrolled = await app.request(`${ORIGIN}/api/op/enroll/${token}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ password: WILLA.password }),
  })
  expect(enrolled.status).toBe(200)
})

afterAll(async () => {
  await stub.close()
  for (const k of ['EMAIL_FROM', 'MAIL_PROVIDER_URL', 'MAIL_PROVIDER_KEY', 'OP_CLIENT_SEED']) delete process.env[k]
  const mailerMod = await import('../../server/mailer')
  mailerMod.resetMailerForTest()
  const { resetInstanceProfileForTest } = await import('../../server/profile')
  resetInstanceProfileForTest()
  rmSync(TMP, { recursive: true, force: true })
  for (const k of ['DATABASE_PATH', 'OP_ISSUER', 'OP_SIGNING_KEY']) delete process.env[k]
})

describe('the fresh-proof gate on the sensitive console acts', () => {
  it('FRESH: the email add rides a minutes-old session without any re-entry', async () => {
    const cookie = await login(WILLA.email, WILLA.password)
    const res = await app.request(`${ORIGIN}/api/op/account/emails`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ email: 'fresh-add@example.org' }),
    })
    expect(res.status, 'the fresh session acts freely').toBe(201)
  })

  it('STALE: the backdated session\'s email add answers the honest 403; the step-up retry lands it', async () => {
    const cookie = await login(WILLA.email, WILLA.password)
    backdateSessions(WILLA.email)

    const stale = await app.request(`${ORIGIN}/api/op/account/emails`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ email: 'stale-add@example.org' }),
    })
    expect(stale.status).toBe(403)
    expect(((await stale.json()) as { step_up?: string }).step_up).toBe('required')

    const stamp = await stepUp(cookie, WILLA.password)
    const retry = await app.request(`${ORIGIN}/api/op/account/emails`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie, 'x-op-step-up': stamp },
      body: JSON.stringify({ email: 'stale-add@example.org' }),
    })
    expect(retry.status, 'the stamp buys the act').toBe(201)
  })

  it('STALE: the PAT mint demands the proof too (a durable credential never rides a stale session)', async () => {
    const cookie = await login(WILLA.email, WILLA.password)
    backdateSessions(WILLA.email)

    const stale = await app.request(`${ORIGIN}/api/op/account/tokens`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ name: 'sneaky', scopes: ['hub-instance:read'] }),
    })
    expect(stale.status).toBe(403)
    expect(((await stale.json()) as { step_up?: string }).step_up).toBe('required')

    const stamp = await stepUp(cookie, WILLA.password)
    const retry = await app.request(`${ORIGIN}/api/op/account/tokens`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie, 'x-op-step-up': stamp },
      body: JSON.stringify({ name: 'honest', scopes: ['hub-instance:read'] }),
    })
    if (retry.status !== 201) console.log('PAT-RETRY', retry.status, JSON.stringify(await retry.clone().json().catch(() => null)))
    expect(retry.status, 'the stamped mint lands').toBe(201)
  })

  it('STALE: the password removal demands the proof (the takeover chain\'s second half)', async () => {
    const cookie = await login(WILLA.email, WILLA.password)
    backdateSessions(WILLA.email)
    const stale = await app.request(`${ORIGIN}/api/op/account/password`, { method: 'DELETE', headers: { cookie } })
    expect(stale.status).toBe(403)
    expect(((await stale.json()) as { step_up?: string }).step_up).toBe('required')
    // The stamp buys the removal… but the leg keeps the password (the
    // honest 409 answer is fine — the WALL is the assertion, and the
    // act's own only-method guard may refuse a bare account).
    const stamp = await stepUp(cookie, WILLA.password)
    const retry = await app.request(`${ORIGIN}/api/op/account/password`, {
      method: 'DELETE',
      headers: { cookie, 'x-op-step-up': stamp },
    })
    expect([200, 409], 'past the wall; the method guard may still speak').toContain(retry.status)
  })

  it('the passkey re-entry: the ceremony answers honestly without any passkey or with a garbage assertion', async () => {
    const cookie = await login(WILLA.email, WILLA.password)
    // WILLA holds no passkey: the options answer the honest 404.
    const options = await app.request(`${ORIGIN}/api/op/step-up/passkey/options`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie }, body: '{}',
    })
    expect(options.status).toBe(404)
    // The verify's refusal is uniform for a garbage assertion.
    const verify = await app.request(`${ORIGIN}/api/op/step-up/passkey`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ credential: { id: 'garbage', response: {} } }),
    })
    expect(verify.status).toBe(400)
  })

  it('STALE: the upstream LINK start demands the proof (the takeover chain\'s first half)', async () => {
    const cookie = await login(WILLA.email, WILLA.password)
    // Fresh: the start proceeds to the provider round trip (the 302 to
    // GitHub's authorize URL).
    const fresh = await app.request(`${ORIGIN}/op/upstream/github/link`, { headers: { cookie }, redirect: 'manual' })
    expect(fresh.status, 'the fresh session links').toBe(302)
    expect(fresh.headers.get('location') ?? '').toContain('github.com')

    // Stale: the wall redirects to the account page with the honest
    // demand — never the provider round trip.
    backdateSessions(WILLA.email)
    const stale = await app.request(`${ORIGIN}/op/upstream/github/link`, { headers: { cookie }, redirect: 'manual' })
    expect(stale.status).toBe(302)
    expect((stale.headers.get('location') ?? '')).toContain('error=link_fresh_proof')
  })

  it('STALE: the factor revoke demands the proof (the victim\'s MFA is never stripped silently)', async () => {
    const cookie = await login(WILLA.email, WILLA.password)
    // A fresh session enrolls the authenticator (the enrollment's own
    // gate passes fresh); the revoke then meets the stale wall.
    const options = await app.request(`${ORIGIN}/api/op/account/factors/totp`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ name: 'Willa\'s authenticator' }),
    })
    expect(options.status, 'the fresh enrollment passes its own gate').toBe(201)
    const { id } = await options.json() as { id: string }
    const rowId = id
    expect(rowId, 'the enrolled authenticator\'s id').toBeTruthy()

    backdateSessions(WILLA.email)
    const stale = await app.request(`${ORIGIN}/api/op/account/factors/totp/${rowId}`, {
      method: 'DELETE',
      headers: { cookie },
    })
    expect(stale.status).toBe(403)
    expect(((await stale.json()) as { step_up?: string }).step_up).toBe('required')

    const stamp = await stepUp(cookie, WILLA.password)
    const retry = await app.request(`${ORIGIN}/api/op/account/factors/totp/${rowId}`, {
      method: 'DELETE',
      headers: { cookie, 'x-op-step-up': stamp },
    })
    expect(retry.status, 'the stamped revoke lands').toBe(200)
  })
})
