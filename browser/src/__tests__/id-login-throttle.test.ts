// ─────────────────────────────────────────────────────────────────────
// TODO.identity-sso/04 slice C — the password leg's per-account backoff
// ladder, proven at the ROUTES in-process (the id-accounts pattern: the
// real router over a real temp SQLite store; the ladder state read back
// through the entity seam):
//
//   CLIMB     every invalid-credentials failure on an address climbs a
//             rung (the opLoginThrottle row's failCount), the answer
//             staying the uniform 401 byte-for-byte — never a 429,
//             never a Retry-After, never a lockout flag;
//   WAIT      the next attempt on a failed address pays the owed wait
//             BEFORE the verify runs (the measured delay);
//   CLEAR     a successful password verify clears the ladder outright
//             (the next failure restarts at rung one);
//   UNIFORM   an UNKNOWN address accumulates the same ladder (no
//             enumeration channel through the timing), and the
//             deactivated-account 403 is no ladder step (it is not a
//             brute-force signal — the audit's reason carries it).
//
// OP_LOGIN_BACKOFF_BASE_MS=1 is the suite's base (the OP_MFA_BACKOFF_
// BASE_MS precedent): the ladder is exercised, not slept through; the
// WAIT leg declares its own larger base for the measured delay.
// ─────────────────────────────────────────────────────────────────────

import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

// The store's DB path is read at module evaluation — set it before any
// import below touches the kernel (the imports are dynamic).
const TMP = mkdtempSync(join(tmpdir(), 'oiml-op-throttle-'))
process.env.DATABASE_PATH = join(TMP, 'test.db')

const ISSUER = 'http://op.test'
process.env.OP_ISSUER = ISSUER
process.env.OP_LOGIN_BACKOFF_BASE_MS = '1'

let app: import('hono').Hono
let store: ReturnType<typeof import('../../server/store').getStore>

// ── the small drivers ────────────────────────────────────────────────

async function demoLogin(email: string): Promise<string> {
  const res = await app.request('/api/auth/demo', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password: 'demo2026' }),
  })
  expect(res.ok, `demo login ${email}`).toBe(true)
  return res.headers.get('set-cookie')!.split(';')[0]!
}

async function inviteAndEnroll(email: string, name: string, password: string): Promise<{ id: string }> {
  const admin = await demoLogin('admin@oiml.org')
  const inviteRes = await app.request('/api/op/accounts', {
    method: 'POST',
    headers: { 'content-type': 'application/json', cookie: admin },
    body: JSON.stringify({ email, name }),
  })
  expect(inviteRes.status, `invite ${email}`).toBe(201)
  const { account, setupUrl } = await inviteRes.json() as { account: { id: string }; setupUrl: string }
  const token = new URL(setupUrl).searchParams.get('token')!
  const res = await app.request(`/api/op/enroll/${token}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ password }),
  })
  expect(res.status, `enroll ${email}`).toBe(200)
  return { id: account.id }
}

/** A password login with its wall-clock duration (the WAIT leg's
 *  instrument — the only leg that reads timing). */
async function timedLogin(email: string, password: string): Promise<{ res: Response; elapsedMs: number }> {
  const started = Date.now()
  const res = await app.request('/api/op/login', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password }),
  })
  return { res, elapsedMs: Date.now() - started }
}

async function ladderRow(email: string): Promise<{ failCount: number; lastFailureAt: string | null } | undefined> {
  const row = await store.getEntity('opLoginThrottle', email)
  return row ? JSON.parse(row.data) as { failCount: number; lastFailureAt: string | null } : undefined
}

beforeAll(async () => {
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

  const { Hono } = await import('hono')
  const { createAuthLeanRouter } = await import('../../server/routes/auth-lean')
  const { createOpAccountsRouter } = await import('../../server/routes/op-accounts')
  const root = new Hono()
  root.route('/api/auth', createAuthLeanRouter({ autoSeedDemo: true }))
  root.route('/', createOpAccountsRouter())
  app = root
  await demoLogin('admin@oiml.org') // the bootstrap seed lands on the first OP request
}, 120_000)

afterAll(async () => {
  rmSync(TMP, { recursive: true, force: true })
  delete process.env.OP_ISSUER
  delete process.env.DATABASE_PATH
  delete process.env.OP_LOGIN_BACKOFF_BASE_MS
  const profileMod = await import('../../server/profile')
  profileMod.resetInstanceProfileForTest()
})

describe('TODO.identity-sso/04 slice C — the password leg’s backoff ladder', () => {
  const CARL = { email: 'carl@example.org', name: 'Carl Example', password: 'carl has a proper passphrase' }
  const DANA = { email: 'dana@example.org', name: 'Dana Example', password: 'dana has a proper passphrase' }
  const ERIN = { email: 'erin@example.org', name: 'Erin Example', password: 'erin has a proper passphrase' }

  it('CLIMB: every failure climbs a rung; the answer stays the uniform 401 byte-for-byte', { timeout: 60_000 }, async () => {
    await inviteAndEnroll(CARL.email, CARL.name, CARL.password)
    for (let n = 1; n <= 5; n++) {
      const { res } = await timedLogin(CARL.email, 'carl has a WRONG passphrase')
      expect(res.status, `failure ${n}`).toBe(401)
      // The silent posture: the exact same body, no throttle semantics
      // leak (no 429, no retryAfterMs, no lockout flag).
      expect(await res.json()).toEqual({ error: 'Invalid email or password' })
      expect((await ladderRow(CARL.email))?.failCount, `rung ${n}`).toBe(n)
    }
  })

  it('WAIT: the next attempt pays the owed wait before the verify', { timeout: 60_000 }, async () => {
    // The measured leg declares its own base: one failure owes the next
    // attempt 2^1 × 40 ms = 80 ms (minus the milliseconds between).
    process.env.OP_LOGIN_BACKOFF_BASE_MS = '40'
    try {
      await inviteAndEnroll(DANA.email, DANA.name, DANA.password)
      const first = await timedLogin(DANA.email, 'dana has a WRONG passphrase')
      expect(first.res.status).toBe(401)
      const throttled = await timedLogin(DANA.email, 'dana has a WRONG passphrase')
      expect(throttled.res.status).toBe(401)
      expect(await throttled.res.json()).toEqual({ error: 'Invalid email or password' })
      // The owed wait rides on top of the same verify cost (loose floor:
      // the 80 ms owed minus the between-calls drift, generously).
      expect(
        throttled.elapsedMs - first.elapsedMs,
        `the second attempt pays the ladder's wait (first ${first.elapsedMs} ms, throttled ${throttled.elapsedMs} ms)`,
      ).toBeGreaterThanOrEqual(40)
    } finally {
      process.env.OP_LOGIN_BACKOFF_BASE_MS = '1'
    }
  })

  it('CLEAR: a successful password verify clears the ladder outright', { timeout: 60_000 }, async () => {
    const { res } = await timedLogin(CARL.email, CARL.password)
    expect(res.status, 'the right password is never locked out').toBe(200)
    expect(await ladderRow(CARL.email), 'the success clears the row').toBeUndefined()

    // The next failure restarts at rung one.
    const again = await timedLogin(CARL.email, 'carl has a WRONG passphrase')
    expect(again.res.status).toBe(401)
    expect((await ladderRow(CARL.email))?.failCount, 'the ladder restarts at rung one').toBe(1)
    // …and the success clears it again for the later legs' clean slate.
    expect((await timedLogin(CARL.email, CARL.password)).res.status).toBe(200)
    expect(await ladderRow(CARL.email)).toBeUndefined()
  })

  it('UNIFORM: an unknown address accumulates the same ladder; the deactivated 403 is no rung', { timeout: 60_000 }, async () => {
    // The unknown address: two failures climb the same row keyed on the
    // normalized address (no account required — no enumeration channel).
    await timedLogin('nobody@example.org', 'a guess')
    await timedLogin('Nobody@Example.ORG', 'another guess')
    expect((await ladderRow('nobody@example.org'))?.failCount, 'the unknown address ladders too').toBe(2)

    // The deactivated account with the RIGHT password: the honest 403,
    // never a ladder step (the audit's reason: 'deactivated' carries it).
    const { id } = await inviteAndEnroll(ERIN.email, ERIN.name, ERIN.password)
    await store.setUserActive(id, false)
    const { res } = await timedLogin(ERIN.email, ERIN.password)
    expect(res.status).toBe(403)
    expect(await res.json().then(b => (b as { error: string }).error)).toContain('deactivated')
    expect(await ladderRow(ERIN.email), 'the deactivated refusal climbs no rung').toBeUndefined()
  })
})
