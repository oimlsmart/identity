// ─────────────────────────────────────────────────────────────────────
// The Server-Timing store phase (TODO.restructure/27 items 5–8, the
// program's Workstream C), proven in-process over the REAL app factory
// and the REAL SQLite store — no mocks, no doubles:
//
//   SERVER_TIMING set (the diagnostic posture): every answer carries
//     BOTH phases in ONE comma-joined header per the Server-Timing
//     spec — app;dur=X, store;dur=Y;desc="N calls" — with N > 0 on a
//     store-bearing request and the honest N = 0 on a storeless one
//     (/api/health touches no store; its store entry is a zero, never
//     an omission — a reader must not guess which phases ran).
//
//   SERVER_TIMING unset (the DEFAULT posture): the answer stays
//     byte-identical to #88's minimal form — app;dur=<ms> alone, no
//     store entry, the zero-overhead world where getStore() passes the
//     installed store through untouched.
//
// The full suite runs in this default posture — it is itself the
// off-state proof at scale.
// ─────────────────────────────────────────────────────────────────────

import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

const TMP = mkdtempSync(join(tmpdir(), 'oiml-id-server-timing-'))
process.env.DATABASE_PATH = join(TMP, 'test.db')
const ISSUER = 'http://op.test'
process.env.OP_ISSUER = ISSUER

let app: import('hono').Hono
/** The demo sign-in's session cookie (the read leg rides it). */
let demoCookie: string

/** The full flag-on header: both phases, one header, the desc a quoted
 *  string with a pluralized count. */
const BOTH_PHASES = /^app;dur=(\d+), store;dur=(\d+(?:\.\d+)?);desc="(\d+) calls"$/
const APP_ONLY = /^app;dur=\d+$/

beforeAll(async () => {
  // The declared signing key (the id-registry posture: a simulated
  // deployment never registers a generated key silently).
  const { generateSuccessorPair } = await import('../../scripts/op-key-rotate')
  process.env.OP_SIGNING_KEY = (await generateSuccessorPair()).privateJwkJson

  const { installSqliteStore } = await import('../../server/store/sqlite')
  installSqliteStore()
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

  const { createApiApp } = await import('../../server/app')
  app = createApiApp({ autoSeedDemo: true, instanceProfile: profileMod.getInstanceProfile() })

  // The diagnostic posture for the first half of the legs.
  process.env.SERVER_TIMING = '1'
})

afterAll(() => {
  delete process.env.SERVER_TIMING
  rmSync(TMP, { recursive: true, force: true })
})

describe('SERVER_TIMING set — the store phase rides the header', () => {
  it('a store-bearing answer (the demo sign-in: seeds, authenticate, session, audit) carries both phases with calls > 0', async () => {
    const res = await app.request(`${ISSUER}/api/auth/demo`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: 'admin@oiml.org', password: 'demo2026' }),
    })
    expect(res.status).toBe(200)
    const m = res.headers.get('server-timing')?.match(BOTH_PHASES)
    expect(m, `the header carries both phases: ${res.headers.get('server-timing')}`).not.toBeNull()
    expect(Number(m![3])).toBeGreaterThan(0)
    demoCookie = res.headers.getSetCookie().map((v) => v.split(';')[0]).join('; ')
  })

  it('a read-only answer (the session resolution) carries both phases with calls > 0', async () => {
    const res = await app.request(`${ISSUER}/api/auth/session`, { headers: { cookie: demoCookie } })
    expect(res.status).toBe(200)
    const m = res.headers.get('server-timing')?.match(BOTH_PHASES)
    expect(m, `the header carries both phases: ${res.headers.get('server-timing')}`).not.toBeNull()
    expect(Number(m![3])).toBeGreaterThan(0)
  })

  it('a storeless answer (/api/health) keeps the store entry with the honest zero', async () => {
    const res = await app.request(`${ISSUER}/api/health`)
    expect(res.status).toBe(200)
    const m = res.headers.get('server-timing')?.match(BOTH_PHASES)
    expect(m, `the store entry stays present at zero calls: ${res.headers.get('server-timing')}`).not.toBeNull()
    expect(Number(m![3])).toBe(0)
  })
})

describe('SERVER_TIMING unset — the default, zero-overhead posture', () => {
  it('every answer stays byte-identical to the minimal form (no store entry)', async () => {
    delete process.env.SERVER_TIMING
    const login = await app.request(`${ISSUER}/api/auth/demo`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: 'admin@oiml.org', password: 'demo2026' }),
    })
    expect(login.status).toBe(200)
    expect(login.headers.get('server-timing')).toMatch(APP_ONLY)

    const health = await app.request(`${ISSUER}/api/health`)
    expect(health.status).toBe(200)
    expect(health.headers.get('server-timing')).toMatch(APP_ONLY)
  })
})

describe('the instrument\'s attribution — exact under concurrency (the 2026-09-18 wire lesson)', () => {
  // The 2026-09-18 wire reading taught this the hard way: a single
  // curl against /api/op/organizations reported 22 calls / ~500 ms —
  // the endpoint's OWN cost is 2 calls / ~20 ms (proven by the
  // scaling gate's new leg), and the other 20 were a CONCURRENT
  // request's calls landing in the shared monotone accumulator (the
  // module header's own honest tolerance, misread as an endpoint
  // defect). An instrument that can misattribute by 10× is not a
  // measurement — this leg pins the exact per-request attribution
  // (AsyncLocalStorage, available under nodejs_compat on the Worker
  // and natively in node — both postures).
  it('two overlapping measured windows each count ONLY their own calls', async () => {
    process.env.SERVER_TIMING = '1'
    const { measureStorePhase, timedStore } = await import('../../server/store-timing')
    const { getStore } = await import('../../server/store')
    try {
      const window = async (keys: string[]) => {
        const { report } = await measureStorePhase(async () => {
          // Reads batch freely (the seam's doctrine); each getEntity on
          // the counting view is exactly one counted call.
          await Promise.all(keys.map(k => timedStore(getStore()).getEntity('attribution-probe', k)))
        })
        return report
      }
      // The interleaving is forced: both windows open before either's
      // calls resolve (the awaits below start concurrently).
      const [a, b] = await Promise.all([
        window(['a1', 'a2', 'a3']),
        window(['b1', 'b2', 'b3', 'b4']),
      ])
      expect(a.total, `window A counts only its own 3 calls (got ${a.total})`).toBe(3)
      expect(b.total, `window B counts only its own 4 calls (got ${b.total})`).toBe(4)
    } finally {
      delete process.env.SERVER_TIMING
    }
  })

  it('the bootstrap never rides anonymous public reads (the 2026-09-18 production lesson: a failing seed retried in every /api/op/* window)', async () => {
    // The full production shape: the account + client seeds DECLARED
    // (op-accounts mounts its bootstrap under /api/op/*), and the
    // anonymous register read must carry ONLY its own 2 calls — never
    // the bootstrap's. On production the seed was failing (and
    // evicting itself), so every request re-ran 5 accounts x 2 + 5
    // clients x 2 = 20 extra calls; the fix scopes the bootstrap to
    // the credential surfaces that need it.
    process.env.SERVER_TIMING = '1'
    process.env.OP_ACCOUNT_SEED = JSON.stringify([
      { email: 'seed-operator@oimlsmart.org', name: 'Seed Operator', role: 'admin' },
      { email: 'seed-second@oimlsmart.org', name: 'Seed Second' },
    ])
    process.env.OP_CLIENT_SEED = JSON.stringify([
      { client_id: 'seed-client', name: 'Seed Client', redirect_uris: ['https://seed.example/cb'] },
    ])
    try {
      const res = await app.request(`${ISSUER}/api/op/organizations`, undefined, {
        SERVER_TIMING: '1', OP_ACCOUNT_SEED: process.env.OP_ACCOUNT_SEED, OP_CLIENT_SEED: process.env.OP_CLIENT_SEED,
      })
      expect(res.status).toBe(200)
      const m = res.headers.get('server-timing')?.match(BOTH_PHASES)
      expect(m, `the header carries both phases: ${res.headers.get('server-timing')}`).not.toBeNull()
      expect(Number(m![3]), `the anonymous read carries only its own 2 calls (got ${m![3]})`).toBe(2)
    } finally {
      delete process.env.SERVER_TIMING
      delete process.env.OP_ACCOUNT_SEED
      delete process.env.OP_CLIENT_SEED
    }
  })
})
