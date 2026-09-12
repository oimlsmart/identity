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
