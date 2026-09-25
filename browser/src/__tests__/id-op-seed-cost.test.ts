// ─────────────────────────────────────────────────────────────────────
// #78's real root cause (the 2026-09-25 SERVER_TIMING finding): the
// per-isolate bootstrap seed ran its FULL declared convergence inline
// on the FIRST credential-gated request — the seven-persona demo cast
// cost 68 store calls ≈ 3.6s of D1 round trips on the Worker, landing
// on whatever login hit a fresh isolate (the "cold isolate ~10s"
// report; the production samples read 72 calls / 3655ms vs 4 / 220ms).
//
// The fix's contract, pinned here:
//   — a COMPLETE declaration (every declared account + client exists)
//     must NOT block the request on the convergence: the first
//     credential request answers with the CHECK's parallel reads only
//     (bounded well under the convergence's cost), and the drift
//     repair runs in the background;
//   — an INCOMPLETE registry (the fresh deployment) still seeds INLINE
//     — the bootstrap IS the first admin's front door, and the
//     declared accounts must exist by the time the answer lands.
// ─────────────────────────────────────────────────────────────────────

import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

const TMP = mkdtempSync(join(tmpdir(), 'oiml-seedcost-'))
process.env.DATABASE_PATH = join(TMP, 'test.db')
process.env.OP_ISSUER = 'http://op.test'

const CAST = [
  'applicant', 'ia', 'tl', 'utilizer', 'cs', 'admin', 'surveillance',
].map((k, i) => ({
  email: `persona-${k}@oimlsmart.org`, name: `Persona ${k}`, role: 'user',
  emailVerified: true, password: `personas-never-publish-${i}`,
  clientRoles: { 'oiml-smart-demo': ['applicant'] },
}))
const CLIENT = { client_id: 'oiml-smart-demo', name: 'demo', secret: 's', redirect_uris: ['https://d.example/cb'] }

let app: import('hono').Hono
let store: ReturnType<typeof import('../../server/store').getStore>

function countStoreCalls(): () => number {
  let calls = 0
  const target = store as unknown as Record<string, unknown>
  for (const k of Object.getOwnPropertyNames(Object.getPrototypeOf(target))) {
    const v = target[k]
    if (typeof v === 'function' && !k.startsWith('_')) {
      target[k] = (...a: unknown[]) => { calls++; return (v as (...a: unknown[]) => unknown).apply(store, a) }
    }
  }
  return () => calls
}

async function bootApp(): Promise<void> {
  const { generateSuccessorPair } = await import('../../scripts/op-key-rotate')
  process.env.OP_SIGNING_KEY = (await generateSuccessorPair()).privateJwkJson
  const { installSqliteStore } = await import('../../server/store/sqlite')
  installSqliteStore()
  store = (await import('../../server/store')).getStore()
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
  const oidc = await import('../../server/oidc')
  oidc.clearOidcCaches()
  const { createApiApp } = await import('../../server/app')
  app = createApiApp({ autoSeedDemo: false, identityModule: { modules: ['identity'] } } as never)
}

const LOGIN = { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ email: 'nobody@oimlsmart.org', password: 'wrong' }) }

beforeAll(bootApp)

afterAll(() => {
  rmSync(TMP, { recursive: true, force: true })
  delete process.env.OP_ISSUER
  delete process.env.OP_SIGNING_KEY
  delete process.env.DATABASE_PATH
  delete process.env.OP_ACCOUNT_SEED
  delete process.env.OP_CLIENT_SEED
})

describe('the declared seed never blocks a complete registry (the #78 fix)', () => {
  it('a fresh isolate whose registry is complete answers the first login with the CHECK cost only', async () => {
    // The registry is ALREADY populated (production steady-state: the
    // cast's rows exist; the declaration rides the env). A fresh
    // isolate's first credential-gated request must pay the parallel
    // existence check — NOT the 68-call convergence.
    process.env.OP_ACCOUNT_SEED = JSON.stringify(CAST)
    process.env.OP_CLIENT_SEED = JSON.stringify([CLIENT])
    const { getStore } = await import('../../server/store')
    for (const p of CAST) {
      await getStore().createOpAccount({ email: p.email, name: p.name, role: 'user', createdBy: 'test-prepopulate' })
    }
    const { seedOidcClientsFromEnv } = await import('../../server/auth/op/registry')
    await seedOidcClientsFromEnv({ OP_CLIENT_SEED: JSON.stringify([CLIENT]) }, getStore())
    // A NEW app instance = a fresh isolate (the seed memo is per-app).
    await bootApp()
    // The instrument: the background drift shares node's single thread
    // with the response, so a raw count races. Stall the drift at its
    // FIRST convergence-only write (setUserRoles — the login and the
    // check never call it) and count what ran before the stall: the
    // check's finds + the login, nothing more.
    let resolveStalled!: () => void
    let resolveRelease!: () => void
    const driftStalled = new Promise<void>(r => { resolveStalled = r })
    const releaseDrift = new Promise<void>(r => { resolveRelease = r })
    const realSetUserRoles = store.setUserRoles.bind(store) as (...a: unknown[]) => unknown
    let stalled = false
    ;(store as unknown as Record<string, (...a: unknown[]) => unknown>).setUserRoles = (...a: unknown[]) => {
      if (stalled) return realSetUserRoles(...a)
      stalled = true
      resolveStalled()
      return releaseDrift.then(() => realSetUserRoles(...a))
    }
    const count = countStoreCalls()
    const res = await app.request('/api/op/login', LOGIN)
    await driftStalled
    const calls = count()
    expect(res.status).toBe(401)
    expect(calls, `the first login on a complete registry made ${calls} store calls before the drift stalled — the convergence still blocked the answer`).toBeLessThanOrEqual(24)
    resolveRelease()
    await new Promise(r => setTimeout(r, 50))
  })

  it('an INCOMPLETE registry still seeds inline — the declared accounts exist by the answer', async () => {
    // A brand-new database (the fresh deployment): the bootstrap IS
    // the front door; the declared cast must exist when the login
    // answers (its 401 must be the honest invalid-credentials, not a
    // missing-row error), and the client registry must be populated.
    rmSync(TMP, { recursive: true, force: true })
    const { installSqliteStore } = await import('../../server/store/sqlite')
    installSqliteStore()
    await bootApp()
    const count = countStoreCalls()
    const res = await app.request('/api/op/login', LOGIN)
    const calls = count()
    expect(res.status).toBe(401)
    expect(calls, 'the fresh deployment pays its bootstrap inline').toBeGreaterThan(24)
    for (const p of CAST) {
      expect(await store.findUserByEmail(p.email), `${p.email} exists after the inline bootstrap`).toBeTruthy()
    }
    expect(await store.getOidcClient(CLIENT.client_id), 'the declared client exists').toBeTruthy()
  })
})
