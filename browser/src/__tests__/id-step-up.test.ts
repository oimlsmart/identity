// ─────────────────────────────────────────────────────────────────────
// TODO.sota/06 — STEP-UP AUTH: the sensitive acts (role grants, the
// identity-link changes) demand a FRESH proof inside the session — a
// short-lived, OP-signed stamp cookie minted by re-entering the
// current password. STATELESS (the owner's law): the stamp is a JWT
// over the OP's own keyset; nothing is stored.
//
//   MINT/VERIFY  the stamp's TTL, the user binding, the tamper refusal
//   ROUTE        POST /api/op/step-up — the right password sets the
//                cookie; the wrong one refuses; the anonymous 401s
//   GATE         the roles editor without the stamp answers 403
//                step_up_required; with a minted stamp the act lands
// ─────────────────────────────────────────────────────────────────────
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

const TMP = mkdtempSync(join(tmpdir(), 'oiml-step-up-'))
process.env.DATABASE_PATH = join(TMP, 'test.db')
const ISSUER = 'http://op.test'
process.env.OP_ISSUER = ISSUER

process.env.OP_ACCOUNT_SEED = JSON.stringify([
  { email: 'granter@oimlsmart.org', name: 'The Granter', role: 'admin', password: 'the granter passphrase 2026', emailVerified: true },
  { email: 'target@oimlsmart.org', name: 'Target Account', role: 'viewer', password: 'the target passphrase', emailVerified: true },
])

let app: import('hono').Hono
let store: ReturnType<typeof import('../../server/store').getStore>
let cookie: string

beforeAll(async () => {
  // identity#7: a declared signing key, so the stamp's verification
  // resolves against the REGISTERED keyset (a generated dev key never
  // registers — verifyOpJwt would honestly refuse).
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
`))
  const { createApiApp } = await import('../../server/app')
  app = createApiApp({ autoSeedDemo: false, instanceProfile: profileMod.getInstanceProfile() })
  store = (await import('../../server/store')).getStore()

  const res = await app.request(`${ISSUER}/api/op/login`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email: 'granter@oimlsmart.org', password: 'the granter passphrase 2026' }),
  })
  expect(res.status).toBe(200)
  cookie = res.headers.get('set-cookie')!.split(';')[0]!

  // The declared key's REGISTRATION rides the OIDC legs (the #7 gate:
  // /jwks.json registers the declared key into the keyset) — the
  // stamp's verification resolves against the registered table.
  const jwks = await app.request(`${ISSUER}/jwks.json`)
  expect(jwks.status).toBe(200)
})

afterAll(() => {
  rmSync(TMP, { recursive: true, force: true })
  for (const key of ['DATABASE_PATH', 'OP_ISSUER', 'OP_ACCOUNT_SEED', 'OP_SIGNING_KEY']) delete process.env[key]
})

describe('TODO.sota/06 — step-up auth', () => {
  it('GATE: the roles editor without a fresh stamp answers 403 step_up_required (the act never lands)', async () => {
    const target = await store.findUserByEmail('target@oimlsmart.org')
    const res = await app.request(`${ISSUER}/api/users/${target!.id}/roles`, {
      method: 'PUT', headers: { cookie, 'content-type': 'application/json' },
      body: JSON.stringify({ role: 'system_admin', roles: ['system_admin'] }),
    })
    expect(res.status).toBe(403)
    const body = await res.json() as { error?: string; stepUp?: boolean }
    expect(body.stepUp).toBe(true)
    expect(body.error).toContain('verify once more')
    // NOTHING was written.
    expect((await store.getUserById(target!.id))?.role).toBe('viewer')
  })

  it('ROUTE: the wrong password refuses 403 and mints NOTHING', async () => {
    const res = await app.request(`${ISSUER}/api/op/step-up`, {
      method: 'POST', headers: { cookie, 'content-type': 'application/json' },
      body: JSON.stringify({ password: 'not the password' }),
    })
    expect(res.status).toBe(403)
    expect(res.headers.get('set-cookie')).toBeNull()
  })

  it('ROUTE + GATE: the right password mints the stamp; the act then lands', async () => {
    const step = await app.request(`${ISSUER}/api/op/step-up`, {
      method: 'POST', headers: { cookie, 'content-type': 'application/json' },
      body: JSON.stringify({ password: 'the granter passphrase 2026' }),
    })
    expect(step.status).toBe(200)
    const setCookie = step.headers.get('set-cookie')!
    expect(setCookie).toContain('op_step_up=')
    const stampCookie = setCookie.split(';')[0]!

    const target = await store.findUserByEmail('target@oimlsmart.org')
    const res = await app.request(`${ISSUER}/api/users/${target!.id}/roles`, {
      method: 'PUT', headers: { cookie: `${cookie}; ${stampCookie}`, 'content-type': 'application/json' },
      body: JSON.stringify({ role: 'system_admin', roles: ['system_admin', 'viewer'] }),
    })
    expect(res.status, await res.text()).toBe(200)
  })

  it('the stamp is USER-BOUND: another account\'s stamp never opens the gate', async () => {
    const { mintStepUpStamp } = await import('../../server/auth/op/step-up-stamp')
    const { resolveOpSigningKey } = await import('../../server/auth/op/keys')
    const key = await resolveOpSigningKey(process.env as Record<string, string>)
    const foreign = await mintStepUpStamp(key, 'someone-else', 'pwd')
    const target = await store.findUserByEmail('target@oimlsmart.org')
    const res = await app.request(`${ISSUER}/api/users/${target!.id}/roles`, {
      method: 'PUT', headers: { cookie: `${cookie}; op_step_up=${foreign}`, 'content-type': 'application/json' },
      body: JSON.stringify({ role: 'system_admin', roles: ['system_admin'] }),
    })
    expect(res.status).toBe(403)
  })

  it('an ORDINARY adjustment (no privileged role) never demands the step-up', async () => {
    const target = await store.findUserByEmail('target@oimlsmart.org')
    const res = await app.request(`${ISSUER}/api/users/${target!.id}/roles`, {
      method: 'PUT', headers: { cookie, 'content-type': 'application/json' },
      body: JSON.stringify({ role: 'viewer', roles: ['viewer', 'scheme_participant'] }),
    })
    expect(res.status, await res.text()).toBe(200)
  })

  it('MINT/VERIFY: the TTL bounds, the tamper refuses', async () => {
    const mod = await import('../../server/auth/op/step-up-stamp')
    const { resolveOpSigningKey } = await import('../../server/auth/op/keys')
    const key = await resolveOpSigningKey(process.env as Record<string, string>)
    const stamp = await mod.mintStepUpStamp(key, 'u-1', 'pwd')
    expect(await mod.stepUpSatisfied(store, stamp, 'u-1')).toBe(true)
    expect(await mod.stepUpSatisfied(store, stamp, 'u-2')).toBe(false) // the binding
    expect(await mod.stepUpSatisfied(store, stamp.slice(0, -2) + 'xx', 'u-1')).toBe(false) // the tamper
    const expired = await mod.mintStepUpStamp(key, 'u-1', 'pwd', Date.now() - mod.STEP_UP_TTL_MS - 1000)
    expect(await mod.stepUpSatisfied(store, expired, 'u-1')).toBe(false) // the TTL
    // A PLAIN OP token (an ID token) never satisfies: the stamp claim gates.
    expect(await mod.stepUpSatisfied(store, 'not-a-jwt', 'u-1')).toBe(false)
  })
})
