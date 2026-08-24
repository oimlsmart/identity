// ─────────────────────────────────────────────────────────────────────
// The oidc_keys self-registration gate (oimlsmart/identity#7, the
// second-order risk identity#6's rollout-flicker report recorded): when
// the OP_SIGNING_KEY binding reads as EMPTY/UNDEFINED (a mid-propagation
// rollout state), resolveOpSigningKey does not throw — it GENERATES a
// development key pair per process (the documented dev posture, the LOUD
// warning included). On the production identity service that generated
// key must never reach oidc_keys: an ephemeral per-isolate kid in the
// keyset the RPs validate against is junk by construction (sibling
// isolates sign with DIFFERENT keys, the row outlives the isolate that
// minted it).
//
// The gate: self-registration is the DECLARED secret's privilege. A
// generated development key registers ONLY in the dev posture — the
// issuer derived from the request origin (OP_ISSUER unset, config.ts's
// documented dev fallback; wrangler.toml's default env works the same
// way). A declared-issuer deployment (the production posture) serves the
// registered table as it stands. The /op/token route's first-use
// registration rides the SAME predicate (routes/op.ts), so the pollution
// vector is closed at both doors; the JWKS route is the issue's named
// path and is what this file drives.
//
// Proven here in-process against the REAL op router over a REAL temp
// SQLite store (the id-jwks-rollout pattern): the production posture
// leaves the table CLEAN, the dev posture keeps registering (the local
// RP round trips depend on it), and the declared key's registration is
// untouched on either posture.
// ─────────────────────────────────────────────────────────────────────

import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'

// The store's DB path is read at module evaluation — set it before any
// import below touches @oimlsmart/platform-server/store/sqlite (the imports are dynamic).
const TMP = mkdtempSync(join(tmpdir(), 'oiml-jwks-key-gate-'))
process.env.DATABASE_PATH = join(TMP, 'test.db')

let app: import('hono').Hono
let store: ReturnType<typeof import('@oimlsmart/platform-server/store').getStore>
let wipeKeys: () => void
let resetOpSigningKeyForTest: typeof import('../../server/auth/op/keys').resetOpSigningKeyForTest

/** The declared signing key (a real ES256 pair, generated for the run). */
let keyA: { privateJwkJson: string; kid: string }

interface JwksBody {
  keys: Array<Record<string, unknown>>
}

beforeAll(async () => {
  const sqlite = await import('@oimlsmart/platform-server/store/sqlite')
  store = sqlite.installSqliteStore()
  const db = sqlite.getDb()
  wipeKeys = () => { db.exec('DELETE FROM oidc_keys') }
  const profileMod = await import('@oimlsmart/platform-server/profile')
  profileMod.installInstanceProfile(profileMod.parseInstanceProfile(`
identity:
  org_id: oimlsmart-id
  org_name: OIML SMART Identity
  role_codes: [identity]
roles: [identity]
branding: { name: OIML SMART Identity }
`))

  const keysMod = await import('../../server/auth/op/keys')
  resetOpSigningKeyForTest = keysMod.resetOpSigningKeyForTest

  const { Hono } = await import('hono')
  const { createOpRouter } = await import('../../server/routes/op')
  app = new Hono()
  app.route('/', createOpRouter())

  // The deployment's declared key (the OP_SIGNING_KEY secret's shape: a
  // JWK JSON EC P-256 private key, kid stamped the OP's own way).
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
  const pub = await crypto.subtle.exportKey('jwk', pair.publicKey)
  const priv = await crypto.subtle.exportKey('jwk', pair.privateKey)
  const kid = await keysMod.kidFor({ kty: 'EC', crv: 'P-256', x: pub.x, y: pub.y } as JsonWebKey)
  keyA = { privateJwkJson: JSON.stringify({ kty: 'EC', crv: 'P-256', x: pub.x, y: pub.y, d: priv.d, kid }), kid }
})

beforeEach(() => {
  wipeKeys()
  delete process.env.OP_ISSUER
  delete process.env.OP_SIGNING_KEY
  resetOpSigningKeyForTest()
})

afterEach(() => {
  vi.restoreAllMocks()
  delete process.env.OP_ISSUER
  delete process.env.OP_SIGNING_KEY
  resetOpSigningKeyForTest()
})

afterAll(() => {
  rmSync(TMP, { recursive: true, force: true })
  delete process.env.DATABASE_PATH
})

describe('the dev-key registration gate (identity#7)', () => {
  it('the production posture (a declared OP_ISSUER) NEVER registers a generated development key — the table stays clean', async () => {
    // The rollout window's second face: the binding reads EMPTY on a
    // fresh isolate of the production identity service. The resolve
    // falls to the dev generation (the loud warning fires, proven
    // below); the registration must NOT follow.
    process.env.OP_ISSUER = 'http://op.test'
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})

    const res = await app.request('http://op.test/jwks.json')
    expect(res.status, 'the JWKS never 500s on the missing secret').toBe(200)
    const body = await res.json() as JwksBody
    expect(body.keys, 'no generated key is advertised').toEqual([])

    // The keyset the RPs validate against carries NO junk row.
    const rows = await store.listOidcKeys()
    expect(rows, 'the production table stays clean').toEqual([])

    // The generated dev key's LOUD warning stays (the dev-posture
    // signal is the operator's cue that the secret is undeclared).
    const warnings = warn.mock.calls.map(c => String(c[0]))
    expect(warnings.some(w => w.includes('OP_SIGNING_KEY is not set')), 'the loud dev-key warning fired').toBe(true)
    expect(warnings.some(w => w.includes('refusing to register')), 'the gate explains itself').toBe(true)
  })

  it('the production posture with the secret restored serves the REGISTERED table, and the window left no junk behind', async () => {
    process.env.OP_ISSUER = 'http://op.test'
    // The window: the binding reads empty, the JWKS is hit (and would
    // have minted a junk row before the gate).
    let res = await app.request('http://op.test/jwks.json')
    expect(res.status).toBe(200)
    expect((await res.json() as JwksBody).keys).toEqual([])

    // The rollout settles: the declared key resolves, self-registers,
    // and the history is EXACTLY the declared key (no ephemeral kid
    // beside it).
    process.env.OP_SIGNING_KEY = keyA.privateJwkJson
    res = await app.request('http://op.test/jwks.json')
    expect(res.status).toBe(200)
    const body = await res.json() as JwksBody
    expect(body.keys.map(k => k.kid)).toEqual([keyA.kid])
    const rows = await store.listOidcKeys()
    expect(rows.map(r => r.kid)).toEqual([keyA.kid])
  })

  it('the dev posture (the issuer from the request origin) still registers the generated key — the local RP round trips work', async () => {
    // OP_ISSUER UNSET: config.ts's documented dev fallback (wrangler
    // dev's default env reads the same way). The generated key
    // self-registers, so a local stack's JWKS answers its own key.
    const res = await app.request('http://localhost:3190/jwks.json')
    expect(res.status).toBe(200)
    const body = await res.json() as JwksBody
    expect(body.keys.length, 'the dev key is advertised').toBe(1)
    expect(body.keys[0]).toMatchObject({ kty: 'EC', crv: 'P-256', alg: 'ES256', use: 'sig' })
    expect(typeof body.keys[0]!.kid).toBe('string')

    const rows = await store.listOidcKeys()
    expect(rows.map(r => r.kid)).toContain(body.keys[0]!.kid)
  })

  it('the dev posture with a DECLARED secret registers the declared key (declaration wins there too)', async () => {
    process.env.OP_SIGNING_KEY = keyA.privateJwkJson
    const res = await app.request('http://localhost:3190/jwks.json')
    expect(res.status).toBe(200)
    const body = await res.json() as JwksBody
    expect(body.keys.map(k => k.kid)).toEqual([keyA.kid])
  })
})
