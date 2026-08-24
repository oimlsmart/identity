// ─────────────────────────────────────────────────────────────────────
// The JWKS rollout window (the 2026-08-24 production flicker): a Worker
// secret put rolls a new version, and a FRESH ISOLATE in the
// propagation window can meet an OP_SIGNING_KEY binding that is
// momentarily unreadable while the rollout settles. The JWKS answer is
// the REGISTERED oidc_keys table; it must never be gated on the signing
// secret's availability (the secret matters for SIGNING, not for
// serving public keys). Before the fix, routes/op.ts resolved the
// secret unguarded on the read path and the endpoint answered an
// unhandled 500 (the identity heartbeat's standing issues:
// oimlsmart/identity#5, oimlsmart/smart#181).
//
// Proven here in-process against the REAL op router over a REAL temp
// SQLite store. The mid-propagation secret is simulated at the VALUE
// level (malformed JSON; a well-formed JWK of the wrong kind; a public
// half with no private half): Node's process.env rejects accessor
// descriptors, so a throwing binding cannot be faked in-process, and
// under hono's node adapter runtimeEnv() IS process.env. Every
// simulated state drives the same production failure: the
// resolveOpSigningKey throw escaping the route as a 500. The
// registration side stays honest too: the self-registration of a
// DECLARED, readable key must keep working (the rotation ceremony's
// overlap poll rides it), and a genuinely empty table answers
// {"keys":[]}.
// ─────────────────────────────────────────────────────────────────────

import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest'

// The store's DB path is read at module evaluation — set it before any
// import below touches @oimlsmart/platform-server/store/sqlite (the imports are dynamic).
const TMP = mkdtempSync(join(tmpdir(), 'oiml-jwks-rollout-'))
process.env.DATABASE_PATH = join(TMP, 'test.db')
process.env.OP_ISSUER = 'http://op.test'

let app: import('hono').Hono
let store: ReturnType<typeof import('@oimlsmart/platform-server/store').getStore>
let kidFor: typeof import('../../server/auth/op/keys').kidFor
let resetOpSigningKeyForTest: typeof import('../../server/auth/op/keys').resetOpSigningKeyForTest

/** The declared signing key (a real ES256 pair, generated for the run). */
let keyA: { privateJwkJson: string; kid: string }

/** The env's signing-secret declaration. */
function declareSecret(raw: string): void {
  process.env.OP_SIGNING_KEY = raw
}

function clearSecret(): void {
  delete process.env.OP_SIGNING_KEY
}

interface JwksBody {
  keys: Array<Record<string, unknown>>
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
`))

  const keysMod = await import('../../server/auth/op/keys')
  kidFor = keysMod.kidFor
  resetOpSigningKeyForTest = keysMod.resetOpSigningKeyForTest

  const { Hono } = await import('hono')
  const { createOpRouter } = await import('../../server/routes/op')
  app = new Hono()
  app.route('/', createOpRouter())

  // The deployment's declared key (the OP_SIGNING_KEY secret's shape:
  // a JWK JSON EC P-256 private key, kid stamped the OP's own way).
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
  const pub = await crypto.subtle.exportKey('jwk', pair.publicKey)
  const priv = await crypto.subtle.exportKey('jwk', pair.privateKey)
  const kid = await kidFor({ kty: 'EC', crv: 'P-256', x: pub.x, y: pub.y } as JsonWebKey)
  keyA = {
    privateJwkJson: JSON.stringify({ kty: 'EC', crv: 'P-256', x: pub.x, y: pub.y, d: priv.d, kid }),
    kid,
  }
})

afterEach(() => {
  clearSecret()
  resetOpSigningKeyForTest()
})

afterAll(() => {
  rmSync(TMP, { recursive: true, force: true })
  delete process.env.OP_ISSUER
  delete process.env.DATABASE_PATH
})

describe('the JWKS rollout window (a Worker secret mid-propagation)', () => {
  it('a genuinely empty table answers an honest empty JWKS, never a 500, when the secret is unreadable', async () => {
    // A fresh deployment's first hit INSIDE the propagation window:
    // nothing registered yet, the secret reads garbage.
    declareSecret('{"kty":"EC","crv":"P-256","x":"truncated')
    const res = await app.request('http://op.test/jwks.json')
    expect(res.status, 'the JWKS never 500s on a mid-propagation secret').toBe(200)
    const body = await res.json() as JwksBody
    expect(body.keys).toEqual([])
  })

  it('a declared, readable secret still self-registers (the rotation ceremony rides this)', async () => {
    declareSecret(keyA.privateJwkJson)
    const res = await app.request('http://op.test/jwks.json')
    expect(res.status).toBe(200)
    const body = await res.json() as JwksBody
    expect(body.keys.map(k => k.kid)).toEqual([keyA.kid])
    expect(body.keys[0]).toMatchObject({ kty: 'EC', crv: 'P-256', alg: 'ES256', use: 'sig' })
    const rows = await store.listOidcKeys()
    expect(rows.map(r => r.kid)).toContain(keyA.kid)
  })

  it('a malformed secret value mid-rollout serves the REGISTERED TABLE, not a 500', async () => {
    // The registration landed above (the settled posture). Now the next
    // isolate reads the secret as garbage while the rollout settles.
    declareSecret('{"kty":"EC","crv":"P-256","x":"truncated')
    const res = await app.request('http://op.test/jwks.json')
    expect(res.status, 'the JWKS never 500s on a mid-propagation secret').toBe(200)
    const body = await res.json() as JwksBody
    expect(body.keys.map(k => k.kid)).toEqual([keyA.kid])
  })

  it('a secret value the key loader rejects serves the REGISTERED TABLE, not a 500', async () => {
    // Well-formed JSON, but not the OP's ES256 private key (the binding
    // answering SOMETHING unreadable is the same window's other face).
    declareSecret(JSON.stringify({ kty: 'RSA', n: '0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM7', e: 'AQAB' }))
    const res = await app.request('http://op.test/jwks.json')
    expect(res.status, 'the JWKS never 500s on a mid-propagation secret').toBe(200)
    const body = await res.json() as JwksBody
    expect(body.keys.map(k => k.kid)).toEqual([keyA.kid])

    // …and the public-half-only variant (no d).
    declareSecret(keyA.privateJwkJson.replace(/,"d":"[^"]*"/, ''))
    const res2 = await app.request('http://op.test/jwks.json')
    expect(res2.status, 'the JWKS never 500s on a mid-propagation secret').toBe(200)
    const body2 = await res2.json() as JwksBody
    expect(body2.keys.map(k => k.kid)).toEqual([keyA.kid])
  })

  it('the rollout settles: the declared key resolves again, and the window registered NO junk rows', async () => {
    declareSecret(keyA.privateJwkJson)
    const res = await app.request('http://op.test/jwks.json')
    expect(res.status).toBe(200)
    const body = await res.json() as JwksBody
    expect(body.keys.map(k => k.kid)).toEqual([keyA.kid])
    // The whole window (the malformed read, the rejected key material)
    // left the rotation history exactly as the settled posture declared.
    const rows = await store.listOidcKeys()
    expect(rows.map(r => r.kid)).toEqual([keyA.kid])
  })
})
