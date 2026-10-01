// ─────────────────────────────────────────────────────────────────────
// TODO.sota/09 — OIDC Federation, slice 1: the LEAF entity
// configuration. The OP publishes its own entity statement at
// /.well-known/openid-federation — a signed JWT whose iss=sub= the
// entity identifier, whose jwks are the OP's public keys, and whose
// openid_provider metadata mirrors the discovery document (the ONE
// builder — the two documents can never drift). The trust chain's
// intermediates are the named next slice; a self-standing leaf is a
// valid federation member today.
// ─────────────────────────────────────────────────────────────────────
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

const TMP = mkdtempSync(join(tmpdir(), 'oiml-fed-'))
process.env.DATABASE_PATH = join(TMP, 'test.db')
const ISSUER = 'http://op.test'
process.env.OP_ISSUER = ISSUER
const PROFILE = join(TMP, 'profile.yaml')
writeFileSync(PROFILE, `name: federation
roles: [identity]
branding: { name: Federation }
demo_personas: true
`)
process.env.INSTANCE_PROFILE = PROFILE

let app: import('hono').Hono

function b64urlToObj(v: string): Record<string, unknown> {
  return JSON.parse(atob(v.replace(/-/g, '+').replace(/_/g, '/'))) as Record<string, unknown>
}

beforeAll(async () => {
  process.env.OP_SIGNING_KEY = await (await import('../../e2e/fixtures/op-signing-key')).fixtureOpSigningKey()
  const { installSqliteStore } = await import('../../server/store/sqlite')
  installSqliteStore()
  const profileMod = await import('../../server/profile')
  profileMod.installInstanceProfile(profileMod.parseInstanceProfile(`
identity:
  org_id: oimlsmart-id
  org_name: Federation
  role_codes: [identity]
roles: [identity]
branding: { name: Federation }
demo_personas: true
`))
  const { Hono } = await import('hono')
  const { createOpRouter } = await import('../../server/routes/op')
  const root = new Hono()
  root.route('/', createOpRouter())
  app = root
}, 30_000)

afterAll(async () => {
  rmSync(TMP, { recursive: true, force: true })
  delete process.env.OP_ISSUER
  delete process.env.OP_SIGNING_KEY
  delete process.env.DATABASE_PATH
  delete process.env.INSTANCE_PROFILE
  const profileMod = await import('../../server/profile')
  profileMod.resetInstanceProfileForTest()
})

describe('the leaf entity configuration (TODO.sota/09, OIDC Federation slice 1)', () => {
  it('answers a signed entity statement whose iss=sub=the issuer, with the OP\'s jwks and the mirrored metadata', async () => {
    const res = await app.request('/.well-known/openid-federation')
    expect(res.status).toBe(200)
    expect(res.headers.get('content-type')).toContain('application/entity-statement+jwt')
    const jwt = await res.text()
    const parts = jwt.split('.')
    expect(parts.length).toBe(3)
    const header = b64urlToObj(parts[0]!) as { typ?: string; alg?: string; kid?: string }
    expect(header.typ).toBe('entity-statement+jwt')
    expect(header.alg).toBe('ES256')
    const payload = b64urlToObj(parts[1]!) as {
      iss?: string; sub?: string; iat?: number; exp?: number
      jwks?: { keys?: unknown[] }
      metadata?: { openid_provider?: Record<string, unknown> }
    }
    expect(payload.iss).toBe(ISSUER)
    expect(payload.sub).toBe(ISSUER)
    expect(typeof payload.iat).toBe('number')
    expect((payload.exp ?? 0) > (payload.iat ?? 1)).toBe(true)
    expect(Array.isArray(payload.jwks?.keys)).toBe(true)
    expect((payload.jwks!.keys as unknown[]).length).toBeGreaterThan(0)
    const op = payload.metadata?.openid_provider ?? {}
    expect(op.issuer).toBe(ISSUER)
    expect(op.authorization_endpoint).toBe(`${ISSUER}/op/authorize`)
    expect(op.token_endpoint).toBe(`${ISSUER}/op/token`)
    expect(op.jwks_uri).toBe(`${ISSUER}/jwks.json`)
  })

  it('the statement signature verifies against the PUBLISHED jwks (self-consistent)', async () => {
    const jwt = await (await app.request('/.well-known/openid-federation')).text()
    const jwks = (await (await app.request('/jwks.json')).json()) as { keys: Array<{ kty?: string; crv?: string; x?: string; y?: string; kid?: string }> }
    const [header, payload, signature] = jwt.split('.') as [string, string, string]
    const h = b64urlToObj(header) as { kid?: string }
    const match = jwks.keys.find(k => k.kid === h.kid)
    expect(match, 'the signing kid resolves in the published set').toBeTruthy()
    const key = await crypto.subtle.importKey(
      'jwk',
      { kty: 'EC', crv: match!.crv, x: match!.x, y: match!.y },
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['verify'],
    )
    const bin = atob(signature.replace(/-/g, '+').replace(/_/g, '/'))
    const sig = new Uint8Array(new ArrayBuffer(bin.length))
    for (let i = 0; i < bin.length; i++) sig[i] = bin.charCodeAt(i)
    const ok = await crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      key,
      sig,
      new TextEncoder().encode(`${header}.${payload}`),
    )
    expect(ok).toBe(true)
  })
})
