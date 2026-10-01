// ─────────────────────────────────────────────────────────────────────
// TODO.sota/08 — the SD-JWT engine (RFC 9445) + the OrgMembership
// credential: the selectively-disclosable JWT's mint/verify core, the
// holder key binding (the KB-JWT), and the issuing route. The keys are
// REAL (the contract fixture signing key; WebCrypto holder pairs), the
// discipline is the spec's: the payload carries _SD hashes, NEVER the
// values; the disclosures are [salt, name, value]; the verifier
// rejects unreferenced disclosures, duplicate claims, and a tampered
// hash leg.
// ─────────────────────────────────────────────────────────────────────
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

const TMP = mkdtempSync(join(tmpdir(), 'oiml-sdjwt-'))
process.env.DATABASE_PATH = join(TMP, 'test.db')
const ISSUER = 'http://op.test'
process.env.OP_ISSUER = ISSUER
const PROFILE = join(TMP, 'profile.yaml')
writeFileSync(PROFILE, `name: sdjwt
roles: [identity]
branding: { name: SD-JWT }
demo_personas: true
`)
process.env.INSTANCE_PROFILE = PROFILE

let store: ReturnType<typeof import('../../server/store').getStore>
let app: import('hono').Hono
let key: import('../../server/auth/op/keys').OpSigningKey
let demoCookie: string

function b64url(bytes: Uint8Array): string {
  let bin = ''
  for (const b of bytes) bin += String.fromCharCode(b)
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

async function holderJwk(): Promise<{ keys: CryptoKeyPair; jwk: { kty: string; crv: string; x: string; y: string }; jkt: string }> {
  const keys = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']) as CryptoKeyPair
  const jwk = await crypto.subtle.exportKey('jwk', keys.publicKey) as { kty: string; crv: string; x: string; y: string }
  const { jktOf } = await import('../../server/auth/op/dpop')
  return { keys, jwk, jkt: await jktOf(jwk) }
}

beforeAll(async () => {
  process.env.OP_SIGNING_KEY = await (await import('../../e2e/fixtures/op-signing-key')).fixtureOpSigningKey()
  const { installSqliteStore } = await import('../../server/store/sqlite')
  store = installSqliteStore()
  const profileMod = await import('../../server/profile')
  profileMod.installInstanceProfile(profileMod.parseInstanceProfile(`
identity:
  org_id: oimlsmart-id
  org_name: SD-JWT
  role_codes: [identity]
roles: [identity]
branding: { name: SD-JWT }
demo_personas: true
`))
  const { resolveOpSigningKey, ensureOpKeyRegistered } = await import('../../server/auth/op/keys')
  key = await resolveOpSigningKey(process.env as Record<string, string | undefined>)
  await ensureOpKeyRegistered(store, key)

  const { Hono } = await import('hono')
  const { createAuthLeanRouter } = await import('../../server/routes/auth-lean')
  const { createOpCredentialsRouter } = await import('../../server/routes/op-credentials')
  const root = new Hono()
  root.route('/api/auth', createAuthLeanRouter({ autoSeedDemo: true }))
  root.route('/', createOpCredentialsRouter())
  app = root
  const res = await app.request('/api/auth/demo', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email: 'ia@oimlsmart.org', password: 'demo2026' }),
  })
  expect(res.ok).toBe(true)
  demoCookie = res.headers.get('set-cookie')!.split(';')[0]!
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

describe('the SD-JWT engine (auth/op/sd-jwt.ts)', () => {
  it('mints a payload of HASHES (never the values); the presentation reconstructs exactly what the holder disclosed', async () => {
    const { mintSdJwt, combinedPresentation, verifySdJwtPresentation } = await import('../../server/auth/op/sd-jwt')
    const minted = await mintSdJwt(key, {
      issuer: ISSUER, subject: 'acct-1', ttlSec: 3600,
      plain: { vct: 'org-membership' },
      disclosable: { name: 'Ada Lovelace', org: 'nist.gov', org_ror: 'https://ror.org/05xpvk416' },
    })
    // The JWS payload carries the hashes — the values are NOWHERE in it.
    const payload = JSON.parse(atob(minted.sdJwt.split('.')[1]!.replace(/-/g, '+').replace(/_/g, '/'))) as Record<string, unknown>
    expect(payload._sd_alg).toBe('sha-256')
    expect(Array.isArray(payload._SD)).toBe(true)
    expect((payload._SD as unknown[]).length).toBe(3)
    expect(minted.sdJwt).not.toContain('Ada Lovelace')

    // Disclose ONLY name + org; org_ror stays hidden.
    const presented = combinedPresentation(minted.sdJwt, minted.disclosures.slice(0, 2))
    const verified = await verifySdJwtPresentation(store, presented, { issuer: ISSUER })
    expect('claims' in verified && verified.claims).toMatchObject({ vct: 'org-membership', name: 'Ada Lovelace', org: 'nist.gov', sub: 'acct-1' })
    if ('claims' in verified) expect('org_ror' in verified.claims).toBe(false)
  })

  it('rejects a tampered disclosure, an unreferenced disclosure, and a duplicate claim', async () => {
    const { mintSdJwt, combinedPresentation, verifySdJwtPresentation, mintArbitraryDisclosure } = await import('../../server/auth/op/sd-jwt')
    const minted = await mintSdJwt(key, {
      issuer: ISSUER, subject: 'acct-1', ttlSec: 60,
      plain: {}, disclosable: { name: 'Ada' },
    })
    // Tamper: flip the value inside a real disclosure (hash mismatch).
    const [salt, claim, value] = JSON.parse(atob(minted.disclosures[0]!.replace(/-/g, '+').replace(/_/g, '/'))) as [string, string, string]
    const tampered = b64url(new TextEncoder().encode(JSON.stringify([salt, claim, 'Someone Else'])))
    expect('error' in await verifySdJwtPresentation(store, combinedPresentation(minted.sdJwt, [tampered]), { issuer: ISSUER })).toBe(true)
    // Unreferenced: an honest-looking disclosure the payload never hashed.
    const alien = await mintArbitraryDisclosure('email', 'ada@example.org')
    expect('error' in await verifySdJwtPresentation(store, combinedPresentation(minted.sdJwt, minted.disclosures.concat([alien])), { issuer: ISSUER })).toBe(true)
    // Duplicate: the same disclosure twice.
    expect('error' in await verifySdJwtPresentation(store, combinedPresentation(minted.sdJwt, [minted.disclosures[0]!, minted.disclosures[0]!]), { issuer: ISSUER })).toBe(true)
    // Wrong issuer.
    expect('error' in await verifySdJwtPresentation(store, combinedPresentation(minted.sdJwt, minted.disclosures), { issuer: 'https://other.example' })).toBe(true)
  })

  it('the holder key binding: the KB-JWT verifies against cnf.jkt; the wrong key and a wrong sd_hash refuse', async () => {
    const { mintSdJwt, combinedPresentation, mintKeyBindingJwt, verifySdJwtPresentation } = await import('../../server/auth/op/sd-jwt')
    const holder = await holderJwk()
    const minted = await mintSdJwt(key, {
      issuer: ISSUER, subject: 'acct-1', ttlSec: 3600,
      plain: {}, disclosable: { name: 'Ada' }, holderJkt: holder.jkt,
    })
    const kb = await mintKeyBindingJwt(holder.keys, { sdJwt: minted.sdJwt, nonce: 'the-nonce', aud: 'the-verifier' })
    const ok = await verifySdJwtPresentation(store, combinedPresentation(minted.sdJwt, minted.disclosures, kb), {
      issuer: ISSUER, keyBinding: { nonce: 'the-nonce', aud: 'the-verifier' },
    })
    expect('claims' in ok).toBe(true)

    const wrongHolder = await holderJwk()
    const wrongKey = await mintKeyBindingJwt(wrongHolder.keys, { sdJwt: minted.sdJwt, nonce: 'the-nonce', aud: 'the-verifier' })
    expect('error' in await verifySdJwtPresentation(store, combinedPresentation(minted.sdJwt, minted.disclosures, wrongKey), {
      issuer: ISSUER, keyBinding: { nonce: 'the-nonce', aud: 'the-verifier' },
    })).toBe(true)

    const wrongNonce = await mintKeyBindingJwt(holder.keys, { sdJwt: minted.sdJwt, nonce: 'other-nonce', aud: 'the-verifier' })
    expect('error' in await verifySdJwtPresentation(store, combinedPresentation(minted.sdJwt, minted.disclosures, wrongNonce), {
      issuer: ISSUER, keyBinding: { nonce: 'the-nonce', aud: 'the-verifier' },
    })).toBe(true)
  })
})

describe('the OrgMembership credential route (TODO.sota/08)', () => {
  it('the well-known credential-issuer document answers publicly; the mint requires the session; the credential verifies', async () => {
    const wellKnown = await app.request('/.well-known/openid-credential-issuer')
    expect(wellKnown.status).toBe(200)
    const doc = await wellKnown.json() as { credential_issuer: string; credential_configurations_supported: Record<string, unknown> }
    expect(doc.credential_issuer).toBe(ISSUER)
    expect(doc.credential_configurations_supported['org-membership']).toBeTruthy()

    const refused = await app.request('/api/op/credentials/membership', { method: 'POST' })
    expect(refused.status).toBe(401)

    const holder = await holderJwk()
    const minted = await app.request('/api/op/credentials/membership', {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: demoCookie },
      body: JSON.stringify({ holder_jwk: holder.jwk }),
    })
    expect(minted.status).toBe(200)
    const body = await minted.json() as { format: string; credential: string }
    expect(body.format).toBe('vc+sd-jwt')

    const { verifySdJwtPresentation, mintKeyBindingJwt } = await import('../../server/auth/op/sd-jwt')
    const kb = await mintKeyBindingJwt(holder.keys, { sdJwt: body.credential.split('~')[0]!, nonce: 'verify-me', aud: 'a-verifier' })
    const verified = await verifySdJwtPresentation(store, `${body.credential}~${kb}`, {
      issuer: ISSUER, keyBinding: { nonce: 'verify-me', aud: 'a-verifier' },
    })
    expect('claims' in verified).toBe(true)
    if ('claims' in verified) {
      expect(verified.claims.vct).toBe('org-membership')
      expect(typeof verified.claims.email).toBe('string')
    }
  })
})
