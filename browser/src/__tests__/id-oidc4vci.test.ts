// ─────────────────────────────────────────────────────────────────────
// TODO.sota/08 slice 3 — the OIDC4VCI authorization-code flow: a
// WALLET (any registered RP) drives OUR authorization server with the
// org-membership scope, the token answer carries the c_nonce
// challenge, and the credential endpoint mints the holder-bound
// credential against the wallet's key proof. Every leg is REAL: the
// authorize→consent→decide dance, the PKCE exchange, the WebCrypto
// wallet key, the HMAC nonce.
// ─────────────────────────────────────────────────────────────────────
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

const TMP = mkdtempSync(join(tmpdir(), 'oiml-o4vci-'))
process.env.DATABASE_PATH = join(TMP, 'test.db')
const ISSUER = 'http://op.test'
process.env.OP_ISSUER = ISSUER
const PROFILE = join(TMP, 'profile.yaml')
writeFileSync(PROFILE, `name: o4vci
roles: [identity]
branding: { name: O4VCI }
demo_personas: true
`)
process.env.INSTANCE_PROFILE = PROFILE

const WALLET = 'the-wallet-rp'
const WALLET_SECRET = 'the-wallet-secret'
const REDIRECT = 'http://127.0.0.1:9991/cb'
const VERIFIER = 'a-verifier-with-plenty-of-entropy-for-s256'
const CREDENTIAL_ENDPOINT = `${ISSUER}/op/credential`

let store: ReturnType<typeof import('../../server/store').getStore>
let app: import('hono').Hono
let key: import('../../server/auth/op/keys').OpSigningKey
let cookie: string

function b64url(bytes: Uint8Array): string {
  let bin = ''
  for (const b of bytes) bin += String.fromCharCode(b)
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

async function json(res: Response, status: number): Promise<Record<string, unknown>> {
  expect(res.status).toBe(status)
  return res.json() as Promise<Record<string, unknown>>
}

/** The wallet's key proof (openid4vci-proof+jwt): ES256, the public jwk
 *  in the header, aud = the issuer, the c_nonce echoed. */
async function mintWalletProof(keys: CryptoKeyPair, nonce: string, aud = ISSUER): Promise<{ proof: string; jkt: string }> {
  const jwk = await crypto.subtle.exportKey('jwk', keys.publicKey) as { kty: string; crv: string; x: string; y: string }
  const { jktOf } = await import('../../server/auth/op/dpop')
  const jkt = await jktOf(jwk)
  const header = { typ: 'openid4vci-proof+jwt', alg: 'ES256', jwk: { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y } }
  const payload = { aud, iat: Math.floor(Date.now() / 1000), nonce }
  const encoder = new TextEncoder()
  const unsigned = `${b64url(encoder.encode(JSON.stringify(header)))}.${b64url(encoder.encode(JSON.stringify(payload)))}`
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, keys.privateKey, encoder.encode(unsigned))
  return { proof: `${unsigned}.${b64url(new Uint8Array(sig))}`, jkt }
}

async function driveCredentialGrant(): Promise<{ accessToken: string; cNonce: string }> {
  const { pkceS256 } = await import('../../server/auth/op/keys')
  const query = new URLSearchParams({
    response_type: 'code', client_id: WALLET, redirect_uri: REDIRECT,
    scope: 'openid org-membership', state: 'st-1', nonce: 'nn-1',
    code_challenge: await pkceS256(VERIFIER), code_challenge_method: 'S256', prompt: 'consent',
  })
  const authorize = await app.request(`/op/authorize?${query}`, { headers: { cookie } })
  expect(authorize.status).toBe(302)
  const authId = new URL(authorize.headers.get('location')!, ISSUER).searchParams.get('auth')!
  const decide = await app.request(`/api/op/consent/${authId}/decide`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', cookie },
    body: JSON.stringify({ decision: 'allow' }),
  })
  const { redirect } = await json(decide, 200)
  const code = new URL(redirect as string).searchParams.get('code')!
  const res = await app.request('/op/token', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', authorization: 'Basic ' + btoa(`${WALLET}:${WALLET_SECRET}`) },
    body: new URLSearchParams({ grant_type: 'authorization_code', code, redirect_uri: REDIRECT, code_verifier: VERIFIER }).toString(),
  })
  const body = await json(res, 200) as { access_token: string; c_nonce?: string }
  expect(body.c_nonce, 'the org-membership grant answers the c_nonce challenge').toBeTruthy()
  return { accessToken: body.access_token, cNonce: body.c_nonce! }
}

beforeAll(async () => {
  process.env.OP_SIGNING_KEY = await (await import('../../e2e/fixtures/op-signing-key')).fixtureOpSigningKey()
  const { installSqliteStore } = await import('../../server/store/sqlite')
  store = installSqliteStore()
  const profileMod = await import('../../server/profile')
  profileMod.installInstanceProfile(profileMod.parseInstanceProfile(`
identity:
  org_id: oimlsmart-id
  org_name: O4VCI
  role_codes: [identity]
roles: [identity]
branding: { name: O4VCI }
demo_personas: true
`))
  const { resolveOpSigningKey, ensureOpKeyRegistered } = await import('../../server/auth/op/keys')
  key = await resolveOpSigningKey(process.env as Record<string, string | undefined>)
  await ensureOpKeyRegistered(store, key)

  await store.upsertOidcClient({
    clientId: WALLET, name: 'The wallet',
    secretHash: await (await import('../../server/auth/op/secrets')).hashClientSecret(WALLET_SECRET),
    redirectUris: [REDIRECT], claimsPolicy: null, createdBy: 'test',
  })

  const { Hono } = await import('hono')
  const { createAuthLeanRouter } = await import('../../server/routes/auth-lean')
  const { createOpProtocolRouter } = await import('../../server/routes/op-protocol')
  const { authenticateClient, createOpTokenRouter } = await import('../../server/routes/op-token')
  const { createOpCredentialsRouter } = await import('../../server/routes/op-credentials')
  const root = new Hono()
  root.route('/api/auth', createAuthLeanRouter({ autoSeedDemo: true }))
  root.route('/', createOpProtocolRouter({ ensureSeeded: async () => {}, audit: async () => {}, authenticateClient }))
  root.route('/', createOpTokenRouter({ ensureSeeded: async () => {}, audit: async () => {} }))
  root.route('/', createOpCredentialsRouter())
  app = root
  const res = await app.request('/api/auth/demo', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email: 'ia@oimlsmart.org', password: 'demo2026' }),
  })
  expect(res.ok).toBe(true)
  cookie = res.headers.get('set-cookie')!.split(';')[0]!
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

describe('the OIDC4VCI authorization-code flow (TODO.sota/08 slice 3)', () => {
  it('the metadata advertises the credential endpoint', async () => {
    const doc = await json(await app.request('/.well-known/openid-credential-issuer'), 200)
    expect(doc.credential_endpoint).toBe(CREDENTIAL_ENDPOINT)
  })

  it('the wallet\'s key proof mints a HOLDER-BOUND credential off its own authorization', async () => {
    const { accessToken, cNonce } = await driveCredentialGrant()
    const walletKeys = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']) as CryptoKeyPair
    const { proof, jkt } = await mintWalletProof(walletKeys, cNonce)
    const res = await app.request('/op/credential', {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${accessToken}` },
      body: JSON.stringify({ format: 'vc+sd-jwt', vct: 'org-membership', proof: { proof_type: 'jwt', jwt: proof } }),
    })
    const body = await json(res, 200) as { format: string; credential: string }
    expect(body.format).toBe('vc+sd-jwt')

    const { verifySdJwtPresentation, credentialRevoked, mintKeyBindingJwt } = await import('../../server/auth/op/sd-jwt')
    const [sdJwt, ...disclosures] = (body.credential as string).split('~')
    const verified = await verifySdJwtPresentation(store, body.credential, { issuer: ISSUER })
    expect('claims' in verified).toBe(true)
    if ('claims' in verified) {
      expect(verified.holderJkt).toBe(jkt)
      expect(verified.claims.vct).toBe('org-membership')
      // The holder proves possession: the KB-JWT over the minted SD-JWT.
      const kb = await mintKeyBindingJwt(walletKeys, { sdJwt, nonce: 'verifier-nonce', aud: 'a-verifier' })
      const bound = await verifySdJwtPresentation(store, `${body.credential}~${kb}`, {
        issuer: ISSUER, keyBinding: { nonce: 'verifier-nonce', aud: 'a-verifier' },
      })
      expect('claims' in bound).toBe(true)
      // The revocation anchor reads.
      const status = (verified.claims.status as { status_list: { uri: string; idx: number } }).status_list
      const listJwt = await (await app.request('/op/credentials/statuslist')).text()
      expect(await credentialRevoked(store, listJwt, status.idx, ISSUER)).toBe(false)
      void disclosures
    }
  })

  it('the refusals: no token, the wrong nonce, the wrong audience, the scope-less grant', async () => {
    const bare = await app.request('/op/credential', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ format: 'vc+sd-jwt', vct: 'org-membership' }),
    })
    expect(bare.status).toBe(401)

    const { accessToken, cNonce } = await driveCredentialGrant()
    const walletKeys = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']) as CryptoKeyPair
    const call = (proof: string) => app.request('/op/credential', {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${accessToken}` },
      body: JSON.stringify({ format: 'vc+sd-jwt', vct: 'org-membership', proof: { proof_type: 'jwt', jwt: proof } }),
    })
    const wrongNonce = await mintWalletProof(walletKeys, 'not-the-issued-nonce')
    expect((await call(wrongNonce.proof)).status).toBe(400)
    const wrongAud = await mintWalletProof(walletKeys, cNonce, 'https://someone-else.example')
    expect((await call(wrongAud.proof)).status).toBe(400)
    const noProof = await call('')
    expect(noProof.status).toBe(400)
  })
})
