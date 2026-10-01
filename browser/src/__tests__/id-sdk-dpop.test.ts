// ─────────────────────────────────────────────────────────────────────
// The TS SDK's DPoP posture (RFC 9449, TODO.sota/08-arc): the proofs
// are REAL (a real WebCrypto key signs; the scripted transport asserts
// the spec's legs — the header typ, the embedded public jwk, the
// signature over its own key, htm/htu/iat/jti, the ath binding, and
// the §8 nonce dance), the answers are the OP's wire shapes.
// ─────────────────────────────────────────────────────────────────────
import { describe, expect, it } from 'vitest'
import { DpopSession, generateDpopKeys, mintDpopProof } from '../../sdk/identity-client'

const ISSUER = 'https://op.test'
const TOKEN_URL = `${ISSUER}/op/token`
const USERINFO_URL = `${ISSUER}/op/userinfo`

function decodeJwt(jwt: string): { header: Record<string, unknown>; payload: Record<string, unknown>; signature: string } {
  const [h, p, s] = jwt.split('.')
  const dec = (v: string) => JSON.parse(atob(v.replace(/-/g, '+').replace(/_/g, '/'))) as Record<string, unknown>
  return { header: dec(h!), payload: dec(p!), signature: s! }
}

describe('the TS SDK\'s DPoP posture (sdk/identity-client.ts)', () => {
  it('a real WebCrypto key produces a verifiable proof (the signature over its own embedded jwk)', async () => {
    const keys = await generateDpopKeys()
    const proof = await mintDpopProof(keys, 'POST', TOKEN_URL, { iat: 1700000000 })
    const { header, payload, signature } = decodeJwt(proof)
    expect(header.typ).toBe('dpop+jwt')
    expect(header.alg).toBe('ES256')
    expect(header.jwk).toMatchObject({ kty: 'EC', crv: 'P-256' })
    expect(payload.htm).toBe('POST')
    expect(payload.htu).toBe(TOKEN_URL)
    expect(payload.iat).toBe(1700000000)
    expect(payload.jti).toBeTruthy()
    const jwk = header.jwk as { x: string; y: string }
    const key = await crypto.subtle.importKey('jwk', { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y }, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify'])
    const [h, p] = proof.split('.')
    const bin = atob(signature.replace(/-/g, '+').replace(/_/g, '/'))
    const sig = new Uint8Array(new ArrayBuffer(bin.length))
    for (let i = 0; i < bin.length; i++) sig[i] = bin.charCodeAt(i)
    await expect(crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, sig, new TextEncoder().encode(`${h}.${p}`))).resolves.toBe(true)
  })

  it('the full session: the challenge-and-retry exchange, the DPoP scheme, the ath binding', async () => {
    const seen: Array<Record<string, unknown>> = []
    const issuedNonce = 'the-issued-nonce'
    const boundToken = 'the-dpop-bound-token'
    const expectedAth = b64url(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(boundToken))))
    const fetchImpl: typeof fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input)
      const proof = decodeJwt(new Headers(init?.headers).get('DPoP')!)
      seen.push(proof.payload)
      if (url === TOKEN_URL) {
        if (!('nonce' in proof.payload)) {
          return new Response(JSON.stringify({ error: 'use_dpop_nonce' }), { status: 400, headers: { 'DPoP-Nonce': issuedNonce } })
        }
        expect(proof.payload.nonce).toBe(issuedNonce)
        return new Response(JSON.stringify({ access_token: boundToken, token_type: 'DPoP' }), { status: 200 })
      }
      const auth = new Headers(init?.headers).get('authorization')!
      expect(auth.startsWith('DPoP ')).toBe(true)
      expect(proof.payload.ath).toBe(expectedAth)
      expect(proof.payload.nonce).toBe(issuedNonce)
      return new Response(JSON.stringify({ sub: 'the-account' }), { status: 200 })
    }) as typeof fetch

    const session = new DpopSession(ISSUER, await generateDpopKeys(), fetchImpl)
    const body = await session.tokenExchange({ grant_type: 'authorization_code', code: 'c' }) as { token_type: string }
    expect(body.token_type).toBe('DPoP')
    expect(session.accessToken).toBe(boundToken)
    expect(seen.length).toBe(2) // the challenge is answered by ONE retry
    await expect(session.request('GET', '/op/userinfo')).resolves.toMatchObject({ sub: 'the-account' })
  })
})

function b64url(bytes: Uint8Array): string {
  let bin = ''
  for (const b of bytes) bin += String.fromCharCode(b)
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}
