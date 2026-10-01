// ═══════════════════════════════════════════════════════════════════
// The identity SDK's posture layer (TODO.modern/07). Everything
// beneath ./gen is GENERATED from the drift-gated OpenAPI spec
// (scripts/generate-sdk.ts) — never hand-edited; this file is the
// only hand-written surface, and it is deliberately thin:
//
//   • the generated operations, re-exported (typed, spec-current);
//   • the PAT exchange helper — the machine posture: one call mints
//     a short-lived, scope-narrowed bearer (the exchange re-judges
//     the PAT's scopes against live standing);
//   • createBearerClient — rides that token on every call;
//   • the session posture needs NO helper: same-origin browser calls
//     carry the oiml-session cookie automatically (fetch's
//     same-origin default credentials).
// ═══════════════════════════════════════════════════════════════════

import { createClient, createConfig, type Client } from './gen/client'

export * from './gen/types.gen'
export * from './gen/sdk.gen'

/** A client for the official service (or a self-hosted instance —
 *  pass its issuer origin as baseUrl). */
export function createIdentityClient(opts: { baseUrl?: string } = {}): Client {
  return createClient(createConfig({ baseUrl: opts.baseUrl ?? 'https://id.oimlsmart.org' }))
}

/** The RFC 8693 exchange: a personal access token in, a short-lived
 *  scope-narrowed OP JWT out (verify it against the instance's JWKS). */
export async function patAccessToken(input: {
  baseUrl: string
  pat: string
  scope?: string
  fetchImpl?: typeof fetch
}): Promise<{ accessToken: string; tokenType: string; expiresInSeconds: number }> {
  const doFetch = input.fetchImpl ?? fetch
  const body = new URLSearchParams({
    grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
    subject_token_type: 'urn:oimlsmart:params:oauth:token-type:pat',
    subject_token: input.pat,
  })
  if (input.scope) body.set('scope', input.scope)
  const res = await doFetch(`${input.baseUrl}/op/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  })
  if (!res.ok) throw new Error(`the PAT exchange was refused (${res.status})`)
  const answer = await res.json() as { access_token: string; token_type: string; expires_in: number }
  return { accessToken: answer.access_token, tokenType: answer.token_type, expiresInSeconds: answer.expires_in }
}

/** The bearer posture: the exchanged token rides every call. */
export function createBearerClient(input: { baseUrl: string; accessToken: string }): Client {
  const client = createIdentityClient(input)
  client.interceptors.request.use((request) => {
    request.headers.set('authorization', `Bearer ${input.accessToken}`)
    return request
  })
  return client
}

// ═══════════════════════════════════════════════════════════════════
// The DPoP posture (RFC 9449, TODO.sota/08-arc): the holder side of
// the sender-constrained tokens — WebCrypto only, zero new
// dependencies. DpopKeys is the client's key pair (generate once —
// the binding IS the key); mintDpopProof builds the compact ES256 JWS
// (the public jwk in the header, htm/htu/iat/jti, the ath binding);
// DpopSession runs the token exchange (the proof rides it; a DPoP-
// bound answer stores) and the authenticated calls (the DPoP scheme +
// the ath proof) with the §8 nonce dance — a use_dpop_nonce challenge
// is answered by ONE retry carrying the issued DPoP-Nonce value.
// ═══════════════════════════════════════════════════════════════════

function b64url(bytes: Uint8Array): string {
  let bin = ''
  for (const b of bytes) bin += String.fromCharCode(b)
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

export interface DpopKeys {
  privateKey: CryptoKey
  publicJwk: { kty: string; crv: string; x: string; y: string }
  jkt: string
}

/** The client's DPoP key pair: a fresh EC P-256 pair (the house
 *  algorithm), the JKT derived from the RFC 7638 members. */
export async function generateDpopKeys(): Promise<DpopKeys> {
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']) as CryptoKeyPair
  const jwk = await crypto.subtle.exportKey('jwk', pair.publicKey) as { kty: string; crv: string; x: string; y: string }
  const publicJwk = { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y }
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(JSON.stringify(publicJwk)))
  return { privateKey: pair.privateKey, publicJwk, jkt: b64url(new Uint8Array(digest)) }
}

/** The proof JWT: header { typ: dpop+jwt, alg: ES256, jwk }, payload
 *  { htm, htu, iat, jti, ath?, nonce? }. */
export async function mintDpopProof(
  keys: DpopKeys,
  method: string,
  url: string,
  opts: { accessToken?: string; nonce?: string; iat?: number } = {},
): Promise<string> {
  const header = { typ: 'dpop+jwt', alg: 'ES256', jwk: keys.publicJwk }
  const payload: Record<string, unknown> = {
    htm: method.toUpperCase(),
    htu: url,
    iat: opts.iat ?? Math.floor(Date.now() / 1000),
    jti: crypto.randomUUID(),
  }
  if (opts.accessToken !== undefined) {
    payload.ath = b64url(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(opts.accessToken))))
  }
  if (opts.nonce !== undefined) payload.nonce = opts.nonce
  const encoder = new TextEncoder()
  const unsigned = `${b64url(encoder.encode(JSON.stringify(header)))}.${b64url(encoder.encode(JSON.stringify(payload)))}`
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, keys.privateKey, encoder.encode(unsigned))
  return `${unsigned}.${b64url(new Uint8Array(sig))}`
}

/** The DPoP session over any fetch (the SDK's own posture): the token
 *  exchange, the authenticated calls, the nonce dance. */
export class DpopSession {
  accessToken: string | null = null
  tokenType: string | null = null
  private nonce: string | null = null

  constructor(readonly baseUrl: string, readonly keys: DpopKeys, private fetchImpl: typeof fetch = fetch) {
  }

  private async headers(method: string, url: string, accessToken?: string): Promise<Record<string, string>> {
    const headers: Record<string, string> = { DPoP: await mintDpopProof(this.keys, method, url, { accessToken, nonce: this.nonce ?? undefined }) }
    if (accessToken !== undefined) headers.authorization = `DPoP ${accessToken}`
    return headers
  }

  private static challenged(res: Response): boolean {
    return res.status === 400 || res.status === 401
  }

  private async absorbNonce(res: Response): Promise<void> {
    const issued = res.headers.get('DPoP-Nonce')
    if (issued) this.nonce = issued
  }

  /** The token exchange: the proof rides the request; a DPoP-bound
   *  answer stores for the authenticated calls. */
  async tokenExchange(form: Record<string, string>): Promise<Record<string, unknown>> {
    const url = `${this.baseUrl}/op/token`
    const res = await this.fetchImpl(url, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', ...(await this.headers('POST', url)) },
      body: new URLSearchParams(form).toString(),
    })
    if (DpopSession.challenged(res)) {
      await this.absorbNonce(res)
      return this.tokenExchange(form)
    }
    if (!res.ok) throw new Error(`the token exchange was refused (${res.status})`)
    const body = await res.json() as { token_type?: string; access_token?: string }
    if (String(body.token_type ?? '').toLowerCase() === 'dpop' && body.access_token) {
      this.accessToken = body.access_token
      this.tokenType = 'DPoP'
    }
    return body as Record<string, unknown>
  }

  /** An authenticated call with the stored bound token. */
  async request(method: 'GET' | 'POST' | 'PUT' | 'DELETE', path: string): Promise<unknown> {
    if (!this.accessToken) throw new Error('no DPoP-bound token — call tokenExchange() first')
    const url = path.startsWith('http') ? path : `${this.baseUrl}${path}`
    let res = await this.fetchImpl(url, {
      method,
      headers: await this.headers(method, url, this.accessToken),
    })
    if (DpopSession.challenged(res)) {
      await this.absorbNonce(res)
      res = await this.fetchImpl(url, { method, headers: await this.headers(method, url, this.accessToken) })
    }
    if (!res.ok) throw new Error(`the DPoP call was refused (${res.status})`)
    return res.json()
  }
}
