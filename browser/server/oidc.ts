// ═══════════════════════════════════════════════════════════════════
// The OIDC client (TODO.federation/10) — relying-party half of the
// Authorization Code + PKCE flow, hand-rolled on WebCrypto + fetch.
//
// NO LIBRARY DEPENDENCY, deliberately: every runtime this server runs
// on (node ≥ 18 via @hono/node-server, Cloudflare Workers) ships
// WebCrypto and fetch, and the platform already hand-rolls its GitHub
// OAuth flow the same way (routes/auth.ts). A general OIDC library
// (openid-client et al.) would add a node-centric dependency tree for
// ~300 lines of standard-conformant HTTP+JWT work we can test directly.
//
// What this module implements (OIDC Core 1.0):
//   - issuer discovery (GET <issuer>/.well-known/openid-configuration,
//     RFC 8414 location; the metadata's issuer MUST match exactly);
//   - the authorization-request URL with PKCE (S256) + state + nonce;
//   - the code exchange at the token endpoint (client_secret_basic when
//     a secret is configured, public-client body auth otherwise);
//   - ID-token validation: signature against the IdP's JWKS (RS256 and
//     ES256), iss, aud (+ azp when multiple audiences), exp (60 s
//     leeway), and the nonce we issued;
//   - RP-initiated logout URL (OIDC RP-Initiated Logout 1.0) when the
//     metadata declares end_session_endpoint.
//
// Failures raise OidcError with a machine `reason` — routes/auth.ts
// maps reasons to the plain-language sign-in error page, never a stack
// trace.
//
// WORKER-SAFE: WebCrypto + fetch only, no node built-ins.
// ═══════════════════════════════════════════════════════════════════

// ── failure surface ─────────────────────────────────────────────────

export type OidcFailureReason =
  | 'discovery'        // the issuer's metadata could not be fetched/parsed
  | 'issuer_mismatch'  // metadata.issuer ≠ the configured issuer
  | 'exchange'         // the token endpoint refused the code exchange
  | 'token_malformed'  // the ID token is not a JWT we can parse
  | 'token_alg'        // the ID token uses an algorithm we do not verify
  | 'token_signature'  // signature verification failed / no matching key
  | 'token_issuer'     // iss ≠ the configured issuer
  | 'token_audience'   // aud/azp does not name our client
  | 'token_expired'    // exp is in the past (60 s leeway allowed)
  | 'token_nonce'      // nonce ≠ the one we issued (replay guard)

export class OidcError extends Error {
  constructor(
    readonly reason: OidcFailureReason,
    message: string,
  ) {
    super(message)
    this.name = 'OidcError'
  }
}

// ── discovery ───────────────────────────────────────────────────────

export interface OidcMetadata {
  issuer: string
  authorization_endpoint: string
  token_endpoint: string
  jwks_uri: string
  /** RP-initiated logout — ABSENT when the IdP does not support it. */
  end_session_endpoint?: string
  userinfo_endpoint?: string
}

interface CachedMetadata { metadata: OidcMetadata; fetchedAt: number }
const metadataCache = new Map<string, CachedMetadata>()
const METADATA_TTL_MS = 60 * 60 * 1000

/** Discover (and cache) the issuer's metadata. The metadata's issuer
 *  MUST equal the configured issuer string exactly (mix-up guard). */
export async function discoverIssuer(issuer: string, fetchImpl: typeof fetch = fetch): Promise<OidcMetadata> {
  const cached = metadataCache.get(issuer)
  if (cached && Date.now() - cached.fetchedAt < METADATA_TTL_MS) return cached.metadata

  const wellKnown = `${issuer.replace(/\/$/, '')}/.well-known/openid-configuration`
  let body: unknown
  try {
    const res = await fetchImpl(wellKnown)
    if (!res.ok) throw new Error(`HTTP ${res.status}`)
    body = await res.json()
  } catch (err) {
    throw new OidcError('discovery', `could not fetch ${wellKnown}: ${(err as Error).message}`)
  }
  const meta = body as Partial<OidcMetadata>
  if (typeof meta?.issuer !== 'string' || typeof meta?.authorization_endpoint !== 'string'
    || typeof meta?.token_endpoint !== 'string' || typeof meta?.jwks_uri !== 'string') {
    throw new OidcError('discovery', `the metadata at ${wellKnown} is incomplete (issuer/authorization_endpoint/token_endpoint/jwks_uri required)`)
  }
  if (meta.issuer.replace(/\/$/, '') !== issuer.replace(/\/$/, '')) {
    throw new OidcError('issuer_mismatch', `the metadata declares issuer ${meta.issuer}, not ${issuer}`)
  }
  const metadata: OidcMetadata = {
    issuer: meta.issuer,
    authorization_endpoint: meta.authorization_endpoint,
    token_endpoint: meta.token_endpoint,
    jwks_uri: meta.jwks_uri,
    ...(typeof meta.end_session_endpoint === 'string' ? { end_session_endpoint: meta.end_session_endpoint } : {}),
    ...(typeof meta.userinfo_endpoint === 'string' ? { userinfo_endpoint: meta.userinfo_endpoint } : {}),
  }
  metadataCache.set(issuer, { metadata, fetchedAt: Date.now() })
  return metadata
}

/** Test hook: drop the cached metadata + JWKS (the e2e stub rotates). */
export function clearOidcCaches(): void {
  metadataCache.clear()
  jwksCache.clear()
}

// ── PKCE + one-time values ──────────────────────────────────────────

function base64url(bytes: Uint8Array): string {
  let bin = ''
  for (const b of bytes) bin += String.fromCharCode(b)
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

function base64urlDecode(s: string): Uint8Array {
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice(0, (4 - (s.length % 4)) % 4)
  const bin = atob(b64)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

/** A one-time random value (state / nonce / PKCE verifier alphabet). */
export function randomToken(): string {
  return base64url(crypto.getRandomValues(new Uint8Array(24)))
}

export interface PkcePair { verifier: string; challenge: string }

/** PKCE (RFC 7636), S256 only — plain is never offered. */
export async function generatePkce(): Promise<PkcePair> {
  const verifier = base64url(crypto.getRandomValues(new Uint8Array(32)))
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))
  return { verifier, challenge: base64url(new Uint8Array(digest)) }
}

// ── the authorization request ───────────────────────────────────────

export function buildAuthorizationUrl(
  metadata: OidcMetadata,
  params: {
    clientId: string
    redirectUri: string
    scopes: string
    state: string
    nonce: string
    codeChallenge: string
  },
): string {
  const url = new URL(metadata.authorization_endpoint)
  url.searchParams.set('response_type', 'code')
  url.searchParams.set('client_id', params.clientId)
  url.searchParams.set('redirect_uri', params.redirectUri)
  url.searchParams.set('scope', params.scopes)
  url.searchParams.set('state', params.state)
  url.searchParams.set('nonce', params.nonce)
  url.searchParams.set('code_challenge', params.codeChallenge)
  url.searchParams.set('code_challenge_method', 'S256')
  return url.toString()
}

// ── the code exchange ───────────────────────────────────────────────

export interface OidcTokenResponse {
  id_token: string
  access_token?: string
  token_type?: string
  expires_in?: number
}

export async function exchangeCode(
  metadata: OidcMetadata,
  params: {
    clientId: string
    clientSecret?: string
    code: string
    redirectUri: string
    codeVerifier: string
  },
  fetchImpl: typeof fetch = fetch,
): Promise<OidcTokenResponse> {
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code: params.code,
    redirect_uri: params.redirectUri,
    client_id: params.clientId,
    code_verifier: params.codeVerifier,
  })
  const headers: Record<string, string> = { 'content-type': 'application/x-www-form-urlencoded' }
  if (params.clientSecret) {
    headers.authorization = `Basic ${btoa(`${encodeURIComponent(params.clientId)}:${encodeURIComponent(params.clientSecret)}`)}`
  }
  let json: unknown
  try {
    const res = await fetchImpl(metadata.token_endpoint, { method: 'POST', headers, body })
    json = await res.json()
    if (!res.ok) {
      const err = (json as { error?: string; error_description?: string }) ?? {}
      throw new Error(`HTTP ${res.status} ${err.error ?? ''} ${err.error_description ?? ''}`.trim())
    }
  } catch (err) {
    throw new OidcError('exchange', `the token endpoint refused the exchange: ${(err as Error).message}`)
  }
  const token = json as Partial<OidcTokenResponse>
  if (typeof token?.id_token !== 'string') {
    throw new OidcError('exchange', 'the token response carries no id_token — this flow requires the openid scope')
  }
  return token as OidcTokenResponse
}

// ── ID-token validation ─────────────────────────────────────────────

interface Jwk {
  kty: string
  kid?: string
  alg?: string
  use?: string
  n?: string
  e?: string
  x?: string
  y?: string
  crv?: string
}

interface CachedJwks { keys: Jwk[]; fetchedAt: number }
const jwksCache = new Map<string, CachedJwks>()
const JWKS_TTL_MS = 60 * 60 * 1000

async function fetchJwks(jwksUri: string, fetchImpl: typeof fetch, force: boolean): Promise<Jwk[]> {
  const cached = jwksCache.get(jwksUri)
  if (!force && cached && Date.now() - cached.fetchedAt < JWKS_TTL_MS) return cached.keys
  let body: unknown
  try {
    const res = await fetchImpl(jwksUri)
    if (!res.ok) throw new Error(`HTTP ${res.status}`)
    body = await res.json()
  } catch (err) {
    throw new OidcError('token_signature', `could not fetch the signing keys (${jwksUri}): ${(err as Error).message}`)
  }
  const keys = (body as { keys?: Jwk[] })?.keys
  if (!Array.isArray(keys)) {
    throw new OidcError('token_signature', `the JWKS at ${jwksUri} carries no keys array`)
  }
  jwksCache.set(jwksUri, { keys, fetchedAt: Date.now() })
  return keys
}

export interface OidcIdTokenClaims {
  iss: string
  sub: string
  aud: string | string[]
  exp: number
  iat?: number
  nonce?: string
  azp?: string
  email?: string
  email_verified?: boolean
  name?: string
  [claim: string]: unknown
}

const EXPIRY_LEEWAY_MS = 60_000

/**
 * Validate the ID token: signature against the IdP's JWKS, then the
 * iss / aud / exp / nonce claims. Returns the claims on success, throws
 * OidcError (a plain `reason`, never the raw crypto failure) otherwise.
 */
export async function validateIdToken(
  idToken: string,
  expectations: { issuer: string; clientId: string; nonce: string; jwksUri: string },
  fetchImpl: typeof fetch = fetch,
): Promise<OidcIdTokenClaims> {
  const parts = idToken.split('.')
  if (parts.length !== 3) {
    throw new OidcError('token_malformed', 'the ID token is not a three-part JWT')
  }
  let header: { alg?: string; kid?: string }
  let claims: OidcIdTokenClaims
  try {
    header = JSON.parse(new TextDecoder().decode(base64urlDecode(parts[0]!)))
    claims = JSON.parse(new TextDecoder().decode(base64urlDecode(parts[1]!))) as OidcIdTokenClaims
  } catch {
    throw new OidcError('token_malformed', 'the ID token header/claims are not JSON')
  }
  if (header.alg !== 'RS256' && header.alg !== 'ES256') {
    throw new OidcError('token_alg', `the ID token uses ${header.alg ?? 'no declared algorithm'} — only RS256 and ES256 are verified`)
  }

  // Signature: pick the JWKS key by kid (and algorithm family); a first
  // miss refetches once (key rotation), then fails honestly.
  const signedContent = new TextEncoder().encode(`${parts[0]}.${parts[1]}`)
  const signature = base64urlDecode(parts[2]!)
  let verified = false
  for (const force of [false, true]) {
    const keys = await fetchJwks(expectations.jwksUri, fetchImpl, force)
    const candidates = keys.filter(k =>
      (!header.kid || k.kid === header.kid)
      && (header.alg === 'RS256' ? k.kty === 'RSA' : k.kty === 'EC'),
    )
    for (const jwk of candidates) {
      try {
        const key = await crypto.subtle.importKey(
          'jwk',
          jwk as JsonWebKey,
          header.alg === 'RS256'
            ? { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }
            : { name: 'ECDSA', namedCurve: 'P-256' },
          false,
          ['verify'],
        )
        verified = await crypto.subtle.verify(
          header.alg === 'RS256'
            ? { name: 'RSASSA-PKCS1-v1_5' }
            : { name: 'ECDSA', hash: 'SHA-256' },
          key,
          signature as BufferSource,
          signedContent,
        )
      } catch {
        verified = false // an unimportable key is a miss, never a pass
      }
      if (verified) break
    }
    if (verified) break
  }
  if (!verified) {
    throw new OidcError('token_signature', 'the ID token signature does not verify against the issuer’s published keys')
  }

  if (claims.iss?.replace(/\/$/, '') !== expectations.issuer.replace(/\/$/, '')) {
    throw new OidcError('token_issuer', `the ID token’s issuer (${claims.iss ?? 'none'}) is not the configured issuer`)
  }
  const audiences = Array.isArray(claims.aud) ? claims.aud : [claims.aud]
  if (!audiences.includes(expectations.clientId)) {
    throw new OidcError('token_audience', 'the ID token was not issued for this application (audience mismatch)')
  }
  if (audiences.length > 1 && claims.azp && claims.azp !== expectations.clientId) {
    throw new OidcError('token_audience', 'the ID token’s authorized party is not this application')
  }
  if (typeof claims.exp !== 'number' || claims.exp * 1000 + EXPIRY_LEEWAY_MS < Date.now()) {
    throw new OidcError('token_expired', 'the ID token has expired')
  }
  if (claims.nonce !== expectations.nonce) {
    throw new OidcError('token_nonce', 'the ID token’s nonce does not match the request (replay guard)')
  }
  return claims
}

// ── RP-initiated logout ─────────────────────────────────────────────

/** The IdP's end-session URL, or null when the metadata declares no
 *  end_session_endpoint (the local sign-out then stands alone). */
export function buildEndSessionUrl(
  metadata: OidcMetadata,
  params: { idTokenHint?: string | null; clientId: string; postLogoutRedirectUri: string },
): string | null {
  if (!metadata.end_session_endpoint) return null
  const url = new URL(metadata.end_session_endpoint)
  if (params.idTokenHint) url.searchParams.set('id_token_hint', params.idTokenHint)
  url.searchParams.set('client_id', params.clientId)
  url.searchParams.set('post_logout_redirect_uri', params.postLogoutRedirectUri)
  return url.toString()
}
