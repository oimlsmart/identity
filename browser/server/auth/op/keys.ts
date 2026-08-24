// ═══════════════════════════════════════════════════════════════════
// The OIDC Provider's signing keys (TODO.identity/01) — one ES256 pair
// per deployment, kid'd, with the rotation history in the database.
//
// The PRIVATE key rides the OP_SIGNING_KEY env/secret (JWK JSON:
// {"kty":"EC","crv":"P-256","x","y","d","kid"?}) — never the repo,
// never the database. Its PUBLIC half is registered into the oidc_keys
// table on first use, so the JWKS endpoint's answer survives isolates
// and a rotation never strands an in-flight ID token: JWKS serves every
// 'active' row (old keys retire by an admin act once the token lifetime
// has passed, never automatically mid-flight).
//
// OP_SIGNING_KEY UNSET: a development pair is generated per process with
// a LOUD warning. That is a development posture only — tokens invalidate
// at every restart, and sibling Worker isolates would sign with
// DIFFERENT keys (each isolate generates its own), so a deployment that
// serves real RPs declares the secret.
//
// WORKER-SAFE: WebCrypto only.
// ═══════════════════════════════════════════════════════════════════

import type { ServerStore } from '@oimlsmart/platform-server/store'

type EnvLike = Record<string, string | undefined>

/** The TS lib's JsonWebKey lacks the JWS header fields this module
 *  stamps (kid/alg/use) — widen it once, locally. */
type OpJwk = JsonWebKey & { kid?: string; alg?: string; use?: string }

export interface OpSigningKey {
  kid: string
  /** The WebCrypto private key (sign usage). */
  privateKey: CryptoKey
  /** The public half as a JWK (kid/alg/use stamped). */
  publicJwk: OpJwk
  /** Symmetric secret material for the OP's own HMAC duties
   *  (TODO.identity/08's upstream flow state): the DECLARED key's raw
   *  JWK JSON when OP_SIGNING_KEY is set; the generated dev key's
   *  private coordinate when it is not (per-process then — the dev
   *  posture's caveat, documented with the dev key). NEVER exposed
   *  outside the server. */
  secretMaterial: string
}

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

/** A stable kid for a key that declares none: the first 16 bytes of the
 *  SHA-256 over its coordinates, base64url'd. Exported for the rotation
 *  ceremony (scripts/op-key-rotate.ts derives the SAME kid, so the kid
 *  it announces is the one the OP will advertise). */
export async function kidFor(publicJwk: JsonWebKey): Promise<string> {
  const digest = await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(`${publicJwk.x}.${publicJwk.y}`),
  )
  return base64url(new Uint8Array(digest)).slice(0, 22)
}

function assertEcJwk(jwk: JsonWebKey): void {
  if (jwk.kty !== 'EC' || jwk.crv !== 'P-256' || typeof jwk.x !== 'string' || typeof jwk.y !== 'string') {
    throw new Error('OP_SIGNING_KEY must be an EC P-256 JWK (kty "EC", crv "P-256", x, y — and d for the private half)')
  }
}

let memoized: { raw: string | null; key: OpSigningKey } | null = null
let warned = false

/** The process/isolate's signing key: the declared secret, else the dev
 *  generation. Memoized per env value (the tests reset between cases). */
export async function resolveOpSigningKey(env: EnvLike): Promise<OpSigningKey> {
  const raw = env.OP_SIGNING_KEY?.trim() ?? null
  if (memoized && memoized.raw === raw) return memoized.key

  let key: OpSigningKey
  if (raw) {
    let jwk: JsonWebKey
    try {
      jwk = JSON.parse(raw) as JsonWebKey
      assertEcJwk(jwk)
      if (typeof jwk.d !== 'string') throw new Error('OP_SIGNING_KEY carries no private half (d)')
    } catch (err) {
      throw new Error(`the OP signing key is unreadable: ${(err as Error).message}`)
    }
    const privateKey = await crypto.subtle.importKey(
      'jwk',
      { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y, d: jwk.d },
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['sign'],
    )
    const publicJwk: OpJwk = { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y }
    const declaredKid = (jwk as OpJwk).kid
    const kid = typeof declaredKid === 'string' && declaredKid ? declaredKid : await kidFor(publicJwk)
    key = { kid, privateKey, publicJwk: { ...publicJwk, kid, alg: 'ES256', use: 'sig' }, secretMaterial: raw }
  } else {
    const pair = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign', 'verify'],
    )
    const exported = await crypto.subtle.exportKey('jwk', pair.publicKey)
    const publicJwk: OpJwk = { kty: 'EC', crv: 'P-256', x: exported.x, y: exported.y }
    const kid = await kidFor(publicJwk)
    const exportedPrivate = await crypto.subtle.exportKey('jwk', pair.privateKey)
    key = {
      kid,
      privateKey: pair.privateKey,
      publicJwk: { ...publicJwk, kid, alg: 'ES256', use: 'sig' },
      secretMaterial: `dev:${exportedPrivate.d ?? kid}`,
    }
    if (!warned) {
      warned = true
      console.warn(
        '[op] OP_SIGNING_KEY is not set — generated an EPHEMERAL development signing key '
        + `(kid ${kid}). ID tokens invalidate at every restart, and sibling Worker isolates sign `
        + 'with DIFFERENT keys. Declare OP_SIGNING_KEY (a JWK JSON EC P-256 private key, a Worker '
        + 'secret in production) for a stable identity — docs/deployment/identity.md.',
      )
    }
  }
  memoized = { raw, key }
  return key
}

/** Test seam: drop the memo (and the warning latch) between cases. */
export function resetOpSigningKeyForTest(): void {
  memoized = null
  warned = false
}

/** Register the key's public half in the rotation history (idempotent). */
export async function ensureOpKeyRegistered(store: ServerStore, key: OpSigningKey): Promise<void> {
  await store.upsertOidcKey({ kid: key.kid, publicJwk: JSON.stringify(key.publicJwk) })
}

/** The JWKS document: every ACTIVE row of the rotation history. */
export async function opJwks(store: ServerStore): Promise<{ keys: JsonWebKey[] }> {
  const rows = await store.listOidcKeys()
  const keys = rows
    .filter(r => r.status === 'active')
    .map(r => JSON.parse(r.publicJwk) as JsonWebKey)
  return { keys }
}

/** Sign an ID token (ES256; WebCrypto emits the raw P1363 signature JWS
 *  wants). */
export async function signOpIdToken(key: OpSigningKey, claims: Record<string, unknown>): Promise<string> {
  const header = base64url(new TextEncoder().encode(JSON.stringify({ alg: 'ES256', typ: 'JWT', kid: key.kid })))
  const payload = base64url(new TextEncoder().encode(JSON.stringify(claims)))
  const signature = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    key.privateKey,
    new TextEncoder().encode(`${header}.${payload}`),
  )
  return `${header}.${payload}.${base64url(new Uint8Array(signature))}`
}

/** PKCE S256: base64url(SHA-256(verifier)) — compared against the
 *  authorize-time challenge. */
export async function pkceS256(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))
  return base64url(new Uint8Array(digest))
}

/** A one-time random value (codes, access tokens — 32 random bytes). */
export function opRandomToken(): string {
  return base64url(crypto.getRandomValues(new Uint8Array(32)))
}
