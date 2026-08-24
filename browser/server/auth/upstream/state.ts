// ═══════════════════════════════════════════════════════════════════
// The upstream flow state (TODO.identity/08) — the STATELESS, signed
// `state` parameter for the OP's upstream sign-in/link round trips,
// the GitHub flow's lesson applied (auth/github.ts): NOTHING rides a
// per-process Map, so a sibling Worker isolate verifies the callback
// exactly. The whole flow's context travels in the parameter:
//
//   state = base64url(json).<hmac>   where the hmac is HMAC-SHA256 over
//   the payload, keyed by the OP's own key material
//   (op/keys.ts's secretMaterial — the OP_SIGNING_KEY secret already
//   deployed; no new secret, no D1 round trip)
//
// The payload carries:
//   p   the identity_providers row id
//   m   'login' | 'link' (link binds the flow to the account `u`)
//   u   the linking account's user id (mode 'link' only)
//   n   the OIDC nonce (oidc kind; the ID token must repeat it)
//   v   the PKCE S256 verifier (oidc kind)
//   r   the post-sign-in redirect (a LOCAL path only — validated)
//   iat the issue time (the 10-minute TTL, ± skew — OAUTH_STATE_TTL_MS)
//
// The PKCE verifier in the parameter is the GitHub-state discipline
// extended: it transits the sign-in's OWN browser channel only (the
// authorize redirect and its return) — the code is useless without it,
// and a tampered payload never verifies.
//
// WORKER-SAFE: WebCrypto only.
// ═══════════════════════════════════════════════════════════════════

import { OAUTH_STATE_TTL_MS } from '@oimlsmart/platform-server/github'

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

async function hmacSha256(key: string, message: string): Promise<string> {
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(key),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  )
  const sig = await crypto.subtle.sign('HMAC', cryptoKey, new TextEncoder().encode(message))
  return base64url(new Uint8Array(sig))
}

/** Constant-time string equality (the github.ts discipline). */
function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i)
  return diff === 0
}

export interface UpstreamStatePayload {
  /** The identity_providers row id. */
  p: string
  /** 'login' (the sign-in) or 'link' (bind to the account u). */
  m: 'login' | 'link'
  /** The linking account (mode 'link'). */
  u?: string
  /** The OIDC nonce (kind 'oidc'). */
  n?: string
  /** The PKCE S256 verifier (kind 'oidc'). */
  v?: string
  /** The post-sign-in redirect — a LOCAL path only. */
  r?: string
  /** The issue time (ms epoch). */
  iat: number
}

/** A redirect target is safe only as a LOCAL path (never a URL — the
 *  open-redirect wall, the same discipline as /op/authorize's refusal). */
export function safeLocalRedirect(raw: string | undefined): string | undefined {
  if (!raw) return undefined
  if (!raw.startsWith('/') || raw.startsWith('//')) return undefined
  return raw
}

/** Mint the state parameter. `now` is injectable for the expiry tests. */
export async function signUpstreamState(
  secretMaterial: string,
  payload: Omit<UpstreamStatePayload, 'iat'>,
  now: number = Date.now(),
): Promise<string> {
  const body = base64url(new TextEncoder().encode(JSON.stringify({ ...payload, iat: now })))
  const sig = await hmacSha256(secretMaterial, body)
  return `${body}.${sig}`
}

/** Verify a presented state: well-formed, inside the TTL (± skew),
 *  carrying the payload's signature — all three, constant-time on the
 *  signature. Answers the payload on success, NULL otherwise. */
export async function verifyUpstreamState(
  secretMaterial: string,
  presented: string,
  opts?: { now?: number; ttlMs?: number },
): Promise<UpstreamStatePayload | null> {
  const parts = presented.split('.')
  if (parts.length !== 2) return null
  const [body, sig] = parts as [string, string]
  if (!body || !sig) return null
  const expected = await hmacSha256(secretMaterial, body)
  if (!timingSafeEqual(expected, sig)) return null

  let payload: UpstreamStatePayload
  try {
    payload = JSON.parse(new TextDecoder().decode(base64urlDecode(body))) as UpstreamStatePayload
  } catch {
    return null
  }
  if (typeof payload?.p !== 'string' || (payload.m !== 'login' && payload.m !== 'link') || typeof payload.iat !== 'number') {
    return null
  }
  const now = opts?.now ?? Date.now()
  const ttl = opts?.ttlMs ?? OAUTH_STATE_TTL_MS
  if (now - payload.iat > ttl) return null
  if (payload.iat - now > 60_000) return null // the clock-skew tolerance
  if (payload.m === 'link' && typeof payload.u !== 'string') return null
  if (payload.r !== undefined && safeLocalRedirect(payload.r) !== payload.r) return null
  return payload
}
