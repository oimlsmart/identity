// ═══════════════════════════════════════════════════════════════════
// TODO.identity-sso (the wave-A tail): the OP's LOGOUT cone — the
// RP-initiated end-session (OIDC RP-Initiated Logout 1.0) and the
// OP-initiated backchannel fan-out (OIDC Back-Channel Logout 1.0).
//
// The client row's logout surface rides the claims-policy JSON — the
// data-level extension doctrine (auth/op/device-clients.ts's shape, no
// migration): `logout: { post_logout_redirect_uris, backchannel_logout_uri }`.
// The machine classes never carry one (nothing signs in, nothing logs
// out — the class checks refuse the block at write).
//
// The two halves:
//   - the END-SESSION validation: the id_token_hint verifies against the
//     LOCAL registered keys (never an HTTP fetch — the OP validates its
//     own mint), the iss must be this issuer, and an EXPIRED token stays
//     a valid hint (the spec's explicit rule — logout happens after
//     expiry all the time). The post_logout_redirect_uri redirect fires
//     ONLY when the URI is registered on the resolved client's logout
//     block (the open-redirector guard) — anything else answers the
//     honest signed-out page;
//   - the BACKCHANNEL fan-out: on the session-ending acts the OP POSTs a
//     logout_token (iss/sub/aud/jti/iat/exp + the backchannel-logout
//     event, NO sid — no sid tracking exists today; the RP drops the
//     account's sessions wholesale, and the remembered-grant re-auth
//     softens a false positive) to every LIVE consent-grant client's
//     registered backchannel_logout_uri. Fire-and-forget: the act never
//     waits on an RP, a failure logs and never fails the act.
//
// WORKER-SAFE: WebCrypto + the store seam only, no node built-ins.
// ═══════════════════════════════════════════════════════════════════

import { getStore, type OidcClientClaimsPolicy } from '@oimlsmart/platform-server/store'
import { opRequestOrigin, resolveOpConfig } from './config'
import { opJwks, resolveOpSigningKey, signOpJwt, type OpSigningKey } from './keys'

/** The fire-and-forget's runtime seam, structural (hono's Context
 *  satisfies it): the Worker's execution context carries the promise
 *  past the response where the runtime provides one (the deployed
 *  posture); hono's executionCtx getter THROWS where the runtime
 *  provides none (the node dev/test stacks), so the guarded float
 *  stands there. A failure inside the promise is the sender's own log
 *  line — it never reaches the act. */
export interface OpFloatContext {
  executionCtx: { waitUntil(p: Promise<unknown>): void }
}

export function floatOp(c: OpFloatContext, p: Promise<unknown>): void {
  const guarded = p.catch(err => console.warn('[op] the background act failed:', (err as Error).message))
  try {
    c.executionCtx.waitUntil(guarded)
  } catch {
    void guarded
  }
}

type EnvLike = Record<string, string | undefined>

// ── the client row's logout block (the policy JSON's data-level
//    extension) ───────────────────────────────────────────────────────

/** The client-registered logout surface: the exact post-logout redirect
 *  URIs (the end-session redirect's allowlist) and the backchannel
 *  receiver (the fan-out's target). The receiver key is OPTIONAL on the
 *  wire (a seed/hand-edited row may omit it — the readers normalize the
 *  absence to null); the validated/stored shape always carries it. */
export interface OpLogoutBlock {
  post_logout_redirect_uris: string[]
  backchannel_logout_uri?: string | null
}

/** The identity-side widening of the kernel's claims-policy type: the
 *  logout block rides the same JSON (the store seam round-trips it
 *  opaquely). */
export interface OpLogoutPolicy extends OidcClientClaimsPolicy {
  logout?: OpLogoutBlock
}

function absoluteUri(value: unknown): string | null {
  if (typeof value !== 'string' || !value.trim()) return null
  try {
    const url = new URL(value.trim())
    return url.protocol === 'http:' || url.protocol === 'https:' ? url.toString() : null
  } catch {
    return null
  }
}

/** The stored policy's logout block, HONESTLY derived: a well-formed
 *  block stands, anything else reads as NO logout surface (null) — a
 *  hand-edited malformed row never becomes a half-shaped redirect
 *  allowlist. Pure. */
export function logoutBlockOf(policy: OidcClientClaimsPolicy | null): OpLogoutBlock | null {
  const block = (policy as OpLogoutPolicy | null)?.logout
  if (!block || typeof block !== 'object') return null
  const redirects = block.post_logout_redirect_uris
  if (!Array.isArray(redirects)) return null
  const uris: string[] = []
  for (const entry of redirects) {
    const uri = absoluteUri(entry)
    if (!uri) return null
    uris.push(uri)
  }
  const backchannel = block.backchannel_logout_uri
  if (backchannel === undefined || backchannel === null) {
    return { post_logout_redirect_uris: uris, backchannel_logout_uri: null }
  }
  const backchannelUri = absoluteUri(backchannel)
  if (!backchannelUri) return null
  return { post_logout_redirect_uris: uris, backchannel_logout_uri: backchannelUri }
}

/** The write-time validation of a declared logout block (the admin API's
 *  + the bootstrap seed's shared rule). Answers the normalized block, or
 *  the refusal's reason. */
export function validateLogoutBlock(input: unknown): { logout: OpLogoutBlock | null; error: string | null } {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    return { logout: null, error: 'logout must be an object: { post_logout_redirect_uris: [...], backchannel_logout_uri: "..." } — the client’s registered logout surface' }
  }
  const rec = input as Record<string, unknown>
  const redirects = rec.post_logout_redirect_uris ?? []
  if (!Array.isArray(redirects) || redirects.some(u => !absoluteUri(u))) {
    return { logout: null, error: 'logout.post_logout_redirect_uris must be a list of absolute http(s) URIs (the exact post-logout landing URIs — the end-session redirect never fires to an unregistered one)' }
  }
  const backchannel = rec.backchannel_logout_uri
  if (backchannel !== undefined && backchannel !== null && !absoluteUri(backchannel)) {
    return { logout: null, error: 'logout.backchannel_logout_uri must be an absolute http(s) URI (the RP’s backchannel receiver), or null' }
  }
  return {
    logout: {
      post_logout_redirect_uris: (redirects as unknown[]).map(u => absoluteUri(u)!),
      backchannel_logout_uri: backchannel == null ? null : absoluteUri(backchannel),
    },
    error: null,
  }
}

// ── the id_token_hint's OP-side validation ─────────────────────────────

function base64urlJson(part: string): unknown | null {
  try {
    const b64 = part.replace(/-/g, '+').replace(/_/g, '/')
    const bin = atob(b64)
    const bytes = Uint8Array.from(bin, ch => ch.charCodeAt(0))
    return JSON.parse(new TextDecoder().decode(bytes))
  } catch {
    return null
  }
}

/** The OP validates its OWN mint: the hint's signature against the LOCAL
 *  registered keyset (opJwks — never an HTTP fetch), the iss against this
 *  issuer. An EXPIRED token stays a valid hint (RP-Initiated Logout's
 *  explicit rule — the logout routinely lands past the token's life); the
 *  nonce is the flow's own and unchecked here. Answers the token's
 *  { sub, aud } (aud normalized to its single string — the OP mints
 *  single-audience ID tokens), or null on any mismatch — the caller then
 *  answers the honest signed-out page, never an error chase. */
export async function verifyOpIdTokenHint(
  keys: Array<JsonWebKey & { kid?: string }>,
  issuer: string,
  hint: string,
): Promise<{ sub: string; aud: string } | null> {
  const parts = hint.split('.')
  if (parts.length !== 3) return null
  const header = base64urlJson(parts[0]!) as { alg?: string; kid?: string } | null
  const claims = base64urlJson(parts[1]!) as { iss?: string; sub?: unknown; aud?: unknown } | null
  if (!header || !claims || header.alg !== 'ES256') return null
  const candidates = keys.filter(k => (!header.kid || k.kid === header.kid) && k.kty === 'EC')
  const signed = new TextEncoder().encode(`${parts[0]}.${parts[1]}`)
  const b64 = parts[2]!.replace(/-/g, '+').replace(/_/g, '/')
  let signature: Uint8Array
  try {
    signature = Uint8Array.from(atob(b64), ch => ch.charCodeAt(0))
  } catch {
    return null
  }
  let verified = false
  for (const jwk of candidates) {
    try {
      const key = await crypto.subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify'])
      verified = await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, signature as BufferSource, signed)
    } catch {
      verified = false // an unimportable key is a miss, never a pass
    }
    if (verified) break
  }
  if (!verified) return null
  if (typeof claims.iss !== 'string' || claims.iss.replace(/\/$/, '') !== issuer.replace(/\/$/, '')) return null
  if (typeof claims.sub !== 'string' || !claims.sub) return null
  const aud = Array.isArray(claims.aud) ? claims.aud[0] : claims.aud
  if (typeof aud !== 'string' || !aud) return null
  return { sub: claims.sub, aud }
}

// ── the ID token's auth_time (the prompt=login freshness proof) ───────

/** The session created_at's OIDC NumericDate (epoch seconds). The column
 *  stores EITHER the app-written ISO 8601 or the database default's
 *  "YYYY-MM-DD HH:MM:SS" (datetime('now'), UTC, NO offset marker — a
 *  bare Date.parse would read it as LOCAL time; the space→T+Z rewrite is
 *  the explicit UTC fix). Unparseable answers null — the claim stays
 *  absent, never a wrong instant. */
export function authTimeOf(createdAt: string | null | undefined): number | null {
  if (!createdAt) return null
  const normalized = createdAt.includes('T') ? createdAt : `${createdAt.replace(' ', 'T')}Z`
  const ms = Date.parse(normalized)
  return Number.isFinite(ms) ? Math.floor(ms / 1000) : null
}

// ── the backchannel fan-out (OP-initiated logout) ──────────────────────

/** The logout event's URI (Back-Channel Logout 1.0 §2.4). */
export const BACKCHANNEL_LOGOUT_EVENT = 'http://schemas.openid.net/event/backchannel-logout'

/** The logout_token's life: the RP consumes it on receipt — two minutes
 *  is generous (never a bearer artifact worth keeping). */
const LOGOUT_TOKEN_TTL_SEC = 120

/** The fan-out's target set: the account's LIVE consent grants (the
 *  store's list read answers live rows only), resolved to the clients
 *  that registered a backchannel receiver. Disabled clients and machine
 *  classes never appear (the former can't serve a session anyway; the
 *  latter never carry a logout block). The account itself stays out of
 *  the answer — the caller knows it. */
export async function collectBackchannelTargets(
  store: ReturnType<typeof getStore>,
  userId: string,
): Promise<Array<{ clientId: string; uri: string }>> {
  const grants = await store.listConsentGrants(userId)
  const seen = new Set<string>()
  const targets: Array<{ clientId: string; uri: string }> = []
  for (const grant of grants) {
    if (seen.has(grant.clientId)) continue
    seen.add(grant.clientId)
    const client = await store.getOidcClient(grant.clientId)
    if (!client || client.status !== 'active') continue
    const uri = logoutBlockOf(client.claimsPolicy)?.backchannel_logout_uri
    if (uri) targets.push({ clientId: grant.clientId, uri })
  }
  return targets
}

/** POST the logout_token to every target — the Back-Channel Logout §3
 *  form POST (logout_token=<jwt>). Each send is bounded (5 s — a slow RP
 *  never holds the fan-out open) and its own try/catch: one RP's failure
 *  never reaches the others, and the ACT that triggered the fan-out never
 *  sees any of it (the caller floats the returned promise). Answers the
 *  per-client outcomes for the callers that DO wait (the tests). */
export async function sendBackchannelLogout(
  targets: Array<{ clientId: string; uri: string }>,
  key: OpSigningKey,
  issuer: string,
  userId: string,
  fetchImpl: typeof fetch = fetch,
): Promise<Array<{ clientId: string; ok: boolean }>> {
  const nowSec = Math.floor(Date.now() / 1000)
  return Promise.all(targets.map(async (target) => {
    try {
      const token = await signOpJwt(key, {
        iss: issuer,
        sub: userId,
        aud: target.clientId,
        jti: crypto.randomUUID(),
        iat: nowSec,
        exp: nowSec + LOGOUT_TOKEN_TTL_SEC,
        events: { [BACKCHANNEL_LOGOUT_EVENT]: {} },
      })
      const controller = new AbortController()
      const timer = setTimeout(() => controller.abort(), 5_000)
      try {
        const res = await fetchImpl(target.uri, {
          method: 'POST',
          headers: { 'content-type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({ logout_token: token }).toString(),
          signal: controller.signal,
        })
        if (!res.ok) {
          console.warn(`[op] backchannel logout: ${target.clientId} answered HTTP ${res.status}`)
          return { clientId: target.clientId, ok: false }
        }
        return { clientId: target.clientId, ok: true }
      } finally {
        clearTimeout(timer)
      }
    } catch (err) {
      console.warn(`[op] backchannel logout: ${target.clientId} unreachable:`, (err as Error).message)
      return { clientId: target.clientId, ok: false }
    }
  }))
}

/** A session-ending act's backchannel leg, ONE shape for every trigger
 *  site (the console's sign-out + session revokes, the admin
 *  revocations, the deactivation + erasure sweeps, the RP-initiated
 *  end-session): prepare BEFORE the act — the target set is the one the
 *  ending presence belonged to, and a destructive act (the erasure's
 *  sweep) may take the grant rows with it — then call the returned
 *  closure AFTER (the answer never waits on an RP). The key resolves
 *  only when targets exist (an account with no live-grant receivers
 *  costs nothing). */
export async function prepareBackchannelLogout(
  c: OpFloatContext,
  env: EnvLike,
  request: Request,
  userId: string,
): Promise<() => void> {
  const targets = await collectBackchannelTargets(getStore(), userId)
  if (!targets.length) return () => {}
  const key = await resolveOpSigningKey(env)
  const { issuer } = resolveOpConfig(env, opRequestOrigin(request))
  return () => floatOp(c, sendBackchannelLogout(targets, key, issuer, userId))
}
