// ═══════════════════════════════════════════════════════════════════
// The OIDC Provider's configuration (TODO.identity/01) — ONE resolution
// the routes and the tests share, from the same env seam the RP side
// uses (hono/adapter reads process.env on node, the Worker bindings on
// Cloudflare):
//
//   OP_ISSUER             the issuer URL the OP answers as (the
//                         discovery document's `issuer`, the ID tokens'
//                         `iss`). UNSET: the request's origin — the dev
//                         posture; a deployment always declares it
//                         (https://id.oimlsmart.org).
//   OP_CODE_TTL_MS        the one-time authorization code's lifetime
//                         (default 5 minutes).
//   OP_AUTHZ_TTL_MS       the pending-consent row's lifetime (default
//                         10 minutes — the sign-in + consent round trip).
//   OP_ACCESS_TOKEN_TTL_MS / OP_ID_TOKEN_TTL_SEC
//                         the issued tokens' lifetimes (default 1 hour).
//   OP_SIGNING_KEY        the ES256 private key as JWK JSON (a Worker
//                         secret / the node's environment). UNSET: a
//                         development key is generated per process with
//                         a LOUD warning (keys.ts) — tokens invalidate
//                         at restart and across isolates, never a
//                         production posture. The generated key's
//                         self-registration into oidc_keys is gated on
//                         the dev posture (issuerFromRequest below;
//                         routes/op.ts's maySelfRegisterOpKey,
//                         identity#7): a declared-issuer deployment
//                         never registers it.
//   OP_CLIENT_SEED        the client registry's bootstrap: a JSON array
//                         of { client_id, name, secret?, redirect_uris,
//                         claims_policy? } upserted at boot (registry.ts);
//                         the MACHINE classes (the machine cone,
//                         auth/op/device-clients.ts + service-clients.ts)
//                         seed as { client_id, name, class: "device",
//                         secret, device: { id, org, instrument_model } }
//                         or { client_id, name, class: "service", secret,
//                         service: { id, org, audience, scopes } }.
//                         Admin-managed afterwards (03 fleshes the UI
//                         out); a Worker secret when it carries secrets.
//
// WORKER-SAFE: no node built-ins.
// ═══════════════════════════════════════════════════════════════════

type EnvLike = Record<string, string | undefined>

export interface OpConfig {
  /** The issuer URL (no trailing slash). */
  issuer: string
  /** TRUE when the issuer came from the request origin (the dev
   *  fallback), not a declaration. */
  issuerFromRequest: boolean
  codeTtlMs: number
  authorizationTtlMs: number
  accessTokenTtlMs: number
  idTokenTtlSec: number
}

function intFrom(env: EnvLike, name: string, fallback: number): number {
  const raw = env[name]?.trim()
  if (!raw) return fallback
  const n = Number(raw)
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : fallback
}

/** The origin the request arrived on (the dev proxy forwards the astro
 *  host) — the same derivation the federation descriptor uses. */
export function opRequestOrigin(request: Request): string {
  const url = new URL(request.url)
  const host = request.headers.get('x-forwarded-host') ?? url.host
  const proto = request.headers.get('x-forwarded-proto') ?? url.protocol.replace(':', '')
  return `${proto}://${host}`
}

/** Resolve the effective OP config. Pure. */
export function resolveOpConfig(env: EnvLike, requestOrigin: string): OpConfig {
  const declared = env.OP_ISSUER?.trim().replace(/\/+$/, '')
  return {
    issuer: declared || requestOrigin,
    issuerFromRequest: !declared,
    codeTtlMs: intFrom(env, 'OP_CODE_TTL_MS', 5 * 60 * 1000),
    authorizationTtlMs: intFrom(env, 'OP_AUTHZ_TTL_MS', 10 * 60 * 1000),
    accessTokenTtlMs: intFrom(env, 'OP_ACCESS_TOKEN_TTL_MS', 60 * 60 * 1000),
    idTokenTtlSec: intFrom(env, 'OP_ID_TOKEN_TTL_SEC', 60 * 60),
  }
}
