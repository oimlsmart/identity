// ═══════════════════════════════════════════════════════════════════
// The service class on the client registry (the machine cone's GENERAL
// half — TODO.identity-ops/07: the honest path for machine callers
// beyond the device class): a NON-HUMAN client registered PER SERVICE
// ACCOUNT — the agent pipelines and MCP servers the device class never
// covers (a device is bound to a twin's identity; a service account is
// bound to an AUDIENCE and a SCOPE allowlist).
//
// The seam is the device class's doctrine applied again: the class
// marker + the service block ride the client row's claims-policy JSON
// (the column round-trips opaquely through the store seam — a DATA-level
// extension: no kernel change, no migration). The device class's own
// semantics are UNTOUCHED (auth/op/device-clients.ts stands as it
// shipped).
//
// THE CLASS RULES (the registry enforces them at write; the token
// endpoint enforces them at issuance) — the device class's rules, with
// the two differences the general caller needs:
//
//   - a service client speaks client_credentials ONLY: no authorization-
//     code flow (there is no user to consent — /op/authorize refuses it
//     in place), no redirect_uris, no refresh (the OP never mints refresh
//     tokens; the caller re-authenticates), no launch card, and NO user
//     claims in the policy;
//   - a service client is CONFIDENTIAL: the secret is the service
//     account's credential. A public service client is refused at write;
//   - the class is FIXED AT REGISTRATION: an application never becomes a
//     service nor the reverse (a re-registration in the other class is
//     refused; register a fresh client);
//   - the service block binds the client to its identity: the service id
//     (the account name — the token's `sub`), its org (the identity
//     registry's org id — resolved at write, like the device class's),
//     the AUDIENCE the token is bound to (the called service's own
//     identifier — the token's `aud`; the device class pins aud to the
//     client id, the service class carries the declared audience), and
//     the SCOPE allowlist (the closed set the token's `scope` claim may
//     carry — least privilege at write, narrowed per request at mint).
//
// THE TOKEN (POST /op/token, grant_type=client_credentials, the service
// class only): a self-contained ES256 JWT access token on the OP's
// signing key (the called service validates it against the OP's JWKS —
// no call-back, no userinfo), carrying EXACTLY the service claims:
//
//   iss, sub = the service id, aud = the declared audience,
//   client_id = the client, iat, exp,
//   org = the service's org, scope = the effective scopes
//
// The request may narrow the scopes (the form's `scope` parameter,
// space-separated): every requested scope must be on the registered
// allowlist or the grant refuses (invalid_scope — never a silent drop,
// never a mint beyond the allowlist); an absent parameter carries the
// full allowlist. NEVER a user claim (no name/email/roles/groups/
// picture/amr — there is no account behind a service token), never an
// ID token, never a refresh token. The discovery document keeps
// advertising the RP contract alone (grant_types_supported stays
// authorization_code): the machine classes are estate-internal cones,
// not RP flows — the OIDC wire the relying parties pin (the contract
// gate's golden) is byte-identical.
//
// WORKER-SAFE: pure functions, no I/O, no node built-ins.
// ═══════════════════════════════════════════════════════════════════

import type { OidcClientClaimsPolicy } from '@oimlsmart/platform-server/store'

/** The class marker's value (claims_policy.class). ABSENT = the
 *  application class (the relying-party posture); 'device' = the device
 *  class (auth/op/device-clients.ts — untouched by this module). */
export const SERVICE_CLASS = 'service' as const

/** The service identity a service-class client binds (the claims the
 *  called service consumes). */
export interface ServiceClientClaims {
  /** The service id (the service account's name) — the token's `sub`. */
  id: string
  /** The service's organization (the identity registry's org id). */
  org: string
  /** The audience the token is bound to (the called service's own
   *  identifier — the token's `aud`; that service refuses a token
   *  naming any other audience). */
  audience: string
  /** The scope allowlist (the closed set the token's `scope` claim may
   *  carry). NON-EMPTY — a scope-less service token is a configuration
   *  bug (least privilege is the class's point). */
  scopes: string[]
}

/** The identity-side widening of the kernel's claims-policy type: the
 *  service class's marker + block ride the same JSON (the store seam
 *  round-trips it opaquely). */
export interface OpServicePolicy extends OidcClientClaimsPolicy {
  class?: typeof SERVICE_CLASS
  service?: ServiceClientClaims
}

/** The stored policy's service class, HONESTLY derived: the marker and a
 *  well-formed block both stand, or the client is NOT a service (null).
 *  A malformed block (a hand-edited row) reads as not-a-service — the
 *  token endpoint then refuses client_credentials with the class
 *  refusal, never a half-shaped service token. Pure. */
export function serviceClassOf(policy: OidcClientClaimsPolicy | null): ServiceClientClaims | null {
  const p = policy as OpServicePolicy | null
  if (p?.class !== SERVICE_CLASS || !p.service) return null
  const { id, org, audience, scopes } = p.service
  if (typeof id !== 'string' || !id || typeof org !== 'string' || !org || typeof audience !== 'string' || !audience) {
    return null
  }
  if (!Array.isArray(scopes) || scopes.length === 0 || scopes.some(s => typeof s !== 'string' || !s)) {
    return null
  }
  return { id, org, audience, scopes: [...scopes] }
}

/** The write-time validation of a declared service block (the admin
 *  API's + the bootstrap seed's shared rule). Answers the normalized
 *  block, or the refusal's reason. The org's EXISTENCE on the registry
 *  is the route's check (it owns the store read); here the shape. */
export function validateServiceBlock(input: unknown): { service: ServiceClientClaims | null; error: string | null } {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    return { service: null, error: 'service must be an object: { id, org, audience, scopes } — the service account this client binds' }
  }
  const rec = input as Record<string, unknown>
  const field = (name: 'id' | 'org' | 'audience'): string | null =>
    typeof rec[name] === 'string' && (rec[name] as string).trim() ? (rec[name] as string).trim() : null
  const id = field('id')
  if (!id) return { service: null, error: 'service.id is required (the service account’s name — the service token’s sub)' }
  const org = field('org')
  if (!org) return { service: null, error: 'service.org is required (the identity registry’s org id the service belongs to)' }
  const audience = field('audience')
  if (!audience) return { service: null, error: 'service.audience is required (the called service’s identifier — the token’s aud; that service refuses any other audience)' }
  const scopesIn = rec.scopes
  if (!Array.isArray(scopesIn) || scopesIn.some(s => typeof s !== 'string')) {
    return { service: null, error: 'service.scopes must be a list of scope strings (the allowlist the token’s scope claim may carry)' }
  }
  const scopes = [...new Set(scopesIn.map(s => s.trim()).filter(Boolean))]
  if (!scopes.length) {
    return { service: null, error: 'service.scopes is required, non-empty (the scope allowlist — least privilege is the class’s point)' }
  }
  return { service: { id, org, audience, scopes }, error: null }
}

/** The request's scope narrowing against the allowlist (RFC 6749 §4.4's
 *  `scope` parameter): absent = the full allowlist; present = every
 *  requested scope must be on it, or the grant refuses (invalid_scope —
 *  never a silent drop, never beyond the allowlist). Pure. */
export function narrowServiceScopes(
  service: ServiceClientClaims,
  requested: string | null,
): { scopes: string[]; error: string | null } {
  if (requested === null) return { scopes: [...service.scopes], error: null }
  const req = [...new Set(requested.split(/\s+/).filter(Boolean))]
  if (!req.length) {
    return { scopes: [], error: 'the scope parameter is present but empty — name the scopes, or omit the parameter for the registered allowlist' }
  }
  const outside = req.filter(s => !service.scopes.includes(s))
  if (outside.length) {
    return { scopes: [], error: `the requested scope(s) ${outside.map(s => `'${s}'`).join(', ')} are not on this service client’s allowlist` }
  }
  return { scopes: req, error: null }
}

/** The service token's claim set (the ONE builder the token endpoint
 *  uses): the service claims EXACTLY — the called service reads sub/aud/
 *  client_id/org/scope; never a user claim. Pure: the caller knows the
 *  issuer + the lifetimes (the request's effective OP config). */
export function serviceTokenClaims(
  clientId: string,
  service: ServiceClientClaims,
  scopes: string[],
  config: { issuer: string; accessTokenTtlMs: number },
): Record<string, unknown> {
  const nowSec = Math.floor(Date.now() / 1000)
  return {
    iss: config.issuer,
    sub: service.id,
    aud: service.audience,
    client_id: clientId,
    iat: nowSec,
    exp: nowSec + Math.floor(config.accessTokenTtlMs / 1000),
    org: service.org,
    scope: scopes.join(' '),
  }
}
