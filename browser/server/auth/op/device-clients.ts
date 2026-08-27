// ═══════════════════════════════════════════════════════════════════
// The device class on the client registry (the machine cone — smart's
// docs/future/07 Part I.3 item 2: per-device credentials for the SMART
// Measuring Instruments' twins): a NON-HUMAN client registered PER
// DEVICE. The estate doc's seam: "the claims policy gains a `device`
// class" — the class marker + the device claims ride the client row's
// claims-policy JSON (the column round-trips opaquely through the store
// seam, so the class is a DATA-level extension: no kernel change, no
// migration — the orgSigningKeys/orgEndorsements doctrine applied to
// the registry row itself).
//
// THE CLASS RULES (the registry enforces them at write; the token
// endpoint enforces them at issuance):
//
//   - a device client speaks client_credentials ONLY: no authorization-
//     code flow (there is no user to consent — /op/authorize refuses it
//     in place), no redirect_uris (nothing to redirect to), no refresh
//     (the OP never mints refresh tokens; the device re-authenticates),
//     no launch card (the SSO home is a human surface), and NO user
//     claims in the policy (roles/groups/picture name accounts, not
//     devices);
//   - a device client is CONFIDENTIAL: the secret is the device's
//     credential (client_secret_basic/post at /op/token). A public
//     device client is refused at write — there is no PKCE leg to
//     carry it;
//   - the class is FIXED AT REGISTRATION: an application never becomes
//     a device nor the reverse (a re-registration in the other class is
//     refused — the shapes are incompatible; register a fresh client);
//   - the device block binds the client to its identity: the device id
//     (the twin's name — the token's `sub`), its org (the identity
//     registry's org id — resolved at write, so the claim the twin
//     endpoints consume names an org the OP actually knows), and the
//     instrument model reference (the product-reference package id —
//     e.g. acme-lc500@2021, the model supply chain's spelling).
//
// THE TOKEN (POST /op/token, grant_type=client_credentials, the device
// class only): a self-contained ES256 JWT access token on the OP's
// signing key (the twin endpoints validate it against the OP's JWKS —
// no call-back, no userinfo), carrying EXACTLY the device claims:
//
//   iss, sub = the device id, aud = the client id, iat, exp,
//   org = the device's org, instrument_model = the model reference
//
// NEVER a user claim (no name/email/roles/groups/picture/amr — there is
// no account behind a device token), never an ID token, never a
// refresh token. The discovery document keeps advertising the RP
// contract alone (grant_types_supported stays authorization_code): the
// device class is an estate-internal cone, not an RP flow — the OIDC
// wire the relying parties pin (the contract gate's golden) is
// byte-identical.
//
// WORKER-SAFE: pure functions, no I/O, no node built-ins.
// ═══════════════════════════════════════════════════════════════════

import type { OidcClientClaimsPolicy } from '@oimlsmart/platform-server/store'

/** The class marker's value (claims_policy.class). ABSENT = the
 *  application class (the relying-party posture — the registry's
 *  pre-device shape, unchanged). */
export const DEVICE_CLASS = 'device' as const

/** The device identity a device-class client binds (the claims the SMI
 *  twin endpoints consume). */
export interface DeviceClientClaims {
  /** The device id (the twin's name) — the device token's `sub`. */
  id: string
  /** The device's organization (the identity registry's org id). */
  org: string
  /** The instrument model reference (the product-reference package id —
   *  the model supply chain's `id@edition` spelling). */
  instrument_model: string
}

/** The identity-side widening of the kernel's claims-policy type: the
 *  device class's marker + block ride the same JSON (the store seam
 *  round-trips it opaquely). */
export interface OpClientPolicy extends OidcClientClaimsPolicy {
  class?: typeof DEVICE_CLASS
  device?: DeviceClientClaims
}

/** The stored policy's device class, HONESTLY derived: the marker and a
 *  well-formed block both stand, or the client is the application class
 *  (null). A malformed block (a hand-edited row) reads as NOT a device —
 *  the token endpoint then refuses client_credentials with the class
 *  refusal, never a half-shaped device token. Pure. */
export function deviceClassOf(policy: OidcClientClaimsPolicy | null): DeviceClientClaims | null {
  const p = policy as OpClientPolicy | null
  if (p?.class !== DEVICE_CLASS || !p.device) return null
  const { id, org, instrument_model } = p.device
  if (typeof id !== 'string' || !id || typeof org !== 'string' || !org || typeof instrument_model !== 'string' || !instrument_model) {
    return null
  }
  return { id, org, instrument_model }
}

/** The write-time validation of a declared device block (the admin
 *  API's + the bootstrap seed's shared rule). Answers the normalized
 *  block, or the refusal's reason. The org's EXISTENCE on the registry
 *  is the route's check (it owns the store read); here the shape. */
export function validateDeviceBlock(input: unknown): { device: DeviceClientClaims | null; error: string | null } {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    return { device: null, error: 'device must be an object: { id, org, instrument_model } — the device identity this client binds' }
  }
  const rec = input as Record<string, unknown>
  const field = (name: keyof DeviceClientClaims): string | null =>
    typeof rec[name] === 'string' && (rec[name] as string).trim() ? (rec[name] as string).trim() : null
  const id = field('id')
  if (!id) return { device: null, error: 'device.id is required (the device id — the twin’s name; the device token’s sub)' }
  const org = field('org')
  if (!org) return { device: null, error: 'device.org is required (the identity registry’s org id the device belongs to)' }
  const instrumentModel = field('instrument_model')
  if (!instrumentModel) return { device: null, error: 'device.instrument_model is required (the instrument model reference — the product-reference package id, e.g. acme-lc500@2021)' }
  return { device: { id, org, instrument_model: instrumentModel }, error: null }
}

/** The device token's claim set (the ONE builder the token endpoint
 *  uses): the device claims EXACTLY — the twin endpoints read sub/org/
 *  instrument_model; never a user claim. Pure: the caller knows the
 *  issuer + the lifetimes (the request's effective OP config). */
export function deviceTokenClaims(
  clientId: string,
  device: DeviceClientClaims,
  config: { issuer: string; accessTokenTtlMs: number },
): Record<string, unknown> {
  const nowSec = Math.floor(Date.now() / 1000)
  return {
    iss: config.issuer,
    sub: device.id,
    aud: clientId,
    iat: nowSec,
    exp: nowSec + Math.floor(config.accessTokenTtlMs / 1000),
    org: device.org,
    instrument_model: device.instrument_model,
  }
}
