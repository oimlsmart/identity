// ═══════════════════════════════════════════════════════════════════
// TODO.sota/06 — the STEP-UP STAMP: the sensitive acts (the role
// grants, the identity-link changes) demand a FRESH proof inside the
// session, minted by re-entering the current password. STATELESS (the
// owner's law): the stamp is a short-lived ES256 JWT over the OP's own
// keyset — nothing is stored, nothing rides a server-side session row.
//
//   stamp = the OP's signOpJwt({ stp: 'op_step_up', u, amr, iat, exp })
//
// The stamp is USER-BOUND (u must equal the acting session's account),
// five-minute-lived (the act window — a step-up is asked per sitting,
// never remembered), and claim-gated (a plain OP token — an ID token,
// a logout token — carries no `stp` and never satisfies). Distinct
// from auth/op/step-up.ts — the OIDC acr/max_age RP-facing core; this
// is the SESSION-side fresh proof for the console's sensitive acts.
//
// WORKER-SAFE: the keys module's own WebCrypto; no node built-ins.
// ═══════════════════════════════════════════════════════════════════

import { resolveOpSigningKey, signOpJwt, verifyOpJwtWithKey, type OpSigningKey } from './keys'

export const STEP_UP_TTL_MS = 5 * 60 * 1000
export const STEP_UP_COOKIE = 'op_step_up'
const STEP_UP_CLAIM = 'op_step_up'

export async function mintStepUpStamp(
  key: OpSigningKey,
  userId: string,
  amr: 'pwd' | 'passkey' | 'upstream',
  now: number = Date.now(),
  ttlMs: number = STEP_UP_TTL_MS,
): Promise<string> {
  return signOpJwt(key, { stp: STEP_UP_CLAIM, u: userId, amr, iat: now, exp: now + ttlMs })
}

/** Whether the presented stamp satisfies the step-up demand for THIS
 *  user: the signature verifies against THE KEY THE OP SIGNS WITH (the
 *  in-memory declared/instantiated pair — the oidc_keys table serves
 *  the external RPs and may be empty), the claim marks it a step-up
 *  stamp, the user binds, the window lives. */
export async function stepUpSatisfied(
  env: Record<string, string | undefined>,
  presented: string,
  userId: string,
  opts?: { now?: number },
): Promise<boolean> {
  const key = await resolveOpSigningKey(env)
  const claims = await verifyOpJwtWithKey(key, presented)
  if (!claims || claims.stp !== STEP_UP_CLAIM || claims.u !== userId) return false
  const now = opts?.now ?? Date.now()
  return typeof claims.exp === 'number' && claims.exp > now
}

/** The presented stamp's carrier-agnostic read: the RETRY carries it
 *  as the x-op-step-up header (the island's sessionStorage copy — no
 *  Set-Cookie dependency through any proxy), the cookie the fallback
 *  (same-origin page flows). Either satisfies; both are the same
 *  signed stamp. */
export function presentedStepUpStamp(headerValue: string | undefined, cookieValue: string | undefined): string {
  return (headerValue ?? '').trim() || (cookieValue ?? '').trim()
}

/** The step-up route's own key resolution (the OP signing key). */
export async function stepUpKey(env: Record<string, string | undefined>): Promise<OpSigningKey> {
  return resolveOpSigningKey(env)
}
