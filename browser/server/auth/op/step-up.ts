// ═══════════════════════════════════════════════════════════════════
// The step-up core (TODO.modern/06): the achieved-acr vocabulary and
// the OIDC max_age freshness gate.
//
// The acr ladder is derived, never asserted: a session's amr records
// HOW it authenticated ('pwd', 'webauthn', 'hwk'), and the ladder
// reads the count — one method is single-factor, more than one is
// multi-factor. The URNs are this OP's vocabulary (advertised in
// discovery as acr_values_supported); an RP asks with acr_values and
// judges the achieved claim per OIDC Core §3.1.2.1 (the OP
// authenticates and answers what it achieved — it never pretends).
//
// max_age (OIDC Core §3.1.2.1): the RP's freshness demand. An absent
// instant proves nothing — it refuses (fail-closed) when the RP asked.
//
// WORKER-SAFE: pure functions, no I/O.
// ═══════════════════════════════════════════════════════════════════

import { authTimeOf } from './logout'

export const ACR_SINGLE_FACTOR = 'urn:oimlsmart:acr:single-factor'
export const ACR_MULTI_FACTOR = 'urn:oimlsmart:acr:multi-factor'

/** The advertised ladder, strongest first. */
export const ACR_LEVELS: readonly string[] = [ACR_MULTI_FACTOR, ACR_SINGLE_FACTOR]

export function acrOf(amr: string[] | null | undefined): string {
  const methods = (amr ?? []).filter(Boolean)
  return methods.length > 1 ? ACR_MULTI_FACTOR : ACR_SINGLE_FACTOR
}

/** The session's authentication instant against the RP's max_age.
 *  Null maxAge = the RP did not ask (always true). */
export function sessionMeetsMaxAge(authTimeIso: string | null, maxAgeSeconds: number | null): boolean {
  if (maxAgeSeconds === null) return true
  if (!authTimeIso) return false
  const epochSec = authTimeOf(authTimeIso)
  if (epochSec === null) return false
  return Date.now() - epochSec * 1000 <= maxAgeSeconds * 1000
}

// ── the per-route freshness gate (the "confirm it's you") ────────────

import type { Context } from 'hono'
import { env as runtimeEnv } from 'hono/adapter'
import { sessionUser } from '../../session'

export const FRESH_AUTH_DEFAULT_MAX_AGE_SEC = 900

/** The bank-grade acts (the token-scope WIDEN, the org-key rotation)
 *  demand a recently-authenticated session — the "confirm it's you".
 *  The refusal is DISTINCT (code fresh_auth_required, never a bare
 *  401) so the console can route the holder through sign-in again
 *  (the fresh session restamps auth_time). Null = the gate passed.
 *  FRESH_AUTH_MAX_AGE_SEC tunes the window (seconds, default 900). */
export async function requireFreshAuth(c: Context): Promise<Response | null> {
  const user = await sessionUser(c as Parameters<typeof sessionUser>[0])
  if (!user) return c.json({ error: 'the session is required' }, 401)
  const raw = runtimeEnv<Record<string, string | undefined>>(c).FRESH_AUTH_MAX_AGE_SEC?.trim()
  const maxAge = raw && /^\d+$/.test(raw) ? Number(raw) : FRESH_AUTH_DEFAULT_MAX_AGE_SEC
  if (sessionMeetsMaxAge(user.sessionCreatedAt ?? null, maxAge)) return null
  return c.json(
    { error: 'this act needs fresh proof — sign in again and retry', code: 'fresh_auth_required' },
    403,
  )
}
