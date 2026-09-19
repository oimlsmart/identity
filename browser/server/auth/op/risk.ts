// ═══════════════════════════════════════════════════════════════════
// The sign-in risk signals (TODO.modern/06's last half): the
// new-device recognition (the UA+IP hash per account) and the
// country-change advisory (the impossible-travel signal's honest
// country-resolution form). The JOURNAL carries the outcome — the
// audit's account.sign_in metadata rides {newDevice, countryChanged}
// — and the known-device record is the console's devices view.
//
// The step-up TRIGGER posture: the second factor ALWAYS gates a
// password sign-in when factors exist (the factor registry's own
// rule — "even when optional" is structurally satisfied); the risk
// signals' job is the ADVISORY layer on top (the audit + the notice's
// data), never a second gate to bypass the first.
//
// WORKER-SAFE: WebCrypto only; the country rides the Worker's cf
// field (then the cf-ipcountry header), absent = null (the advisory
// honestly does not fire without geo).
// ═══════════════════════════════════════════════════════════════════

import type { ServerStore } from '../../store'

/** The recognition key: SHA-256 of the normalized UA + IP. Absent
 *  values fold to a canonical marker (an absent IP is a real device
 *  state, not a hash breaker). */
export async function deviceHashOf(userAgent: string | null, ip: string | null): Promise<string> {
  const digest = await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(`${userAgent ?? 'no-ua'}|${ip ?? 'no-ip'}`),
  )
  return [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, '0')).join('')
}

/** The sign-in's country: the Worker's cf field first, then the
 *  cf-ipcountry header, else null (no geo = no advisory). */
export function countryOf(input: { req: Request }): string | null {
  const cf = (input.req as Request & { cf?: { country?: string } }).cf
  return cf?.country ?? input.req.headers.get('cf-ipcountry') ?? null
}

export interface SignInRiskAssessment {
  newDevice: boolean
  countryChanged: boolean
}

/** The sign-in's risk assessment — called at EVERY OP-side session
 *  mint (the password path + the MFA completion), BEFORE the session.
 *  The device record upserts (the prior row answers the advisory);
 *  the assessment never gates the sign-in (the advisory layer). */
export async function assessSignInRisk(
  store: ServerStore,
  input: { accountId: string; userAgent: string | null; ip: string | null; country: string | null },
): Promise<SignInRiskAssessment> {
  const hash = await deviceHashOf(input.userAgent, input.ip)
  const sighting = await store.recordKnownDevice({
    id: crypto.randomUUID(),
    accountId: input.accountId,
    deviceHash: hash,
    userAgent: input.userAgent,
    ip: input.ip,
    country: input.country,
  })
  const countryChanged = Boolean(
    sighting.previousCountry && input.country && sighting.previousCountry !== input.country,
  )
  return { newDevice: sighting.isNew, countryChanged }
}
