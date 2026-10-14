// ═══════════════════════════════════════════════════════════════════
// The fresh-proof gate (TODO.sota/06, the DRY extraction) — ONE seam
// for EVERY sensitive console act: a hijacked session (the cookie
// without the credentials) must never plant durable access — an email
// address (verified in the attacker's mailbox, then promoted, then the
// reset owns the account), a personal access token (survives every
// session sweep), a planted passkey, or the STRIPPING of the victim's
// own factors. The proof is FRESHNESS: a session born within the last
// five minutes was minted by a real credential act, and the step-up
// stamp (the account console's re-entry — /api/op/step-up's signed
// stamp) extends the window on demand. A stale session demands the
// re-entry; the holder's ordinary flow never sees it.
//
// WORKER-SAFE: hono + the store seam only.
// ═══════════════════════════════════════════════════════════════════
import type { Context } from 'hono'
import { getCookie } from 'hono/cookie'
import { env as runtimeEnv } from 'hono/adapter'
import { getStore } from '../../store'
import { SESSION_COOKIE } from '../../session'
import { presentedStepUpStamp, stepUpSatisfied, STEP_UP_COOKIE } from './step-up-stamp'
import { auditFactor, FRESH_SESSION_MS } from './factors'

/** Answers null (the act proceeds) or the honest 403 the console's
 *  dialog answers — { error, step_up: 'required' }. */
export async function demandFreshProof(c: Context, userId: string): Promise<Response | null> {
  const stamp = presentedStepUpStamp(c.req.header('x-op-step-up'), getCookie(c, STEP_UP_COOKIE))
  if (stamp && await stepUpSatisfied(runtimeEnv<Record<string, string | undefined>>(c), stamp, userId)) {
    return null
  }
  const sessionToken = getCookie(c, SESSION_COOKIE) ?? ''
  const sessions = await getStore().listUserSessions(userId, sessionToken)
  const current = sessions.find(s => s.current) ?? sessions[0]
  // The sqlite datetime carries no zone marker — parse it as UTC (the
  // wall clock IS utc; a local read skews the age by the zone offset).
  if (current && Date.now() - new Date(current.createdAt.replace(' ', 'T') + 'Z').getTime() < FRESH_SESSION_MS) {
    return null
  }
  await auditFactor('account.step_up_demanded', userId, { userId }, { demanded: true })
  return c.json({
    error: 'this act needs a fresh proof of you — sign in again (or verify your current password on the account page), then try the act again',
    step_up: 'required',
  }, 403)
}
