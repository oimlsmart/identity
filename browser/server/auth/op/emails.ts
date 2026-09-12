// ═══════════════════════════════════════════════════════════════════
// Multiple emails per account (TODO.identity-features/01) — the
// per-address verification ceremony's delivery, riding TODO.identity/09's
// mailer (server/auth/op/mail.ts — the 'verify_added_email' template
// ships there for exactly this flow).
//
// The doctrine follows TODO.identity/06's email-change ceremony
// (auth/op/email-change.ts) with ONE deliberate departure: the added
// address's proof travels BY MAIL ONLY. The change flow SHOWS the link
// on screen when no mailer is configured because completing it still
// APPLIES the change (the address moves, honestly unverified); the add
// flow's completion has exactly one effect — the verification stamp —
// and a shown link could never prove the mailbox, so no-mailer means
// the honest 'unavailable': the address lands unverified, the console
// says why, and the resend waits for a mailer. Never a fake ceremony.
//
// The token row is the email_change_tokens machinery with kind 'add'
// (the kernel's 0.1.8 seam, migration 0022) or kind 'verify' (the 0.2.4
// kind — the CURRENT primary's re-verification, TODO.identity-sso/04
// wave A; the completion stamps users.email_verified_at instead of an
// account_emails row): one-time, 24 h, atomically consumed; the 'add'
// completion stamps the account_emails row's verified_at. The mint
// follows the send — a token without a delivered link never exists (a
// send failure, the rate limit: all honestly 'unavailable').
//
// WORKER-SAFE: the mailer seam only, no node built-ins.
// ═══════════════════════════════════════════════════════════════════

import { sendOpMail } from './mail'
import { resolveMailerConfig, type MailEnv } from '../../mailer'

/** The added address's verification delivery: 'mailer' = the link is on
 *  its way to the mailbox (the token may mint); 'unavailable' = this
 *  deployment could not send it (no mailer, a provider failure, the
 *  rate limit) — the address stands unverified, honestly. */
export type EmailVerificationDelivery = 'mailer' | 'unavailable'

/** Deliver the verification link to the address: by mail, or not at all
 *  (the module header's doctrine). The template names the ceremony — the
 *  ADDED address's own verification ('verify_added_email', the default)
 *  or the CURRENT primary's re-verification ('verify_primary_email',
 *  TODO.identity-sso/04 wave A); the copy differs honestly (an add vs
 *  the address of record). */
export async function deliverEmailVerificationLink(
  env: MailEnv,
  input: { to: string; name: string; issuer: string; verificationUrl: string; hours: number; template?: 'verify_added_email' | 'verify_primary_email' },
): Promise<EmailVerificationDelivery> {
  if (resolveMailerConfig(env).posture === 'console') return 'unavailable'
  const result = await sendOpMail(env, {
    to: input.to,
    template: input.template ?? 'verify_added_email',
    issuer: input.issuer,
    params: { name: input.name, verifyUrl: input.verificationUrl, hours: input.hours },
  })
  if (result.sent) return 'mailer'
  console.log(
    `[op] the verification link for ${input.to} could not be mailed (posture ${result.posture}`
    + `${result.error ? `, ${result.error}` : ''}) — the address stands unverified`,
  )
  return 'unavailable'
}
