// ═══════════════════════════════════════════════════════════════════
// The verify-new-email ceremony's delivery (TODO.identity/06), riding
// TODO.identity/09's mailer (server/auth/op/mail.ts — the
// 'verify_email' template ships there for exactly this flow).
//
// An email change on the OP is a one-time, 24 h token link (the
// enrollment doctrine: the email_change_tokens row IS the proof). When
// a mail provider is configured the link travels BY MAIL to the NEW
// address and completing it verifies the mailbox; when none is (the
// mailer's honest console posture) the link is SHOWN to the signed-in
// holder instead — a change confirmed that way CANNOT verify the
// mailbox, so the address keeps its unverified state. The token row's
// delivered_by records the channel and the completion derives the
// verification from it, never from a route parameter.
//
// A send FAILURE (the provider down, the rate limit) also answers
// 'shown': the console displays the link with the explanation rather
// than dropping the user's change (the invite flow's posture — never a
// silent drop).
//
// WORKER-SAFE: the mailer seam only, no node built-ins.
// ═══════════════════════════════════════════════════════════════════

import { sendOpMail } from './mail'
import type { MailEnv } from '@oimlsmart/platform-server/mailer'

export const OP_EMAIL_CHANGE_TTL_MS = 24 * 60 * 60 * 1000

export type EmailChangeDelivery = 'mailer' | 'shown'

/** Deliver the verification link: by mail when the deployment's mailer
 *  sends it, on screen otherwise (the console posture, a send failure,
 *  the rate limit — all honestly the 'shown' path). */
export async function deliverEmailChangeLink(
  env: MailEnv,
  input: { to: string; name: string; issuer: string; verificationUrl: string },
): Promise<EmailChangeDelivery> {
  const result = await sendOpMail(env, {
    to: input.to,
    template: 'verify_email',
    issuer: input.issuer,
    params: {
      name: input.name,
      verifyUrl: input.verificationUrl,
      hours: Math.round(OP_EMAIL_CHANGE_TTL_MS / 3_600_000),
    },
  })
  if (result.sent) return 'mailer'
  console.log(
    `[op] email change link for ${input.to} not mailed (posture ${result.posture}`
    + `${result.error ? `, ${result.error}` : ''}) — the holder sees it on screen`,
  )
  return 'shown'
}
