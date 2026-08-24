// ═══════════════════════════════════════════════════════════════════
// The OP's transactional email (TODO.identity/09) — the templates and
// the send helper the routes call:
//
//   invite        the one-time setup link (POST /api/op/accounts, the
//                 join-request approval, the org invite) — the program's
//                 primary sender;
//   reset         a fresh setup link for an existing account (POST
//                 /api/op/accounts/:id/enrollment — the link sets the
//                 password either way, so the reset rides it);
//   signin        the new-sign-in notification (the password sign-in and
//                 every upstream sign-in — the account holder learns of
//                 every entry);
//   verify_email  the confirm-the-new-address message — the template
//                 ships NOW (EN/FR) for TODO.identity/06's email-change
//                 flow to send; it wires in when that route lands.
//
// The copy lives in the i18n catalogs (src/i18n/en.ts + fr.ts, the
// mail.* namespace) so the EN/FR lockstep rule covers the outbound mail;
// the locale resolves from MAIL_LOCALE ('en' default, 'fr' honored —
// accounts carry no per-user locale yet; that preference is a follow-up
// the account console owns). The branding rides the instance profile
// (fed-09: branding.name is the sender's display identity).
//
// The PLAIN TEXT is the message; the HTML shell reuses it (escaped
// paragraphs, the standalone action URL lifted into a button-styled
// link with the raw URL kept for copy-paste — email clients mangle
// everything else).
//
// sendOpMail NEVER throws and NEVER blocks the triggering flow on a
// failure: the result says sent/not-sent/why, the route surfaces it (the
// invite UI's "the email could not be sent — copy the link instead").
//
// WORKER-SAFE: the mailer seam + the catalogs only, no node built-ins.
// ═══════════════════════════════════════════════════════════════════

import { en, type MessageKey } from '../../../src/i18n/en'
import { fr } from '../../../src/i18n/fr'
import { getInstanceProfile } from '@oimlsmart/platform-server/profile'
import { mailerFor, type MailEnv, type MailPosture } from '@oimlsmart/platform-server/mailer'

export type OpMailTemplate = 'invite' | 'reset' | 'signin' | 'verify_email'

const TEMPLATE_KEYS: Record<OpMailTemplate, { subject: MessageKey; body: MessageKey; action?: MessageKey }> = {
  invite: { subject: 'mail.invite.subject', body: 'mail.invite.body', action: 'mail.invite.action' },
  reset: { subject: 'mail.reset.subject', body: 'mail.reset.body', action: 'mail.reset.action' },
  signin: { subject: 'mail.signin.subject', body: 'mail.signin.body' },
  verify_email: { subject: 'mail.verifyEmail.subject', body: 'mail.verifyEmail.body', action: 'mail.verifyEmail.action' },
}

export type MailLocale = 'en' | 'fr'

/** The deployment's mail locale: MAIL_LOCALE, 'en' default; an unknown
 *  value falls back honestly (the problem named, English sent). */
export function resolveMailLocale(env: MailEnv): { locale: MailLocale; problem: string | null } {
  const raw = typeof env.MAIL_LOCALE === 'string' ? env.MAIL_LOCALE.trim().toLowerCase() : ''
  if (!raw) return { locale: 'en', problem: null }
  if (raw === 'en' || raw === 'fr') return { locale: raw, problem: null }
  return { locale: 'en', problem: `MAIL_LOCALE '${raw}' is not one of en/fr — English applies` }
}

/** The catalogs' interpolation rule (the same {name} shape t() uses). */
function interpolate(message: string, params: Record<string, string | number>): string {
  return message.replace(/\{(\w+)\}/g, (match, name: string) =>
    params[name] !== undefined ? String(params[name]) : match)
}

function escapeHtml(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')
}

export interface RenderedMail {
  subject: string
  text: string
  html: string
}

/** Render a template: the subject + the plain-text body (+ footer), and
 *  the branded HTML shell. Params interpolate into the TEXT raw; the
 *  HTML interpolates the ESCAPED values (a name is operator-entered —
 *  never trusted markup). */
export function renderOpMail(
  template: OpMailTemplate,
  locale: MailLocale,
  params: Record<string, string | number>,
): RenderedMail {
  const catalog: Record<MessageKey, string> = locale === 'fr' ? fr : en
  const keys = TEMPLATE_KEYS[template]
  const subject = interpolate(catalog[keys.subject], params)
  const body = interpolate(catalog[keys.body], params)
  const footer = interpolate(catalog['mail.footer'], params)
  const text = `${body}\n\n--\n${footer}`

  const escaped = Object.fromEntries(Object.entries(params).map(([k, v]) => [k, escapeHtml(String(v))]))
  // The action URL is per-template (the setup link for invite/reset,
  //  the confirmation link for verify_email) — never "whichever param
  //  happens to be present" (a caller carrying both would mis-lift).
  const actionKey = template === 'verify_email' ? 'verifyUrl' : 'setupUrl'
  const actionUrl = typeof params[actionKey] === 'string' ? String(params[actionKey]) : null
  const paragraphs = interpolate(catalog[keys.body], escaped).split(/\n\n+/).map((p) => {
    // The standalone action URL (its own paragraph) becomes the
    // button-styled link with the raw URL kept below it — everything
    // else is a plain paragraph.
    if (actionUrl && p.trim() === escapeHtml(actionUrl)) {
      const href = escapeHtml(actionUrl)
      const label = keys.action ? interpolate(catalog[keys.action], escaped) : href
      return `<p style="margin:20px 0 6px"><a href="${href}" style="display:inline-block;background:#1e40af;color:#ffffff;padding:10px 18px;border-radius:6px;text-decoration:none;font-weight:600">${label}</a></p>`
        + `<p style="margin:0 0 20px;font-size:12px;word-break:break-all"><a href="${href}" style="color:#1e40af">${href}</a></p>`
    }
    return `<p style="margin:0 0 14px">${p.replace(/\n/g, '<br>')}</p>`
  })
  const product = escapeHtml(String(params.product ?? ''))
  const html = '<!DOCTYPE html><html><body style="margin:0;padding:24px;background:#f8fafc;font-family:ui-sans-serif,system-ui,sans-serif;font-size:14px;line-height:1.5;color:#1e293b">'
    + '<div style="max-width:560px;margin:0 auto;background:#ffffff;border:1px solid #e2e8f0;border-radius:8px;padding:24px">'
    + `<p style="margin:0 0 18px;font-size:15px;font-weight:700;color:#0f172a">${product}</p>`
    + paragraphs.join('')
    + `<hr style="border:none;border-top:1px solid #e2e8f0;margin:20px 0 12px"><p style="margin:0;font-size:12px;color:#64748b">${interpolate(catalog['mail.footer'], escaped)}</p>`
    + '</div></body></html>'

  return { subject, text, html }
}

export interface OpMailResult {
  sent: boolean
  posture: MailPosture
  error: string | null
  rateLimited?: boolean
}

/** Send one of the OP's templates. The product + issuer params are filled
 *  from the deployment (the instance profile's branding; the OP's
 *  issuer — the caller resolves it, the routes already do for the setup
 *  link's base). Never throws: a transport failure is the honest result. */
export async function sendOpMail(
  env: MailEnv,
  input: {
    to: string
    template: OpMailTemplate
    issuer: string
    params?: Record<string, string | number>
  },
): Promise<OpMailResult> {
  const { locale, problem } = resolveMailLocale(env)
  if (problem) console.warn(`[mail] ${problem}`)
  const params: Record<string, string | number> = {
    product: getInstanceProfile().branding.name,
    issuer: input.issuer,
    ...(input.params ?? {}),
  }
  // The sign-in notification's method: the callers pass the upstream
  // provider's display name; the password sign-in leaves it unset and
  // the localized label fills in.
  if (input.template === 'signin' && params.method === undefined) {
    params.method = (locale === 'fr' ? fr : en)['mail.signin.methodPassword']
  }
  const rendered = renderOpMail(input.template, locale, params)
  try {
    const result = await mailerFor(env).send(
      { to: input.to, subject: rendered.subject, text: rendered.text, html: rendered.html },
      { template: input.template },
    )
    return { sent: result.ok, posture: result.posture, error: result.error ?? null, ...(result.rateLimited ? { rateLimited: true } : {}) }
  } catch (err) {
    // Unreachable by construction (the mailer never throws) — the belt
    // for the invariant: a mail problem NEVER fails the triggering flow.
    console.error('[mail] the send raised past the mailer seam:', (err as Error).message)
    return { sent: false, posture: 'console', error: (err as Error).message }
  }
}
