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
//   mfa_locked    the second-factor lockout notice (TODO.identity-sso/03:
//                 a burned sign-in attempt surfaces to the account by
//                 email — the hard-throttle rule's other half).
//
// The copy lives in the i18n catalogs (src/i18n/en.ts + fr.ts, the
// mail.* namespace) so the EN/FR lockstep rule covers the outbound mail;
// the locale resolves from MAIL_LOCALE ('en' default, 'fr' honored —
// accounts carry no per-user locale yet; that preference is a follow-up
// the account console owns). The branding rides the instance profile
// (fed-09: branding.name is the sender's display identity).
//
// The PLAIN TEXT is the message; the HTML shell mirrors it honestly. The
// shell is the 600px table layout (email clients strip <style>, so every
// style is inline): the hidden preheader, the branded header (the
// self-hosted globe + the service name), the white content card (the
// serif heading, the message, the brand-600 primary button with the raw
// URL kept for copy-paste and the one-time/expiry caption), and the
// honest footer (why-you-got-this, the service identity, the support
// pointer). The brand mark is self-hosted (browser/public/brand/) and
// referenced by its production URL (OP_MAIL_LOGO_URL) — email clients
// need an absolute public image URL.
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

export type OpMailTemplate = 'invite' | 'reset' | 'signin' | 'verify_email' | 'mfa_locked'

/** The self-hosted brand mark the HTML shell carries. Email clients need
 *  an ABSOLUTE public URL for images and the platform's www asset path
 *  404s today, so the OP serves its own copy (browser/public/brand/) and
 *  the shell references the production URL. The globe is the SMART
 *  program's light mark (deep-blue line art on transparency) — the light
 *  variant because the header sits on the light card. */
export const OP_MAIL_LOGO_URL = 'https://id.oimlsmart.org/brand/oiml-smart-globe-light.png'

/** The web-safe stacks the brand typography falls back to in email (no
 *  web fonts: Fraunces → Georgia serif for the display line, IBM Plex
 *  Sans → the system sans for body). Every style is inline; email clients
 *  strip <style>. */
const SERIF = `Georgia, 'Times New Roman', ui-serif, serif`
const SANS = `-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif`

const TEMPLATE_KEYS: Record<OpMailTemplate, {
  subject: MessageKey
  preheader: MessageKey
  heading: MessageKey
  body: MessageKey
  why: MessageKey
  action?: MessageKey
  /** link: the template carries a one-time action URL (the button, the
   *  plain-text fallback, the expiry caption). signin is the pure
   *  notification — no link, no expiry. */
  link: boolean
}> = {
  invite: { subject: 'mail.invite.subject', preheader: 'mail.invite.preheader', heading: 'mail.invite.heading', body: 'mail.invite.body', why: 'mail.invite.why', action: 'mail.invite.action', link: true },
  reset: { subject: 'mail.reset.subject', preheader: 'mail.reset.preheader', heading: 'mail.reset.heading', body: 'mail.reset.body', why: 'mail.reset.why', action: 'mail.reset.action', link: true },
  signin: { subject: 'mail.signin.subject', preheader: 'mail.signin.preheader', heading: 'mail.signin.heading', body: 'mail.signin.body', why: 'mail.signin.why', link: false },
  verify_email: { subject: 'mail.verifyEmail.subject', preheader: 'mail.verifyEmail.preheader', heading: 'mail.verifyEmail.heading', body: 'mail.verifyEmail.body', why: 'mail.verifyEmail.why', action: 'mail.verifyEmail.action', link: true },
  // TODO.identity-sso/03: the second-factor lockout notice — a pure
  // notification like signin (no link, no expiry).
  mfa_locked: { subject: 'mail.mfaLocked.subject', preheader: 'mail.mfaLocked.preheader', heading: 'mail.mfaLocked.heading', body: 'mail.mfaLocked.body', why: 'mail.mfaLocked.why', link: false },
}
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

/** Render a template: the subject, the plain-text part, and the branded
 *  HTML shell. Params interpolate into the TEXT raw; the HTML interpolates
 *  the ESCAPED values (a name is operator-entered — never trusted markup).
 *
 *  The HTML is the 600px table layout (the email-client-safe structure):
 *  the hidden preheader, the branded header (the self-hosted globe + the
 *  service name), the white content card (the serif heading, the message,
 *  the brand-600 primary button with its plain-text fallback and the
 *  expiry caption), and the honest footer (why-you-got-this, the service
 *  identity, the support pointer). The card + text colors are explicit on
 *  both axes so the contrast holds on dark-mode clients; the text part
 *  mirrors the same content honestly. */
export function renderOpMail(
  template: OpMailTemplate,
  locale: MailLocale,
  params: Record<string, string | number>,
): RenderedMail {
  const catalog: Record<MessageKey, string> = locale === 'fr' ? fr : en
  const keys = TEMPLATE_KEYS[template]
  const escaped = Object.fromEntries(Object.entries(params).map(([k, v]) => [k, escapeHtml(String(v))]))
  const raw = (key: MessageKey): string => interpolate(catalog[key], params)
  const esc = (key: MessageKey): string => interpolate(catalog[key], escaped)
  const product = escapeHtml(String(params.product ?? ''))

  // The action URL is per-template (the setup link for invite/reset,
  //  the confirmation link for verify_email) — never "whichever param
  //  happens to be present" (a caller carrying both would mis-lift).
  const actionKey = template === 'verify_email' ? 'verifyUrl' : 'setupUrl'
  const actionUrl = keys.link && typeof params[actionKey] === 'string' ? String(params[actionKey]) : null

  // ── The plain-text part: the message IS the text. The expiry note sits
  //    right after the action link; the footer mirrors the HTML footer. ──
  const textBody = raw(keys.body).split(/\n\n+/).flatMap((p) =>
    actionUrl && p.trim() === String(params[actionKey]) ? [p, raw('mail.link.once')] : [p])
  const text = [...textBody, '--', raw(keys.why), raw('mail.footer'), raw('mail.footer.support')].join('\n\n')
  const subject = raw(keys.subject)

  // ── The HTML shell. The primary action: the bulletproof button (a
  //    bgcolor'd cell for Outlook + the styled anchor) with the raw URL
  //    kept for copy-paste and the one-time/expiry caption under it. ──
  const actionBlock = actionUrl
    ? '<table role="presentation" cellpadding="0" cellspacing="0" border="0" style="margin:26px 0 10px"><tr>'
      + `<td align="center" bgcolor="#004996" style="border-radius:8px;background-color:#004996">`
      + `<a href="${escapeHtml(actionUrl)}" style="display:inline-block;padding:14px 30px;font-family:${SANS};font-size:16px;line-height:1.4;font-weight:600;color:#ffffff;text-decoration:none;border-radius:8px;background-color:#004996">${esc(keys.action!)}</a>`
      + '</td></tr></table>'
      + `<p style="margin:0 0 4px;font-family:${SANS};font-size:13px;line-height:1.5;color:#5b6b7f">${esc('mail.link.fallback')}</p>`
      + `<p style="margin:0 0 12px;font-family:${SANS};font-size:12px;line-height:1.5;word-break:break-all"><a href="${escapeHtml(actionUrl)}" style="color:#004996;text-decoration:underline">${escapeHtml(actionUrl)}</a></p>`
      + `<p style="margin:0 0 4px;font-family:${SANS};font-size:12px;line-height:1.5;color:#5b6b7f">${esc('mail.link.once')}</p>`
    : ''

  const paragraphs = esc(keys.body).split(/\n\n+/).map((p) => {
    // The standalone action URL (its own paragraph) becomes the button
    // block in place — everything else is a body paragraph.
    if (actionUrl && p.trim() === escapeHtml(actionUrl)) return actionBlock
    return `<p style="margin:0 0 16px;font-family:${SANS};font-size:15px;line-height:1.6;color:#1d1d1b">${p.replace(/\n/g, '<br>')}</p>`
  }).join('')

  const preheader = esc(keys.preheader) + '&zwnj;&nbsp;'.repeat(18)
  const html = '<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">'
    + `<html lang="${locale}" xmlns="http://www.w3.org/1999/xhtml">`
    + `<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="x-apple-disable-message-reformatting"><meta name="color-scheme" content="light"><meta name="supported-color-schemes" content="light"><title>${escapeHtml(subject)}</title></head>`
    + '<body style="margin:0;padding:0;word-spacing:normal;background-color:#f5f3ed">'
    + `<div style="display:none;font-size:1px;line-height:1px;max-height:0;max-width:0;opacity:0;overflow:hidden;mso-hide:all">${preheader}</div>`
    + '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background-color:#f5f3ed"><tr><td align="center" style="padding:32px 16px">'
    + '<table role="presentation" width="600" cellpadding="0" cellspacing="0" border="0" style="width:600px;max-width:600px">'
    // The branded header: the self-hosted globe + the service name.
    + '<tr><td style="padding:0 8px 20px"><table role="presentation" cellpadding="0" cellspacing="0" border="0"><tr>'
    + `<td width="40" valign="middle"><img src="${OP_MAIL_LOGO_URL}" width="40" height="40" alt="${product}" style="display:block;border:0;outline:none"></td>`
    + `<td valign="middle" style="padding-left:12px;font-family:${SERIF};font-size:19px;line-height:1.2;font-weight:600;color:#001e41">${product}</td>`
    + '</tr></table></td></tr>'
    // The content card on the light canvas.
    + '<tr><td style="background-color:#ffffff;border:1px solid #e3e9f2;border-radius:12px;padding:34px 34px 30px">'
    + `<h1 style="margin:0 0 20px;font-family:${SERIF};font-size:24px;line-height:1.3;font-weight:600;color:#001e41">${esc(keys.heading)}</h1>`
    + paragraphs
    + '</td></tr>'
    // The honest footer.
    + '<tr><td style="padding:24px 12px 8px">'
    + `<p style="margin:0 0 10px;font-family:${SANS};font-size:12px;line-height:1.6;color:#5b6b7f">${esc(keys.why)}</p>`
    + `<p style="margin:0 0 10px;font-family:${SANS};font-size:12px;line-height:1.6;color:#5b6b7f">${esc('mail.footer')}</p>`
    + `<p style="margin:0;font-family:${SANS};font-size:12px;line-height:1.6;color:#5b6b7f">${esc('mail.footer.support')}</p>`
    + '</td></tr>'
    + '</table></td></tr></table></body></html>'

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
  // provider's display name OR (TODO.identity-sso/02+03) a catalog key
  // for the factor methods ('mail.signin.methodPasswordTotp', …); the
  // password sign-in leaves it unset and the localized label fills in.
  if (input.template === 'signin') {
    const catalog: Record<MessageKey, string> = locale === 'fr' ? fr : en
    if (params.method === undefined) {
      params.method = catalog['mail.signin.methodPassword']
    } else if (typeof params.method === 'string' && params.method in catalog) {
      params.method = catalog[params.method as MessageKey]
    }
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
