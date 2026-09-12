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
//   verify_added_email
//                 the confirm-the-ADDED-address message
//                 (TODO.identity-features/01): every additional address
//                 verifies independently — the same one-time-link
//                 doctrine, the copy naming the add (never "the account
//                 is moving").
//   verify_primary_email
//                 the confirm-the-CURRENT-address message
//                 (TODO.identity-sso/04 wave A, riding the kernel 0.2.4
//                 'verify' token kind): the primary the account ALREADY
//                 holds never went through a mailbox proof (the
//                 invited-not-yet-set-up and the admin-re-addressed
//                 postures) — the copy names the address of record,
//                 never a move and never an add.
//   mfa_locked    the second-factor lockout notice (TODO.identity-sso/03:
//                 a burned sign-in attempt surfaces to the account by
//                 email — the hard-throttle rule's other half).
//   pat_minted    the developer-token mint notice (TODO.identity-features/
//                 08: every mint surfaces to the account holder — the
//                 security notification posture);
//   pat_expiring  the token's expiry-soon notice (the same wave: the
//                 lazy sweep — the notice rides the exchange path, once
//                 per token, while the automation still works).
//
// TODO.identity-sso/04 slice D — the account-lifecycle notices (every
// one fans out like a security notice and carries the "was this you?"
// reset pointer, the muted secondary block naming the sign-in page's
// self-service reset):
//
//   password_changed        the password was set or changed (the
//                           enrollment's completion + the console's
//                           change — one copy, both moments);
//   email_changed           the primary address moved (the fan-out to
//                           the account's current mailboxes PLUS the
//                           orphaned OLD address directly — a hijack's
//                           victim reads the notice where the account
//                           used to reach them);
//   linked_method_added /   an upstream identity was linked / unlinked
//   linked_method_removed   (routes/op-upstream.ts's ceremonies);
//   factor_enrolled /       a second factor landed / left (TOTP app,
//   factor_revoked          passkey; factor_enrolled also carries the
//                           recovery set's REGENERATION — the old set's
//                           death is the security-relevant half);
//   recovery_code_used      the account-recovery floor was exercised at
//                           sign-in (it REPLACES that sign-in's generic
//                           'signin' notice — one entry, one message);
//   client_roles_granted    an administrator granted per-client roles
//                           (grants + changes with a non-empty set; a
//                           clear never mails — the checklist's choice).
//
// The SECURITY notices (signin, mfa_locked, pat_minted, pat_expiring,
// and slice D's lifecycle notices) fan out to the primary PLUS every
// verified additional address (sendOpSecurityMail — the "was this you?"
// must reach every proven mailbox); the transactional ones (invite,
// reset, verify_*) keep their single addressed target.
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
import { getInstanceProfile } from '../../profile'
import { mailerFor, type MailEnv, type MailPosture } from '../../mailer'
import type { ServerStore } from '../../store'

export type OpMailTemplate = 'invite' | 'reset' | 'signin' | 'verify_email' | 'verify_added_email' | 'verify_primary_email' | 'mfa_locked' | 'pat_minted' | 'pat_expiring'
  // TODO.identity-sso/04 slice D: the account-lifecycle security notices
  // (each a pure notification — never a primary button; the "was this
  // you?" reset pointer rides the secondary block, the `reset` flag).
  | 'password_changed' | 'email_changed' | 'linked_method_added' | 'linked_method_removed'
  | 'factor_enrolled' | 'factor_revoked' | 'recovery_code_used' | 'client_roles_granted'

/** The DEFAULT mail brand mark: the OIML SMART logo (the globe + the
 *  OIML/SMART wordmark), referenced by its absolute production URL (email
 *  clients need an ABSOLUTE public image URL and the platform's www asset
 *  path 404s today, so the OP serves its own copy,
 *  browser/public/brand/oiml-smart-logo.png — the estate's
 *  assets/oiml-logo_smart-light.svg rendered to PNG: no SVG in email).
 *  The light variant because the header sits on the light card.
 *
 *  SELF-HOST NOTE (TODO.self-host/02): a self-hosted OP that configures
 *  a mailer must declare OP_MAIL_LOGO_URL to its OWN absolute https
 *  image URL — the default names the estate's domain, and mail bearing
 *  another deployment's brand is the leak this env closes. */
export const OP_MAIL_LOGO_URL = 'https://id.oimlsmart.org/brand/oiml-smart-logo.png'

/** The deployment's mail brand mark: the OP_MAIL_LOGO_URL env wins, the
 *  estate's self-hosted default otherwise. */
export function resolveMailLogoUrl(env: Record<string, unknown>): string {
  const declared = typeof env.OP_MAIL_LOGO_URL === 'string' ? env.OP_MAIL_LOGO_URL.trim() : ''
  return declared || OP_MAIL_LOGO_URL
}

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
  /** reset (TODO.identity-sso/04 slice D): the security notice's "was
   *  this you?" block — the muted secondary pointer to the sign-in
   *  page's self-service reset (params.resetUrl, auto-filled from the
   *  issuer by sendOpMail). Never a primary button, never one-time. */
  reset?: boolean
}> = {
  invite: { subject: 'mail.invite.subject', preheader: 'mail.invite.preheader', heading: 'mail.invite.heading', body: 'mail.invite.body', why: 'mail.invite.why', action: 'mail.invite.action', link: true },
  reset: { subject: 'mail.reset.subject', preheader: 'mail.reset.preheader', heading: 'mail.reset.heading', body: 'mail.reset.body', why: 'mail.reset.why', action: 'mail.reset.action', link: true },
  signin: { subject: 'mail.signin.subject', preheader: 'mail.signin.preheader', heading: 'mail.signin.heading', body: 'mail.signin.body', why: 'mail.signin.why', link: false },
  verify_email: { subject: 'mail.verifyEmail.subject', preheader: 'mail.verifyEmail.preheader', heading: 'mail.verifyEmail.heading', body: 'mail.verifyEmail.body', why: 'mail.verifyEmail.why', action: 'mail.verifyEmail.action', link: true },
  // TODO.identity-features/01: the added address's own verification —
  // the same one-time-link ceremony, the copy naming the ADD.
  verify_added_email: { subject: 'mail.verifyAddedEmail.subject', preheader: 'mail.verifyAddedEmail.preheader', heading: 'mail.verifyAddedEmail.heading', body: 'mail.verifyAddedEmail.body', why: 'mail.verifyAddedEmail.why', action: 'mail.verifyAddedEmail.action', link: true },
  // TODO.identity-sso/04 wave A: the CURRENT primary's own verification
  // (the kernel 0.2.4 'verify' kind) — the same ceremony again, the copy
  // naming the address of record (nothing moves, nothing is added).
  verify_primary_email: { subject: 'mail.verifyPrimaryEmail.subject', preheader: 'mail.verifyPrimaryEmail.preheader', heading: 'mail.verifyPrimaryEmail.heading', body: 'mail.verifyPrimaryEmail.body', why: 'mail.verifyPrimaryEmail.why', action: 'mail.verifyPrimaryEmail.action', link: true },
  // TODO.identity-sso/03: the second-factor lockout notice — a pure
  // notification like signin (no link, no expiry).
  mfa_locked: { subject: 'mail.mfaLocked.subject', preheader: 'mail.mfaLocked.preheader', heading: 'mail.mfaLocked.heading', body: 'mail.mfaLocked.body', why: 'mail.mfaLocked.why', link: false },
  // TODO.identity-features/08: the developer-token notices — pure
  // notifications (the console's developer-tokens section is named in
  // the prose, never a deep link).
  pat_minted: { subject: 'mail.patMinted.subject', preheader: 'mail.patMinted.preheader', heading: 'mail.patMinted.heading', body: 'mail.patMinted.body', why: 'mail.patMinted.why', link: false },
  pat_expiring: { subject: 'mail.patExpiring.subject', preheader: 'mail.patExpiring.preheader', heading: 'mail.patExpiring.heading', body: 'mail.patExpiring.body', why: 'mail.patExpiring.why', link: false },
  // TODO.identity-sso/04 slice D: the account-lifecycle notices — every
  // one a pure notification (link: false) carrying the "was this you?"
  // reset pointer (reset: true).
  password_changed: { subject: 'mail.passwordChanged.subject', preheader: 'mail.passwordChanged.preheader', heading: 'mail.passwordChanged.heading', body: 'mail.passwordChanged.body', why: 'mail.passwordChanged.why', link: false, reset: true },
  email_changed: { subject: 'mail.emailChanged.subject', preheader: 'mail.emailChanged.preheader', heading: 'mail.emailChanged.heading', body: 'mail.emailChanged.body', why: 'mail.emailChanged.why', link: false, reset: true },
  linked_method_added: { subject: 'mail.linkedMethodAdded.subject', preheader: 'mail.linkedMethodAdded.preheader', heading: 'mail.linkedMethodAdded.heading', body: 'mail.linkedMethodAdded.body', why: 'mail.linkedMethodAdded.why', link: false, reset: true },
  linked_method_removed: { subject: 'mail.linkedMethodRemoved.subject', preheader: 'mail.linkedMethodRemoved.preheader', heading: 'mail.linkedMethodRemoved.heading', body: 'mail.linkedMethodRemoved.body', why: 'mail.linkedMethodRemoved.why', link: false, reset: true },
  factor_enrolled: { subject: 'mail.factorEnrolled.subject', preheader: 'mail.factorEnrolled.preheader', heading: 'mail.factorEnrolled.heading', body: 'mail.factorEnrolled.body', why: 'mail.factorEnrolled.why', link: false, reset: true },
  factor_revoked: { subject: 'mail.factorRevoked.subject', preheader: 'mail.factorRevoked.preheader', heading: 'mail.factorRevoked.heading', body: 'mail.factorRevoked.body', why: 'mail.factorRevoked.why', link: false, reset: true },
  recovery_code_used: { subject: 'mail.recoveryCodeUsed.subject', preheader: 'mail.recoveryCodeUsed.preheader', heading: 'mail.recoveryCodeUsed.heading', body: 'mail.recoveryCodeUsed.body', why: 'mail.recoveryCodeUsed.why', link: false, reset: true },
  client_roles_granted: { subject: 'mail.clientRolesGranted.subject', preheader: 'mail.clientRolesGranted.preheader', heading: 'mail.clientRolesGranted.heading', body: 'mail.clientRolesGranted.body', why: 'mail.clientRolesGranted.why', link: false, reset: true },
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
  // The brand mark: the caller's logoUrl (sendOpMail fills it from the
  // deployment's env), else the estate default.
  const logoUrl = escapeHtml(typeof params.logoUrl === 'string' && params.logoUrl ? String(params.logoUrl) : OP_MAIL_LOGO_URL)

  // The action URL is per-template (the setup link for invite/reset,
  //  the confirmation link for the verify_* family) —
  //  never "whichever param happens to be present" (a caller carrying
  //  both would mis-lift).
  const actionKey = template === 'verify_email' || template === 'verify_added_email' || template === 'verify_primary_email' ? 'verifyUrl' : 'setupUrl'
  const actionUrl = keys.link && typeof params[actionKey] === 'string' ? String(params[actionKey]) : null

  // TODO.identity-sso/04 slice D: the security notices' "was this you?"
  // reset pointer (the muted secondary block — never the primary button).
  // sendOpMail auto-fills params.resetUrl from the issuer for these.
  const resetUrl = keys.reset === true && typeof params.resetUrl === 'string' && params.resetUrl ? String(params.resetUrl) : null

  // ── The plain-text part: the message IS the text. The expiry note sits
  //    right after the action link; the footer mirrors the HTML footer. ──
  const textBody = raw(keys.body).split(/\n\n+/).flatMap((p) =>
    actionUrl && p.trim() === String(params[actionKey]) ? [p, raw('mail.link.once')] : [p])
  const text = [...textBody, ...(resetUrl ? [raw('mail.resetLink.text')] : []), '--', raw(keys.why), raw('mail.footer'), raw('mail.footer.support')].join('\n\n')
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

  // The reset pointer's HTML: the copy line with its URL wrapped in a
  // plain anchor (the escaped-interpolation trick: the escaped URL is a
  // known substring of the escaped line, so split/join lifts it).
  const resetBlock = resetUrl
    ? '<p style="margin:24px 0 0;padding-top:16px;border-top:1px solid #e3e9f2;font-family:' + SANS + ';font-size:13px;line-height:1.6;color:#5b6b7f">'
      + esc('mail.resetLink.text').split(escapeHtml(resetUrl)).join(`<a href="${escapeHtml(resetUrl)}" style="color:#004996;text-decoration:underline">${escapeHtml(resetUrl)}</a>`)
      + '</p>'
    : ''

  const preheader = esc(keys.preheader) + '&zwnj;&nbsp;'.repeat(18)
  const html = '<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">'
    + `<html lang="${locale}" xmlns="http://www.w3.org/1999/xhtml">`
    + `<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="x-apple-disable-message-reformatting"><meta name="color-scheme" content="light"><meta name="supported-color-schemes" content="light"><title>${escapeHtml(subject)}</title></head>`
    + '<body style="margin:0;padding:0;word-spacing:normal;background-color:#f5f3ed">'
    + `<div style="display:none;font-size:1px;line-height:1px;max-height:0;max-width:0;opacity:0;overflow:hidden;mso-hide:all">${preheader}</div>`
    + '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background-color:#f5f3ed"><tr><td align="center" style="padding:32px 16px">'
    + '<table role="presentation" width="600" cellpadding="0" cellspacing="0" border="0" style="width:600px;max-width:600px">'
    // The branded header: the OIML SMART logo + the service name (the logo's
    // natural ratio — the wordmark lockup is 110:96, never squished square).
    + '<tr><td style="padding:0 8px 20px"><table role="presentation" cellpadding="0" cellspacing="0" border="0"><tr>'
    + `<td width="44" valign="middle"><img src="${logoUrl}" width="44" height="38" alt="${product}" style="display:block;border:0;outline:none"></td>`
    + `<td valign="middle" style="padding-left:12px;font-family:${SERIF};font-size:19px;line-height:1.2;font-weight:600;color:#001e41">${product}</td>`
    + '</tr></table></td></tr>'
    // The content card on the light canvas.
    + '<tr><td style="background-color:#ffffff;border:1px solid #e3e9f2;border-radius:12px;padding:34px 34px 30px">'
    + `<h1 style="margin:0 0 20px;font-family:${SERIF};font-size:24px;line-height:1.3;font-weight:600;color:#001e41">${esc(keys.heading)}</h1>`
    + paragraphs
    + resetBlock
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
    logoUrl: resolveMailLogoUrl(env),
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
  // TODO.identity-sso/04 slice D: the factor notices' label — the callers
  // pass the factor KIND (params.factorKind: 'totp' | 'passkey' |
  // 'recovery'); the localized label fills from the catalog (the sign-in
  // method's precedent), the factor's user-chosen name interpolating
  // (params.factorName; the recovery set carries none).
  if (input.template === 'factor_enrolled' || input.template === 'factor_revoked') {
    const catalog: Record<MessageKey, string> = locale === 'fr' ? fr : en
    const kind = params.factorKind
    const kindKey: MessageKey | null = kind === 'totp' ? 'mail.factor.kindTotp'
      : kind === 'passkey' ? 'mail.factor.kindPasskey'
      : kind === 'recovery' ? 'mail.factor.kindRecovery'
      : null
    params.factor = kindKey
      ? interpolate(catalog[kindKey], { factorName: params.factorName ?? '' })
      : String(kind ?? '')
  }
  // The security notices' reset pointer defaults to the deployment's
  // sign-in page (the self-service reset lives there — the login.vue
  // "Forgot your password?" panel).
  if (TEMPLATE_KEYS[input.template].reset === true && params.resetUrl === undefined) {
    params.resetUrl = `${input.issuer}/`
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

/** The security-notification fan-out (TODO.identity-features/01): a
 *  security notice ("was this you?" — a sign-in, a factor lockout, a
 *  developer-token mint/expiry) reaches the PRIMARY (the address of
 *  record, always — an unverified primary included, the pre-01 posture)
 *  PLUS every VERIFIED additional (a proven mailbox of the holder): a
 *  compromised or unread primary never hides the notice, and an
 *  UNVERIFIED additional never receives account activity (an unproven
 *  address may be a stranger's). The transactional mail (the invite,
 *  the reset, the verification links) keeps its single addressed
 *  target and never rides this helper.
 *
 *  Every recipient gets its own send (the mailer's per-recipient rate
 *  limit + audit journal stay honest). Answers the PRIMARY send's
 *  result, so the caller's stamp semantics (the pat_expiring one-shot)
 *  ride the address of record; the additional sends honor sendOpMail's
 *  never-throws rule one by one. */
export async function sendOpSecurityMail(
  env: MailEnv,
  store: ServerStore,
  input: {
    userId: string
    template: OpMailTemplate
    issuer: string
    params?: Record<string, string | number>
  },
): Promise<OpMailResult> {
  const addresses = await store.listAccountEmails(input.userId)
  const targets = addresses.filter(a => a.isPrimary || a.verifiedAt)
  let primaryResult: OpMailResult = { sent: false, posture: 'console', error: 'the account carries no primary address' }
  for (const target of targets) {
    const result = await sendOpMail(env, {
      to: target.email,
      template: input.template,
      issuer: input.issuer,
      params: input.params,
    })
    if (target.isPrimary) primaryResult = result
  }
  return primaryResult
}
