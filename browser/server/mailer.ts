// ═══════════════════════════════════════════════════════════════════
// The transactional mailer (TODO.identity/09) — ONE send interface with
// three postures, resolved from the environment, best first:
//
//   1. send_email — the Cloudflare Email Service (public beta): the
//      Worker's `send_email` binding (env.EMAIL) + EMAIL_FROM. The
//      binding's builder form carries { from, to, subject, text, html }
//      — no raw MIME to compose. Domain authentication (SPF/DKIM/DMARC
//      on oimlsmart.org) is the operator act documented in
//      docs/deployment/cloudflare.md; without it the binding sends
//      nothing deliverable, which is why it ships commented-out in
//      wrangler.toml.
//   2. https — a small HTTPS mail provider (Resend is the documented
//      choice: a simple JSON POST API, a free tier, the key a Worker
//      secret). MAIL_PROVIDER_URL + MAIL_PROVIDER_KEY + EMAIL_FROM; the
//      request shape is Resend's POST /emails ({ from, to, subject,
//      text, html } with a Bearer key), so any provider speaking that
//      shape plugs in by URL alone.
//   3. console — the honest no-op when no provider is configured: the
//      message is LOGGED in full (the setup link lands in the deploy
//      log, the OP_ACCOUNT_SEED posture) and the result says not-sent,
//      so the triggering flow keeps SHOWING the link (the invite card's
//      copy path). NEVER a silent drop.
//
// Every send — sent, failed, logged, rate-limited — writes an audit
// event (entity_type 'email': recipient, template, posture, result).
// Sends are RATE-LIMITED per recipient (a token bucket, in-memory per
// process/isolate — the federation limiter's documented posture; a
// global limit needs a durable counter, deliberately out of scope):
//
//   MAIL_RATE_LIMIT_CAPACITY    messages per window per recipient
//                               (default 5; 0 disables the limiter,
//                               honestly)
//   MAIL_RATE_LIMIT_WINDOW_MS   the window (default 3_600_000 — 1 h)
//
// The mailer NEVER throws from send(): a transport failure is a result
// ({ ok: false, error }), never an exception into the triggering flow.
//
// WORKER-SAFE: fetch + the store seam only, no node built-ins.
// ═══════════════════════════════════════════════════════════════════

import { getStore } from './store'

/** The env as the mailer reads it: strings on node, plus the Worker's
 *  object bindings on Cloudflare (the EMAIL send_email binding). */
export type MailEnv = Record<string, unknown>

export interface MailMessage {
  to: string
  subject: string
  text: string
  html?: string
}

export type MailPosture = 'send_email' | 'https' | 'console'

export interface MailSendResult {
  ok: boolean
  posture: MailPosture
  /** Named when ok is false (the provider's answer, bounded; the
   *  no-provider posture's 'not configured'; the rate-limit refusal). */
  error?: string
  rateLimited?: boolean
}

/** The minimal shape of the Cloudflare Email Service binding (the
 *  workers-types `SendEmail`'s builder form), declared structurally so
 *  this module never imports the worker types. */
export interface SendEmailBinding {
  send(message: {
    from: string
    to: string
    subject: string
    text?: string
    html?: string
  }): Promise<unknown>
}

export interface MailerConfig {
  posture: MailPosture
  /** The From address (EMAIL_FROM) — required by both real postures. */
  from: string | null
  binding: SendEmailBinding | null
  providerUrl: string | null
  providerKey: string | null
  rateLimit: { capacity: number; windowMs: number }
  /** Every configuration problem, named (logged once per config change —
   *  a misdeclared mailer must never silently degrade). */
  problems: string[]
}

export const MAIL_RATE_LIMIT_DEFAULTS = { capacity: 5, windowMs: 3_600_000 }

/** The provider call's ceiling — a hung provider must never hold the
 *  triggering request. */
export const MAIL_TIMEOUT_MS = 10_000

/** Read the env into the effective configuration. PURE (the tests drive
 *  every posture through it). */
export function resolveMailerConfig(env: MailEnv): MailerConfig {
  const problems: string[] = []
  const str = (name: string): string | null => {
    const v = env[name]
    return typeof v === 'string' && v.trim() ? v.trim() : null
  }
  const bindingCandidate = env.EMAIL as SendEmailBinding | undefined
  const binding = bindingCandidate && typeof bindingCandidate.send === 'function' ? bindingCandidate : null
  const from = str('EMAIL_FROM')
  const providerUrl = str('MAIL_PROVIDER_URL')
  const providerKey = str('MAIL_PROVIDER_KEY')

  if (binding && !from) problems.push('the EMAIL send_email binding is present but EMAIL_FROM is unset — the binding posture is skipped')
  if ((providerUrl || providerKey) && !(providerUrl && providerKey)) {
    problems.push('MAIL_PROVIDER_URL and MAIL_PROVIDER_KEY must be set together — the HTTPS provider posture is skipped')
  } else if (providerUrl && providerKey && !from) {
    problems.push('MAIL_PROVIDER_URL is set but EMAIL_FROM is unset — the HTTPS provider posture is skipped')
  }
  if (!binding && !(providerUrl && providerKey && from)) {
    problems.push('no mail provider is configured (no EMAIL binding, no MAIL_PROVIDER_URL+MAIL_PROVIDER_KEY) — messages are logged, never delivered; the flows keep showing their links')
  }

  let capacity = MAIL_RATE_LIMIT_DEFAULTS.capacity
  const rawCapacity = str('MAIL_RATE_LIMIT_CAPACITY')
  if (rawCapacity !== null) {
    const parsed = Number(rawCapacity)
    if (!Number.isInteger(parsed) || parsed < 0) {
      problems.push(`MAIL_RATE_LIMIT_CAPACITY is not a non-negative integer: ${JSON.stringify(rawCapacity)} — the default ${MAIL_RATE_LIMIT_DEFAULTS.capacity} applies`)
    } else {
      capacity = parsed
    }
  }
  let windowMs = MAIL_RATE_LIMIT_DEFAULTS.windowMs
  const rawWindow = str('MAIL_RATE_LIMIT_WINDOW_MS')
  if (rawWindow !== null) {
    const parsed = Number(rawWindow)
    if (!Number.isInteger(parsed) || parsed <= 0) {
      problems.push(`MAIL_RATE_LIMIT_WINDOW_MS is not a positive integer: ${JSON.stringify(rawWindow)} — the default ${MAIL_RATE_LIMIT_DEFAULTS.windowMs} applies`)
    } else {
      windowMs = parsed
    }
  }

  const posture: MailPosture = binding && from ? 'send_email' : providerUrl && providerKey && from ? 'https' : 'console'
  return { posture, from, binding, providerUrl, providerKey, rateLimit: { capacity, windowMs }, problems }
}

export interface Mailer {
  readonly config: MailerConfig
  send(message: MailMessage, meta?: { template?: string }): Promise<MailSendResult>
}

/** The audit trail on every send outcome (the spec's invariant) —
 *  logged, never thrown (the audit never blocks the path). */
async function auditSend(
  action: 'email.sent' | 'email.failed' | 'email.logged' | 'email.rate_limited',
  message: MailMessage,
  meta: { template?: string; posture: MailPosture; error?: string },
): Promise<void> {
  try {
    const id = crypto.randomUUID()
    await getStore().putEntity('auditEvents', id, null, JSON.stringify({
      id,
      timestamp: new Date().toISOString(),
      standard_id: '',
      entity_type: 'email',
      entity_id: message.to,
      action,
      metadata: {
        subject: message.subject,
        template: meta.template ?? null,
        posture: meta.posture,
        error: meta.error ?? null,
      },
    }))
  } catch (err) {
    console.error('[mail] the send audit failed to persist:', (err as Error).message)
  }
}

interface Bucket {
  tokens: number
  resetAt: number
}

/** Build the mailer over a resolved configuration. `now`/`fetcher` are
 *  the tests' seams (the clock, the stubbed provider). */
export function createMailer(config: MailerConfig, deps?: { now?: () => number; fetcher?: typeof fetch }): Mailer {
  const now = deps?.now ?? (() => Date.now())
  const fetcher = deps?.fetcher ?? fetch
  const buckets = new Map<string, Bucket>()

  async function transport(message: MailMessage): Promise<MailSendResult> {
    if (config.posture === 'send_email') {
      await config.binding!.send({
        from: config.from!,
        to: message.to,
        subject: message.subject,
        text: message.text,
        ...(message.html ? { html: message.html } : {}),
      })
      return { ok: true, posture: 'send_email' }
    }
    if (config.posture === 'https') {
      const res = await fetcher(config.providerUrl!, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          authorization: `Bearer ${config.providerKey}`,
        },
        body: JSON.stringify({
          from: config.from,
          to: message.to,
          subject: message.subject,
          text: message.text,
          ...(message.html ? { html: message.html } : {}),
        }),
        signal: AbortSignal.timeout(MAIL_TIMEOUT_MS),
      })
      if (!res.ok) {
        const body = (await res.text().catch(() => '')).slice(0, 300)
        return { ok: false, posture: 'https', error: `the mail provider answered ${res.status}${body ? `: ${body}` : ''}` }
      }
      return { ok: true, posture: 'https' }
    }
    // The console posture: the honest no-op. The message is logged in
    // full (the link survives in the deploy log) and the result says
    // not-sent, so the triggering flow keeps showing its own link.
    console.warn(
      `[mail] no provider configured — the message for ${message.to} is NOT delivered (the flow shows its link instead).\n`
      + `  subject: ${message.subject}\n`
      + message.text.split('\n').map(l => `  ${l}`).join('\n'),
    )
    return { ok: false, posture: 'console', error: 'no mail provider is configured on this deployment' }
  }

  return {
    config,
    async send(message, meta) {
      const recipient = message.to.trim().toLowerCase()
      const { capacity, windowMs } = config.rateLimit
      if (capacity > 0) {
        const at = now()
        let bucket = buckets.get(recipient)
        if (!bucket || at >= bucket.resetAt) {
          bucket = { tokens: capacity, resetAt: at + windowMs }
          buckets.set(recipient, bucket)
        }
        if (bucket.tokens <= 0) {
          const error = `rate limited — this recipient already received ${capacity} message(s) within the window`
          await auditSend('email.rate_limited', message, { template: meta?.template, posture: config.posture, error })
          return { ok: false, posture: config.posture, error, rateLimited: true }
        }
        bucket.tokens -= 1
      }

      let result: MailSendResult
      try {
        result = await transport(message)
      } catch (err) {
        result = { ok: false, posture: config.posture, error: (err as Error).message }
      }
      await auditSend(
        result.ok ? 'email.sent' : config.posture === 'console' ? 'email.logged' : 'email.failed',
        message,
        { template: meta?.template, posture: result.posture, error: result.error },
      )
      return result
    },
  }
}

// ── the per-process mailer slot ──────────────────────────────────────
// The rate-limit buckets must survive across requests (a mailer rebuilt
// per request would reset them), so the composition roots resolve
// through this slot: ONE mailer per effective configuration, rebuilt
// when the env's mail surface changes (a test mutating process.env, an
// isolate booting with the binding). Per-ISOLATE on the Worker — the
// rate limiter's documented posture, same as the federation one.

let cached: { fingerprint: string; mailer: Mailer } | null = null

function fingerprintOf(config: MailerConfig): string {
  return JSON.stringify([
    config.posture,
    config.from,
    config.providerUrl,
    config.providerKey ? 'key-set' : null, // never the key itself
    !!config.binding,
    config.rateLimit.capacity,
    config.rateLimit.windowMs,
  ])
}

/** The process's mailer for this env (built once per configuration;
 *  the configuration problems log once per build, not per request). */
export function mailerFor(env: MailEnv): Mailer {
  const config = resolveMailerConfig(env)
  const fingerprint = fingerprintOf(config)
  if (!cached || cached.fingerprint !== fingerprint) {
    for (const problem of config.problems) console.warn(`[mail] ${problem}`)
    cached = { fingerprint, mailer: createMailer(config) }
  }
  return cached.mailer
}

/** Test seam: drop the cached mailer (the next mailerFor re-resolves). */
export function resetMailerForTest(): void {
  cached = null
}
