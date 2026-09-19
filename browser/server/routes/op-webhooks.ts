// ═══════════════════════════════════════════════════════════════════
// The outbound webhooks' console API (TODO.modern/08) — the account's
// OWN event subscriptions, every route session-gated:
//
//   GET    /api/op/account/webhooks              — the registry (the
//               url, the subscribed events, the state) — NEVER the
//               secret (it answered the mint ONCE, the GitHub
//               doctrine for shared keys shown at creation);
//   POST   /api/op/account/webhooks              — the subscribe: the
//               https-only public url + the event picker (⊆ the
//               WEBHOOK_EVENTS whitelist) → the shared secret ONCE;
//   DELETE /api/op/account/webhooks/:id          — the unsubscribe
//               (the owner's guarded deactivation; the row stays for
//               the delivery history);
//   GET    /api/op/account/webhooks/deliveries   — the delivery log
//               (the ladder's outcomes incl. the dead letters).
//
// The endpoint's honest SSRF posture: https-only, literal
// localhost/private-range hostnames refused. The named limit (never
// silent): DNS rebinding is not defended here — a public name that
// resolves private is possible; the Worker's egress is the platform's
// control surface for that class.
//
// WORKER-SAFE: hono + the store seam + WebCrypto only.
// ═══════════════════════════════════════════════════════════════════

import { Hono } from 'hono'
import { getStore } from '../store'
import { sessionUser } from '../session'
import { WEBHOOK_EVENTS } from '../webhooks/events'

const WEBHOOK_SECRET_PREFIX = 'oswh_'

function base64url(bytes: Uint8Array): string {
  let binary = ''
  for (const b of bytes) binary += String.fromCharCode(b)
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

/** The shared signing key: `oswh_` + 43 base64url chars (32 random
 *  bytes — the same entropy shape as the PAT mint). Shown to the
 *  subscriber ONCE, stored plaintext (we SIGN with it; it is never a
 *  credential presented to us). */
function mintWebhookSecret(): string {
  return `${WEBHOOK_SECRET_PREFIX}${base64url(crypto.getRandomValues(new Uint8Array(32)))}`
}

/** The endpoint's literal-host guards. Returns the refusal's reason,
 *  or null when the url admits. */
function webhookUrlProblem(rawUrl: string): string | null {
  let parsed: URL
  try {
    parsed = new URL(rawUrl)
  } catch {
    return 'the endpoint URL does not parse'
  }
  if (parsed.protocol !== 'https:') return 'the endpoint must be https'
  const host = parsed.hostname.toLowerCase()
  if (
    host === 'localhost' || host === '[::1]' || host.endsWith('.localhost')
    || /^127\./.test(host) || /^10\./.test(host) || /^192\.168\./.test(host)
    || /^169\.254\./.test(host) || /^172\.(1[6-9]|2\d|3[01])\./.test(host)
  ) {
    return 'the endpoint must be a public host'
  }
  return null
}

function toClientView(sub: { id: string; url: string; events: string[]; active: boolean; createdAt: string }) {
  return { id: sub.id, url: sub.url, events: sub.events, active: sub.active, createdAt: sub.createdAt }
}

export function createOpWebhooksRouter(): Hono {
  const webhooks = new Hono()

  webhooks.get('/api/op/account/webhooks', async (c) => {
    const user = await sessionUser(c)
    if (!user) return c.json({ error: 'the session is required' }, 401)
    // The LIVE registry: revoked subscriptions leave it (the rows stay
    // for the delivery history — the deliveries feed below carries it).
    const subscriptions = (await getStore().listWebhookSubscriptions(user.id)).filter(sub => sub.active)
    // The event catalog rides the registry read — the picker's source
    // of truth is the SERVER's whitelist (never a client-side copy
    // that could drift).
    return c.json({ subscriptions: subscriptions.map(toClientView), events: WEBHOOK_EVENTS })
  })

  webhooks.post('/api/op/account/webhooks', async (c) => {
    const user = await sessionUser(c)
    if (!user) return c.json({ error: 'the session is required' }, 401)
    const body = await c.req.json<{ url?: unknown; events?: unknown }>().catch(() => null)
    const url = typeof body?.url === 'string' ? body.url.trim() : ''
    const events = Array.isArray(body?.events) ? body!.events.filter((e): e is string => typeof e === 'string') : []

    const urlProblem = webhookUrlProblem(url)
    if (urlProblem) return c.json({ error: urlProblem }, 400)
    if (!events.length) return c.json({ error: 'name at least one event' }, 400)
    const unknown = events.filter(event => !WEBHOOK_EVENTS.includes(event))
    if (unknown.length) {
      return c.json({ error: `not webhook events: ${unknown.join(', ')}`, events: WEBHOOK_EVENTS }, 400)
    }

    const secret = mintWebhookSecret()
    const sub = await getStore().createWebhookSubscription({
      id: crypto.randomUUID(),
      accountId: user.id,
      url,
      events: [...new Set(events)],
      secret,
    })
    // The secret answers the mint ONCE — never listed again.
    return c.json({ ...toClientView(sub), secret }, 201)
  })

  webhooks.delete('/api/op/account/webhooks/:id', async (c) => {
    const user = await sessionUser(c)
    if (!user) return c.json({ error: 'the session is required' }, 401)
    const revoked = await getStore().revokeWebhookSubscription(c.req.param('id'), user.id)
    if (!revoked) return c.json({ error: 'no such subscription on this account' }, 404)
    return c.json({ revoked: true })
  })

  webhooks.get('/api/op/account/webhooks/deliveries', async (c) => {
    const user = await sessionUser(c)
    if (!user) return c.json({ error: 'the session is required' }, 401)
    const deliveries = await getStore().listWebhookDeliveries(user.id, 50)
    return c.json({ deliveries })
  })

  return webhooks
}
