// ═══════════════════════════════════════════════════════════════════
// The dead-letter redelivery pass (TODO.modern/08's edition 2 — the
// cron half the in-band ladder could not be): ONE bounded pass per
// dead letter, driven by the scheduled workflow through the
// bearer-gated endpoint.
//
//   • The pass re-signs the letter's STORED envelope body verbatim
//     (the act's own no-secrets projection) with a FRESH timestamp —
//     the subscriber dedupes by the envelope id.
//   • ONE attempt per letter, ever: the pass stamps redelivered_at
//     whether the attempt landed or not (a persistently-down endpoint
//     gets 3 in-band tries + 1 out-of-band, never a storm; the
//     delivery log records the attempt's outcome either way).
//   • A revoked/unknown subscription retires the letter without a
//     fetch. A legacy letter (body NULL — pre-0033) retires too:
//     nothing to re-sign.
// ═══════════════════════════════════════════════════════════════════

import type { Context } from 'hono'
import { getStore } from '../store'
import { signWebhookPayload } from './signature'

/** Letters younger than this stay the in-band ladder's business. */
const MIN_AGE_MS = 15 * 60_000
/** The pass's batch bound (the workflow's hourly cadence drains a
 *  backlog in waves; one run never scans the world). */
const PASS_LIMIT = 100

export async function redeliverDeadLetters(
  env: Record<string, string | undefined>,
  traceCtx?: { traceId: string },
): Promise<{ attempted: number; delivered: number; retired: number }> {
  void env
  const store = getStore()
  const now = new Date().toISOString()
  const dead = await store.listDeadWebhookDeliveries({
    olderThan: new Date(Date.now() - MIN_AGE_MS).toISOString(),
    limit: PASS_LIMIT,
  })

  let attempted = 0
  let delivered = 0
  let retired = 0

  for (const letter of dead) {
    // Retire quietly: no live subscription, or nothing to re-sign
    // (a legacy body-less letter).
    const subs = await store.listWebhookSubscriptions(letter.accountId)
    const sub = subs.find(s => s.id === letter.subscriptionId)
    if (!sub || !sub.active || !letter.body) {
      await store.stampWebhookRedelivered(letter.id, now)
      retired++
      continue
    }

    attempted++
    let status = 0
    let ok = false
    try {
      const res = await fetch(sub.url, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          // A FRESH timestamp on the stored body — each attempt is its
          // own signed statement; the envelope id inside dedupes.
          'webhook-signature': await signWebhookPayload(sub.secret, Date.now(), letter.body),
        },
        body: letter.body,
      })
      status = res.status
      ok = res.ok
    } catch {
      status = 0
    }

    // The attempt's outcome rides the log; the letter retires either
    // way (the stamp excludes it from every future pass).
    await store.recordWebhookDelivery({
      subscriptionId: letter.subscriptionId,
      accountId: letter.accountId,
      event: letter.event,
      url: letter.url,
      attempts: 1,
      lastStatus: status,
      delivered: ok,
      bodyDigest: letter.bodyDigest,
      recordedAt: now,
      redeliveredAt: now,
    })
    await store.stampWebhookRedelivered(letter.id, now)
    if (ok) delivered++
  }

  return { attempted, delivered, retired }
}

/** The bearer gate's posture (the SCIM pattern): the token env unset =
 *  the endpoint does not exist (404); a wrong bearer = 401. */
export function redeliveryBearerOk(presented: string | undefined, expected: string | undefined): 'unset' | 'ok' | 'refused' {
  const expectedTrimmed = expected?.trim()
  if (!expectedTrimmed) return 'unset'
  if (!presented?.startsWith('Bearer ')) return 'refused'
  const token = presented.slice('Bearer '.length)
  if (token.length !== expectedTrimmed.length) return 'refused'
  let diff = 0
  for (let i = 0; i < expectedTrimmed.length; i++) {
    diff |= token.charCodeAt(i) ^ expectedTrimmed.charCodeAt(i)
  }
  return diff === 0 ? 'ok' : 'refused'
}

/** The endpoint's handler shape (the router mounts it). Exported for
 *  the route's thin wrapper; traceCtx mirrors the request seam. */
export async function handleRedeliver(
  c: Context,
  env: Record<string, string | undefined>,
): Promise<Response> {
  const verdict = redeliveryBearerOk(c.req.header('authorization'), env.WEBHOOK_REDELIVERY_TOKEN)
  if (verdict === 'unset') return c.json({ error: 'not found' }, 404)
  if (verdict === 'refused') return c.json({ error: 'the redelivery bearer is required' }, 401)
  const tally = await redeliverDeadLetters(env)
  return c.json(tally)
}
