// ═══════════════════════════════════════════════════════════════════
// The webhook delivery (TODO.modern/08): the fan-out at the act, the
// bounded retry ladder, the dead-letter record. The POSTURE:
//
//   • NEVER in the act's path — emitWebhookEvent is fire-and-forget
//     (waitUntil on the Worker; a swallowed honest catch on node). A
//     failed delivery never blocks the act it reports.
//   • The signature (Webhook-Signature) rides every attempt with a
//     FRESH timestamp (each attempt is its own signed statement).
//   • The ladder is bounded (default 3 attempts, 0/1s/5s — the
//     waitUntil budget's honest fit); exhaustion records the dead
//     letter. Cron-driven redelivery is edition 2 (the scheduled
//     entry is the owner's deploy-shape decision).
//   • The delivery reads the account's subscriptions ONCE per event,
//     SQL-narrowed (never a table scan — the scaling doctrine).
//
// WORKER-SAFE: fetch + WebCrypto only.
// ═══════════════════════════════════════════════════════════════════

import type { Context } from 'hono'
import { env as runtimeEnv } from 'hono/adapter'
import { getStore } from '../store'
import { buildWebhookEnvelope, isWebhookEvent } from './events'
import { signWebhookPayload } from './signature'
import { formatTraceparent, newSpanId, type TraceContext } from '../obs/trace'

const DEFAULT_RETRY_DELAYS_MS: readonly number[] = [0, 1_000, 5_000]

function retryDelays(env: Record<string, string | undefined>): readonly number[] {
  const raw = env.WEBHOOK_RETRY_DELAYS_MS?.trim()
  if (!raw) return DEFAULT_RETRY_DELAYS_MS
  const parsed = raw.split(',').map(part => Number(part.trim())).filter(n => Number.isFinite(n) && n >= 0)
  return parsed.length ? parsed : DEFAULT_RETRY_DELAYS_MS
}

async function sha256Hex(body: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(body))
  return [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, '0')).join('')
}

interface SubscriptionForDelivery {
  id: string
  url: string
  secret: string
}

/** One endpoint's ladder. True = delivered (a 2xx); false = the dead
 *  letter (recorded). The recorded body is the digest ONLY. */
async function dispatchWithLadder(
  env: Record<string, string | undefined>,
  subscription: SubscriptionForDelivery,
  accountId: string,
  event: string,
  body: string,
  traceCtx?: TraceContext,
): Promise<boolean> {
  const delays = retryDelays(env)
  let lastStatus = 0
  for (const delay of delays) {
    if (delay > 0) await new Promise(resolve => setTimeout(resolve, delay))
    try {
      const res = await fetch(subscription.url, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'webhook-signature': await signWebhookPayload(subscription.secret, Date.now(), body),
          ...(traceCtx ? { traceparent: formatTraceparent({ ...traceCtx, spanId: newSpanId() }) } : {}),
        },
        body,
      })
      lastStatus = res.status
      if (res.ok) {
        await recordDelivery(subscription, accountId, event, body, delays.length, lastStatus, true)
        return true
      }
    } catch (err) {
      lastStatus = 0
    }
  }
  await recordDelivery(subscription, accountId, event, body, delays.length, lastStatus, false)
  return false
}

async function recordDelivery(
  subscription: SubscriptionForDelivery,
  accountId: string,
  event: string,
  body: string,
  attempts: number,
  lastStatus: number,
  delivered: boolean,
): Promise<void> {
  try {
    await getStore().recordWebhookDelivery({
      subscriptionId: subscription.id,
      accountId,
      event,
      url: subscription.url,
      attempts,
      lastStatus,
      delivered,
      bodyDigest: await sha256Hex(body),
      recordedAt: new Date().toISOString(),
    })
  } catch (err) {
    // The record is best-effort bookkeeping — its failure never
    // resurrects the act and never throws into the caller.
    console.error('[webhooks] the delivery record failed:', (err as Error).message)
  }
}

/** The delivery core, awaited (the tests + any future cron consumer).
 *  Answers the count of endpoints the event reached. Reads the
 *  account's subscriptions once, filters by the subscribed set, and
 *  dispatches per endpoint. */
export async function deliverWebhookEvent(
  env: Record<string, string | undefined>,
  input: { event: string; accountId: string; data: Record<string, unknown> },
  traceCtx?: TraceContext,
): Promise<number> {
  if (!isWebhookEvent(input.event)) return 0
  const subscriptions = (await getStore().listWebhookSubscriptions(input.accountId))
    .filter(sub => sub.active && sub.events.includes(input.event))
  if (!subscriptions.length) return 0
  const envelope = buildWebhookEnvelope(input.event, input.accountId, input.data)
  const body = JSON.stringify(envelope)
  let delivered = 0
  for (const sub of subscriptions) {
    if (await dispatchWithLadder(env, { id: sub.id, url: sub.url, secret: sub.secret }, input.accountId, input.event, body, traceCtx)) {
      delivered++
    }
  }
  return delivered
}

/** The act's one-line emission: fire-and-forget. On the Worker the
 *  delivery rides waitUntil (the isolate outlives the response); on
 *  node the promise simply runs on (the honest swallowed catch). */
export function emitWebhookEvent(
  c: Context,
  input: { event: string; accountId: string; data: Record<string, unknown> },
): void {
  const env = runtimeEnv<Record<string, string | undefined>>(c)
  // TODO.modern/09's outbound half: the delivery inherits the
  // REQUEST's trace context (a fresh child span id per endpoint — W3C)
  // when the trace seam is armed; unarmed = no header, byte-identical.
  const traceCtx = (c.get('traceCtx') as TraceContext | undefined) ?? undefined
  const run = deliverWebhookEvent(env, input, traceCtx).catch(err => {
    console.error('[webhooks] the delivery failed:', (err as Error).message)
  })
  try {
    c.executionCtx.waitUntil(run)
  } catch {
    // Not the Worker runtime — the promise runs on its own.
  }
}
