// ═══════════════════════════════════════════════════════════════════
// The OP-surface rate limiter (the extraction map's risk-8
// follow-through, smart's PROGRESS/41 §6): the operating plan says the
// token endpoint is rate-limited; the monorepo's federation limiter
// covered only the federation paths and no OP route carried a 429.
// This limiter guards the credential-bearing OP endpoints — authorize,
// token, the password sign-in + reset — with a per-caller token bucket,
// honest 429s (Retry-After + the body's retryAfterMs), and an audit
// event on every trip. The claim becomes true with this mount.
//
//   OP_RATE_LIMIT_CAPACITY    tokens per window per caller key
//                             (default 120 — generous: the legitimate
//                             flows are human-paced; 0 DISABLES the
//                             limiter, honestly)
//   OP_RATE_LIMIT_WINDOW_MS   the window (default 60_000)
//
// The bucket key is the caller's network identity as the edge sees it
// (the first X-Forwarded-For hop when fronted by a proxy, else the
// direct-connection marker). IN-MEMORY, per process/isolate: on the
// Worker the bucket is per isolate (the honest documented posture — a
// global limit needs a durable counter, deliberately out of scope).
//
// WORKER-SAFE: no node built-ins; the audit rides the store seam. The
// pattern descends from the monorepo's federation limiter
// (server/federation/rate-limit.ts there) — copied, licensed to drift.
// ═══════════════════════════════════════════════════════════════════

import type { Context, MiddlewareHandler } from 'hono'
import { env as runtimeEnv } from 'hono/adapter'
import { getStore } from '@oimlsmart/platform-server/store'

export interface OpRateLimitConfig {
  capacity: number
  windowMs: number
}

export const OP_RATE_LIMIT_DEFAULTS: OpRateLimitConfig = { capacity: 120, windowMs: 60_000 }

/** Resolve the limiter config from the env surface. Invalid values fall
 *  back to the defaults with the problem named (never a silent clamp). */
export function resolveOpRateLimitConfig(env: Record<string, string | undefined>): { config: OpRateLimitConfig; problems: string[] } {
  const problems: string[] = []
  let capacity = OP_RATE_LIMIT_DEFAULTS.capacity
  let windowMs = OP_RATE_LIMIT_DEFAULTS.windowMs
  const rawCapacity = env.OP_RATE_LIMIT_CAPACITY?.trim()
  if (rawCapacity !== undefined && rawCapacity !== '') {
    const parsed = Number(rawCapacity)
    if (!Number.isInteger(parsed) || parsed < 0) {
      problems.push(`OP_RATE_LIMIT_CAPACITY is not a non-negative integer: ${JSON.stringify(rawCapacity)} — the default ${OP_RATE_LIMIT_DEFAULTS.capacity} applies`)
    } else {
      capacity = parsed
    }
  }
  const rawWindow = env.OP_RATE_LIMIT_WINDOW_MS?.trim()
  if (rawWindow !== undefined && rawWindow !== '') {
    const parsed = Number(rawWindow)
    if (!Number.isInteger(parsed) || parsed <= 0) {
      problems.push(`OP_RATE_LIMIT_WINDOW_MS is not a positive integer: ${JSON.stringify(rawWindow)} — the default ${OP_RATE_LIMIT_DEFAULTS.windowMs} applies`)
    } else {
      windowMs = parsed
    }
  }
  return { config: { capacity, windowMs }, problems }
}

interface Bucket {
  tokens: number
  resetAt: number
}

/** The bucket key: the proxy-forwarded client address's first hop, else
 *  the direct marker. */
export function opRateLimitKeyFor(c: Context): string {
  const forwarded = c.req.header('x-forwarded-for')?.split(',')[0]?.trim()
  return forwarded || 'direct'
}

/** The audit trail on a trip — logged, never thrown. */
async function auditTrip(key: string, path: string): Promise<void> {
  try {
    const id = crypto.randomUUID()
    await getStore().putEntity('auditEvents', id, null, JSON.stringify({
      id,
      timestamp: new Date().toISOString(),
      standard_id: '',
      entity_type: 'op',
      entity_id: key,
      action: 'rate_limited',
      metadata: { path },
    }))
  } catch (err) {
    console.error('[op] the rate-limit audit failed to persist:', (err as Error).message)
  }
}

/** The middleware: one token bucket per caller key, refilled per window.
 *  A trip answers 429 with Retry-After and audits. `now` is the tests'
 *  clock seam. */
export function createOpRateLimiter(opts?: { now?: () => number }): MiddlewareHandler {
  const now = opts?.now ?? (() => Date.now())
  const buckets = new Map<string, Bucket>()
  return async (c, next) => {
    const { config, problems } = resolveOpRateLimitConfig(runtimeEnv<Record<string, string | undefined>>(c))
    for (const problem of problems) console.warn(`[op] ${problem}`)
    if (config.capacity === 0) return next() // honestly disabled

    const key = opRateLimitKeyFor(c)
    const at = now()
    let bucket = buckets.get(key)
    if (!bucket || at >= bucket.resetAt) {
      bucket = { tokens: config.capacity, resetAt: at + config.windowMs }
      buckets.set(key, bucket)
    }
    if (bucket.tokens <= 0) {
      const retryAfterMs = Math.max(bucket.resetAt - at, 1)
      await auditTrip(key, c.req.path)
      c.header('Retry-After', String(Math.ceil(retryAfterMs / 1000)))
      return c.json({
        error: 'op rate limit exceeded',
        reason: `this caller exhausted its ${config.capacity}-request allowance per ${config.windowMs / 1000}s window on the OP endpoints — retry after the named interval`,
        retryAfterMs,
      }, 429)
    }
    bucket.tokens -= 1
    await next()
  }
}
