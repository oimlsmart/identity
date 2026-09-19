// ═══════════════════════════════════════════════════════════════════
// The trace-context seam (TODO.modern/09's export half): W3C
// traceparent honored inbound + echoed on the answer, and the
// config-gated OTLP/HTTP JSON export — one span per request,
// fire-and-forget (never in the answer's path).
//
// The arm: OTEL_EXPORTER_OTLP_ENDPOINT. UNSET = the whole feature OFF
// — no header, no fetch, byte-identical answers (the Turnstile
// pattern). OTEL_SERVICE_NAME names the resource (default
// 'oiml-identity').
//
// WORKER-SAFE: fetch + WebCrypto only.
// ═══════════════════════════════════════════════════════════════════

import type { Context, MiddlewareHandler } from 'hono'
import { env as runtimeEnv } from 'hono/adapter'

export type EnvLike = Record<string, string | undefined>

const TRACEPARENT_RE = /^00-([0-9a-f]{32})-([0-9a-f]{16})-[0-9a-f]{2}$/
const DEFAULT_SERVICE_NAME = 'oiml-identity'

export interface TraceContext {
  traceId: string
  /** THIS request's span id (a fresh one — a child, never the
   *  inbound parent's, per W3C). */
  spanId: string
}

export function traceExportEnabled(env: EnvLike): boolean {
  return Boolean(env.OTEL_EXPORTER_OTLP_ENDPOINT?.trim())
}

export function parseTraceparent(header: string | undefined): TraceContext | null {
  if (!header) return null
  const match = TRACEPARENT_RE.exec(header.trim())
  if (!match) return null
  return { traceId: match[1]!, spanId: newSpanId() }
}

function randomHex(bytes: number): string {
  const buf = crypto.getRandomValues(new Uint8Array(bytes))
  return [...buf].map(b => b.toString(16).padStart(2, '0')).join('')
}

export function newTraceId(): string {
  return randomHex(16)
}

export function newSpanId(): string {
  return randomHex(8)
}

export function formatTraceparent(ctx: TraceContext): string {
  return `00-${ctx.traceId}-${ctx.spanId}-01`
}

/** The OTLP/HTTP JSON one-span export. Fire-and-forget by contract:
 *  the catch swallows honestly (a collector's failure is never the
 *  answer's failure). */
export function exportSpan(
  c: Context,
  span: {
    ctx: TraceContext
    method: string
    path: string
    status: number
    durationMs: number
    requestId: string
  },
): void {
  const env = runtimeEnv<EnvLike>(c)
  const endpoint = env.OTEL_EXPORTER_OTLP_ENDPOINT?.trim()
  if (!endpoint) return
  const now = Date.now()
  const durationNano = Math.round(span.durationMs * 1e6)
  const serviceName = env.OTEL_SERVICE_NAME?.trim() || DEFAULT_SERVICE_NAME
  const payload = {
    resourceSpans: [{
      resource: {
        attributes: [
          { key: 'service.name', value: { stringValue: serviceName } },
        ],
      },
      scopeSpans: [{
        scope: { name: 'oiml.identity' },
        spans: [{
          traceId: span.ctx.traceId,
          spanId: span.ctx.spanId,
          name: `${span.method} ${span.path}`,
          kind: 2,
          startTimeUnixNano: String(now * 1e6 - durationNano),
          endTimeUnixNano: String(now * 1e6),
          attributes: [
            { key: 'http.request.method', value: { stringValue: span.method } },
            { key: 'url.path', value: { stringValue: span.path } },
            { key: 'http.response.status_code', value: { intValue: span.status } },
            { key: 'app.request_id', value: { stringValue: span.requestId } },
          ],
          status: { code: span.status < 500 ? 1 : 2 },
        }],
      }],
    }],
  }
  const run = fetch(`${endpoint.replace(/\/$/, '')}/v1/traces`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(payload),
  }).catch(err => {
    console.error('[otel] the span export failed:', (err as Error).message)
  })
  try {
    c.executionCtx.waitUntil(run)
  } catch {
    // Not the Worker runtime — the promise runs on its own.
  }
}

/** The middleware: parse-or-root the context, echo it on the answer,
 *  and (armed) export the request's span AFTER the answer is settled.
 *  FIRST in the stack's observability block, after the request-id
 *  seam (the span names the request id). */
export function traceContextMiddleware(): MiddlewareHandler {
  return async (c, next) => {
    const env = runtimeEnv<EnvLike>(c)
    if (!traceExportEnabled(env)) {
      await next()
      return
    }
    const ctx = parseTraceparent(c.req.header('traceparent')) ?? { traceId: newTraceId(), spanId: newSpanId() }
    c.set('traceCtx', ctx)
    c.header('traceparent', formatTraceparent(ctx))
    const start = performance.now()
    await next()
    exportSpan(c, {
      ctx,
      method: c.req.method,
      path: new URL(c.req.url).pathname,
      status: c.res.status,
      durationMs: performance.now() - start,
      requestId: (c.get('requestId') as string) ?? 'unassigned',
    })
  }
}
