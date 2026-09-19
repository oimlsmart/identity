// ═══════════════════════════════════════════════════════════════════
// The request-id seam (TODO.modern/09): every answer carries
// X-Request-Id — a support conversation's reference, the correlation
// key for the operator's logs. A well-formed INBOUND id is honored
// (the edge/CDN/OTel trace context survives the hop); anything not
// matching the safe alphabet is sanitized away (never echoed). The id
// is stamped BEFORE next() so error answers (the typed store outage,
// the plain 500) carry it too, and exposed to the error handlers
// through Hono's variable slot.
//
// WORKER-SAFE: crypto.randomUUID only.
// ═══════════════════════════════════════════════════════════════════

import type { MiddlewareHandler } from 'hono'

export const REQUEST_ID_KEY = 'requestId'

const SAFE_REQUEST_ID = /^[A-Za-z0-9_.-]{8,64}$/

export function newRequestId(): string {
  return crypto.randomUUID().replace(/-/g, '')
}

/** The request's id, as the error handlers and log lines read it. */
export function currentRequestId(c: { get: (key: string) => unknown }): string {
  return (c.get(REQUEST_ID_KEY) as string) ?? 'unassigned'
}

export function requestIdMiddleware(): MiddlewareHandler {
  return async (c, next) => {
    const inbound = c.req.header('x-request-id')
    const id = inbound && SAFE_REQUEST_ID.test(inbound) ? inbound : newRequestId()
    c.set(REQUEST_ID_KEY, id)
    c.header('X-Request-Id', id)
    await next()
  }
}
