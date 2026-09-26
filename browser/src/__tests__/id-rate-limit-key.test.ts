// ─────────────────────────────────────────────────────────────────────
// The rate limiter's caller key (the 2026-09-26 audit finding): the key
// MUST come from the edge-set `CF-Connecting-IP` — the one address the
// platform attests — not from the client-supplied `X-Forwarded-For`
// first hop. On Cloudflare a client-sent XFF survives with the real IP
// APPENDED (client value first), so reading the first hop let one
// header rotate buckets and defeat the limiter trivially. The node
// posture (no edge) falls back to XFF's LAST hop — the value a
// TLS-terminating proxy appends — then 'direct'.
// ─────────────────────────────────────────────────────────────────────

import { describe, expect, it } from 'vitest'
import { Hono, type Context } from 'hono'

import { opRateLimitKeyFor } from '../../server/rate-limit'

function keyFor(headers: Record<string, string>): string {
  const app = new Hono()
  app.use('/', (c, next) => next())
  app.get('/', (c) => c.json({ key: opRateLimitKeyFor(c) }))
  const headersWithHost: Record<string, string> = { host: 'op.test', ...headers }
  return opRateLimitKeyFor({
    req: { header: (name: string) => headersWithHost[name.toLowerCase()] },
  } as unknown as Context)
}

describe('the rate limiter key (the edge-attested address)', () => {
  it('CF-Connecting-IP wins over a client-supplied X-Forwarded-For', () => {
    expect(keyFor({
      'cf-connecting-ip': '203.0.113.7',
      'x-forwarded-for': '9.9.9.9, 203.0.113.7',
    })).toBe('203.0.113.7')
  })

  it('without the edge header, XFF’s LAST hop keys (the proxy-appended client)', () => {
    expect(keyFor({ 'x-forwarded-for': '9.9.9.9, 203.0.113.7' })).toBe('203.0.113.7')
  })

  it('a spoofed XFF first hop no longer rotates the key', () => {
    const spoofedA = keyFor({ 'cf-connecting-ip': '203.0.113.7', 'x-forwarded-for': '1.1.1.1' })
    const spoofedB = keyFor({ 'cf-connecting-ip': '203.0.113.7', 'x-forwarded-for': '2.2.2.2' })
    expect(spoofedA).toBe(spoofedB)
  })

  it('a direct connection (no headers at all) keys as direct', () => {
    expect(keyFor({})).toBe('direct')
  })
})
