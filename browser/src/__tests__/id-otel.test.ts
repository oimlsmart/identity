// ─────────────────────────────────────────────────────────────────────
// TODO.modern/09 — the trace-context seam, in-process: W3C traceparent
// honored inbound + echoed outbound, and the config-gated OTLP export
// (one span per request, fire-and-forget). Unset
// OTEL_EXPORTER_OTLP_ENDPOINT = the whole feature OFF — no header, no
// fetch, byte-identical answers (the Turnstile pattern).
// ─────────────────────────────────────────────────────────────────────

import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest'

const TMP = mkdtempSync(join(tmpdir(), 'oiml-otel-'))
process.env.DATABASE_PATH = join(TMP, 'test.db')
const ISSUER = 'http://op.test'
process.env.OP_ISSUER = ISSUER
const ENDPOINT = 'https://otel.test'
process.env.OTEL_EXPORTER_OTLP_ENDPOINT = ENDPOINT

let app: import('hono').Hono
const realFetch = globalThis.fetch
const exported: Array<{ url: string; body: any }> = []

beforeAll(async () => {
  const { installSqliteStore } = await import('../../server/store/sqlite')
  installSqliteStore()
  const profileMod = await import('../../server/profile')
  profileMod.installInstanceProfile(profileMod.parseInstanceProfile(`
identity:
  org_id: oimlsmart-id
  org_name: OIML SMART Identity
  role_codes: [identity]
roles: [identity]
branding: { name: OIML SMART Identity }
`))
  const { createApiApp } = await import('../../server/app')
  app = createApiApp({ autoSeedDemo: false, instanceProfile: profileMod.getInstanceProfile() })

  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url
    if (url.startsWith(ENDPOINT)) exported.push({ url, body: JSON.parse(String(init?.body)) })
    return new Response('{}', { status: 200 })
  }) as typeof fetch
})

afterEach(() => {
  exported.length = 0
  process.env.OTEL_EXPORTER_OTLP_ENDPOINT = ENDPOINT
})

afterAll(() => {
  globalThis.fetch = realFetch
  rmSync(TMP, { recursive: true, force: true })
  delete process.env.DATABASE_PATH
  delete process.env.OP_ISSUER
  delete process.env.OTEL_EXPORTER_OTLP_ENDPOINT
  delete process.env.OTEL_SERVICE_NAME
})

function headerOf(res: Response): { traceId: string; spanId: string } | null {
  const tp = res.headers.get('traceparent')
  if (!tp) return null
  const match = /^00-([0-9a-f]{32})-([0-9a-f]{16})-[0-9a-f]{2}$/.exec(tp)
  return match ? { traceId: match[1]!, spanId: match[2]! } : null
}

describe('the trace context (W3C traceparent)', () => {
  it('a generated context answers on every response (armed)', async () => {
    const res = await app.request(`${ISSUER}/api/health`)
    expect(res.status).toBe(200)
    const ctx = headerOf(res)
    expect(ctx).not.toBeNull()
    expect(ctx!.traceId).toMatch(/^[0-9a-f]{32}$/)
  })

  it('a valid inbound traceparent PROPAGATES the trace id (a fresh span)', async () => {
    const inbound = '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01'
    const res = await app.request(`${ISSUER}/api/health`, { headers: { traceparent: inbound } })
    const ctx = headerOf(res)!
    expect(ctx.traceId).toBe('4bf92f3577b34da6a3ce929d0e0e4736')
    expect(ctx.spanId).not.toBe('00f067aa0ba902b7')
  })

  it('garbage inbound never echoes — a fresh root answers', async () => {
    for (const evil of ['not-a-traceparent', '00-xyz-abc-01', '00f067aa0ba902b7']) {
      const res = await app.request(`${ISSUER}/api/health`, { headers: { traceparent: evil } })
      const ctx = headerOf(res)
      expect(ctx, `garbage must not propagate: ${evil}`).not.toBeNull()
      expect(evil).not.toContain(ctx!.traceId)
    }
  })

  it('UNSET = the whole feature OFF: no header, no fetch (byte-identical)', async () => {
    delete process.env.OTEL_EXPORTER_OTLP_ENDPOINT
    const res = await app.request(`${ISSUER}/api/health`)
    expect(res.headers.get('traceparent')).toBeNull()
    expect(exported).toHaveLength(0)
  })
})

describe('the OTLP export (fire-and-forget, one span per request)', () => {
  it('exports the request span to <endpoint>/v1/traces with the W3C ids', async () => {
    const inbound = '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01'
    await app.request(`${ISSUER}/api/health`, { headers: { traceparent: inbound } })

    const deadline = Date.now() + 5_000
    while (exported.length === 0 && Date.now() < deadline) await new Promise(r => setTimeout(r, 50))
    expect(exported).toHaveLength(1)
    expect(exported[0]!.url).toBe(`${ENDPOINT}/v1/traces`)

    const span = exported[0]!.body.resourceSpans[0].scopeSpans[0].spans[0]
    expect(span.traceId).toBe('4bf92f3577b34da6a3ce929d0e0e4736')
    expect(span.name).toBe('GET /api/health')
    expect(span.attributes).toContainEqual({ key: 'http.response.status_code', value: { intValue: 200 } })
    expect(span.attributes).toContainEqual({ key: 'url.path', value: { stringValue: '/api/health' } })
    expect(Number(span.endTimeUnixNano)).toBeGreaterThan(Number(span.startTimeUnixNano))

    const resource = exported[0]!.body.resourceSpans[0].resource.attributes
    expect(resource).toContainEqual({ key: 'service.name', value: { stringValue: 'oiml-identity' } })
  })

  it('the service name honors OTEL_SERVICE_NAME', async () => {
    process.env.OTEL_SERVICE_NAME = 'id-oiml-test'
    await app.request(`${ISSUER}/api/health`)
    const deadline = Date.now() + 5_000
    while (exported.length === 0 && Date.now() < deadline) await new Promise(r => setTimeout(r, 50))
    const resource = exported[0]!.body.resourceSpans[0].resource.attributes
    expect(resource).toContainEqual({ key: 'service.name', value: { stringValue: 'id-oiml-test' } })
  })

  it('an export failure never fails the request (the swallowed honest catch)', async () => {
    globalThis.fetch = (async (): Promise<Response> => { throw new Error('collector down') }) as typeof fetch
    const res = await app.request(`${ISSUER}/api/health`)
    expect(res.status).toBe(200)
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url
      if (url.startsWith(ENDPOINT)) exported.push({ url, body: JSON.parse(String(init?.body)) })
      return new Response('{}', { status: 200 })
    }) as typeof fetch
  })
})
