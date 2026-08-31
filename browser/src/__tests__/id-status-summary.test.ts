// ─────────────────────────────────────────────────────────────────────
// The estate status projection (server/routes/status-summary.ts's
// /api/status-summary), the ISO-benchmark structural item 1:
//
//   the aggregate — worst-of with the honest ordering (down > degraded >
//     operational), the affected services named with their reasons, the
//     never-probed service unable to drag the estate off green;
//   the honesty floors — an upstream 5xx, an unreachable upstream, an
//     unparseable answer, and a STALE PROBER (the status service's own
//     PROBER_STALE_MS doctrine) all read 'unknown', never a fake green;
//   the brief cache — a second request inside the window never re-hits
//     upstream, and an unknown from a failed fetch never poisons the
//     window (the next request retries);
//   the env seam — STATUS_SUMMARY_URL + STATUS_PAGE_URL declared.
//
// The upstream is a REAL stub HTTP server (the route's fetch path runs
// for real); the cache resets between legs.
// ─────────────────────────────────────────────────────────────────────

import { createServer, type Server } from 'node:http'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest'

const TMP = mkdtempSync(join(tmpdir(), 'oiml-status-summary-'))
process.env.DATABASE_PATH = join(TMP, 'test.db')
process.env.OP_ISSUER = 'http://op.test'

import { aggregateStatus, resetStatusSummaryCache, type StatusSummaryProjection } from '../../server/routes/status-summary'

let app: import('hono').Hono
let stub: Server
let stubUrl: string
let stubHits = 0
let stubBody: unknown = {}
let stubStatus = 200

interface Projection extends StatusSummaryProjection {
  pageUrl: string
}

async function projection(): Promise<Projection> {
  const res = await app.request('http://op.test/api/status-summary')
  expect(res.status).toBe(200)
  expect(res.headers.get('cache-control')).toBe('no-store')
  return res.json() as Promise<Projection>
}

function summaryDoc(services: { id: string; state: string; reason?: string }[], proberAgeMs = 30_000): unknown {
  return {
    generatedAt: new Date().toISOString(),
    prober: { lastRunAt: Date.now() - proberAgeMs },
    services: services.map((s) => ({
      id: s.id,
      name: `The ${s.id} service`,
      url: `https://example.invalid/${s.id}`,
      state: s.state,
      reason: s.reason ?? null,
      lastGoodAt: Date.now() - 60_000,
      uptime30d: '100',
      uptime90d: '99.9',
    })),
  }
}

beforeAll(async () => {
  stub = createServer((req, res) => {
    stubHits += 1
    res.writeHead(stubStatus, { 'content-type': 'application/json' })
    res.end(typeof stubBody === 'string' ? stubBody : JSON.stringify(stubBody))
  })
  await new Promise<void>((resolveListen) => stub.listen(0, '127.0.0.1', resolveListen))
  const address = stub.address()
  if (typeof address === 'object' && address) stubUrl = `http://127.0.0.1:${address.port}/api/summary.json`

  const { installSqliteStore } = await import('@oimlsmart/platform-server/store/sqlite')
  installSqliteStore()
  const { parseInstanceProfile } = await import('@oimlsmart/platform-server/profile')
  const { createApiApp } = await import('../../server/app')
  app = createApiApp({
    autoSeedDemo: false,
    instanceProfile: parseInstanceProfile(`
identity:
  org_id: oimlsmart-id
  org_name: OIML SMART Identity
  role_codes: [identity]
roles: [identity]
branding: { name: OIML SMART Identity }
demo_personas: false
`),
  })
})

afterAll(async () => {
  await new Promise<void>((resolveClose) => stub.close(() => resolveClose()))
  rmSync(TMP, { recursive: true, force: true })
})

afterEach(() => {
  resetStatusSummaryCache()
  delete process.env.STATUS_SUMMARY_URL
  delete process.env.STATUS_PAGE_URL
})

describe('/api/status-summary — the estate status projection', () => {
  it('all-operational upstream → operational, the counts carried, the default page URL', async () => {
    process.env.STATUS_SUMMARY_URL = stubUrl
    stubStatus = 200
    stubBody = summaryDoc([
      { id: 'id-op', state: 'operational' },
      { id: 'platform', state: 'operational' },
    ])
    const p = await projection()
    expect(p.state).toBe('operational')
    expect(p.reason).toBeNull()
    expect(p.counts).toEqual({ operational: 2, degraded: 0, down: 0, unknown: 0 })
    expect(p.affected).toEqual([])
    expect(p.pageUrl).toBe('https://status.oimlsmart.org/')
  })

  it('degraded + down aggregate worst-of, the affected services named with reasons', async () => {
    process.env.STATUS_SUMMARY_URL = stubUrl
    stubBody = summaryDoc([
      { id: 'id-op', state: 'operational' },
      { id: 'demo', state: 'degraded', reason: 'a recent probe failed inside the watch window' },
      { id: 'nmi', state: 'down', reason: 'the last probes failed' },
    ])
    const p = await projection()
    expect(p.state).toBe('down')
    expect(p.reason).toBe('the last probes failed')
    expect(p.affected.map((s) => s.id)).toEqual(['demo', 'nmi'])
    expect(p.counts).toEqual({ operational: 1, degraded: 1, down: 1, unknown: 0 })
  })

  it('degraded alone reads degraded (down stays a strong claim)', async () => {
    process.env.STATUS_SUMMARY_URL = stubUrl
    stubBody = summaryDoc([{ id: 'demo', state: 'degraded', reason: 'slow' }])
    const p = await projection()
    expect(p.state).toBe('degraded')
    expect(p.affected[0]).toMatchObject({ id: 'demo', name: 'The demo service', reason: 'slow' })
  })

  it('a never-probed (unknown) service cannot drag the estate off green', async () => {
    process.env.STATUS_SUMMARY_URL = stubUrl
    stubBody = summaryDoc([
      { id: 'id-op', state: 'operational' },
      { id: 'new-service', state: 'unknown' },
    ])
    const p = await projection()
    expect(p.state).toBe('operational')
    expect(p.counts.unknown).toBe(1)
  })

  it('a stale prober collapses the read to unknown — never a hearsay green', async () => {
    process.env.STATUS_SUMMARY_URL = stubUrl
    stubBody = summaryDoc([{ id: 'id-op', state: 'operational' }], 10 * 60_000)
    const p = await projection()
    expect(p.state).toBe('unknown')
    expect(p.reason).toBe('prober stale')
  })

  it('upstream 5xx → unknown; unreachable → unknown; unparseable → unknown', async () => {
    process.env.STATUS_SUMMARY_URL = stubUrl
    stubStatus = 500
    stubBody = { error: 'boom' }
    expect((await projection()).state).toBe('unknown')
    expect((await projection()).reason).toBe('upstream answered 500')

    resetStatusSummaryCache()
    process.env.STATUS_SUMMARY_URL = 'http://127.0.0.1:1/never'
    const unreachable = await projection()
    expect(unreachable.state).toBe('unknown')
    expect(unreachable.reason).toMatch(/^upstream unreachable/)

    resetStatusSummaryCache()
    process.env.STATUS_SUMMARY_URL = stubUrl
    stubStatus = 200
    stubBody = 'this is not json'
    expect((await projection()).state).toBe('unknown')
  })

  it('the brief cache: a second request inside the window never re-hits upstream', async () => {
    process.env.STATUS_SUMMARY_URL = stubUrl
    stubStatus = 200
    stubBody = summaryDoc([{ id: 'id-op', state: 'operational' }])
    stubHits = 0
    await projection()
    await projection()
    expect(stubHits).toBe(1)
  })

  it('an unknown from a failed fetch never poisons the window — the retry recovers', async () => {
    process.env.STATUS_SUMMARY_URL = stubUrl
    stubStatus = 503
    stubBody = { error: 'down' }
    expect((await projection()).state).toBe('unknown')
    stubStatus = 200
    stubBody = summaryDoc([{ id: 'id-op', state: 'operational' }])
    expect((await projection()).state).toBe('operational')
  })

  it('the env seam: STATUS_PAGE_URL carries through (the preview posture links its own)', async () => {
    process.env.STATUS_SUMMARY_URL = stubUrl
    process.env.STATUS_PAGE_URL = 'https://status-preview.example.org/'
    stubBody = summaryDoc([{ id: 'id-op', state: 'operational' }])
    expect((await projection()).pageUrl).toBe('https://status-preview.example.org/')
  })

  it('the aggregate is pure: an empty service list is unknown, not green', () => {
    const p = aggregateStatus({ services: [], prober: { lastRunAt: Date.now() } }, Date.now(), 'https://x/', Date.now())
    expect(p.state).toBe('unknown')
  })
})
