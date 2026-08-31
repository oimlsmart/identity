// ═══════════════════════════════════════════════════════════════════
// The estate status projection (the ISO-benchmark structural item 1,
// the visual-elevation wave's move 4): GET /api/status-summary distills
// the estate's OWN status service (status.oimlsmart.org's public
// /api/summary.json — the shape discovered from oimlsmart/status's
// src/worker.ts, verified live 2026-08-31) into the aggregate the
// sign-in page + the shell footer's status pill render.
//
// The proxy is server-side because the summary endpoint sends no CORS
// header — a browser on id.oimlsmart.org cannot read it cross-origin.
// One fetch per CACHE_TTL_MS per isolate; a 4 s upstream timeout; on ANY
// upstream failure (or a stale prober — the status service's own
// PROBER_STALE_MS doctrine: a frozen page is a lying page) the aggregate
// is UNKNOWN, never a fake green.
//
// Env: STATUS_SUMMARY_URL (default https://status.oimlsmart.org/api/
// summary.json), STATUS_PAGE_URL (the pill's link target, default
// https://status.oimlsmart.org/).
//
// WORKER-SAFE: fetch + AbortSignal.timeout + a module-level cache only.
// ═══════════════════════════════════════════════════════════════════
import { Hono } from 'hono'
import { env as runtimeEnv } from 'hono/adapter'

export const STATUS_SUMMARY_DEFAULT_URL = 'https://status.oimlsmart.org/api/summary.json'
export const STATUS_PAGE_DEFAULT_URL = 'https://status.oimlsmart.org/'
/** The upstream answer is reused within this window ("cached briefly"). */
export const CACHE_TTL_MS = 60_000
/** The upstream fetch's ceiling — the sign-in page never waits longer. */
export const UPSTREAM_TIMEOUT_MS = 4_000
/** The status service's own staleness doctrine (src/state.ts's
 *  PROBER_STALE_MS): a prober older than this makes every row hearsay. */
export const PROBER_STALE_MS = 5 * 60_000

export type EstateState = 'operational' | 'degraded' | 'down' | 'unknown'

export interface StatusSummaryProjection {
  state: EstateState
  /** Why the aggregate is not green (the first non-operational reason,
   *  'prober stale', 'upstream unreachable', …) — null when operational. */
  reason: string | null
  counts: { operational: number; degraded: number; down: number; unknown: number }
  /** The non-operational services, named (the banner's honest detail). */
  affected: { id: string; name: string; state: EstateState; reason: string | null }[]
  proberLastRunAt: number | null
  generatedAt: string | null
  /** The status page's URL (the deployment's STATUS_PAGE_URL). */
  pageUrl: string
  fetchedAt: number
}

interface SummaryServiceRow {
  id?: unknown
  name?: unknown
  state?: unknown
  reason?: unknown
}

interface SummaryDocument {
  generatedAt?: unknown
  prober?: { lastRunAt?: unknown }
  services?: unknown
}

const LEVELS: readonly EstateState[] = ['operational', 'degraded', 'down', 'unknown']

/** The pure aggregate: the summary document → the projection. Exported
 *  for the unit legs. Worst-of with the honest ordering (any down → down;
 *  else any degraded → degraded; else ≥1 operational → operational — a
 *  never-probed service cannot drag the estate off green on its own, the
 *  status page shows it as unknown itself; else unknown). A stale prober
 *  collapses the whole read to unknown — never a hearsay green. */
export function aggregateStatus(
  doc: SummaryDocument,
  now: number,
  pageUrl: string,
  fetchedAt: number,
): StatusSummaryProjection {
  const counts = { operational: 0, degraded: 0, down: 0, unknown: 0 }
  const affected: StatusSummaryProjection['affected'] = []
  const rows = Array.isArray(doc.services) ? (doc.services as SummaryServiceRow[]) : []
  for (const row of rows) {
    const state = LEVELS.includes(row.state as EstateState) ? (row.state as EstateState) : 'unknown'
    counts[state] += 1
    if (state !== 'operational') {
      affected.push({
        id: typeof row.id === 'string' ? row.id : '?',
        name: typeof row.name === 'string' ? row.name : '?',
        state,
        reason: typeof row.reason === 'string' ? row.reason : null,
      })
    }
  }
  const proberLastRunAt = typeof doc.prober?.lastRunAt === 'number' ? doc.prober.lastRunAt : null
  const proberStale = proberLastRunAt === null || now - proberLastRunAt > PROBER_STALE_MS

  let state: EstateState
  let reason: string | null = null
  if (rows.length === 0 || proberStale) {
    state = 'unknown'
    reason = rows.length === 0 ? 'no services in the summary' : 'prober stale'
  } else if (counts.down > 0) {
    state = 'down'
    reason = affected.find((s) => s.state === 'down')?.reason ?? null
  } else if (counts.degraded > 0) {
    state = 'degraded'
    reason = affected.find((s) => s.state === 'degraded')?.reason ?? null
  } else if (counts.operational > 0) {
    state = 'operational'
  } else {
    state = 'unknown'
    reason = 'no service has been probed yet'
  }

  return {
    state,
    reason,
    counts,
    affected,
    proberLastRunAt,
    generatedAt: typeof doc.generatedAt === 'string' ? doc.generatedAt : null,
    pageUrl,
    fetchedAt,
  }
}

/** The unknown projection: an upstream failure (or an unparseable
 *  answer) is honestly "status unknown", never a fake green. */
export function unknownStatus(reason: string, pageUrl: string, now: number): StatusSummaryProjection {
  return {
    state: 'unknown',
    reason,
    counts: { operational: 0, degraded: 0, down: 0, unknown: 0 },
    affected: [],
    proberLastRunAt: null,
    generatedAt: null,
    pageUrl,
    fetchedAt: now,
  }
}

// The brief cache: one upstream read per window per isolate. A fresh
// cache answers; an EXPIRED window with a failed re-fetch is unknown —
// last-green is hearsay past the window.
let cached: { at: number; body: StatusSummaryProjection } | null = null

/** The fetch seam: the unit legs substitute a stub. */
export type StatusFetch = (url: string, init: RequestInit) => Promise<Response>

export function createStatusSummaryRouter(deps: { fetchImpl?: StatusFetch; now?: () => number } = {}): Hono {
  const fetchImpl: StatusFetch = deps.fetchImpl ?? fetch
  const now = deps.now ?? (() => Date.now())
  const app = new Hono()

  app.get('/api/status-summary', async (c) => {
    const env = runtimeEnv<Record<string, string | undefined>>(c)
    const summaryUrl = env.STATUS_SUMMARY_URL?.trim() || STATUS_SUMMARY_DEFAULT_URL
    const pageUrl = env.STATUS_PAGE_URL?.trim() || STATUS_PAGE_DEFAULT_URL
    const at = now()
    if (cached && at - cached.at < CACHE_TTL_MS) {
      return c.json(cached.body, 200, { 'cache-control': 'no-store' })
    }
    let body: StatusSummaryProjection
    try {
      const res = await fetchImpl(summaryUrl, { signal: AbortSignal.timeout(UPSTREAM_TIMEOUT_MS) })
      if (!res.ok) {
        body = unknownStatus(`upstream answered ${res.status}`, pageUrl, at)
      } else {
        body = aggregateStatus((await res.json()) as SummaryDocument, at, pageUrl, at)
      }
    } catch (err) {
      body = unknownStatus(`upstream unreachable (${(err as Error).name})`, pageUrl, at)
    }
    // Only a REAL answer caches; an unknown from a failed fetch never
    // poisons the window (the next request retries upstream).
    if (body.state !== 'unknown' || body.proberLastRunAt !== null) cached = { at, body }
    return c.json(body, 200, { 'cache-control': 'no-store' })
  })

  return app
}

/** Test seam: drop the cache between legs. */
export function resetStatusSummaryCache(): void {
  cached = null
}
