// ═══════════════════════════════════════════════════════════════════
// The estate status, client half (the ISO-benchmark structural item 1,
// the visual-elevation wave's move 4): one shared probe of the service's
// /api/status-summary projection (the server distills status.oimlsmart
// .org's public summary — no CORS on the upstream, hence the proxy),
// consumed by the shell footer's status pill and the sign-in page's
// incident banner. Never a fake green: any failure reads 'unknown',
// and until the probe lands the callers render their STATIC affordance
// (the plain status link), not a guessed state.
// ═══════════════════════════════════════════════════════════════════
import { computed, shallowRef, type ComputedRef } from 'vue'

export type EstateState = 'operational' | 'degraded' | 'down' | 'unknown'

export interface StatusSummary {
  state: EstateState
  reason: string | null
  counts: { operational: number; degraded: number; down: number; unknown: number }
  affected: { id: string; name: string; state: EstateState; reason: string | null }[]
  proberLastRunAt: number | null
  generatedAt: string | null
  pageUrl: string
  fetchedAt: number
}

const summary = shallowRef<StatusSummary | null>(null)
let probed = false
let inflight: Promise<void> | null = null

/** The minimal shape check — the projection is only trusted whole. */
function summaryShapeOk(body: unknown): body is StatusSummary {
  if (typeof body !== 'object' || body === null) return false
  const b = body as StatusSummary
  return (
    ['operational', 'degraded', 'down', 'unknown'].includes(b.state) &&
    typeof b.pageUrl === 'string' &&
    Array.isArray(b.affected)
  )
}

/** Probe once (inflight-deduped, the branding.ts posture). Any failure
 *  records the honest UNKNOWN — the pill says "status unknown", the
 *  banner stays down. */
export function resolveStatusSummary(): Promise<void> {
  if (probed) return Promise.resolve()
  if (inflight) return inflight
  inflight = (async () => {
    try {
      const res = await fetch('/api/status-summary', { credentials: 'include' })
      if (res.ok) {
        const body: unknown = await res.json()
        summary.value = summaryShapeOk(body)
          ? body
          : { state: 'unknown', reason: 'unparseable projection', counts: { operational: 0, degraded: 0, down: 0, unknown: 0 }, affected: [], proberLastRunAt: null, generatedAt: null, pageUrl: 'https://status.oimlsmart.org/', fetchedAt: Date.now() }
      } else {
        summary.value = { state: 'unknown', reason: `projection answered ${res.status}`, counts: { operational: 0, degraded: 0, down: 0, unknown: 0 }, affected: [], proberLastRunAt: null, generatedAt: null, pageUrl: 'https://status.oimlsmart.org/', fetchedAt: Date.now() }
      }
    } catch {
      summary.value = { state: 'unknown', reason: 'projection unreachable', counts: { operational: 0, degraded: 0, down: 0, unknown: 0 }, affected: [], proberLastRunAt: null, generatedAt: null, pageUrl: 'https://status.oimlsmart.org/', fetchedAt: Date.now() }
    } finally {
      probed = true
      inflight = null
    }
  })()
  return inflight
}

/** The reactive read: null until the probe lands (callers render their
 *  static affordance), then the projection — never null after. */
export function useStatusSummary(): { summary: ComputedRef<StatusSummary | null> } {
  return { summary: computed(() => summary.value) }
}

/** Test seam: force the projection (null re-arms the probe). */
export function setStatusForTest(value: StatusSummary | null): void {
  inflight = null
  probed = value !== null
  summary.value = value
}
