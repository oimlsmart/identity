// ─────────────────────────────────────────────────────────────────────
// The endpoint-scaling gate's harness (the estate's N+1 doctrine —
// docs/deployment/endpoint-scaling.md): a list endpoint's STORE-CALL
// count is invariant to the store's row count. The disease class this
// pins (the 2026-09 portal load audit on the sibling platform repo, and
// the measured 2–11 s orgs page on THIS service's production registry
// import): a handler awaiting a store read PER ROW inside a loop, every
// leg a fresh D1 round trip.
//
// THE MEASUREMENT SEAM: the kernel's store seam is injectable
// (installStore), so the gate wraps the REAL SQLite store in a counting
// facade — test-side only, the kernel's production code untouched. One
// counted call = one ServerStore method invocation (the D1 round-trip
// unit in production; the sqlite backend runs the same call shape
// in-process). Per-request constants (the session resolution chain)
// cancel out of the assertion, which is on the DELTA between scales.
//
// THE ASSERTION (scaling invariance): run the endpoint against a small
// fixture, then against the same fixture grown 10×. The call-count
// delta must be ZERO (an O(1) endpoint) or within the leg's DECLARED
// per-row budget (a named residual — e.g. a leg awaiting a kernel bulk
// read). A budget is a CEILING with a named follow-up, never a hiding
// place: the doctrine file names the rule.
// ─────────────────────────────────────────────────────────────────────

import { expect } from 'vitest'
import type { ServerStore } from '@oimlsmart/platform-server/store'

/** One measured request's store-call report (the gate evidence's unit). */
export interface StoreCallReport {
  total: number
  byMethod: Record<string, number>
}

/** The counting facade over the real store. Wrap the installed store
 *  ONCE at suite boot (installStore(counter.wrap(realStore))); every
 *  handler's getStore() then rides the counter. */
export class StoreCallCounter {
  private counts = new Map<string, number>()
  private depth = 0

  wrap(inner: ServerStore): ServerStore {
    const counter = this
    return new Proxy(inner, {
      get(target, prop, receiver) {
        const value = Reflect.get(target, prop, receiver)
        if (typeof value !== 'function' || typeof prop !== 'string') return value
        return (...args: unknown[]) => {
          // Only the OUTERMOST call counts when a store method calls a
          // sibling (the depth guard): the seam's contract is the method.
          if (counter.depth === 0) {
            counter.counts.set(prop, (counter.counts.get(prop) ?? 0) + 1)
          }
          counter.depth += 1
          try {
            return (value as (...a: unknown[]) => unknown).apply(target, args)
          } finally {
            counter.depth -= 1
          }
        }
      },
    }) as ServerStore
  }

  /** Run one request leg and answer its store-call delta. */
  async measure<T>(run: () => Promise<T> | T): Promise<{ result: T; report: StoreCallReport }> {
    const before = new Map(this.counts)
    const result = await run()
    const byMethod: Record<string, number> = {}
    let total = 0
    for (const [method, count] of this.counts) {
      const delta = count - (before.get(method) ?? 0)
      if (delta > 0) {
        byMethod[method] = delta
        total += delta
      }
    }
    return { result, report: { total, byMethod } }
  }
}

export interface ScalingLeg {
  /** The leg's name in the gate report (the endpoint + the session posture). */
  label: string
  /** The scaling dimension's small size (the fixture's row count at scale 1). */
  smallRows: number
  /** ...and at scale 2 (the gate grows 10× by convention). */
  largeRows: number
  /** The small scale's measured call report. */
  small: StoreCallReport
  /** The large scale's measured call report. */
  large: StoreCallReport
  /** The DECLARED per-row budget (default 0 — the O(1) rule). */
  budgetPerRow?: number
  /** A nonzero budget's named justification (the follow-up that drives
   *  it to zero). Required with a budget; the doctrine says why. */
  budgetNote?: string
}

/** THE GATE'S ASSERTION: the large scale's call count may exceed the
 *  small scale's by at most budgetPerRow per added row (default: not at
 *  all). The report names the exact per-method growth on a failure — the
 *  regression's address, never a bare red. */
export function expectScalingInvariant(leg: ScalingLeg): void {
  const budget = leg.budgetPerRow ?? 0
  if (budget > 0) {
    expect(leg.budgetNote, `${leg.label}: a nonzero budgetPerRow requires the named follow-up (budgetNote)`).toBeTruthy()
  }
  const allowed = budget * (leg.largeRows - leg.smallRows)
  const grew = leg.large.total - leg.small.total
  // The evidence line (the PR report's per-endpoint table rides it):
  // ENDPOINT_SCALING_REPORT=1 npx vitest run src/__tests__/endpoint-scaling.test.ts
  if (process.env.ENDPOINT_SCALING_REPORT) {
    console.info(`[scaling] ${leg.label}: ${leg.small.total} → ${leg.large.total} store calls `
      + `(rows ${leg.smallRows} → ${leg.largeRows}; Δ${grew}, budget ${budget}/row)`)
  }
  const methods = [...new Set([...Object.keys(leg.small.byMethod), ...Object.keys(leg.large.byMethod)])].sort()
  const detail = methods.map(m => `${m} ${leg.small.byMethod[m] ?? 0}→${leg.large.byMethod[m] ?? 0}`).join(', ')
  expect(
    grew <= allowed,
    `${leg.label}: store calls grew ${leg.small.total} → ${leg.large.total} (+${grew}) as the fixture grew `
    + `${leg.smallRows} → ${leg.largeRows} rows; the budget allows +${allowed}`
    + (budget > 0 ? ` (${leg.budgetNote})` : ' (the O(1) rule — prefetch the referenced sets once per request, group in memory)')
    + `. Per-method: ${detail}`,
  ).toBe(true)
}
