// ═══════════════════════════════════════════════════════════════════
// The store-phase instrument behind Server-Timing (TODO.restructure/27
// items 5–8; the program's Workstream C). #88 shipped the minimal
// form — every answer carries `Server-Timing: app;dur=<ms>`. This
// module adds the STORE phase: when SERVER_TIMING is set, every
// answer additionally carries
//   `Server-Timing: app;dur=X, store;dur=Y;desc="N calls"`
// — one header, comma-joined per the Server-Timing spec — so the next
// performance claim about the store seam reads a measurement, not an
// inference.
//
// The instrument is the endpoint-scaling gate's counting facade
// (src/__tests__/endpoint-scaling.ts) promoted to production: the
// same Proxy over the store seam, the same outermost-call depth guard
// (one counted call = one ServerStore method invocation = one D1
// round trip on the Worker), now also timing each counted call
// through its promise (performance.now() — the Worker-safe clock;
// Date.now() does not advance between I/O on workerd).
//
// DEFAULT OFF — the zero-overhead posture: unset, getStore() returns
// the installed store untouched and no counter state exists at all.
// When SERVER_TIMING is set (any non-empty value), the Server-Timing
// middleware (server/app.ts) measures each request through this
// module and getStore() resolves through the counting proxy for the
// request's duration.
//
// PER-REQUEST ATTRIBUTION, EXACT: each measured window runs inside
// its own AsyncLocalStorage context carrying a FRESH counter (the
// gate's own measure() primitive — the same instrument, DRY), so a
// request's report counts exactly its own calls — never a sibling
// concurrent request's. (The 2026-09-18 wire lesson that forced this:
// the earlier monotone-accumulator + delta form let concurrent
// requests' calls land in one another's reports — one curl against
// the public org list read 22 calls / ~500 ms on an endpoint whose
// own cost is 2 calls / ~20 ms, and the misreading nearly refactored
// a healthy surface. The tolerance is gone; the numbers are now
// measurements, not hints.)
//
// PORTABLE: node:async_hooks' AsyncLocalStorage is the ONE node
// import — legal in both postures (native in node; on the Worker
// under the deployment's nodejs_compat compatibility flag) — because
// exact per-request attribution requires it and an inexact
// instrument is worse than none (see the request seam below).
// ═══════════════════════════════════════════════════════════════════

import { AsyncLocalStorage } from 'node:async_hooks'
import type { ServerStore } from './store'

/** One measured window's store-call report: the call COUNT (the
 *  scaling gate's currency — one per seam-method invocation) and the
 *  summed wall time of those calls, per method and total. `totalMs`
 *  settles when the calls' promises do, so a fire-and-forget write
 *  whose promise outlives the window is counted but may not be timed
 *  — the count is the reliable number; the time is the diagnostic. */
export interface StoreTimingReport {
  total: number
  totalMs: number
  byMethod: Record<string, number>
}

/** The counting facade over a real store. The endpoint-scaling gate
 *  wraps its fixture store in one instance; the SERVER_TIMING
 *  middleware scopes one instance per REQUEST (the ALS seam below).
 *  One instance, one monotone set of totals. */
export class StoreCallCounter {
  private counts = new Map<string, number>()
  private times = new Map<string, number>()
  private depth = 0
  /** The per-instance proxy cache: one counting view per (counter,
   *  store) pair — a measured request re-getStore()s freely without
   *  re-wrapping. Weak so the views die with the stores. */
  private views = new WeakMap<ServerStore, ServerStore>()

  /** The counting view of a store through THIS counter — cached, so
   *  the flag-on world allocates one proxy per store per window,
   *  never one per getStore() call. */
  view(store: ServerStore): ServerStore {
    let wrapped = this.views.get(store)
    if (!wrapped) {
      wrapped = this.wrap(store)
      this.views.set(store, wrapped)
    }
    return wrapped
  }

  /** Wrap the store: every method invocation passes through record()
   *  below; non-function properties forward untouched. */
  wrap(inner: ServerStore): ServerStore {
    const counter = this
    return new Proxy(inner, {
      get(target, prop, receiver) {
        const value = Reflect.get(target, prop, receiver)
        if (typeof value !== 'function' || typeof prop !== 'string') return value
        return (...args: unknown[]) =>
          counter.record(prop, () => (value as (...a: unknown[]) => unknown).apply(target, args))
      },
    }) as ServerStore
  }

  /** One seam-method invocation. Only the OUTERMOST call counts when
   *  a store method calls a sibling (the depth guard): the seam's
   *  contract is the method — the gate's budgets are calibrated to
   *  exactly this rule, so it never changes. The count lands at
   *  invocation; the wall time settles when the returned promise (if
   *  any) settles. */
  private record<T>(method: string, invoke: () => T): T {
    const outermost = this.depth === 0
    if (outermost) this.counts.set(method, (this.counts.get(method) ?? 0) + 1)
    this.depth += 1
    const started = performance.now()
    try {
      const result = invoke()
      if (!outermost) return result
      if (result instanceof Promise) {
        return result.then(
          (value) => {
            this.settle(method, performance.now() - started)
            return value
          },
          (err: unknown) => {
            this.settle(method, performance.now() - started)
            throw err
          },
        ) as T
      }
      this.settle(method, performance.now() - started)
      return result
    } finally {
      this.depth -= 1
    }
  }

  private settle(method: string, ms: number): void {
    this.times.set(method, (this.times.get(method) ?? 0) + ms)
  }

  /** Run one window (a request, a measured gate leg) and answer its
   *  store-call delta against the totals before it began. */
  async measure<T>(run: () => Promise<T> | T): Promise<{ result: T; report: StoreTimingReport }> {
    const beforeCounts = new Map(this.counts)
    const beforeTimes = new Map(this.times)
    const result = await run()
    const byMethod: Record<string, number> = {}
    let total = 0
    let totalMs = 0
    for (const [method, count] of this.counts) {
      const delta = count - (beforeCounts.get(method) ?? 0)
      if (delta > 0) {
        byMethod[method] = delta
        total += delta
      }
    }
    for (const [method, ms] of this.times) {
      const delta = ms - (beforeTimes.get(method) ?? 0)
      if (delta > 0) totalMs += delta
    }
    return { result, report: { total, totalMs, byMethod } }
  }
}

// ── the request seam: server/app.ts drives it, getStore() reads it ──

/** The flag is env-driven, never a code constant defaulting on (the
 *  configuration-over-hardcoding doctrine): any non-empty declared
 *  value enables the store phase; unset or blank keeps the
 *  zero-overhead posture. Declared per posture in wrangler [vars] or
 *  process env — absent everywhere today. */
export function serverTimingEnabled(env: Record<string, string | undefined>): boolean {
  return env.SERVER_TIMING !== undefined && env.SERVER_TIMING.trim() !== ''
}

/** The per-request counter scope. AsyncLocalStorage gives every
 *  measured request its OWN StoreCallCounter — exact attribution under
 *  concurrency — and is legal in BOTH postures: natively in node, and
 *  on the Worker under the deployment's nodejs_compat flag. (The
 *  2026-09-18 wire lesson: the earlier monotone-accumulator + delta
 *  design let a concurrent request's calls land in another's report —
 *  a single curl read 22 calls on an endpoint whose own cost is 2, and
 *  the misreading nearly refactored a healthy surface. An instrument
 *  that can misattribute by 10× is not a measurement.) */
const requestScope = new AsyncLocalStorage<StoreCallCounter>()

/** getStore()'s hook: the counting view of the store when the current
 *  async context carries a measured window; the store itself,
 *  unchanged, at every other moment (scripts, seeds, the flag-off
 *  world, unmeasured requests). The proxy caches per counter instance
 *  — one proxy per (request, store) pair, never per getStore() call. */
export function timedStore(store: ServerStore): ServerStore {
  const counter = requestScope.getStore()
  return counter ? counter.view(store) : store
}

/** The Server-Timing middleware's measurement window: a FRESH counter
 *  scoped to this request's async context, so the report answers
 *  exactly this request's calls — never a sibling's. */
export async function measureStorePhase<T>(run: () => Promise<T> | T): Promise<{ result: T; report: StoreTimingReport }> {
  const counter = new StoreCallCounter()
  return requestScope.run(counter, () => counter.measure(run))
}
