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
// PER-REQUEST ATTRIBUTION, honestly scoped: the counter is a
// MONOTONE per-process accumulator and each request measures a
// snapshot DELTA (the gate's own measure() primitive — the same
// instrument, DRY). AsyncLocalStorage would give exact attribution
// under concurrency but is a node builtin, off-limits in this
// worker-safe layer; a per-request resettable slot would RACE under
// concurrent in-flight requests in one isolate (a later request's
// begin would clobber an earlier one's counter mid-flight). The
// monotone-delta form never loses or double-resets anything: under
// concurrency a request's report may include a concurrent request's
// calls — a diagnostic posture's honest tolerance, never a billing
// meter. The flag is off by default and on only for measurement
// sessions.
//
// WORKER-SAFE: no node built-ins — the Worker bundle carries this
// module whole.
// ═══════════════════════════════════════════════════════════════════

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
 *  middleware measures each request through the module's own
 *  accumulator below. One instance, one monotone set of totals. */
export class StoreCallCounter {
  private counts = new Map<string, number>()
  private times = new Map<string, number>()
  private depth = 0

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

/** The module's own monotone accumulator — created at module load (an
 *  empty pair of maps, no cost until a counted call lands) and NEVER
 *  reset: per-request numbers are snapshot deltas, which is what makes
 *  concurrent measured requests lose nothing. */
const counter = new StoreCallCounter()

/** Whether a measured request window is currently in flight (set for
 *  the duration of measureStorePhase below). getStore() resolves
 *  through the counting proxy ONLY while this is true — outside a
 *  measured window (scripts, seeds, the flag-off world) the installed
 *  store passes through untouched. */
let measuring = false

/** The cached proxy per wrapped store instance, so the flag-on world
 *  allocates one proxy per installed store, not one per getStore()
 *  call. The Worker installs a fresh D1 store per request; the cache
 *  rotates with it. */
let proxyFor: ServerStore | null = null
let proxy: ServerStore | null = null

/** getStore()'s hook: the counting view of the store while a
 *  SERVER_TIMING-measured request is in flight; the store itself,
 *  unchanged, at every other moment. */
export function timedStore(store: ServerStore): ServerStore {
  if (!measuring) return store
  if (proxyFor !== store || proxy === null) {
    proxyFor = store
    proxy = counter.wrap(store)
  }
  return proxy
}

/** The Server-Timing middleware's measurement window: engage the
 *  counting view for the duration of the request, then answer the
 *  request's store-call delta. The window is the middleware closure's
 *  own span — the per-request scoping lives here. */
export async function measureStorePhase<T>(run: () => Promise<T> | T): Promise<{ result: T; report: StoreTimingReport }> {
  measuring = true
  try {
    return await counter.measure(run)
  } finally {
    measuring = false
  }
}
