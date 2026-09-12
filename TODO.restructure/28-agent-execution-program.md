# TODO.restructure/28 — the agent-execution program

**Priority:** P1 · **Status:** THE PLAN — dispatchable as written. Each
workstream = one agent, one branch, one PR; the gates are the arbiter;
**NO agent merges** (integration is sequential, after CI green, by the
orchestrator). The doctrine every agent inherits (verbatim): reads may
batch in parallel, WRITES stay serial on the store seam; configuration
over hardcoding; the kernel repo is untouchable; no AI attribution
anywhere; never `git add -A`; PR bodies via `--body-file`.

## Workstream A — journal retention (INDEPENDENT, agent-ready)

Branch `ops/journal-retention`. Implement a config-gated purge:
`AUDIT_RETENTION_DAYS` (unset = the current no-purge posture, the
dashboard's retention statement stays honest). A new
`scripts/op-audit-retention.ts` (the op-access-review.ts pattern: the
store seam, `listEntities`/paged delete of `auditEvents` older than N)
+ a step in `.github/workflows/identity-operations.yml` behind the same
var. Gates: a unit spec proving the cutoff math + the no-op default;
the full suite. The N default the owner sets in Worker vars — never
ours.

## Workstream B — e2e sharding (INDEPENDENT, agent-ready)

Branch `ci/e2e-shards`. `ci.yml`: the leg list splits into 2 matrix
jobs (`shard: [0, 1]`), each running its subset serially via the same
`e2e-run.ts` (it already takes files). Doctrine note encoded: legs are
file-hermetic (own vitest + dev-reset); the shared-server legs all live
in shard 0 (verify: any leg using `E2E_BASE_URL` without its own ports
stays in shard 0). Gates: BOTH shards green in CI; wall time ~halves.

## Workstream C — Server-Timing phase breakdown (INDEPENDENT, small)

Branch `perf/timing-phases`. The `StoreCallCounter` facade
(`endpoint-scaling.ts`) becomes production-safe behind `SERVER_TIMING`
env: when set, `getStore()` wraps the store in the counting proxy and
the middleware (already merged, #88) emits
`Server-Timing: store;dur=X;desc=N calls;total;dur=Y` per answer.
Default off — zero overhead posture preserved. Gates: a spec with the
flag on asserting the header; the suite with it off.

## Workstream D — the store instance refactor (SERIAL — after E)

Branch `refactor/store-instances`. `server/store/sqlite/store.ts`'s
module-global `_db` becomes instance state: `createSqliteStore(path)`
answers a `ServerStore` (the D1 class is already instance-shaped —
mirror it); `installSqliteStore()` remains as the default-instance
shim so no caller changes. Proofs: the whitelabel-federation spec
rewrites its spawned-central hack into a second in-process instance
(the refactor's whole point); the full suite.

## Workstream E — D1 replica reads (SERIAL — before D, env-gated)

Branch `perf/d1-replica-reads`. `server/store/d1.ts`: when
`D1_REPLICA_READS=1`, the store resolves `env.DB.withSession()` once
per request-context and routes READS through the replica bookmark;
writes and write-then-read sequences pin the primary (the withSession
bookkeeping discipline from Cloudflare's docs, current version —
VERIFY against the live docs before coding). **The verification gap,
encoded**: local suites run SQLite only; the D1 runtime proof is the
deploy pipeline — so the flag ships OFF, turns on in PREVIEW
(`[env.identity-preview]` vars) for one cycle, then production.
Acceptance: type-green + suite green + the flag documented in
identity-operations.md with the preview-first rollout.

## Dispatch order

B and C now (independent); A now; D after E lands (or E after D — one
at a time, same files); the orchestrator merges in CI-green order and
re-runs the full gate on main after each.
