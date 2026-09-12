# TODO.restructure/28 — the agent-execution program

**Priority:** P1 · **Status:** COMPLETE (2026-09-12) — executed as
written: each workstream = one agent, one branch, one PR; the gates
were the arbiter; **NO agent merged** (the orchestrator squash-merged
each in CI-green order, main's post-merge run green after each). The doctrine every agent inherits (verbatim): reads may
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

## Landed (2026-09-12)

- **A → #92** (squash 14:02Z, main 65a6dd4): `AUDIT_RETENTION_DAYS`
  config-gated purge — `server/audit-retention.ts` +
  `scripts/op-audit-retention.ts` (dry-run default, serial deletes)
  + the nightly `identity-audit-retention.yml` (23:53 UTC, after the
  23:41 backup so purged rows survive that night's R2 snapshot) + six
  dashboard surfaces honest under both flag states + a 14-case spec.
  ONE CORRECTION to the plan's own text: this file's
  "identity-operations.yml" named a workflow that never existed on
  any ref — a conflation of the ops DOC's name; the workflow landed
  concern-named per repo convention. Owner acts to enable: the repo
  variable + the Worker var of the same name (both or neither) + the
  `cloudflare-identity-retention` environment secrets.
- **B → #90** (squash 13:48Z): the e2e pack runs two balanced shards —
  e2e stage 14m35s → 7m51s (−46%, run 34697043497; shards 41s apart;
  40 legs = 19+21 by measured duration). The shared-server rule
  verified VACUOUS: every E2E_BASE_URL ref is a self-contained
  comment — any leg may live in either shard.
- **C → #91** (squash 14:01Z): the counting facade is production code
  (`server/store-timing.ts`, worker-safe) behind `SERVER_TIMING` —
  `app;dur=X, store;dur=Y;desc="N calls"` in ONE comma-joined header
  when set; byte-identical minimal form when unset (default OFF). The
  gate re-exports the same facade (DRY, budgets unchanged).
- **E → #93** (squash 14:27Z): `D1_REPLICA_READS=1` (exactly '1',
  ships OFF) routes the store's statements through ONE
  `withSession('first-primary')` per store INSTANCE — verified
  against the live Cloudflare docs (sequential consistency,
  read-my-own-writes; 'first-primary' pins only the first query).
  Preview-first rollout documented; wrangler.toml untouched.
- **D → #94** (squash 15:29Z): the SQLite cone goes instance-shaped —
  143 verbs db-parameterized, `SqliteServerStore` mirrors the D1
  class, `createSqliteStore(path)` is the factory, the
  default-instance shims keep every caller untouched; the
  whitelabel-federation spec's spawned-central hack became a second
  IN-PROCESS instance (the refactor's whole point, proven).
- **Named follow-ups** (each named in its PR, none smuggled in): the
  per-REQUEST D1 session (unlocked by D's instance state, still
  blocked on the module-global installStore seam — which D's
  federation proof showed needs save/restore under nested installs);
  and the OWNER's flag flips (retention vars+secrets, replica-reads
  preview cycle, SERVER_TIMING in prod) and deploy tags — never ours.
- **Program note**: the `isolation: worktree` spawn did not isolate
  every agent (two shared one checkout and collided once; repaired,
  no work lost). Every later brief carried explicit worktree
  verification and directory ownership. Recorded in the session
  memory for future dispatches.
