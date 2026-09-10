# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repo is

The OIML SMART identity service: the OpenID Connect Provider (OP) at
https://id.oimlsmart.org, extracted from the `oimlsmart/smart` monorepo. This
repo carries the **OP half only** of the identity contract (the routers, pages,
auth flows, e2e legs, ops scripts). The RP half stays with the platform.

**Independent since TODO.restructure/15 (2026-09-10):** identity carries its
OWN server machinery — the store implementations (`server/store/`, D1 +
SQLite), the migration set (`browser/migrations/`, filenames = the live D1's
journal keys), and the supporting seams (profile, RBAC, mailer, session,
client-info, vocab, OIDC validators) — copied verbatim from the
`@oimlsmart/platform-server` kernel at 0.2.13. No npm dependency on the
kernel remains; other services consume identity only via its OIDC/API
surface.

AGENTS.md (repo root) carries the same doctrine with more detail and is kept in
sync; the `docs/deployment/` runbooks are authoritative for operations.

## Commands

Everything runs from `browser/`:

```sh
cd browser
npm ci           # no kernel: identity is self-contained
npm run dev      # astro on :5190 + the node API (tsx watch server/serve.ts) on :3190
```

### The gates (CI runs all; all must stay green)

```sh
cd browser
npx vue-tsc --noEmit          # type check (islands + vue-pages)
npx astro check               # .astro route shells + layouts
npx vitest run                # unit suite (vitest.config.ts)
npm run build                 # astro production build (node adapter)
npm run build:cloudflare      # the Workers bundle (the deploy artifact)
npx vitest run --config vitest.e2e.config.ts e2e/op-surface-contract.e2e.ts   # the OIDC-surface contract gate (pre-deploy)
npm run test:e2e              # the identity e2e legs
```

Run a single unit test file: `npx vitest run src/__tests__/id-home.test.ts`
(or `-t 'some case name'` for one case).

Run a single e2e leg: `npx tsx scripts/e2e-run.ts e2e/id-01-op.e2e.ts`
(no args = the full serial set; each file gets its own vitest invocation and a
`/api/dev-reset` reseed, so legs are hermetic).

Endpoint-scaling gate (see Invariants): `npx vitest run
src/__tests__/endpoint-scaling.test.ts`; per-leg store-call counts table with
`ENDPOINT_SCALING_REPORT=1`.

## Architecture

**Two composition roots, one app factory.** `server/app.ts` builds the OP-only
Hono app (the `server/routes/op*.ts` routers, `routes/auth-lean.ts` as the
session/demo seam — NOT the platform's RP router, `/api/health`, the OP-surface
rate limiter). It is mounted by:

- `server/index.ts` — the node posture (self-host + the e2e stacks): SQLite
  store via `installSqliteStore` (`server/store/sqlite`), demo accounts
  auto-seeded, `dev-reset` mounted in dev.
- `server/cloudflare.ts` — the Worker posture (production): the D1 store from
  the env binding, never auto-seeded.

Everything `app.ts` pulls must stay worker-safe portable TS — no node built-ins
in `server/*.ts`; `better-sqlite3` stays behind the store seam
(`server/store/sqlite`, node-only — imported solely by `server/index.ts` and
the tests).

**Dual posture request routing.** In production one Worker serves everything:
the OP API endpoints answer inside the Worker via the catch-alls
`src/pages/op/[...path].ts` and the `/api` shim. In node dev, Astro's server
proxy (`astro.config.mjs`) forwards `/op` and `/api` to the tsx API on :3190
(static Astro routes always win over the proxy).

**Frontend = Astro shells + Vue islands.** Each page is a prerendered `.astro`
shell (`src/pages/`) that mounts one Vue island from `src/vue-pages/` through
`src/layouts/IdShell.astro` (no platform chrome on this host). Shared UI lives
in `src/components/`. The admin console pages are `src/pages/op/admin/*.astro`
mounting `src/vue-pages/op-admin-*.vue`; their data comes from the OP routers
(`server/routes/op-dashboard.ts`, `op-registry.ts`, `op-memberships.ts`, …).

**The store seam is identity's own** (`server/store.ts`): routes resolve the
store lazily through `getStore()`; the seam's bulk reads
(`listAllOrgMemberships`, `listUsers`, `countSignInMethodsBulk`,
`listIdentityLinksBulk`, …) are the instruments for list endpoints — the
endpoint-scaling gate proves their call counts invariant to row count. The
D1 migration set is `browser/migrations/` (the `migrations_dir` in
`browser/wrangler.toml`), append-expand-only, never renumber.

**E2E doctrine.** Legs run serial against one shared dev server;
`render-baseline.e2e.ts` runs first, and every flow file re-resets via
`/api/dev-reset` before running. The `op-surface-contract` golden
(`e2e/golden/op-surface-contract.golden.json`) deep-compares the public OIDC
surface (discovery, JWKS, claims shape, error taxonomy) — a deliberate surface
change requires re-recording the golden, never editing assertions to pass.

## Invariants

- **The account registry never moves.** The live D1
  (`oiml-smart-platform-identity`) is owned by this repo's deployment. The
  migration set is this repo's own (`browser/migrations/`); wrangler keys
  bookkeeping on filenames — append expand-only, never renumber.
- **The issuer is load-bearing.** `OP_ISSUER=https://id.oimlsmart.org` in
  production; never repoint outside the cutover plan.
- **Deploys are deliberate acts.** Only an `id-v*` tag runs
  `deploy-identity.yml` (contract gate → e2e legs → build → preview →
  production). Never add a branch-push deploy trigger. Never push tags or
  commit/push to main.
- **Endpoint scaling: a list endpoint's store-call count is invariant to row
  count.** Prefetch referenced sets once per request, group in memory, never
  `await` a store read inside a per-row loop (each call is a D1 round trip on
  the Worker — O(rows) calls is the disease). The gate
  (`src/__tests__/endpoint-scaling.test.ts`) proves it per endpoint per PR;
  budget exceptions are declared per leg (`budgetPerRow` + a named follow-up
  driving it to zero). Doctrine: `docs/deployment/endpoint-scaling.md`. Every
  new root-level GET list endpoint lands in the gate with the endpoint.
- **No secrets in the repo** — `OP_SIGNING_KEY`, `MAIL_PROVIDER_KEY`,
  upstream-provider client pairs are Worker secrets (`wrangler secret put`).
- Do not commit or perform other git mutations unless explicitly asked.
