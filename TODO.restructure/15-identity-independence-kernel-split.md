# TODO.restructure/15 — identity's independence: the kernel split

**Priority:** P0 (architecture — the owner's approved direction, 2026-09-10:
"the identity server should be fully independent and provide an API for
the other services")
**Status:** WAVES 1–4 + 6 COMPLETE (2026-09-10, executed as one working-
tree change for the owner to review/commit; the wave boundaries below
are the commit-split guide):
- Wave 1+3 DONE — the kernel's OP cone copied verbatim at 0.2.13
  (working tree, carrying the bulk reads) into `server/` (28 files);
  all 105 import sites rewritten to relative paths; the TODO 06 swap
  landed for real; the three budgets DELETED.
- Wave 2 DONE — 32 migrations copied byte-identical (`diff -q` clean)
  into `browser/migrations/`; the three `migrations_dir` sites
  repointed; the schema-mirror test re-homed
  (`src/__tests__/migrations.test.ts`); the two test-side MIGRATIONS_DIR
  resolvers repointed at the repo's own set.
- Wave 4 DONE — the dependency REMOVED from package.json;
  `bcryptjs@3.0.3` direct (the one transitive); `node_modules/@oimlsmart`
  holds only `site-shell`; grep-clean of real kernel imports.
- Wave 6 DONE — AGENTS.md/CLAUDE.md/README/wrangler doctrine rewritten.
- Wave 5 REMAINS (owner-coordinated, in the kernel repo): the OP cone's
  removal there + its version bump + the monorepo's own wave. The
  kernel's uncommitted bulk-read work is now REDUNDANT (identity carries
  it); keep or drop at the owner's discretion.
Proof: vue-tsc clean, astro check 0/0, FULL SUITE 575/575 (571 prior +
the bulk-parity 2 + the migrations-mirror 2 — the scaling gate WITH ZERO
BUDGETS), both builds green, op-surface-contract golden UNTOUCHED.
The remote read-only `wrangler d1 migrations list` comparison remains
the pre-deploy gate (named in the waves below).

## The decision this reverses, deliberately

TODO.repos/01's extraction doctrine ("one shared kernel, consumed by
semver, zero store code in consumers") was the transition's cost-saver.
Post-cutover it is historical scaffolding: every platform instance is an
RP that validates identity's tokens STATELESSLY — the platform never
reads identity's tables. The API half of independence is already true
(services see only the OIDC surface + the public feeds); this TODO
completes the machinery half. Also closes the coupling cost TODO 06
exposed (a trivial store verb cost a cross-repo release dance).

## The measured evidence (2026-09-10)

- **The dependency surface**: 15 kernel subpaths imported — `store` (87
  sites), `store/sqlite` (73), `profile` (88+node 1), `oidc` (36),
  `vocab` (17), `session` (17), `mailer` (16), `rbac` (6+node 1),
  `client-info` (5), `github` (3), `store/d1` (2).
- **~137 distinct store verbs** called by identity's server code (the
  seam is fat; the platform-only verb families ride along unused).
- **30 migration files** (0001..0030) — filenames ARE the live D1's
  `d1_migrations` journal keys.
- **The monorepo's OP-cone usage is TESTS ONLY** (d1-store,
  federation-registration, seed-core-slices) — its OP server code is
  inert pending the wave-04 retirement. The diet is a MOVE, not a
  duplication.
- **The swap is atomic by construction**: identity programs solely
  through `getStore()` / `installSqliteStore()` / the D1 binding — the
  routers never import store implementations.

## The end-state

Zero `@oimlsmart/platform-server` imports. Identity owns: the store
implementations (D1 + SQLite), the migration set (its journal), the
session seam, the mailer adapters, its profile/RBAC/vocabulary needs.
The kernel slims to the platform cone (its migration files STAY — they
anchor the monorepo fleet's journals). Other services change nothing.

## The waves (each: gates green → owner merges)

- **Wave 1 — identity's own store module** (`browser/server/store/`):
  copy the kernel's store implementations WHOLESALE at 0.2.10
  (provenance-noted; worker-safety rules carry verbatim), swap the two
  composition roots' imports (`server/index.ts`, `server/cloudflare.ts`).
  The bulk-read work already proven in TODO 06 re-homes HERE — no kernel
  release ever needed; TODO 06's staged diff dissolves into this wave.
  Parity proof: the endpoint-scaling gate's counting facade + the
  bounded-write (StoreUnavailable) suites over the new module.
  Pruning the platform-only verb families is a LATER cleanup PR, never
  this wave (whole-copy first, surgery second).
- **Wave 2 — the migrations**: copy the 30 files VERBATIM (filenames
  never touched) into `browser/migrations/`; repoint `migrations_dir`
  in `browser/wrangler.toml`. Proof: `wrangler d1 migrations list
  --local` AND the read-only remote listing show the identical applied
  set before/after.
- **Wave 3 — the small seams**: session, client-info, the mailer
  adapters, vocab constants, rbac + its node loader, profile + node
  loader, the oidc validators (test-side). Each a small copy; the
  catalogs stay untouched.
- **Wave 4 — the pin dies**: `package.json` drops the dependency;
  `grep -r "@oimlsmart/platform-server" browser/` → empty.
- **Wave 5 — the kernel's diet** (in `oimlsmart/platform-server`, its
  own version bump + the monorepo's own wave): remove the OP-cone
  store methods + their tests. The kernel's migration files STAY (the
  monorepo's journal anchor). The monorepo's three OP-cone test files
  follow its wave-04 retirement.
- **Wave 6 — the doctrine rewrite**: identity's AGENTS.md/CLAUDE.md/
  README + the deploy runbooks (the kernel references become own-store
  references); the kernel's AGENTS.md gains the single-consumer note.

## The named risks (each has its proof above)

1. **Journal preservation** — filenames are the keys; verbatim copy;
   the before/after listings are the gate.
2. **Behavior parity** — the bounded-write budget (StoreUnavailable)
   and the scaling gate's counting facade must behave identically over
   the new module; both suites are the proof, run in wave 1.
3. **Schema divergence after the split** — identity's D1 and the
   monorepo's D1s append their OWN migrations from 0031 onward; the
   fleets are separate, the divergence is deliberate, and this file is
   its record.
4. **The third repo** — the kernel's diet bumps a version the SMART
   MONOREPO pins; its switch is its own wave, never simultaneous.

## Acceptance (the whole TODO)

- `grep -r "@oimlsmart/platform-server" browser/` → empty; both builds
  green; the full unit suite; `id-16-selfhost.e2e.ts` green in CI (the
  SQLite posture proven kernel-free); the op-surface-contract golden
  UNTOUCHED (the wire surface never moves); the journal listings
  identical.

## What the owner does

Merge each wave on green; name the kernel-diet version (the monorepo's
wave follows); the `id-v*` deploy tag when identity ships the split.
