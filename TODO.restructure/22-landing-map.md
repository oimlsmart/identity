# TODO.restructure/22 — the landing map: the tree into commits, the owner acts

**Priority:** P0 (the program's last executable act — the owner's "Do all
of this! Do not hold off", 2026-09-10)
**Status:** COMPLETE — executed as written below.

## The law this lands under

Branch → commits → push → PR. NEVER main, NEVER a tag, NEVER
`git add -A` — every commit staged by explicit path with the staged set
verified before each commit. No AI attribution anywhere.

## The commit map (the wave order; review units, gate-green at the head)

1. **The split** — `browser/server/{store*,context,profile*,mailer,oidc,
   github,session,client-info,rbac*,vocab*}`, `browser/migrations/`,
   `package.json`, `package-lock.json`, `wrangler.toml`,
   `AGENTS.md`, `CLAUDE.md`, `README.md`. The machinery, the journal,
   the pin's death, the doctrine.
2. **The API core** — every `browser/server/routes/*.ts` + `auth/*` +
   `app.ts` + `rate-limit.ts` + `blobs*` + `serve.ts`/`index.ts`/
   `cloudflare.ts` + `signin-panels.json` + `import-org-registry.ts` +
   `seed-org-register.ts` (the import rewrite + the perf batches +
   self-registration + the whitelabel projection, one compiling unit).
3. **The whitelabel assets** — `browser/profiles/` +
   `docs/deployment/identity-whitelabel.md`.
4. **The catalogs** — `src/i18n/en.ts` + `fr.ts` (~290 keys).
5. **The pages** — every `src/vue-pages/**` + `src/pages/**` +
   `src/components/ConsoleChrome.vue` + `src/branding.ts` +
   `src/org-vocabulary.ts` + `src/lib/api-client.ts` +
   `src/astro/app-entrypoint.ts`.
6. **The specs** — the new/re-homed tests (`id-self-registration`,
   `id-whitelabel`, `id-whitelabel-federation`, `migrations`,
   `store-bulk-posture`) + `e2e/id-37-register.e2e.ts` + the two
   MIGRATIONS_DIR test fixes + `ci.yml` + every touched existing test.
7. **The program record** — `TODO.restructure/` + `CLAUDE.md` (if not
   already in 1). `x/` is NOT ours: untracked, untouched, never staged.

## The kernel repo (its own branch, no push)

`op-cone-bulk-reads` — one commit preserving the six bulk-read files
(seam, sqlite ×2 + wiring, d1, the parity test). Reference value for
the owner's diet wave; no version bump, no publish — the owner's acts.

## The owner acts that remain after this (standing law, never delegated)

- The kernel's diet wave (15 wave 5) at the owner's version call.
- The `id-v*` deploy tag when the PR merges.
- The remote read-only `wrangler d1 migrations list` before/after check
  at the first post-split deploy.
