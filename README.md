# OIML SMART Identity

The OIML SMART identity service: the OpenID Connect Provider (OP) at
https://id.oimlsmart.org, extracted from the `oimlsmart/smart` monorepo
(the extraction map: smart's `PROGRESS/41-identity-extraction-map.md`).

**Deployment state (2026-08-24): this repository's build serves
production.** The wave-03 cutover deployed tag `id-v2026.08.24-1` to
the `oiml-smart-platform-identity` Worker over the unchanged account
registry (the D1 never moved); the monorepo's OP code is inert pending
the wave-04 retirement. The preview posture lives at
https://id-preview.oimlsmart.org (the deploy gate's first stop).

This repository carries the OP half of the identity contract only:

- the OP domain modules (`browser/server/auth/op/`, `auth/upstream/`,
  `auth/passwords.ts`, `auth/org-registry.ts`),
- the five OP routers (`browser/server/routes/op*.ts`),
- the D1 migrations (`browser/server/db/migrations/`), byte-identical
  with the monorepo's set: the live account registry
  (`oiml-smart-platform-identity`, D1) never moves, and wrangler keys
  migration bookkeeping on filenames, so the set appends expand-only
  and never renumbers,
- the OP pages (sign-in, consent, enrollment, the account console, the
  admin consoles) under `browser/src/pages/` + `browser/src/vue-pages/`,
- the OP-side unit suites and e2e legs (`browser/src/__tests__/`,
  `browser/e2e/`), including the OIDC-surface contract gate,
- the operations scripts (`browser/scripts/op-*.ts`) and the ops
  workflows (deploy gate, heartbeat, access review).

What it deliberately does NOT carry: the store implementations, the
profile/RBAC/OIDC-client machinery. Those are the published kernel
package `@oimlsmart/platform-server` (owned by the smart monorepo). While
the first npm publish is pending, this repo consumes it through the
sibling-checkout `file:` dependency the CI declares at
`x/oimlsmart/smart` (the same `x/` doctrine smart's CI uses for the
SST positions).

## Develop

```sh
# the kernel checkout (until @oimlsmart/platform-server is on npm):
git clone --branch v2 git@github.com:oimlsmart/smart.git x/oimlsmart/smart
npm --prefix x/oimlsmart/smart/packages/platform-server ci --no-audit --no-fund

cd browser
npm ci
npm run dev        # astro on :5190 + the node API on :3190
```

## The gates (CI runs all of them)

```sh
cd browser
npx vue-tsc --noEmit
npx astro check
npx vitest run
npm run build
npx vitest run --config vitest.e2e.config.ts e2e/op-surface-contract.e2e.ts
npm run test:e2e   # the identity e2e legs (each boots its own stack)
```

## Deploy

Deploys are tag-gated deliberate acts: an `id-v*` tag runs
`.github/workflows/deploy-identity.yml` (contract gate, the identity
e2e legs, build, the preview environment, then production on the
environment's required reviewers). The runbook:
`docs/deployment/identity-deploy.md`; operations:
`docs/deployment/identity-operations.md`; Relying Party integration:
`docs/integration/identity-service.md`.
