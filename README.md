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
  `auth/passwords.ts`, `auth/org-registry.ts`) — including the
  strong-authentication half (TODO.identity-sso/02+03: `auth/op/totp.ts`,
  `auth/op/webauthn.ts`, `auth/op/recovery.ts`, `auth/op/factors.ts`),
- the OP routers (`browser/server/routes/op*.ts` — the protocol, the accounts, the upstream providers, the join intake, the memberships, the registry) plus the factor registry's console API
  (`routes/op-factors.ts`) and the sign-in's second-factor + passwordless
  half (`routes/op-mfa.ts`),
- the OP pages (sign-in, consent, enrollment, the account console, the
  admin consoles) under `browser/src/pages/` + `browser/src/vue-pages/`,
- the OP-side unit suites and e2e legs (`browser/src/__tests__/`,
  `browser/e2e/`), including the OIDC-surface contract gate,
- the operations scripts (`browser/scripts/op-*.ts`) and the ops
  workflows (deploy gate, heartbeat, access review).

What it deliberately does NOT carry: the store implementations, the
profile/RBAC/OIDC-client machinery, and the D1 migration set. Those are
the published kernel package `@oimlsmart/platform-server` (its own
repository, `oimlsmart/platform-server`; TODO.repos/01 in smart),
consumed from npm by semver — the version pin is the contract. The live
account registry (`oiml-smart-platform-identity`, D1) never moves, and
wrangler keys migration bookkeeping on filenames, so the package's set
appends expand-only and never renumbers.

## Develop

```sh
cd browser
npm ci           # the kernel comes from npm
npm run dev      # astro on :5190 + the node API on :3190
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

## Self-host

Running this service as YOUR OWN OP on your own domain (your users, your
registry, your keys) is a configuration act, never a code change — the
runbook (Node + SQLite and Workers + D1 on a non-estate account, the
bootstrap admin, the degradation story, the upgrade path):
`docs/deployment/identity-self-host.md`. Its executable proof:
`browser/e2e/id-16-selfhost.e2e.ts`.
