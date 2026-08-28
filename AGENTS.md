# AGENTS.md, OIML SMART Identity

Guidance for agent sessions working in this repository.

## What this repo is

The OIML SMART identity service: the OpenID Connect Provider (OP) at
https://id.oimlsmart.org, extracted from the `oimlsmart/smart` monorepo
(the extraction map: smart's `PROGRESS/41-identity-extraction-map.md`;
the program: smart's `TODO.identity-extract/`). The OP half of the
identity contract lives here; the RP half stays with the platform (every
platform instance is an RP of this OP).

The shared server machinery (the store seam, the instance profile, the
mailer, RBAC, the OIDC/OAuth client cones, the role vocabulary, and the
canonical D1 migration set) is the kernel package
`@oimlsmart/platform-server`, owned by its own repository
(`oimlsmart/platform-server`, extracted from the smart monorepo in
TODO.repos/01 with the package's history) and consumed from npm by
semver (`^0.1.2`): the version pin IS the contract between the repos.
ZERO store-implementation code lives here.

## Command gates (all must stay green)

```
cd browser && npx vue-tsc --noEmit     # type check (islands + vue-pages)
cd browser && npx astro check          # .astro route shells + layouts
cd browser && npx vitest run           # unit tests (vitest.config.ts)
cd browser && npm run build            # astro production build (node adapter)
cd browser && npm run build:cloudflare # the Workers bundle (the deploy artifact)
cd browser && npx vitest run --config vitest.e2e.config.ts e2e/op-surface-contract.e2e.ts
cd browser && npm run test:e2e         # the identity e2e legs (each boots its own stack)
```

The contract gate (the last-but-one line) is the pre-deploy gate: the
OIDC surface (discovery, JWKS, the claims shape, the error taxonomy)
deep-compares against the committed golden
(`e2e/golden/op-surface-contract.golden.json`); a surface break fails
before it can reach a relying party.

## Rules

- **The account registry never moves.** The live D1
  (`oiml-smart-platform-identity`) is owned by THIS repo's deployment
  since the wave-03 cutover (2026-08-24, tag `id-v2026.08.24-1`); the
  monorepo's OP code is inert pending the wave-04 retirement. The
  migration set ships in the kernel package
  (`node_modules/@oimlsmart/platform-server/migrations`, the
  `migrations_dir` in `browser/wrangler.toml`) and wrangler keys the
  bookkeeping on filenames: future files append expand-only in the
  KERNEL repo, never renumber, and a kernel bump lands here as a normal
  dependency PR.
- **The issuer is load-bearing.** `OP_ISSUER=https://id.oimlsmart.org`
  in production: every RP's `OIDC_ISSUER` and every token's `iss` name
  it. Never repoint it outside the cutover plan.
- **Deploys are deliberate acts.** Only an `id-v*` tag runs
  deploy-identity.yml (contract gate, the identity e2e legs, the preview
  environment, then production on required reviewers). Never add a
  branch-push deploy trigger.
- **The kernel is consumed by semver, never vendored.** Changes that
  need store/profile/mailer machinery land in
  `oimlsmart/platform-server` and arrive here as a version bump, never
  as copies here.
- **No secrets in the repo.** `OP_SIGNING_KEY`, `MAIL_PROVIDER_KEY`,
  the upstream-provider client pairs: Worker secrets, declared with
  `wrangler secret put`. The runbooks name them; the code never carries
  them.
- Run the command gates above before declaring a change done.
- Do not commit or perform other git mutations unless explicitly asked.

## The ops doctrine

- Operations runbook: `docs/deployment/identity-operations.md`.
- Deploy runbook (the staged rollout, the one-time setup, rollback):
  `docs/deployment/identity-deploy.md`.
- Self-host runbook (posture b: a third party's own OP on their domain,
  Node + SQLite or Workers + D1 on a non-estate account, proven by
  `browser/e2e/id-16-selfhost.e2e.ts`):
  `docs/deployment/identity-self-host.md`.
- The upstream identity providers (GitHub/Google/Apple/Entra setup):
  `docs/deployment/identity-upstreams.md`.
- The RP integration guide (consumed by every OIML SMART instance):
  `docs/integration/identity-service.md`.
