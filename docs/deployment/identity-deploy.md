# Deploying the identity service (the deliberate act)

> CANONICAL LOCATION: this document moved to `oimlsmart/identity`
> at the wave-02 extraction (the code it describes lives here). The
> smart monorepo's copy becomes a pointer page in wave 04.

The OIDC Provider at `id.oimlsmart.org` (the
`oiml-smart-platform-identity` Worker) deploys **only on a deliberate
act**: an `id-v*` tag push or a manual dispatch of the
`deploy-identity` workflow. A merge to `main` never carries the OP (the
platform hub's auto-deploy lives in the monorepo's
`deploy-cloudflare.yml`, with a different trigger).

This page is the exact procedure. The operating plan it implements is
[docs/deployment/identity-operations.md](identity-operations.md)
(both live here since the wave-02 extraction; its
"Deploy discipline" section cites this one). The rotation ceremony for
the signing key is scripted (`browser/scripts/op-key-rotate.ts`) and
documented below.

## The pipeline (`.github/workflows/deploy-identity.yml`)

Triggered by an `id-v*` tag or Actions → deploy-identity → Run
workflow. The jobs, in order:

1. **contract-gate**: the OIDC-surface golden test
   (`e2e/op-surface-contract.e2e.ts`) boots the identity-profile API
   from the tagged tree and deep-compares the captured surface (the
   discovery document, the JWKS shape, the claims contract, the error
   taxonomy) against the committed golden
   (`browser/e2e/golden/op-surface-contract.golden.json`). A breaking
   change fails here, before it can reach a Relying Party.
2. **identity-e2e**: the identity e2e legs (`e2e/id-01…id-10` plus the
   contract leg) against the tagged tree, the same harness as the CI
   e2e job.
3. **build**: the Workers bundle (`npm run build:cloudflare`).
4. **deploy-preview**: D1 migrations for the preview database, the
   preview deploy (`[env.identity-preview]` →
   `id-preview.oimlsmart.org`), the custom-domain attach, then the
   OIDC-surface probe against the deployed preview URL.
5. **deploy-production**: gated by the `cloudflare-identity-production`
   environment's required reviewers (the manual approval **is** the
   production gate). D1 migrations, the deploy, the domain attach, then
   the surface probe against `https://id.oimlsmart.org`.

Deploys serialize (`concurrency: deploy-identity`, never cancelled
mid-flight).

## One-time setup

Once per deployment programme (the workflow header carries the same
checklist). State as of 2026-08-24 (the wave-03 deploy prep): items 1
and 2 are DONE; the first `id-v*` tag run proves the declared
Cloudflare token end to end.

1. **The preview database** (DONE 2026-08-24, PR #8): `cd browser &&
   npx wrangler d1 create oiml-smart-platform-identity-preview`, paste
   the issued `database_id` into `browser/wrangler.toml`'s
   `[env.identity-preview]` block (replacing the zero-UUID placeholder)
   and commit. The preview deploy job refuses to run while the
   placeholder stands.
2. **The GitHub environments** (DONE 2026-08-24): create
   `cloudflare-identity-preview` and `cloudflare-identity-production`
   (both exist; production carries the required-reviewers rule). On
   **both**, the secrets `CLOUDFLARE_API_TOKEN` (Workers Scripts:Edit
   + D1:Edit on the account) and `CLOUDFLARE_ACCOUNT_ID` are declared
   (the coordinator's act at the wave-03 prep; the first tag run
   proves them end to end). On `cloudflare-identity-production`,
   **required reviewers** are the manual approval; on
   `cloudflare-identity-preview`, the variable `IDENTITY_PREVIEW_URL`
   is `https://id-preview.oimlsmart.org`.
3. **The signing keys** (one ES256 pair per environment, never shared):
   run the rotation ceremony
   (`browser/scripts/op-key-rotate.ts`, below) with `--env identity`
   and `--env identity-preview` to generate and declare each
   environment's `OP_SIGNING_KEY` secret. The private material never
   lands in the repo, the database, or a log. (State 2026-08-24:
   production's key is account-side Worker state from the monorepo
   era and no code deploy disturbs it; the preview's first ceremony
   runs with the first preview deploy.)
4. **The preview domain** (first preview deploy only): the workflow's
   domain step attaches `id-preview.oimlsmart.org` via
   `browser/scripts/cloudflare-domains.sh`; the DNS record for the
   hostname is a one-time Cloudflare dashboard act (the same posture as
   the other instances, the monorepo’s cloudflare.md (https://github.com/oimlsmart/smart/blob/v2/docs/deployment/cloudflare.md)).
5. **Optional**: to extend the deployed-surface probe with the
   known-client refusal legs, declare `OP_CONTRACT_KNOWN_CLIENT_ID` +
   `OP_CONTRACT_KNOWN_REDIRECT_URI` (a registered client's id and one
   of its exact redirect URIs) as variables on
   `cloudflare-identity-production`, and the `OP_CONTRACT_PREVIEW_*`
   pair on the preview environment. Undeclared, those legs skip
   honestly and the public legs still run.

## The release act

```bash
git fetch origin main
git tag id-v2026.08.23-1 origin/main        # date + ordinal of the day
git push origin id-v2026.08.23-1
```

Then watch the run: `gh run list --workflow deploy-identity`. The
production job pauses for the environment approval; approve in the
Actions UI when the preview stage is green. The run ends with the
surface probe against `https://id.oimlsmart.org` as the deployment
proof.

What to tag: the identity service is a deployment profile of the one
build, so any `main` commit is deployable; tag a commit whose CI is
green (the workflow re-proves the identity legs itself, so a red trunk
does not block a deliberate identity release).

## Rollback

The Worker keeps its deployment history; the migration contract (below)
keeps the database readable by the previous version.

```bash
cd browser
npm run build:cloudflare                                   # the composed config needs dist/
npx tsx scripts/deploy-instance.ts identity --compose-only # writes dist/server/wrangler.identity.json
npx wrangler rollback --config dist/server/wrangler.identity.json
# or to a known deployment id:
npx wrangler rollback <deployment-id> --config dist/server/wrangler.identity.json
```

Then re-prove: `npx tsx scripts/op-surface-contract.ts probe
https://id.oimlsmart.org`.

**The migration contract**: migrations under
`browser/server/db/migrations/` are expand-only (new tables, new
columns with defaults, never a drop or a narrowing rename) and anything
destructive waits for a two-release overlap, so a rollback never meets
a schema it cannot read. The workflow applies migrations forward only;
a rollback never migrates back.

## Key rotation (the ceremony)

Cadence: quarterly, and immediately on suspicion of compromise. The
ceremony is a script, not a hand-edit:

```bash
cd browser
# 1. Generate the successor pair + print the ceremony (touches nothing):
npx tsx scripts/op-key-rotate.ts rotate --env identity

# 2. The same run with --apply pipes the private JWK to
#    `wrangler secret put` itself (stdin, never argv, never a file):
npx tsx scripts/op-key-rotate.ts rotate --env identity --apply

# 3. The overlap assert (also the tail of a --apply run): the JWKS must
#    advertise BOTH the incumbent kid(s) and the new kid before the old
#    row may retire:
npx tsx scripts/op-key-rotate.ts verify --url https://id.oimlsmart.org \
  --expect-kids <oldKid>,<newKid>
```

The script prints the retirement note: after the longest token lifetime
plus margin (the access-token TTL and the RP-side JWKS cache are both
one hour, so 24 hours is the calm margin), retire the old row by the
admin act:

```bash
npx wrangler d1 execute oiml-smart-platform-identity --remote \
  --command "UPDATE oidc_keys SET status='retired', retired_at=datetime('now') WHERE kid='<oldKid>'"
```

JWKS serves every `active` row, so in-flight ID tokens keep validating
through the overlap; a retired row leaves the JWKS answer and tokens
signed with it fail validation at the RPs' next JWKS fetch (their cache
TTL is one hour, `JWKS_TTL_MS` in `@oimlsmart/platform-server/oidc`).

**Compromise**: rotate immediately (`--apply`), then retire the
compromised row at once (the same SQL, no margin; in-flight tokens die
within the RPs' one-hour JWKS cache), then review the audit trail
(`auditEvents`) for the window.

## The standing gates around the deploy

- Every PR runs the contract gate as part of the e2e suite
  (`e2e/op-surface-contract.e2e.ts` rides `npm run test:e2e`).
- The heartbeat (`.github/workflows/identity-heartbeat.yml`) probes the
  live surface every 15 minutes and opens a standing issue on red.
- The access review (`.github/workflows/identity-access-review.yml`,
  dispatch-only) answers "who holds OP admin" from the live registry.
