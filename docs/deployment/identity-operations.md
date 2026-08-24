# Operating the identity service (the OIDC OP at id.oimlsmart.org)

> CANONICAL LOCATION: this document moved to `oimlsmart/identity`
> at the wave-02 extraction (the code it describes lives here). The
> smart monorepo's copy becomes a pointer page in wave 04.

The production discipline for the OIML SMART identity service: the OIDC
Provider (OP) plus its account registry, admin console, and upstream-IdP
linking. Terminology: the OP authenticates users and issues ID tokens;
every service trusting it is a Relying Party (RP) — the platform hub,
the NMI/TL/demo instances today, the estate's other services (the RAG,
future tooling) next.

The governing principle: the OP is the federation's single
authentication point. Every discipline below is blast-radius control
around that fact.

## Deploy discipline

- The id instance deploys only on a deliberate act: an `id-v*` tag or a
  workflow dispatch — never on a trunk merge. (The platform hub's
  auto-deploy on v2 push must never carry the OP.)
- Staged rollout: deploy the identity build to the preview environment,
  run the identity e2e legs against it, then production.
- Rollback: `wrangler rollback` plus the migration contract —
  expand-only migrations; nothing destructive without a two-release
  overlap, so a rollback never meets a schema it cannot read.
- The pre-deploy contract gate: a golden test of the OIDC surface (the
  discovery document, the JWKS shape, the claims contract, the error
  taxonomy) fails the pipeline before a break reaches an RP.

## Key management

One ES256 pair per deployment. The private key rides the
`OP_SIGNING_KEY` secret — never the repo, never the database, never the
logs. Its public half registers in the `oidc_keys` table on first use;
JWKS serves every active row, so a rotation never strands an in-flight
ID token, and old keys retire by an admin act after the token lifetime
has passed, never automatically mid-flight.

- The rotation ceremony is a script, not a hand-edit: generate the
  successor pair, declare the secret, JWKS advertises both, retire the
  old row after the longest token lifetime plus margin. Cadence:
  quarterly.
- The compromise runbook: revoke, rotate, and the RP-side effect (RPs
  re-fetch JWKS at their cache TTL — the number is written down), plus
  the comms template.
- Custody honesty: Workers run our code with the key material present;
  the trust boundary is the edge provider plus the review discipline.
  Non-exportable keys (KMS/HSM) are a later, evidence-driven wave.

## The account registry's data lifecycle

- Backups: a scheduled D1 export to an R2 bucket with retention, and a
  quarterly restore drill — an untested backup is a hope, not a backup.
- Offboarding: disable revokes sessions and blocks issuance while
  preserving the audit trail; delete is the erasure path and
  anonymizes. RP-side: existing sessions expire at their own lifetime;
  sensitive acts re-check (the approval queues already do).
- The admin audit log (every grant, rotation, offboarding) is retained
  and exportable — the scheme's peer-assessment habit makes the OP's
  own admin log audit evidence.

## Availability and monitoring

- The heartbeat, independent of the platform: a scheduled probe hitting
  the discovery document, JWKS, and a synthetic RP claim; a red probe
  opens or updates a standing issue (the demo-reset pattern).
- Degraded mode: existing RP sessions ride their own cookies (OP down
  does not mean logged out); new logins fail honestly on a plain status
  page; the demo instances' local demo accounts stay available as the
  clearly-marked development posture.
- The stated SLO: 99.9% monthly, measured by the heartbeat.

## Security practice

- The identity e2e legs are the named pre-deploy gate.
- The token endpoint is rate-limited; PKCE is enforced everywhere; the
  redirect-URI registry is exact-match.
- The quarterly access review: a script answers "who holds OP admin"
  from the registry, posted for review.
- The OP's dependency cone stays minimal and listed.
- Upstream-IdP onboarding (GitHub today; the member bodies' identity
  providers next) is a config act with this runbook's page, never a
  code change.

## The repo question

The identity service is a deployment profile of the smart monorepo
(`browser/server/auth/op/` plus its migrations and the account
console), deployed as the id instance: its own Worker, D1, domain,
secrets. The OP and the RPs are two ends of one contract; the
monorepo's CI proves both ends in one harness. The deploy gate above
gives the operational separation without losing that lockstep proof.

The extraction trigger: the first external operator needing to run or
audit the identity service standalone, or a maintainer split. Then it
is a planned extraction (the OP code plus its migrations into its own
repository, consuming a published platform-server kernel package, the
federation contract as the seam), never an improvisation.

## Downstream services

The standing rule: no service in the estate keeps its own account list,
ever. Every service trusts the OP as an RP.

The onboarding checklist (the RAG service is the reference):

1. Register the client in the OP's registry (the bootstrap seed for the
   first deploy, then the admin-managed registry): its client_id, its
   exact-match redirect URIs, and its per-client claims policy — which
   claims the ID token carries for this client, with the role allowlist
   bounding what may be carried. Least claims by default.
2. The service validates ID tokens against the OP's JWKS inside the
   service — edge checks are UX, never the gate — and makes its own
   authorization decisions. The OP provides identity and coarse roles;
   the fine-grained "which document" policy never belongs in the OP.
3. The service states its degraded-mode behavior when the OP is
   unreachable.
4. It inherits the OP's offboarding semantics: a disabled account dies
   at the RP at the session lifetime; sensitive acts re-check.

The recorded gap: the OP speaks authorization code + PKCE only; there
is no client_credentials grant today. Human users do not need it;
machine callers (the RAG's planned MCP server for the agent ecosystem)
do — service accounts as confidential clients with no redirect URIs,
audience-bound tokens, and scoped claims. Sized as a feature, not an
architecture change.

## Deployment portability (not tied to one edge provider)

The identity service is not single-vendor by construction:

- The Worker-safe doctrine: the shared server code uses WebCrypto only,
  no node built-ins; the same bundle runs in the edge runtime and Node.
- The store seam (@oimlsmart/platform-server/store): two live backends today —
  D1 on the edge, SQLite on Node. Local development and the CI e2e
  identity legs run the Node+SQLite shape constantly, so the portable
  path is continuously proven, not theoretical.
- The keys are an env secret; the mailer swaps providers by URL (the
  edge email binding / a generic HTTPS provider / the honest console
  no-op).

Our own production choice of the edge platform is about anycast
latency, co-located data, and near-zero ops cost — a choice, not a
lock-in.

The portability wave, for operators who need sovereign deployment:

1. The packaged artifact: a container image (Node plus embedded SQLite;
   three envs — the issuer URL, the signing-key secret, the mail
   provider; one volume for the database), published to the container
   registry on the identity release tag.
2. The optional Postgres backend: the third store implementation, for
   operators whose operational habits sit on Postgres. Bounded by the
   seam; honestly not urgent at an account registry's size.
3. The portable-deployment runbook: envs, volumes, the reverse-proxy
   posture, the backup arrangement, the upgrade path.
4. The CI leg that proves the portable shape on every identity release:
   boot the container, run the identity e2e legs against it.

The hosted id.oimlsmart.org stays on the edge platform either way;
portability exists for the operators who need it.
