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

- Availability invariant: the JWKS answer is the registered table, never
  gated on the secret's availability. Signing needs the secret; serving
  public keys does not. A secret mid-propagation (a fresh isolate that
  cannot resolve `OP_SIGNING_KEY` while a `wrangler secret put` rollout
  settles) serves the table as it stands, and a genuinely empty table
  answers an honest empty JWKS, never an unhandled 500. (The 2026-08-24
  flicker: the read path resolved the secret unguarded, so a
  propagation window 500'd the endpoint; oimlsmart/identity#5,
  oimlsmart/smart#181.)
- Registration invariant: `oidc_keys` accepts a public half only from
  the DECLARED `OP_SIGNING_KEY` secret, plus the one dev exception: the
  generated development key registers only when the issuer comes from
  the request origin (`OP_ISSUER` unset, the local dev posture). When
  the binding reads empty mid-propagation on the declared-issuer
  deployment, the resolve falls to the dev generation (the loud warning
  fires), but that ephemeral per-isolate key never enters the keyset
  the RPs validate against; the JWKS serves the registered table as it
  stands (oimlsmart/identity#7).

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
  anonymizes. On the account page the lighter act sits between the
  two: "end all sessions" signs the account out everywhere without
  touching its ability to sign in again.
  RP-side: existing sessions expire at their own lifetime;
  sensitive acts re-check (the approval queues already do). At the
  ORGANIZATION level (the multi-org membership model), the org's
  administrator disables one membership: the account stops acting as
  that organization (its sessions' context and its tokens' claims fall
  back to the primary binding at once) while the account and its other
  memberships stand.
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

## The admin dashboard

The OP's admin console (`/op/admin`, admin/cs_admin gated) is the
operations surface: the overview (accounts by lifecycle state, the
14-day sign-in series, today's anomaly counts, the SLO panel read from
the heartbeat workflow's own run history), the aggregate live-session
view with the act ladder (end one session; end all of an account's
sessions, the light act; deactivate the account, the heavy act, which
also revokes issued tokens and blocks issuance), the account registry,
the relying-party registry with per-client issuance activity, and the
security + audit page (the signals, the queryable and CSV-exportable
audit log, the quarterly access review's live version).

The rules the surface keeps, stated once:

- Every administrative act writes an audit event naming the actor; the
  dashboard is a read surface over the audit journal, the store, and
  the heartbeat's history, never a separate data pipeline.
- Session views never expose token values; the revocation acts ride the
  store's own session-deletion halves.
- Retention: the audit journal is retained for the life of the registry
  (no automated purge); the heartbeat history is retained by GitHub
  Actions under its own policy; the dashboard computes its counters at
  request time and stores nothing. The panels carry this statement.
- The security signals and their thresholds are stated on the page: the
  failed-login burst rule (one account or address with 5+ failures
  inside 24 hours), the token-endpoint refusals by error class, the
  rate-limit trips by caller and path, the week's new upstream links
  and client registrations.
- The heartbeat read is unauthenticated against the public GitHub API
  (this repository is public), cached per isolate for five minutes, and
  degrades to the workflow link when the read fails; the
  `OP_HEARTBEAT_API_BASE` / `OP_HEARTBEAT_REPO` /
  `OP_HEARTBEAT_WORKFLOW` envs override the source for tests and
  forks.

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

## The SSO home (the post-login launcher)

After sign-in at `/` the account lands on `/op/home`: one card per
service the account can enter, the account-console entry, and the admin
area entry for administrators. The cards come from the client
registry's launch metadata (migration 0011, the `launch_url`,
`launch_icon`, `launch_description`, `launch_visibility` columns on
`oidc_clients`; a client with no launch row never appears).

The visibility is computed per account: the role claims the OP would
emit for that account on that client (the per-client assignment through
the claims policy's allowlist, the same rule the token endpoint and the
consent page share). A non-empty set launches; an empty set never
renders a working launch. The `launch_visibility` column picks the
not-admitted posture: `roles` hides the card, `request` shows it with a
plain request-access state (the intake records `account.access_request`
on the audit chain; the registry's activity feed carries it), `open`
never gates (the service admits every signed-in account).

Manage the metadata on the client editor (`/op/admin/clients`) or the
registry API (`POST /api/op/clients` with the `launch` object; omit the
key to keep the stored card, pass `launch: null` to take the client off
the launcher). The bootstrap seed carries the same `launch` field per
entry. The icon names ride a small named set (`grid`, `monitor`,
`scale`, `flask`, `chat`, `external`); the write path refuses unknown
names.

The estate's cards (the recommended starting posture; the admin's act
on the live registry, one console session):

| Service | Registry client id | Launch URL | Icon | Visibility |
|---|---|---|---|---|
| The platform hub | `oiml-smart-platform` | `https://platform.oimlsmart.org/api/auth/signin/oidc` | `grid` | `roles` |
| The demo hub | `oiml-smart-demo` | `https://demo.oimlsmart.org/api/auth/signin/oidc` | `monitor` | `roles` |
| The NMI instance | `oiml-smart-nmi` | `https://nmi.oimlsmart.org/api/auth/signin/oidc` | `scale` | `roles` |
| The test laboratory | `oiml-smart-tl` | `https://tl.oimlsmart.org/api/auth/signin/oidc` | `flask` | `request` |
| The Publications Assistant | `oiml-rag` | `https://ai.oimlsmart.org/auth/login` | `chat` | `open` |

The launch URL is the service's own sign-in start (the platform
instances' RP start is `/api/auth/signin/oidc`; the assistant's is
`/auth/login`), so the live OP session lets the user straight in. The
client ids name the documented registry rows; if the live registry's
naming resolution (the wave-03 finding) lands differently, the same
metadata applies to the resolved rows.

The migration applies like every registry change: the deploy's
zero-pending guard aborts while 0011 is unapplied, so the operator
applies it first (`npx wrangler d1 migrations apply
oiml-smart-platform-identity --remote --config wrangler.toml --env
identity`), then the tag deploy proceeds (the wave-03 catch-up
pattern). Until the columns exist the launcher simply shows no cards;
the reads degrade honestly.

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
