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

- Backups: ALL THREE legs are landed — the nightly scheduled export to
  R2 (the scheduled-exports section below: the timestamped SQL
  snapshot in `oiml-identity-backups`, the bucket's 30-day expiry
  rule, the run's own read-back verification, the failure alarm), the
  weekly automated restore dry-run (the DR section below: the freshest
  snapshot restored into a throwaway local D1 with the assertions in
  CI), and the quarterly restore drill (the DR section below) that
  restores FROM the latest R2 snapshot and proves it byte-clean — the
  R2 path itself is drilled, not just the export. The data-loss window
  is one night, a broken restore path surfaces within a week, and a
  red night is never silent.
- Offboarding: disable revokes sessions and blocks issuance while
  preserving the audit trail; delete is the erasure path and
  anonymizes. On the account page the lighter act sits between the
  two: "end all sessions" signs the account out everywhere without
  touching its ability to sign in again. The account's developer
  tokens (TODO.identity-features/08 — the personal access tokens)
  follow the same line: a disabled account's tokens refuse at the
  exchange (reversible — a re-activation restores them), and the
  erasure removes the token rows outright (the hashes die with the
  account).
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

### The automated restore dry-run

The drill's continuous half (identity#73 — TODO.identity-ops/03's
deferred half): the `identity-restore-dryrun` workflow
(`.github/workflows/identity-restore-dryrun.yml`) runs every Wednesday
at 04:17 UTC (an off-herd minute, a few hours after the night's 23:41
UTC export, so the restore source is never more than a day stale) and
is dispatchable by hand any time. Each run:

1. Resolves the freshest snapshot from the Cloudflare API's bucket
   object listing (wrangler carries no `r2 object list`; the pilot
   token carries the R2 object verbs — the same
   `cloudflare-identity-backup` environment and two secrets as the
   nightly; no new owner act) and fetches it read-only.
2. Restores it into a THROWAWAY local D1 (`wrangler d1 execute --local
   --persist-to <a runner-temp dir>` — miniflare-local only; the live
   registry is never written and never named on a remote command; the
   state dies with the runner).
3. Asserts, in order: the SQL applies clean; the restored table set is
   exactly the export's CREATE TABLE set (internal `sqlite_`/`_cf_`
   tables excluded on both sides — the LIKE prefixes are plain, no
   backslash escapes); the restored per-table row counts equal the
   export's per-table INSERT counts (the export is one INSERT per row,
   so the floor is exact); and `d1_migrations` agrees with the kernel's
   migration set — the restored bookkeeping is byte-faithful to the
   snapshot's, and every applied name is a file in the kernel's
   canonical set (`node_modules/@oimlsmart/platform-server/migrations`,
   the append-only contract: an applied name that is not a kernel file
   is drift and fails). A kernel file not yet applied is the normal
   kernel-bump → tag-deploy window (the migration discipline above):
   logged as a notice, never a failure.

A red run opens (or appends to) the standing issue "Identity restore
dry-run failing — …", the heartbeat's report-failure pattern mirrored
from the nightly. The quarterly drill below stays the human proof —
this leg narrows a broken restore path to a week, inside the bucket's
30-day retention, with up to 30 nights of fallback snapshots behind it.

### Disaster recovery: the restore drill

An untested backup is a hope, not a backup. The drill restores the live
registry into a scratch D1 and proves the restore byte-clean — last run
2026-08-27: 35 tables on both sides, zero missing/extra, zero row-count
mismatches (173 rows each side). Cadence: quarterly, plus before any
migration-carrying deploy.

The credentials posture: the Cloudflare pilot token
(`source ~/.cloudflare-credentials-oimlsmart`), with
`CLOUDFLARE_ACCOUNT_ID` and `CLOUDFLARE_API_TOKEN` exported explicitly
(the credentials file's account id alone is not picked up
non-interactively). The live database is `oiml-smart-platform-identity`
(D1 id 6d24ab5f-f275-472f-82b1-fd0e3ca6ed96, the `identity` env in
`browser/wrangler.toml`). The backup bucket is `oiml-identity-backups`;
the same credentials posture drives both the export and the R2 object
verbs (wrangler-compatible, no S3 key pair anywhere).

```bash
cd browser
source ~/.cloudflare-credentials-oimlsmart
export CLOUDFLARE_ACCOUNT_ID=06cad8ae9a017c856ab496c6bca9a9d8
export CLOUDFLARE_API_TOKEN="$API_TOKEN"
STAMP=$(date +%Y%m%d)          # the drill's scratch namespace
SCRATCH="identity-dr-drill-$STAMP"

# 1. Fetch the LATEST scheduled snapshot from R2 — the drill's restore
#    source is the artifact the estate would actually recover from, so
#    the drill proves the R2 path, not just the export. The key is the
#    one the latest identity-backup run's upload step printed
#    (identity/YYYYMMDD-HHMMZ.sql; the bucket's object list is also
#    visible in the Cloudflare dashboard — wrangler carries no
#    `r2 object list`). For the tightest step-3 diff, dispatch a fresh
#    backup first (Actions → identity-backup → Run workflow) and use
#    THAT run's key: the snapshot is then minutes old and the live
#    side has barely moved.
KEY="identity/<the latest identity-backup run's key>"
npx wrangler r2 object get "oiml-identity-backups/$KEY" \
  --file "/tmp/id-dr-$STAMP.sql"

# 2. Create the scratch database (a throwaway — NEVER the live one) and
#    restore the snapshot into it.
npx wrangler d1 create "$SCRATCH"
npx wrangler d1 execute "$SCRATCH" --remote --file "/tmp/id-dr-$STAMP.sql"

# 3. Compare: the table SET, then the per-table ROW COUNTS — one
#    "name<TAB>count" line per table per side; the diff must be EMPTY.
#    (The internal sqlite_%/_cf_% tables are excluded; d1_migrations IS
#    compared — schema parity is part of the proof.)
snapshot() { # $1 = the database name, $2 = the output file
  local db="$1" out="$2"
  local args=(--remote --json)
  [ "$db" = oiml-smart-platform-identity ] && args+=(--env identity)
  local tables
  tables=$(npx wrangler d1 execute "$db" "${args[@]}" \
    --command "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite\_%' AND name NOT LIKE '\_cf\_%' ORDER BY name" \
    | node -e 'console.log(JSON.parse(require("fs").readFileSync(0,"utf8"))[0].results.map(r=>r.name).join("\n"))')
  : > "$out"
  while IFS= read -r t; do
    local n
    n=$(npx wrangler d1 execute "$db" "${args[@]}" \
      --command "SELECT COUNT(*) AS n FROM \"$t\"" \
      | node -e 'console.log(JSON.parse(require("fs").readFileSync(0,"utf8"))[0].results[0].n)')
    printf '%s\t%s\n' "$t" "$n" >> "$out"
  done <<< "$tables"
}
snapshot oiml-smart-platform-identity "/tmp/id-dr-$STAMP-live.txt"
snapshot "$SCRATCH"                         "/tmp/id-dr-$STAMP-restored.txt"
diff "/tmp/id-dr-$STAMP-live.txt" "/tmp/id-dr-$STAMP-restored.txt" \
  && echo "DRILL GREEN: table set + row counts identical"

# 4. Destroy the scratch and clean the workspace. The drill leaves
#    NOTHING behind locally; the snapshot stays in R2 under its own
#    30-day expiry.
npx wrangler d1 delete "$SCRATCH" --skip-confirmation
rm -f "/tmp/id-dr-$STAMP.sql" "/tmp/id-dr-$STAMP-live.txt" "/tmp/id-dr-$STAMP-restored.txt"
```

The comparison in step 3 is a per-table row-count diff, not a spot
check: every table on the live side exists on the scratch with the same
count, and no extra table appears. A mismatch is either the honest
drift of a snapshot older than the drill minute (rows written since
the snapshot — re-run against a freshly dispatched backup's key, step
1) or a failed drill. A REAL mismatch is an incident — the restore
path is broken and the next migration-carrying deploy does NOT
proceed on an unproven backup.

### Scheduled exports: the nightly D1 → R2 backup

The other half of the backup discipline (TODO.identity-ops/03): the
`identity-backup` workflow (`.github/workflows/identity-backup.yml`)
exports the live registry every night at 23:41 UTC (an off-herd
minute; dispatchable by hand any time) and uploads the SQL text to
the R2 bucket `oiml-identity-backups` under a timestamped key:

    identity/YYYYMMDD-HHMMZ.sql

The artifact is exactly the drill's export shape (SQL text), so the
drill's restore — step 2 onward above — applies verbatim to any
nightly snapshot.

- Cadence: nightly. The data-loss window is one day plus whatever the
  standing issue's age says (a red night is never silent — below).
- Retention: 30 days, enforced by the BUCKET's lifecycle rule, not by
  the workflow — the one-time `expire-30-days` rule (prefix
  `identity/`, objects expire 30 days after upload) was applied
  2026-09-07 from the operator's local credentials (the drill's
  credentials posture):

  ```bash
  npx wrangler r2 bucket lifecycle add oiml-identity-backups \
    expire-30-days identity/ --expire-days 30 --force
  ```

  A bucket-side rule can never delete the aging survivors because the
  export broke — there is no prune code to run on a red night. The
  workflow re-asserts the rule's presence every night (the
  retention-posture leg), so a deleted or drifted rule alarms instead
  of silently hoarding. (It governs the SNAPSHOTS; the admin audit
  journal itself is retained for the life of the registry, per the
  dashboard's retention statement.)
- The run's own verification: a sanity gate on the export before
  upload (non-empty, carries CREATE TABLE statements), then a
  read-back after upload (a byte-length compare and a byte-identical
  `cmp` on the downloaded copy). A landed-but-corrupt object fails
  the night, never the restore. The restore PATH is proven twice over:
  the quarterly drill restores FROM the latest of these snapshots
  (step 1 above), so the R2 path itself is drilled, not just the
  export — and the automated restore dry-run (the DR section's first
  subsection) restores the freshest snapshot into a throwaway local D1
  every week with the drill's assertions in CI.
- The failure alarm: a red run opens (or appends to) the standing
  issue "Identity backup failing — …", the heartbeat's
  report-failure pattern.

Fetching a backup, operator-local (the drill's credentials posture —
the same pilot token drives the R2 object verbs; wrangler carries no
`r2 object list`, so the freshest key comes from the latest
identity-backup run's upload-step log line or the dashboard's object
list):

```bash
cd browser
source ~/.cloudflare-credentials-oimlsmart
export CLOUDFLARE_ACCOUNT_ID=06cad8ae9a017c856ab496c6bca9a9d8
export CLOUDFLARE_API_TOKEN="$API_TOKEN"

# fetch one night, then restore it through the drill's step 2 onward
npx wrangler r2 object get \
  "oiml-identity-backups/identity/20260907-2341Z.sql" \
  --file /tmp/identity-snapshot.sql
```

The one-time provisioning — OWNER ACTS, done once, never by the
workflow (all landed 2026-09-07):

1. The bucket (the estate account, the coordinator): the private
   `oiml-identity-backups` — no public access, no custom domain.
2. The lifecycle rule (above): `expire-30-days` on prefix
   `identity/`. Re-apply with the same command if the nightly
   retention-posture leg ever reports it missing.
3. The GitHub environment `cloudflare-identity-backup` — WITHOUT
   required reviewers, on purpose: a nightly job cannot wait on an
   approval (the production environment's gate would stall it; the
   contrast is the point) — carrying the two secrets:
   `CLOUDFLARE_ACCOUNT_ID` (the estate account id) and
   `CLOUDFLARE_API_TOKEN` (the Cloudflare pilot token,
   wrangler-compatible — it carries the export AND the R2 object
   verbs; no S3 key pair exists in this lane).

Until act 3 lands, the workflow's guard leg fails honestly and the
standing issue says exactly that.

### The audit journal's retention (TODO.restructure/27 item 4)

The auditEvents journal grows unbounded by default: the no-purge
posture retains every event for the life of the registry (the panels'
statement says so). A retention window is the OWNER's decision, in
days, carried by AUDIT_RETENTION_DAYS — the code never supplies a
default N. Setting the policy means setting the var in BOTH places:

1. The GitHub repository VARIABLE (Settings → Secrets and variables →
   Actions → Variables) drives the nightly run: the
   identity-operations workflow (23:53 UTC, twelve minutes after the
   backup export — the purged rows always survive in that night's R2
   snapshot, thirty nights of them) runs
   `npx tsx scripts/op-audit-retention.ts --remote --apply`, purging
   events strictly older than the window, serial page by serial page.
   UNSET (or empty) = the clean no-op: the step prints the posture
   line, touches nothing, stays green.
2. The WORKER var (the identity env in wrangler.toml) drives the
   dashboard's retention statement, which stays honest under both flag
   states (server/audit-retention.ts resolves the statement from the
   same parse). A set-but-malformed value fails the run and the
   statement loudly, never guesses.

The one-time provisioning — OWNER ACTS, only when setting a window:
the GitHub environment `cloudflare-identity-retention` — WITHOUT
required reviewers (the backup environment's precedent: a nightly job
cannot wait on an approval) — carrying `CLOUDFLARE_ACCOUNT_ID` and a
`CLOUDFLARE_API_TOKEN` with the D1 write verbs on
oiml-smart-platform-identity. The operator-local rehearsal and dry-run
postures run against a scratch SQLite through the store seam:

```bash
cd browser
# the dry-run (counts, deletes nothing) against the live registry:
AUDIT_RETENTION_DAYS=365 npx tsx scripts/op-audit-retention.ts --remote
# the rehearsal on a scratch file (the same verbs the server runs):
AUDIT_RETENTION_DAYS=30 npx tsx scripts/op-audit-retention.ts \
  --db .cache/id-01/identity.db            # dry-run; --apply purges
```

## The participant registry's bootstrap (TODO.identity-features/10)

The organization registry's production population is the authoritative
OIML directory: `browser/data/org-registry.bootstrap.yaml` (217 rows —
63 member states, 66 corresponding members, 14 issuing authorities, 32
test-laboratory associations, 31 utilizers, 11 associates — fetched from
oiml.org 2026-08-29, the per-row provenance in the file). The importer
(`browser/server/import-org-registry.ts`, driven by
`browser/scripts/import-org-registry.ts`) upserts through the server's
own designation-link validation; it never deletes a row, never touches
curated contacts, and never resurrects a disabled org.

The apply is a deliberate act (the coordinator reviews the dataset
first). The rehearsal + apply, from `browser/`:

```sh
# 1. the rehearsal on a scratch SQLite (no Cloudflare anything)
npx tsx scripts/import-org-registry.ts --db .cache/bootstrap-proof/identity.db
npx tsx scripts/import-org-registry.ts --db .cache/bootstrap-proof/identity.db --execute
npx tsx scripts/import-org-registry.ts --db .cache/bootstrap-proof/identity.db   # the re-plan: 217 unchanged

# 2. the plan against the LIVE registry (read-only) + the apply SQL.
#    The operator's wrangler credentials ride the environment; with more
#    than one account on the token, name the estate's account:
export CLOUDFLARE_ACCOUNT_ID=<the OIML SMART account id>   # `npx wrangler whoami` lists them
npx tsx scripts/import-org-registry.ts --remote            # prints the plan, emits the SQL (default .cache/org-registry.bootstrap.sql)
#    — review the printed plan (217 create on a fresh registry) and the
#    emitted SQL; both name every row they touch.

# 3. the apply (the deliberate act; the same D1 the deploy gates name)
npx wrangler d1 execute oiml-smart-platform-identity --remote --config wrangler.toml --env identity --file .cache/org-registry.bootstrap.sql

# 4. the verification (read-only)
npx wrangler d1 execute oiml-smart-platform-identity --remote --config wrangler.toml --env identity --json \
  --command "SELECT kind, COUNT(*) AS n FROM org_registry GROUP BY kind ORDER BY kind"
#    expect: associate 11, corresponding-member 66, issuing-authority 14,
#    member-state 63, test-laboratory 32, utilizer 31
```

Re-runnable by construction: the re-import's plan is all-`unchanged`
when the registry already carries the dataset. A directory refresh
re-edits the YAML (never the rows by hand for the bootstrap-managed
fields) and re-runs the same commands; the plan's update list IS the
review of what changed.

## Availability and monitoring

- The heartbeat, independent of the platform: a scheduled probe hitting
  the discovery document, JWKS, and a synthetic RP claim; a red probe
  opens or updates a standing issue (the demo-reset pattern).
- Degraded mode: existing RP sessions ride their own cookies (OP down
  does not mean logged out); new logins fail honestly on a plain status
  page; the demo instances' local demo accounts stay available as the
  clearly-marked development posture.
- The stated SLO: 99.9% monthly, measured by the heartbeat. The
  published statement is `identity-slo.md` (next to this runbook); the
  public read is https://status.oimlsmart.org, and the admin dashboard's
  SLO panel reads the heartbeat workflow's own run history.

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
  request time and stores nothing. The panels carry this statement. —
  UNLESS the owner sets a retention window (see "The audit journal's
  retention" below): with AUDIT_RETENTION_DAYS set, the panels' first
  sentence changes to the window (the statement resolves from the same
  var the purge does, so it stays honest under both flag states).
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
is a planned extraction (the OP code into its own repository,
consuming the published platform-server kernel package, the
federation contract as the seam), never an improvisation. (Done:
TODO.identity-extract; the kernel's own extraction followed in
TODO.repos/01.)

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

The machine callers: the OP's machine cone carries two non-human client
classes on `client_credentials` — the DEVICE class (per-device
credentials for the SMART Measuring Instruments' twins, identity#35) and
the SERVICE class (the general caller — agent pipelines, MCP servers,
scheduled jobs): a confidential client with no redirect URIs, an
audience-bound token (`aud` is the declared called service, never just
the client id), and a scoped claim set (the registered allowlist,
narrowed per request, never exceeded). The claim contract and the
onboarding shape are the integration guide's §3/§9; machine tokens never
carry a user claim, and a machine acting on behalf of a user is the PAT
surface's exchange (TODO.identity-features/08), never a service token.

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
