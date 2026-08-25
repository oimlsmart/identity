# Self-hosting the identity service (your own OP on your domain)

> CANONICAL LOCATION: this document lives in `oimlsmart/identity`
> (the code it drives lives here).

This is the runbook for **posture (b)** of the four identity postures —
deploying THIS repository as your own OpenID Connect Provider for your
own users on your own domain, instead of trusting the estate's OP at
`id.oimlsmart.org`. The full matrix (trust the estate's OP / deploy this
service / bring your own OIDC provider entirely / the hybrid) is the
smart monorepo's
[identity-postures.md](https://github.com/oimlsmart/smart/blob/v2/docs/deployment/identity-postures.md).

**The guarantee this page keeps:** self-hosting is a *configuration*
act — environment variables, an instance-profile YAML, the seed
declarations, `wrangler secret put`, the admin console. It is **never** a
code change: no tracked file is edited, no fork is kept. The executable
proof is `browser/e2e/id-16-selfhost.e2e.ts` — it boots the OP from
stock `main` with only env config (a loopback issuer, a seeded bootstrap
admin, client, and upstream row, a generated ES256 key), drives a full
sign-in round trip, and asserts the boot wrote nothing into the
checkout. Run it yourself:

```bash
cd browser
npx vitest run --config vitest.e2e.config.ts e2e/id-16-selfhost.e2e.ts
```

Two deployment shapes are supported, both continuously proven:

- **Node + SQLite** — on-prem or a container: the same store seam and
  the same build; the CI e2e legs boot exactly this shape.
- **Cloudflare Workers + D1** — on YOUR OWN Cloudflare account (a
  non-estate account): the same Workers bundle the estate deploys,
  composed from your own untracked overlay config.

The worked example below is the neutral cast: the operator is "ACME",
the public issuer is `https://id.example.invalid` (`.invalid` — RFC
2606; substitute your own domain everywhere), the first administrator is
`admin@id.example.invalid`.

## Prerequisites (both shapes)

- Node.js 22+, npm.
- This repository, stock `main` (or a tagged `id-v*` release).
- **Read access to `oimlsmart/smart`** — the shared server kernel
  (`@oimlsmart/platform-server`) is owned by the smart monorepo and,
  until its first npm publish lands, is consumed as a `file:` dependency
  through the sibling checkout at `x/oimlsmart/smart` (the `x/`
  doctrine). At publish this prerequisite retires and `npm ci` alone
  suffices.

```bash
git clone https://github.com/oimlsmart/identity.git
cd identity
git clone --branch v2 https://github.com/oimlsmart/smart.git x/oimlsmart/smart
npm --prefix x/oimlsmart/smart/packages/platform-server ci --no-audit --no-fund
cd browser
npm ci
```

Nothing in the checkout is edited at any step below. Everything you
declare lives in your process environment, in files OUTSIDE the tracked
tree, or in one explicitly gitignored overlay file.

## The instance profile (both shapes)

The profile YAML says WHO this deployment is (its public name on the
consent page and in outbound mail) and gates the demo cast OFF. Write it
outside the repo — here `../acme-identity.profile.yaml`:

```yaml
identity:
  org_id: acme-id
  org_name: ACME Identity
  role_codes: [identity]
roles: [identity]
branding:
  name: ACME Identity
demo_personas: false
```

`roles: [identity]` is the OP profile gate (the one build serves the OP
contract only under it). `demo_personas: false` is the production
posture: no demo cast, no demo sign-in surface. (The repo's dev default
`server/instance.profile.dev.yaml` carries `demo_personas: true` so
`npm run dev` signs in out of the box — never deploy that file.)

## The signing key (both shapes)

One ES256 pair per deployment. Generate it with the rotation ceremony's
own generator (prints the private JWK ONCE; never commit it, never log
it):

```bash
cd browser
npx tsx scripts/op-key-rotate.ts rotate --env selfhost --url https://id.example.invalid
```

Keep the printed JSON as `OP_SIGNING_KEY` in your secrets store. Undeclared,
the OP generates an ephemeral development key per process with a loud
warning — tokens invalidate at every restart; never a production
posture. Rotations later ride the same script (the JWKS overlap keeps
in-flight tokens valid; see `identity-deploy.md` → "Key rotation").

## Shape A: Node + SQLite (on-prem / container)

### A1. Build

```bash
cd browser
npm run build        # the Astro production build, node adapter → dist/
```

### A2. The two processes

The node deployment is two processes behind your TLS reverse proxy:

1. **The API** (the OP protocol + the account/admin APIs), run from the
   source tree under tsx (the repo's node entry; a compiled entry is
   packaging follow-up):

   ```bash
   cd browser
   NODE_ENV=production \
   PORT=3190 \
   DATABASE_PATH=/var/lib/acme-identity/registry.db \
   INSTANCE_PROFILE=../../acme-identity.profile.yaml \
   OP_ISSUER=https://id.example.invalid \
   OP_SIGNING_KEY='<the private JWK JSON>' \
   OP_ACCOUNT_SEED='[{"email":"admin@id.example.invalid","name":"Ada Example","role":"admin"}]' \
   npx tsx server/serve.ts
   ```

   `NODE_ENV=production` matters twice: the session cookie flips to
   `Secure` (the browser only ever meets it over your TLS endpoint), and
   the dev-only `/api/dev-reset` seam is NOT mounted.

2. **The pages** (sign-in, consent, setup, the account + admin
   consoles) — the Astro standalone server:

   ```bash
   cd browser
   HOST=0.0.0.0 PORT=5190 node dist/server/entry.mjs
   ```

### A3. The reverse proxy (TLS)

Terminate TLS at your proxy and route by path prefix — the OP's pages
are served by the Astro process, the protocol + API by the tsx process
(the same split `astro.config.mjs`'s dev proxy installs):

| Route prefix | Upstream |
|---|---|
| `/api/` | `http://127.0.0.1:3190` (the API) |
| `/.well-known/openid-configuration` | the API |
| `/jwks.json` | the API |
| `/op/authorize`, `/op/token`, `/op/userinfo` | the API |
| `/op/avatar/`, `/op/upstream/` | the API |
| everything else (`/`, `/op/setup`, `/op/consent`, `/op/account`, …) | `http://127.0.0.1:5190` (the pages) |

**The issuer is the PUBLIC https URL.** `OP_ISSUER` is what the
discovery document, the ID tokens' `iss`, and the setup links name —
declare it once, exactly, no trailing slash. (Only when it is undeclared
does the OP derive the issuer from the request's `Host`/
`X-Forwarded-*` headers — the dev posture; a deployment always
declares it.)

### A4. The node env surface (reference)

| Variable | Required | What it is |
|---|---|---|
| `OP_ISSUER` | yes | The public issuer URL (`https://id.example.invalid`). |
| `OP_SIGNING_KEY` | yes | The ES256 private JWK JSON (from the ceremony above). |
| `DATABASE_PATH` | yes | The SQLite file's location. The store self-initializes on first boot (no migration step on node). Default when undeclared: `<repo>/data/oiml-smart.db` (gitignored scratch). |
| `INSTANCE_PROFILE` | yes | Path to your profile YAML (above). |
| `OP_ACCOUNT_SEED` | first boot | The bootstrap admin(s) — see "The bootstrap story" below. |
| `OP_CLIENT_SEED` | recommended | A JSON array of RP client rows upserted at boot: `[{"client_id":"acme-app","name":"The ACME application","secret":"…","redirect_uris":["https://app.example.invalid/auth/callback"],"claims_policy":{"claims":["roles","groups","org"]}}]`. Admin-managed afterwards (the console's `/op/admin/clients` or `POST /api/op/clients`). |
| `OP_UPSTREAM_SEED` | optional | A JSON array of upstream sign-in providers (GitHub / generic OIDC — shape and secrets discipline: `identity-upstreams.md`). |
| `EMAIL_FROM` + `MAIL_PROVIDER_URL` / `MAIL_PROVIDER_KEY` | optional | The transactional mailer (HTTPS provider posture). Undeclared, the mailer is an honest console no-op — see "The mailer" below. |
| `MAIL_LOCALE` | optional | `en` (default) or `fr`. |
| `OP_MAIL_LOGO_URL` | recommended with a mailer | The absolute https URL of YOUR brand mark in outbound mail. Default: the estate's logo URL — declare your own, or your mail wears another deployment's brand. |
| `BLOBS_DIR` | optional | The avatar uploads' disk directory (default `browser/data/blobs`, gitignored scratch — declare a real path for production). |
| `BLOBS_DISABLED` | optional | `true` binds NO avatar store: uploads answer an honest 503 and accounts render initials (the console says so). |
| `AVATAR_MAX_BYTES` | optional | The upload cap (default 2 MiB). |
| `OP_RATE_LIMIT_CAPACITY` | optional | `0` disables the OP-surface rate limiter (generous human-paced defaults otherwise). |
| `PORT` | optional | The API's listen port (default 3190). |

## Shape B: Cloudflare Workers + D1 (your own account)

The estate's tracked `browser/wrangler.toml` names the ESTATE's worker,
D1 ids, and domains — you never edit it. Your deployment composes from
an **untracked overlay** (`browser/wrangler.self-host.toml`, gitignored
by name) that carries your own values.

### B1. Your account, your database, your bucket

```bash
cd browser
npx wrangler login                                # YOUR Cloudflare account
npx wrangler d1 create acme-identity-registry     # note the database_id
npx wrangler r2 bucket create acme-identity-avatars
```

### B2. The overlay config

Write `browser/wrangler.self-host.toml` (gitignored — it is yours,
never committed):

```toml
# ACME's self-hosted OP — the overlay for scripts/deploy-instance.ts --overlay.
[env.selfhost]
name = "acme-identity-op"

[[env.selfhost.d1_databases]]
binding = "DB"
database_name = "acme-identity-registry"
database_id = "<the database_id from B1>"
migrations_dir = "server/db/migrations"

[[env.selfhost.r2_buckets]]
binding = "BLOBS"
bucket_name = "acme-identity-avatars"

[env.selfhost.vars]
ENTITY_BACKEND = "server"
OP_ISSUER = "https://id.example.invalid"
EMAIL_FROM = "ACME Identity <no-reply@example.invalid>"
OP_UPSTREAM_SEED = '''
[]
'''
INSTANCE_PROFILE_YAML = '''
identity:
  org_id: acme-id
  org_name: ACME Identity
  role_codes: [identity]
roles: [identity]
branding:
  name: ACME Identity
demo_personas: false
'''
```

(The mailer's Cloudflare Email Service binding — `[[env.selfhost.send_email]]
name = "EMAIL"` — only once your account's email-sending access and
domain authentication are in place; the HTTPS provider posture via
`MAIL_PROVIDER_URL` + a `MAIL_PROVIDER_KEY` secret works on any account.
With neither, the mailer degrades honestly — see "The mailer" below.)

### B3. Build, migrate, deploy, declare the secrets

```bash
cd browser
npm run build:cloudflare            # the Workers bundle → dist/
# Apply the schema to YOUR D1 (the expand-only migration set):
npx wrangler d1 migrations apply acme-identity-registry --remote \
  --config wrangler.self-host.toml --env selfhost
# Compose the deploy config from the build + YOUR overlay, and deploy:
npx tsx scripts/deploy-instance.ts selfhost --overlay wrangler.self-host.toml
# Declare the secrets (stdin prompts; never argv, never a file):
npx wrangler secret put OP_SIGNING_KEY --config wrangler.self-host.toml --env selfhost
npx wrangler secret put OP_ACCOUNT_SEED --config wrangler.self-host.toml --env selfhost
```

`wrangler secret put` restarts the worker on each update; declare
`OP_SIGNING_KEY` before the first real traffic. Until it lands, the OP
serves an honest empty JWKS (signing needs the secret; serving public
keys does not) and the logs warn loudly — the declared-issuer posture
never registers an ephemeral development key into the keyset your RPs
validate against.

The composer strips routes deliberately (the estate attaches domains by
a script of its own). Your bring-up URL is the free
`<worker-name>.<account-subdomain>.workers.dev` — set `OP_ISSUER` to it
for the first boot if you like. When your DNS zone is on the same
account, attach the custom domain in the dashboard (Workers →
`acme-identity-op` → Settings → Domains & Routes → Add Custom Domain),
flip `OP_ISSUER` to `https://id.example.invalid` in the overlay, and
redeploy (B3's last two commands). The issuer string is the only
coupling your RPs have — see "The federation note" below.

## The bootstrap story (both shapes)

A fresh OP has NO accounts and no open signup. The first administrator
arrives by declaration:

1. Declare `OP_ACCOUNT_SEED` — a JSON array of
   `{ "email", "name", "role?" }` (default role `admin`).
2. Boot. For every seeded account without a password the OP mints a
   fresh one-time enrollment token and logs the setup link ONCE per
   process (the operator reads the deploy log):

   ```
   [op] bootstrap: account admin@id.example.invalid has no password — its ONE-TIME setup link (24 h):
     https://id.example.invalid/op/setup?token=…
   ```

3. Open the link on the PUBLIC issuer, set the password. The link is
   one-time and lives **24 hours**; completing it consumes it atomically.
   Until the password is set, every boot mints and logs a FRESH link —
   an expired first link is recovered by restarting the process (or
   redeploying), never by editing anything.
4. Afterwards the seed goes quiet: an existing account is left entirely
   alone, and the console/admin API manage the account from there.

Inviting FURTHER accounts is the same machinery: an admin runs
`POST /api/op/accounts` (or the console's accounts page). The 201
response carries the one-time setup link; when a mailer is configured it
is emailed, otherwise the response shows it for the out-of-band handover
(honestly — the `mail` block says which happened). Re-issuing a link
(re-invite after expiry, or a password reset by admin act):
`POST /api/op/accounts/<id>/enrollment`. The account holder's own
"forgot password" (`POST /api/op/login/reset`) travels BY EMAIL ONLY —
without a mailer it answers a plain 503 pointing at the administrator,
never an on-screen link (an unauthenticated link would be an
account-takeover door).

The seeds are lazy and idempotent: each rides its own once-per-process
seam on the first request that needs it — the login projection's first
read trips the upstream seed, the first sign-in or account act trips the
account and client seeds (the smoke leg trips them the same way). A
fresh deployment needs no provisioning call.

## The mailer (optional, honestly degraded without)

Three postures, resolved at send time, the never-blocks rule throughout:

- **Cloudflare Email Service** (Workers shape): the `send_email`
  binding + `EMAIL_FROM`.
- **A generic HTTPS provider** (either shape): `MAIL_PROVIDER_URL` +
  `MAIL_PROVIDER_KEY` (the Resend-shaped POST; the key is a secret).
- **Console** (neither configured): messages are logged, sends report
  not-sent, and every flow keeps working — invites and re-issues show
  their setup links, the self-service reset answers its honest 503.

With a mailer configured, declare `OP_MAIL_LOGO_URL` as YOUR absolute
https brand-mark URL (default: the estate's logo — a self-host
deployment wants its own) and `MAIL_LOCALE` (`en`/`fr`).

## The avatar store (optional, honestly degraded without)

Node: the local-disk adapter under `BLOBS_DIR` (default
`browser/data/blobs`; `BLOBS_DISABLED=true` binds nothing). Workers: the
`BLOBS` R2 binding. With no store bound, uploads and reads answer an
honest 503, `/api/config` reports `blobs.available: false`, and the
pages fall back to the linked provider's picture or the initials — the
console says so on the account page.

## The federation note

Your OP is fully independent. There is no hidden estate dependency: no
call home, no shared registry, no estate key material. The WHOLE
coupling between your OP and any relying party (an OIML SMART platform
instance, or anything else speaking OIDC code+PKCE) is the RP's own
configuration: `OIDC_ISSUER=https://id.example.invalid` plus a client
registration in YOUR registry (`OP_CLIENT_SEED`, the console, or
`POST /api/op/clients`). The estate's RPs do not trust your OP unless
they choose to point at it, and your OP knows nothing of the estate's.
The RP-side integration guide is `docs/integration/identity-service.md`
— it reads the same for your OP, with your issuer substituted.

## Upgrades and the pre-deploy proof

Track `main` (or the `id-v*` tags). The compatibility contract is the
same one the estate runs on:

- **Migrations are expand-only** (`browser/server/db/migrations/`:
  appends only, never a renumber, never a drop without a two-release
  overlap), so a rollback never meets a schema it cannot read. On the
  Workers shape, apply new files to YOUR D1 out of band before deploying
  the code that needs them (B3's `d1 migrations apply` command; check
  with `d1 migrations list`). On the node shape the SQLite store
  self-applies the schema at boot — pull, `npm ci`, restart.
- **The contract gate is your pre-deploy proof too.** The OIDC-surface
  golden test boots your tree and deep-compares the discovery document,
  the JWKS shape, the claims contract, and the error taxonomy against
  the committed golden:

  ```bash
  cd browser
  npx vitest run --config vitest.e2e.config.ts e2e/op-surface-contract.e2e.ts
  ```

  After deploying, the same script's probe mode proves the live surface
  (the deploy pipeline's own shape):

  ```bash
  npx tsx scripts/op-surface-contract.ts probe https://id.example.invalid
  ```

- And the smoke leg on this page (`e2e/id-16-selfhost.e2e.ts`) re-proves
  at every release that the node boot you ran stays configuration-only.

## The ops doctrine that still applies

Key rotation cadence and compromise handling, the account registry's
data lifecycle (backups — your own arrangement on node; the D1 export
pattern on Workers), the admin dashboard's security signals, and the
monitoring posture are deployment-shape-independent:
[identity-operations.md](identity-operations.md). Where that page names
estate infrastructure (the estate's heartbeat workflow, its D1
bookkeeping), substitute your own — the disciplines, not the hostnames,
are the doctrine.
