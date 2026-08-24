# Identity federation (OIDC single sign-on)

> CANONICAL LOCATION: this document moved to `oimlsmart/identity`
> at the wave-02 extraction (the code it describes lives here). The
> smart monorepo's copy becomes a pointer page in wave 04.

Each instance can delegate sign-in to its organization's identity
provider (IdP) with OpenID Connect — Authorization Code + PKCE, with
ID-token validation (signature, issuer, audience, expiry, nonce) done
server-side. SAML is a later bridge (deliberately out of scope here).

For GitHub-based teams there is also the lighter **GitHub OAuth** path
(OAuth 2.0, not OIDC — no discovery, no ID token) with an env-declared
authorized-users list. It was the recommended sign-in on the Cloudflare
Worker deployment while the SSO flow's state jar was per-process;
TODO.identity/04 made the jar store-backed, so both paths are exact on
the Worker, and the federation's own instances lead with the OP (the
wiring section below). It is documented in its own section below.

**The federation's own IdP is this codebase too**: `id.oimlsmart.org`
runs the OIDC **Provider** built here (TODO.identity/01) as another
deployment profile of the same build — see *The OIML SMART identity
provider* below. Every instance then signs in through it with exactly
the generic SSO configuration this page documents. The architecture
chapter ([22, the identity service](https://github.com/oimlsmart/smart/blob/v2/docs/architecture/22-the-identity-service.md))
teaches the merged whole; this page is the operator's reference.

Local accounts stay for development and small deployments: the demo
accounts are served exactly as before **until SSO is configured** — a
configured SSO turns them off automatically (spec §3), and the login
page says so honestly. `DEMO_ACCOUNTS_ENABLED=true` keeps them
alongside SSO (the evaluation posture — useful while a deployment is
being stood up). A deployment can also close them outright with the
instance profile's `demo_personas: false` — the production posture,
see its own section below.

![The sign-in flow](identity-flow.svg)

## Configuration

The identity configuration is a per-instance SERVER property, resolved
from the environment (`browser/server/auth/identity.ts` — one
resolution path for the routes, the login page and the admin UI):

| Variable | Meaning |
|---|---|
| `OIDC_ISSUER` | The IdP's issuer URL. Discovery reads `<issuer>/.well-known/openid-configuration` and requires the metadata's `issuer` to match exactly. |
| `OIDC_CLIENT_ID` | This instance's client id at the IdP. |
| `OIDC_CLIENT_SECRET` | The client secret (confidential clients). |
| `OIDC_CLIENT_SECRET_REF` | Or by reference: `env:OTHER_VAR`. The secret is never stored inline in a profile file. |
| `OIDC_SCOPES` | Space-separated; default `openid profile email`. The `email` scope is required — accounts key on the email claim. |
| `OIDC_PROVIDER_NAME` | The login-button label (default `SSO`) — e.g. `BIML SSO`. |
| `OIDC_CLAIM_MAPPING` | The claim mapping as JSON (reference below). Absent ⇒ every SSO user waits in the approval queue. |
| `DEMO_ACCOUNTS_ENABLED` | `true`/`false`. Unset: demo accounts are enabled exactly when SSO is NOT configured. |

Either both of `OIDC_ISSUER` + `OIDC_CLIENT_ID` or neither: a partial
or invalid configuration fails CLOSED — SSO answers "not configured"
(501 with the problems listed), the login page hides the button, and
the instance settings page shows the problems.

### The instance profile seam (fed-01)

The deployment profile (TODO.federation/01) carries the same section:

```yaml
identity:
  issuer: https://idp.example.org
  clientId: oiml-smart
  clientSecretRef: env:OIDC_CLIENT_SECRET   # by reference, never inline
  providerName: BIML SSO
  scopes: "openid profile email"
  claimMapping:
    claims: [groups, roles]                  # default: groups, roles
    defaultRole: viewer                      # OPTIONAL — see below
    rules:
      - match: oiml-ia-officers              # a groups/roles claim value
        role: ia_officer                     # one of the platform roles
        org: EX1                             # literal org binding…
      - match: oiml-lab
        role: tl_operator
        orgFromClaim: lab_id                 # …or read from a claim
```

The section's OIDC fields ride the SAME `identity:` block as the org
identity (`org_id`/`org_name`/`role_codes`); the profile parser
(`@oimlsmart/platform-server/profile`) reads the org half and tolerates the OIDC
half. The two runtimes consume the OIDC half differently:

- **Node (self-hosted).** The boot reads the profile FILE's section
  additively (`browser/server/auth/identity-node.ts`, called from
  `server/serve.ts`): the fields are synthesized into the `OIDC_*` env
  surface, and **set env vars always win** over the file.
- **The Worker.** There is no file; declare the `OIDC_*` values as
  `[vars]` (and the secret as a Worker secret) directly — the wiring
  recipe below for the federation's own instances does exactly that. The
  `identity:` section inside `INSTANCE_PROFILE_YAML` then carries the
  org identity only.

### Per-IdP-family setup

Every case: register a **confidential or public web application** with
the redirect (callback) URI
`https://<your-host>/api/auth/callback/oidc` and the post-logout
redirect URI `https://<your-host>/app/login`. PKCE is always used
(S256); a client secret is optional (public client) but recommended
where the IdP issues one.

- **Microsoft Entra ID (Azure AD).** App registration → "Web" platform
  with the redirect URI; the issuer is
  `https://login.microsoftonline.com/<tenant-id>/v2.0`. Put your
  security groups in tokens: "Optional claims" → ID token → `groups`
  (choose the group id or name format — the `match` values in the
  claim mapping must equal whatever Entra emits). RP-initiated logout
  is supported (`end_session_endpoint`).
- **Keycloak.** Realm → client (openid-connect, standard flow =
  authorization code) with the redirect URI. Issuer:
  `https://<host>/realms/<realm>`. Map groups into the token with a
  "groups" client-scope mapper (Group Membership); Keycloak's default
  group claim path is configurable — set the mapper's claim name to
  `groups` or point `claimMapping.claims` at yours.
- **Auth0 / Okta.** Create a "Regular Web Application" (Auth0) /
  "OIDC Web Application" (Okta); issuer `https://<tenant>/`
  (Auth0 — trailing slash matters, copy it verbatim) resp.
  `https://<domain>/oauth2/default` (Okta). Groups arrive via an
  Action/group claim (Auth0) or a Groups claim filter (Okta) named
  `groups`.
- **Google.** OAuth client (web) — note: Google does NOT emit groups;
  map nothing and let everyone fall to `defaultRole` / the approval
  queue, or put a different IdP in front. Issuer:
  `https://accounts.google.com`.

Whatever the family: the mapping reads **string values** of the
configured claims (`groups`/`roles` by default) and matches them
**exactly** — check what your IdP actually emits (group ids vs display
names) before writing `match` values.

## Claim mapping reference

The mapping decides the account's **role** (one of the platform roles
of `@oimlsmart/platform-server/vocab`: `applicant`, `ia_officer`,
`tl_operator`, `biml_officer`, `cs_admin`, `mc_member`, `rc_member`,
`executive_secretary`, `admin`, `viewer`) and its **organization
binding** (a manufacturer id, an IA `oiml_code`, or a TL `oiml_id`).

Semantics (`browser/server/auth/claim-mapping.ts`, unit-tested):

- `claims` — the token claims read, in order (default
  `["groups", "roles"]`). String and string-array values count;
  anything else is ignored.
- `rules` — first match wins, in config order. `match` is an exact
  string equality against a claim value. `role` must be a platform
  role (anything else is a configuration error, rejected loudly).
  `org` binds literally; `orgFromClaim` names the claim carrying the
  org id (absent claim ⇒ org `null`); they are mutually exclusive.
- `defaultRole` — the role for an authenticated user no rule matches.
  **Absent ⇒ the approval queue** (no session until an admin decides).
  When declared, `viewer` is the intended safe value.
- **Honest least privilege**: unmapped claims never widen access, a
  rule never assigns a role it does not declare, and a mapping that
  fails validation disables SSO rather than guessing.

### Account resolution order (per sign-in)

1. The identity is known (issuer + `sub` already on an account) → sign
   in as that account.
2. A prior approval decision exists → approved: provision the account
   with the decided role + org and sign in; rejected: an honest
   refusal page, no session.
3. The IdP asserts a **verified** email that an existing account holds
   → the identity LINKS to that account; the account's locally
   assigned role/org are kept (the mapping does not apply to linked
   accounts).
4. Otherwise the claim mapping decides: a matching rule → provision
   with that role + org; no match → `defaultRole` if declared, else
   the **approval queue**.

### The approval queue

Users in the queue have authenticated with the IdP but hold no access:
no session is created, and the login page shows a plain-language
"waiting for approval" notice. Administrators (the `admin` /
`cs_admin` roles) review the queue on the instance settings page
(**Admin → Instance settings**, `/app/cs/settings`): each pending row
shows the name, email, issuer, and the groups/roles claims the IdP
sent. Approving assigns the role (and optional organization) — the
account is provisioned at the user's next sign-in. Rejecting closes
the request; the user's next sign-in gets an honest "declined" page.
Repeat attempts never duplicate the queue row (one row per
issuer + subject).

Every step writes an audit event (the `auditEvents` store):
`sso_sign_in`, `sso_link`, `sso_provision` (source: `claim_mapping` /
`default_role` / `approval`), `sso_pending`, `sso_approved`,
`sso_rejected`.

## Sign-out (RP-initiated logout)

Signing out always ends the local session. When the session came from
SSO **and** the IdP declares an `end_session_endpoint`, the browser is
then sent through the IdP's logout (with the `id_token` hint kept per
session for exactly this) and returns to the login page. An IdP
without the endpoint degrades honestly: the local sign-out stands
alone.

## Failure modes (plain language, never a stack trace)

Token-verification and flow failures redirect to the login page with a
plain-language message per cause: expired/mismatched sign-in state,
exchange failure, unreadable/unsigned/unverifiable token, wrong issuer
or audience, expired token, nonce mismatch (the replay guard), a
missing email claim, the pending-approval notice, and the rejection
notice. The server log carries the technical detail; the user carries
a sentence they can act on.

## The RBAC seam (item 12)

The claim mapping's output is a **role string + org binding** — the
same shape a demo account carries. Item 12's action-permission layer
(TODO.federation/12) consumes that role exactly as it consumes any
locally assigned role: the mapping never grants actions directly, and
the permission layer is free to narrow what a role may do per
deployment profile. The seam is the `MappingOutcome` type of
`browser/server/auth/claim-mapping.ts` — coordinated with the item-12
stream by contract, not shared files.

## GitHub OAuth (authorized sign-in)

GitHub sign-in is OAuth 2.0, **not** OIDC: no discovery, no ID token —
after the code exchange the platform reads the user's profile and
emails from the REST API, and that is all it needs. It is the
lightweight alternative to the generic SSO above; its stateless state
parameter is exact in every posture (the SSO flow's state jar has been
store-backed since TODO.identity/04, so the Worker posture is exact
there too). The demo accounts remain a fallback sign-in path (they are
served exactly as before unless the OIDC posture or
`DEMO_ACCOUNTS_ENABLED` disables them — GitHub being configured does
not, by itself, turn them off; the instance profile's `demo_personas:
false` does — the production posture, below). On the federation's own
instances GitHub is the CUTOVER fallback only: it retires once the
direct-GitHub accounts have migrated to the OP (the migration runbook
below).

### Creating the OAuth App

GitHub → **Settings → Developer settings → OAuth Apps → New OAuth App**
(for a team deployment, register it under the ORGANIZATION's settings →
Developer settings, so the app outlives any one account):

- **Homepage URL:** `https://<your-host>`
- **Authorization callback URL:**
  `https://<your-host>/api/auth/callback/github`

Register, note the **Client ID**, and generate a **Client secret**.

### Configuration

The GitHub posture arrives through the same env seam as the OIDC one
(`process.env` on node, the Worker bindings on Cloudflare):

| Variable | Meaning |
|---|---|
| `GITHUB_CLIENT_ID` | The OAuth App's client id. |
| `GITHUB_CLIENT_SECRET` | The OAuth App's client secret. |
| `GITHUB_ADMIN_LOGINS` | Comma-separated GitHub usernames (case-insensitive) → role `admin`. |
| `GITHUB_ALLOWED_LOGINS` | Comma-separated usernames → the default allowed role, `cs_admin`. |
| `GITHUB_ROLE_MAP` | `login:role,login2:role2` — per-login initial roles. Roles validate against the platform vocabulary (`@oimlsmart/platform-server/vocab`); an unknown role fails CLOSED: the entry is dropped and logged at boot, never invented. |
| `GITHUB_ALLOWED_ORG` | One org slug — every ACTIVE member may sign in. Membership is checked LIVE at each sign-in (`GET /user/memberships/orgs/{org}` with the user's own token; `pending` invitations do not count). Members get the default allowed role. The authorization request adds the `read:org` scope when this is set — a private membership is invisible without it. |
| `GITHUB_OAUTH_BASE_URL` / `GITHUB_API_BASE_URL` | Endpoint overrides for GitHub Enterprise Server (defaults `https://github.com` / `https://api.github.com`). |

On the Worker the client pair arrives as Worker secrets — never inline
in `wrangler.toml`:

```sh
cd browser
npx wrangler secret put GITHUB_CLIENT_ID
npx wrangler secret put GITHUB_CLIENT_SECRET
```

The allowlists are not secrets: `[vars]` in `wrangler.toml` for the
deployment, `.dev.vars` (gitignored) for local dev — or plain
environment variables on node.

### Authorizing a team

The four declarations compose; per-login precedence is **admin list →
role map → allowed list → org membership → denied**. To open the
platform to the team through the `oimlsmart` org:

```toml
GITHUB_ADMIN_LOGINS = "alice,bob"        # the platform operators
GITHUB_ALLOWED_ORG = "oimlsmart"         # every active org member
GITHUB_ROLE_MAP = "carol:tl_operator"    # per-login refinement
```

What the allowlist is — and is not:

- **Admission + the INITIAL role.** A new account is provisioned with
  the resolved role and org NULL; an EXISTING account keeps its locally
  assigned role and org — refine both afterwards in **Admin → Instance
  settings → users** (the fed-12 users section); the env declaration
  never re-applies over a local assignment.
- **Revocation is live.** A login struck off every list (or removed
  from the org) is refused at its NEXT sign-in, whatever account it
  holds.
- **No org binding from GitHub.** GitHub sign-ins always provision
  with org NULL; binding a user to a manufacturer / IA / TL record is
  the admin's users-section decision, never the OAuth flow's.
- **An honest refusal.** A denied login lands on the login page with a
  plain-language "your GitHub account is not authorized for this
  platform — contact the administrator" message: no account, no
  session, no stack trace. The server log carries the detail.

When **no** allowlist env is declared the instance is OPEN ENROLLMENT:
any GitHub account signs in with role `user` (the historical behavior)
and the server logs a boot warning. That posture suits a personal
evaluation; it is unsuitable for a shared deployment.

### Security notes

- **The state parameter is stateless.** `<nonce>.<issuedAt>.<hmac>` —
  HMAC-SHA256 over `nonce:issuedAt`, keyed by the client secret,
  compared constant-time, with a 10-minute TTL. Nothing is stored, no
  D1 round trip: the Worker isolate answering the callback needs
  nothing the request does not carry (the old per-process jar
  intermittently failed the check across isolates; it is gone, on node
  too).
- **Never commit the client secret.** `wrangler secret put` on the
  Worker, the process environment on node; `.dev.vars` stays
  gitignored. The secret also keys the state HMAC, so rotate it with
  the usual care (in-flight sign-ins within the 10-minute TTL fail the
  state check once, then simply restart).
- **The token never leaves the server.** The GitHub access token is
  used for the profile/emails/membership reads during the callback
  and discarded — it is not stored, not exposed to the client, and the
  session cookie carries only the platform session id.

## The production posture: no demo cast (TODO.demo-ops/01)

A deployment that serves real accounts only declares
`demo_personas: false` in its instance profile. The flag closes the
whole demo path at once:

- the account seed skips the demo cast — no `provider='demo'` rows are
  provisioned (the profile-aware account plan,
  `@oimlsmart/platform-server/profile`);
- the demo endpoints refuse honestly: `POST /api/auth/demo` answers 403
  and `GET /api/auth/demo-accounts` answers
  `{ enabled: false, accounts: [] }`;
- `/api/config`'s `identity.demoAccountsEnabled` answers `false`, so
  the login page renders no persona block and no local email/password
  form — the configured sign-in (GitHub on the platform hub, or SSO)
  leads. A deployment with nothing configured at all gets an honest
  "no sign-in method configured" note instead of a blank card.

The demo gate resolves (`demoAccountsEnabled`,
`browser/server/auth/identity.ts`): the `DEMO_ACCOUNTS_ENABLED` env
override wins in both directions; otherwise the profile flag decides;
with neither declared, the historical default stands (the cast on, off
once SSO is configured).

The platform hub (platform.oimlsmart.org) runs exactly this posture:
`wrangler.toml`'s top-level `[vars]` carries the hub profile with
`demo_personas: false`, and GitHub sign-in (above) is the only path.
The demo cast lives on the dedicated demo instances (TODO.demo-ops/02+)
and on preview deployments, which declare `demo_personas: true`
explicitly.

Two operational notes:

- **Local users have no sign-in path under this posture.** Accounts an
  admin creates in the instance-settings users section are
  local-password accounts (`provider='demo'`); with the demo endpoint
  closed they cannot sign in. On a personas-off deployment, accounts
  arrive through GitHub/SSO provisioning only.
- **Removing an already-provisioned cast is an ops act, not a deploy.**
  `browser/scripts/demo-ops/remove-demo-users.ts` deletes the known
  cast's `users` rows and their sessions from a D1 database (a dry run
  by default; `--execute` applies; admin-created local users outside
  the known cast are listed, never touched). The workflow content and
  the audit trail stay — records the cast created keep their recorded
  attribution.

Proof: `src/__tests__/demo-ops-gate.test.ts` (the endpoints' refusal +
the seed skip, in-process), `src/__tests__/demo-ops-login.test.ts` (the
login page per configuration), and the fixture-stack e2e
`browser/e2e/demo-ops-01.e2e.ts` (a personas-off stack with GitHub
declared shows no demo path; a personas-on stack renders the cast).

## The OIML SMART identity provider (id.oimlsmart.org)

TODO.identity/01 builds the federation's own OpenID Connect **Provider**
in this codebase: another deployment profile of the SAME build — one
Worker with its own D1 — serving the OP contract that the instances
(the relying-party side above) already consume. An instance signs in
through it by declaring `OIDC_ISSUER=https://id.oimlsmart.org` (+ its
client id/secret) exactly as it would for any external IdP.

![The OP/RP arrangement](identity-op-rp.svg)

### The `identity` deployment profile

`@oimlsmart/platform-server/profile` carries a fourth profile role: `identity`.
An instance booted with `roles: [identity]` serves the OP endpoints and
nothing else — the profile's own identity (`org_name`, the branding)
IS the provider's public identity (the consent page names it), and the
module gates every OP route: any other profile answers 404 on them
(the routes exist in the one build; the profile decides). The OP's own
sign-in surface IS the instance's login page — the invite-only password
accounts with GitHub as a linked login method (TODO.identity/02, "The
account model" below); the demo cast rides along in development only
(the profile keeps `demo_personas: false` in production).

### The endpoints

| Endpoint | What it is |
|---|---|
| `GET /.well-known/openid-configuration` | The discovery document (the RP's `discoverIssuer` requires the exact issuer match). |
| `GET /jwks.json` | The public signing keys: ES256, kid'd, with the rotation history (every `active` row of `oidc_keys` is served, so a rotation never strands an in-flight token). |
| `GET /op/authorize` | The authorization endpoint: validates the client and the EXACT `redirect_uri` against the registry (an unregistered one is refused in place, never redirected to), requires `response_type=code`, the `openid` scope and PKCE S256, then either redirects to the instance's login page (no session — the flow re-enters afterwards) or to the consent page. |
| `GET /op/consent` | The consent page (the app's house style): the client name, the scopes, the account being shared, allow/deny. |
| `POST /op/token` | The code exchange: the one-time code (consumed atomically — a replay always loses with `invalid_grant`), the PKCE verifier, and the client secret (HTTP Basic or form; public clients run on PKCE alone). Answers the signed ES256 ID token (`iss`, `sub`, `aud`, `exp`, `iat`, `nonce`, plus the claims policy's extras) and a Bearer access token. |
| `GET /op/userinfo` | The access token's claims (the same scope + policy split as the ID token). |
| `GET /op/avatar/:id` | The PUBLIC avatar serve (no session; the GitHub-avatars convention): the stored upload with its real content type + `nosniff` + a short public cache, the generated-initials SVG for a known account without an upload (or with no blob store bound), a plain JSON 404 for an unknown or erased account. This is the URL the `picture` claim names. |

All OP state that must survive Worker isolates lives in D1
(`oidc_clients`, `oidc_authorizations`, `oidc_codes`,
`oidc_access_tokens`, `oidc_keys` — schema `0004_oidc_op.sql`);
NOTHING rides a per-process Map (the GitHub-flow lesson). The
implementation is `browser/server/routes/op.ts` +
`browser/server/auth/op/`, WebCrypto only.

### The client registry

Every relying party is a row in `oidc_clients`: client id, display name,
the hashed secret (NULL = a public client), the exact redirect URIs, the
**claims policy**, and the status (`active`/`disabled` — a disabled
client is refused at authorize and token, its rows kept).

The claims policy is a per-client privilege: `claims: ["roles"]` (and/or
`"groups"`, `"org"`) puts the account's platform roles/organization into
that client's ID tokens — the values the instance's fed-10 claim mapping
reads. A client with no policy receives profile+email claims only.

The registry is admin-managed (`GET/POST /api/op/clients`,
`POST /api/op/clients/:id/status`, gated to `admin`/`cs_admin`); the
client console (`/op/admin/clients`, TODO.identity/07) carries the CRUD
with the shown-once generated secret, and the per-client role
assignments of TODO.identity/03 consume the claims policy (the user
registry's console landed with it). The known instances bootstrap
from the `OP_CLIENT_SEED` env (a JSON array of
`{ client_id, name, secret?, redirect_uris, claims_policy? }`,
upserted at boot — secrets hashed PBKDF2 before they touch the
database; declare the seed as a Worker secret when it carries them).

### The signing keys

One ES256 (P-256) pair per deployment, kid'd. The PRIVATE key is the
`OP_SIGNING_KEY` secret — a JWK JSON document
(`{"kty":"EC","crv":"P-256","x","y","d","kid"?}`) put with
`npx wrangler secret put OP_SIGNING_KEY --env identity`, never the
repo, never the database. Its public half registers into `oidc_keys` on
first use; JWKS serves the table, so the public key set survives
isolates and restarts. Unset (a dev boot): an ephemeral pair is
generated per process with a loud warning — tokens invalidate at
restart and sibling isolates would sign differently; never a production
posture. Rotation: issue the new key into `OP_SIGNING_KEY` and the old
public half stays served until you retire its kid (after the token
lifetime, default 1 h, has passed).

### The account model (TODO.identity/02)

The OP holds its OWN account list — real password accounts, invited by
an administrator, with GitHub as a linkable login method. There is no
open signup, ever.

**Password accounts.** The credential lives apart from the account row
(the `passwords` table — no `SELECT *` on `users` ever reads credential
material), PBKDF2-HMAC-SHA256 at 600 000 iterations (OWASP's current
recommendation) over WebCrypto (`browser/server/auth/passwords.ts`), so
node and the Worker run the identical code path and no dependency enters
the bundle. The stored value is self-describing
(`pbkdf2:<iterations>:<salt>:<digest>`) — a cost change never strands an
account. The policy gates on length only (≥ 12); the strength meter on
the setup page advises honestly and refuses nothing beyond the policy.
Passwords are never logged; the sign-in is timing-shaped (an unknown
email pays one full-cost verify too, so the response time cannot
enumerate accounts). The demo cast's shared-plaintext pattern stays with
the demo instances — the OP never carries it.

**Invite-only enrollment.** An admin creates the account (email + name)
through `POST /api/op/accounts` and receives a ONE-TIME setup link
(`/op/setup?token=…`, 24 h TTL, the `enrollment_tokens` table). The link
is EMAILED to the account when a mail provider is configured (the
transactional-email section below) and handed over out-of-band when it
is not; the response's `mail` block says which happened, honestly. The
setup page names the account (name + email,
nothing more), takes the password, and consumes the link atomically:
one-time means one-time, and an expired link is burned on presentation,
never redeemed later. `POST /api/op/accounts/:id/enrollment` mints a
fresh link (an expired invite, or a password reset; the link sets the
password either way, and the reset email carries it when the mailer is
configured). The first administrator on a fresh OP arrives by
declaration: `OP_ACCOUNT_SEED` (a JSON array of `{ email, name, role? }`,
a Worker secret in production) upserts the account at boot and — while
it has no password — logs a fresh one-time setup link at every boot (the
operator's way in; once the password is set the seed goes quiet).

**The self-service password reset.** `POST /api/op/login/reset` (the
login page's "Forgot your password?") is the account holder's own path,
and it is deliberately narrower than the admin's: the answer is the same
constant 200 whether the address names an account, is unknown, is
deactivated, or belongs to another provider (no enumeration, and the
mailer's per-recipient rate limit never becomes an oracle either: a
refused send swallows into the same 200). The reset travels BY EMAIL
ONLY: the one-time link (02's enrollment machinery again, 24 h) sets a
password, so it never appears on screen to an unauthenticated requester;
a deployment without a mail provider answers an honest 503 and points at
the administrator's re-issue. The request lands on the account's own
activity feed (`account.password_reset`), so the holder learns of it
whoever asked.

**Offboarding: deactivate vs erase.** `POST /api/op/accounts/:id/status`
deactivates: the row stays, sign-ins refuse honestly, and every live
credential (sessions, access tokens, unconsumed codes, pending
authorizations) is revoked; reactivation restores. `DELETE
/api/op/accounts/:id` is the erasure path the operations runbook
promises: everything the account held is removed (password credential,
enrollment and email-change tokens, linked identities, per-client role
assignments, the live credentials, the uploaded avatar's bytes) and the
user row is anonymized in place: `Deleted account`,
`deleted-<id>@erased.invalid`, provider `erased`, inactive, no
organization, no roles. The tombstone keeps the audit chain's entity_id
resolvable and the foreign keys intact, while every surface (the
registry list, the sign-in joins, the admin acts) drops the row: the
account is gone, the history stands, and the freed email address can be
invited again. Both paths refuse to act on your own account (the lockout
guard).

**The avatar.** The account console's picture uploads ride the
document-store seam (`server/blobs.ts`: R2 on the Worker, disk on node)
under `avatars/<account id>/avatar.<ext>` keys, through the account's own
routes, never the entity-gated `/api/blobs` surface. The limits live in
`browser/server/auth/op/avatars.ts`: **2 MiB** (`AVATAR_MAX_BYTES`
overrides), the four raster types only (PNG, JPEG, WebP or GIF; SVG is
excluded so an image channel can never become a script channel), and the
stored bytes are sniffed against the declared Content-Type (a mislabeled
payload is refused, never stored). The console's upload runs through a
client-side crop step first: the picked file opens a dialog (square
crop, drag + zoom, a live preview) and the confirm renders the framed
square to a 256 px PNG in the browser (`src/lib/avatar-crop.ts` +
`src/components/AvatarCropDialog.vue`), so the route always receives the
final image and never has to fix one. The serving route
(`GET /api/op/account/avatar`) answers the session account's own picture
with `x-content-type-options: nosniff`; the account row's `avatar_url`
points at it, so the console, the header's user menu and the consent
page all render the same picture. Without a blob store binding the
feature degrades honestly: the routes answer 503, the console hides the
upload and says why (the identity Worker's R2 binding ships commented
out in `wrangler.toml` until the operator creates the bucket, the same
doctrine as the mailer).

The READ side has a second, public face: `GET /op/avatar/<account id>`
(the table above) serves the same bytes WITHOUT a session, the
GitHub-avatars pattern, because the OIDC `picture` claim names that URL
and an RP loads it from a cross-origin `<img>`. A known account without
an upload answers the generated-initials SVG (the console's own
fallback, served), an unknown or erased account the plain 404; never an
error page. The claim itself (`picture`, one of the claims-policy
families) appears in the ID token and userinfo only when the client's
policy carries the family AND the account has an uploaded picture, so a
token never points at the fallback. The console's avatar section states
this public-by-convention posture to the account holder.

**Linked identities.** The `identity_links` table binds an upstream
account to the identity it may sign in: `(user, provider,
provider_account_id, linked_at, linked_by)`, one row per
`(provider, provider_account_id)`. The account page (`/app/account`)
lists them with link/unlink actions. The upstream sign-in methods
themselves — GitHub, Google, Apple, Entra, generic OIDC — are
TODO.identity/08's registry-driven flows (the section below): a provider
is a ROW in `identity_providers`, never a code fork, and THE MATCH RULE
holds throughout — an upstream sign-in resolves by
`(provider, provider_account_id)` against these links, **never by email
alone**, even when the upstream vouches for the address (an unlinked
identity gets the honest "not linked — ask your administrator" refusal).
**GitHub (or any upstream) is a login method, never the account list** —
unlinking it never touches the account, and the account list never
depends on the upstream.

**Sessions.** The OP's sessions ride the same `sessions` store as every
instance; the account page lists the account's live sessions (the
current one marked, the token itself never exposed) and revokes any of
them (`POST /api/op/account/sessions/:id/revoke` — another account's
session id is a no-op by construction).

The account API surface (every path profile-gated to the identity
module, like the OP's):

| Endpoint | What it is |
|---|---|
| `POST /api/op/login` | The password sign-in (timing-shaped; a deactivated account with the right password gets its own honest refusal). |
| `POST /api/op/login/reset` | The self-service password reset: the constant 200 (no enumeration), the one-time link by email only; the honest 503 when no mail provider is configured. |
| `POST /api/op/accounts` · `GET /api/op/accounts` · `POST /api/op/accounts/:id/enrollment` | The admin's invite surface (admin/cs_admin): create the account + its one-time link (emailed when the mailer is configured; the response's `mail` block says), list the accounts with their sign-in posture (never credentials), re-issue a link. |
| `POST /api/op/accounts/:id/status` · `DELETE /api/op/accounts/:id` | The offboarding pair (admin): deactivate/reactivate (the history kept, the live credentials revoked) and the erasure (everything removed, the row anonymized in place). Both refuse the operator's own account. |
| `GET /api/op/enroll/:token` · `POST /api/op/enroll/:token` | The setup page's context and completion (public; the completion consumes the link atomically). |
| `GET /api/op/account` · `POST /api/op/account/password` · `POST /api/op/account/sessions/:id/revoke` | The account self-service (the linked identities' list/link/unlink ride 08's `/api/op/account/links` + `/op/upstream/:id/*`). The context carries the avatar feature's availability and its byte cap (`features.avatarUploads` / `features.avatarMaxBytes`). |
| `PUT /api/op/account/avatar` · `GET /api/op/account/avatar` · `DELETE /api/op/account/avatar` | The avatar: the upload (2 MiB cap; PNG/JPEG/WebP/GIF; the bytes sniffed against the declared type), the same-origin serve (the session account's own picture), the removal. 503 honestly where no blob store is bound. |

The schema is migration `0006_op_accounts.sql` (`passwords` +
`enrollment_tokens`; `identity_links` landed with 08's
`0005_upstream_providers.sql` — `schema.sql` carries the same end state
and the D1 tripwire pins the union). On the live service:

```sh
npx wrangler d1 migrations apply oiml-smart-platform-identity --env identity
npx wrangler secret put OP_ACCOUNT_SEED --env identity   # the first administrator(s)
# the GitHub linked login rides OP_UPSTREAM_SEED — the upstream section below
```

### Running it locally

```sh
cd browser
INSTANCE_PROFILE=e2e/fixtures/instance.profile.identity.yaml \
OP_ISSUER=http://localhost:3190 \
OP_CLIENT_SEED='[{"client_id":"local-hub","name":"Local hub","secret":"dev-secret","redirect_uris":["http://localhost:5190/api/auth/callback/oidc"],"claims_policy":{"claims":["roles","org"]}}]' \
npm run dev
```

…then point a local instance at it (`OIDC_ISSUER=http://localhost:3190`,
`OIDC_CLIENT_ID=local-hub`, `OIDC_CLIENT_SECRET` by reference). The e2e
(`browser/e2e/id-01-op.e2e.ts`) boots exactly this stack, port-isolated.

### The live deploy (the item's final step)

`wrangler.toml`'s `[env.identity]` declares the Worker
(`oiml-smart-platform-identity`), its own D1, `OP_ISSUER =
https://id.oimlsmart.org`, and the identity profile inline. To deploy:

```sh
cd browser
npx wrangler d1 create oiml-smart-platform-identity   # paste the id into [env.identity]'s database_id
npx wrangler d1 migrations apply oiml-smart-platform-identity --env identity
npx wrangler secret put OP_SIGNING_KEY --env identity # the ES256 private JWK (JSON)
npx wrangler secret put OP_CLIENT_SEED --env identity # the known instances' registry rows
npm run deploy:cloudflare -- --env identity           # then attach id.oimlsmart.org (the domain step)
```

### Proving the OP

- Unit: `src/__tests__/id-op-core.test.ts` — the full
  authorize→consent→token→userinfo round trip in-process, with the RP's
  REAL validator (`auth/oidc.ts`'s `validateIdToken`) consuming the OP's
  token against the OP's own JWKS; PKCE failure and code replay refused;
  the registry's refusals (unknown client, unregistered redirect_uri,
  disabled client); the per-client claims policy; the sign-in redirect;
  deny; the cross-account wall; the admin surface; the module gate.
- e2e: `browser/e2e/id-01-op.e2e.ts` boots the identity-profile stack
  (its own API + astro + SQLite) and drives a fixture RP
  (`e2e/fixtures/stub-rp.ts`, riding the RP's real client code) through
  the browser round trip — discovery, sign-in, consent (allow AND deny),
  the validated token, userinfo, the redirect_uri wall, the replayed
  code.
- Accounts (TODO.identity/02): `src/__tests__/id-accounts.test.ts` — the
  hashing (round-trip, wrong-password, the login path's timing shape),
  the policy + the meter, the enrollment link (one-time, expiry,
  re-issue), the link rules (linked/refreshed/taken, NEVER email-only,
  the lockout guard), the session listing + revocation, the self-service
  reset's no-mailer 503 (the mailed half is id-mail.test.ts's), the
  avatar (the full circle over an in-memory blob store, the 2 MiB cap
  both ways, the type allowlist, the byte sniff, the audit events, the
  honest 503 with no store bound), the account erasure (the guards, the
  tombstone, the freed email), and the module
  gate — all in-process over a real SQLite store against the stub
  GitHub; `src/__tests__/d1-store.test.ts` proves the same account
  semantics on the D1 store + the migration tripwire.
  `browser/e2e/id-02-accounts.e2e.ts` drives the browser through the
  full lifecycle — the bootstrap seed's logged link, the invite, the
  setup page, the password sign-in, the GitHub link/sign-in/unlink
  (stub GitHub), the honest not-linked refusal, and a full
  authorize→consent→token round trip with an invited password account.
  The console legs extend it: `id-06-account-console.e2e.ts` leg 6 is
  the avatar (the upload through the real file input, the client- AND
  server-side refusals, the serve, the header's user menu, the removal,
  the guide capture); `id-07-registry.e2e.ts` leg 9 is the erasure (the
  two-step console act, the dropped directory row, the refused sign-in,
  the freed email, the journaled act); `id-09-email.e2e.ts` leg 4 is the
  self-service reset (the login page's forgot-password panel, the
  captured reset email, the emailed link completing, the oracle legs).

### The account-holder console (TODO.identity/06)

`/app/account` on the OP is the account holder's full self-service
console (the Keycloak/Clerk standard), five sections, every string keyed
in the `account.*` EN/FR catalog namespace:

1. **Profile**: the display name (edited inline through
   `POST /api/op/account/profile`), the avatar (an uploaded picture:
   2 MiB cap, PNG/JPEG/WebP/GIF, the bytes sniffed against the declared
   type, `PUT/GET/DELETE /api/op/account/avatar`; a linked provider's
   picture; initials otherwise; the section above details the limits),
   and the primary email with its verification state
   (`users.email_verified_at`). The invite ceremony
   marks the invited address verified (the administrator delivered the
   one-time link there); an email change re-judges it (below).
2. **Sign-in methods**: the password and the linked upstream identities
   as equal citizens. THE GUARD: an account always keeps at least one
   way in. `DELETE /api/op/account/password` and 08's
   `DELETE /api/op/account/links/:provider` both refuse (409, with the
   explanation) when the removal would strand the account; the console
   disables the button and shows the same explanation.
3. **Password**: set/change with the current-password check when one is
   set. A change revokes every OTHER session of the account
   (`deleteOtherSessions`; the response names the count and the console
   shows it): the best-practice eviction path.
4. **Sessions**: `sessions` gained `user_agent` and `ip` (stamped at
   creation from the request's `user-agent` and `cf-connecting-ip` /
   first `x-forwarded-for` hop, `@oimlsmart/platform-server/client-info`; NULL
   renders as "not recorded") and `last_seen_at` (touched by session
   resolution, throttled to one write per minute per session).
   `POST /api/op/account/sessions/revoke-others` signs out everywhere
   else.
5. **Activity**: `GET /api/op/account/activity` reads the account's OWN
   events from the OP's audit chain (the `account`/`auth` families the
   identity routes write: sign-ins, invite/enrollment, profile edits,
   email changes, link/unlink, password acts, session revocations),
   newest first, bounded at 50. The filter keys on the account id:
   nobody else's events ever appear, and the events never carry
   credential material.

**The verify-new-email ceremony.** `POST /api/op/account/email`
validates the address (format, not the current one, not taken), mints a
one-time 24 h link (`email_change_tokens`, the enrollment doctrine: a
256-bit random token, the row is its proof, consumed atomically at
completion; a fresh request voids the account's earlier pending links),
and delivers it through the seam in `server/auth/op/email-change.ts`.
The token row stamps `delivered_by`:

- `'mailer'`: the link was emailed to the NEW address; completing it
  marks the address verified.
- `'shown'`: no mailer is configured, so the link is returned to the
  signed-in holder and displayed with the honest explanation; completing
  it applies the change but the address stays unverified.

`GET /api/op/email-change/:token` is the landing page's
(`/op/email-change?token=…`) public context (name + the from/to
addresses, nothing more); `POST` completes: one-time, expiry burned on
presentation, and a take-over of the address between request and
completion answers 409 with the token burned.

**The delivery seam** (documented here as TODO.identity/09's integration
point, now wired): `deliverEmailChangeLink(env, { to, name, issuer,
verificationUrl })` in `server/auth/op/email-change.ts` hands the link to
09's mailer (`server/auth/op/mail.ts`'s `verify_email` template) and
answers `'mailer'` on a confirmed send; a console-posture mailer, a
transport failure, or the rate limit all answer `'shown'` and the console
displays the link with the honest explanation. Nothing else in the flow
changes per channel.

The schema is migration `0009_account_console.sql` (`schema.sql`
carries the same end state; the D1 tripwire pins the union, and both
stores ensure the new columns defensively for pre-0008 dev databases).
Proven by `src/__tests__/id-account-console.test.ts` (the ceremony's
every exit, the guards, the session revocation, the feed's scoping) and
`browser/e2e/id-06-account-console.e2e.ts` (the browser legs, including
the guard's disabled button against the server's 409).

## The upstream sign-in providers (TODO.identity/08)

The identity provider's own account holders sign in through UPSTREAM
providers — GitHub, Google, Apple, Microsoft Entra, or any OIDC issuer
(an NMI's internal Keycloak/ADFS plugs in with zero code) — driven by
the **upstream provider registry**: rows in the `identity_providers`
table. Adding a provider is a row, never a code fork.

![The provider buttons on the identity provider's sign-in page](img/identity-upstream-login.png)

### The registry

One row per provider (`server/routes/op-upstream.ts` + the
`identity_providers` table — migration `0005_upstream_providers.sql`):

| Field | Meaning |
|---|---|
| `id` | The provider slug — it rides URLs (`/op/upstream/<id>/…`) and the link rows. Lowercase, dash-separated. |
| `kind` | `github` (the OAuth web flow — no discovery, no ID token; the account id is the numeric profile id) or `oidc` (discovery + Authorization Code + PKCE; the account id is the ID token's `sub`). |
| `display_name` | The sign-in button's label. |
| `brand_mark` | The button's icon key: `github` / `google` / `apple` / `microsoft` / `oidc` (absent = the generic mark). |
| `issuer` | `oidc` kind only: the issuer URL (the discovery root — the metadata's `issuer` must match it exactly). GitHub's endpoints instead ride the `GITHUB_OAUTH_BASE_URL` / `GITHUB_API_BASE_URL` env seam (github.com by default, GHES by override). |
| `client_id` | The OAuth/OIDC client id (Apple: the Services ID). |
| `client_secret_ref` | `env:<NAME>` — the client secret's environment variable. **The secret is never stored** — not in the table, not in a profile file (the `OIDC_CLIENT_SECRET_REF` discipline). Absent = a public client (PKCE carries the proof). |
| `scopes` | Optional override. Defaults per kind: github `read:user user:email`; oidc `openid profile email`; Apple `openid name email`. |
| `enabled` | The toggle. Only enabled rows render on the sign-in page and accept flows; disabling keeps the row (and the links against it) for the audit trail. |

The registry is admin-managed (`GET/POST /api/op/providers`,
`POST /api/op/providers/:id/status`, `DELETE /api/op/providers/:id`,
gated to `admin`/`cs_admin`); the provider console
(`/op/admin/providers`, TODO.identity/07) carries the rows, the enable
toggle, and the secret-by-reference discipline.
Deployments can also bootstrap rows from the `OP_UPSTREAM_SEED` env (a
JSON array of the same shape, upserted at boot — the `OP_CLIENT_SEED`
pattern).

The flow state is STATELESS and signed (`auth/upstream/state.ts`):
`state` carries the provider, the mode (`login`/`link`), the OIDC nonce
+ PKCE verifier, the post-sign-in redirect (local paths only) and its
issue time, HMAC-signed with the OP's own key material — nothing rides
a per-process Map, so the callback verifies on any Worker isolate (the
GitHub-flow lesson). Rotating `OP_SIGNING_KEY` invalidates in-flight
flows (10-minute TTL) — they simply restart.

### The match rule — never by email

An upstream sign-in resolves **only** by `(provider,
provider_account_id)` against the `identity_links` table — GitHub's
numeric profile id or the OIDC `sub`. **Never by email alone**: an
upstream identity whose (even verified) email address matches an
account but that holds NO link is refused honestly ("your ⟨provider⟩
account is not linked — ask your administrator"): no account, no
session, and the audit trail records the refusal. One upstream account
links to exactly one OIML SMART account
(`UNIQUE(provider, provider_account_id)`); one account holds at most
one link per provider (unlink first to re-link).

### Linking

The account holder links from the account console (`/app/account`,
TODO.identity/02 + 06; the old `/op/account` path redirects there):
"Link ⟨provider⟩" runs the provider's flow **bound
to the current session** (the state carries the account id; a switched
session mid-flow fails honestly) and returns to the account page with
the link listed. Unlink is the same page. Signing in afterwards is the
provider button on the sign-in page.

### Per-provider setup

Every case: the redirect (callback) URI is
`https://<op-host>/op/upstream/<id>/callback` where `<id>` is the
registry row's slug.

- **GitHub.** GitHub → Settings → Developer settings → OAuth Apps (the
  organization for a team deployment), callback URL as above;
  `kind: github`, the client id on the row, the secret as
  `env:GITHUB_CLIENT_SECRET`-style reference. GHES: the
  `GITHUB_*_BASE_URL` overrides.
- **Google.** Google Cloud console → APIs & Services → Credentials →
  "Create OAuth client ID" (Web application) with the redirect URI;
  issuer `https://accounts.google.com`. The client secret goes in the
  referenced env var.
- **Apple ("Sign in with Apple").** Apple developer portal →
  Identifiers → create an **App ID**, then a **Services ID** (the
  registry row's `client_id`) configured with the domain + the redirect
  URI; then Keys → a "Sign in with Apple" key (download the `.p8`).
  Issuer `https://appleid.apple.com` (the row is recognized as Apple by
  the issuer HOST — the quirks apply automatically):
  - the authorize request uses `response_mode=form_post` (the callback
    answers POST);
  - the user's **name** arrives only at the FIRST consent, in the
    callback's `user` form field (the link keys on `sub` regardless);
  - the client secret is a short-lived **ES256 JWT** signed with the
    `.p8` key, minted per exchange from the env: `APPLE_TEAM_ID` (the
    team id), `APPLE_KEY_ID` (the key id), `APPLE_PRIVATE_KEY` (the
    `.p8` PKCS#8 PEM — a Worker secret in production). No
    `client_secret_ref` on the row.
- **Microsoft Entra.** Entra admin center → App registrations → Web
  with the redirect URI; the issuer is tenant-scoped:
  `https://login.microsoftonline.com/<tenant-id>/v2.0`. Client secret
  (or certificate-backed federated credentials are NOT supported — the
  client-secret posture only) in the referenced env var.
- **Generic OIDC (Keycloak, an NMI's internal IdP).** Keycloak: realm →
  client (openid-connect, standard flow) with the redirect URI; issuer
  `https://<host>/realms/<realm>`. Any standards-conformant issuer
  works the same way — discovery, PKCE S256, RS256/ES256 ID-token
  signatures.

### The failure surface

Every failure lands on the sign-in page with a plain-language message
(`?error=upstream_<reason>`, the provider named): the unknown/disabled
provider, the state mismatch/expiry, the upstream's own refusal, the
exchange/discovery/token-validation failures, and THE MATCH RULE's
`upstream_not_linked`. The server log carries the technical detail;
audit events record `upstream_sign_in` / `upstream_link` /
`upstream_unlink` / `upstream_refused` / `upstream_link_conflict`.

### Proving the upstream providers

- Unit: `src/__tests__/id-upstream.test.ts` — the registry validation +
  CRUD + the enabled-only public projection; the stateless state's
  sign/verify/tamper/expiry/open-redirect matrix; the Apple secret JWT
  (claims, header kid, the signature against the public key); the OIDC
  link/sign-in/refusal/unlink round trips against the stub IdP; the
  GitHub kind against the stub GitHub; the form_post (Apple) callback
  shape; the cross-provider state binding; the no-email-only-match
  guard (a verified-email lookalike with no link is refused).
- e2e: `browser/e2e/id-08-upstream.e2e.ts` boots the identity-profile
  stack plus the stub IdP (the generic provider row) and drives the
  browser through the registry → the login-page button → link →
  sign-in → the honest refusal → unlink → refused again.

## The central user registry + the per-client role claims (TODO.identity/03)

The OP is where "the list of possible accounts" lives — the
administrator maintains the whole federation's accounts from one place,
and each instance receives only the roles its client registration
allows.

**The registry console.** The administration console
(`/op/admin/users`) — the same surface TODO.identity/10's delegated
organization administration uses — carries the wide grant's registry
view (`admin`/`cs_admin`): every OP account with its organization
binding, its sign-in posture, its **per-client roles**, its **last
sign-in** (read back from the audit chain), and the acts: invite, edit
(name/email), assign roles per client, a fresh setup link,
deactivate/reactivate. The org-scoped `org.users.manage` grant is
refused on every one of these — the organization administrator keeps its
own org's slice (10's view) and never reaches the registry's acts.

**The per-client role assignments.** The account's own role set
(`users.role`/`roles`) is its federation-wide default. A row in
`op_client_roles` (migration `0008_op_client_roles.sql`) overrides it
for ONE registered client: the ID token issued to that client carries
the assigned roles. An EMPTY assignment is the explicit "no roles on
this client" — distinct from NO ROW, which leaves the default carrying
(the pre-03 behavior, so a deployment that never assigns per-client
roles emits exactly what it always did). The admin acts:

| Endpoint | What it is |
|---|---|
| `PUT /api/op/accounts/:id/client-roles/:clientId` | Assign the account's roles for one client (`{ roles: [...] }`; `[]` = the explicit none). Validated: the client must be registered, the roles in the platform vocabulary, and within the client's claims-policy role allowlist when it declares one — a refusal names the policy. |
| `DELETE /api/op/accounts/:id/client-roles/:clientId` | Clear the assignment (the account default carries for that client again). |
| `PUT /api/op/accounts/:id` | The edit act (name/email; a taken email is the honest 409). |
| `POST /api/op/accounts/:id/status` | Deactivate/reactivate (below). |

**The role-claim policy per client.** The client registry's claims
policy (01) gains the optional `roles` allowlist
(`claims_policy: { claims: [...], roles?: [...] }`): the closed set of
roles the ID token may carry for that client. The shaping rule
(`server/auth/op/claims.ts` — the ONE function the token endpoint,
userinfo, the consent context and the console's preview share):

1. the claim gate (01): no `roles`/`groups` in the policy's `claims` →
   no role claim at all;
2. the assignment (03): the per-client set, or the account default when
   no row exists;
3. the allowlist (03): when the policy declares `roles`, the emitted set
   is intersected with it — **the OP never emits a role the client is
   not configured to receive**.

The allowlist is validated at write time (the clients API and the
`OP_CLIENT_SEED` parser both refuse a role outside the platform
vocabulary, naming it). The consent page names the effective set before
anything is released ("On ⟨client⟩ you hold: …"). The instance side
never invents a role either: the fed-10 claim mapping
(`@oimlsmart/platform-server/vocab`'s `rolesFromClaims`, and the profile's declared
`claimMapping` rules) keeps only roles the instance's own RBAC map
knows; an account with NO role claim for the instance lands in the
configured `defaultRole` (viewer — the intended safe value) or the
administrator's approval queue, never silently wider.

**The honest deactivation.** `POST /api/op/accounts/:id/status` with
`active: false`: the account row STAYS (the history — assignments,
audit trail, linked identities), sign-ins REFUSE (the credential check
answers the plain "deactivated" message; the session join stops
resolving), and the live credentials are REVOKED in the same act —
every session, every issued OIDC access token, every unconsumed code and
pending authorization (`revokeOpUserCredentials`; the counts ride the
audit event). You cannot deactivate your own account (the lockout
guard). Reactivation restores sign-in; the assignments were never
wiped.

**The audit chain.** Every admin act lands an `auditEvents` row (the
invite with its org binding + per-client roles, the edit's before/after,
each assignment with its previous value, the deactivation's revocation
counts, the reactivation), and every OP-side sign-in writes
`account.sign_in` (the password login; a linked-provider sign-in rides
08's `upstream_sign_in`). The registry list's last-sign-in column is
read back FROM the chain (`lastAccountSignIns`), never from a mutable
column.

**Proving the registry.** Unit: `src/__tests__/id-registry.test.ts` —
the shaping rule (the pure half + the real round trip: the assignment
rides the ID token, the explicit empty set omits the claim, the
allowlist filters, userinfo agrees), the policy validation, every admin
act (invite/edit/assign/deactivate/reactivate, the lockout guard, the
409s), the org-scope bound, the instance-side honoring. e2e:
`browser/e2e/id-03-registry.e2e.ts` boots the identity-profile stack +
the fixture RP and drives the browser through invite → assign (the
offer bounded by the policy) → the consent page's honest preview → the
issued ID token's claims → deactivate (the live session revoked, the
right password refused) → reactivate (the assignment kept). The admin
guide page:
[The oimlsmart identity registry](https://github.com/oimlsmart/smart/blob/v2/docs/guides/biml-admin/the-identity-registry.md) (the guide lives with the monorepo until its own transfer).

## Delegated organization administration (TODO.identity/10)

The account-management topology for the member states: BIML never
manages hundreds of member-state people by hand. Three tiers:

```
BIML ── manages ──▶ ORGANIZATIONS (the participants register is the
                     source of truth — an account naming an org is
                     created only for a REGISTERED participant org,
                     PD-03 / B 18:2025 §10.2)
                      │
                      ▼  one org admin per org, created by BIML after
                         verification (the org_admin role)
ORGANIZATION ── manages ──▶ ITS OWN PEOPLE (the org-scoped
                            org.users.manage permission: the org admin
                            invites, assigns the kind-bounded roles and
                            deactivates — only ever its own org's slice)
```

### The pieces

- **The `org_admin` role + the org-scoped `org.users.manage`
  permission** (the RBAC catalog, `@oimlsmart/platform-server/vocab`).
  On the users API (`/api/users`) the grant scopes EVERY read and write
  to the caller's own organization binding: the list answers only the
  org's users, creates land in the org with a role the org's KIND bounds
  (an IA's staff get `ia_officer` and the NMI split roles, a TL's staff
  `tl_operator`, a Utilizer/Associate's staff `viewer` —
  `server/auth/org-registry.ts`), and another org's accounts are not
  found (no cross-org slice exists). The org's own administrator account
  stays with the scheme operator: the scoped grant can neither assign
  `org_admin` nor modify an account holding it.
- **The eligibility rule**: assigning `org_admin` requires the account's
  org to be a REGISTERED participant org — the register is read from the
  entity store (a signed Declaration for IAs/Utilizers/Associates, the
  ACTIVE participation case for TLs). A mid-pipeline org is refused,
  honestly.
- **The join-request flow** (`server/routes/op-join.ts`, the identity
  profile): the public "Request an account" page (`/op/join`, linked
  from the OP's login page) — name, work email, the organization
  SELECTOR fed from the register (searchable; only registered orgs are
  selectable, never a typed name), the role asked for (options bounded
  by the org's kind) and the honest note that approval comes from the
  requester's own organization. The request lands in the ORG's admin
  queue. The "my organization is not listed" path names the org in free
  text and lands with BIML (the new-organizations queue): BIML verifies
  the participation, and the approval — possible only once the org is
  registered — creates its organization administrator. A refusal always
  carries a reason (the requester sees it; for a fake org, the
  participation pointer).
- **The org-admin console** (`/op/admin/users`): the org admin's queue
  (approve → the invite is issued — the TODO.identity/02 enrollment
  seam, bound to its real machinery: an OP password account + the
  one-time 24 h setup link, shown once to the deciding admin for the
  out-of-band handover) and the org's people slice; the scheme
  operator's new-organizations queue and org-admin creation form. The
  same console's wide view is TODO.identity/03's **central user
  registry** (the scheme operator's account surface: per-client roles,
  the audit-chain last sign-in, the honest deactivation — the section
  above).
- **The register's view**: the hub's participants page links each
  registered org to its administration state (has an admin / needs one)
  through the users API's `org-admin-state` projection.

The selector's feed is the instance's SEEDED participants register (the
provisioning seed's organizations + participants phases — the identity
e2e/development profile carries the demonstration register via
`demo_personas: true`). The production identity service takes its
register from the scheme's published content as that content lands —
until then the "not listed" path routes every real request to BIML,
honestly.

### The known reviewer cohort

The IA investigators' list (2026-08-16) maps to registry orgs: NIST,
Sartorius, ISED/ISDE Canada, METTLER TOLEDO, BEV Austria, AIST Japan,
NIM China, INTI Argentina, Measurement Australia, PTB, METAS, NMi, OIML.
Their accounts are issued through the console's invite flow — the
operator invites them as the cohort onboards; accounts are never
auto-created for real people.

### Proving the delegation

- Unit: `src/__tests__/id-org-admin.test.ts` — the org-scoping honesty
  (an org admin provably cannot touch another org's users: scoped list,
  cross-org writes 404, a body naming another org 403, roles outside the
  kind's bound 403, `org_admin` unassignable/untouchable through the
  scoped grant), the eligibility rule (unregistered / mid-pipeline /
  org-less refused), the join flow (the registered-only feed, the
  submit validations, the two queues, the atomic double-decide, the
  email-domain hint, the module gate).
- e2e: `browser/e2e/id-10-org-admin.e2e.ts` boots the identity-profile
  stack and drives the browser through the full topology: the reviewer
  signs up picking their org from the register, BIML creates the org
  admin, the org admin approves (the invite is issued), the colleague
  signs in with the org binding (and the console honestly refuses them —
  staff, not the administrator), and a fake-organization request lands
  in BIML's queue and is refused with the participation pointer.

## Transactional email (TODO.identity/09)

The OP sends real email: the invite (the setup link), the password reset
(the same link, re-issued by the administrator or requested by the
account holder at `POST /api/op/login/reset`, the login page's "Forgot
your password?"; the self-service path is email-only (the link never
shows on screen to an unauthenticated requester) and its answer never
reveals whether the address names an account), the new-sign-in
notification (the password sign-in and every upstream sign-in), and the
confirm-the-new-address
message (TODO.identity/06's email-change flow sends it through the
delivery seam; the section above documents it). Every send rides ONE
mailer interface (`@oimlsmart/platform-server/mailer`, `send({ to, subject, text,
html? })`), with three postures resolved from the environment, best
first:

![The mailer's three postures](identity-email.svg)

The diagram, in prose: the OP's routes call the mailer, which rate-limits
per recipient and audits every send, then delivers through the best
configured posture. The `send_email` binding and the HTTPS provider reach
the recipient's mailbox; the console posture (nothing configured) logs
the message and the flow keeps showing its link.

1. **The Cloudflare Email Service** (public beta): the Worker's
   `send_email` binding. When the `EMAIL` binding and `EMAIL_FROM` are
   present, the message leaves through Cloudflare's own pipeline; no
   HTTPS call leaves the Worker. This is the intended production posture
   for id.oimlsmart.org once the domain authentication below is done.
2. **The HTTPS provider fallback**: `MAIL_PROVIDER_URL` +
   `MAIL_PROVIDER_KEY` (a Worker secret) + `EMAIL_FROM`. The request
   shape is Resend's `POST /emails` (`{ from, to, subject, text, html }`
   with a Bearer key), so any provider speaking that shape plugs in by
   URL alone. Resend is the documented choice (a simple HTTPS API, a
   free tier that covers the OP's volume); the key is an operator
   secret, never the repo, and the provider account itself is an
   operator act (this codebase never creates it).
3. **The console posture** (neither configured): the honest no-op. The
   message is logged in full (the setup link lands in the deploy log,
   the same posture as the bootstrap seed) and the send result says
   not-sent, so the triggering flow keeps SHOWING the link: the invite
   card says "No mail provider is configured on this deployment" and the
   admin copies the link, exactly the pre-mailer handover. Never a
   silent drop.

### The env surface

| Variable | What it is |
|---|---|
| `EMAIL` (binding) | The Cloudflare Email Service `send_email` binding (`[[env.identity.send_email]]` in `browser/wrangler.toml`, shipped commented until the beta and the domain authentication are done; a binding declared before the beta is enabled would fail the deploy). |
| `EMAIL_FROM` | The sender identity both real postures use, declared in the identity env's vars: `OIML SMART Identity <no-reply@oimlsmart.org>`. |
| `MAIL_PROVIDER_URL` + `MAIL_PROVIDER_KEY` | The HTTPS provider endpoint (var) + key (secret: `npx wrangler secret put MAIL_PROVIDER_KEY --env identity`). Both or neither; a half configuration is skipped with the problem named in the log. |
| `MAIL_LOCALE` | `en` (default) or `fr`. The templates render from the EN/FR catalogs (`browser/src/i18n`, the `mail.*` namespace), locked in step by the catalog typing; accounts carry no per-user locale yet (the account console owns that follow-up). |
| `MAIL_RATE_LIMIT_CAPACITY` / `MAIL_RATE_LIMIT_WINDOW_MS` | The per-recipient budget: 5 messages per hour by default; capacity `0` disables the limiter honestly. |

### The guards

Sends are rate-limited per recipient: a token bucket, in-memory per
process/isolate (the federation limiter's documented posture; a global
cap needs a durable counter and is deliberately out of scope). Every
send writes an audit event (`email.sent` / `email.failed` /
`email.logged` / `email.rate_limited`) with the recipient, the template,
the posture, and the error. A failed or tripped send never fails the
triggering flow: the invite and reset responses carry a `mail` block
(`{ posture, sent, error }`), the invite card surfaces it ("The setup
email could not be sent (...). Copy the link below instead"), and the
sign-in notification just audits.

### The templates

Plain text first (the text is the message), with a branded HTML shell
beside it: the instance profile's `branding.name` heads the message
(fed-09), the action URL lifts into a button-styled link with the raw
URL kept for copy-paste, and every interpolated value is escaped. The
copy is EN/FR from the shared catalogs, so the platform's bilingual
lockstep rule covers the outbound mail too.

### Domain authentication (the operator act)

Real delivery needs the sending domain authenticated; the steps live in
the operations runbook ([the monorepo’s cloudflare.md](https://github.com/oimlsmart/smart/blob/v2/docs/deployment/cloudflare.md), "Transactional
email"). In short: enable the Email Service beta on the account, add
oimlsmart.org as a sending domain, publish the SPF / DKIM / DMARC
records it names (the zone is on Cloudflare, so they are ours to set),
then uncomment the binding and deploy. The HTTPS fallback needs the same
class of records at the provider (its dashboard names them) plus the
key secret.

### Proving the mailer

- Unit: `src/__tests__/id-mail.test.ts`: the three postures (a fake
  binding; the stub HTTPS provider over real HTTP; the console log), the
  never-throws rule, the per-recipient rate limit with the injected
  clock, the audit events read back from the store, the EN/FR rendering
  with the HTML escaping, and the routes in-process: the invite email
  carries a WORKING setup link (the enrollment completes with it), the
  console posture's honest fallback response, the password-reset send,
  the sign-in notification, the rate-limit surface, the French locale,
  and the provider failure that never fails the invite.
- e2e: `browser/e2e/id-09-email.e2e.ts` boots the identity-profile stack
  with `MAIL_PROVIDER_URL` pointed at the stub mailer
  (`e2e/fixtures/stub-mailer.ts`) and drives the browser: the admin
  invites through the registry form, the console says the email was
  sent, the invited user completes setup from the link IN THE CAPTURED
  EMAIL, and the sign-in notification arrives.

## Wiring the oimlsmart instances to the OP (TODO.identity/04)

The federation's own arrangement: `id.oimlsmart.org` (the OP, the
`[env.identity]` deployment) is the one identity provider; the platform
hub, the demo hub, the NMI instance and the TL instance are its
registered relying parties. GitHub remains as a **linked sign-in method
at the OP** (TODO.identity/08's upstream registry), never the account
list, and the demo casts stay local to the demo instances (a demo must
never depend on the identity service). The per-user migration from the
old direct-GitHub sign-in is the next subsection.

The wiring is three coordinated declarations, proven end to end by
`browser/e2e/id-04-wiring.e2e.ts` and pinned as committed by
`src/__tests__/id-04-wiring.test.ts`:

### 1. One client per instance, registered at the OP

Each instance is a row in the OP's client registry — registered through
the client console (`/op/admin/clients`) or the registry's admin API
(`POST /api/op/clients`), or the bootstrap `OP_CLIENT_SEED`; the secret is
hashed at rest either way. The four committed clients:

| Client id | Instance | Redirect URI | Role allowlist (the claims policy) |
|---|---|---|---|
| `oiml-smart-platform` | platform.oimlsmart.org | `https://platform.oimlsmart.org/api/auth/callback/oidc` | the hub's full console set: `admin`, `cs_admin`, `biml_officer`, `ia_officer`, `case_officer`, `certification_officer`, `signatory`, `tl_operator`, `mc_member`, `rc_member`, `executive_secretary`, `applicant`, `viewer` |
| `oiml-smart-demo` | demo.oimlsmart.org | `https://demo.oimlsmart.org/api/auth/callback/oidc` | the same (the demo hub serves every console) |
| `oiml-smart-nmi` | nmi.oimlsmart.org | `https://nmi.oimlsmart.org/api/auth/callback/oidc` | `admin`, `ia_officer`, `case_officer`, `certification_officer`, `signatory`, `tl_operator`, `viewer` |
| `oiml-smart-tl` | tl.oimlsmart.org | `https://tl.oimlsmart.org/api/auth/callback/oidc` | `admin`, `tl_operator`, `viewer` |

Every client's policy carries `claims: ["roles", "groups", "org"]` and
the role allowlist above. The `OP_CLIENT_SEED` form (a Worker secret,
since it carries the client secrets):

```json
[
  { "client_id": "oiml-smart-tl", "name": "Example Test Laboratory",
    "secret": "<generated>", "redirect_uris": ["https://tl.oimlsmart.org/api/auth/callback/oidc"],
    "claims_policy": { "claims": ["roles", "groups", "org"], "roles": ["admin", "tl_operator", "viewer"] } }
]
```

### 2. The instance's relying-party declaration

Committed in `browser/wrangler.toml` per environment (the production
hub's top-level `[vars]`, `[env.demo]`, `[env.nmi]`, `[env.tl]`):

```toml
OIDC_ISSUER = "https://id.oimlsmart.org"
OIDC_CLIENT_ID = "oiml-smart-tl"          # this instance's registry row
OIDC_PROVIDER_NAME = "oimlsmart"          # the login button leads with "Sign in with oimlsmart"
OIDC_CLAIM_MAPPING = '''{ "claims": ["groups", "roles"], "rules": [ … ] }'''
DEMO_ACCOUNTS_ENABLED = "true"            # the demo instances only: the cast stays local
```

The secret is never in the file. One per environment:

```sh
cd browser
npx wrangler secret put OIDC_CLIENT_SECRET            # the production hub
npx wrangler secret put OIDC_CLIENT_SECRET --env demo
npx wrangler secret put OIDC_CLIENT_SECRET --env nmi
npx wrangler secret put OIDC_CLIENT_SECRET --env tl
```

The deploy itself applies the D1 migrations per instance (the standard
recipe, the monorepo’s cloudflare.md (https://github.com/oimlsmart/smart/blob/v2/docs/deployment/cloudflare.md) — `0009_sso_states.sql` adds the
SSO sign-in state jar's table, which the sign-in start writes and the
callback consumes atomically; an instance without it cannot serve SSO
(the routes fail loudly, never half-configured).

### 3. The mapping / policy agreement

Two allowlists bound the same channel, and the deployment keeps them
agreeing:

- **The OP's claims policy** (the client row) bounds what the ID token
  may carry for that instance: the OP never emits a role the client is
  not configured to receive, and an account's roles for the instance are
  the registry's **per-client assignment** (TODO.identity/03). No
  assignment at all means the account's OP-side default carries; an
  explicitly EMPTY assignment means the token carries no role claim.
- **The instance's claim mapping** (its `OIDC_CLAIM_MAPPING`) maps the
  emitted values 1:1 onto the platform roles that instance serves, org
  from the `org` claim, with **no `defaultRole`**: an account whose
  token carries no mapped role waits in the instance's approval queue
  (the administrator sees the claims the OP sent and decides), never
  silently wider.

So the effective access decision is the OP registry's per-client
assignment, with the instance's approval queue as the admission control
for accounts the assignment leaves empty. Note what the mapping does NOT
do to a linked account: the next subsection.

### Migrating the direct-GitHub accounts

The instances signed in directly with GitHub before the OP existed
(`users.provider = 'github'` rows, provisioned by the GITHUB_*
allowlists). The cutover keeps those accounts, roles and org bindings
intact, and it is honest about the mechanics:

**The model.** The account of record is the OP account. GitHub becomes
a sign-in method linked to that account **at the OP** (the upstream
registry, TODO.identity/08); the OP's account list never depends on
GitHub, and revoking GitHub access never touches the account. On each
instance, the user's EXISTING local account is adopted by the SSO
sign-in, not replaced.

**The adoption (per user, at their first SSO sign-in).** The OP's ID
token always vouches for the account's email (`email_verified: true`,
the invite-only registry vouches by construction). The instance's
resolution order (above, step 3) links the OP identity onto the local
account whose email matches: the row's provider pair becomes the OP
identity, and **the locally assigned role and org binding stand**; the
OP's role claims are never applied to a linked account. The instance
writes an `sso_link` audit event; the user's console, history and
attributions are untouched. The same adoption covers admin-created
local (`demo`-provider) accounts: any account whose email the OP
vouches for migrates on first SSO sign-in.

**After the move.** A direct-GitHub retry by a migrated user does not
fork a duplicate account and never hits the `users.email` uniqueness
violation: the GitHub callback refuses with the plain-language "this
account now signs in with oimlsmart" page (the
`github_account_moved` outcome; an un-migrated collision with a local
account is `github_email_taken`). GitHub sign-in keeps working normally
for users who have NOT migrated yet.

**The runbook.**

1. Register the instance's client at the OP (subsection 1) and declare
   the instance's `OIDC_*` vars + secret (subsection 2). Both sign-in
   paths now coexist: the SSO button leads, GitHub remains below it.
2. On the OP, invite each person who currently signs in with GitHub
   (the registry console; the one-time setup link goes out-of-band).
   They set their password and may link their GitHub account as a
   sign-in method at the OP (`/app/account`).
3. Assign each account's roles PER CLIENT in the registry (03's
   editor). For existing GitHub users this assignment only governs
   accounts that have no local counterpart; migrated accounts keep
   their local role either way.
4. Each user's first "Sign in with oimlsmart" on an instance migrates
   their account there. Nothing else changes for them.
5. When every direct-GitHub user has migrated (the users section shows
   no `github` rows left), retire the instance's GitHub pair: remove
   `GITHUB_CLIENT_ID` / `GITHUB_CLIENT_SECRET` (and the allowlists) from
   the environment. The button disappears and the endpoint honestly
   501s; GitHub sign-in lives on at the OP as a linked method.

## Troubleshooting

The whole arrangement's failure surface, symptom first. Every one of
these is an honest message or a loud log line; none is a stack trace.
The user-facing half of this table (what the account holder can do) is
[the account guide's "If something looks wrong"](https://github.com/oimlsmart/smart/blob/v2/docs/guides/your-oimlsmart-account.md#if-something-looks-wrong) (the guide lives with the monorepo until its own transfer).

### On an instance (the relying party)

| Symptom | Cause | Fix |
|---|---|---|
| No "Sign in with …" button on the login page | The OIDC configuration is partial or invalid; SSO fails CLOSED | Declare both `OIDC_ISSUER` and `OIDC_CLIENT_ID` (+ the secret); the instance settings page lists the problems verbatim. |
| `sso_config` after the button | The secret or issuer does not resolve | Re-check `OIDC_CLIENT_SECRET` (the Worker secret per environment); the discovery document's `issuer` must match `OIDC_ISSUER` exactly, trailing slash included. |
| `sso_exchange` | The code exchange with the OP failed | The OP is unreachable, or the client id/secret pair does not match the registry row. Re-register or re-seed the client; the row's status must be `active`. |
| `sso_token_*` (signature, issuer, audience, expiry, nonce) | The ID token failed the RP's validation | Retry once (an in-flight sign-in across a key rotation fails honestly); otherwise check the OP's `OP_SIGNING_KEY` and the issuer match. |
| A user lands in the approval queue | No mapping rule matched the claims the OP sent (or the OP emitted none: the explicit empty assignment) | The instance administrator approves on the instance settings page, or the OP administrator assigns roles per client in the registry. The decision applies at the user's NEXT sign-in. |
| `github_account_moved` on the GitHub button | The account migrated to the OP (the cutover) | Use the SSO button. The local role and org binding were kept; nothing was lost. |
| `github_unauthorized` | The login is on no allowlist and no longer in the allowed org | The allowlists are live: re-add the login or the membership, or migrate the account to the OP. |

### On the identity service (the OP)

| Symptom | Cause | Fix |
|---|---|---|
| The OP endpoints answer 404 | The deployment is not the identity profile | Only `roles: [identity]` serves the OP contract (the module gate). Check `INSTANCE_PROFILE` / the `[env.identity]` vars. |
| Sign-ins survive neither restart nor a second isolate (dev) | `OP_SIGNING_KEY` unset: the ephemeral per-process key pair signs | Set the ES256 private JWK as a secret. Never a production posture; the boot log warns loudly. |
| A setup link reports itself used or expired | One-time, 24 h TTL; an expired link is burned on presentation | Re-issue: `POST /api/op/accounts/:id/enrollment` (the registry console's "fresh setup link"). The same link serves as the password reset. |
| "This account is deactivated" with the right password | The registry's status act deactivated the account | Reactivate from the registry console (`/op/admin/users`). The assignments, links, and history were kept; the live sessions stay revoked (sign in again). |
| `upstream_not_linked` | The upstream identity holds no link row; the match rule never keys on email | The account holder links the provider from `/app/account` (signed in another way), or an administrator links on their behalf from the registry detail with the recorded justification. |
| `upstream_config` / `upstream_discovery` | The provider row's client id, secret reference, or issuer is wrong | The `client_secret_ref` env var must exist on the OP; the `oidc` kind's `issuer` must match the discovery document exactly. |
| No email arrives (invite, reset, notification) | The console posture: no mail provider configured | The flows keep SHOWING their links (never a silent drop); the boot log carries the message. Configure the `send_email` binding or the HTTPS fallback, and read the audit events (`email.sent` / `email.failed` / `email.logged` / `email.rate_limited`). |
| The seeded clients or providers are missing | The bootstrap seed did not parse or never ran | `OP_CLIENT_SEED` / `OP_UPSTREAM_SEED` upsert at boot; the boot log names the seeded ids or the validation problem. A secret-bearing seed belongs in a Worker secret. |
| A join request never reaches an org's queue | The organization is not a REGISTERED participant | Only registered orgs are selectable; the "not listed" path routes to the scheme operator's new-organizations queue. Register the participation first (PD-03). |

## Known limits

- One issuer per instance.
- The SSO sign-in state jar is store-backed (`sso_states`,
  TODO.identity/04): the nonce + PKCE verifier survive Worker isolates
  and are consumed atomically, so the Worker's SSO posture is exact. The
  table accumulates nothing (the expiry sweep rides each write) but is
  never compacted beyond that.
- **The mail rate limiter is per-isolate** (TODO.identity/09): on the
  Worker, each isolate holds its own per-recipient bucket (the
  federation limiter's documented posture). Every send still lands on
  the audit chain; a durable counter is the follow-up if the volume
  ever justifies it. And a deployment with no provider configured never
  drops a message silently: the console posture logs it and the flows
  keep showing their links.

## Proving it works

- Unit: `src/__tests__/oidc-claim-mapping.test.ts` (the mapping +
  validation), `src/__tests__/oidc-identity.test.ts` (the config
  surface + the profile seam), `src/__tests__/oidc-client.test.ts`
  (discovery, PKCE, the full ID-token validation matrix against real
  RSA signatures), `src/__tests__/oidc-auth-flow.test.ts` (the whole
  server flow in-process against the stub IdP: mapping, linking, the
  queue, the demo gate, RP-logout).
- GitHub OAuth: `src/__tests__/github-auth.test.ts` (the stateless
  state's sign/verify/tamper/expiry matrix, the allowlist/role-map/org
  resolution, the stubbed membership check), and
  `src/__tests__/github-auth-flow.test.ts` (the whole server flow
  in-process against the stub GitHub, `e2e/fixtures/stub-github.ts`:
  the authorized sign-ins, the refusals, the local-role seam, the SSO
  cutover guard (github_account_moved / github_email_taken,
  TODO.identity/04), open enrollment, the state failure surface).
- e2e: `browser/e2e/fed-10-oidc.e2e.ts` drives the browser through
  sign-in → the mapped console → sign-out (RP-initiated logout) → the
  approval queue → the approved sign-in, against the stub IdP
  (`browser/e2e/fixtures/stub-idp.ts` — no external dependency). The
  legs ride the SUITE's dev stack when it declares the SSO posture
  (the `OIDC_*` envs in the file's header — CI's e2e job declares them;
  the stub itself boots from the test file on 127.0.0.1:8699).
  Undeclared → the legs skip honestly, like the live-sim legs.
- The instance wiring (TODO.identity/04): `src/__tests__/id-04-wiring.test.ts`
  pins the committed `wrangler.toml` (every instance at the OP with its
  own client id, valid mappings, no inline secrets, the demo postures);
  the state jar's one-time/expiry/sibling-isolate semantics sit in
  `oidc-auth-flow.test.ts` + `d1-store.test.ts` (the SQLite and D1
  stores both). e2e: `browser/e2e/id-04-wiring.e2e.ts` boots TWO spawned
  stacks (the identity-profile OP AND a real fixture instance wired at
  it) plus the stub GitHub and drives the whole story in the browser:
  the login page leads with "Sign in with oimlsmart", a direct-GitHub
  account migrates on its first OP sign-in (the verified-email link; the
  local role stands against the OP's claim; the GitHub retry gets the
  moved message), a mapped newcomer lands in her console, the explicit
  empty assignment queues with no session, and the approval queue shows
  the OP's unmapped claim as the evidence before the admin's decision.
- The capstone (TODO.identity/05): `browser/e2e/id-05-full.e2e.ts` boots
  the two spawned stacks plus the stub GitHub (the OP's upstream
  registry row) and drives the WHOLE arc in the browser, in one
  narrative: the invite with its per-client role, the one-time setup
  link, the OIDC round trip landing the assigned console, the GitHub
  link from the account console, the GitHub-through-the-OP sign-in, the
  organization administration (the org admin created, the join request
  approved, the org-bound enrollment), the explicit empty assignment's
  queue and the viewer assignment's landing, the deactivation (the live
  session revoked, the next sign-in refused honestly at the OP), and the
  reactivation with the link and the assignment kept.
