# Onboarding an upstream identity provider

> CANONICAL LOCATION: this document moved to `oimlsmart/identity`
> at the wave-02 extraction (the code it describes lives here). The
> smart monorepo's copy becomes a pointer page in wave 04.

The OP (`id.oimlsmart.org`) accepts upstream identity providers for
sign-in and account linking: GitHub today, Microsoft Entra and national
or organizational IdPs next. **Adding one is a config act** (a row in
the provider registry, plus a secret declared through the env), never a
code change. This page is the procedure, grounded in the implementation
it drives: `browser/server/auth/upstream/` (the registry, the OIDC
client, the flow state) and `browser/server/routes/op-upstream.ts` (the
routes).

The model, in one paragraph: a provider is a row in
`identity_providers` with a `kind` (`github` or `oidc`), a `client_id`,
and a `client_secret_ref` that NAMES an environment variable
(`env:<NAME>`); the secret value is never stored. An upstream identity
resolves to a local account ONLY through a link row (`identity_links`,
keyed on provider + the upstream account id), never by email alone: an
unlinked upstream identity gets the honest refusal
(`/app/login?error=upstream_not_linked`), no account, no session.

## The two configuration paths

**The deployment declaration (recommended)**: the bootstrap seed
`OP_UPSTREAM_SEED`, a JSON array upserted at boot (idempotent; a re-seed
overwrites later admin edits, so the seed is the deployment's
declaration). It belongs in `browser/wrangler.toml`'s
`[env.identity.vars]` (it carries no secrets, only the env REFERENCE):

```toml
[env.identity.vars]
OP_UPSTREAM_SEED = '''
[
  {
    "id": "github",
    "kind": "github",
    "display_name": "GitHub",
    "brand_mark": "github",
    "client_id": "0ab12cd34ef56",
    "client_secret_ref": "env:GITHUB_UPSTREAM_CLIENT_SECRET"
  }
]
'''
```

**The admin API** (for a provider that should not ride a redeploy):
`POST /api/op/providers` with an admin or cs_admin session, the same
field shape (`id`, `kind`, `display_name`, `brand_mark`, `issuer`,
`client_id`, `client_secret_ref`, `scopes`, `enabled`). The validation
(`validateProviderInput` in `auth/upstream/registry.ts`) refuses a
malformed row with the full problem list: the id is a lowercase slug
(it rides URLs), an `oidc` row needs an https `issuer` (loopback is the
test posture), and `client_secret_ref` must have the `env:` form.

## The procedure

### 1. Register the OP as a client AT THE UPSTREAM

At the upstream's developer console, create the OAuth/OIDC client and
register the redirect (callback) URI exactly:

```
https://id.oimlsmart.org/op/upstream/<id>/callback
```

where `<id>` is the registry row's slug (for example `github` or
`entra`). Exact match, no wildcards; the OP sends precisely this URI.
Notes per family:

- **GitHub** (`kind: "github"`): a GitHub OAuth App (Settings →
  Developer settings → OAuth Apps). One callback URL, GET. For a GitHub
  Enterprise Server deployment the endpoints come from the
  `GITHUB_OAUTH_BASE_URL` / `GITHUB_API_BASE_URL` env seam instead of
  the row (a row never declares an issuer for this kind).
- **Generic OIDC** (`kind: "oidc"`), including **Microsoft Entra**: the
  issuer is the discovery root (for Entra:
  `https://login.microsoftonline.com/<tenant-id>/v2.0`); the OP
  discovers the endpoints from
  `<issuer>/.well-known/openid-configuration` and requires the
  metadata's `issuer` to match exactly. The flow is Authorization Code
  + PKCE (S256), client authentication by HTTP Basic
  (`client_secret_basic`).
- **Apple**: the callback must accept POST as well (the OP sends
  `response_mode=form_post` for Apple's issuer host); the client secret
  is not stored at all, it is a short-lived ES256 JWT minted per
  exchange from `APPLE_TEAM_ID` / `APPLE_KEY_ID` /
  `APPLE_PRIVATE_KEY` (the three envs replace `client_secret_ref` for
  this provider).

### 2. Declare the secret through the env

The registry row never carries the secret; it names the env variable:

```bash
cd browser
npx wrangler secret put GITHUB_UPSTREAM_CLIENT_SECRET --env identity
```

(The same discipline as `OP_SIGNING_KEY`: never the repo, never the
database, never a log.) A dangling reference fails CLOSED: a provider
whose `client_secret_ref` names an unset variable refuses to start a
flow, it never signs in half-configured.

### 3. Add the registry row

By the seed (above) or the admin API. Fields beyond the minimum:

- `brand_mark`: one of `github`, `google`, `apple`, `microsoft`,
  `oidc` (the login page's icon; unknown or absent renders the generic
  OIDC mark).
- `scopes`: optional override. Defaults: `read:user user:email` for
  GitHub, `openid profile email` for OIDC, `openid name email` for
  Apple (Apple shares the name only at the first consent).
- `enabled`: the seed sets it true; the admin API takes it explicitly.

### 4. The claim mapping (what the OP reads from the upstream)

The OP's link keys on the stable account id and nothing else:

- `oidc` kind: the ID token's `sub` (validated for signature against
  the upstream's JWKS, issuer, audience, expiry, and the flow nonce).
  `email` and `name`, when shared, are display and audit values only.
- `github` kind: the numeric profile id (the login name is the display
  handle).

No upstream claim maps to roles: the account's roles live in the OP's
own registry and reach relying parties through the OP's per-client
claims policy (`docs/deployment/identity.md`); an upstream identity
never widens what an account holds.

### 5. Test

Before the live run, the code-level proof already exists:
`browser/e2e/id-08-upstream.e2e.ts` drives the flows against a stub IdP
(the sign-in, the link, the refusal, the state discipline). For the NEW
provider, against the live OP:

1. The login page shows the button: `GET
   https://id.oimlsmart.org/api/op/providers/public` lists the row
   (public fields only, never the secret ref).
2. Sign in with an UNLINKED upstream identity: the flow must end at
   `/app/login?error=upstream_not_linked` (the honest refusal), and an
   `upstream_refused` row lands in the audit trail.
3. Link it: sign in to the OP with a local account, open
   `/app/account`, use the provider's link action
   (`/op/upstream/<id>/link`), complete the upstream round trip, and
   confirm the link listed on the account page.
4. Sign out, sign in with the upstream identity: the session opens on
   the linked account, an `upstream_sign_in` audit row lands, and the
   account holder gets the sign-in email (when the mailer is
   configured).
5. RP round trip: with the upstream-signed-in OP session, authorize a
   relying party (for example the platform hub) and confirm the RP
   receives the account's claims.

### 6. Rollback

- Disable, keeping the rows: `POST /api/op/providers/<id>/status` with
  `{"enabled": false}`. The provider vanishes from the login page and
  refuses flows; the registry row and every link against it stay, so
  re-enabling restores the exact prior state.
- Remove the row: `DELETE /api/op/providers/<id>`. Links stay (the
  audit trail); sign-ins against the missing row fail closed.
- If the provider rode the seed, remove it from `OP_UPSTREAM_SEED` too,
  or the next boot re-declares it.

There is nothing else to roll back: the flow state is stateless and
signed (`auth/upstream/state.ts`, ten-minute TTL), so no migration and
no server-side residue follows a provider.

## The standing notes

- The flow state is signed with the OP's signing key, so a key rotation
  (docs/deployment/identity-deploy.md → "Key rotation") invalidates
  in-flight upstream flows within their ten-minute TTL; a user simply
  restarts the sign-in.
- Every registration, enable/disable, removal, sign-in, link, and
  refusal lands an `auditEvents` row (the admin console's activity view
  and the access review's evidence base).
- The admin console UI for the registry is TODO.identity/07's; until
  then the admin API above is the surface.
