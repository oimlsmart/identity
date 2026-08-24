# Integrating with the OIML SMART identity service

> CANONICAL LOCATION: this document moved to `oimlsmart/identity`
> at the wave-02 extraction (the code it describes lives here). The
> smart monorepo's copy becomes a pointer page in wave 04.

**Audience:** an agent or engineer building a service that authenticates
users via the OIML SMART identity service. This file is self-contained;
nothing outside it is required reading. The canonical copy lives at
`docs/integration/identity-service.md` in the `oimlsmart/smart`
repository — copies into consumer repos are welcome; the canonical copy
wins on any drift.

> **Repo note (2026-08):** the identity service's code is moving from
> the smart monorepo to its own repository (`oimlsmart/identity`) — the
> extraction changes where the code lives, NEVER the public surface:
> the issuer `https://id.oimlsmart.org`, every endpoint, and the claims
> contract below are stable across the move. The source paths cited in
> §6 and §11 are the pre-extraction locations in `oimlsmart/smart`;
> after the cutover they read as the same relative paths inside
> `oimlsmart/identity`.

## 1. The cast

- **The OP (OpenID Provider)** — the identity service at
  `https://id.oimlsmart.org`. It authenticates users and issues OIDC ID
  tokens (JWT, ES256). It is the ONLY account registry in the estate.
- **Your service is an RP (Relying Party)** — it trusts the OP. It runs
  NO login form and holds NO account list of its own.
- **Upstream IdPs** (GitHub today; member-body providers such as
  Microsoft Entra next) sit BEHIND the OP as linked login methods. Your
  service never talks to them; the OP's account links them.

The OP speaks OIDC Core 1.0 (authorization code + PKCE), RFC 8414
discovery, and OIDC RP-Initiated Logout 1.0.

## 2. The endpoint cheat sheet

Issuer: `https://id.oimlsmart.org`

| What | Where |
|---|---|
| Discovery (RFC 8414) | `GET {issuer}/.well-known/openid-configuration` |
| JWKS (the signing keys) | `GET {issuer}/jwks.json` (the discovery document's `jwks_uri` is authoritative) |
| Authorization endpoint | `{issuer}/op/authorize` |
| Token endpoint | `{issuer}/op/token` (authorization_code ONLY) |
| UserInfo | `{issuer}/op/userinfo` |
| Avatar (the `picture` claim's target; public, no session) | `{issuer}/op/avatar/<account id>` |
| Account console (your users manage their own profile, linked identities, password, avatar there) | `{issuer}/op/account` |

## 3. Onboarding your service (the client registry)

Your service needs a client registration on the OP. One entry:

```json
{
  "client_id": "your-service-name",
  "name": "Your Service",
  "secret": "… (confidential clients only)",
  "redirect_uris": ["https://your-service.example/auth/callback"],
  "claims_policy": {
    "claims": ["roles", "groups", "org"],
    "roles": ["viewer", "mc_member"]
  }
}
```

- **Public client** (no `secret`): browser/SPA/native apps — PKCE is
  the whole credential. **Confidential client** (with `secret`):
  server-side apps that can keep a secret.
- `redirect_uris` are **exact-match**. No wildcards, ever.
- `claims_policy` (the per-client privilege): `claims` names the claim
  FAMILIES the ID token may carry for your service (absent = profile +
  email only): `roles`, `groups`, `org`, and `picture`. `roles` bounds
  WHICH roles those claims may carry
  (absent = unbounded by the policy; declare it). **Least claims by
  default**: if you need only identity, ask for no claims policy.
- How to get registered: ask an OP administrator (the admin console at
  `{issuer}/op/admin` manages clients), or the registry API
  (`POST /api/op/clients`, admin-held), or — for a self-hosted OP — the
  `OP_CLIENT_SEED` bootstrap env.
- Rotation and disable: a client can be disabled without deleting its
  audit trail; a disabled client's tokens stop at issuance (existing
  sessions at your service die at YOUR session lifetime — see §8).

## 4. The claims contract (what the ID token carries)

Standard: `iss` (exactly the issuer URL), `sub` (the stable account id —
THIS is your user key, never the email), `aud` (your client_id), `exp`
(validate with ≤ 60 s leeway), `email`, `name`, plus the policy-gated
families:

- `roles` — the account's estate role codes (see §6 for the vocabulary).
- `groups` — the account's group memberships.
- `org` — the account's registered organization affiliation.
- `picture`: the absolute URL of the account's avatar under the issuer
  (`{issuer}/op/avatar/<sub>`). The serve is PUBLIC (no session; the
  GitHub-avatars convention), so your UI can load it from a plain
  cross-origin `<img>`. The claim appears only when your client's policy
  carries the family AND the account has an uploaded picture; when it is
  absent, render your own initials fallback (the OP's console does the
  same). The URL stays fetchable for a known account even without an
  upload: the OP answers a generated-initials image there, and a plain
  404 for an unknown account.

Claims beyond profile+email arrive ONLY when your client's policy
allows them. The same user signing into two services can therefore
carry different claim sets — by design.

## 5. The sign-in flow (authorization code + PKCE)

1. Discover: `GET {issuer}/.well-known/openid-configuration`; the
   `issuer` value in the metadata MUST match the issuer URL exactly.
2. Build the authorization request: `GET {issuer}/op/authorize` with
   `response_type=code`, `client_id`, `redirect_uri` (exact), `scope`
   (`openid profile email` + your policy's families), `state`
   (unguessable, stored), `nonce` (unguessable, stored), and PKCE
   (`code_challenge`, S256 — never plain).
3. The user authenticates at the OP (password and/or a linked upstream
   IdP) and consents; the OP redirects to your `redirect_uri` with
   `code` + `state`. Verify `state` before anything else.
4. Exchange: `POST {issuer}/op/token` with `grant_type=
   authorization_code`, the code, the same `redirect_uri`, and the PKCE
   `code_verifier` (plus HTTP-Basic client auth for confidential
   clients). No other grant type is served today (machine callers: §9).
5. Validate the ID token (§6), then build YOUR OWN session (your cookie,
   your lifetime). The ID token is evidence of the sign-in event, not a
   session.
6. Logout: end your session; if the metadata declares
   `end_session_endpoint`, redirect there for the OP-side sign-out.

## 6. Validating tokens (the must-dos)

- Verify the signature against the JWKS (`jwks.json`, cached briefly —
  the OP rotates keys with JWKS overlap, so never hard-pin a `kid`).
- Check `iss` (exact), `aud` (your client_id; `azp` when several
  audiences), `exp` (≤ 60 s leeway), and the `nonce` you issued.
- Do the validation INSIDE your service. A check at an edge/WAF is UX,
  never the gate.
- On any failure: fail closed, in plain language, never a stack trace.

The reference implementation (copy it; ~300 lines, zero dependencies,
WebCrypto + fetch only, runs on Node ≥ 18 and edge runtimes):
`@oimlsmart/platform-server/oidc` in `oimlsmart/smart` — discovery, PKCE,
the exchange, the validation, the logout URL, and the error taxonomy.

## 7. Who declares what actions are allowed (the authorization division)

This is the question every integrator asks. The division:

- **The OP declares WHO the user is** — identity plus the coarse estate
  role claims your client's policy allows. The OP's administrator
  controls which roles exist and which accounts hold them; the OP's
  per-client claims policy bounds what your service may SEE.
- **Your service declares WHAT those roles may do** — your action
  vocabulary, your role→permission map, your enforcement at your own
  routes. Never invert this (the OP is not a fine-grained policy
  engine, by design).

The platform's own RBAC is the reference shape (`oimlsmart/smart`):
`@oimlsmart/platform-server/vocab` declares the action vocabulary;
`@oimlsmart/platform-server/vocab` holds the default role→permission map;
`browser/server/rbac.ts` resolves the EFFECTIVE map per instance
(an installed profile map, then the `INSTANCE_RBAC_JSON` env, then the
shipped default) and the entity routes enforce the write gates. The
estate role vocabulary today: `applicant`, `ia_officer`, `tl_operator`,
`biml_officer`, `cs_admin`, `mc_member`, `rc_member`,
`executive_secretary`, `admin`, `viewer`, plus the NMI split roles
(`case_officer`, `certification_officer`, `signatory`) and `org_admin`
(delegated organization administration). Map your service's actions to
the roles your claims policy receives — or keep your own roles internal
and map the estate roles into them at your boundary.

## 8. Centralized management or multiple services — both, deliberately

- **Centralized (the estate's shape):** ONE OP, many registered
  clients. Every service onboards per §3. Users have one account with
  linked login methods; the admin surface is one console. This is the
  recommended shape for anything in the oimlsmart.org estate.
- **Multiple SERVICES on one OP** is the normal case (one client
  registration each) — nothing extra to do.
- **Multiple identity PROVIDERS** (a sovereign deployment): a
  self-hosted platform instance can point its RP side at a DIFFERENT
  issuer entirely (the instance's `OIDC_ISSUER` configuration) — e.g. a
  national body's own provider. Supported, with the trade named: that
  deployment leaves the estate's shared account registry and role
  coherence. The softer shape for most members: keep trusting the
  estate OP and link the member's provider as an UPSTREAM login method
  (users sign in with their national IdP; the account stays the
  estate's).
- The OP itself is deployable outside the hosted Cloudflare shape
  (Node + SQLite / a container image — see
  `docs/deployment/identity-operations.md` §"Deployment portability"),
  so a sovereign operator can run the whole OP too.

## 8a. One login across every oimlsmart.org property (the SSO doctrine)

The estate spans many properties (the platform instances, the identity
console, the minisites, the future services). The rule for how a login
spans them:

- **The OP holds the single sign-on session.** Its own session cookie
  lives on id.oimlsmart.org and nowhere else. Every interactive
  property keeps ITS OWN session, established by the §5 round-trip.
  After the first sign-in anywhere, every other property's sign-in is a
  redirect that finds the OP session already live — one account, one
  password, one click everywhere. (Verified 2026-08-23: all six app
  instances — platform, demo, nmi, tl, id, preview — answer
  `ssoEnabled` with the OP as their provider.)
- **NEVER share a session cookie across subdomains** (a
  `.oimlsmart.org` cookie). It bypasses the protocol's checks (state,
  nonce, PKCE), couples every property's session security to the
  weakest one, and lets any static property's XSS ride the platform's
  sessions. The redirect pattern above IS the mechanism; the shared
  cookie is the anti-pattern.
- **Static properties** (the www site and the minisites) stay public —
  no fake login buttons. If one ever needs identity, it uses the OP's
  public-client PKCE flow (§3's public client kind) entirely in the
  browser: no server, no shared cookie, tokens in memory.

## 9. Machine callers (today's honest gap)

The OP serves authorization code + PKCE ONLY. There is no
`client_credentials` grant today: non-human callers (agent pipelines,
MCP servers) are NOT served yet. The gap is recorded and sized in
`TODO.identity-ops/07` (service accounts as confidential clients with
no redirect URIs, audience-bound tokens, scoped claims). If your
integration needs machine tokens, say so — that is the trigger that
schedules it. Do NOT work around it by embedding a human's credentials.

## 10. What your service inherits

- **Degraded mode**: when the OP is unreachable, existing sessions at
  your service ride their own cookies; new sign-ins fail honestly.
  State your behavior and cache JWKS briefly so validation survives
  short OP outages.
- **Offboarding**: an account disabled at the OP stops issuing
  immediately; its existing session at YOUR service dies at YOUR
  session lifetime. Re-check the OP on sensitive acts.
- **Erasure**: a deleted account's `sub` stops resolving; keep your own
  records keyed by `sub` and treat an unresolvable `sub` as anonymous.

## 11. Development and test posture

- A local OP for development: the platform's node dev stack boots the OP
  profile locally (see `docs/deployment/identity-operations.md`); point
  your service's issuer config at it. The demo accounts exist for
  development only — never a production login path.
- The test pattern to copy: the identity e2e legs in
  `oimlsmart/smart` (`browser/e2e/`, the identity-arc legs) boot the OP
  and an RP in one harness.
- The OP's failures answer a machine `reason` — map them to plain
  language; never leak internals to your users.
