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
| Token endpoint | `{issuer}/op/token` (authorization_code for the application class; client_credentials for the DEVICE class only — §9) |
| UserInfo | `{issuer}/op/userinfo` |
| Avatar (the `picture` claim's target; public, no session) | `{issuer}/op/avatar/<account id>` |
| Whoami (the account-chip beacon for the static properties: the OP session's minimal projection, CORS-gated on the registered clients' origins) | `GET {issuer}/op/whoami` |
| Org signing keys (TODO.trust-registry/01 — an org's PUBLIC key set + its standing, for artifact verifiers; anonymous, `Cache-Control: public, max-age=60`, CORS-open) | `{issuer}/op/keys/<org id>.json` |
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

### The device class (the machine cone)

A **device client** is a NON-HUMAN client registered PER DEVICE (the
SMART Measuring Instruments' twins — the estate register, docs/future/07
Part I.3 item 2). It speaks `client_credentials` at the token endpoint
ONLY — no authorization-code flow, no redirect URIs, no refresh, no
launch card, no user claims — and it is always confidential (the secret
IS the device's credential; the console's re-key rotates it, the disable
revokes it). One entry:

```json
{
  "client_id": "device-acme-lc500-0001",
  "name": "ACME LC-500 sn 0001 (the twin)",
  "class": "device",
  "device": {
    "id": "acme-lc500-0001",
    "org": "mfr-acme",
    "instrument_model": "acme-lc500@2021"
  },
  "generate_secret": true
}
```

The `device` block binds the identity the token carries: the device id
(the twin's name), its org (must resolve on the OP's organization
registry), and the instrument model reference (the product-reference
package id). The class is fixed at registration — an application never
becomes a device nor the reverse; register a fresh client. See §9 for
the token's exact claim contract.

## 4. The claims contract (what the ID token carries)

Standard: `iss` (exactly the issuer URL), `sub` (the stable account id —
THIS is your user key, never the email), `aud` (your client_id), `exp`
(validate with ≤ 60 s leeway), `email`, `name`, plus the policy-gated
families:

- `roles` — the account's estate role codes (see §6 for the vocabulary).
- `groups` — the account's group memberships.
- `org` — the account's registered organization affiliation.
- `cone` — the active-org membership's **data cone**
  (TODO.identity-features/09): the org administrator's per-member
  posture — `org-wide` (the default), `assigned` (the member sees the
  org's rows only where named), `read-only` or `assigned+read-only`
  (writes refused). The claim appears only when your client's policy
  names the family AND the context resolved an org membership; the
  platform instances enforce from their own session resolution (the
  claim lets any RP learn the posture without a callback). The
  discovery document deliberately does not advertise it in wave A.
- `picture`: the absolute URL of the account's avatar under the issuer
  (`{issuer}/op/avatar/<sub>`). The serve is PUBLIC (no session; the
  GitHub-avatars convention), so your UI can load it from a plain
  cross-origin `<img>`. The claim appears only when your client's policy
  carries the family AND the account has an uploaded picture; when it is
  absent, render your own initials fallback (the OP's console does the
  same). The URL stays fetchable for a known account even without an
  upload: the OP answers a generated-initials image there, and a plain
  404 for an unknown account.
- `amr` - the authentication methods provenance (RFC 8176): how the user
  authenticated AT the OP for this authorization. The values this OP
  emits: `pwd` (the password), `otp` (a TOTP authenticator app),
  `webauthn` (a passkey), `hwk` (the passkey's registration declared a
  roaming hardware transport; attestation is `none`, so read it as the
  declared hint, never a proof), and `recovery` (a recovery code; the
  OP-private value, documented here). A present `amr` is the consenting
  session's truth at the moment of consent; the claim is ABSENT when the
  sign-in came through a linked upstream IdP (this OP verified no
  credential itself in that case). `userinfo` answers the same value.
  A sensitive-act policy reads it: password+factor sign-ins carry two
  entries; a passkey-only (passwordless) sign-in carries `webauthn`.

The multi-organization model: an account can belong to several
organizations and acts as ONE at a time (the account console's
Organizations section switches the context). The claims never change
shape: `org` is the account's ACTIVE organization (its primary binding
when it never switches), and `roles`/`groups` carry the active
organization's role set. Your service never learns the account's other
memberships from the token, and a mid-session switch takes effect on
the next sign-in round trip.

Claims beyond profile+email arrive ONLY when your client's policy
allows them. The same user signing into two services can therefore
carry different claim sets - by design. (`amr` is the exception that
proves the rule's honesty: it is authentication provenance, not a
client privilege, so it rides every ID token that has one.)

## 4a. Strong authentication at the OP (passkeys, authenticator apps, recovery codes)

The OP holds a per-account factor registry (TODO.identity-sso/02+03;
the reference: `docs/integration/identity-strong-auth.md`). The shape
your users see at the OP:

- **Passkeys** (WebAuthn): a primary sign-in (the passwordless button
  plus conditional-UI autofill on the identifier field) AND a second
  factor after the password, the account's choice. Registered at
  attestation `none`; the RP ID is the OP's exact domain and the origin
  check is exact. The signature counter's regression is the clone signal
  (the assertion fails and audits).
- **Authenticator apps** (TOTP, RFC 6238): the classic second factor.
  Enrollment activates only after a first valid code verifies.
- **Recovery codes**: generated at the first factor's enrollment, shown
  once, stored hashed, one-time each. Behind everything stands the email
  reset, so there is never a lockout.

Deliberately absent: SMS/voice OTP. SIM-swap and interception make them
a documented refusal, not an oversight. Verification endpoints are
rate-limited hard (per-caller buckets plus a per-account backoff ladder
on the pending sign-in row); a burned burst emails the account and
audits.

For your service this composes naturally: a fresh or phishing-resistant
authentication demand (`prompt=login`, `max_age` - wave A) re-runs the
OP's chain, and the `amr` claim (§4) tells your sensitive-act policy
what actually happened.

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

The four postures an operator can take toward identity — trust the
estate's OP, deploy this service on their own domain, bring their own
OIDC provider entirely, or the hybrid (estate accounts behind their
upstream IdP) — are the canonical matrix in the smart monorepo's
[identity-postures.md](https://github.com/oimlsmart/smart/blob/v2/docs/deployment/identity-postures.md),
each pinned as a configuration act with its proof; the self-host
posture's runbook lives here as `docs/deployment/identity-self-host.md`.

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
  no fake login buttons. The account CHIP on a static property rides the
  OP's whoami beacon: `GET {issuer}/op/whoami` with
  `credentials: 'include'` (the OP session cookie is same-site on
  id.oimlsmart.org, so it rides; CORS admits exactly the origins the
  registered clients declare — never `*`). Signed out it answers
  `{ "signedIn": false }` (cheap, `Cache-Control: public, max-age=60`);
  signed in it answers `{ signedIn: true, name, picture, admin }` —
  `picture` is the public avatar URL (null without an upload: render the
  initials fallback), `admin` marks the administration consoles — NEVER
  emails, roles, or orgs (the chip needs a face, not a dossier). A
  static property that needs REAL identity (protected content, acts)
  uses the OP's public-client PKCE flow (§3's public client kind)
  entirely in the browser: no server, no shared cookie, tokens in
  memory.

## 9. Machine callers (the device cone; the general gap honestly open)

The OP's machine cone is the **device class** (§3): per-device
credentials for the SMART Measuring Instruments' twins. A device client
presents `grant_type=client_credentials` with its secret
(client_secret_basic or post) at `{issuer}/op/token` and receives a
SELF-CONTAINED ES256 JWT access token (validate it against the OP's
JWKS — no call-back):

```json
{
  "iss": "{issuer}",
  "sub": "<the device id>",
  "aud": "<the client id>",
  "iat": …, "exp": …,
  "org": "<the device's org (the identity registry's org id)>",
  "instrument_model": "<the instrument model reference>"
}
```

That is the WHOLE claim set: never an ID token, never a refresh token,
never a user claim (no name/email/roles/groups/picture/amr — there is no
account behind a device token). The token lifetime is the OP's access
token TTL; an expired token re-authenticates (the secret is the
credential). Revocation is the client's disable: in-flight tokens die at
their `exp`, new mints refuse at once. The grant is NOT advertised in
the discovery document (`grant_types_supported` stays
`authorization_code`): the device cone is an estate-internal class, not
an RP flow — application clients asking `client_credentials` get the
plain `unsupported_grant_type` refusal.

The GENERAL machine-caller gap (agent pipelines, MCP servers — service
accounts with audience-bound, scoped tokens) remains honestly open and
sized in `TODO.identity-ops/07`. If your integration needs machine
tokens beyond the device cone, say so — that is the trigger that
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
