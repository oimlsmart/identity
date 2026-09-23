# The SOTA integration additions (PAR, JARM, login_hint, the account chooser, the typed SDK)

> FOR: a relying party (RP) integrating with the OIML SMART identity
> service — the post-default OIDC features shipped under the modern/*
> wave. Each section is self-contained: read what your service needs,
> skip the rest. The companion reference is `identity-service.md`; the
> machine-facing surface (drift-gated) is `GET {issuer}/api/openapi.json`.

The default OIDC posture (authorization code + PKCE, the consent memory,
the logout cone) is documented end-to-end in
`docs/integration/identity-service.md` — read that first. This document
covers the additions:

1. **PAR** — Pushed Authorization Request (RFC 9126)
2. **JARM** — JWT-secured Authorization Response Mode (RFC 9150)
3. **`login_hint`** — the pre-filled address field
4. **`prompt=select_account`** — the account chooser
5. **The typed SDK** — `@oimlsmart/identity-api` (or the local build)

## 1. PAR — Pushed Authorization Request (RFC 9126)

The OP advertises the endpoint in discovery as
`pushed_authorization_request_endpoint: {issuer}/op/par`. PAR moves the
authorization request's parameters from the browser-visible query
string onto a back-channel POST whose answer carries a single-use
`request_uri`. The browser then visits:

```
GET {issuer}/op/authorize?request_uri=urn:ietf:params:oauth:request_uri:<id>
```

…carrying only the URI; the OP resolves the URI server-side and runs the
flow with the parameters you POSTed. The benefits a service sees:

- **No parameters in the browser's URL bar.** The size limit disappears
  for large `scope` sets, custom claims policies, or a long `state`.
- **The unregistered `redirect_uri` is caught at PAR time, not at
  authorize time.** The OP refuses the push with HTTP 400 and never
  reaches a redirect — the redirect-wall class of bug is closed.
- **The push is client-authenticated.** Confidential clients POST with
  HTTP Basic or `client_secret_post`; the OP rejects the wrong secret
  with `401 invalid_client` before any URI is minted. Public clients
  push without a secret (PKCE is the credential).

### The wire form

```
POST {issuer}/op/par
Authorization: Basic <base64(client_id:client_secret)>     ← confidential
Content-Type: application/x-www-form-urlencoded

response_type=code
&client_id=…
&redirect_uri=https%3A%2F%2Fyour-service.example%2Fauth%2Fcallback
&scope=openid+profile+email
&state=…
&nonce=…
&code_challenge=…
&code_challenge_method=S256
```

The answer is `201 Created` with:

```json
{ "request_uri": "urn:ietf:params:oauth:request_uri:<id>",
  "expires_in": 90 }
```

The URI is **single-use**, **expiry-bound** (90 seconds), and
**client-bound** (a query `client_id` on the subsequent authorize must
match the owner — absent, the owner stands). An unknown, expired,
already-consumed, or cross-client URI refuses **in place** with a
400 — the request has no validated `redirect_uri` left to error to,
so the OP renders the refusal page directly. The default flow is
unchanged for clients that never push.

### When to push

- Any confidential RP — it's the FAPI-aligned posture and removes the
  URL-length worry. The SDK (below) wraps the push transparently.
- Skip when you're an SPA with a tiny scope and want one round trip —
  the authorize query is fine, the URL bar is not a leak for `openid`.

## 2. JARM — JWT-secured Authorization Response Mode (RFC 9150)

The discovery document declares `response_modes_supported: ["query",
"jwt"]`. Send `response_mode=jwt` on the authorization request (or on
the PAR push) and the OP answers with a SINGLE parameter on the
redirect:

```
https://your-service.example/auth/callback?response=<JWT>
```

The JWT is ES256-signed with the OP's signing key — verify it against
the JWKS you already hold (§6 of `identity-service.md`). Its claims:

| Claim | Source |
|---|---|
| `iss` | `{issuer}` |
| `aud` | your `client_id` |
| `code` / `error` / `error_description` / `state` | the redirect's parameters, verbatim |

The `nonce` is **never** put into a JARM response (the response
identifies the OP, not the request — the OP doesn't echo the request's
nonce back). Anything else (the `response` parameter itself, custom
extensions) is absent. An unsupported `response_mode` is refused with
`invalid_request` — the OP supports `query` (the default, the URL
parameters live in the query) and `jwt` (this mode). `form_post`,
`fragment`, and `web_message` are deliberately **not** served.

### When to ask for JARM

- You already validate JWTs everywhere else — the redirect leg becomes
  one more JWT verification, no parameter-name spelunking.
- The full parameter set is large and you want it bound to the OP's
  signature (forensic value, the wire can never drift past the OP).

## 3. `login_hint` — the pre-filled address field

If your service knows the user's identifier (the email they typed
into YOUR form, the one stored in your session from a prior sign-in,
the value pulled from a directory), send it as `login_hint` on the
authorization request:

```
GET {issuer}/op/authorize
    ?client_id=…
    &redirect_uri=…
    &response_type=code
    &scope=openid+profile+email
    &state=…
    &code_challenge=…&code_challenge_method=S256
    &login_hint=ada%40example.invalid
```

The OP **pre-fills** the sign-in page's address field with the value.
It is a hint, never a bypass — the human can correct it before
submitting. The hint rides the sign-in redirect (the page reads it
beside the legacy `email` form field; both feed the same field, the
hint wins when present). It rides a PAR push too (the pushed
parameters replace the query's). **The default flow carries no hint —
the absent-parameter path is byte-identical.**

## 4. `prompt=select_account` — the account chooser

If your service's user can present as MORE THAN ONE account on this
OP (a multi-role person, a delegated admin who is also a personal
member), ask for the chooser:

```
&prompt=select_account
```

The OP routes the flow through `/op/choose-account` even with a live
remembered grant on this device: the page lists the accounts a live
session on this browser already knows (the cookie jar carries them),
and the user picks one before the OP continues. **This holds even
when the same browser already has a session for one of the
accounts** — the chooser is the answer, the remembered grant is
short-circuited. The user confirms by clicking; the OP continues with
the chosen account. A `prompt=select_account` value is consumed by
the redirect — the OP does not forward it to your callback.

Send `login_hint` **together with** `prompt=select_account` and the
hint pre-selects on the chooser itself: the entry whose address
matches carries the visible pre-selection badge, and the page scrolls
it into view. The pre-selection is an affordance, never a decision —
the holder still clicks. A hint nothing remembers rides "use another
account" as the sign-in form's prefill.

Without `prompt=select_account` and with a live remembered grant, the
OP skips the chooser and the consent page alike — your service gets
the code directly. The chooser is the explicit ask, never the default.

### The demonstration personas (the grant-based assumption)

On OPs that declare the persona-assumption posture, the chooser ALSO
lists the deployment's demonstration personas to a grant-holder: a
live session whose account the `OP_DEMO_ASSUME_GRANTS` declaration
names sees the persona rows (badged "Demo persona", the `login_hint`
pre-selects them like any entry), and clicking one continues the flow
AS the persona — Google Workspace's "sign in as user": the persona's
session mints WITHOUT the persona's credential ever being presented,
the assumption event journals to the OP's `op_assumptions` table
(who, whom, when, which client), and the tokens your service receives
name the persona (its `sub`, its `roles`/`org` claims for your client)
with `amr: ["assumed"]` marking the delegated sign-in. An account
without a grant — and the signed-out posture — never sees the persona
rows. Persona credentials do not exist as shared knowledge: no
password is published for any persona, so the chooser assumption is
the only way in.

## 5. The typed SDK (`@oimlsmart/identity-api`)

The SDK is generated from the drift-gated OpenAPI spec
(`GET {issuer}/api/openapi.json`). The artifact (`browser/sdk/gen/`)
is committed build output — `npm run sdk:generate` re-derives it and
`npm run sdk:check` is the CI tripwire (the regenerated tree must be
byte-identical to the committed tree). Two surfaces:

### 5a. The typed operations

```ts
import { createIdentityClient } from '@oimlsmart/identity-api'

const id = createIdentityClient({ baseUrl: 'https://id.oimlsmart.org' })

// Every operation is typed against the LIVE spec. A renamed or
// removed operation FAILS the type check — the spec is the contract.
const meta = await getDiscovery()
const jwks = await getJwks()

// The PAT-scoped machine cone (the §9a PAT in / OP JWT out exchange):
import { patAccessToken, createBearerClient } from '@oimlsmart/identity-api'

const { accessToken } = await patAccessToken({
  baseUrl: 'https://id.oimlsmart.org',
  pat: process.env.OIML_PAT!,
  scope: 'hub-instance:read',          // OPTIONAL narrowing
})
const idAuthed = createBearerClient({ baseUrl: 'https://id.oimlsmart.org', accessToken })
```

The bearer rides every call automatically; the session-cookie posture
needs no helper — same-origin browser `fetch` carries `oiml-session`
by the default credentials setting.

### 5b. The typed operations (the generated set)

The generated module (`sdk.gen.ts`) names every operation against the
OpenAPI spec. The ones an RP reaches for:

| Operation | Path | Use |
|---|---|---|
| `getDiscovery` | `GET /.well-known/openid-configuration` | The discovery read (§5 of `identity-service.md` uses this URL — the SDK gives you the typed answer). |
| `getJwks` | `GET /jwks.json` | The signing-key set, refreshed on your cadence. |
| `getWebfinger` | `GET /.well-known/webfinger` | The address-to-issuer discovery (the federation's step zero — `identity-member-deployment.md`). |
| `pushAuthorizationRequest` | `POST /op/par` | The PAR push; the answer carries the `request_uri` the browser then visits. |
| `getSessionCheck` / `getSessionState` | `GET /op/session/check` + `/op/session/state` | The OIDC Session Management cone. |
| `getUserinfo` | `GET /op/userinfo` | The bearer-presented claims read. |
| `exchangeToken` / `introspectToken` / `revokeToken` | `POST /op/token` (RFC 8693), `/op/introspect`, `/op/revoke` | The PAT exchange, the standing check, the revocation. |

The typed set stays current: `npm run sdk:generate` re-derives the
module from the drift-gated spec, and `npm run sdk:check` is the CI
tripwire (the regenerated tree must be byte-identical to the committed
tree — a spec drift fails the gate, never the type check).

### 5c. The freshness gate

`npm run sdk:check` is part of CI. A drift between the spec and the
committed artifact fails the gate; the recovery is
`npm run sdk:generate` and committing the regenerated tree in the
same PR that changed the spec.

### 5d. Composing an authorize call (PAR + JARM + login_hint + chooser)

The SDK does NOT ship a high-level "one-call authorize" helper — the
authorize URL is composed by your service (the request_uri comes from
`pushAuthorizationRequest`, the PKCE pair is yours to mint, the
redirect's parameters are yours to verify). The shape:

```ts
import { pushAuthorizationRequest, getJwks } from '@oimlsmart/identity-api'
import { createRemoteJWKSet, jwtVerify } from 'jose'      // JARM verify

// 1. PKCE (yours).
const verifier = base64url(crypto.getRandomValues(new Uint8Array(32)))
const challenge = await sha256base64url(verifier)

// 2. PAR push (the typed operation).
const { request_uri } = await pushAuthorizationRequest({
  baseUrl: 'https://id.oimlsmart.org',
  body: {
    client_id: 'your-service-name',
    client_secret: process.env.OIDC_CLIENT_SECRET!,
    response_type: 'code',
    redirect_uri: 'https://your-service.example/auth/callback',
    scope: 'openid profile email',
    state: crypto.randomUUID(),
    nonce: crypto.randomUUID(),
    code_challenge: challenge,
    code_challenge_method: 'S256',
    response_mode: 'jwt',               // OPTIONAL — JARM
    login_hint: 'ada@example.invalid',  // OPTIONAL — pre-fills
    prompt: 'select_account',           // OPTIONAL — chooser
  },
})

// 3. The browser redirects to the authorize URL carrying only the URI.
return Response.redirect(
  `https://id.oimlsmart.org/op/authorize?request_uri=${encodeURIComponent(request_uri)}`
)

// 4. The callback verifies the response. If response_mode=jwt:
const url = new URL(request.url)
const jwt = url.searchParams.get('response')!
const jwks = createRemoteJWKSet(new URL('https://id.oimlsmart.org/jwks.json'))
const { payload } = await jwtVerify(jwt, jwks, {
  issuer: 'https://id.oimlsmart.org',
  audience: 'your-service-name',
})
const code = payload.code as string
const state = payload.state as string
```

## What's deliberately absent

A reminder of items the modern wave considered and refused, so you
don't ask for them later:

- **Front-channel logout** (RP-initiated logout via `<iframe>` POST).
  Backchannel logout (RFC 8252-style, `application/x-www-form-urlencoded`
  POST to a registered `backchannel_logout_uri`) is the only cone;
  document in §5a of `identity-service.md`.
- **`max_age`.** The OP does not enforce a max authentication age —
  ask with `prompt=login` and verify the ID token's `auth_time` ≥
  your ask instant. The ask alone is half the contract; the verification
  is the gate.
- **SMS / voice OTP.** SIM-swap and interception. A documented refusal,
  not an oversight.
- **`form_post`, `fragment`, `web_message` response modes.** JARM's
  `jwt` is the only alternative to the `query` default.
- **The PAT-scoped SCIM bearer.** A dedicated `SCIM_BEARER_TOKEN` is
  the only credential; the PAT grammar would contort the service-client
  shape. (Operator-side: `identity-operations.md` §SOTA config gates
  covers the SCIM half; the HR connector uses the `scim*` typed
  operations in §5b.)
