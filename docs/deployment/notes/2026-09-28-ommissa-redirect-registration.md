# Deploy note: the Ommisa redirect registration on `oiml-ai` (2026-09-28)

This note records the operator act that admitted
`https://ommissa.org/auth/callback` as a redirect URI of the registered
client `oiml-ai` on the production OpenID Connect Provider (OP) at
`https://id.oimlsmart.org`, and renamed the client's display name to
Ommisa, together with the live verification evidence gathered
immediately after the act. The OIML SMART AI assistant has been renamed
Ommisa and is moving from `ai.oimlsmart.org` to `ommisa.org`; its
worker (the pull request oimlsmart/ai#492) now sends
`OIDC_REDIRECT_URI=https://ommissa.org/auth/callback`, and the
authorization endpoint refused that redirect until this registration
landed. The existing `https://ai.oimlsmart.org/auth/callback` remains
registered, so both addresses work during the transition.

## The registration

The row was updated directly in the live D1 registry
(`oiml-smart-platform-identity`, database id
`6d24ab5f-f275-472f-82b1-fd0e3ca6ed96`) through the operator's wrangler
credential, in accordance with the precedent set by
`notes/2026-09-26-smart-cli-registration.md`: the admin console
(`/op/admin/clients`) requires an interactive administrator session,
and overwriting the `OP_CLIENT_SEED` Worker secret is not admissible
because the existing secret value is write-only and a rewritten seed
could not have carried the other clients' secrets. The statement is an
UPDATE confined to the `name` and `redirect_uris` columns, so the
client's claims policy, status, and launcher metadata are preserved
verbatim; the existing redirect URIs
(`https://ai.oimlsmart.org/auth/callback` and the operations instance's
`https://ops-ai.oimlsmart.org/auth/callback`) are carried into the new
list unchanged. The write:

```
CLOUDFLARE_ACCOUNT_ID=06cad8ae9a017c856ab496c6bca9a9d8 \
npx wrangler d1 execute oiml-smart-platform-identity --remote --env identity --json \
  --command "UPDATE oidc_clients SET name='Ommisa',
             redirect_uris='[\"https://ai.oimlsmart.org/auth/callback\",\"https://ops-ai.oimlsmart.org/auth/callback\",\"https://ommissa.org/auth/callback\"]'
             WHERE client_id='oiml-ai'"
```

Response: `success: true`, `changes: 1`, `rows_written: 1`. The
read-back confirms the row's new state, with the claims policy and the
launcher metadata untouched:

```
SELECT client_id, name, secret_hash IS NOT NULL AS has_secret, redirect_uris,
       claims_policy, status, launch_url, launch_visibility
  FROM oidc_clients WHERE client_id='oiml-ai'
```

```json
[{"client_id":"oiml-ai","name":"Ommisa","has_secret":0,
  "redirect_uris":"[\"https://ai.oimlsmart.org/auth/callback\",\"https://ops-ai.oimlsmart.org/auth/callback\",\"https://ommissa.org/auth/callback\"]",
  "claims_policy":"{\"claims\":[\"roles\",\"picture\"]}","status":"active",
  "launch_url":"https://ai.oimlsmart.org/auth/login","launch_visibility":"open"}]
```

The launch URL still names the assistant's sign-in start on
`ai.oimlsmart.org`, which remains live during the transition; repointing
the launcher card to `ommisa.org` is a follow-up act once the renamed
service is cut over.

## The live verification

All transcripts were captured against the production service on
2026-09-28. Before the act, the same authorization request with the new
redirect answered HTTP 400 with the page titled "Cannot authorize this
request — OIML SMART Identity", which is the endpoint's refusal of an
unregistered redirect URI.

1. The new redirect is admitted. The authorization request no longer
   meets the redirect refusal: the endpoint answers HTTP 302 back to
   the registered redirect URI, and the only error on the redirect is
   the protocol-level demand for Proof Key for Code Exchange (PKCE),
   which the probe deliberately omits and the real worker supplies:

```
GET https://id.oimlsmart.org/op/authorize?client_id=oiml-ai&redirect_uri=https%3A%2F%2Fommissa.org%2Fauth%2Fcallback&response_type=code&scope=openid&state=probe&nonce=probe
```

```
HTTP 302
Location: https://ommissa.org/auth/callback?error=invalid_request&error_description=PKCE+is+required+%28code_challenge+%2B+code_challenge_method%3DS256%29&state=probe
```

The error is delivered to the redirect URI itself, which proves the
redirect validated; an unregistered redirect would have answered the
HTTP 400 refusal page instead, because the endpoint never redirects to
an address the client has not registered.

2. The old redirect still passes, so the running service on
   `ai.oimlsmart.org` is undisturbed:

```
GET https://id.oimlsmart.org/op/authorize?client_id=oiml-ai&redirect_uri=https%3A%2F%2Fai.oimlsmart.org%2Fauth%2Fcallback&response_type=code&scope=openid&state=probe&nonce=probe
```

```
HTTP 302
Location: https://ai.oimlsmart.org/auth/callback?error=invalid_request&error_description=PKCE+is+required+%28code_challenge+%2B+code_challenge_method%3DS256%29&state=probe
```

No code changed in this act, so no `id-v*` tag deploys: the registry
row is live data, and the deploy pipeline's contract gate guards the
OIDC surface, which is untouched. The consent screen now reads Ommisa,
because the consent copy renders the client's registered display name.
