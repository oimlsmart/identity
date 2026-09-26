# Deploy note: the `smart-cli` public client registration (2026-09-26)

This note records the one-time operator act that registered the public
client for the RFC 8628 device authorization grant on the production
OpenID Connect Provider (OP) at `https://id.oimlsmart.org`, together
with the live verification evidence gathered immediately after the act.
The device grant itself deployed with tag `id-v2026.09.24-6`, which
contains the grant implementation (#189, commit `b3a878f`) and the
rate-limiter hardening (commit `9cd8e2e`); both commits are ancestors
of the tag, and the live discovery document advertises
`device_authorization_endpoint`.

## The registration

The client is a secretless, application-class row in the client
registry, in accordance with `docs/integration/identity-service.md`
§9c: a confidential client has the authorization-code flow and a
machine class has `client_credentials`, so the command-line interface
registers as a public client and never carries a secret. The row was
written directly to the live D1 registry
(`oiml-smart-platform-identity`, database id
`6d24ab5f-f275-472f-82b1-fd0e3ca6ed96`) through the operator's wrangler
credential, because the two documented surfaces were not applicable
from this machine: the admin console (`/op/admin/clients`) requires an
interactive administrator session, and overwriting the `OP_CLIENT_SEED`
Worker secret was not admissible, because the existing secret value is
write-only and a rewritten seed could not have carried the other
clients' secrets — the registry upsert overwrites `secret_hash` on
conflict, so a partial re-seed would have erased them at the next boot.
The direct insert follows the same statement the store's own
`upsertOidcClient` issues, and the runbook already uses
`wrangler d1 execute --remote` against this database for operator acts
(`docs/deployment/identity-operations.md`). The write:

```
CLOUDFLARE_ACCOUNT_ID=06cad8ae9a017c856ab496c6bca9a9d8 \
npx wrangler d1 execute oiml-smart-platform-identity --remote --env identity --json \
  --command "INSERT INTO oidc_clients (client_id, name, secret_hash, redirect_uris, claims_policy, created_by)
             VALUES ('smart-cli', 'The OIML SMART CLI', NULL, '[]', '{\"claims\":[]}', 'operator-d1-2026-09-26')"
```

Response: `success: true`, `changes: 1`, `rows_written: 2`,
`last_row_id: 6`. The `redirect_uris` list is empty because nothing
redirects to a command-line client, and the claims policy is empty
because the device flow mints personal access tokens rather than ID
tokens; the shape mirrors the committed end-to-end fixture in
`browser/e2e/id-43-device-grant.e2e.ts`. The scope set the client may
ask for is not a registry field: the endpoint admits any scope in the
`<service>:<read|write|admin>` grammar that names a registered, active,
application-class relying party, and the approval re-judges the full
ask against the approving account's live standing. The production
services the command-line interface is expected to name are the
platform's registry entries (`oiml-smart-platform` and its sibling
instances).

## The live verification

All transcripts were captured against the production service on
2026-09-26.

1. The registered client receives a device-code pair:

```
POST https://id.oimlsmart.org/op/device/authorization
Content-Type: application/x-www-form-urlencoded

client_id=smart-cli&scope=oiml-smart-platform%3Aread
```

```
HTTP 200
{"device_code":"…","user_code":"RFE8-ZZCJ",
 "verification_uri":"https://id.oimlsmart.org/op/device",
 "verification_uri_complete":"https://id.oimlsmart.org/op/device?code=RFE8-ZZCJ",
 "expires_in":600,"interval":5}
```

2. An invented client id is refused honestly (the same answer the
   unregistered `smart-cli` received before the act):

```
client_id=invented-nope-123&scope=oiml-smart-platform%3Aread
```

```
HTTP 401
{"error":"invalid_client","error_description":"unknown or disabled client"}
```

3. The approval surface renders: `GET /op/device` answers 307 to
   `/op/device/`, which answers HTTP 200 with the page titled
   "Connect a device | OIML SMART Identity".

4. The poll speaks RFC 8628 §3.5 verbatim. The undecided device code:

```
HTTP 400
{"error":"authorization_pending","error_description":"the account holder has not decided yet"}
```

   and an immediate second poll inside the five-second interval:

```
HTTP 400
{"error":"slow_down","error_description":"the poll interval is being exceeded — the interval grows by 5 seconds"}
```

5. The committed end-to-end leg is green on the deployed build:

```
cd browser && npx vitest run --config vitest.e2e.config.ts e2e/id-43-device-grant.e2e.ts
✓ e2e/id-43-device-grant.e2e.ts (3 tests) — 3 passed
```

The local `main` at the time of the run (commit `d82b442`) carries one
commit past the deployed tag `id-v2026.09.24-6` (`3b57413`), and that
commit touches only the access-review operator tooling, so the end-to-end
result covers the deployed OpenID Provider surface.

## The `oiml-ommisa` registration (the second public client, the same act class)

The estate's second command-line client registered through the same
direct-insert path and for the same reasons that ruled out the two
documented surfaces (the admin console requires an interactive
administrator session, and rewriting `OP_CLIENT_SEED` would risk the
other clients' stored secrets). The row names the Ommisa assistant —
the OIML Metrology Machine Intelligence Standards Assistant, whose
brand the owner holds at `github.com/ommisa` and
`ommisa.{com,org,net}`. Its `claims_policy` is NULL rather than an
empty object, because the class doctrine marks a client's cone inside
that policy and an absent policy reads as the application class, which
is exactly the public command-line posture the device grant requires.
The write and the read-back:

```
CLOUDFLARE_ACCOUNT_ID=06cad8ae9a017c856ab496c6bca9a9d8 \
npx wrangler d1 execute oiml-smart-platform-identity --remote --env identity --json \
  --command "INSERT INTO oidc_clients (client_id, name, secret_hash, redirect_uris, claims_policy, status, created_by, launch_icon, launch_description, launch_visibility)
             VALUES ('oiml-ommisa', 'Ommisa', NULL, '[]', NULL, 'active',
                     'operator-device-grant-registration', 'chat',
                     'The OIML Metrology Machine Intelligence Standards Assistant, serving as your own agent for the estate service.',
                     'open')"
```

```
SELECT client_id, name, secret_hash IS NULL AS secretless, redirect_uris,
       claims_policy, status, launch_icon, launch_visibility
  FROM oidc_clients WHERE client_id='oiml-ommisa'
```

```json
[{"client_id":"oiml-ommisa","name":"Ommisa","secretless":1,
  "redirect_uris":"[]","claims_policy":null,"status":"active",
  "launch_icon":"chat","launch_visibility":"open"}]
```

## The `oiml-ommisa` verification transcripts

All transcripts were captured against the production service on
2026-09-26, after the registration above.

1. The registered client receives a device-code pair; the scope names
   the `oiml-ai` service, which is a registered, active,
   application-class relying party:

```
POST https://id.oimlsmart.org/op/device/authorization
Content-Type: application/x-www-form-urlencoded

client_id=oiml-ommisa&scope=oiml-ai%3Aread
```

```
HTTP 200
{"device_code":"…","user_code":"WQXZ-HR77",
 "verification_uri":"https://id.oimlsmart.org/op/device",
 "verification_uri_complete":"https://id.oimlsmart.org/op/device?code=WQXZ-HR77",
 "expires_in":600,"interval":5}
```

2. The refusal contrast stands, and it sharpens: an invented id still
   answers the honest refusal, while `smart-cli` now answers HTTP 200
   because the sibling section above registered it after the
   pre-registration probe that had cited it as a refusal example.

```
client_id=invented-cli-xyz&scope=oiml-ai%3Aread
```

```
HTTP 401
{"error":"invalid_client","error_description":"unknown or disabled client"}
```

3. The approval surface renders for the entered code: `GET /op/device`
   answers 307 to `/op/device/?code=WQXZ-HR77` (the canonical directory
   form preserves the query), which answers HTTP 200.

4. The poll speaks RFC 8628 §3.5 verbatim with an `oiml-ommisa` device
   code. The undecided code:

```
HTTP 400
{"error":"authorization_pending","error_description":"the account holder has not decided yet"}
```

   and an immediate second poll inside the five-second interval:

```
HTTP 400
{"error":"slow_down","error_description":"the poll interval is being exceeded — the interval grows by 5 seconds"}
```

5. The committed end-to-end leg is green on the deployed build: the
   `id-v2026.09.26-1` deploy pipeline (run 36207383896) carried the
   full end-to-end shard set green, which includes
   `browser/e2e/id-43-device-grant.e2e.ts` on the production-bound
   bundle.
