# TODO.modern/12 — JARM (RFC 9150, JWT Secured Authorization Response Mode)

**Priority:** P1 · **Status:** IMPLEMENTED
PAR's FAPI companion: the authorization response itself becomes an
OP-signed JWT — the code/state/error never ride the front channel as
plain query parameters, and the RP can authenticate the response.

## What shipped
1. **response_mode=jwt** on the authorize (query param or a pushed
   PAR parameter — both param sources admit it): every redirect BACK
   to the RP — the error refusals AND the code mint — wraps its
   parameters into `redirect_uri?response=<JWT>` (RFC 9150 §5's
   parameter name). The JWT: ES256 via the OP's own key (the RPs
   verify against the JWKS they already hold — the asymmetric
   OP-signed form, the standard posture), carrying iss + aud (the
   client) + every response parameter verbatim.
2. **The response_mode rides the authorization row** (migration
   `0032_oidc_auth_response_mode`, an expand-only ALTER, schema-
   lockstep): the consent flow's decide re-derives the redirect from
   the row, so the mode must survive the sign-in hop. Default absent
   = `query` — **byte-identical answers for every existing RP**.
3. **The refusals**: `response_mode=form_post` (and any unknown mode)
   refuses `invalid_request` the redirect-shaped way (the redirect
   wall holds — the refusal goes to the REGISTERED redirect with the
   error IN the response JWT when the mode parsed, else in the query).
4. Discovery advertises `response_modes_supported: ['query', 'jwt']`;
   the route surface documented; the golden re-recorded deliberately.
5. Specs (`id-jarm.test.ts`): the discovery key, the FULL round trip
   (response_mode=jwt → consent allow → the response JWT decodes with
   code/state/iss/aud → the exchange consumes the decoded code), the
   ERROR path's signed refusal, the form_post refusal, and the
   default's unchanged query shape.

**Open (honest):** `query.jwt`/`form_post.jwt` hybrid modes and
client-side-encrypted responses — named for the day an RP asks.
