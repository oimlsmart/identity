# TODO.modern/11 — PAR (RFC 9126, Pushed Authorization Requests)

**Priority:** P1 · **Status:** IMPLEMENTED
The FAPI-class posture's baseline: the authorization request's
parameters posted to the BACK channel (client-authenticated), the
browser redirect carrying only the `request_uri` — the parameters
never ride the front channel where mix-up and tampering live.

## What shipped
1. **POST /op/par** — the token endpoint's own client authentication
   (Basic or post; the public-client posture holds), the full
   authorize parameter set as the form. The open-redirect wall applies
   AT PAR TIME (an unregistered redirect_uri refuses before anything
   is stored). The machine classes refuse as the authorize itself
   does. Answers `201 {request_uri, expires_in: 90}`.
2. **The storage** (migration `0031_pushed_authorization_requests`,
   schema-lockstep, both backends): one row per pushed request — the
   params JSON, the owning client, the expiry, the consumed flag. The
   consume is ATOMIC and SINGLE-USE (the UPDATE's WHERE carries the
   client binding + the not-consumed + the not-expired predicates).
3. **authorize + request_uri** — per §5, the pushed parameters
   REPLACE the query's (any other query parameter is IGNORED, never
   merged); a query `client_id` must match the PAR's owner. Unknown,
   expired, consumed, or cross-client request URIs refuse the
   redirect-shaped `invalid_request` way.
4. Discovery advertises `pushed_authorization_request_endpoint`; the
   route joins the OP-surface rate limiter; documented in the OpenAPI
   spec (the SDK artifact regenerated); the surface golden
   re-recorded deliberately.
5. Specs (`id-par.test.ts`): the push, the FULL round trip through a
   pushed request (authorize → consent → code → token), single-use,
   the ignore-the-query rule, the cross-client refusal, the wrong
   secret, the PAR-time redirect wall, the discovery key.

**Open (honest):** the FAPI profile set beyond PAR (JARM's signed
responses, DPoP's sender-constrained tokens) — named for the day an
RP asks for them; each is a sized protocol surface of its own.
