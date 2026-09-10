# TODO.restructure/12 — the authorize hot path's two serial reads

**Priority:** P1 (throughput — the estate's hottest path)
**Status:** COMPLETE

## Problem

`GET /op/authorize` (`browser/server/routes/op.ts:324`) read the client
registry and THEN the session serially — two store phases on EVERY RP
sign-in (the remembered-grant fast path: client → session → grant →
mint; the first consent: client → session → authorization row → page).
The client read and the session read are independent: neither's answer
parameterizes the other's fetch.

## The fix

`Promise.all([getOidcClient(clientId), sessionUser(c)])` — one phase;
the validation order below unchanged (a refused client also pays the
session read — a read, no state, no observable difference). The mint's
own `getSessionActiveOrg` read stays serial by necessity: the code row
inherits the org context it reads (a true dependency, not a waterfall).

## Acceptance

- id-op-core, id-consent-grants, id-logout, id-token-surface: 63/63
  (the full authorize → consent → token round trips over the real
  routers). vue-tsc clean.
- The contract golden untouched (the wire surface is unchanged).
