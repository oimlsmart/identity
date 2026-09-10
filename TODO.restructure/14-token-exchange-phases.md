# TODO.restructure/14 — the token exchange's two serial reads

**Priority:** P1 (throughput — the estate's second-hottest path)
**Status:** COMPLETE

## Problem

`POST /op/token` (authorization_code, `browser/server/routes/op.ts:1178`):
after the atomic code consume, the handler read the account
(`getUserById`) and THEN the per-client roles (`getOpClientRoles`)
serially — both are keyed by the consumed code's `userId` (the roles
read needs no field of the user object), so the second phase was a pure
waterfall on every code exchange — every RP sign-in's second half.

## The fix

`Promise.all([getUserById(code.userId), getOpClientRoles(code.userId,
client.clientId)])` — one phase. `claimsContextFor` stays behind the
user read (it resolves the org context against the user object — a true
dependency). The client-auth → code-consume order is untouched: the
machine-class mixup refusal must precede consumption (the one-time-code
doctrine — a confused deputy never burns another flow's code).

## Acceptance

- id-op-core, id-consent-grants, id-token-surface, id-refresh-rotation,
  id-email-verification (the full exchange round trips): 44/44.
- vue-tsc clean; the contract golden untouched (the wire surface is
  unchanged).
