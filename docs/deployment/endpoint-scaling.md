# Endpoint scaling: the N+1 gate

The identity service's half of the estate's endpoint-scaling doctrine (the
sibling platform repo's AGENTS.d/17 is the platform half). Born of two
measurements of the same disease class: the 2026-09 portal load audit on
the platform (a 423-row store behind a per-row visibility gate = a 107 s
list answer, every read a fresh D1 round trip), and this service's admin
organizations page at 2–11 s against the production registry import (217
sequential store round trips — one membership read per organization).

## The rule

**A list endpoint's store-call count is invariant to the store's row
count.** The handler reads its referenced sets ONCE per request (one
indexed read per referenced table), groups them in memory, and the
per-row logic (joins, display projections, derived flags) reads the
memory. Never `await` a store read inside a per-row loop. On the Worker
each call is a D1 round trip — O(rows) calls is the disease; O(1) calls
is the contract.

## The gate proves it

`browser/src/__tests__/endpoint-scaling.test.ts` runs every root-level
GET list endpoint against a small fixture and the same fixture grown 10×,
with the store seam wrapped in the counting facade
(`endpoint-scaling.ts`'s `StoreCallCounter` — a test-side Proxy over the
installed `ServerStore`; the kernel's production code is never touched
for this). The assertion is on the DELTA between the two scales: zero
growth, or within the leg's declared per-row budget. Per-request
constants (the session resolution) cancel out of the delta.

```sh
cd browser && npx vitest run src/__tests__/endpoint-scaling.test.ts
# the per-leg counts table (the evidence for a PR touching a list):
cd browser && ENDPOINT_SCALING_REPORT=1 npx vitest run src/__tests__/endpoint-scaling.test.ts
```

The gate rides the CI's vitest leg, and CI runs it once more as its own
named step ("endpoint-scaling gate").

## Fixing a failing leg

The audit's pattern: prefetch the referenced sets once per request, group
in memory. The kernel seam's bulk reads are the instruments
(`listAllOpClientRoles`, `listAllOrgMemberships`, `listOidcClients`,
`listUsers`, …); where the per-row helper is shared with a single-row
caller, the batch arrives as an OPTIONAL parameter and the single-row
caller keeps its plain point read. Responses stay byte-compatible: the
batch read answers the same rows in the same per-account order (the
kernel's bulk reads keep the per-account `ORDER BY`), verified by the
gate's content pins and the route's own suites.

## A budget exception is a ceiling with a named follow-up

Declare `budgetPerRow` on a leg ONLY when the kernel seam carries no bulk
read for a genuinely per-row need, and name the follow-up that drives it
to zero in `budgetNote` (the harness refuses a budget without the note).
Live examples on this service: the accounts list's and the registry users
list's sign-in posture + linked-handles reads (a kernel bulk
sign-in-posture read is the follow-up), and the dashboard overview's
invited count (the same follow-up). A regression BEYOND a budget fails
exactly like a missing prefetch.

## New list endpoints land in the gate with the endpoint

The suite's fixture helpers seed through the store seam directly (setup
is never measured); a leg is seed-small → measure → grow-10× → measure →
assert. Single-record endpoints (detail reads, token acts) need no leg; a
root-level list endpoint without a leg is a review finding.
