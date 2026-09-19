# TODO.modern/07 — the typed SDKs, generated from the drift-gated OpenAPI

**Priority:** P2 · **Status:** IMPLEMENTED (TypeScript; Python deliberately deferred)
CI-generated TS (+ Python later) client libraries from `server/openapi/spec.ts`, published on tag.

## What shipped
1. **The generator**: `@hey-api/openapi-ts` (v0.99 — the one maintained generator
   whose peer range admits this repo's TypeScript 6; `openapi-typescript` pins
   `^5.x` and would force a repo-wide legacy-peer-deps posture, which is refused).
   `npm run sdk:generate` (browser/scripts/generate-sdk.ts) dumps the LIVE
   `OPENAPI_SPEC` and generates `browser/sdk/gen/` (client.gen, sdk.gen,
   types.gen) — a **committed build artifact, never hand-edited**.
2. **The freshness gate**: `npm run sdk:check` (regenerate → `git diff --exit-code
   -- sdk` must be empty); a named CI step in ci.yml — the artifact can never go
   stale against the service, because the spec itself is drift-gated (#118).
3. **The posture layer** (browser/sdk/identity-client.ts, the only hand-written
   surface, deliberately thin): re-exports the typed operations;
   `patAccessToken()` — the RFC 8693 machine exchange (PAT in → short-lived
   scope-narrowed OP JWT out); `createBearerClient()` — rides that token on every
   call; the session-cookie posture needs no helper (same-origin browser calls
   carry `oiml-session` by fetch's default credentials).
4. **The consumer proof** (src/__tests__/id-sdk.test.ts): the generated client
   drives REAL documented operations through the in-process app (the typed
   discovery read); the exchange helper's exact wire form; the honest refusal;
   the bearer rider. The compile IS the type proof — a mistyped operation fails
   vue-tsc.

## Honest open items (owner acts)
- **Publication** is a release act: `npm install @oimlsmart/identity-api` needs
  the npm package decision (name, version, provenance) — the owner's. Until
  then, consumers install from the repo (`browser/sdk/`).
- **Python client**: deferred (no consumer asks yet; the generator supports it
  when one does).
