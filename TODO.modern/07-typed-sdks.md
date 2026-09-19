# TODO.modern/07 — the typed SDKs, generated from the drift-gated OpenAPI

**Priority:** P2 · **Status:** DISPATCHABLE (the contract already exists — #118)
CI-generated TS (+ Python later) client libraries from `server/openapi/spec.ts`, published on tag.

## The acts
1. The generator step (openapi-typescript for TS) runs in CI against the spec; the output is a build artifact (never hand-edited, committed as a dist on release tags).
2. The client's auth: the session cookie (browser) + the PAT exchange helper (node) — the exchange is a one-call helper producing a scoped fetch.
3. The consumer proof: the RAG assistant (issue #115's consumer) builds against the SDK.
4. The drift gate already guarantees the input — the SDK can never be stale against the service.

**Acceptance:** `npm install @oimlsmart/identity-api` (or the repo-package equivalent) types every documented operation.
