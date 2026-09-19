# TODO.modern/06 — step-up authentication + the risk signals

**Priority:** P1 · **Status:** IMPLEMENTED (the OIDC step-up core) — the risk signals are the honest open half

## What shipped (the core)
1. **The step-up module** (`browser/server/auth/op/step-up.ts`): the achieved-acr
   vocabulary — `urn:oimlsmart:acr:single-factor` / `urn:oimlsmart:acr:multi-factor`,
   DERIVED from the session's amr (`pwd`, `webauthn`, `hwk`), never asserted; and
   `sessionMeetsMaxAge` — the OIDC max_age freshness gate, fail-closed (an absent
   instant proves nothing and refuses when the RP asked).
2. **max_age on authorize** (OIDC Core §3.1.2.1): the freshness gate sends a stale
   (or unprovable) session down the SAME sign-in path as prompt=login — the
   re-entry re-checks and the fresh session satisfies it. A malformed max_age
   refuses the redirect-shaped way (`invalid_request`), strictly BELOW the
   redirect_uri validation wall (an error redirect is only safe for a registered
   URI).
3. **The achieved acr rides both ID-token paths** (the code exchange AND every
   refresh rotation, beside the amr/auth_time provenance).
4. **Discovery advertises** `acr_values_supported` (the ladder, strongest first).
5. Specs: `src/__tests__/id-stepup.test.ts` — the ladder mapping, the staleness
   truth table (fresh/stale/max_age=0/unprovable), the authorize gate's three
   postures, the ID-token round trip, the discovery key.

**Open (honest):** the RISK SIGNALS (new-device recognition, impossible-travel)
and the per-route freshness gate on sensitive console acts (the "confirm it's
you" re-auth flow) are the remaining half — the signals need a known-device
record (a store migration) and the confirm-flow is console UX, each worth its
own PR.
Per-transaction re-authentication (ACR levels) and the risk posture (new device, impossible travel).

## The acts
1. ACR essentials: `acr_values` on authorize; the ID token carries the achieved `acr`; sensitive acts (token mint PATCH-widen, org-key rotate, password change) declare a required ACR and the route enforces a fresh-enough `auth_time` (the session's) — the "confirm it's you" re-auth is a fresh sign-in (password or passkey) restamping auth_time.
2. The risk signals (the audit journal already carries the raw events): new-device recognition (the user_agent+ip hash per account), impossible-travel (the sign-in geo delta vs the last), both as advisory banners + the step-up TRIGGER (a risky sign-in requires the second factor even when optional).
3. The discovery advertises `acr_values_supported`.
4. Specs: the ACR flow (the authorize ask, the achieved claim, the stale-auth_time refusal); the risk triggers; e2e: the step-up leg.

**Acceptance:** a bank-grade act demands and gets fresh proof; a risky sign-in steps up.
