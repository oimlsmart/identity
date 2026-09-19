# TODO.modern/06 — step-up authentication + the risk signals

**Priority:** P1 · **Status:** DISPATCHABLE
Per-transaction re-authentication (ACR levels) and the risk posture (new device, impossible travel).

## The acts
1. ACR essentials: `acr_values` on authorize; the ID token carries the achieved `acr`; sensitive acts (token mint PATCH-widen, org-key rotate, password change) declare a required ACR and the route enforces a fresh-enough `auth_time` (the session's) — the "confirm it's you" re-auth is a fresh sign-in (password or passkey) restamping auth_time.
2. The risk signals (the audit journal already carries the raw events): new-device recognition (the user_agent+ip hash per account), impossible-travel (the sign-in geo delta vs the last), both as advisory banners + the step-up TRIGGER (a risky sign-in requires the second factor even when optional).
3. The discovery advertises `acr_values_supported`.
4. Specs: the ACR flow (the authorize ask, the achieved claim, the stale-auth_time refusal); the risk triggers; e2e: the step-up leg.

**Acceptance:** a bank-grade act demands and gets fresh proof; a risky sign-in steps up.
