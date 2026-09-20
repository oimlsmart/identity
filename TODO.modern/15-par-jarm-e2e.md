# TODO.modern/15 — the PAR+JARM e2e leg (the deploy gate covers the FAPI posture)

**Priority:** P1 · **Status:** IMPLEMENTED
The deploy pipeline now exercises the FAPI-class authorization surface
end to end — and the leg's first run caught a real bug the unit suites
had missed.

## What shipped
1. **The leg** (`e2e/id-40-par-jarm.e2e.ts`, the id-39 API-only
   posture — real HTTP against the booted stack, port-isolated 10659):
   the PUSH (RFC 9126, the confidential client's Basic auth, the full
   set with response_mode=jwt) → the authorize carrying ONLY the
   request_uri → the consent allow → the SIGNED response (RFC 9150:
   `response=<JWT>`, NO plain code in the front channel, iss/aud/state
   verified) → the DECODED code's PKCE exchange → the single-use
   replay refusal.
2. **The bug it caught**: the authorize's pushed-parameter
   reassignment DROPPED `response_mode` (a ten-name left side against
   an eleven-value map — the mode silently discarded, so a
   PAR-pushed JARM request answered the plain query; live on
   production since id-v2026.09.20-3). Fixed (the eleventh name), the
   leg green, and the regression PINNED in-process too
   (`id-jarm.test.ts` — the pushed-mode path through the full dance).
3. Gates: 736 tests green, types clean, both builds; the leg runs
   locally (the API-only posture boots where astro legs cannot) and in
   the CI/deploys' e2e shards.

**Open (honest):** nothing — the standing frontier holds (DPoP, the
content-CSP story, the conformance host, the bridge).
