# TODO.modern/10 — the password KDF posture (the adjudicated record)

**Priority:** P1 record · **Status:** ADJUDICATED (2026-09-19) — the audit's "weak KDF" finding corrected
The audit flagged PBKDF2@100k as below OWASP's 600k floor. The code already adjudicates why (server/auth/passwords.ts:25-31): **workerd caps WebCrypto PBKDF2 at 100,000 iterations** — above that, deriveBits throws (the 2026-08-16 incident 500'd the Worker). Argon2id is not WebCrypto-available. The cap is the cost factor on both runtimes (interop).

## The standing decision
100k PBKDF2-SHA256 (per-hash random salt) IS the platform ceiling; the compensating controls carry the posture: the timing-uniform login ladder, the rate bounds, the breach checks, and TODO 01's Turnstile (the stuffing killer).

## The follow-up (the only open question)
A pure-TS/WASM Argon2id evaluated for workerd (the viability check: bundle size, CPU limits, and interop — a Worker-only hash diverges from the node posture). If viable: the rehash-on-verify migration (the params ride the stored hash). If not: this record stands.
