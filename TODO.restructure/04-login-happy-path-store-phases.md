# TODO.restructure/04 — the login happy path's serial store phases

**Priority:** P0 (throughput — the sign-in answer's tail latency)
**Status:** COMPLETE

## Problem

`POST /api/op/login` (`browser/server/routes/op-accounts.ts`): the
FAILING path was already cut to two phases (e9e081e), but the HAPPY path
still ran ~7 serial store phases after the password verified:
`clearLoginThrottle` → `recheckBreachedPassword` → `factorCounts` →
`touchLastLogin` → `createSession` → `audit` → `getUserById`. Seven D1
round trips ≈ 7 × ~250 ms from an EU vantage against the APAC primary.

## The fix (as landed)

- Phase 1 — `Promise.all([clearLoginThrottle, recheckBreachedPassword,
  factorCounts])`: the backoff clear, the breach re-check, and the
  factor count never read each other's answer.
- Phase 2 — the WRITES stay SERIAL (`touchLastLogin` then
  `createSession`), with only the `getUserById` READ parallel to the
  write chain; `audit` follows the cookie.

## The finding that shaped it (write it down forever)

Parallelizing `touchLastLogin` ‖ `createSession` (two WRITES in one
`Promise.all`) broke the session mint on the sqlite path — the
id-email-verification suite failed 4/4 with a consent-decide 400 and
dead sessions, while every suite passed in isolation against HEAD.
**The kernel's store seam makes no concurrent-WRITE promise**: reads
alongside writes proved safe (phase 1 is green everywhere), write ‖
write did not. Until the kernel documents otherwise, batch reads
freely; keep a request's writes serial.

## Proof

Full suite 571/571 (incl. id-store-unavailable's first-tripped-write
pin — `UPDATE users` still leads), vue-tsc clean, astro check 0/0,
both builds green, op-surface-contract golden untouched.
