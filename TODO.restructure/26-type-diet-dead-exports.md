# TODO.restructure/26 — the type diet: the dead exports behind the import mask

**Priority:** P2 (cleanliness — the verb diet's natural second half)
**Status:** AUDITED, OPEN — the analysis needs a proper reachability
solver, not an end-of-session heuristic (two audits ran; details below).

## The finding (measured 2026-09-12)

After the verb diet (24), ~50 of store.ts's 71 exported types + 9 of 13
constants belong to the pruned families (notify, certificate holders,
instruments, the journal, approvals, SSO states...) — yet naive
reference counts answer ZERO dead, because:

1. **The import mask**: `server/store/sqlite.ts:133` still imports the
   WHOLE type catalog (the kernel-era wiring imported everything it
   wired; the diet deleted the wiring entries but not the import names),
   and `d1.ts:61` carries similar type imports. Import-only references
   are dangling, not liveness.
2. **Mutual type chains**: the families' types reference each other
   (NotifyDelivery ↔ NotifyDeliveryStatus, the instrument write/result
   types, ...) — each looks referenced; only the GROUP is dead.
3. **Live-signature seeds matter**: a naive fixpoint over-subtracts and
   marks LIVE types dead (EnrollmentToken is the return of the LIVE
   enrollment verbs; IdentityLink, OidcCode, SessionView likewise ride
   live signatures).

## The correct solver (a fresh session's mechanical PR)

1. Seed the LIVE set from every reference in `server/routes/`,
   `server/auth/`, pages/scripts/tests — PLUS the seam interface's own
   signatures (a type in a live verb's signature is alive even if no
   route names it directly).
2. Walk: a declared type/const is alive if reachable from the seeds
   through type bodies and signatures. The unreachable set is the diet.
3. Delete the unreachable declarations from `store.ts`; strip every
   dangling name from the `sqlite.ts`/`d1.ts` import lists.
4. Proof: vue-tsc (a wrongly-deleted type fails loudly), the full
   suite, both builds, the contract golden.

Expected yield: a few hundred lines of type declarations + import
names. Zero behavior change.
