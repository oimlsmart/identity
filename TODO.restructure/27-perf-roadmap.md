# TODO.restructure/27 — the perf roadmap: what shipped, what stands

**Priority:** P1/P2 mix · **Status:** PARTIAL, honestly — item 1 SHIPPED,
item 2 was already true (a false claim corrected), the rest stand as
scoped follow-ups with recipes.

## 1. The sign-in notice off the login critical path — SHIPPED

`op-accounts.ts`: the mail-provider round trip no longer sits in front
of the password sign-in's answer (`waitUntil` on the Worker, `void` on
the node/test posture — the doctrine's own words finally true in code).
Every login stops paying the mailer's latency. The notice's
eventual-delivery posture: best-effort beside the answer, the mailer's
own honest failure handling intact. The four mail-asserting suites
gained a 25ms flush after their logins (the notice now lands a beat
after the answer — the tests assert the same mails, slightly later).
Gates: vue-tsc clean, 581/581, the Workers build, contract green.

## 2. Signing-key memoization — ALREADY TRUE (claim withdrawn)

`auth/op/keys.ts:100` has memoized per isolate all along
(`if (memoized && memoized.raw === raw)`). My roadmap asserted a
per-request parse that does not exist. Recorded here so the record
corrects me, not flatters me.

## 3. D1 replica reads for the list surfaces — OPEN (the big one)

The seam's D1 class can adopt `env.DB.withSession()`: replica reads for
the eventually-consistent surfaces (admin lists, dashboards, activity),
primary-pinned sessions for write-then-read. One place changes; the
scaling gate proves counts stay O(1). EU users stop paying the
APAC-resident primary's ~250ms on every list view.

## 4. The audit journal's retention — OPEN (an ops decision)

`auditEvents` grows unbounded (the retention statement says so). A
purge policy past N days (the ops docs carry the vocabulary) keeps
every surface fast forever. The decision is the owner's.

## 5-8. The architecture items — OPEN

- TODO 26 (the type diet) stands with its solver recipe.
- The store's module-singleton → instance-based (multi-instance tests,
  tenant-per-process hosting).
- `Server-Timing` headers on the batched store phases (the next perf
  claim becomes a measurement).
- e2e sharding (14min serial → parallel; hermetic legs already).
