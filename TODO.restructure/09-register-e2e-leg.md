# TODO.restructure/09 — the register path's e2e leg

**Priority:** P2 (specs — the puppeteer proof of TODO.restructure/05)
**Status:** COMPLETE (the leg written + wired; its CI run is the
arbiter — see the local-environment note)

## What landed

`browser/e2e/id-37-register.e2e.ts` — the id-29 boot pattern (own ports
10647-10650, own SQLite, the stub mailer + the fixture RP, fresh
browser per leg), five legs:

1. the sign-in page carries the register entry; `/register` renders
   the form (typed inputs asserted);
2. a short password is refused at the policy gate and NO account
   exists (the login probe 401s);
3. the happy register: the success panel, the verify link captured
   from the MAIL only, the password signing in at once, the console's
   unverified banner, and the RP round trip answering email_verified
   FALSE on both surfaces;
4. the mailed link completes: the banner lifts, the claim answers TRUE;
5. the duplicate register renders the honest 409 and the registry
   still holds exactly one row for the address.

`.github/workflows/ci.yml`'s e2e leg list carries `id-37`.

## The local-environment note (honest verification posture)

The leg cannot boot on THIS machine: three `astro dev` processes hold
Astro 7's background-dev lock, and `--ignore-lock` is foreground-only —
the IDENTICAL invocation ships in id-29 (and every stack-booting leg);
the repo's history records this class ("id-03/id-07 discharged by CI's
clean runners — a local listener holds their port"). The leg follows
the house pattern byte-for-byte; CI is its arbiter. The SERVER-side
arc is proven locally by `id-self-registration.test.ts` (4/4, in the
unit suite). vue-tsc covers the leg's types (clean).
