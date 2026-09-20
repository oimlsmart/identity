# TODO.modern/17 — login_hint (the chooser's missing companion)

**Priority:** P1 · **Status:** IMPLEMENTED
**The corrected record**: the account chooser itself ALREADY SHIPS — an
earlier wave built `/op/choose-account` (its context + continue APIs)
and wires `prompt=select_account` into the authorize (the flow ALWAYS
routes through the chooser when asked; the value is consumed by the
redirect). This brief's original premise — that select_account was
unsupported — was an audit error, caught by its own spec's first run
(the redirect answered `/op/choose-account`, not the assumed consent
page). The one genuinely missing piece:

## What shipped
1. **`login_hint` on the authorize**: carried through the sign-in
   redirect (`&login_hint=` on the `/?redirect=` target) when the
   session is absent, and **prefilled into the login page's address
   field** (the page reads its own query — `login_hint` joins the
   existing `email` prefill; the hint is a HINT, the human corrects).
2. The parameter rides the PAR source too (the pushed set carries it
   like any other).
3. Specs (`id-account-chooser.test.ts`): the chooser's own behavior
   pinned (select_account → `/op/choose-account` even with a live
   remembered grant — the page is the confirmation), login_hint rides
   the sign-in redirect, the default carries no hint (the
   byte-identical posture).

**Open (honest):** nothing — the chooser wave's own brief owns the
chooser's future.
