# TODO.modern/03 — the session management surface (RP-side session state)

**Priority:** P1 · **Status:** DISPATCHABLE
The discovery doc carries no session-management metadata — RPs cannot observe session state passively.

## The acts
1. `check_session_iframe` (`/op/session/check`): the iframe posts a `changed`/`unchanged` message per the OIDC Session Management spec (the cookie present + the client's salted state comparison).
2. The discovery doc advertises `session_management` + `check_session_iframe`.
3. Front-channel logout is DELIBERATELY not adopted (backchannel logout already shipped — the newer posture; record the decision).
4. Specs: the iframe's answer shape; the discovery keys; the e2e contract golden re-record.

**Acceptance:** discovery advertises the surface; a spec RP leg observes a session change.
