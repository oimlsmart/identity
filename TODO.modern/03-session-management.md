# TODO.modern/03 — the session management surface (RP-side session state)

**Priority:** P1 · **Status:** IMPLEMENTED (the poll surface, spec-faithful)
The discovery doc carries no session-management metadata — RPs cannot observe session state passively.

## The acts — what shipped
1. `check_session_iframe` (`/op/session/check`): the iframe listens for the RP's
   poll message (`client_id=…&session_state=…`), recomputes the digest **server-side
   per poll** against the request's live session (`/op/session/state`), and answers
   `unchanged`/`changed` via postMessage. **Fail-closed:** any poll failure (no
   session, network, parse) answers `changed` — an RP never trusts a dead session.
   Frameable by any RP origin (`CSP: frame-ancestors *` — X-Frame-Options has no
   allow-all value), `no-store`.
2. The authorize answer (both mint paths — remembered-grant skip AND the consent
   allow) carries `session_state` = base64url(SHA-256(client_id + ' ' + RP origin +
   ' ' + session token)). The entropy is the HttpOnly session token itself — no
   stored salt is needed, and no RP can read or guess it. Discovery advertises
   `check_session_iframe` (the standard key only — `session_management` is NOT an
   OIDC Discovery field and is deliberately not invented).
3. Front-channel logout is DELIBERATELY not adopted (backchannel logout already
   shipped — the newer posture).
4. `client_secret` is deliberately unused in the poll protocol: no RP secret
   belongs in browser JS (the public-client posture; confidential clients
   authenticate at the token endpoint, never in an iframe).
5. Specs: `src/__tests__/id-session-management.test.ts` — the discovery key, the
   iframe's poll page posture (frameable/no-store/message-driven), the state
   endpoint's 401-without-session, determinism, input binding, the sign-out → 401
   honest-changed, and the authorize answer's digest round trip. Both new GETs are
   documented in the OpenAPI spec (the drift gate holds).

**Open (honest):** the e2e contract golden (`op-surface-contract.golden.json`)
re-records on the next contract-gate run if it pins the discovery body (the new
`check_session_iframe` key is a deliberate surface addition). A browser-driven RP
poll leg (a real RP iframe listening) would be the last mile of "a spec RP leg
observes a session change" — the unit suite proves the protocol's halves; the
browser glue is the RP side's own.
