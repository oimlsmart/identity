# TODO.modern/02 — the OpenID conformance suite (OIDC Certification)

**Priority:** P1 · **Status:** DISPATCHABLE (the brief)
Run the OpenID Foundation's conformance suite (Basic OP + Config + Refresh OP) against a scratch deployment; fix every finding; record the certification.

## The acts
1. A scratch deployment (self-host runbook posture) with a seeded conformance client (the suite's RP client registered via OP_CLIENT_SEED).
2. The suite runs from the official container against the deployment's public origin (local tunnel or a preview-shaped host).
3. Every finding is a code fix + a spec leg (the finding's regression test), never an assertion relaxed.
4. The discovery doc advertises only what's certified (`check_session_iframe` rides TODO 03, not ahead of it).
5. Record: the run's summary in docs/deployment/identity.md + the cert listing.

**Acceptance:** the suite's three profiles green; the record committed.
