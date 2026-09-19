# TODO.modern/02 — the OpenID conformance suite (OIDC Certification)

**Priority:** P1 · **Status:** HELD (needs the owner's scratch host)
Run the OpenID Foundation's conformance suite (Basic OP + Config + Refresh OP) against a scratch deployment; fix every finding; record the certification.

## The acts
1. A scratch deployment (self-host runbook posture) with a seeded conformance client (the suite's RP client registered via OP_CLIENT_SEED).
2. The suite runs from the official container against the deployment's public origin (local tunnel or a preview-shaped host).
3. Every finding is a code fix + a spec leg (the finding's regression test), never an assertion relaxed.
4. The discovery doc advertises only what's certified (`check_session_iframe` rides TODO 03, not ahead of it).
5. Record: the run's summary in docs/deployment/identity.md + the cert listing.

**Acceptance:** the suite's three profiles green; the record committed.

**Why held:** the suite runs from the OpenID Foundation's container against a
PUBLIC origin — a scratch deployment with a public hostname is an owner
infrastructure act (a tunnel or a throwaway Workers route + the conformance
client seed). Everything in-repo is ready: the self-host runbook, the
OP_CLIENT_SEED seeding, the contract gate. First slice when unheld: the three
profiles (Basic OP, Config OP, Refresh OP) on the scratch host; every finding
lands as a code fix + a regression leg.
