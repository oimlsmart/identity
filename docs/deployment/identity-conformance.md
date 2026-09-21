# The OpenID conformance run — the operator's runbook (TODO.modern/02)

> FOR: the service owner, when certification is scheduled. Everything
> in-repo is ready; this page is the exact procedure. The house rule
> for findings: **every finding is a code fix + a regression leg,
> never a relaxed assertion** — and a deliberate surface change
> re-records the contract golden, never edits it to pass.

## What the suite needs

The OpenID Foundation's conformance suite runs from a container against
a PUBLIC origin (it drives real browser redirects and token
round-trips). The three profiles that match this OP's surface:

1. **Basic OP** (code flow + PKCE — the core authorization surface),
2. **Config OP** (the discovery document's honesty),
3. **Refresh OP** (the rotation + the reuse-kill).

## The scratch deployment (the owner's one infrastructure act)

Pick either posture — both are proven by this repo's own machinery:

- **The Workers scratch route** (the production posture): `wrangler
  deploy` the built Worker under a scratch `routes` entry + a scratch
  D1 (never the production binding — the account registry never
  moves). Declare the same secrets as production plus the ones below.
- **The self-host node posture** (`identity-self-host.md`): SQLite on
  a scratch VM + a tunnel to a public hostname.

## The seed (the suite's RP client)

The suite acts as a relying party. Register its client through the
config seed (never the production console):

```json
OP_CLIENT_SEED=[{
  "client_id": "conformance-suite",
  "name": "OpenID Foundation Conformance Suite",
  "secret": "<generated>",
  "redirect_uris": ["https://localhost:8443/callback", "http://localhost:8080/callback"],
  "claims_policy": { "claims": ["roles", "groups", "org"] }
}]
```

Set `OP_ACCOUNT_SEED` with a test account for the browser legs (the
suite drives real sign-ins). `OP_ISSUER` is the scratch origin.

## The run

```sh
docker run -p 8080:8080 openid/conformance-suite:latest
```

Browse the suite, point it at the scratch origin's discovery document,
and run the three profiles. The suite's own UI carries the per-test
detail; export the summary (JSON + the HTML report).

## The findings protocol

For every failure the suite reports:

1. Reproduce in-process (the `app.request` pattern — the suite's own
   test spec in `src/__tests__/`) before touching code.
2. Fix the CODE (the spec is the truth — a finding means the surface
   deviates from it; the fix direction is toward the spec).
3. If the fix is a deliberate surface change, re-record
   `browser/e2e/golden/op-surface-contract.golden.json` (the record
   command is in the gate's failure message) and update the OpenAPI
   spec (the drift gate enforces it).
4. Record the run in `docs/deployment/identity.md` (the summary, the
   profile verdicts, the findings' resolutions) and, on certification,
   the OP's listing entry.

## The known-posture notes (read before the run)

- Front-channel logout is deliberately absent (back-channel shipped);
  the Config profile must not penalize its absence (the discovery
  document advertises only what exists — `check_session_iframe` now
  rides TODO.modern/03).
- The token endpoint's refusal is the ONE `invalid_grant` shape by
  design (no enumeration aid); the suite's invalid-grant tests should
  pass against it, and if a test demands MORE distinction, that is a
  finding to ADJUDICATE with the owner, not to fix silently.
- `max_age`/`acr` (TODO.modern/06) and `session_state` (03) are in the
  surface now; their conformance behavior is unit-proven in
  `id-stepup.test.ts` / `id-session-management.test.ts`.
