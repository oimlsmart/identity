# The identity service SLO (the published statement)

The service-level objective for the OIML SMART identity service — the
OIDC Provider (OP) at https://id.oimlsmart.org, the federation's single
authentication point. This page is the public statement; the operating
discipline around it is `identity-operations.md`.

## The objective

**99.9% monthly availability of the OP's public OIDC surface.**

- *The surface:* the discovery document
  (`/.well-known/openid-configuration`), the JWKS (`/jwks.json`), and
  the token endpoints answering with the correct error taxonomy — the
  surface every relying party pins. An answer is available when the
  heartbeat probe (below) passes: the right documents, the right shape,
  the right refusals.
- *The budget:* 99.9% of a 30-day month is **≈ 43 minutes** of
  unavailability — at the heartbeat's 15-minute cadence, roughly three
  consecutive red probes exhaust the month.
- *The floor:* the edge provider's anycast network fronts the service;
  the objective assumes that floor and adds our own failure modes on
  top.

## The measurement

- *The instrument:* the `identity-heartbeat` GitHub Actions workflow
  (`.github/workflows/identity-heartbeat.yml`) runs
  `browser/scripts/op-heartbeat.ts` every 15 minutes from GitHub's
  runners — an external vantage, no shared fate with the service. The
  probe reads the public surface only: no secrets, no credentials.
- *The operator read:* the admin dashboard's SLO panel
  (`/op/admin`, the overview) reads the heartbeat workflow's own run
  history — the same data, no second pipeline.
- *The public read:* https://status.oimlsmart.org — the estate's status
  service probes the OP among its surfaces; the OP's current state is
  visible there without an account.
- *A red probe is never silent:* the workflow opens (or updates) the
  standing issue in this repository with the run link and the failing
  leg named.

## What the objective covers — and what it does not

- It covers the OP itself, as seen from outside. A relying party's own
  availability is that service's objective, not this one.
- The RP-side effect of an OP outage is the **degraded-mode doctrine**:
  existing RP sessions ride their own cookies (OP down does NOT mean
  logged out); new logins fail honestly on a plain status page; the demo
  instances' local demo accounts stay available as the clearly-marked
  development posture. RPs are asked to cache the JWKS briefly so
  validation survives short OP outages.
- Maintenance carries no planned-downtime carve-out: migrations are
  expand-only and applied out-of-band before the tag deploy, and a
  rollback is `wrangler rollback` against a schema the previous release
  can still read (`identity-deploy.md`). A change that could not keep
  that posture would say so in its deploy notes — none is planned.
- The account registry's disaster-recovery posture (the restore drill,
  the export cadence) is the operations runbook's DR section — a
  data-loss event is a different failure class than an availability
  one, and it has its own proven path.

## The failure response

1. The heartbeat's red run opens/updates the standing issue
   (the demo-reset report pattern — one issue, appended, never a flood).
2. The operator's first read is the run log's failing leg, then the
   deploy state: the last `id-v*` tag, the last migration applied.
3. The rollback recipe and the staged-rollout discipline are
   `identity-deploy.md`; the restore drill is `identity-operations.md`'s
   DR section.
4. A breach of the monthly objective is stated honestly on the status
   service's incident record — the probe history is the evidence, and
   it is public.
