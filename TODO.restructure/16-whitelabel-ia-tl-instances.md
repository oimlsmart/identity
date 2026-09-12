# TODO.restructure/16 — whitelabel instances for the IAs and TLs

**Priority:** P1 (product architecture — the owner's question, 2026-09-10:
"the identity server can be whitelabeled for the IAs and TLs separately —
different features and domains and stuff")
**Status:** CLOSED — the owner chose posture (a) on 2026-09-10 ("make it
work smoothly and no hard coding"), executed via 17+18+19+21; the
federation verification leg is 20 (scoped). Posture (b) remains
unbuilt by decision.

## What the architecture already carries (the split made it stronger)

- **The instance profile is per-deployment**: branding (name, logo,
  theme), `modules` toggles (routes 404 without their module — "one
  build, the profile decides"), `role_codes`, `org_id`/`org_name`. An
  IA-flavored and a TL-flavored profile are two YAML files.
- **Per-instance identity**: `OP_ISSUER` derives per deployment (the
  dev posture derives from the request origin); signing keys, account
  seeds (`OP_ACCOUNT_SEED`), and RP client registries (`OP_CLIENT_SEED`)
  are per-instance env.
- **The self-host posture is PROVEN**: `id-16-selfhost.e2e.ts` boots a
  third party's own OP on its own domain (Node+SQLite and Workers+D1)
  — the whitelabel deployment story's executable skeleton.
- **The org vocabulary is kind-aware end to end** (TODO 07/10/11): an
  IA instance can present its TL cone; a TL instance its operator cone.
- **Independence (TODO 15)**: no kernel coordination — each whitelabel
  deployment is this repo, configured, never forked.

## The two postures (owner picks; they compose)

- **(a) Per-tenant instances** — each IA/TL runs its own deployment
  (own domain, own D1 or SQLite, own profile). Fits the existing
  self-host runbook; the federation cone (`upstream` — generic OIDC)
  lets a tenant's instance delegate to the central OP if it wants one
  workforce sign-in. Gaps: canned `profile.ia.yaml` / `profile.tl.yaml`
  flavors; a per-kind page/nav projection (the admin console's sections
  filter by the profile's kind today only implicitly); the tenant
  provisioning runbook (seed the tenant's org + its clients + its
  signing key ceremony).
- **(b) Hosted multi-tenant** — one deployment serves
  `ia.example.org` and `tl.example.org` with per-host profiles. Gaps:
  per-host profile resolution middleware (the profile is per-isolate
  today), per-host issuer + keyset discipline, cookie/origin isolation
  auditing. Heavier; only worth it if tenants are many and small.

Recommendation: (a) first — it is configuration and runbook work over
machinery that exists; revisit (b) when tenant count says so.

## The named gaps (either way)

1. Canned IA/TL profile flavors + the kind-projected console nav.
2. The tenant provisioning runbook (org seed, client registry, keys,
   the first administrator).
3. An e2e proof leg per flavor (the id-16 pattern with the flavor
   profiles).

## Acceptance

A whitelabel IA instance boots on its own domain, shows only its
cone's sections, carries its own registry rows and clients, and never
sees the central instance's data — proven by the flavor e2e legs.
