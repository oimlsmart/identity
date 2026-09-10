# TODO.restructure/17 — the whitelabel flavors (posture a)

**Priority:** P0 (the owner's decision, 2026-09-10: "posture: we want to
support (a) ... no hard coding")
**Status:** COMPLETE — executed with 18/19 (they were one slice); this
file records it.

## What landed

- **`browser/profiles/ia.yaml` + `tl.yaml`** — the flavors, TENANTS'
  STARTING POINTS (copy, fill in, point INSTANCE_PROFILE): org
  identity, brand (name, tagline, logo paths), the console-section
  set each flavor operates.
- **No hard coding, model-driven**: the profile schema (now identity's
  own — TODO 15's dividend) gained optional `branding` asset/copy
  fields and the `console.sections` declaration, validated against the
  shell's KNOWN admin keys (fail-loud parse). /api/config projects
  them; `branding.ts` merges over the defaults client-side;
  `ConsoleChrome` filters ADMIN_ENTRIES by the projected set. A new
  flavor = a YAML file; a new section = one entry + one catalog key.
- **The runbook**: `docs/deployment/identity-whitelabel.md` — the
  tenant provisioning acts (profile, assets, issuer/keys, bootstrap
  admin, RP seed, deploy posture, optional federation).

## Proof

`id-whitelabel.test.ts` 3/3: the declared brand rides /api/config
verbatim (undeclared fields absent — the client-side merge's other
half); the declared console answers exactly its set; undeclared
answers null (the central posture unchanged); an unknown key fails
the parse loudly. vue-tsc clean; full gates green (this slice's
landing run).
