# Running a whitelabeled identity instance (an IA's or TL's own OP)

Posture (a) of TODO.restructure/16: each Issuing Authority or Test
Laboratory runs its OWN instance of this service — own domain, own
registry, own brand. It is a CONFIGURATION act, never a code change.

## The acts

1. **The profile** — copy a flavor (`browser/profiles/ia.yaml` or
   `tl.yaml`), fill in the tenant's values (`identity.org_id`,
   `org_name`, `country`, the `branding:` fields — name, logo/mark
   asset paths, `login_tagline` — and the `console.sections` set the
   tenant operates). Point `INSTANCE_PROFILE` at the copy. The parse
   fails loudly on an unknown section key (a typo never narrows a
   console silently).
2. **The brand assets** — the tenant's logos/marks live under its
   static root or absolute URLs; the profile declares the paths and
   the client merges them over the service defaults (undeclared fields
   keep the identity service's own).
3. **The issuer + keys** — `OP_ISSUER` is the tenant's domain
   (identity#7: a declared issuer declares `OP_SIGNING_KEY` too).
4. **The first administrator** — `OP_ACCOUNT_SEED` (the bootstrap
   invite lands in the boot log; the setup link is one-time, 24 h).
5. **The tenant's RPs** — `OP_CLIENT_SEED` (each relying party the
   tenant's services register).
6. **The deploy posture** — Node + SQLite or Workers + D1, the
   self-host runbook (`identity-self-host.md`, proven by e2e
   `id-16-selfhost.e2e.ts`).
7. **Optional federation** — the tenant's instance may delegate
   sign-in to the central OP by registering it as a generic-OIDC
   upstream provider (`identity-upstreams.md`); the verification leg
   is TODO.restructure/20.

## What a whitelabel instance is NOT

It never sees the central instance's data; its org registry is its own
(seed it via `scripts/import-org-registry.ts` or the console). Its
console shows only the declared sections — the shell filters
ADMIN_ENTRIES by the projected set; the code never branches on kind.
