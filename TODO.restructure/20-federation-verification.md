# TODO.restructure/20 — federation verification (the generic-OIDC upstream)

**Priority:** P0 (the owner's ask: "verify that our federation works")
· **Status:** COMPLETE — `id-whitelabel-federation.test.ts` 2/2 (2026-09-10):
LEG 1 LINK and LEG 2 SIGN-IN across TWO REAL instances (central spawned
on :3991 with its own process/DB — the sqlite singleton forbids one
process; the tenant in-process on the IA flavor). PKCE asserted on the
wire, the real consent decide, the code exchanged at the REAL /op/token,
the ID token JWKS-validated, the match rule linked, the remembered
grant skipping consent, the tenant session on ITS issuer, exactly ONE
link row. Incidental proof: the whitelabel brand rode the sign-in
notice mail ("Sent by Example IA Sign-In") unprompted.

## What exists (verified by audit, 2026-09-10)

- `id-upstream.test.ts`: the flow-state round-trip (tamper/expiry/
  open-redirect refusals), the provider registry's validation + secret
  BY-REFERENCE resolution + `OP_UPSTREAM_SEED` bootstrap, the Apple
  client-secret JWT. The callback redirect URI is pinned (:79).
- `id-security-notices.test.ts` drives an upstream LINK flow against a
  fixture provider.

## The missing leg (the actual federation ask)

A TENANT instance delegating sign-in to the CENTRAL OP through a
generic-OIDC upstream — the full dance across two REAL apps:

1. Boot CENTRAL (in-process identity app, the standard harness) and
   register a confidential client for the tenant.
2. Boot TENANT with an `OP_UPSTREAM_SEED` entry of kind `oidc`
   (issuer = CENTRAL, the client pair by env REF) and an
   `INSTANCE_PROFILE` flavor (17's ia.yaml shape).
3. Drive: TENANT `/op/upstream/{id}/signin` → the redirect to CENTRAL
   `/op/authorize` (assert the tenant's client_id + redirect_uri +
   PKCE) → a session on CENTRAL (its own store) → consent → code →
   TENANT's callback exchanges at CENTRAL `/op/token` → the match rule
   (provider + provider_account_id, never email) links/creates the
   tenant account → the tenant session stands (its OWN cookie), and a
   second pass takes the LINK path (no duplicate account).
4. Assert the tenant's ID token (its own issuer/key) — the two
   issuers never blur.

Name: `id-whitelabel-federation.test.ts`. The two-app harness is the
id-email-verification pattern ×2 with the upstream seed wired. Run in
the full suite + CI; this machine's astro lock blocks only browser
legs, not in-process ones.
