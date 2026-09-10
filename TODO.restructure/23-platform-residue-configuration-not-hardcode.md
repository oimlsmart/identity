# TODO.restructure/23 — the platform residue: configuration, never hardcoded

**Priority:** P0 (the owner's doctrine, restated 2026-09-10: "Do you
understand configuration vs hardcoding? Clearly the oimlsmart platform
requires the identity service to obtain permissions.")
**Status:** SCOPED — the audit complete, the waves below; a follow-up
to PR #79 (the split's "whole-copy first, surgery second" rule named
this pruning as the second step).

## The doctrine (the owner's law, corrected twice)

Identity's code stands alone. The PLATFORM obtains its permissions
FROM identity through CONFIGURATION: it registers as a relying party
(the client registry — issuer, client pair, redirect URIs, claims
policy, per-client role assignments), its services present tokens
identity mints, and its users hold roles identity assigns. NEVER
through platform taxonomy baked into identity's code, and never
through shared code across the repos. Cross-repo work happens when the
owner explicitly asks.

## The measured residue (the audit, 2026-09-10)

The split copied the kernel's profile module WHOLESALE — it carries the
PLATFORM's deployment vocabulary, hardcoded:

- `server/profile.ts:34` — PROFILE_ROLES includes the platform's
  'hub'/'ia'/'tl' postures alongside identity's own
- `:40-53` — INSTANCE_MODULES: 11 of 12 modules are PLATFORM surfaces
  (portal, ia-console, tl-workbench, biml-console, register, cs-admin,
  engagement, federation, cnml, twin, engine); only 'identity' is
  identity's
- `:177-178` (defaultModulesForRoles) — builds hub-era module sets
- `defaultInstanceProfile()` — the BIML HUB platform profile as
  identity's fallback default
- `server/store/d1.ts:110,839` — `seedAccountsForProfile`, the
  platform's per-role STAFF seeding model, riding identity's D1 path

All dead-or-foreign weight in identity: every identity deployment
declares `roles: [identity]` (the whitelabel flavors included), so the
platform postures never activate — but they HARDCODE a platform
concept where configuration should stand.

## The waves

1. **The profile module becomes identity's own**: PROFILE_ROLES =
   the identity posture + the whitelabel kinds it actually serves;
   INSTANCE_MODULES = identity's own surface(s); the fallback default
   = the identity service's own profile (never the BIML hub's); the
   hub/ia/tl default module sets deleted. `/api/config`'s module
   projection and the route gates stay driven by the DECLARED profile
   — configuration, exactly as the whitelabel flavors already do.
2. **The D1 staff-seeding path**: identity's seeding is its own
   (OP_ACCOUNT_SEED bootstrap + demo personas for dev); the platform
   staff model goes.
3. **The specs**: the whitelabel suite gains a leg pinning that an
   identity boot NEVER answers a platform module; the fallback-default
   leg pins the identity-service default (not the hub's).

## Acceptance

- `grep -n "portal\|ia-console\|tl-workbench\|biml-console\|register\|cs-admin\|engagement\|federation\|cnml\|twin\|engine" browser/server/profile.ts`
  → the historical comment references only; zero live vocabulary.
- The full suite + whitelabel legs green; the contract golden
  untouched; the whitelabel flavors boot unchanged (they never
  declared a platform module).
