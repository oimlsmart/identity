# TODO.restructure/13 — the admin consoles' EN-only copy (the lockstep gap)

**Priority:** P2 (product polish — the declared EN/FR posture)
**Status:** COMPLETE (2026-09-10, slices 1–4): the shared error line
everywhere (37 sites, one key); the three FLOW PAGES (setup.*, consent.*,
emailChange.*); SIX CONSOLES whole (overview, sessions, activity,
registry, clients, security — incl. the two 40-case describe() audit
families, MECE-shared keys between them); and op-admin-users.vue — the
org console's notices, forms, queues, and the per-client roles editor
(admin.users.*, 71 keys). ~290 keys total, EN verbatim (every e2e pin
holds) + FR in the same commits. Final gates: vue-tsc clean, 580/580,
both builds, astro check, the contract golden untouched, id-i18n parity
green, and `grep "Network error. Is the server running?" src/vue-pages`
answers ZERO. The whole-file rule held throughout — no page was left
half-migrated.

## Slice 2 — COMPLETE (2026-09-10): the three public flow pages

`op-setup.vue`, `op-consent.vue`, `op-email-change.vue` — the
user-facing ceremonies — now ride the catalogs whole: the new
`setup.*` (17 keys), `consent.*` (19), `emailChange.*` (30) namespaces,
66 keys EN verbatim + FR in the same commit (580/580, vue-tsc clean,
the OIDC suites + parity green; the e2e text pins hold — EN text moved
verbatim and textContent is preserved through the parameterized
sentences).

## Slice 1 — COMPLETE (2026-09-10): the shared error line, everywhere

The single most-repeated literal — "Network error. Is the server
running?" (37 sites across 12 pages) — now rides ONE catalog key,
`error.network` (EN verbatim, so every e2e pin holds; FR translated).
The five admin pages that had NO i18n wiring at all (overview, sessions,
security, activity, registry) now import `t` — the wiring for the rest
of their copy is in place. Proof: vue-tsc clean, full suite 571/571
(incl. the id-i18n parity leg).

## The remainder (one PR, mechanical — the recipe stands)

Per-page body copy: titles, act notices, form labels, forbidden panels,
`describe()` strings. The measured inventory (grep heuristics,
2026-09-10, after slice 1):

- `op-admin-users.vue` — worst: the act-notice families + form labels
  (~20 clusters, some interpolating — they become `t(key, {params})`)
- `op-admin-security.vue` — the `describe()` audit-line family +
  filter option labels (~10)
- `op-admin-overview.vue` — tiles + the forbidden panel (~6)
- `op-admin-sessions.vue` — act notices + the confirm ladders (~6)
- `op-admin-clients.vue` — form labels + notices (~4)
- `op-admin-registry.vue` / `op-admin-activity.vue` — small (~2 each)
- DISCOVERED SCOPE: the three public flow pages are EN-only pages
  entire (`op-setup.vue`, `op-consent.vue`, `op-email-change.vue`) —
  they need their own namespaces (`setup.*`, `consent.*`,
  `emailChange.*`), not admin keys.

Recipe as before: EN strings move VERBATIM into en.ts (the e2e pins
read English under the default locale), FR lands in the same commit
(the `Record<MessageKey, string>` typing refuses a drift), recurring
lines share keys.

## Acceptance

- `grep -rn "Network error. Is the server running?" src/vue-pages` →
  empty (met by slice 1 — verified).
- Final: the seven consoles + three flow pages read `t(...)` throughout;
  id-i18n parity green; vue-tsc, astro check, vitest, builds; the
  affected e2e legs (id-10/id-12/id-13 + the flow-page legs) green in
  CI.
