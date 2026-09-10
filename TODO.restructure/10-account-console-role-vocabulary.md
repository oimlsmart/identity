# TODO.restructure/10 — the account console's role vocabulary

**Priority:** P1 (product logic — Member vs IA/TL legibility on the
USER-facing surface)
**Status:** COMPLETE

## Problem

The account console — the surface every member reads — rendered raw
role machine codes everywhere (`browser/src/vue-pages/account.vue`):

- the membership chips: `{{ m.roles.join(', ') }}` → "ia_officer, viewer"
  (:1304)
- the join-request lines: `{{ r.requestedRole }}` (:1461)
- the join form's role select: `{{ r }}` (:1491)

The join page (since TODO.restructure/07) renders `code — gloss`; the
console predates the vocabulary. A member reading "tl_operator" on
their own console still cannot tell what it is for.

## The fix

The console joins the ONE vocabulary: `roleGloss` over the shared
module (`src/org-vocabulary.ts`), rendering `code — gloss` on all
three surfaces — the code stays visible (the support/admin
cross-reference and the e2e pins read it), the gloss carries the
meaning. No new catalog keys (org.role.* already ride EN/FR).

## Acceptance

- id-13's e2e pin (`account-org-roles` contains 'ia_officer') still
  holds — the code is part of the rendered line by design.
- Gates: vue-tsc, id-account-console, id-memberships, id-i18n.
