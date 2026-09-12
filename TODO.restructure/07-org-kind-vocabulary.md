# TODO.restructure/07 — the ONE org-kind vocabulary (Member vs IA/TL made legible)

**Priority:** P1 (product logic — the audit's second headline illogic)
**Status:** COMPLETE

## Problem

The domain model already distinguishes the kinds perfectly
(`server/auth/org-registry.ts:69-140`): the OIML MEMBER kinds hold the
read/access posture (`viewer` only — membership is the Convention's fact,
never workflow authority), while the PARTICIPANT kinds hold the CS
workflow authority (an IA's staff: `ia_officer`/`case_officer`/
`certification_officer`/`signatory`; a TL's: `tl_operator`), and
`manufacturer` is never a participant. **The UI never says any of this** —
three divergent presentations, none complete:

1. the organizations admin list renders the RAW kind code
   (`op-admin-organizations.vue:345` — `{{ row.kind ?? … }}`);
2. the registry org detail's `kindText` labels ONLY the two member kinds
   (`op-admin-registry-org.vue:337`) — IA/TL/utilizer/associate/manufacturer
   fall through to the raw code;
3. the join page carries its OWN local English-only maps
   (`op-join.vue:67` `KIND_LABELS`, `:80` `ROLE_GLOSSES`) — breaking the
   EN/FR catalog lockstep every other page keeps.

Nobody reading the orgs list can tell what a Member org is FOR versus an
IA or a TL. DRY/MECE violated three ways.

## The fix

One vocabulary module — `browser/src/org-vocabulary.ts` — the single
source mapping kind → i18n key (label + one-line purpose) and role →
i18n key (gloss), consumed by all four surfaces (the orgs list, the
registry org detail, the join page, the registry user detail's role
glosses). Catalogs gain the `org.kind.*` / `org.role.*` namespaces in
EN **and** FR (the join page's inline strings dissolve into them — its
i18n gap closes in the same stroke). Adding a kind or role becomes ONE
entry in ONE map (OCP); the per-kind standing line on the orgs list
(standingLine, manufacturer-only today) draws from the same module.

The copy states the doctrine in one line each, e.g.:
- member-state: "OIML Member State — the Convention's membership; read
  access to the estate's services, never certificate workflow authority."
- issuing-authority: "Issuing Authority — runs the OIML CS: evaluates,
  issues and endorses certificates; its staff hold the workflow roles."
- test-laboratory: "Test Laboratory — performs the tests an IA dispatches;
  its operators hold the tl_operator role."

## Acceptance

- All four surfaces render labeled kinds + purposes, EN and FR.
- `grep -r "KIND_LABELS\|ROLE_GLOSSES" src/vue-pages` → only the shared
  module's consumers; no page-local kind/role label maps remain.
- Gates: id-registry.test.ts, id-org-admin.test.ts, id-i18n.test.ts
  (the EN/FR key-parity leg), vue-tsc, astro check.
