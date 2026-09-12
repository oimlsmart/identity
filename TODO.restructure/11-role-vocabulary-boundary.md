# TODO.restructure/11 — the role-vocabulary boundary (which surface glosses)

**Priority:** P2 (semantics — the model decision, recorded)
**Status:** CLOSED (a decision, not a defect)

## The question

TODO.restructure/07+10 gloss the org-role vocabulary on every
USER-facing surface. The ADMIN consoles (op-admin-users, registry,
security, activity, clients) still render raw role codes in many
places (`row.requestedRole`, `acc.roles.join(', ')`, per-client claims
lists). Should they gloss too?

## The decision

No — deliberately. Two reasons, both model-level:

1. **The vocabularies differ.** The glosses cover the seven ORG-BOUND
   roles (orgKindRoles' vocabulary). The admin consoles also render the
   PER-CLIENT claims vocabulary (claimsPolicy.roles, client role
   overrides) and the OP-wide APP_ROLES — different vocabularies with
   no gloss keys; glossing them by map-miss would silently fall back to
   codes anyway (the honest t() behavior), and adding keys for every
   client's custom claims is not this repo's model.
2. **The audience acts on ids.** An administrator EDITING role sets
   needs the exact code (the write payload is the code); a member
   READING their membership needs the meaning. User surfaces gloss,
   admin surfaces code — the seam between them is the shared module,
   and any admin surface that wants glosses imports the same helper
   (open for extension, no console-wide change required).

## The audit note that triggered this

`admitsJoinFlow` (server/auth/org-registry.ts) ALREADY admits the OIML
MEMBER kinds (member-state / corresponding-member personnel ask against
their org, viewer-bounded — TODO.identity-features/10) — the pass-1
suspicion that member orgs were unreachable from the self-service
paths was WRONG. The stale doctrine comment above the function (the
"participant kind only" text) was corrected in the same stroke
(TODO.restructure/10's landing).
