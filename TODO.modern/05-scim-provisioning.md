# TODO.modern/05 — SCIM 2.0 provisioning (the enterprise lifecycle)

**Priority:** P1 · **Status:** IMPLEMENTED (Users lifecycle; Groups = edition 2.1)
Members provision/deprovision accounts from their HR systems via SCIM 2.0 (RFC 7644).

## The acts
1. The SCIM surface (`/scim/v2`, bearer = a PAT with the new `scim:admin` scope): Users (create/get/list/filter/update/deactivate), Groups (optional, edition 2.1).
2. The mapping: SCIM user → an invited OP account (the enrollment invite mails; active=false → the honest disable).
3. The store: the org-scoped account ops already exist (the registry verbs); the SCIM layer maps, never duplicates.
4. Specs: the RFC 7644 shapes (the error taxonomy, the filter subset, pagination); e2e: a provisioning client's lifecycle.
5. The OpenAPI: the SCIM surface documents as its own tag group (edition 2 of the spec).

**Acceptance:** a standard SCIM client provisions a member's people.

**Why held:** RFC 7644 is a protocol (Users CRUD + filter subset + pagination +
its own error taxonomy), and this repo's standard is the full honest surface,
never a partial one behind a half-open door. The mapping target already exists
(the org-scoped account ops, the enrollment invite machinery) — the SCIM layer
maps, never duplicates. First slice when scheduled: `/scim/v2/Users` with the
create/get/filter-by-username/deactivate lifecycle + the `scim:admin` PAT scope,
then Groups as edition 2.1.

## What shipped
1. **The surface** (`browser/server/routes/scim.ts`, RFC 7644):
   POST /scim/v2/Users (the create → the EXISTING account model: the
   account row + the one-time enrollment setup link, emailed
   best-effort), GET the list (pagination + the ONE supported filter
   `userName eq "<email>"` — anything else refuses 400
   scimType=invalid_filter, never a silent mis-answer), GET /:id,
   PATCH (the active replace, pathful or pathless; the HONEST disable
   kills every session; the row stays), DELETE = deactivate NEVER the
   erase (§3.6 — the erase is the console's own sovereign act). The
   RFC's Error schema on every refusal.
2. **The credential — a deliberate deviation, recorded:** the brief
   named a PAT `scim:admin` scope; the PAT grammar is
   client-service-derived and a synthetic 'scim' service would contort
   it. The shipped credential is a DEDICATED `SCIM_BEARER_TOKEN` (a
   Worker secret, constant-time compare) — the Okta/Auth0 SCIM
   connector norm; a dedicated token IS the scoped credential
   (only-SCIM by construction). UNSET = the surface answers 404
   entirely (the Turnstile pattern — zero attack surface).
3. **The mapping (MECE):** SCIM maps, never duplicates — createOpAccount,
   the enrollment invite machinery, setUserActive, deleteAllUserSessions.
   No migration, no second account store.
4. **Documented** in the OpenAPI spec (the SCIM tag + the scimBearer
   scheme; the drift gate holds); the SDK artifact regenerated. The
   endpoint-scaling gate's list leg (one bulk read, paged in memory —
   invariant). Specs: `id-scim.test.ts` (10) — the unset-404 posture,
   the 401 taxonomy, the create/duplicate/malformed trio, the reads +
   the filter subset + invalid_filter, the honest disable (sessions
   die), the deactivate-never-erase tail.

**Groups — ADJUDICATED (2026-09-19), deliberately not built:** SCIM
Groups have NO faithful mapping in this domain. The account's
group-hood IS org membership, and memberships are GOVERNED (the org
registry's own semantics — the OIML register, the join/accept
ceremonies, the endorsement acts). Mapping SCIM Groups onto orgs would
open a SECOND org-creation path — an HR system minting registry
entities by fiat, bypassing the governance the whole registry is
built on. If an HR integration ever needs group-shaped assignment,
the honest path is a dedicated assignment surface with its own
ceremony — its own brief. **The rename (shipped):** SCIM PATCH `replace name` (pathful
`name {givenName,familyName,formatted}` or the pathless
`value.name`) maps onto the account's EXISTING rename verb
(`updateUserName` — no new seam, MECE); the display name is the
formatted, else the given+family join (the create's own projection
rule). (externalId maps nothing today — stays named.)
