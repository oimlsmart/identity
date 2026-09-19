# TODO.modern/05 — SCIM 2.0 provisioning (the enterprise lifecycle)

**Priority:** P1 · **Status:** HELD (a full protocol surface — its own PR)
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
