# TODO.modern/05 — SCIM 2.0 provisioning (the enterprise lifecycle)

**Priority:** P1 · **Status:** DISPATCHABLE
Members provision/deprovision accounts from their HR systems via SCIM 2.0 (RFC 7644).

## The acts
1. The SCIM surface (`/scim/v2`, bearer = a PAT with the new `scim:admin` scope): Users (create/get/list/filter/update/deactivate), Groups (optional, edition 2.1).
2. The mapping: SCIM user → an invited OP account (the enrollment invite mails; active=false → the honest disable).
3. The store: the org-scoped account ops already exist (the registry verbs); the SCIM layer maps, never duplicates.
4. Specs: the RFC 7644 shapes (the error taxonomy, the filter subset, pagination); e2e: a provisioning client's lifecycle.
5. The OpenAPI: the SCIM surface documents as its own tag group (edition 2 of the spec).

**Acceptance:** a standard SCIM client provisions a member's people.
