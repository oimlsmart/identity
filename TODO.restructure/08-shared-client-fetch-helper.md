# TODO.restructure/08 — the shared client fetch helper (the per-page `api()` copies)

**Priority:** P2 (cleanliness — DRY/OCP on the client seam)
**Status:** COMPLETE

## What landed

`browser/src/lib/api-client.ts` — the ONE wrapper (credentials always,
the JSON content type on a body, everything else passes through). The
SEVEN byte-identical per-page copies (op-admin-users, -registry,
-organizations, -clients, -sessions, -registry-user, -registry-org)
dissolved into the import; a cross-cutting client concern now lands in
one file. The login page's bounded-fetch variant stays local by design
(its abort bound is that page's ceremony — noted in the module header).

## Acceptance (met)

- `grep -rn "async function api(" src/vue-pages` → empty.
- vue-tsc clean; the admin suites (id-admin-dashboard, id-org-admin,
  id-registry-admin, id-registry) 89/89.
