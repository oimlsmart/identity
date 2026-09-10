# TODO.restructure/02 — the admin/console pages' session-gate waterfall

**Priority:** P0 (throughput — the admin surfaces' every visit pays it)
**Status:** COMPLETE

## Problem

Every admin page pays `await GET /api/auth/session` BEFORE its first data
fetch — a serial two-phase boot whose first leg exists only to decide the
redirect-to-login. The session read's answer never parameterizes the data
URL. Evidence (onMounted blocks):

- `op-admin-overview.vue:79` (session → overview → heartbeat: THREE phases)
- `op-admin-security.vue:185`, `op-admin-sessions.vue:176`,
  `op-admin-activity.vue:160`, `op-admin-registry.vue:146`,
  `op-admin-registry-user.vue:814`, `op-admin-organizations.vue:176`,
  `op-admin-clients.vue:532`, `op-admin-users.vue:1008`

## Approach

Fire the session read and the first data reads CONCURRENTLY
(`Promise.all`); the session branch keeps the redirect decision, the data
branches keep their own error rendering. An unauthenticated visit pays one
extra 401'd data fetch (it redirects anyway); the authenticated happy path
— the only one that matters for throughput — halves.

## Acceptance

- Each page's boot is one latency phase (plus the page's own lazy loads).
- 401 still redirects to the sign-in page with the return URL.
- Gates: vue-tsc, astro check, the admin pages' unit suites (id-admin-dashboard,
  id-org-admin, id-registry-admin, …), build.
