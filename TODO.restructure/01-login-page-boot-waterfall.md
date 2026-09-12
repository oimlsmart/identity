# TODO.restructure/01 — the login page's boot waterfall

**Priority:** P0 (throughput — every sign-in pays it)
**Status:** COMPLETE

## Problem

The sign-in page (`/`, `browser/src/vue-pages/public/login.vue:165`) gates
the form's render (`loading`) behind THREE sequential awaited round trips in
`onMounted`:

1. `GET /api/config` (demo posture)
2. `GET /api/op/providers/public` (upstream buttons)
3. `GET /api/auth/session` (the live-session skip)

Each hop is a full request→response; against the APAC-resident D1/Wire the
page's time-to-form is ~3× the honest latency. The three are independent —
nothing downstream of one reads another's answer.

## Approach

One `Promise.allSettled` over the three bounded fetches; each result lands
in its own try/catch-equivalent branch (the settled posture keeps one
failure from masking the others — the existing per-fetch `catch` semantics
preserved exactly). The session-redirect branch stays last-ordered in
effect but no longer waits on the first two.

## Acceptance

- The form renders after ONE latency phase, not three.
- A failing `/api/config` still defaults the demo posture; a failing
  providers read still renders no buttons; a live session still redirects.
- Gates: vue-tsc, astro check, vitest (id-signin-panels, id-op-core), build.
