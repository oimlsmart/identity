# TODO.restructure/03 — the SSO home's feeds

**Priority:** P0 (throughput — the post-login landing)
**Status:** CLOSED (no defect — the audit's first read was wrong)

## The finding

The initial report suspected a two-phase boot (`/api/op/home` then
`/api/op/home/requests`). Reading the component: `onMounted`
(`browser/src/vue-pages/home.vue:58`) issues ONE fetch (`/api/op/home` —
the launcher feed); the `/api/op/home/requests` hit is the
request-access BUTTON's POST (`requestAccess`, :77), a user action, not
a boot read. The 401 branch redirects with the return URL; the error
branch renders honestly.

The launcher's boot is already one latency phase. Nothing to change —
recorded so the program's evidence trail stays honest.

## Acceptance

n/a — no change. The page keeps its unit proof (id-home.test.ts).
