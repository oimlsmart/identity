// ═══════════════════════════════════════════════════════════════════
// @astrojs/vue app entrypoint — runs once per island app (client-side).
//
// The identity shell mounts one Vue island per Astro page and performs
// NO SPA navigation: every page transition is a full document load.
// The page components call useRoute()/useRouter() and render
// <router-link>, so every island gets a real vue-router instance built
// from the OP's route table below: useRoute() matches the actual
// browser URL (route.query/route.params behave as the pages expect) and
// <router-link> renders correct hrefs. All patterns share one dummy
// component — this router never renders page content.
//
// Navigation: router.push/replace are patched AFTER install (install()
// performs the initial navigation — patching earlier would reload-loop
// the page) to FULL document loads. The smart monorepo's entrypoint
// decides per navigation between an in-shell swap and a boundary load;
// this shell has no in-shell swap, so the decision collapses to the
// boundary case.
//
// NOTE: @astrojs/vue prepends `import "<this file>"` into every .vue it
// transforms, so this module must stay side-effect-free at import time —
// createWebHistory() runs inside setup() only, never at module scope.
// ═══════════════════════════════════════════════════════════════════
import type { App } from 'vue'
import { createRouter, createMemoryHistory, createWebHistory, type RouteLocationRaw } from 'vue-router'

const IslandPage = { template: '<div />' }

// The OP's route table: every URL the identity pages serve or link to.
// Names exist so useRoute().name resolves exactly as the pages expect.
const ROUTE_PATHS: Array<{ path: string; name: string }> = [
  { path: '/', name: 'landing' },
  { path: '/app/login', name: 'login' },
  { path: '/app/account', name: 'account' },
  { path: '/op/account', name: 'op-account' },
  { path: '/op/consent', name: 'op-consent' },
  { path: '/op/join', name: 'op-join' },
  { path: '/op/setup', name: 'op-setup' },
  { path: '/op/email-change', name: 'op-email-change' },
  { path: '/op/admin/clients', name: 'op-admin-clients' },
  { path: '/op/admin/providers', name: 'op-admin-providers' },
  { path: '/op/admin/users', name: 'op-admin-users' },
  { path: '/op/admin/activity', name: 'op-admin-activity' },
  { path: '/op/admin/registry', name: 'op-admin-registry' },
  { path: '/op/admin/registry/users/:id', name: 'op-admin-registry-user' },
]

export default function setup(app: App): void {
  const router = createRouter({
    // SSR (the prerender + the Cloudflare worker's page renders) runs
    // setup() for the shell's chrome islands: no window there, so the
    // router rides a memory history. On the client the web history makes
    // useRoute() match the real browser URL.
    history: import.meta.env.SSR ? createMemoryHistory() : createWebHistory(),
    routes: [
      ...ROUTE_PATHS.map(p => ({ path: p.path, name: p.name, component: IslandPage })),
      // Fallback for URLs outside the route table — keeps useRoute()
      // reflecting the real path.
      { path: '/:pathMatch(.*)*', name: 'not-found', component: IslandPage },
    ],
  })

  app.use(router)

  const toUrl = (to: RouteLocationRaw): string => {
    if (typeof to === 'string') return to
    if ('path' in to && typeof to.path === 'string') {
      const query = new URLSearchParams(to.query as Record<string, string>).toString()
      return to.path + (query ? `?${query}` : '') + (to.hash ?? '')
    }
    return router.resolve(to).fullPath
  }

  // Every in-router navigation is a full document load (see the header).
  router.push = (to: RouteLocationRaw) => {
    window.location.assign(toUrl(to))
    return new Promise(() => {}) // the document unloads; never settles
  }
  router.replace = (to: RouteLocationRaw) => {
    window.location.replace(toUrl(to))
    return new Promise(() => {})
  }
}
