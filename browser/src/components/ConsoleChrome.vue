<script setup lang="ts">
// ═══════════════════════════════════════════════════════════════════
// ConsoleChrome — the identity console's ONE section navigation
// (TODO.identity-features/07, the shell reimplementation). Replaces the
// per-page OpAdminNav tab strip (a second bar stacked under the page
// header, clipped to a sideways scroller even at desktop widths) with
// the professional console pattern:
//
//   DESKTOP (lg+)   a left RAIL beside the page: the console switch
//                   (My applications / Your account / Administration —
//                   the movement between the three areas is one click,
//                   the admin entry gated by the session's role) and the
//                   current console's sections (the admin surfaces; the
//                   account console's on-page anchors).
//   PHONE (<lg)     the rail collapses to a DISCLOSURE: the header's
//                   nav toggle opens the same nav as a sheet under the
//                   header (a backdrop + Escape close it; picking an
//                   entry closes it). Never a stacked second bar.
//
// The header bits (the toggle + the current-section label) TELEPORT
// into the shell header's #shell-chrome-slot, so the one component owns
// the disclosure's state for both render points.
//
// Every navigation is a plain <a href>: this shell performs no SPA
// navigation (astro/app-entrypoint.ts turns router pushes into document
// loads; an anchor is the same act with no router needed). The admin
// entries carry the pre-existing op-admin-nav testids (the e2e surface
// leg waits on op-admin-nav; a testid change is a breaking change).
// ═══════════════════════════════════════════════════════════════════
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { t, type MessageKey } from '../i18n'
import { useConsoleSections } from '../branding'

type ConsoleArea = 'home' | 'account' | 'admin'

const props = defineProps<{
  area: ConsoleArea
  /** The current admin surface (the rail's aria-current entry). */
  current?: string
}>()

interface NavEntry { key: string; to: string; labelKey: MessageKey }

// The administration surfaces — the set and order of the pre-07 tab
// strip (the wave-05 organizations entry between registry and
// sessions), the labels riding the admin.nav.* / admin.orgs.title
// catalog keys.
const ADMIN_ENTRIES: ReadonlyArray<NavEntry> = [
  { key: 'overview', to: '/op/admin/overview', labelKey: 'admin.nav.overview' },
  { key: 'registry', to: '/op/admin/registry', labelKey: 'admin.nav.registry' },
  { key: 'organizations', to: '/op/admin/organizations', labelKey: 'admin.orgs.title' },
  { key: 'sessions', to: '/op/admin/sessions', labelKey: 'admin.nav.sessions' },
  { key: 'clients', to: '/op/admin/clients', labelKey: 'admin.nav.clients' },
  { key: 'activity', to: '/op/admin/activity', labelKey: 'admin.nav.activity' },
  { key: 'providers', to: '/op/admin/providers', labelKey: 'admin.nav.providers' },
  { key: 'security', to: '/op/admin/security', labelKey: 'admin.nav.security' },
  { key: 'users', to: '/op/admin/users', labelKey: 'admin.nav.users' },
]

// The account console's sections (the one long page's anchors — every
// section carries its id in account.vue / AccountFactors.vue). The
// hrefs are HASH-ONLY, deliberately: the served page's canonical URL
// may carry a trailing slash (/op/account/), and a path-carrying href
// (/op/account#x) would then be a DIFFERENT document — every section
// click a full reload landing back at the top (the 2026-09-18
// production report: "they don't go anywhere except profile"). A
// hash-only href is same-document on either canonical form.
const ACCOUNT_ENTRIES: ReadonlyArray<NavEntry> = [
  { key: 'profile', to: '#profile', labelKey: 'account.profile.title' },
  { key: 'organizations', to: '#organizations', labelKey: 'account.organizations.title' },
  { key: 'methods', to: '#methods', labelKey: 'account.methods.title' },
  { key: 'factors', to: '#factors', labelKey: 'account.factors.title' },
  { key: 'password', to: '#password', labelKey: 'account.password.title' },
  { key: 'sessions', to: '#sessions', labelKey: 'account.sessions.title' },
  { key: 'activity', to: '#activity', labelKey: 'account.activity.title' },
]

// ── the session role gate (the console switch's admin entry + the
// admin sections' audience) ──────────────────────────────────────────
// The Administration area link renders only for the roles the admin
// API admits (op-home.ts's flag: admin | cs_admin) — the pages
// self-gate regardless; the rail never offers an act the server
// refuses.
interface SessionUser { id: string; email: string; name: string; role: string }
const user = ref<SessionUser | null>(null)
const isAdmin = computed(() => user.value?.role === 'admin' || user.value?.role === 'cs_admin')

// The current console's sections. The admin set keeps the pre-07 tab
// strip's audience: the WIDE grant only — the org-grant visitor (the
// org_admin role, whose queue is the users page; routes/op-join.ts's
// grant envelope) was never shown the strip (its sibling surfaces
// would 403, honestly but noisily), so the rail offers it the console
// switch alone. The gate is the same role computation as the switch's
// (the default RBAC map: admin | cs_admin hold users.manage, org_admin
// only org.users.manage).
// The admin rail's entries (TODO.restructure/17 — the kind-projected
// nav): the deployment's profile DECLARES its console-section set
// (profiles/*.yaml, a configuration act); undeclared = the full default
// set. The component never branches on the instance's kind — it filters
// by the projected set.
const { consoleSections } = useConsoleSections()
const adminEntries = computed<ReadonlyArray<NavEntry>>(() => {
  const declared = consoleSections.value
  return declared ? ADMIN_ENTRIES.filter(e => declared.includes(e.key)) : ADMIN_ENTRIES
})
const sections = computed<ReadonlyArray<NavEntry>>(() =>
  props.area === 'admin'
    ? (isAdmin.value ? adminEntries.value : [])
    : props.area === 'account' ? ACCOUNT_ENTRIES : [])

// ── the account console's scroll-spy (the one long page) ────────────
// The admin area's `current` is a static, per-page prop (separate
// pages); the account console is ONE long page whose sections live in
// the page's own island — the rail's highlight must FOLLOW: the hash
// on load and on section-link clicks, the scroll as the viewport
// crosses sections (the 2026-09-18 report: "the highlight doesn't
// follow"). The pick: the LAST section whose top has crossed the focus
// line just below the sticky header (the section whose heading sits at
// the top of the reading area); before any crossing, profile. A deep
// focus line (a viewport fraction) let a SHORT section's successor
// cross the line while the short section was still at the top — the
// highlight ran one entry ahead of the reader (the 2026-09-25 report:
// "the links don't navigate" — the entry clicked was the dead one).
// The header-anchored line keeps the highlight ON the clicked section.
const activeSection = ref('profile')
const currentKey = computed(() => (props.area === 'account' ? activeSection.value : props.current))

function pickActiveFromScroll(): void {
  // The last section can never reach the focus line (the page ends
  // first) — at the bottom of the document, the last section IS the
  // current one. GUARDED on the island's content existing: before the
  // page's own island renders, the document is short and the clamp
  // would falsely fire.
  if (document.getElementById('profile')
    && window.innerHeight + window.scrollY >= document.documentElement.scrollHeight - 2) {
    activeSection.value = ACCOUNT_ENTRIES[ACCOUNT_ENTRIES.length - 1].key
    return
  }
  // The shell header is h-12 (48 px); a small margin below it.
  const focusLine = 64
  let current = 'profile'
  for (const entry of ACCOUNT_ENTRIES) {
    const el = document.getElementById(entry.key)
    if (el && el.getBoundingClientRect().top <= focusLine) current = entry.key
  }
  activeSection.value = current
}

function pickActiveFromHash(): void {
  const key = window.location.hash.replace(/^#/, '')
  activeSection.value = ACCOUNT_ENTRIES.some(e => e.key === key) ? key : 'profile'
}

if (typeof window !== 'undefined') {
  onMounted(() => {
    if (props.area !== 'account') return
    pickActiveFromHash()
    pickActiveFromScroll()
    window.addEventListener('scroll', pickActiveFromScroll, { passive: true })
    window.addEventListener('hashchange', pickActiveFromHash)
  })
  onUnmounted(() => {
    window.removeEventListener('scroll', pickActiveFromScroll)
    window.removeEventListener('hashchange', pickActiveFromHash)
  })
}

/** The header's current-section label (the area's name). */
const areaLabel = computed(() =>
  props.area === 'admin' ? t('shell.nav.admin') : props.area === 'account' ? t('account.title') : t('home.title'))

/** The sections group's aria-label (the admin set kept its pre-07
 *  catalog key). */
const sectionsLabel = computed(() =>
  props.area === 'admin' ? t('admin.nav.label') : t('shell.nav.sections'))

// ── the disclosure (phone widths) ────────────────────────────────────
const open = ref(false)
function close() { open.value = false }
function onKeydown(e: KeyboardEvent) { if (e.key === 'Escape') close() }

onMounted(async () => {
  window.addEventListener('keydown', onKeydown)
  try {
    const res = await fetch('/api/auth/session', { credentials: 'include' })
    if (res.ok) user.value = (await res.json()) as SessionUser
  } catch { /* signed out or offline — the console switch hides */ }
})
onUnmounted(() => window.removeEventListener('keydown', onKeydown))
</script>

<template>
  <!-- The header's chrome: the disclosure toggle + the current section.
       Teleported into the shell header's slot so the ONE component owns
       the open state for both the header button and the sheet. -->
  <Teleport to="#shell-chrome-slot">
    <button
      type="button"
      class="lg:hidden shrink-0 w-8 h-8 flex items-center justify-center rounded border border-slate-200 dark:border-slate-700 text-slate-500 dark:text-slate-400 hover:border-brand-500 dark:hover:border-brand-400 transition-colors"
      data-testid="shell-nav-toggle"
      :aria-expanded="open"
      aria-controls="shell-console-nav"
      :aria-label="open ? t('shell.nav.close') : t('shell.nav.menu')"
      @click="open = !open"
    >
      <svg v-if="!open" class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><line x1="3" y1="6" x2="21" y2="6"/><line x1="3" y1="12" x2="21" y2="12"/><line x1="3" y1="18" x2="21" y2="18"/></svg>
      <svg v-else class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
    </button>
    <span class="hidden sm:block min-w-0 truncate text-sm text-slate-500 dark:text-slate-400" data-testid="shell-section">{{ areaLabel }}</span>
  </Teleport>

  <!-- The backdrop (phone, while the sheet is open). -->
  <div
    v-if="open"
    class="fixed inset-0 z-30 lg:hidden bg-slate-900/30 dark:bg-slate-950/60"
    aria-hidden="true"
    @click="close"
  />

  <!-- The ONE nav element: the left rail at lg+, the disclosure sheet
       below (CSS-only switch — one DOM node, one testid set, no
       duplication). Below lg it is a fixed overlay under the header;
       from lg it is the flex row's sticky rail. -->
  <aside
    id="shell-console-nav"
    :class="open ? 'block' : 'hidden'"
    class="lg:block fixed inset-x-0 top-12 z-40 max-h-[calc(100vh-3rem)] overflow-y-auto border-b border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 shadow-lg px-4 py-4 lg:static lg:z-auto lg:max-h-none lg:overflow-visible lg:border-0 lg:bg-transparent lg:dark:bg-transparent lg:shadow-none lg:p-0 lg:pt-10 lg:w-52 lg:shrink-0 lg:self-start lg:sticky lg:top-6"
  >
    <!-- The console switch: the movement between the three areas, one
         click from every console surface. The current area is not a
         link (the house idiom: aria-current on a span). -->
    <nav aria-label="OIML SMART Identity" data-testid="shell-areas">
      <p class="px-3 mb-1 text-[11px] font-semibold uppercase tracking-wider text-slate-400 dark:text-slate-500">{{ t('shell.nav.areas') }}</p>
      <ul class="space-y-0.5">
        <li>
          <span v-if="area === 'home'" class="block rounded-md px-3 py-1.5 text-sm font-semibold text-brand-700 dark:text-brand-200 bg-brand-50 dark:bg-brand-900/30" aria-current="page" data-testid="shell-nav-home">{{ t('home.title') }}</span>
          <a v-else href="/op/home" class="block rounded-md px-3 py-1.5 text-sm font-medium text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 hover:text-slate-900 dark:hover:text-white focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-500 transition-colors" data-testid="shell-nav-home" @click="close">{{ t('home.title') }}</a>
        </li>
        <li>
          <span v-if="area === 'account'" class="block rounded-md px-3 py-1.5 text-sm font-semibold text-brand-700 dark:text-brand-200 bg-brand-50 dark:bg-brand-900/30" aria-current="page" data-testid="shell-nav-account">{{ t('account.title') }}</span>
          <a v-else href="/op/account" class="block rounded-md px-3 py-1.5 text-sm font-medium text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 hover:text-slate-900 dark:hover:text-white focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-500 transition-colors" data-testid="shell-nav-account" @click="close">{{ t('account.title') }}</a>
        </li>
        <li v-if="isAdmin">
          <span v-if="area === 'admin'" class="block rounded-md px-3 py-1.5 text-sm font-semibold text-brand-700 dark:text-brand-200 bg-brand-50 dark:bg-brand-900/30" aria-current="page" data-testid="shell-nav-admin">{{ t('shell.nav.admin') }}</span>
          <a v-else href="/op/admin/overview" class="block rounded-md px-3 py-1.5 text-sm font-medium text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 hover:text-slate-900 dark:hover:text-white focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-500 transition-colors" data-testid="shell-nav-admin" @click="close">{{ t('shell.nav.admin') }}</a>
        </li>
      </ul>
    </nav>

    <!-- The current console's sections. -->
    <nav v-if="sections.length" class="mt-5 pt-5 border-t border-slate-200 dark:border-slate-700" :aria-label="sectionsLabel" :data-testid="area === 'admin' ? 'op-admin-nav' : 'op-account-nav'">
      <p class="px-3 mb-1 text-[11px] font-semibold uppercase tracking-wider text-slate-400 dark:text-slate-500">{{ t('shell.nav.sections') }}</p>
      <ul class="space-y-0.5">
        <li v-for="entry in sections" :key="entry.key">
          <!-- EVERY entry is an anchor — the current one carries
               aria-current instead of turning into a dead <span> (the
               2026-09-25 report: clicking the highlighted entry did
               nothing, which read as "the links don't navigate"). A
               re-click on the current section re-aligns it at the top;
               assistive tech still gets the current-page marker. -->
          <a
            :href="entry.to"
            :aria-current="entry.key === currentKey ? 'page' : undefined"
            :class="entry.key === currentKey
              ? 'block rounded-md px-3 py-1.5 text-sm font-semibold text-brand-700 dark:text-brand-200 bg-brand-50 dark:bg-brand-900/30'
              : 'block rounded-md px-3 py-1.5 text-sm font-medium text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 hover:text-slate-900 dark:hover:text-white focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-500 transition-colors'"
            :data-testid="`${area === 'admin' ? 'op-admin-nav' : 'op-account-nav'}-${entry.key}`"
            @click="close"
          >{{ t(entry.labelKey) }}</a>
        </li>
      </ul>
    </nav>
  </aside>
</template>
