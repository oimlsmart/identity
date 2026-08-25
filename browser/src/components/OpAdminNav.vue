<script setup lang="ts">
// ─────────────────────────────────────────────────────────────────────
// The admin console's tab bar (TODO.identity/07) — the ONE navigation
// across every administration surface, rendered directly under the
// page header. The house idiom is the underline tab strip: the current
// surface carries the brand underline + aria-current and is not a link;
// the rest are plain router links with honest hover/focus states. The
// strip scrolls horizontally at narrow widths — it never wraps onto a
// second line and never overflows the viewport. The labels ride the
// admin.nav.* catalog keys (EN/FR lockstep).
// ─────────────────────────────────────────────────────────────────────
import { t, type MessageKey } from '../i18n'

type AdminSurface = 'overview' | 'registry' | 'organizations' | 'sessions' | 'clients' | 'activity' | 'providers' | 'security' | 'users'

defineProps<{ current: AdminSurface }>()

const entries: ReadonlyArray<{ key: AdminSurface; to: string; labelKey: MessageKey }> = [
  { key: 'overview', to: '/op/admin/overview', labelKey: 'admin.nav.overview' },
  { key: 'registry', to: '/op/admin/registry', labelKey: 'admin.nav.registry' },
  // TODO.identity-features/05 — the organization registry's own surface.
  { key: 'organizations', to: '/op/admin/organizations', labelKey: 'admin.orgs.title' },
  { key: 'sessions', to: '/op/admin/sessions', labelKey: 'admin.nav.sessions' },
  { key: 'clients', to: '/op/admin/clients', labelKey: 'admin.nav.clients' },
  { key: 'activity', to: '/op/admin/activity', labelKey: 'admin.nav.activity' },
  { key: 'providers', to: '/op/admin/providers', labelKey: 'admin.nav.providers' },
  { key: 'security', to: '/op/admin/security', labelKey: 'admin.nav.security' },
  { key: 'users', to: '/op/admin/users', labelKey: 'admin.nav.users' },
]
</script>

<template>
  <nav class="mb-6 border-b border-slate-200 dark:border-slate-700" data-testid="op-admin-nav" :aria-label="t('admin.nav.label')">
    <ul class="flex gap-x-1 overflow-x-auto">
      <li v-for="entry in entries" :key="entry.key" class="shrink-0 -mb-px">
        <span
          v-if="entry.key === current"
          class="inline-flex items-center whitespace-nowrap px-3 py-2 border-b-2 border-brand-600 dark:border-brand-400 text-sm font-semibold text-brand-700 dark:text-brand-200"
          aria-current="page"
          :data-testid="`op-admin-nav-${entry.key}`"
        >{{ t(entry.labelKey) }}</span>
        <router-link
          v-else
          :to="entry.to"
          class="inline-flex items-center whitespace-nowrap px-3 py-2 border-b-2 border-transparent text-sm font-medium text-slate-500 dark:text-slate-400 rounded-t-md transition-colors hover:text-slate-900 dark:hover:text-white hover:border-slate-300 dark:hover:border-slate-500 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-500"
          :data-testid="`op-admin-nav-${entry.key}`"
        >{{ t(entry.labelKey) }}</router-link>
      </li>
    </ul>
  </nav>
</template>
