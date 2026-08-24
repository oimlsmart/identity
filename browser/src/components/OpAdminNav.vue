<script setup lang="ts">
// ─────────────────────────────────────────────────────────────────────
// The identity administration surfaces' shared sub-nav (TODO.identity/07)
// — the deep links between the registry console, the per-audience admin
// pages, and the provider registry. Rendered at the top of each surface;
// the current one is marked and not clickable.
// ─────────────────────────────────────────────────────────────────────
defineProps<{ current: 'overview' | 'registry' | 'sessions' | 'clients' | 'activity' | 'providers' | 'security' | 'users' }>()

const entries = [
  { key: 'overview', to: '/op/admin/overview', label: 'Overview' },
  { key: 'registry', to: '/op/admin/registry', label: 'Identity registry' },
  { key: 'sessions', to: '/op/admin/sessions', label: 'Live sessions' },
  { key: 'clients', to: '/op/admin/clients', label: 'Relying parties' },
  { key: 'activity', to: '/op/admin/activity', label: 'Activity' },
  { key: 'providers', to: '/op/admin/providers', label: 'Sign-in providers' },
  { key: 'security', to: '/op/admin/security', label: 'Security' },
  { key: 'users', to: '/op/admin/users', label: 'Organization administration' },
] as const
</script>

<template>
  <nav class="flex flex-wrap justify-center gap-x-4 gap-y-1 text-xs" data-testid="op-admin-nav" aria-label="Identity administration surfaces">
    <template v-for="entry in entries" :key="entry.key">
      <span
        v-if="entry.key === current"
        class="font-semibold text-slate-900 dark:text-white"
        :data-testid="`op-admin-nav-${entry.key}`"
      >{{ entry.label }}</span>
      <router-link
        v-else
        :to="entry.to"
        class="text-brand-600 dark:text-brand-300 hover:underline"
        :data-testid="`op-admin-nav-${entry.key}`"
      >{{ entry.label }}</router-link>
    </template>
  </nav>
</template>
