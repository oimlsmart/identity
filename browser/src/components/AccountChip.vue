<script setup lang="ts">
// ═══════════════════════════════════════════════════════════════════
// AccountChip — the identity shell's signed-in account surface: the
// avatar (the OP's upload serving route, or the linked provider's
// picture; the initial stands in), the account-console link, sign out.
// Rendered as the slim account bar under the federation header (the
// site shell's SiteHeader takes no slot — the OP's account context is
// its own row). Signed out, nothing renders: the site header's Sign-in
// link carries that posture.
// ═══════════════════════════════════════════════════════════════════
import { computed, onMounted, ref } from 'vue'

interface SessionUser {
  id: string
  email: string
  name: string
  avatarUrl?: string
}

const user = ref<SessionUser | null>(null)
const initial = computed(() => (user.value?.name ?? '?').charAt(0).toUpperCase())

onMounted(async () => {
  try {
    const res = await fetch('/api/auth/session', { credentials: 'include' })
    if (res.ok) user.value = (await res.json()) as SessionUser
  } catch { /* signed out or offline — the chip stays empty */ }
})

async function signOut() {
  try { await fetch('/api/auth/signout', { method: 'POST', credentials: 'include' }) } catch { /* the navigation reloads the posture anyway */ }
  window.location.assign('/app/login')
}
</script>

<template>
  <div v-if="user" class="border-b border-rule bg-paper-soft dark:bg-paper-deep" data-testid="account-bar">
    <div class="max-w-7xl mx-auto px-6 h-9 flex items-center justify-end gap-2 text-xs">
      <img v-if="user.avatarUrl" :src="user.avatarUrl" :alt="user.name" class="w-5 h-5 rounded-full object-cover" data-testid="header-avatar" />
      <div v-else class="w-5 h-5 rounded-full bg-brand-100 dark:bg-brand-800 flex items-center justify-center text-[9px] font-bold text-brand-600 dark:text-brand-300" data-testid="header-avatar-initial">{{ initial }}</div>
      <a href="/app/account" class="font-medium text-ink-soft hover:text-accent transition-colors" data-testid="header-account-link">{{ user.name }}</a>
      <span class="text-slate-300 dark:text-slate-600" aria-hidden="true">·</span>
      <button type="button" class="text-ink-soft hover:text-accent transition-colors" data-testid="header-signout" @click="signOut">Sign out</button>
    </div>
  </div>
</template>
