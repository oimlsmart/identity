<script setup lang="ts">
// ═══════════════════════════════════════════════════════════════════
// AccountChip — the shell header's signed-in account surface (inline at
// the header bar's right end): the avatar (the OP's upload serving
// route, or the linked provider's picture; the initial stands in), the
// account-console link, sign out. Signed out, nothing renders (the
// sign-in page is /).
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
  window.location.assign('/')
}
</script>

<template>
  <span v-if="user" class="flex items-center gap-2 text-xs" data-testid="account-chip">
    <img v-if="user.avatarUrl" :src="user.avatarUrl" :alt="user.name" class="w-5 h-5 rounded-full object-cover" data-testid="header-avatar" />
    <span v-else class="w-5 h-5 rounded-full bg-brand-100 dark:bg-brand-800 flex items-center justify-center text-[9px] font-bold text-brand-600 dark:text-brand-300" data-testid="header-avatar-initial">{{ initial }}</span>
    <a href="/op/account" class="font-medium text-slate-600 dark:text-slate-300 hover:text-brand-600 dark:hover:text-brand-300 transition-colors" data-testid="header-account-link">{{ user.name }}</a>
    <span class="text-slate-300 dark:text-slate-600" aria-hidden="true">·</span>
    <button type="button" class="text-slate-500 dark:text-slate-400 hover:text-brand-600 dark:hover:text-brand-300 transition-colors" data-testid="header-signout" @click="signOut">Sign out</button>
  </span>
</template>
