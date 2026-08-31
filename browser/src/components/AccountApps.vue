<script lang="ts">
// ═══════════════════════════════════════════════════════════════════
// The remembered consent grants' console API payload (GET
// /api/op/account/grants) — the AccountApps component's prop type,
// exported so the account page's loader types its fetch with the same
// shape (never a drift).
// ═══════════════════════════════════════════════════════════════════
export interface GrantRow {
  id: string
  clientId: string
  clientName: string
  scopes: string[]
  createdAt: string
}
export interface GrantsPayload {
  grants: GrantRow[]
}
</script>

<script setup lang="ts">
// ═══════════════════════════════════════════════════════════════════
// The account console's APPS section (TODO.identity-features/12): the
// services this account allowed in — the remembered consent grants.
// Each row names the client, the scope set it may keep asking for
// without re-asking, and the "Revoke access" act: the grant's live row
// flips, and the next sign-in to that client shows the consent page
// again (the OIDC-correct round trip).
// ═══════════════════════════════════════════════════════════════════
import { ref } from 'vue'
import { t } from '../i18n'

defineProps<{
  /** The grants read (GET /api/op/account/grants), loaded by the parent. */
  grants: GrantsPayload | null
}>()

const emit = defineEmits<{ changed: [] }>()

const error = ref<string | null>(null)
const notice = ref<string | null>(null)
const busy = ref(false)

function fmtDate(iso: string): string {
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })
}

async function revoke(grant: GrantRow) {
  if (busy.value) return
  busy.value = true
  error.value = null
  notice.value = null
  try {
    const res = await fetch(`/api/op/account/grants/${encodeURIComponent(grant.id)}`, {
      method: 'DELETE',
      credentials: 'include',
    })
    if (!res.ok) {
      const body = await res.json().catch(() => null) as { error?: string } | null
      error.value = body?.error ?? t('account.networkError')
      busy.value = false
      return
    }
    notice.value = t('account.apps.revoked')
    emit('changed')
    busy.value = false
  } catch {
    error.value = t('account.networkError')
    busy.value = false
  }
}
</script>

<template>
  <section id="apps" class="bg-white dark:bg-slate-800 rounded-xl border border-slate-200/80 dark:border-slate-700 p-6 mb-6" data-testid="account-apps">
    <h2 class="text-sm font-semibold text-slate-900 dark:text-white mb-1">{{ t('account.apps.title') }}</h2>
    <p class="text-xs text-slate-500 dark:text-slate-400 mb-4">{{ t('account.apps.description') }}</p>

    <p v-if="error" class="mb-3 text-sm text-red-700 dark:text-red-300" data-testid="apps-error">{{ error }}</p>
    <p v-if="notice" class="mb-3 text-sm text-green-700 dark:text-green-300" data-testid="apps-notice">{{ notice }}</p>

    <ul v-if="grants?.grants.length" class="space-y-2" data-testid="apps-list">
      <li
        v-for="grant in grants.grants"
        :key="grant.id"
        class="flex items-start justify-between gap-3 rounded-lg border border-slate-100 dark:border-slate-700/60 px-3 py-2"
        :data-testid="`app-${grant.id}`"
      >
        <div class="min-w-0">
          <p class="text-sm font-medium text-slate-900 dark:text-white break-words" :data-testid="`app-${grant.id}-name`">
            {{ grant.clientName }}
          </p>
          <p class="text-xs text-slate-500 dark:text-slate-400 font-mono break-all" :data-testid="`app-${grant.id}-scopes`">{{ grant.scopes.join('  ') }}</p>
          <p class="text-[11px] text-slate-400 dark:text-slate-500" :data-testid="`app-${grant.id}-stamps`">
            {{ t('account.apps.granted', { date: fmtDate(grant.createdAt) }) }}
          </p>
        </div>
        <button
          type="button"
          :disabled="busy"
          class="shrink-0 text-xs text-red-600 dark:text-red-400 hover:underline disabled:opacity-50"
          :data-testid="`app-${grant.id}-revoke`"
          @click="revoke(grant)"
        >{{ t('account.apps.revoke') }}</button>
      </li>
    </ul>
    <p v-else class="text-sm text-slate-500 dark:text-slate-400" data-testid="apps-empty">{{ t('account.apps.empty') }}</p>
  </section>
</template>
