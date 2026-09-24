<script setup lang="ts">
// ═══════════════════════════════════════════════════════════════════
// The account chooser island (the multi-account wave) — the Google-style
// "choose an account" card: the account jar's remembered accounts (each
// re-verified against its live session row by the context endpoint),
// one row per account, plus "use another account" (the normal login
// form, returning to the same continue target).
//
// A LIVE account: POST /api/op/choose-account swaps the active session
// cookie to the remembered token and the page navigates to the answer's
// target — the original authorize request (prompt=select_account's
// `continue`) or the account console (the standalone posture). A DEAD
// account: the same POST answers the login URL with the remembered
// email prefilled — the session row is gone, so the account must
// re-prove itself.
//
// The flow's login_hint pre-selects: the context endpoint marks the
// entry whose address matches, the page outlines it and scrolls it into
// view — the pre-selection is an affordance, never a decision (the
// holder still clicks). A hint nothing matches rides "use another
// account" as the sign-in form's prefill.
//
// The GRANTED PERSONA ROWS (the demo cast's assumption): when the
// context marks a row `assumable`, it is a declared demonstration
// persona the presenting account may assume — the click assumes it
// WITHOUT any persona password (the grant-based posture; the server
// re-verdicts the grant and journals the assumption).
// ═══════════════════════════════════════════════════════════════════
import { ref, onMounted, nextTick } from 'vue'
import { useRoute } from 'vue-router'
import BrandLogo from '../../components/BrandLogo.vue'
import { t } from '../../i18n'

interface ChooserAccount {
  userId: string | null
  name: string
  email: string
  avatarUrl: string | null
  org: string | null
  live: boolean
  current: boolean
  hinted: boolean
  /** A DECLARED demo persona the presenting account is granted to
   *  assume: the click assumes the persona — no persona password is
   *  ever presented (the grant-based posture; the server re-verdicts). */
  assumable: boolean
}

interface ChooserContext {
  continue: string | null
  loginHint: string | null
  client: { name: string } | null
  currentUserId: string | null
  accounts: ChooserAccount[]
}

const route = useRoute()

const loading = ref(true)
const busyKey = ref<string | null>(null)
const anotherBusy = ref(false)
const error = ref<string | null>(null)
const context = ref<ChooserContext | null>(null)

const rowKeyOf = (account: ChooserAccount): string => account.userId ?? `email:${account.email}`

const initialOf = (account: ChooserAccount): string => (account.name || account.email || '?').charAt(0).toUpperCase()

/** The "use another account" landing: the normal login form, which
 *  returns to the same continue target (or the account console when
 *  the chooser stands alone). The flow's login_hint rides along when
 *  the context carried one — the form prefills it. */
function loginUrl(): string {
  const target = context.value?.continue ?? '/op/account'
  const hint = context.value?.loginHint
  const suffix = hint ? `&login_hint=${encodeURIComponent(hint)}` : ''
  return `/?redirect=${encodeURIComponent(target)}${suffix}`
}

onMounted(async () => {
  // The context read carries the flow's own parameters: the continue
  // target (the authorize re-entry) and the login_hint (the
  // pre-selection marker).
  const params = new URLSearchParams()
  if (typeof route.query.continue === 'string' && route.query.continue) params.set('continue', route.query.continue)
  if (typeof route.query.login_hint === 'string' && route.query.login_hint) params.set('login_hint', route.query.login_hint)
  const query = params.toString()
  try {
    const res = await fetch(`/api/op/choose-account${query ? `?${query}` : ''}`, { credentials: 'include' })
    if (res.ok) {
      context.value = await res.json() as ChooserContext
      // The hinted entry earns the first glance: scrolled into view
      // after the list renders (a long remembered list must not hide
      // the pre-selection below the fold).
      await nextTick()
      document.querySelector('[data-testid="chooser-hinted-badge"]')?.scrollIntoView({ block: 'center' })
    }
    else error.value = t('chooser.failed')
  } catch {
    error.value = t('error.network')
  }
  loading.value = false
})

/** Continue as a remembered account — or assume a granted demo
 *  persona. The server re-verifies every choice (the render-to-click
 *  gap is the server's verdict, never the page's): ok swaps the cookie
 *  and answers the navigation target; not-ok answers the login fallback
 *  (dead row — sign in again); a refused assumption (403) says so. */
async function choose(account: ChooserAccount) {
  const rowKey = rowKeyOf(account)
  if (busyKey.value) return
  busyKey.value = rowKey
  error.value = null
  try {
    const res = await fetch('/api/op/choose-account', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify(
        account.assumable
          ? { email: account.email, continue: context.value?.continue ?? undefined }
          : { userId: account.userId, continue: context.value?.continue ?? undefined },
      ),
    })
    if (res.status === 403) {
      error.value = t('chooser.assumptionDenied')
      busyKey.value = null
      return
    }
    if (!res.ok) {
      error.value = t('chooser.failed')
      busyKey.value = null
      return
    }
    const body = await res.json() as { ok: boolean; redirect?: string; login?: string }
    if (body.ok && body.redirect) window.location.assign(body.redirect)
    else if (body.login) window.location.assign(body.login)
    else window.location.assign(loginUrl())
  } catch {
    error.value = t('error.network')
    busyKey.value = null
  }
}

/** The fresh-sign-in entry (the form renders the jar untouched; the
 *  sign-in's own jar touch refreshes the remembered set). */
function useAnother() {
  if (anotherBusy.value) return
  anotherBusy.value = true
  window.location.assign(loginUrl())
}
</script>

<template>
  <div class="min-h-screen flex items-center justify-center px-4 py-12 bg-cream dark:bg-slate-900">
    <!-- Loading state -->
    <div v-if="loading" class="flex flex-col items-center gap-4">
      <div class="w-8 h-8 border-2 border-brand-300 border-t-brand-600 rounded-full animate-spin" />
    </div>

    <!-- The chooser card -->
    <div v-else class="w-full max-w-sm" data-testid="op-choose-account">
      <div class="text-center mb-8">
        <BrandLogo kind="logo" class="h-10 mx-auto mb-4" />
        <h1 class="text-xl font-serif font-bold text-slate-900 dark:text-white" data-testid="chooser-heading">{{ t('chooser.heading') }}</h1>
        <p class="mt-2 text-sm text-slate-600 dark:text-slate-400" data-testid="chooser-subtitle">
          <template v-if="context?.client">{{ t('chooser.subtitle', { client: context.client.name }) }}</template>
          <template v-else>{{ t('chooser.subtitleGeneric') }}</template>
        </p>
      </div>

      <!-- Error -->
      <div v-if="error" class="mb-4 p-3 rounded-lg bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800">
        <p class="text-sm text-red-700 dark:text-red-300" data-testid="chooser-error">{{ error }}</p>
      </div>

      <ul class="space-y-2">
        <li v-for="account in context?.accounts ?? []" :key="rowKeyOf(account)">
          <button
            type="button"
            :disabled="!!busyKey"
            :data-testid="`chooser-account-${account.email}`"
            :data-hinted="account.hinted ? 'true' : undefined"
            :data-assumable="account.assumable ? 'true' : undefined"
            :aria-label="t('chooser.continueAs', { name: account.name || account.email })"
            :class="account.hinted
              ? 'w-full text-left px-4 py-3 rounded-xl border-2 border-brand-500 dark:border-brand-400 bg-brand-50/60 dark:bg-brand-900/20 hover:bg-brand-50 dark:hover:bg-brand-900/30 transition-colors cursor-pointer disabled:cursor-not-allowed disabled:opacity-50 flex items-center gap-3'
              : 'w-full text-left px-4 py-3 rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 hover:bg-slate-50 dark:hover:bg-slate-700 transition-colors cursor-pointer disabled:cursor-not-allowed disabled:opacity-50 flex items-center gap-3'"
            @click="choose(account)"
          >
            <img
              v-if="account.avatarUrl"
              :src="account.avatarUrl"
              :alt="account.name"
              class="w-10 h-10 shrink-0 rounded-full object-cover border border-slate-200 dark:border-slate-700"
              data-testid="chooser-avatar"
            />
            <span
              v-else
              class="w-10 h-10 shrink-0 rounded-full bg-brand-100 dark:bg-brand-800 flex items-center justify-center text-base font-bold text-brand-600 dark:text-brand-300"
              data-testid="chooser-avatar-initial"
            >{{ initialOf(account) }}</span>
            <span class="min-w-0 flex-1">
              <span class="block text-sm font-medium text-slate-900 dark:text-white truncate">
                {{ account.name || account.email }}
                <span
                  v-if="account.current"
                  class="ml-2 inline-block rounded-full bg-brand-50 dark:bg-brand-900/40 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider text-brand-600 dark:text-brand-300"
                  data-testid="chooser-current-badge"
                >{{ t('chooser.currentAccount') }}</span>
                <span
                  v-if="account.hinted"
                  class="ml-2 inline-block rounded-full bg-brand-100 dark:bg-brand-800/60 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider text-brand-700 dark:text-brand-200"
                  data-testid="chooser-hinted-badge"
                >{{ t('chooser.preselected') }}</span>
                <span
                  v-if="account.assumable"
                  class="ml-2 inline-block rounded-full bg-amber-50 dark:bg-amber-900/40 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider text-amber-700 dark:text-amber-300"
                  data-testid="chooser-persona-badge"
                >{{ t('chooser.personaBadge') }}</span>
              </span>
              <span class="block text-sm text-slate-600 dark:text-slate-400 truncate" data-testid="chooser-account-email">{{ account.email }}</span>
              <span v-if="account.org" class="block text-xs text-slate-400 dark:text-slate-500 truncate" data-testid="chooser-account-org">{{ account.org }}</span>
              <span v-if="account.assumable" class="block text-xs text-slate-400 dark:text-slate-500" data-testid="chooser-persona-note">{{ t('chooser.personaNote') }}</span>
              <span v-if="!account.live" class="block text-xs text-amber-600 dark:text-amber-400" data-testid="chooser-account-dead">{{ t('chooser.deadSession') }}</span>
            </span>
            <span v-if="busyKey === rowKeyOf(account)" class="w-4 h-4 shrink-0 border-2 border-brand-300 border-t-brand-600 rounded-full animate-spin" aria-hidden="true" />
          </button>
        </li>

        <!-- The fresh sign-in entry: the normal login form, returning to
             the same continue target. -->
        <li>
          <button
            type="button"
            :disabled="anotherBusy"
            data-testid="chooser-use-another"
            @click="useAnother"
            class="w-full text-left px-4 py-3 rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 hover:bg-slate-50 dark:hover:bg-slate-700 transition-colors cursor-pointer disabled:cursor-not-allowed disabled:opacity-50 flex items-center gap-3"
          >
            <span class="w-10 h-10 shrink-0 rounded-full border border-dashed border-slate-300 dark:border-slate-600 flex items-center justify-center text-slate-400 dark:text-slate-500" aria-hidden="true">
              <svg class="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4"/><polyline points="10 17 15 12 10 7"/><line x1="15" y1="12" x2="3" y2="12"/></svg>
            </span>
            <span class="text-sm font-medium text-slate-900 dark:text-white">{{ anotherBusy ? t('chooser.busy') : t('chooser.useAnother') }}</span>
          </button>
        </li>
      </ul>
    </div>
  </div>
</template>
