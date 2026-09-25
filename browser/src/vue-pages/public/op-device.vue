<script setup lang="ts">
// ═══════════════════════════════════════════════════════════════════
// The device authorization grant's approval page (TODO.ai-platform/10 —
// RFC 8628): the holder lands here from the terminal's verification
// URI (the code rides ?code= or is typed), reads the ask honestly —
// WHICH client, WHAT it may do (the services + the action classes) —
// and approves or refuses. The decision POSTs back; the terminal's
// poll picks it up. Nothing more, nothing hidden.
//
// The page rides the JSON API (GET /api/op/device, POST
// /api/op/device/decide): a missing session bounces to the sign-in
// with the page's re-entry; an approve the account's standing cannot
// hold shows the refusal verbatim (the ceremony stays pending — the
// holder may switch accounts and retry while the code lives).
// ═══════════════════════════════════════════════════════════════════
import { ref, onMounted } from 'vue'
import { useRoute } from 'vue-router'
import BrandLogo from '../../components/BrandLogo.vue'
import { t } from '../../i18n'

interface DeviceContext {
  client: { id: string; name: string }
  /** The ask, named honestly: each service's display name + the action
   *  class (read | write | admin — the PAT grammar's ordinal). */
  scopes: Array<{ service: string; name: string; action: 'read' | 'write' | 'admin' }>
  account: { name: string; email: string; avatarUrl?: string | null }
  expiresAt: string
  issuer: string
  issuerName: string
}

type Stage = 'enter' | 'loading' | 'context' | 'approved' | 'denied'

const route = useRoute()

const stage = ref<Stage>('enter')
const deciding = ref(false)
const error = ref<string | null>(null)
const standingError = ref<string | null>(null)
const context = ref<DeviceContext | null>(null)
const code = ref('')

/** The "switch account" target (the consent page's pattern): the
 *  chooser carrying this page (code and all) as its continue target. */
const switchAccountUrl = (): string =>
  `/op/choose-account?continue=${encodeURIComponent(`/op/device?code=${code.value}`)}`

const ACTION_LABELS: Record<string, string> = {
  read: t('device.action.read'),
  write: t('device.action.write'),
  admin: t('device.action.admin'),
}

async function load() {
  stage.value = 'loading'
  error.value = null
  standingError.value = null
  try {
    const res = await fetch(`/api/op/device?user_code=${encodeURIComponent(code.value)}`, { credentials: 'include' })
    if (res.status === 401) {
      const body = await res.json().catch(() => null) as { login?: string } | null
      window.location.assign(body?.login ?? '/')
      return
    }
    if (!res.ok) {
      const body = await res.json().catch(() => null) as { error?: string } | null
      error.value = body?.error === 'unknown_code' ? t('device.unknownCode')
        : body?.error === 'expired' ? t('device.expired')
          : body?.error === 'decided' ? t('device.decided')
            : body?.error === 'invalid_request' ? t('device.badCode')
              : t('error.network')
      stage.value = 'enter'
      return
    }
    context.value = await res.json() as DeviceContext
    stage.value = 'context'
  } catch {
    error.value = t('error.network')
    stage.value = 'enter'
  }
}

async function decide(decision: 'approve' | 'deny') {
  if (!context.value || deciding.value) return
  deciding.value = true
  standingError.value = null
  try {
    const res = await fetch('/api/op/device/decide', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ user_code: code.value, decision }),
    })
    if (res.status === 401) {
      const body = await res.json().catch(() => null) as { login?: string } | null
      window.location.assign(body?.login ?? '/')
      return
    }
    if (res.status === 403) {
      // The account's standing cannot hold the ask — shown verbatim
      // (the ceremony stays pending: switch account and retry).
      const body = await res.json().catch(() => null) as { error_description?: string } | null
      standingError.value = body?.error_description ?? t('device.noStanding', { reason: '' })
      deciding.value = false
      return
    }
    if (!res.ok) {
      const body = await res.json().catch(() => null) as { error?: string } | null
      error.value = body?.error === 'decided' ? t('device.decided') : t('device.decideFailed')
      stage.value = 'enter'
      return
    }
    stage.value = decision === 'approve' ? 'approved' : 'denied'
  } catch {
    error.value = t('error.network')
    deciding.value = false
  }
}

onMounted(() => {
  const prefill = typeof route.query.code === 'string' ? route.query.code.trim() : ''
  if (prefill) {
    code.value = prefill
    void load()
  }
})
</script>

<template>
  <div class="min-h-screen flex items-center justify-center px-4 py-12 bg-cream dark:bg-slate-900">
    <!-- Loading state -->
    <div v-if="stage === 'loading'" class="flex flex-col items-center gap-4">
      <div class="w-8 h-8 border-2 border-brand-300 border-t-brand-600 rounded-full animate-spin" />
    </div>

    <div v-else class="w-full max-w-md" data-testid="op-device">
      <div class="text-center mb-8">
        <BrandLogo kind="logo" class="h-10 mx-auto mb-4" />
        <h1 class="text-xl font-serif font-bold text-slate-900 dark:text-white">
          {{ context ? context.issuerName : t('device.title') }}
        </h1>
      </div>

      <!-- Error (the code lookup + the decision transport) -->
      <div v-if="error" class="mb-4 p-3 rounded-lg bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800">
        <p class="text-sm text-red-700 dark:text-red-300" data-testid="op-device-error">{{ error }}</p>
      </div>

      <!-- The code entry -->
      <template v-if="stage === 'enter'">
        <form
          class="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 p-5 mb-6"
          data-testid="op-device-entry"
          @submit.prevent="load"
        >
          <label for="op-device-code" class="block text-sm text-slate-700 dark:text-slate-200 mb-2">
            {{ t('device.codePrompt') }}
          </label>
          <input
            id="op-device-code"
            v-model="code"
            data-testid="op-device-code"
            type="text"
            autocomplete="off"
            autocapitalize="characters"
            spellcheck="false"
            :placeholder="t('device.codePlaceholder')"
            class="w-full mb-4 px-3 py-2.5 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 text-slate-900 dark:text-white font-mono tracking-widest text-center text-lg uppercase"
          >
          <button
            type="submit"
            data-testid="op-device-lookup"
            :disabled="!code.trim()"
            class="w-full min-h-11 py-2.5 rounded-lg text-sm font-medium bg-brand-600 text-white hover:bg-brand-700 transition-colors disabled:opacity-50"
          >
            {{ t('device.codeSubmit') }}
          </button>
        </form>
      </template>

      <!-- The ask -->
      <template v-if="stage === 'context' && context">
        <div class="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 p-5 mb-6">
          <p class="text-sm text-slate-700 dark:text-slate-200 mb-4" data-testid="op-device-lead">
            <span class="font-semibold" data-testid="op-device-client">{{ context.client.name }}</span>
            {{ t('device.lead', { issuer: context.issuerName }) }}
          </p>

          <h2 class="text-xs font-semibold uppercase tracking-wider text-slate-400 dark:text-slate-500 mb-2">{{ t('device.asksFor') }}</h2>
          <ul class="mb-4 space-y-1" data-testid="op-device-scopes">
            <li
              v-for="scope in context.scopes"
              :key="scope.service"
              class="flex items-center gap-2 text-sm text-slate-700 dark:text-slate-300"
            >
              <svg class="w-3.5 h-3.5 text-brand-600 dark:text-brand-300 shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
              <span class="font-medium">{{ scope.name }}</span>
              <span class="text-slate-400 dark:text-slate-500">— {{ ACTION_LABELS[scope.action] ?? scope.action }}</span>
            </li>
          </ul>

          <h2 class="text-xs font-semibold uppercase tracking-wider text-slate-400 dark:text-slate-500 mb-2">{{ t('consent.signedInAs') }}</h2>
          <p class="flex items-center gap-2 text-sm text-slate-700 dark:text-slate-300" data-testid="op-device-account">
            <img
              v-if="context.account.avatarUrl"
              :src="context.account.avatarUrl"
              :alt="context.account.name"
              class="w-6 h-6 rounded-full object-cover border border-slate-200 dark:border-slate-700"
              data-testid="op-device-avatar"
            >
            <span class="font-medium">{{ context.account.name }}</span>
            <span class="text-slate-400 dark:text-slate-500"> &lt;{{ context.account.email }}&gt;</span>
          </p>
          <p class="mt-2 text-right">
            <a
              :href="switchAccountUrl()"
              data-testid="op-device-switch-account"
              class="text-sm text-brand-600 dark:text-brand-300 hover:underline"
            >{{ t('consent.switchAccount') }}</a>
          </p>

          <!-- The standing refusal (the approve the account cannot hold —
               the ceremony stays pending: switch account and retry). -->
          <div v-if="standingError" class="mt-4 p-3 rounded-lg bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800">
            <p class="text-sm text-amber-800 dark:text-amber-300" data-testid="op-device-standing">{{ standingError }}</p>
          </div>
        </div>

        <div class="flex gap-3">
          <button
            data-testid="op-device-approve"
            :disabled="deciding"
            class="flex-1 min-h-11 py-2.5 rounded-lg text-sm font-medium bg-brand-600 text-white hover:bg-brand-700 transition-colors disabled:opacity-50 flex items-center justify-center gap-2"
            @click="decide('approve')"
          >
            <div v-if="deciding" class="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
            {{ t('device.approve') }}
          </button>
          <button
            data-testid="op-device-deny"
            :disabled="deciding"
            class="flex-1 min-h-11 py-2.5 rounded-lg text-sm font-medium border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-900 dark:text-white hover:bg-slate-50 dark:hover:bg-slate-700 transition-colors disabled:opacity-50"
            @click="decide('deny')"
          >
            {{ t('consent.deny') }}
          </button>
        </div>

        <p class="mt-4 text-center text-[10px] text-slate-400 dark:text-slate-500">
          {{ t('device.tokenNote') }}
        </p>
      </template>

      <!-- The decision landed -->
      <template v-if="stage === 'approved' || stage === 'denied'">
        <div class="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 p-5 mb-6 text-center">
          <p class="text-sm text-slate-700 dark:text-slate-200" :data-testid="stage === 'approved' ? 'op-device-approved' : 'op-device-denied'">
            {{ stage === 'approved' ? t('device.approved') : t('device.denied') }}
          </p>
        </div>
      </template>
    </div>
  </div>
</template>
