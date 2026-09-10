<script setup lang="ts">
// ═══════════════════════════════════════════════════════════════════
// The OP's account setup page (TODO.identity/02) — the invite-only
// enrollment's landing: the one-time setup link (?token=…) resolves to
// the account it belongs to (name + email, nothing more), the user sets
// their password here, and the link is consumed ATOMICALLY at submit —
// one-time means one-time, and an expired link (24 h) is burned on use.
//
// The password field carries the honest strength meter (the policy's
// only REFUSAL is length ≥ 12; the meter advises, never invents rules).
// A successful setup signs the account in and lands on /op/account.
// ═══════════════════════════════════════════════════════════════════
import { computed, ref, onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import BrandLogo from '../../components/BrandLogo.vue'
import { t } from '../../i18n'

interface SetupContext {
  name: string
  email: string
  expiresAt: string
}

const route = useRoute()
const router = useRouter()

const loading = ref(true)
/** The link's failure class: 'unknown' | 'used' | 'expired' — each with
 *  its plain-language card (the API's error_description). */
const failure = ref<{ kind: string; message: string } | null>(null)
const context = ref<SetupContext | null>(null)

const password = ref('')
const confirm = ref('')
const submitting = ref(false)
const error = ref<string | null>(null)

// The meter mirrors server/auth/passwords.ts's classes — DISPLAY only
// (the server re-judges the policy at submit; a drift here can only ever
// under-advise, never admit a weaker password).
const strength = computed(() => {
  const pw = password.value
  const len = pw.length
  let variety = 0
  if (/[a-z]/.test(pw)) variety++
  if (/[A-Z]/.test(pw)) variety++
  if (/[0-9]/.test(pw)) variety++
  if (/[^a-zA-Z0-9]/.test(pw)) variety++
  if (len < 12) return { score: 0, label: 'Too short', hint: `Passwords here are at least 12 characters — ${12 - len} more to go.` }
  if (len < 16 && variety < 3) return { score: 1, label: t('setup.strength.fair'), hint: t('setup.strength.fair.hint') }
  if (len < 20) return { score: 2, label: t('setup.strength.good'), hint: variety < 3 ? t('setup.strength.good.hintMix') : t('setup.strength.good.hintMore') }
  return { score: 3, label: t('setup.strength.strong'), hint: '' }
})

const METER_COLORS = ['bg-red-400', 'bg-amber-400', 'bg-brand-400', 'bg-green-500']

onMounted(async () => {
  const token = route.query.token as string | undefined
  if (!token) {
    failure.value = { kind: 'unknown', message: t('setup.noToken') }
    loading.value = false
    return
  }
  try {
    const res = await fetch(`/api/op/enroll/${encodeURIComponent(token)}`, { credentials: 'include' })
    if (!res.ok) {
      const body = await res.json().catch(() => null) as { error?: string; error_description?: string } | null
      failure.value = {
        kind: body?.error ?? 'unknown',
        message: body?.error_description ?? t('setup.linkInvalid'),
      }
      loading.value = false
      return
    }
    context.value = await res.json() as SetupContext
    loading.value = false
  } catch {
    failure.value = { kind: 'unknown', message: t('error.network') }
    loading.value = false
  }
})

async function submit() {
  if (!context.value || submitting.value) return
  error.value = null
  if (password.value.length < 12) {
    error.value = t('setup.password.tooShort')
    return
  }
  if (password.value !== confirm.value) {
    error.value = t('setup.password.mismatch')
    return
  }
  submitting.value = true
  try {
    const token = route.query.token as string
    const res = await fetch(`/api/op/enroll/${encodeURIComponent(token)}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ password: password.value }),
    })
    if (!res.ok) {
      const body = await res.json().catch(() => null) as { error?: string } | null
      error.value = body?.error ?? t('setup.failed')
      submitting.value = false
      return
    }
    // The setup signs the account in — straight to the account page.
    router.replace('/op/account')
  } catch {
    error.value = t('error.network')
    submitting.value = false
  }
}
</script>

<template>
  <div class="min-h-screen flex items-center justify-center px-4 py-12 bg-cream dark:bg-slate-900">
    <!-- Loading state -->
    <div v-if="loading" class="flex flex-col items-center gap-4">
      <div class="w-8 h-8 border-2 border-brand-300 border-t-brand-600 rounded-full animate-spin" />
    </div>

    <div v-else class="w-full max-w-sm" data-testid="op-setup">
      <div class="text-center mb-8">
        <BrandLogo kind="logo" class="h-10 mx-auto mb-4" />
        <h1 class="text-xl font-serif font-bold text-slate-900 dark:text-white">{{ t('setup.title') }}</h1>
      </div>

      <!-- The honest failure cards (used / expired / unknown link). -->
      <div v-if="failure" class="rounded-lg border border-amber-200 dark:border-amber-800 bg-amber-50 dark:bg-amber-900/20 p-5" :data-testid="`op-setup-${failure.kind}`">
        <p class="text-sm text-amber-800 dark:text-amber-300">{{ failure.message }}</p>
      </div>

      <template v-if="context">
        <p class="text-sm text-slate-600 dark:text-slate-300 mb-6 text-center" data-testid="op-setup-account">
          This sets the password for
          <span class="font-medium text-slate-900 dark:text-white">{{ context.name }}</span>
          <span class="text-slate-400 dark:text-slate-500"> &lt;{{ context.email }}&gt;</span>.
        </p>

        <div v-if="error" class="mb-4 p-3 rounded-lg bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800">
          <p class="text-sm text-red-700 dark:text-red-300" data-testid="op-setup-error">{{ error }}</p>
        </div>

        <form @submit.prevent="submit" class="space-y-3">
          <div>
            <label class="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">{{ t('setup.password.label') }}</label>
            <input
              v-model="password"
              type="password"
              required
              autocomplete="new-password"
              data-testid="op-setup-password"
              class="w-full px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-500"
              placeholder="at least 12 characters"
            />
            <!-- The honest meter: length carries the score. -->
            <div v-if="password" class="mt-2" data-testid="op-setup-meter">
              <div class="flex gap-1 mb-1">
                <div
                  v-for="step in 4"
                  :key="step"
                  class="h-1 flex-1 rounded-full"
                  :class="step - 1 <= strength.score && password.length >= 12 ? METER_COLORS[strength.score] : (strength.score === 0 && step === 1 ? METER_COLORS[0] : 'bg-slate-200 dark:bg-slate-700')"
                />
              </div>
              <p class="text-xs text-slate-500 dark:text-slate-400">
                <span class="font-medium" data-testid="op-setup-meter-label">{{ strength.label }}</span>
                <span v-if="strength.hint"> — {{ strength.hint }}</span>
              </p>
            </div>
          </div>
          <div>
            <label class="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">{{ t('setup.password.repeat') }}</label>
            <input
              v-model="confirm"
              type="password"
              required
              autocomplete="new-password"
              data-testid="op-setup-confirm"
              class="w-full px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-500"
            />
          </div>
          <button
            type="submit"
            :disabled="submitting"
            data-testid="op-setup-submit"
            class="w-full min-h-11 py-2 rounded-lg text-sm font-medium bg-brand-600 text-white hover:bg-brand-700 transition-colors disabled:opacity-50 flex items-center justify-center gap-2"
          >
            <div v-if="submitting" class="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
            {{ submitting ? t('setup.password.busy') : t('setup.password.submit') }}
          </button>
        </form>

        <p class="mt-4 text-center text-[10px] text-slate-400 dark:text-slate-500">
          The setup link works exactly once and expires 24 hours after it was issued.
        </p>
      </template>
    </div>
  </div>
</template>
