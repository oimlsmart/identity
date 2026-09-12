<script setup lang="ts">
// ═══════════════════════════════════════════════════════════════════
// The public self-registration (TODO.restructure/05) — the applicant's
// own account, created by the applicant: no organization membership,
// no privileges beyond the account page. The mailbox proof follows by
// mail (the kernel 'verify' ceremony): the password works immediately,
// the address reads unverified to relying parties until the one-time
// link (24 h) is opened, and the strong sign-in factors stay locked
// until then. The organization binding stays where it was — the join
// intake and the org admins gate it, never this form.
// ═══════════════════════════════════════════════════════════════════
import { computed, ref } from 'vue'
import BrandLogo from '../../components/BrandLogo.vue'
import { useBranding } from '../../branding'
import { t } from '../../i18n'

const { branding } = useBranding()

const name = ref('')
const email = ref('')
const password = ref('')
const submitting = ref(false)
const error = ref<string | null>(null)
/** The success posture once the account stands: 'mailed' (the link is
 *  on its way) or 'pending' (a transient send failure — the console
 *  banner's resend carries it). */
const filed = ref<'mailed' | 'pending' | null>(null)

const canSubmit = computed(() =>
  !submitting.value
  && name.value.trim() !== ''
  && email.value.includes('@')
  && password.value.length >= 12,
)

async function submit() {
  if (!canSubmit.value) return
  submitting.value = true
  error.value = null
  try {
    const res = await fetch('/api/op/register', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ name: name.value.trim(), email: email.value.trim(), password: password.value }),
    })
    if (res.status === 201) {
      const body = await res.json().catch(() => ({})) as { verification?: string }
      filed.value = body.verification === 'mailed' ? 'mailed' : 'pending'
      return
    }
    const body = await res.json().catch(() => null) as { error?: string } | null
    error.value = body?.error ?? t('register.failed')
  } catch {
    error.value = t('register.networkError')
  } finally {
    submitting.value = false
  }
}
</script>

<template>
  <div class="min-h-screen flex items-center justify-center px-4 py-12 bg-cream dark:bg-slate-900">
    <div class="w-full max-w-md" data-testid="register">

      <div v-if="filed">
        <div class="bg-white dark:bg-slate-800 rounded-2xl border border-slate-200 dark:border-slate-700 p-8 text-center">
          <BrandLogo kind="logo" class="h-10 mx-auto mb-4" />
          <h1 class="text-lg font-serif font-bold text-slate-900 dark:text-white" data-testid="register-done-title">
            {{ filed === 'mailed' ? t('register.mailed.title') : t('register.pending.title') }}
          </h1>
          <p class="mt-3 text-sm text-slate-600 dark:text-slate-400" data-testid="register-done-body">
            {{ filed === 'mailed'
              ? t('register.mailed.body', { email: email.trim() })
              : t('register.pending.body') }}
          </p>
          <router-link
            to="/"
            class="mt-6 inline-block px-4 py-2 rounded-lg bg-brand-600 text-white text-sm font-medium hover:bg-brand-700"
            data-testid="register-done-signin"
          >{{ t('register.signIn') }}</router-link>
        </div>
      </div>

      <div v-else>
        <div class="bg-white dark:bg-slate-800 rounded-2xl border border-slate-200 dark:border-slate-700 p-8">
          <BrandLogo kind="logo" class="h-10 mx-auto mb-2" />
          <h1 class="text-center text-lg font-serif font-bold text-slate-900 dark:text-white">{{ t('register.title') }}</h1>
          <p class="mt-2 text-center text-sm text-slate-600 dark:text-slate-400">{{ t('register.description') }}</p>

          <div v-if="error" class="mt-4 p-3 rounded-lg bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800">
            <p class="text-sm text-red-700 dark:text-red-300" data-testid="register-error">{{ error }}</p>
          </div>

          <form class="mt-6 space-y-4" @submit.prevent="submit">
            <div>
              <label class="block text-sm font-medium text-slate-700 dark:text-slate-300" for="register-name">{{ t('register.name.label') }}</label>
              <input
                id="register-name"
                v-model="name"
                type="text"
                autocomplete="name"
                data-testid="register-name"
                class="mt-1 w-full px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-500"
              />
            </div>
            <div>
              <label class="block text-sm font-medium text-slate-700 dark:text-slate-300" for="register-email">{{ t('register.email.label') }}</label>
              <input
                id="register-email"
                v-model="email"
                type="email"
                autocomplete="email"
                data-testid="register-email"
                class="mt-1 w-full px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-500"
              />
            </div>
            <div>
              <label class="block text-sm font-medium text-slate-700 dark:text-slate-300" for="register-password">{{ t('register.password.label') }}</label>
              <input
                id="register-password"
                v-model="password"
                type="password"
                autocomplete="new-password"
                data-testid="register-password"
                class="mt-1 w-full px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-500"
              />
              <p class="mt-1 text-xs text-slate-400 dark:text-slate-500">{{ t('register.password.hint') }}</p>
            </div>
            <button
              type="submit"
              :disabled="!canSubmit"
              data-testid="register-submit"
              class="w-full px-4 py-2 rounded-lg bg-brand-600 text-white text-sm font-medium hover:bg-brand-700 disabled:opacity-50 disabled:cursor-not-allowed"
            >{{ submitting ? t('register.busy') : t('register.submit') }}</button>
          </form>
        </div>

        <p class="mt-4 text-center text-sm text-slate-600 dark:text-slate-400" data-testid="register-signin-prompt">
          {{ t('register.haveAccount') }}
          <router-link to="/" class="text-brand-600 dark:text-brand-300 hover:underline" data-testid="register-signin-link">{{ t('register.signIn') }}</router-link>
        </p>
      </div>

    </div>
  </div>
</template>
