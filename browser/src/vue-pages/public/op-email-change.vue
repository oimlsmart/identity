<script setup lang="ts">
// ═══════════════════════════════════════════════════════════════════
// The verify-an-address landing page (TODO.identity/06 +
// TODO.identity-features/01) — the one-time link (?token=…) resolves
// here: the account, the address(es), a confirm act. The token's KIND
// names the ceremony (the API carries it): 'change' (the
// primary-address replacement) or 'add' (the added address's own
// verification — the copy names the add, never the move). The ceremony
// mirrors the account setup page's (op-setup.vue): the token is
// consumed ATOMICALLY at confirm (one-time means one-time), an expired
// link (24 h) is burned on presentation, and a fresh request voids the
// earlier links of the same ceremony target.
//
// The completion may run signed out (the link arrives by mail): the
// token IS the proof. A link that was SHOWN on screen (no mailer
// configured — the 'change' ceremony only) applies the change without
// verifying the mailbox; the result card says so honestly.
// ═══════════════════════════════════════════════════════════════════
import { ref, onMounted } from 'vue'
import { useRoute } from 'vue-router'
import BrandLogo from '../../components/BrandLogo.vue'

interface ChangeContext {
  name: string
  email: string
  newEmail: string
  expiresAt: string
  /** TODO.identity-features/01: the ceremony the link carries —
   *  'change' (the primary-address replacement) or 'add' (the added
   *  address's own verification). */
  kind?: 'change' | 'add'
}

const route = useRoute()

const loading = ref(true)
/** The link's failure class: 'unknown' | 'used' | 'expired' — each with
 *  its plain-language card (the API's error_description). */
const failure = ref<{ kind: string; message: string } | null>(null)
const context = ref<ChangeContext | null>(null)
const confirming = ref(false)
const error = ref<string | null>(null)
/** The completed ceremony's honest outcome (verified = the link
 *  traveled by mail to the new mailbox). */
const done = ref<{ email: string; verified: boolean; kind?: 'change' | 'add' } | null>(null)

function fmtDate(iso: string): string {
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })
}

onMounted(async () => {
  const token = route.query.token as string | undefined
  if (!token) {
    failure.value = { kind: 'unknown', message: 'This page needs a verification link (no ?token= parameter). Start the email change from your account page.' }
    loading.value = false
    return
  }
  try {
    const res = await fetch(`/api/op/email-change/${encodeURIComponent(token)}`)
    if (!res.ok) {
      const body = await res.json().catch(() => null) as { error?: string; error_description?: string } | null
      failure.value = {
        kind: body?.error ?? 'unknown',
        message: body?.error_description ?? 'This verification link is not valid. Start the email change again from your account page.',
      }
      loading.value = false
      return
    }
    context.value = await res.json() as ChangeContext
    loading.value = false
  } catch {
    error.value = 'The link could not be read. Is the server running?'
    loading.value = false
  }
})

async function confirm() {
  if (confirming.value) return
  const token = route.query.token as string
  confirming.value = true
  error.value = null
  try {
    const res = await fetch(`/api/op/email-change/${encodeURIComponent(token)}`, { method: 'POST' })
    if (!res.ok) {
      const body = await res.json().catch(() => null) as { error?: string; error_description?: string } | null
      if (body?.error === 'conflict' || body?.error === 'used' || body?.error === 'expired') {
        failure.value = { kind: body.error, message: body.error_description ?? 'This verification link is not valid.' }
      } else {
        error.value = body?.error_description ?? 'The change could not be completed. Try again.'
      }
      confirming.value = false
      return
    }
    done.value = await res.json() as { email: string; verified: boolean }
    confirming.value = false
  } catch {
    error.value = 'Network error. Is the server running?'
    confirming.value = false
  }
}
</script>

<template>
  <div class="flex items-center justify-center px-6 py-12">
    <div class="w-full max-w-md">
      <div class="flex justify-center mb-8">
        <BrandLogo class="h-10 w-auto" />
      </div>

      <div class="bg-white dark:bg-slate-800 rounded-xl border border-slate-200/80 dark:border-slate-700 p-8" data-testid="op-email-change">
        <div v-if="loading" class="flex justify-center py-8">
          <div class="w-8 h-8 border-2 border-brand-300 border-t-brand-600 rounded-full animate-spin" />
        </div>

        <!-- The honest failure cards (used / expired / unknown). -->
        <template v-else-if="failure">
          <h1 class="text-xl font-serif font-bold text-slate-900 dark:text-white mb-2" data-testid="op-email-change-failure-title">
            {{ failure.kind === 'used' ? 'This link was already used' : failure.kind === 'expired' ? 'This link has expired' : failure.kind === 'conflict' ? 'The address was taken' : 'This link is not valid' }}
          </h1>
          <p class="text-sm text-slate-600 dark:text-slate-300" :data-testid="`op-email-change-${failure.kind}`">{{ failure.message }}</p>
          <p class="mt-4 text-center text-xs">
            <a href="/op/account" class="text-brand-600 dark:text-brand-300 hover:underline" data-testid="op-email-change-back">Back to your account</a>
          </p>
        </template>

        <!-- The completed ceremony. -->
        <template v-else-if="done">
          <h1 class="text-xl font-serif font-bold text-slate-900 dark:text-white mb-2" data-testid="op-email-change-done">{{ done.kind === 'add' ? 'Email address verified' : 'Email address changed' }}</h1>
          <p v-if="done.kind === 'add'" class="text-sm text-slate-600 dark:text-slate-300">
            <span class="font-medium">{{ done.email }}</span> now signs in to your OIML SMART account alongside your other addresses, and receives the account's security notices.
          </p>
          <p v-else class="text-sm text-slate-600 dark:text-slate-300">
            Your OIML SMART account now signs in with <span class="font-medium">{{ done.email }}</span>.
          </p>
          <p v-if="done.verified && done.kind !== 'add'" class="mt-2 text-xs text-slate-500 dark:text-slate-400" data-testid="op-email-change-verified">
            The new address is verified: you opened the link that was emailed to it.
          </p>
          <p v-else-if="!done.verified" class="mt-2 text-xs text-slate-500 dark:text-slate-400" data-testid="op-email-change-unverified">
            This link was shown on screen (no mailer is configured), so the new address stays marked "not verified" until a mailed link can confirm it.
          </p>
          <p class="mt-4 text-center text-xs">
            <a href="/op/account" class="text-brand-600 dark:text-brand-300 hover:underline" data-testid="op-email-change-back-done">Back to your account</a>
          </p>
        </template>

        <!-- The confirmation. -->
        <template v-else-if="context">
          <h1 class="text-xl font-serif font-bold text-slate-900 dark:text-white mb-2">{{ context.kind === 'add' ? 'Confirm the email address' : 'Change the email address' }}</h1>
          <p v-if="context.kind === 'add'" class="text-sm text-slate-600 dark:text-slate-300 mb-4" data-testid="op-email-change-context">
            <span class="font-medium">{{ context.name }}</span>, this link confirms
            <span class="font-medium">{{ context.newEmail }}</span> as an address on your OIML SMART account.
          </p>
          <p v-else class="text-sm text-slate-600 dark:text-slate-300 mb-4" data-testid="op-email-change-context">
            <span class="font-medium">{{ context.name }}</span>, this link moves your OIML SMART account
            from <span class="font-medium">{{ context.email }}</span>
            to <span class="font-medium">{{ context.newEmail }}</span>.
          </p>
          <p v-if="context.kind === 'add'" class="text-xs text-slate-500 dark:text-slate-400 mb-4">
            The link works exactly once and expires {{ fmtDate(context.expiresAt) }}. Once confirmed, the
            address signs in to the same account and receives its security notices.
          </p>
          <p v-else class="text-xs text-slate-500 dark:text-slate-400 mb-4">
            The link works exactly once and expires {{ fmtDate(context.expiresAt) }}. Sign-ins then use the
            new address; nothing else about the account changes.
          </p>

          <div v-if="error" class="mb-4 p-3 rounded-lg bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800">
            <p class="text-sm text-red-700 dark:text-red-300" data-testid="op-email-change-error">{{ error }}</p>
          </div>

          <button
            :disabled="confirming"
            data-testid="op-email-change-confirm"
            class="w-full min-h-11 py-2 rounded-lg text-sm font-medium bg-brand-600 text-white hover:bg-brand-700 transition-colors disabled:opacity-50 flex items-center justify-center gap-2"
            @click="confirm"
          >
            <div v-if="confirming" class="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
            {{ confirming ? (context.kind === 'add' ? 'Confirming…' : 'Changing…') : (context.kind === 'add' ? 'Confirm the address' : 'Confirm the change') }}
          </button>
        </template>

        <p v-else class="text-sm text-red-700 dark:text-red-300" data-testid="op-email-change-error">{{ error }}</p>
      </div>
    </div>
  </div>
</template>
