<script lang="ts">
// ═══════════════════════════════════════════════════════════════════
// The multiple-emails console payload (GET /api/op/account's `emails`
// block, TODO.identity-features/01) — the AccountEmails component's
// prop type, exported so the account page's context types it with the
// same shape (never a drift).
// ═══════════════════════════════════════════════════════════════════
export interface AccountEmailRow {
  email: string
  isPrimary: boolean
  verifiedAt: string | null
  createdAt: string
}
</script>

<script setup lang="ts">
// ═══════════════════════════════════════════════════════════════════
// The account console's EMAILS section (TODO.identity-features/01):
// every address of the account — the PRIMARY (the address of record:
// the claims' `email`, never removable) plus the additional addresses,
// each verified independently (the per-address one-time link, mailed
// only). The acts:
//
//   ADD            the address lands UNVERIFIED (never sign-in-usable,
//                  never a notice's target); the verification link
//                  travels by mail — the no-mailer deployment says so
//                  honestly (the amber card, never a fake ceremony);
//   RESEND         a fresh one-time link for an unverified address (the
//                  503 honesty carries through when no mailer exists);
//   MAKE PRIMARY   a VERIFIED additional takes over (the old primary
//                  stays a verified additional — sign-in by it keeps
//                  working);
//   REMOVE         an additional goes; the primary refuses honestly
//                  (promote another first — the note says it).
// ═══════════════════════════════════════════════════════════════════
import { computed, ref } from 'vue'
import { t } from '../i18n'

defineProps<{
  /** The account's addresses (the primary first), from the context. */
  emails: AccountEmailRow[]
}>()

const emit = defineEmits<{ changed: [] }>()

const error = ref<string | null>(null)
const notice = ref<string | null>(null)
/** The in-flight act: 'add', or `<verb>:<email>` per row (one act at a
 *  time — the buttons disable honestly). */
const busy = ref<string | null>(null)

const draft = ref('')
const draftValid = computed(() => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(draft.value.trim()))
/** The add's honest outcome: the mailed green card or the no-mailer
 *  amber one. */
const addResult = ref<{ email: string; delivery: 'mailer' | 'unavailable' } | null>(null)

async function act(key: string, run: () => Promise<Response>, onOk: (body: Record<string, unknown>) => string): Promise<void> {
  if (busy.value) return
  busy.value = key
  error.value = null
  notice.value = null
  try {
    const res = await run()
    const body = await res.json().catch(() => null) as Record<string, unknown> | null
    if (!res.ok) {
      error.value = (body?.error as string | undefined) ?? t('account.networkError')
      busy.value = null
      return
    }
    notice.value = onOk(body ?? {})
    emit('changed')
    busy.value = null
  } catch {
    error.value = t('account.networkError')
    busy.value = null
  }
}

async function add(): Promise<void> {
  const email = draft.value.trim().toLowerCase()
  if (!draftValid.value) {
    error.value = t('account.profile.emailInvalid')
    return
  }
  addResult.value = null
  await act('add', () => fetch('/api/op/account/emails', {
    method: 'POST',
    credentials: 'include',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email }),
  }), (body) => {
    const delivery = body.delivery === 'mailer' ? 'mailer' : 'unavailable'
    addResult.value = { email, delivery }
    draft.value = ''
    return delivery === 'mailer' ? t('account.emails.addMailed', { email }) : t('account.emails.addUnavailable', { email })
  })
}

async function resend(email: string): Promise<void> {
  await act(`resend:${email}`, () => fetch(`/api/op/account/emails/${encodeURIComponent(email)}/verification`, {
    method: 'POST',
    credentials: 'include',
  }), () => t('account.emails.resent', { email }))
}

async function makePrimary(email: string): Promise<void> {
  await act(`primary:${email}`, () => fetch('/api/op/account/emails/primary', {
    method: 'POST',
    credentials: 'include',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email }),
  }), () => t('account.emails.switched', { email }))
}

async function remove(email: string): Promise<void> {
  await act(`remove:${email}`, () => fetch(`/api/op/account/emails/${encodeURIComponent(email)}`, {
    method: 'DELETE',
    credentials: 'include',
  }), () => t('account.emails.removed', { email }))
}
</script>

<template>
  <section id="emails" class="bg-white dark:bg-slate-800 rounded-xl border border-slate-200/80 dark:border-slate-700 p-6 mb-6" data-testid="account-emails">
    <h2 class="text-sm font-semibold text-slate-900 dark:text-white mb-1">{{ t('account.emails.title') }}</h2>
    <p class="text-xs text-slate-500 dark:text-slate-400 mb-4">{{ t('account.emails.description') }}</p>

    <p v-if="error" class="mb-3 text-sm text-red-700 dark:text-red-300" data-testid="emails-error">{{ error }}</p>
    <p v-if="notice" class="mb-3 text-sm text-green-700 dark:text-green-300" data-testid="emails-notice">{{ notice }}</p>

    <ul class="space-y-2" data-testid="emails-list">
      <li
        v-for="row in emails"
        :key="row.email"
        class="rounded-lg border border-slate-100 dark:border-slate-700/60 px-3 py-2"
        :data-testid="`email-row-${row.email}`"
      >
        <div class="flex items-center justify-between gap-3 flex-wrap">
          <div class="min-w-0">
            <p class="text-sm font-medium text-slate-900 dark:text-white break-all" :data-testid="`email-${row.email}`">
              {{ row.email }}
              <span
                v-if="row.isPrimary"
                class="ml-1 px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wider bg-brand-100 dark:bg-brand-900/40 text-brand-700 dark:text-brand-200"
                :data-testid="`email-primary-${row.email}`"
              >{{ t('account.emails.primaryBadge') }}</span>
              <span
                v-if="row.verifiedAt"
                class="ml-1 px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wider bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-300"
                :data-testid="`email-verified-${row.email}`"
              >{{ t('account.profile.verified') }}</span>
              <span
                v-else
                class="ml-1 px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wider bg-amber-100 dark:bg-amber-900/30 text-amber-700 dark:text-amber-300"
                :data-testid="`email-unverified-${row.email}`"
              >{{ t('account.profile.unverified') }}</span>
            </p>
            <p v-if="row.isPrimary" class="mt-0.5 text-[11px] text-slate-400 dark:text-slate-500" :data-testid="`email-primary-note-${row.email}`">
              {{ t('account.emails.primaryNote') }}
            </p>
          </div>
          <div v-if="!row.isPrimary" class="shrink-0 flex items-center gap-3">
            <button
              v-if="!row.verifiedAt"
              type="button"
              :disabled="busy !== null"
              class="text-xs text-brand-700 dark:text-brand-300 hover:underline disabled:opacity-50"
              :data-testid="`email-resend-${row.email}`"
              @click="resend(row.email)"
            >{{ busy === `resend:${row.email}` ? t('account.emails.resendBusy') : t('account.emails.resend') }}</button>
            <button
              v-if="row.verifiedAt"
              type="button"
              :disabled="busy !== null"
              class="text-xs text-brand-700 dark:text-brand-300 hover:underline disabled:opacity-50"
              :data-testid="`email-make-primary-${row.email}`"
              @click="makePrimary(row.email)"
            >{{ busy === `primary:${row.email}` ? t('account.emails.makePrimaryBusy') : t('account.emails.makePrimary') }}</button>
            <button
              type="button"
              :disabled="busy !== null"
              class="text-xs text-red-600 dark:text-red-400 hover:underline disabled:opacity-50"
              :data-testid="`email-remove-${row.email}`"
              @click="remove(row.email)"
            >{{ busy === `remove:${row.email}` ? t('account.emails.removeBusy') : t('account.emails.remove') }}</button>
          </div>
        </div>
      </li>
    </ul>

    <!-- The add: the address lands unverified; the verification link
         travels by mail (the honest no-mailer card otherwise). The input
         takes its own row on phones (the 04-account offender's rule). -->
    <form class="mt-4 max-w-sm" @submit.prevent="add">
      <label class="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">{{ t('account.emails.addLabel') }}</label>
      <div class="flex flex-wrap items-center gap-2">
        <input
          v-model="draft"
          type="email"
          data-testid="emails-add-input"
          class="w-full sm:flex-1 min-w-0 px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-500"
          @input="error = null"
        />
        <button
          type="submit"
          :disabled="busy !== null || !draftValid"
          data-testid="emails-add-submit"
          class="shrink-0 px-3 py-2 rounded-lg text-xs font-medium border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-700 transition-colors disabled:opacity-50"
        >{{ busy === 'add' ? t('account.emails.addBusy') : t('account.emails.addSubmit') }}</button>
      </div>
    </form>

    <div
      v-if="addResult"
      class="mt-3 rounded-lg border p-3 text-xs"
      :class="addResult.delivery === 'mailer'
        ? 'bg-green-50 dark:bg-green-900/20 border-green-200 dark:border-green-800 text-green-700 dark:text-green-300'
        : 'bg-amber-50 dark:bg-amber-900/20 border-amber-200 dark:border-amber-800 text-amber-800 dark:text-amber-200'"
      data-testid="emails-add-delivery"
    >
      <p v-if="addResult.delivery === 'mailer'">{{ t('account.emails.addMailed', { email: addResult.email }) }}</p>
      <p v-else>{{ t('account.emails.addUnavailable', { email: addResult.email }) }}</p>
    </div>
  </section>
</template>
