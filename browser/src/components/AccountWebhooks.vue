<script lang="ts">
// ═══════════════════════════════════════════════════════════════════
// The webhooks' console API payloads — the AccountWebhooks component's
// prop types, exported so the account page's loader types its fetch
// with the same shape (the AccountTokens doctrine: never a drift).
// ═══════════════════════════════════════════════════════════════════
export interface WebhookRow {
  id: string
  url: string
  events: string[]
  active: boolean
  createdAt: string
}
export interface WebhookDeliveryRow {
  id: string
  event: string
  url: string
  attempts: number
  lastStatus: number
  delivered: boolean
  bodyDigest: string
  recordedAt: string
}
export interface WebhooksPayload {
  subscriptions: WebhookRow[]
  /** The SERVER's whitelist — the picker's source of truth. */
  events: string[]
}
export interface DeliveriesPayload {
  deliveries: WebhookDeliveryRow[]
}
</script>

<script setup lang="ts">
// ═══════════════════════════════════════════════════════════════════
// The account console's WEBHOOKS section (TODO.modern/08): the
// outbound events' self-service surface — the registry (the endpoint,
// the subscribed events), the subscribe act (an https public endpoint
// + the event picker from the server's whitelist), the shared signing
// secret shown ONCE (the GitHub doctrine again: it signs every
// delivery — the subscriber verifies with the copy they kept), the
// revoke act, and the delivery log (the dead letters included).
// ═══════════════════════════════════════════════════════════════════
import { computed, ref } from 'vue'
import { t } from '../i18n'

const props = defineProps<{
  webhooks: WebhooksPayload | null
  deliveries: DeliveriesPayload | null
}>()

const emit = defineEmits<{ changed: [] }>()

const error = ref<string | null>(null)
const notice = ref<string | null>(null)
const busy = ref(false)

function fmtDate(iso: string): string {
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })
}

// ── the subscribe act ────────────────────────────────────────────────

const formOpen = ref(false)
const endpointUrl = ref('')
const chosen = ref<Record<string, boolean>>({})

const subscribable = computed(() =>
  /^https:\/\/[^\s]+$/.test(endpointUrl.value.trim())
  && Object.values(chosen.value).some(Boolean),
)

function openForm() {
  formOpen.value = true
  endpointUrl.value = ''
  chosen.value = Object.fromEntries((props.webhooks?.events ?? []).map(e => [e, false]))
  error.value = null
  notice.value = null
}

/** The shown-once shared secret (the subscribe's answer) — the dialog
 *  until dismissed, never re-answered. */
const secret = ref<{ url: string; secret: string } | null>(null)
const secretCopied = ref(false)

async function subscribe() {
  if (busy.value || !subscribable.value) return
  busy.value = true
  error.value = null
  notice.value = null
  try {
    const events = Object.entries(chosen.value).filter(([, on]) => on).map(([name]) => name)
    const res = await fetch('/api/op/account/webhooks', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ url: endpointUrl.value.trim(), events }),
    })
    const body = await res.json().catch(() => null) as WebhookRow & { secret?: string; error?: string } | null
    if (!res.ok) {
      error.value = body?.error ?? t('account.networkError')
      busy.value = false
      return
    }
    if (body?.secret) {
      secret.value = { url: body.url, secret: body.secret }
      secretCopied.value = false
    }
    formOpen.value = false
    notice.value = t('account.webhooks.subscribed')
    emit('changed')
    busy.value = false
  } catch {
    error.value = t('account.networkError')
    busy.value = false
  }
}

async function copySecret() {
  if (!secret.value) return
  try {
    await navigator.clipboard.writeText(secret.value.secret)
    secretCopied.value = true
  } catch {
    secretCopied.value = false
  }
}

// ── the revoke act ───────────────────────────────────────────────────

async function revoke(row: WebhookRow) {
  if (busy.value) return
  busy.value = true
  error.value = null
  notice.value = null
  try {
    const res = await fetch(`/api/op/account/webhooks/${encodeURIComponent(row.id)}`, {
      method: 'DELETE',
      credentials: 'include',
    })
    if (!res.ok) {
      const body = await res.json().catch(() => null) as { error?: string } | null
      error.value = body?.error ?? t('account.networkError')
      busy.value = false
      return
    }
    notice.value = t('account.webhooks.revoked')
    emit('changed')
    busy.value = false
  } catch {
    error.value = t('account.networkError')
    busy.value = false
  }
}
</script>

<template>
  <section id="webhooks" class="bg-white dark:bg-slate-800 rounded-xl border border-slate-200/80 dark:border-slate-700 p-6 mb-6" data-testid="account-webhooks">
    <h2 class="text-sm font-semibold text-slate-900 dark:text-white mb-1">{{ t('account.webhooks.title') }}</h2>
    <p class="text-xs text-slate-500 dark:text-slate-400 mb-4">{{ t('account.webhooks.description') }}</p>

    <p v-if="error" class="mb-3 text-sm text-red-700 dark:text-red-300" data-testid="webhooks-error">{{ error }}</p>
    <p v-if="notice" class="mb-3 text-sm text-green-700 dark:text-green-300" data-testid="webhooks-notice">{{ notice }}</p>

    <!-- The registry. -->
    <ul v-if="webhooks?.subscriptions.length" class="space-y-2 mb-4" data-testid="webhooks-list">
      <li
        v-for="row in webhooks.subscriptions"
        :key="row.id"
        class="rounded-lg border border-slate-100 dark:border-slate-700/60 px-3 py-2"
        :data-testid="`webhook-${row.id}`"
      >
        <div class="flex items-start justify-between gap-3">
          <p class="text-sm font-medium text-slate-900 dark:text-white break-all" :data-testid="`webhook-${row.id}-url`">{{ row.url }}</p>
          <button
            type="button"
            :disabled="busy"
            class="shrink-0 text-xs text-red-600 dark:text-red-400 hover:underline disabled:opacity-50"
            :data-testid="`webhook-${row.id}-revoke`"
            @click="revoke(row)"
          >{{ t('account.webhooks.revoke') }}</button>
        </div>
        <p class="mt-1 flex flex-wrap gap-1">
          <span
            v-for="name in row.events"
            :key="name"
            class="inline-block rounded-full bg-slate-100 dark:bg-slate-700 px-2 py-0.5 font-mono text-[10px] text-slate-600 dark:text-slate-300"
          >{{ name }}</span>
        </p>
        <p class="mt-1 text-[11px] text-slate-400 dark:text-slate-500" :data-testid="`webhook-${row.id}-stamps`">
          {{ t('account.webhooks.since', { date: fmtDate(row.createdAt) }) }}
        </p>
      </li>
    </ul>
    <p v-else class="text-sm text-slate-500 dark:text-slate-400 mb-4" data-testid="webhooks-empty">{{ t('account.webhooks.empty') }}</p>

    <!-- The subscribe form. -->
    <div v-if="formOpen" class="border-t border-slate-100 dark:border-slate-700/60 pt-4" data-testid="webhook-form">
      <input
        v-model="endpointUrl"
        type="url"
        data-testid="webhook-url"
        :placeholder="t('account.webhooks.fieldUrl')"
        class="mb-3 w-full max-w-lg px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-500"
      />
      <p class="text-xs font-medium text-slate-600 dark:text-slate-300 mb-2">{{ t('account.webhooks.fieldEvents') }}</p>
      <ul class="space-y-1 mb-3" data-testid="webhook-event-picker">
        <li v-for="name in webhooks?.events ?? []" :key="name" class="flex items-center gap-2">
          <input
            :id="`webhook-event-${name}`"
            v-model="chosen[name]"
            type="checkbox"
            :data-testid="`webhook-event-${name}`"
            class="h-3.5 w-3.5 rounded border-slate-300 dark:border-slate-600 text-brand-600"
          />
          <label :for="`webhook-event-${name}`" class="font-mono text-xs text-slate-700 dark:text-slate-200">{{ name }}</label>
        </li>
      </ul>
      <div class="flex items-center gap-2">
        <button
          type="button"
          :disabled="busy || !subscribable"
          data-testid="webhook-subscribe-submit"
          class="px-4 py-2 rounded-lg text-sm font-medium bg-brand-600 text-white hover:bg-brand-700 transition-colors disabled:opacity-50"
          @click="subscribe"
        >{{ busy ? t('account.webhooks.busy') : t('account.webhooks.subscribe') }}</button>
        <button
          type="button"
          data-testid="webhook-subscribe-cancel"
          class="px-4 py-2 rounded-lg text-sm font-medium border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-700 transition-colors"
          @click="formOpen = false"
        >✕</button>
      </div>
    </div>
    <button
      v-else
      type="button"
      data-testid="webhook-subscribe-open"
      class="mb-4 px-4 py-2 rounded-lg text-sm font-medium border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-900 dark:text-white hover:bg-slate-50 dark:hover:bg-slate-700 transition-colors"
      @click="openForm"
    >+ {{ t('account.webhooks.subscribe') }}</button>

    <!-- The delivery log (the dead letters included). -->
    <div v-if="deliveries?.deliveries.length" class="border-t border-slate-100 dark:border-slate-700/60 pt-4">
      <p class="text-xs font-medium text-slate-600 dark:text-slate-300 mb-2">{{ t('account.webhooks.deliveries') }}</p>
      <ul class="space-y-1" data-testid="webhooks-deliveries">
        <li
          v-for="d in deliveries.deliveries"
          :key="d.id"
          class="flex items-center justify-between gap-3 text-xs"
          :data-testid="`webhook-delivery-${d.id}`"
        >
          <span class="font-mono text-slate-600 dark:text-slate-300 min-w-0 truncate">{{ d.event }} · {{ d.url }}</span>
          <span
            class="shrink-0 inline-block rounded-full px-2 py-0.5 text-[10px] font-medium"
            :class="d.delivered
              ? 'bg-emerald-50 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-300'
              : 'bg-red-50 text-red-700 dark:bg-red-900/30 dark:text-red-300'"
          >{{ d.delivered ? t('account.webhooks.delivered') : t('account.webhooks.deadLetter', { attempts: d.attempts, status: d.lastStatus }) }}</span>
        </li>
      </ul>
    </div>

    <!-- The one-time secret dialog (the same doctrine as the token's
         plaintext: shown once; a lost secret is revoked and
         re-subscribed). -->
    <div
      v-if="secret"
      class="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/50 px-4"
      data-testid="webhook-once-dialog"
      @click.self="secret = null"
    >
      <div class="w-full max-w-lg rounded-xl bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 p-6 shadow-xl">
        <h3 class="text-sm font-semibold text-slate-900 dark:text-white mb-2">{{ t('account.webhooks.onceTitle') }}</h3>
        <p class="text-xs text-slate-500 dark:text-slate-400 mb-4">{{ t('account.webhooks.onceNote') }}</p>
        <code class="block rounded-lg bg-slate-50 dark:bg-slate-900 px-3 py-2 mb-2 text-xs font-mono text-slate-800 dark:text-slate-100 break-all select-all" data-testid="webhook-once-secret">{{ secret.secret }}</code>
        <p class="text-[11px] text-slate-400 dark:text-slate-500 mb-4">{{ t('account.webhooks.verifyHint') }}</p>
        <div class="flex items-center gap-2">
          <button
            type="button"
            data-testid="webhook-once-copy"
            class="px-4 py-2 rounded-lg text-sm font-medium border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-700 transition-colors"
            @click="copySecret"
          >{{ secretCopied ? t('account.webhooks.copied') : t('account.webhooks.copy') }}</button>
          <button
            type="button"
            data-testid="webhook-once-dismiss"
            class="px-4 py-2 rounded-lg text-sm font-medium bg-brand-600 text-white hover:bg-brand-700 transition-colors"
            @click="secret = null"
          >✓</button>
        </div>
      </div>
    </div>
  </section>
</template>
