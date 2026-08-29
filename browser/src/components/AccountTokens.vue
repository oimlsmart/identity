<script lang="ts">
// ═══════════════════════════════════════════════════════════════════
// The developer tokens' console API payload (GET /api/op/account/tokens)
// — the AccountTokens component's prop type, exported so the account
// page's loader types its fetch with the same shape (never a drift).
// ═══════════════════════════════════════════════════════════════════
export interface TokenRow {
  id: string
  name: string
  prefix: string
  scopes: string[]
  orgContext: string | null
  createdAt: string
  expiresAt: string
  lastUsedAt: string | null
  revokedAt: string | null
  state: 'active' | 'expired' | 'revoked'
}
export interface TokenServiceOption {
  id: string
  name: string
  maxAction: 'read' | 'write' | 'admin'
}
export interface TokensPayload {
  tokens: TokenRow[]
  services: TokenServiceOption[]
}
</script>

<script setup lang="ts">
// ═══════════════════════════════════════════════════════════════════
// The account console's DEVELOPER TOKENS section (TODO.identity-
// features/08): the personal access tokens' self-service surface — the
// list (name, the scope summary, the last-used stamp, the expiration,
// the state), the mint act (the scope picker bounded by the account's
// own standing + the expiration picker, mandatory), the one-time
// plaintext dialog (the GitHub doctrine: shown once, the store holds
// the hash), and the revoke act.
//
// The token NEVER rides a request directly — the dialog's copy says it:
// it exchanges for a short-lived access token (RFC 8693). A token is a
// PERSON's credential, never an org's (the machine cone is the
// registered clients').
// ═══════════════════════════════════════════════════════════════════
import { computed, ref } from 'vue'
import { t } from '../i18n'

const props = defineProps<{
  /** The registry read (GET /api/op/account/tokens), loaded by the parent. */
  tokens: TokensPayload | null
}>()

const emit = defineEmits<{ changed: [] }>()

const error = ref<string | null>(null)
const notice = ref<string | null>(null)
const busy = ref(false)

function fmtDate(iso: string): string {
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })
}

// ── the mint act ─────────────────────────────────────────────────────

const mintOpen = ref(false)
const mintName = ref('')
/** The picker's per-service selection: '' = not included, else the
 *  action class (the options above the service's maxAction disable). */
const mintScopes = ref<Record<string, '' | 'read' | 'write' | 'admin'>>({})
const mintDays = ref(90)
const EXPIRY_CHOICES = [30, 60, 90, 180, 365]

/** The shown-once plaintext (the mint's answer) — the dialog until
 *  dismissed, never re-answered. */
const minted = ref<{ name: string; plaintext: string } | null>(null)
const mintedCopied = ref(false)

const ACTION_ORDER = ['read', 'write', 'admin'] as const

function openMint() {
  mintOpen.value = true
  mintName.value = ''
  mintDays.value = 90
  mintScopes.value = Object.fromEntries((props.tokens?.services ?? []).map(s => [s.id, '' as const]))
  error.value = null
  notice.value = null
}

/** An action-class option disables above the service's bound (the
 *  server's bound is the same rule — the picker's honesty, never the
 *  enforcement). */
function actionAllowed(service: TokenServiceOption, action: string): boolean {
  return ACTION_ORDER.indexOf(action as typeof ACTION_ORDER[number]) <= ACTION_ORDER.indexOf(service.maxAction)
}

const mintable = computed(() =>
  mintName.value.trim().length > 0
  && Object.values(mintScopes.value).some(v => v !== ''),
)

async function mint() {
  if (busy.value || !mintable.value) return
  busy.value = true
  error.value = null
  notice.value = null
  try {
    const scopes = Object.entries(mintScopes.value)
      .filter(([, action]) => action !== '')
      .map(([service, action]) => `${service}:${action}`)
    const res = await fetch('/api/op/account/tokens', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ name: mintName.value.trim(), scopes, expiresInDays: mintDays.value }),
    })
    const body = await res.json().catch(() => null) as { token?: TokenRow & { plaintext?: string }; error?: string } | null
    if (!res.ok) {
      error.value = body?.error ?? t('account.networkError')
      busy.value = false
      return
    }
    if (body?.token?.plaintext) {
      minted.value = { name: body.token.name, plaintext: body.token.plaintext }
      mintedCopied.value = false
    }
    mintOpen.value = false
    notice.value = t('account.tokens.minted')
    emit('changed')
    busy.value = false
  } catch {
    error.value = t('account.networkError')
    busy.value = false
  }
}

async function copyMinted() {
  if (!minted.value) return
  try {
    await navigator.clipboard.writeText(minted.value.plaintext)
    mintedCopied.value = true
  } catch {
    mintedCopied.value = false
  }
}

// ── the revoke act ───────────────────────────────────────────────────

async function revoke(token: TokenRow) {
  if (busy.value) return
  busy.value = true
  error.value = null
  notice.value = null
  try {
    const res = await fetch(`/api/op/account/tokens/${encodeURIComponent(token.id)}`, {
      method: 'DELETE',
      credentials: 'include',
    })
    if (!res.ok) {
      const body = await res.json().catch(() => null) as { error?: string } | null
      error.value = body?.error ?? t('account.networkError')
      busy.value = false
      return
    }
    notice.value = t('account.tokens.revoked')
    emit('changed')
    busy.value = false
  } catch {
    error.value = t('account.networkError')
    busy.value = false
  }
}

function stateLabel(state: TokenRow['state']): string {
  if (state === 'revoked') return t('account.tokens.stateRevoked')
  if (state === 'expired') return t('account.tokens.stateExpired')
  return t('account.tokens.stateActive')
}
</script>

<template>
  <section id="tokens" class="bg-white dark:bg-slate-800 rounded-xl border border-slate-200/80 dark:border-slate-700 p-6 mb-6" data-testid="account-tokens">
    <h2 class="text-sm font-semibold text-slate-900 dark:text-white mb-1">{{ t('account.tokens.title') }}</h2>
    <p class="text-xs text-slate-500 dark:text-slate-400 mb-4">{{ t('account.tokens.description') }}</p>

    <p v-if="error" class="mb-3 text-sm text-red-700 dark:text-red-300" data-testid="tokens-error">{{ error }}</p>
    <p v-if="notice" class="mb-3 text-sm text-green-700 dark:text-green-300" data-testid="tokens-notice">{{ notice }}</p>

    <!-- The registry. -->
    <ul v-if="tokens?.tokens.length" class="space-y-2 mb-4" data-testid="tokens-list">
      <li
        v-for="token in tokens.tokens"
        :key="token.id"
        class="flex items-start justify-between gap-3 rounded-lg border border-slate-100 dark:border-slate-700/60 px-3 py-2"
        :data-testid="`token-${token.id}`"
      >
        <div class="min-w-0">
          <p class="text-sm font-medium text-slate-900 dark:text-white break-words">
            <span :data-testid="`token-${token.id}-name`">{{ token.name }}</span>
            <span class="ml-2 font-mono text-xs text-slate-400 dark:text-slate-500">{{ token.prefix }}…</span>
            <span
              class="ml-2 inline-block rounded-full px-2 py-0.5 text-[10px] font-medium"
              :class="token.state === 'active'
                ? 'bg-emerald-50 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-300'
                : 'bg-slate-100 text-slate-500 dark:bg-slate-700 dark:text-slate-300'"
              :data-testid="`token-${token.id}-state`"
            >{{ stateLabel(token.state) }}</span>
          </p>
          <p class="text-xs text-slate-500 dark:text-slate-400 font-mono break-all" :data-testid="`token-${token.id}-scopes`">{{ token.scopes.join('  ') }}</p>
          <p class="text-[11px] text-slate-400 dark:text-slate-500" :data-testid="`token-${token.id}-stamps`">
            {{ t('account.tokens.expires', { date: fmtDate(token.expiresAt) }) }}
            · {{ token.lastUsedAt ? t('account.tokens.lastUsed', { date: fmtDate(token.lastUsedAt) }) : t('account.tokens.neverUsed') }}
          </p>
        </div>
        <button
          v-if="token.state === 'active'"
          type="button"
          :disabled="busy"
          class="shrink-0 text-xs text-red-600 dark:text-red-400 hover:underline disabled:opacity-50"
          :data-testid="`token-${token.id}-revoke`"
          @click="revoke(token)"
        >{{ t('account.tokens.revoke') }}</button>
      </li>
    </ul>
    <p v-else class="text-sm text-slate-500 dark:text-slate-400 mb-4" data-testid="tokens-empty">{{ t('account.tokens.empty') }}</p>

    <!-- The mint form. -->
    <div v-if="mintOpen" class="border-t border-slate-100 dark:border-slate-700/60 pt-4" data-testid="token-form">
      <input
        v-model="mintName"
        type="text"
        data-testid="token-name"
        :placeholder="t('account.tokens.fieldName')"
        class="mb-3 w-full max-w-lg px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-500"
      />
      <p class="text-xs font-medium text-slate-600 dark:text-slate-300 mb-2">{{ t('account.tokens.fieldScopes') }}</p>
      <ul class="space-y-1 mb-3" data-testid="token-scope-picker">
        <li v-for="service in tokens?.services ?? []" :key="service.id" class="flex items-center gap-3" :data-testid="`token-scope-row-${service.id}`">
          <span class="text-xs text-slate-700 dark:text-slate-200 min-w-0 flex-1 break-words">{{ service.name }} <span class="font-mono text-slate-400">({{ service.id }})</span></span>
          <select
            v-model="mintScopes[service.id]"
            :data-testid="`token-scope-${service.id}`"
            class="px-2 py-1 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-xs text-slate-900 dark:text-white"
          >
            <option value="">{{ t('account.tokens.scopeOff') }}</option>
            <option v-for="action in ACTION_ORDER" :key="action" :value="action" :disabled="!actionAllowed(service, action)" :data-testid="`token-scope-${service.id}-${action}`">
              {{ t(`account.tokens.scopeAction.${action}`) }}
            </option>
          </select>
        </li>
      </ul>
      <div class="flex flex-wrap items-center gap-2 mb-3">
        <label class="text-xs text-slate-600 dark:text-slate-300">{{ t('account.tokens.fieldExpiry') }}</label>
        <select
          v-model.number="mintDays"
          data-testid="token-expiry"
          class="px-2 py-1 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-xs text-slate-900 dark:text-white"
        >
          <option v-for="days in EXPIRY_CHOICES" :key="days" :value="days" :data-testid="`token-expiry-${days}`">{{ t('account.tokens.expiryDays', { days }) }}</option>
        </select>
      </div>
      <div class="flex items-center gap-2">
        <button
          type="button"
          :disabled="busy || !mintable"
          data-testid="token-mint-submit"
          class="px-4 py-2 rounded-lg text-sm font-medium bg-brand-600 text-white hover:bg-brand-700 transition-colors disabled:opacity-50"
          @click="mint"
        >{{ busy ? t('account.tokens.busy') : t('account.tokens.mint') }}</button>
        <button
          type="button"
          data-testid="token-mint-cancel"
          class="px-4 py-2 rounded-lg text-sm font-medium border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-700 transition-colors"
          @click="mintOpen = false"
        >✕</button>
      </div>
    </div>
    <button
      v-else-if="tokens?.services.length"
      type="button"
      data-testid="token-mint-open"
      class="px-4 py-2 rounded-lg text-sm font-medium border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-900 dark:text-white hover:bg-slate-50 dark:hover:bg-slate-700 transition-colors"
      @click="openMint"
    >+ {{ t('account.tokens.mint') }}</button>

    <!-- The one-time plaintext dialog (the GitHub doctrine: the store
         holds only the hash — a lost token is revoked and re-minted). -->
    <div
      v-if="minted"
      class="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/50 px-4"
      data-testid="token-once-dialog"
      @click.self="minted = null"
    >
      <div class="w-full max-w-lg rounded-xl bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 p-6 shadow-xl">
        <h3 class="text-sm font-semibold text-slate-900 dark:text-white mb-2">{{ t('account.tokens.onceTitle') }}</h3>
        <p class="text-xs text-slate-500 dark:text-slate-400 mb-4">{{ t('account.tokens.onceNote') }}</p>
        <code class="block rounded-lg bg-slate-50 dark:bg-slate-900 px-3 py-2 mb-4 text-sm font-mono text-slate-800 dark:text-slate-100 break-all select-all" data-testid="token-once">{{ minted.plaintext }}</code>
        <div class="flex items-center gap-2">
          <button
            type="button"
            data-testid="token-once-copy"
            class="px-4 py-2 rounded-lg text-sm font-medium border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-700 transition-colors"
            @click="copyMinted"
          >{{ mintedCopied ? t('account.tokens.copied') : t('account.tokens.copy') }}</button>
          <button
            type="button"
            data-testid="token-once-dismiss"
            class="px-4 py-2 rounded-lg text-sm font-medium bg-brand-600 text-white hover:bg-brand-700 transition-colors"
            @click="minted = null"
          >✓</button>
        </div>
      </div>
    </div>
  </section>
</template>
