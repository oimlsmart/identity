<script lang="ts">
// ═══════════════════════════════════════════════════════════════════
// The factor registry's console API payload (GET /api/op/account/factors)
// — the AccountFactors component's prop type, exported so the account
// page's loader types its fetch with the same shape (never a drift).
// ═══════════════════════════════════════════════════════════════════
export interface FactorsPasskeyRow {
  credentialId: string
  name: string
  createdAt: string
  lastUsedAt: string | null
  aaguid: string | null
  transports: string[]
}
export interface FactorsTotpRow { id: string; name: string; createdAt: string; lastUsedAt: string | null }
export interface FactorsPayload {
  passkeys: FactorsPasskeyRow[]
  totp: FactorsTotpRow[]
  pendingTotp: Array<{ id: string; createdAt: string }>
  recoveryCodes: { total: number; remaining: number; createdAt: string | null }
}
</script>

<script setup lang="ts">
// ═══════════════════════════════════════════════════════════════════
// The account console's FACTORS section (TODO.identity-sso/02 + /03):
// the factor registry's self-service surface —
//
//   PASSKEYS        register (the WebAuthn ceremony, named), list with
//                   created/last-used + the declared device hints, revoke
//                   (the last-way-in guard rides);
//   AUTHENTICATOR   the TOTP enrollment: the otpauth:// URI as a LOCAL
//   APPS            QR (src/qr.ts — the secret never leaves the page),
//                   the manual secret, and the first-code activation;
//   RECOVERY CODES  the set's honest state (count + age, never a code),
//                   the regenerate act (the old set dies); a fresh set
//                   shows ONCE (the dialog) and is never stored raw.
//
// THE GATE (wave E's live lifecycle state): a verified primary address
// is required to enroll — the recovery floor rides the mailbox. An
// unverified account sees the refusal honestly (the list still reads).
// ═══════════════════════════════════════════════════════════════════
import { computed, ref } from 'vue'
import { t } from '../i18n'
import { qrSvg } from '../qr'
import {
  registerPasskey,
  webauthnAvailable,
  type CredentialJson,
  type RegistrationOptionsJson,
} from '../webauthn'

const props = defineProps<{
  /** The account's primary-address verification state (the enrollment gate). */
  emailVerified: boolean
  /** The registry read (GET /api/op/account/factors), loaded by the parent. */
  factors: FactorsPayload | null
  /** THE GUARD: the sole remaining passkey is the account's last way in
   *  (no password, no upstream link) — its revoke is refused (the server
   *  holds the same rule). */
  lastPasskeyIsLastMethod: boolean
}>()

const emit = defineEmits<{ changed: [] }>()

const error = ref<string | null>(null)
const notice = ref<string | null>(null)
const busy = ref(false)

// The platform's WebAuthn availability (the passkey controls hide honestly
// where the browser has none — an old browser is not an error).
const passkeysSupported = webauthnAvailable()

function fmtDate(iso: string): string {
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })
}

/** The passkey row's honest device hint (the DECLARED transports — never
 *  attested). */
function transportHint(transports: string[]): string {
  if (!transports.length) return t('account.factors.passkeyNoHint')
  return transports.join(', ')
}

// ── the passkey registration ─────────────────────────────────────────

const passkeyName = ref('')
const passkeyNameOpen = ref(false)

async function registerPasskeyStart() {
  if (busy.value) return
  const name = passkeyName.value.trim()
  if (!name) {
    error.value = t('account.factors.passkeyNameRequired')
    return
  }
  busy.value = true
  error.value = null
  notice.value = null
  try {
    const optRes = await fetch('/api/op/account/factors/passkeys/options', {
      method: 'POST', headers: { 'content-type': 'application/json' }, credentials: 'include', body: '{}',
    })
    if (!optRes.ok) {
      const body = await optRes.json().catch(() => null) as { error?: string } | null
      error.value = body?.error ?? t('account.networkError')
      busy.value = false
      return
    }
    const { publicKey } = await optRes.json() as { publicKey: RegistrationOptionsJson }
    let credential: CredentialJson
    try {
      credential = await registerPasskey(publicKey)
    } catch (e) {
      // The user dismissed or the authenticator refused — plain language,
      // never a DOMException dump.
      error.value = t('account.factors.passkeyCancelled')
      console.warn('[factors] the passkey ceremony did not complete:', (e as Error).name)
      busy.value = false
      return
    }
    const finishRes = await fetch('/api/op/account/factors/passkeys', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ name, credential, transports: credential.transports ?? [] }),
    })
    if (!finishRes.ok) {
      const body = await finishRes.json().catch(() => null) as { error?: string } | null
      error.value = body?.error ?? t('account.networkError')
      busy.value = false
      return
    }
    const body = await finishRes.json() as { recoveryCodes?: string[] | null }
    passkeyName.value = ''
    passkeyNameOpen.value = false
    if (body.recoveryCodes?.length) showRecoveryCodes(body.recoveryCodes, true)
    notice.value = t('account.factors.passkeyEnrolled', { name })
    emit('changed')
    busy.value = false
  } catch {
    error.value = t('account.networkError')
    busy.value = false
  }
}

async function revokePasskey(credentialId: string) {
  if (busy.value) return
  busy.value = true
  error.value = null
  notice.value = null
  try {
    const res = await fetch(`/api/op/account/factors/passkeys/${encodeURIComponent(credentialId)}`, {
      method: 'DELETE', credentials: 'include',
    })
    if (!res.ok) {
      const body = await res.json().catch(() => null) as { error?: string } | null
      error.value = body?.error ?? t('account.networkError')
      busy.value = false
      return
    }
    notice.value = t('account.factors.passkeyRevoked')
    emit('changed')
    busy.value = false
  } catch {
    error.value = t('account.networkError')
    busy.value = false
  }
}

// ── the TOTP enrollment ──────────────────────────────────────────────

interface TotpEnrollment { id: string; secret: string; otpauthUri: string }
const totpEnroll = ref<TotpEnrollment | null>(null)
const totpCode = ref('')
const totpNameDraft = ref('')

const totpQrSvg = computed(() => totpEnroll.value ? qrSvg(totpEnroll.value.otpauthUri, { moduleSize: 4 }) : null)
/** The manual-entry form of the secret: dashed groups read aloud cleanly. */
const totpSecretManual = computed(() => totpEnroll.value?.secret.replace(/(.{4})/g, '$1-').replace(/-$/, '') ?? '')

async function startTotp() {
  if (busy.value) return
  busy.value = true
  error.value = null
  notice.value = null
  try {
    const res = await fetch('/api/op/account/factors/totp', {
      method: 'POST', headers: { 'content-type': 'application/json' }, credentials: 'include', body: '{}',
    })
    if (!res.ok) {
      const body = await res.json().catch(() => null) as { error?: string } | null
      error.value = body?.error ?? t('account.networkError')
      busy.value = false
      return
    }
    totpEnroll.value = await res.json() as TotpEnrollment
    totpCode.value = ''
    totpNameDraft.value = ''
    busy.value = false
  } catch {
    error.value = t('account.networkError')
    busy.value = false
  }
}

async function verifyTotpEnroll() {
  if (busy.value || !totpEnroll.value) return
  busy.value = true
  error.value = null
  try {
    const res = await fetch(`/api/op/account/factors/totp/${encodeURIComponent(totpEnroll.value.id)}/verify`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ code: totpCode.value.trim(), name: totpNameDraft.value.trim() || undefined }),
    })
    const body = await res.json().catch(() => null) as { error?: string; recoveryCodes?: string[] | null } | null
    if (!res.ok) {
      error.value = body?.error ?? t('account.networkError')
      busy.value = false
      if (res.status === 429) totpEnroll.value = null // the throttle burned the setup — start over
      return
    }
    if (body?.recoveryCodes?.length) showRecoveryCodes(body.recoveryCodes, true)
    totpEnroll.value = null
    notice.value = t('account.factors.totpEnrolled')
    emit('changed')
    busy.value = false
  } catch {
    error.value = t('account.networkError')
    busy.value = false
  }
}

function cancelTotp() {
  // The pending row expires server-side on its own (10 min); the console
  // simply closes the panel (the registry list never shows pending rows).
  totpEnroll.value = null
  totpCode.value = ''
}

async function revokeTotp(id: string) {
  if (busy.value) return
  busy.value = true
  error.value = null
  notice.value = null
  try {
    const res = await fetch(`/api/op/account/factors/totp/${encodeURIComponent(id)}`, {
      method: 'DELETE', credentials: 'include',
    })
    if (!res.ok) {
      const body = await res.json().catch(() => null) as { error?: string } | null
      error.value = body?.error ?? t('account.networkError')
      busy.value = false
      return
    }
    notice.value = t('account.factors.totpRevoked')
    emit('changed')
    busy.value = false
  } catch {
    error.value = t('account.networkError')
    busy.value = false
  }
}

// ── the recovery codes ───────────────────────────────────────────────

/** The shown-once set (the dialog's payload) + whether it came from the
 *  first factor's enrollment (the intro line differs). */
const recoveryShown = ref<{ codes: string[]; firstFactor: boolean } | null>(null)
const recoveryCopied = ref(false)

function showRecoveryCodes(codes: string[], firstFactor: boolean) {
  recoveryShown.value = { codes, firstFactor }
  recoveryCopied.value = false
}

async function copyRecoveryCodes() {
  if (!recoveryShown.value) return
  try {
    await navigator.clipboard.writeText(recoveryShown.value.codes.join('\n'))
    recoveryCopied.value = true
  } catch {
    recoveryCopied.value = false
  }
}

async function regenerateRecoveryCodes() {
  if (busy.value) return
  busy.value = true
  error.value = null
  notice.value = null
  try {
    const res = await fetch('/api/op/account/factors/recovery-codes', {
      method: 'POST', headers: { 'content-type': 'application/json' }, credentials: 'include', body: '{}',
    })
    const body = await res.json().catch(() => null) as { codes?: string[]; error?: string } | null
    if (!res.ok) {
      error.value = body?.error ?? t('account.networkError')
      busy.value = false
      return
    }
    if (body?.codes?.length) showRecoveryCodes(body.codes, false)
    emit('changed')
    busy.value = false
  } catch {
    error.value = t('account.networkError')
    busy.value = false
  }
}
</script>

<template>
  <section id="factors" class="bg-white dark:bg-slate-800 rounded-xl border border-slate-200/80 dark:border-slate-700 p-6 mb-6" data-testid="account-factors">
    <h2 class="text-sm font-semibold text-slate-900 dark:text-white mb-1">{{ t('account.factors.title') }}</h2>
    <p class="text-xs text-slate-500 dark:text-slate-400 mb-4">{{ t('account.factors.description') }}</p>

    <!-- The unverified-address posture (wave E's lifecycle state): the
         enrollment acts refuse honestly — the recovery floor rides the
         mailbox. The registry itself still reads. -->
    <div
      v-if="!emailVerified"
      class="mb-4 p-3 rounded-lg bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800"
      data-testid="factors-unverified-banner"
    >
      <p class="text-xs text-amber-800 dark:text-amber-200">{{ t('account.factors.unverifiedNote') }}</p>
    </div>

    <div v-if="error" class="mb-4 p-3 rounded-lg bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800">
      <p class="text-sm text-red-700 dark:text-red-300" data-testid="factors-error">{{ error }}</p>
    </div>
    <div v-if="notice" class="mb-4 p-3 rounded-lg bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800">
      <p class="text-sm text-green-700 dark:text-green-300" data-testid="factors-notice">{{ notice }}</p>
    </div>

    <!-- ── The passkeys ── -->
    <div class="mb-5" data-testid="factors-passkeys">
      <h3 class="text-xs font-semibold text-slate-700 dark:text-slate-200 mb-2">{{ t('account.factors.passkeysTitle') }}</h3>
      <ul v-if="factors?.passkeys.length" class="space-y-2 mb-3" data-testid="factors-passkey-list">
        <li
          v-for="pk in factors.passkeys"
          :key="pk.credentialId"
          class="flex items-center justify-between rounded-lg border border-slate-200 dark:border-slate-700 px-4 py-3"
          :data-testid="`factor-passkey-${pk.credentialId}`"
        >
          <div class="min-w-0">
            <p class="text-sm font-medium text-slate-900 dark:text-white" :data-testid="`factor-passkey-${pk.credentialId}-name`">{{ pk.name }}</p>
            <p class="text-xs text-slate-400 dark:text-slate-500">
              {{ t('account.factors.added', { date: fmtDate(pk.createdAt) }) }} ·
              {{ pk.lastUsedAt ? t('account.factors.lastUsed', { date: fmtDate(pk.lastUsedAt) }) : t('account.factors.neverUsed') }}
            </p>
            <p class="text-[10px] text-slate-400 dark:text-slate-500">{{ transportHint(pk.transports) }}</p>
          </div>
          <button
            type="button"
            :disabled="busy || (lastPasskeyIsLastMethod && factors!.passkeys.length === 1)"
            :data-testid="`factor-passkey-${pk.credentialId}-revoke`"
            class="shrink-0 px-3 py-1.5 rounded-lg text-xs font-medium border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-700 transition-colors disabled:opacity-50"
            @click="revokePasskey(pk.credentialId)"
          >{{ t('account.factors.revoke') }}</button>
        </li>
      </ul>
      <p v-else class="text-sm text-slate-500 dark:text-slate-400 mb-3" data-testid="factors-passkey-empty">{{ t('account.factors.passkeyEmpty') }}</p>

      <template v-if="passkeysSupported && emailVerified">
        <div v-if="passkeyNameOpen" class="flex flex-wrap items-center gap-2" data-testid="factor-passkey-form">
          <input
            v-model="passkeyName"
            type="text"
            maxlength="60"
            data-testid="factor-passkey-name"
            :placeholder="t('account.factors.passkeyNamePlaceholder')"
            class="flex-1 min-w-0 basis-full sm:basis-auto px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-500"
          />
          <button
            type="button"
            :disabled="busy"
            data-testid="factor-passkey-register"
            class="shrink-0 px-4 py-2 rounded-lg text-sm font-medium bg-brand-600 text-white hover:bg-brand-700 transition-colors disabled:opacity-50"
            @click="registerPasskeyStart"
          >{{ t('account.factors.passkeyRegister') }}</button>
          <button
            type="button"
            data-testid="factor-passkey-cancel"
            class="shrink-0 px-3 py-2 rounded-lg text-xs font-medium border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-700 transition-colors"
            @click="passkeyNameOpen = false; passkeyName = ''"
          >{{ t('account.profile.cancel') }}</button>
        </div>
        <button
          v-else
          type="button"
          data-testid="factor-passkey-add"
          class="px-4 py-2 rounded-lg text-sm font-medium border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-900 dark:text-white hover:bg-slate-50 dark:hover:bg-slate-700 transition-colors"
          @click="passkeyNameOpen = true"
        >{{ t('account.factors.passkeyAdd') }}</button>
      </template>
      <p v-else-if="!passkeysSupported" class="text-xs text-slate-400 dark:text-slate-500" data-testid="factors-passkey-unsupported">
        {{ t('account.factors.passkeyUnsupported') }}
      </p>
    </div>

    <!-- ── The authenticator apps (TOTP) ── -->
    <div class="mb-5" data-testid="factors-totp">
      <h3 class="text-xs font-semibold text-slate-700 dark:text-slate-200 mb-2">{{ t('account.factors.totpTitle') }}</h3>
      <ul v-if="factors?.totp.length" class="space-y-2 mb-3" data-testid="factors-totp-list">
        <li
          v-for="app in factors.totp"
          :key="app.id"
          class="flex items-center justify-between rounded-lg border border-slate-200 dark:border-slate-700 px-4 py-3"
          :data-testid="`factor-totp-${app.id}`"
        >
          <div class="min-w-0">
            <p class="text-sm font-medium text-slate-900 dark:text-white" :data-testid="`factor-totp-${app.id}-name`">{{ app.name }}</p>
            <p class="text-xs text-slate-400 dark:text-slate-500">
              {{ t('account.factors.added', { date: fmtDate(app.createdAt) }) }} ·
              {{ app.lastUsedAt ? t('account.factors.lastUsed', { date: fmtDate(app.lastUsedAt) }) : t('account.factors.neverUsed') }}
            </p>
          </div>
          <button
            type="button"
            :disabled="busy"
            :data-testid="`factor-totp-${app.id}-revoke`"
            class="shrink-0 px-3 py-1.5 rounded-lg text-xs font-medium border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-700 transition-colors disabled:opacity-50"
            @click="revokeTotp(app.id)"
          >{{ t('account.factors.revoke') }}</button>
        </li>
      </ul>
      <p v-else class="text-sm text-slate-500 dark:text-slate-400 mb-3" data-testid="factors-totp-empty">{{ t('account.factors.totpEmpty') }}</p>

      <!-- The enrollment panel: the LOCAL QR (the secret never leaves the
           page), the manual secret, the first-code activation. -->
      <div
        v-if="totpEnroll"
        class="rounded-lg border border-slate-200 dark:border-slate-700 p-4 mb-3"
        data-testid="factor-totp-enroll"
      >
        <p class="text-xs text-slate-600 dark:text-slate-300 mb-3">{{ t('account.factors.totpEnrollHint') }}</p>
        <div class="flex flex-col sm:flex-row items-start gap-4">
          <div class="shrink-0 rounded-lg overflow-hidden border border-slate-200 dark:border-slate-700" data-testid="factor-totp-qr" v-html="totpQrSvg" />
          <div class="min-w-0 flex-1">
            <p class="text-[11px] uppercase tracking-wide text-slate-400 dark:text-slate-500 mb-1">{{ t('account.factors.totpManual') }}</p>
            <code class="block text-xs font-mono text-slate-700 dark:text-slate-200 break-all select-all" data-testid="factor-totp-secret">{{ totpSecretManual }}</code>
            <div class="mt-3">
              <label class="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">{{ t('account.factors.totpNameLabel') }}</label>
              <input
                v-model="totpNameDraft"
                type="text"
                maxlength="60"
                data-testid="factor-totp-name"
                :placeholder="t('account.factors.totpNamePlaceholder')"
                class="w-full px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-500"
              />
            </div>
            <div class="mt-2">
              <label class="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">{{ t('account.factors.totpCodeLabel') }}</label>
              <form class="flex flex-wrap items-center gap-2" @submit.prevent="verifyTotpEnroll">
                <input
                  v-model="totpCode"
                  type="text"
                  inputmode="numeric"
                  autocomplete="one-time-code"
                  maxlength="6"
                  data-testid="factor-totp-code"
                  placeholder="000000"
                  class="w-32 px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm font-mono text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-500"
                />
                <button
                  type="submit"
                  :disabled="busy || !/^\d{6}$/.test(totpCode.trim())"
                  data-testid="factor-totp-activate"
                  class="shrink-0 px-4 py-2 rounded-lg text-sm font-medium bg-brand-600 text-white hover:bg-brand-700 transition-colors disabled:opacity-50"
                >{{ t('account.factors.totpActivate') }}</button>
                <button
                  type="button"
                  data-testid="factor-totp-cancel"
                  class="shrink-0 px-3 py-2 rounded-lg text-xs font-medium border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-700 transition-colors"
                  @click="cancelTotp"
                >{{ t('account.profile.cancel') }}</button>
              </form>
            </div>
          </div>
        </div>
      </div>

      <button
        v-if="emailVerified && !totpEnroll"
        type="button"
        data-testid="factor-totp-add"
        class="px-4 py-2 rounded-lg text-sm font-medium border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-900 dark:text-white hover:bg-slate-50 dark:hover:bg-slate-700 transition-colors"
        @click="startTotp"
      >{{ t('account.factors.totpAdd') }}</button>
    </div>

    <!-- ── The recovery codes ── -->
    <div data-testid="factors-recovery">
      <h3 class="text-xs font-semibold text-slate-700 dark:text-slate-200 mb-2">{{ t('account.factors.recoveryTitle') }}</h3>
      <p class="text-xs text-slate-500 dark:text-slate-400 mb-2" data-testid="factors-recovery-state">
        <template v-if="factors && factors.recoveryCodes.total > 0">
          {{ t('account.factors.recoveryState', { remaining: factors.recoveryCodes.remaining, total: factors.recoveryCodes.total, date: fmtDate(factors.recoveryCodes.createdAt!) }) }}
        </template>
        <template v-else>{{ t('account.factors.recoveryEmpty') }}</template>
      </p>
      <button
        v-if="emailVerified && factors && (factors.passkeys.length + factors.totp.length) > 0"
        type="button"
        :disabled="busy"
        data-testid="factor-recovery-regenerate"
        class="px-4 py-2 rounded-lg text-sm font-medium border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-900 dark:text-white hover:bg-slate-50 dark:hover:bg-slate-700 transition-colors disabled:opacity-50"
        @click="regenerateRecoveryCodes"
      >{{ t('account.factors.recoveryRegenerate') }}</button>
    </div>

    <!-- The shown-once recovery codes dialog. -->
    <div
      v-if="recoveryShown"
      class="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/50 px-4"
      data-testid="factor-recovery-dialog"
      @click.self="recoveryShown = null"
    >
      <div class="w-full max-w-md rounded-xl bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 p-6 shadow-xl">
        <h3 class="text-sm font-semibold text-slate-900 dark:text-white mb-2">{{ t('account.factors.recoveryDialogTitle') }}</h3>
        <p class="text-xs text-slate-500 dark:text-slate-400 mb-4">
          {{ recoveryShown.firstFactor ? t('account.factors.recoveryDialogFirst') : t('account.factors.recoveryDialogRegenerated') }}
        </p>
        <ul class="grid grid-cols-2 gap-2 mb-4" data-testid="factor-recovery-codes">
          <li
            v-for="code in recoveryShown.codes"
            :key="code"
            class="rounded-lg bg-slate-50 dark:bg-slate-900 px-3 py-2 text-center text-sm font-mono text-slate-800 dark:text-slate-100 select-all"
          >{{ code }}</li>
        </ul>
        <div class="flex items-center gap-2">
          <button
            type="button"
            data-testid="factor-recovery-copy"
            class="px-4 py-2 rounded-lg text-sm font-medium border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-700 transition-colors"
            @click="copyRecoveryCodes"
          >{{ recoveryCopied ? t('account.factors.recoveryCopied') : t('account.factors.recoveryCopy') }}</button>
          <button
            type="button"
            data-testid="factor-recovery-dismiss"
            class="px-4 py-2 rounded-lg text-sm font-medium bg-brand-600 text-white hover:bg-brand-700 transition-colors"
            @click="recoveryShown = null"
          >{{ t('account.factors.recoveryDismiss') }}</button>
        </div>
      </div>
    </div>
  </section>
</template>
