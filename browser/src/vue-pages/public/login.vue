<script setup lang="ts">
// ═══════════════════════════════════════════════════════════════════
// The OP-posture sign-in page (the extraction map's OP/RP hybrid split,
// smart's PROGRESS/41 §5): the monorepo's login.vue served both
// postures; this fork keeps the OP half only — the OP password form
// (POST /api/op/login), the upstream-provider sign-in rows (the OP's
// registry), the self-service reset, the join intake link. The RP
// surface (the SSO button, the instance-level GitHub button, the demo
// cast grid, the guided-demo entry) is the platform's copy and stays
// with the monorepo.
//
// The demo FALLBACK stays: when the deployment keeps the demo cast (the
// development/e2e posture, the identity preview), a refused password
// sign-in retries against POST /api/auth/demo — one form, two account
// kinds; the refusal text never distinguishes them.
//
// TODO.identity-sso/02+03 (the strong-authentication wave): the passkey
// button beside the password form (the passwordless ceremony), the
// conditional-UI passkey autofill on the email field as the progressive
// enhancement, and the SECOND-FACTOR step when the account holds factors
// (the TOTP code, the passkey assertion, or a recovery code — the user's
// choice; routes/op-mfa.ts's pending challenge carries it).
// ═══════════════════════════════════════════════════════════════════
import { ref, onMounted, onUnmounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import BrandLogo from '../../components/BrandLogo.vue'
import { useBranding } from '../../branding'
import { t } from '../../i18n'
import {
  assertPasskey,
  conditionalUiAvailable,
  webauthnAvailable,
  type AssertionOptionsJson,
  type CredentialJson,
} from '../../webauthn'

const route = useRoute()
const router = useRouter()
const { branding } = useBranding()

const loading = ref(true)
const error = ref<string | null>(null)
const email = ref('')
const password = ref('')
const submitting = ref(false)

// The deployment's demo posture (from /api/config's public projection):
// the demo-cast fallback for the password form exists only while the
// deployment keeps the cast (DEMO_ACCOUNTS_ENABLED / the profile's
// demo_personas flag).
const demoEnabled = ref(false)
// The OP's upstream providers: the enabled registry rows render as
// sign-in buttons (GitHub, Google, Apple, Entra, a generic OIDC — the
// OP's sign-in methods).
const upstreamProviders = ref<Array<{ id: string; kind: string; displayName: string; brandMark: string | null }>>([])
// The self-service password reset (POST /api/op/login/reset): the
// "Forgot your password?" panel. The answer is the honest constant ("if
// an account exists…"), or the 503's plain explanation when the
// deployment carries no mailer.
const resetOpen = ref(false)
const resetEmail = ref('')
const resetBusy = ref(false)
const resetDone = ref<string | null>(null)
const resetError = ref<string | null>(null)

// ── the strong-authentication state (TODO.identity-sso/02+03) ────────
// The password answer's mfaRequired branch: the pending second-factor
// challenge. The page swaps the password form for the factor step.
const mfa = ref<{ token: string; methods: { totp: boolean; passkey: boolean; recovery: boolean } } | null>(null)
const mfaCode = ref('')
const mfaBusy = ref(false)
const mfaShowRecovery = ref(false)
const recoveryCode = ref('')
/** The passkey sign-in's availability (the button hides where the
 *  browser has no WebAuthn — an old browser is not an error). */
const passkeysSupported = webauthnAvailable()
const passkeyBusy = ref(false)

/** The post-login destination (the authorize flow's re-entry target). */
function redirectTarget(): string {
  return (route.query.redirect as string) || '/op/home'
}

/** A completed sign-in's landing (the session cookie is set by then). */
function landSignedIn() {
  router.replace(redirectTarget())
}

// The upstream provider outcomes (server/routes/op-upstream.ts). THE
// MATCH RULE's refusal is upstream_not_linked: the provider
// authenticated you, but no OIML SMART account is linked to that
// identity — we never match by email.
const upstreamError = (key: string, provider: string): string | null => {
  const name = provider || 'the provider'
  const messages: Record<string, string> = {
    upstream_unknown: 'That sign-in method is not available on this service. Contact your administrator.',
    upstream_not_linked: `Your ${name} account is not linked to an OIML SMART account — ask your administrator, or sign in another way and link it from your account page.`,
    upstream_refused: `${name} did not complete the sign-in (access was declined). Please try again.`,
    upstream_state: 'Your sign-in session expired or did not match. Please try again.',
    upstream_config: `${name} sign-in is not configured correctly on this server. Contact your administrator.`,
    upstream_discovery: `${name} sign-in configuration could not be read. Contact your administrator.`,
    upstream_issuer_mismatch: `${name} answered with an unexpected identity. Contact your administrator.`,
    upstream_exchange: `${name} did not complete the sign-in. Please try again — if it keeps failing, contact your administrator.`,
    upstream_token_malformed: `${name}'s response could not be read. Contact your administrator.`,
    upstream_token_alg: `${name} signed its response with an unsupported algorithm. Contact your administrator.`,
    upstream_token_signature: `${name}'s response could not be verified, so the sign-in was refused. Contact your administrator.`,
    upstream_token_issuer: `${name}'s response came from an unexpected issuer, so the sign-in was refused. Contact your administrator.`,
    upstream_token_audience: `${name}'s response was not issued for this application, so the sign-in was refused. Contact your administrator.`,
    upstream_token_expired: `${name}'s response had expired. Please try again.`,
    upstream_token_nonce: 'The sign-in response did not match the request, so the sign-in was refused. Please try again.',
  }
  return messages[key] ?? null
}

onMounted(async () => {
  const errorKey = route.query.error as string | undefined
  const upstreamProviderName = (route.query.provider as string | undefined) ?? ''
  if (errorKey && upstreamError(errorKey, upstreamProviderName)) {
    error.value = upstreamError(errorKey, upstreamProviderName)!
  } else if (errorKey) {
    error.value = 'Sign-in failed. Please try again — if it keeps failing, contact your administrator.'
  }

  try {
    const res = await fetch('/api/config')
    if (res.ok) {
      const cfg = await res.json() as { identity?: { demoAccountsEnabled?: boolean } }
      demoEnabled.value = cfg.identity?.demoAccountsEnabled !== false
    }
  } catch { demoEnabled.value = true /* the offline posture keeps the demo path */ }

  // The OP's enabled upstream providers.
  try {
    const res = await fetch('/api/op/providers/public')
    if (res.ok) {
      const list = await res.json() as Array<{ id: string; kind: string; displayName: string; brandMark: string | null }>
      upstreamProviders.value = Array.isArray(list) ? list : []
    }
  } catch { /* a registry read failure renders no extra buttons */ }

  // An existing session skips the form: the authorize flow's re-entry
  // target, else the SSO home (the launcher's post-login landing).
  try {
    const res = await fetch('/api/auth/session', { credentials: 'include' })
    if (res.ok) {
      router.replace(redirectTarget())
      return
    }
  } catch { /* no session — the form renders */ }
  loading.value = false
  // The conditional-UI passkey autofill (the progressive enhancement):
  // the email field offers the device's passkeys directly.
  void startConditionalUi()
})

// The OP's upstream provider button: the flow starts at the OP's
// sign-in endpoint, carrying the page's post-login redirect (the OIDC
// re-entry when the sign-in is mid-flow for a relying party).
function upstreamLogin(providerId: string) {
  const redirect = route.query.redirect as string | undefined
  const suffix = redirect ? `?redirect=${encodeURIComponent(redirect)}` : ''
  window.location.href = `/op/upstream/${encodeURIComponent(providerId)}/signin${suffix}`
}

/** The identity provider's own sign-in: the password account against
 *  POST /api/op/login. Lands on the redirect target (the authorize
 *  flow's re-entry) or the SSO home (the launcher's post-login
 *  landing). When the deployment keeps the DEMO cast alongside (the
 *  development/e2e/preview posture), a refused password sign-in falls
 *  back to the demo endpoint — one form, two account kinds; the refusal
 *  text never distinguishes them.
 *
 *  flow's re-entry) or the account page. When the deployment keeps the
 *  DEMO cast alongside (the development/e2e/preview posture), a refused
 *  password sign-in falls back to the demo endpoint — one form, two
 *  account kinds; the refusal text never distinguishes them.
 *
 *  TODO.identity-sso/03: an account holding factors answers
 *  `mfaRequired` + the one-time challenge token instead of a session —
 *  the page swaps to the factor step (below). */
async function submitOpLogin() {
  abortConditionalUi() // the form wins over the passkey autofill
  const res = await fetch('/api/op/login', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify({ email: email.value, password: password.value }),
  })
  if (res.ok) {
    const body = await res.json().catch(() => null) as {
      mfaRequired?: boolean
      mfaToken?: string
      methods?: { totp: boolean; passkey: boolean; recovery: boolean }
    } | null
    if (body?.mfaRequired && body.mfaToken && body.methods) {
      // The password branch won: the pending conditional-UI autofill must
      // not answer over the factor step (the factor ceremony is now the
      // active one).
      abortConditionalUi()
      mfa.value = { token: body.mfaToken, methods: body.methods }
      mfaCode.value = ''
      recoveryCode.value = ''
      mfaShowRecovery.value = false
      return
    }
    landSignedIn()
    return
  }
  if (res.status === 401 && demoEnabled.value) {
    // The demo cast signs in through the demo endpoint (the server-side
    // demo gate still applies).
    const demoRes = await fetch('/api/auth/demo', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ email: email.value, password: password.value }),
    })
    if (demoRes.ok) {
      landSignedIn()
      return
    }
  }
  const body = await res.json().catch(() => null) as { error?: string } | null
  if (res.status === 403 && body?.error) {
    error.value = body.error // the deactivated account's honest message
  } else if (res.status === 401) {
    error.value = 'Invalid email or password.'
  } else {
    error.value = body?.error ?? 'Sign-in failed. Please try again.'
  }
}

async function submitLogin() {
  submitting.value = true
  error.value = null
  try {
    await submitOpLogin()
  } catch {
    error.value = 'Network error. Is the server running?'
  } finally {
    submitting.value = false
  }
}

// ── the second-factor step (TODO.identity-sso/03) ────────────────────

/** The factor step's error mapping: the honest 401 (try again), the
 *  throttle's 429 (the backoff, or the locked burn), the expired
 *  challenge's restart. */
function mfaErrorFrom(res: Response, body: { error?: string; locked?: boolean } | null) {
  if (res.status === 429) {
    error.value = body?.error ?? t('login.mfa.throttled')
    if (body?.locked) mfa.value = null // the burned attempt: back to the password form
  } else if (body?.error) {
    error.value = body.error
    if (res.status === 401 && /expired|already completed/i.test(body.error)) mfa.value = null
  } else {
    error.value = t('login.mfa.failed')
  }
}

/** The TOTP code against the pending challenge. */
async function submitMfaTotp() {
  if (mfaBusy.value || !mfa.value) return
  mfaBusy.value = true
  error.value = null
  try {
    const res = await fetch('/api/op/login/mfa/totp', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ token: mfa.value.token, code: mfaCode.value.trim() }),
    })
    if (res.ok) { landSignedIn(); return }
    mfaErrorFrom(res, await res.json().catch(() => null))
  } catch {
    error.value = 'Network error. Is the server running?'
  } finally {
    mfaBusy.value = false
  }
}

/** A recovery code against the pending challenge (the account-recovery
 *  floor — one-time each). */
async function submitMfaRecovery() {
  if (mfaBusy.value || !mfa.value) return
  mfaBusy.value = true
  error.value = null
  try {
    const res = await fetch('/api/op/login/mfa/recovery', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ token: mfa.value.token, code: recoveryCode.value }),
    })
    if (res.ok) { landSignedIn(); return }
    mfaErrorFrom(res, await res.json().catch(() => null))
  } catch {
    error.value = 'Network error. Is the server running?'
  } finally {
    mfaBusy.value = false
  }
}

/** The passkey as the second factor (the account's credentials only). */
async function submitMfaPasskey() {
  if (mfaBusy.value || !mfa.value) return
  abortConditionalUi() // one pending get at a time
  mfaBusy.value = true
  error.value = null
  try {
    const optRes = await fetch('/api/op/login/mfa/passkey/options', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ token: mfa.value.token }),
    })
    if (!optRes.ok) { mfaErrorFrom(optRes, await optRes.json().catch(() => null)); mfaBusy.value = false; return }
    const { publicKey } = await optRes.json() as { publicKey: AssertionOptionsJson }
    let credential: CredentialJson
    try {
      credential = await assertPasskey(publicKey)
    } catch {
      error.value = t('login.mfa.passkeyCancelled')
      mfaBusy.value = false
      return
    }
    const res = await fetch('/api/op/login/mfa/passkey', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ token: mfa.value.token, credential }),
    })
    if (res.ok) { landSignedIn(); return }
    mfaErrorFrom(res, await res.json().catch(() => null))
  } catch {
    error.value = 'Network error. Is the server running?'
  } finally {
    mfaBusy.value = false
  }
}

/** Abandon the factor step (the challenge expires server-side; the page
 *  returns to the password form). */
function cancelMfa() {
  mfa.value = null
  error.value = null
}

// ── the passwordless passkey sign-in (TODO.identity-sso/02) ──────────

/** The passwordless ceremony's shared finish: the assertion against the
 *  passwordless endpoint. */
async function finishPasswordless(credential: CredentialJson) {
  const res = await fetch('/api/op/login/passkey', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify({ credential }),
  })
  if (res.ok) { landSignedIn(); return }
  const body = await res.json().catch(() => null) as { error?: string } | null
  error.value = body?.error ?? t('login.passkeyFailed')
}

/** The passkey button: the discoverable assertion ceremony. */
async function signInWithPasskey() {
  if (passkeyBusy.value) return
  abortConditionalUi() // the button wins over the autofill wait (one pending get at a time)
  passkeyBusy.value = true
  error.value = null
  try {
    const optRes = await fetch('/api/op/login/passkey/options', { method: 'POST', credentials: 'include' })
    if (!optRes.ok) {
      error.value = t('login.passkeyFailed')
      passkeyBusy.value = false
      return
    }
    const { publicKey } = await optRes.json() as { publicKey: AssertionOptionsJson }
    let credential: CredentialJson
    try {
      credential = await assertPasskey(publicKey)
    } catch {
      error.value = t('login.mfa.passkeyCancelled')
      passkeyBusy.value = false
      return
    }
    await finishPasswordless(credential)
  } catch {
    error.value = 'Network error. Is the server running?'
  } finally {
    passkeyBusy.value = false
  }
}

// The conditional-UI autofill: on a browser that offers it, the email
// field's autofill can answer a passkey directly. The wait is aborted
// when the password form or the passkey button wins.
const conditionalUiAbort = ref<AbortController | null>(null)

function abortConditionalUi() {
  conditionalUiAbort.value?.abort()
  conditionalUiAbort.value = null
}

async function startConditionalUi() {
  if (!(await conditionalUiAvailable())) return
  const controller = new AbortController()
  conditionalUiAbort.value = controller
  try {
    const optRes = await fetch('/api/op/login/passkey/options', { method: 'POST', credentials: 'include' })
    if (!optRes.ok || controller.signal.aborted) return
    const { publicKey } = await optRes.json() as { publicKey: AssertionOptionsJson }
    const credential = await assertPasskey(publicKey, { mediation: 'conditional', signal: controller.signal })
    if (controller.signal.aborted) return
    await finishPasswordless(credential)
  } catch {
    // A conditional-UI wait that never resolves, the user dismissing the
    // autofill, or the abort — all silent: the password form stands.
  }
}

onUnmounted(() => abortConditionalUi())

/** The self-service reset request. The panel prefills the form's email;
 *  the response's own words render (the constant 200 answer, or the
 *  no-mailer 503's explanation) — the page adds nothing of its own, so
 *  it can never leak more than the route does. */
async function submitReset() {
  if (resetBusy.value) return
  resetBusy.value = true
  resetDone.value = null
  resetError.value = null
  try {
    const res = await fetch('/api/op/login/reset', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ email: resetEmail.value }),
    })
    const body = await res.json().catch(() => null) as { message?: string; error?: string } | null
    if (res.ok) {
      resetDone.value = body?.message ?? 'If an account exists for that address, a password reset email is on its way.'
    } else {
      resetError.value = body?.error ?? 'The reset could not be requested. Please try again.'
    }
  } catch {
    resetError.value = 'Network error. Is the server running?'
  } finally {
    resetBusy.value = false
  }
}
</script>

<template>
  <div class="flex-1 flex items-center justify-center px-4 py-12">
    <!-- Loading state -->
    <div v-if="loading" class="flex flex-col items-center gap-4">
      <div class="w-8 h-8 border-2 border-brand-300 border-t-brand-600 rounded-full animate-spin" />
    </div>

    <!-- Login card -->
    <div v-else class="w-full max-w-sm">
      <div class="text-center mb-8">
        <BrandLogo kind="logo" class="h-10 mx-auto mb-4" />
        <h1 class="text-xl font-serif font-bold text-slate-900 dark:text-white">Sign in to {{ branding.productName }}</h1>
        <p v-if="branding.loginTagline" data-testid="login-tagline" class="mt-2 text-sm text-slate-500 dark:text-slate-400">{{ branding.loginTagline }}</p>
      </div>

      <!-- Error -->
      <div v-if="error" class="mb-4 p-3 rounded-lg bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800">
        <p class="text-sm text-red-700 dark:text-red-300" data-testid="login-error">{{ error }}</p>
      </div>

      <!-- The OP's upstream providers (the registry, enabled rows only):
           GitHub, Google, Apple, Entra, a generic OIDC — each runs its
           flow at the OP and resolves by (provider, account id), never
           by email. -->
      <div v-if="upstreamProviders.length" class="space-y-2 mb-6">
        <button
          v-for="provider in upstreamProviders"
          :key="provider.id"
          :data-testid="`upstream-login-${provider.id}`"
          @click="upstreamLogin(provider.id)"
          class="w-full py-2.5 rounded-lg text-sm font-medium border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-900 dark:text-white hover:bg-slate-50 dark:hover:bg-slate-700 transition-colors flex items-center justify-center gap-2"
        >
          <svg v-if="provider.brandMark === 'github'" class="w-4 h-4" viewBox="0 0 24 24" fill="currentColor"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z"/></svg>
          <svg v-else-if="provider.brandMark === 'google'" class="w-4 h-4" viewBox="0 0 24 24"><path fill="#4285F4" d="M23.49 12.27c0-.79-.07-1.54-.19-2.27H12v4.51h6.47c-.29 1.48-1.14 2.73-2.4 3.58v3h3.86c2.26-2.09 3.56-5.17 3.56-8.82z"/><path fill="#34A853" d="M12 24c3.24 0 5.95-1.08 7.93-2.91l-3.86-3c-1.08.72-2.45 1.16-4.07 1.16-3.13 0-5.78-2.11-6.73-4.96H1.29v3.09C3.26 21.3 7.31 24 12 24z"/><path fill="#FBBC05" d="M5.27 14.29c-.25-.72-.38-1.49-.38-2.29s.14-1.57.38-2.29V6.62H1.29C.47 8.24 0 10.06 0 12s.47 3.76 1.29 5.38l3.98-3.09z"/><path fill="#EA4335" d="M12 4.75c1.77 0 3.35.61 4.6 1.8l3.42-3.42C18.95 1.19 15.24 0 12 0 7.31 0 3.26 2.7 1.29 6.62l3.98 3.09C6.22 6.86 8.87 4.75 12 4.75z"/></svg>
          <svg v-else-if="provider.brandMark === 'apple'" class="w-4 h-4" viewBox="0 0 24 24"><path fill="currentColor" d="M17.05 20.28c-.98.95-2.05.8-3.08.35-1.09-.46-2.09-.48-3.24 0-1.44.62-2.2.44-3.06-.35C2.79 15.25 3.51 7.59 9.05 7.31c1.35.07 2.29.74 3.08.8.98-.2 1.92-.86 3.24-.77 1.58.13 2.76.74 3.53 1.87-3.25 1.94-2.71 6.23.55 7.42-.65 1.69-1.49 3.36-2.4 3.65M12.03 7.25c-.15-2.23 1.66-4.07 3.74-4.25.29 2.58-2.34 4.5-3.74 4.25"/></svg>
          <svg v-else-if="provider.brandMark === 'microsoft'" class="w-4 h-4" viewBox="0 0 24 24"><path fill="#f35325" d="M1 1h10v10H1z"/><path fill="#81bc06" d="M13 1h10v10H13z"/><path fill="#05a6f0" d="M1 13h10v10H1z"/><path fill="#ffba08" d="M13 13h10v10H13z"/></svg>
          <svg v-else class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4"/><polyline points="10 17 15 12 10 7"/><line x1="15" y1="12" x2="3" y2="12"/></svg>
          Sign in with {{ provider.displayName }}
        </button>
      </div>

      <!-- The OP's account sign-in form (always present — the identity
           provider always has its account form). Swaps for the factor
           step when the account holds factors (TODO.identity-sso/03). -->
      <template v-if="mfa">
        <div class="space-y-3" data-testid="login-mfa">
          <p class="text-sm text-slate-600 dark:text-slate-300">{{ t('login.mfa.prompt') }}</p>

          <!-- The authenticator code (the user's choice when both exist). -->
          <form v-if="mfa.methods.totp" class="flex items-center gap-2" @submit.prevent="submitMfaTotp">
            <input
              v-model="mfaCode"
              type="text"
              inputmode="numeric"
              autocomplete="one-time-code"
              maxlength="6"
              data-testid="login-mfa-code"
              :placeholder="t('login.mfa.codePlaceholder')"
              class="flex-1 px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm font-mono text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-500"
            />
            <button
              type="submit"
              :disabled="mfaBusy || !/^\d{6}$/.test(mfaCode.trim())"
              data-testid="login-mfa-submit"
              class="shrink-0 px-4 py-2 rounded-lg text-sm font-medium bg-brand-600 text-white hover:bg-brand-700 transition-colors disabled:opacity-50"
            >{{ mfaBusy ? t('login.mfa.busy') : t('login.mfa.verify') }}</button>
          </form>

          <button
            v-if="mfa.methods.passkey"
            type="button"
            :disabled="mfaBusy"
            data-testid="login-mfa-passkey"
            class="w-full py-2.5 rounded-lg text-sm font-medium border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-900 dark:text-white hover:bg-slate-50 dark:hover:bg-slate-700 transition-colors disabled:opacity-50"
            @click="submitMfaPasskey"
          >{{ t('login.mfa.usePasskey') }}</button>

          <!-- The recovery floor (one-time codes; the email reset stands
               behind everything). -->
          <div v-if="mfa.methods.recovery">
            <p v-if="!mfaShowRecovery" class="text-center">
              <button
                type="button"
                data-testid="login-mfa-recovery-toggle"
                class="text-xs text-brand-600 dark:text-brand-300 hover:underline"
                @click="mfaShowRecovery = true"
              >{{ t('login.mfa.useRecovery') }}</button>
            </p>
            <form v-else class="flex items-center gap-2" @submit.prevent="submitMfaRecovery">
              <input
                v-model="recoveryCode"
                type="text"
                data-testid="login-mfa-recovery-code"
                :placeholder="t('login.mfa.recoveryPlaceholder')"
                class="flex-1 px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm font-mono text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-500"
              />
              <button
                type="submit"
                :disabled="mfaBusy"
                data-testid="login-mfa-recovery-submit"
                class="shrink-0 px-4 py-2 rounded-lg text-sm font-medium bg-brand-600 text-white hover:bg-brand-700 transition-colors disabled:opacity-50"
              >{{ mfaBusy ? t('login.mfa.busy') : t('login.mfa.recoverySubmit') }}</button>
            </form>
          </div>

          <p class="text-center">
            <button
              type="button"
              data-testid="login-mfa-cancel"
              class="text-xs text-slate-400 dark:text-slate-500 hover:underline"
              @click="cancelMfa"
            >{{ t('login.mfa.cancel') }}</button>
          </p>
        </div>
      </template>

      <template v-else>
      <!-- The passwordless passkey button (TODO.identity-sso/02): beside
           the password form, and the email field carries the conditional
           autofill where the browser offers it. -->
      <div v-if="passkeysSupported" class="mb-4">
        <button
          type="button"
          :disabled="passkeyBusy"
          data-testid="login-passkey"
          class="w-full py-2.5 rounded-lg text-sm font-medium border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-900 dark:text-white hover:bg-slate-50 dark:hover:bg-slate-700 transition-colors flex items-center justify-center gap-2 disabled:opacity-50"
          @click="signInWithPasskey"
        >
          <svg class="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/><circle cx="12" cy="16" r="1"/></svg>
          {{ passkeyBusy ? t('login.passkeyBusy') : t('login.passkeyButton') }}
        </button>
        <div class="flex items-center gap-3 mt-4 mb-1" aria-hidden="true">
          <div class="flex-1 border-t border-slate-200 dark:border-slate-700" />
          <span class="text-[10px] uppercase tracking-wider text-slate-400 dark:text-slate-500">{{ t('login.passkeyOr') }}</span>
          <div class="flex-1 border-t border-slate-200 dark:border-slate-700" />
        </div>
      </div>

      <form @submit.prevent="submitLogin" class="space-y-3">
        <div>
          <label class="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">Email</label>
          <input
            v-model="email"
            type="email"
            required
            autocomplete="username webauthn"
            data-testid="login-email"
            class="w-full px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-500"
            placeholder="you@example.org"
          />
        </div>
        <div>
          <label class="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">Password</label>
          <input
            v-model="password"
            type="password"
            required
            data-testid="login-password"
            class="w-full px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-500"
            placeholder="your account password"
          />
        </div>
        <button
          type="submit"
          :disabled="submitting"
          data-testid="login-submit"
          class="w-full py-2 rounded-lg text-sm font-medium bg-brand-600 text-white hover:bg-brand-700 transition-colors disabled:opacity-50 flex items-center justify-center gap-2"
        >
          <div v-if="submitting" class="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
          {{ submitting ? 'Signing in…' : 'Sign in' }}
        </button>
      </form>

      <!-- The self-service password reset. The route's own words render;
           the page never adds an existence hint of its own. -->
      <div class="mt-3">
        <p v-if="!resetOpen" class="text-center">
          <button
            type="button"
            data-testid="login-forgot"
            class="text-xs text-brand-600 dark:text-brand-300 hover:underline"
            @click="resetOpen = true; resetEmail = email; resetDone = null; resetError = null"
          >Forgot your password?</button>
        </p>
        <div v-else class="rounded-lg border border-slate-200 dark:border-slate-700 p-3" data-testid="login-reset">
          <template v-if="!resetDone">
            <p class="text-xs text-slate-500 dark:text-slate-400 mb-2">
              Enter your account's email address; the identity service emails a one-time reset link (24 hours).
            </p>
            <form class="flex items-center gap-2" @submit.prevent="submitReset">
              <input
                v-model="resetEmail"
                type="email"
                required
                data-testid="login-reset-email"
                class="flex-1 px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-500"
                placeholder="you@example.org"
              />
              <button
                type="submit"
                :disabled="resetBusy"
                data-testid="login-reset-submit"
                class="shrink-0 px-3 py-2 rounded-lg text-xs font-medium bg-brand-600 text-white hover:bg-brand-700 transition-colors disabled:opacity-50"
              >{{ resetBusy ? 'Sending…' : 'Send the reset email' }}</button>
            </form>
            <p v-if="resetError" class="mt-2 text-xs text-red-600 dark:text-red-400" data-testid="login-reset-error">{{ resetError }}</p>
          </template>
          <p v-else class="text-xs text-green-700 dark:text-green-300" data-testid="login-reset-done">{{ resetDone }}</p>
        </div>
      </div>

      <!-- The self-service join intake: request an account naming your
           organization from the participants register; approval comes
           from your organization. -->
      <p class="mt-4 text-center text-xs text-slate-400 dark:text-slate-500" data-testid="login-join">
        No account yet?
        <router-link to="/op/join" class="text-brand-600 dark:text-brand-300 hover:underline" data-testid="login-join-link">Request an account</router-link>
        — approval comes from your organization.
      </p>

      <p v-if="branding.supportUrl" class="mt-4 text-center text-xs text-slate-400 dark:text-slate-500">
        Need help? <a :href="branding.supportUrl" target="_blank" rel="noopener" data-testid="login-support" class="text-brand-600 dark:text-brand-300 hover:underline">Contact support</a>
      </p>
      </template>
    </div>
  </div>
</template>
