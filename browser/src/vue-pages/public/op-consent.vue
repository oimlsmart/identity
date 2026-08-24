<script setup lang="ts">
// ═══════════════════════════════════════════════════════════════════
// The OIDC Provider's consent page (TODO.identity/01) — the identity
// instance's honest gate between sign-in and the code grant: the
// CLIENT's name, the SCOPES requested, the ACCOUNT being shared, and
// allow/deny. Nothing more, nothing hidden.
//
// The page rides the pending-authorization row the authorize endpoint
// created (?auth=<id>): the context endpoint (/api/op/consent/:id)
// answers the client/scopes/account, or bounces the browser to the
// instance's login page (401 + a login URL) when the session is gone.
// The decision POSTs back and navigates to the returned RP redirect —
// allow carries the one-time code, deny carries error=access_denied.
// ═══════════════════════════════════════════════════════════════════
import { ref, onMounted } from 'vue'
import { useRoute } from 'vue-router'
import BrandLogo from '../../components/BrandLogo.vue'

interface ConsentContext {
  id: string
  client: { id: string; name: string }
  scopes: string[]
  /** The extra claims this client's tokens carry (the registry's
   *  claims policy) — shown honestly: the account shares its platform
   *  roles/organization with THIS client, not just its name. */
  policyClaims: string[]
  /** TODO.identity/03 — the EFFECTIVE role set this client's token will
   *  carry for THIS account (the per-client assignment through the
   *  client's policy allowlist); empty = no roles shared. */
  roleClaims?: string[]
  /** The organization binding the token will carry (policy 'org'). */
  orgClaim?: string | null
  account: { name: string; email: string; avatarUrl?: string | null }
  issuer: string
  issuerName: string
}

const route = useRoute()

const loading = ref(true)
const deciding = ref(false)
const error = ref<string | null>(null)
const context = ref<ConsentContext | null>(null)

/** Human labels for the scopes (an unknown scope shows its raw name —
 *  honest, never silently dropped). */
const SCOPE_LABELS: Record<string, string> = {
  openid: 'Sign you in',
  profile: 'Your name',
  email: 'Your email address',
}
const POLICY_CLAIM_LABELS: Record<string, string> = {
  roles: 'Your platform roles',
  groups: 'Your platform roles (as groups)',
  org: 'Your organization binding',
}

function scopeLabel(scope: string): string {
  return SCOPE_LABELS[scope] ?? scope
}

function policyClaimLabel(claim: string): string {
  return POLICY_CLAIM_LABELS[claim] ?? claim
}

onMounted(async () => {
  const id = route.query.auth as string | undefined
  if (!id) {
    error.value = 'This consent page needs an authorization request (no ?auth= parameter). Start the sign-in again.'
    loading.value = false
    return
  }
  try {
    const res = await fetch(`/api/op/consent/${encodeURIComponent(id)}`, { credentials: 'include' })
    if (res.status === 401 || res.status === 403) {
      // No session (or a different account's): the answer carries the
      // login URL with the flow's re-entry target.
      const body = await res.json().catch(() => null) as { login?: string } | null
      window.location.assign(body?.login ?? '/')
      return
    }
    if (!res.ok) {
      const body = await res.json().catch(() => null) as { error_description?: string } | null
      error.value = body?.error_description ?? 'This authorization request is no longer valid. Start the sign-in again.'
      loading.value = false
      return
    }
    context.value = await res.json() as ConsentContext
    loading.value = false
  } catch {
    error.value = 'Network error. Is the server running?'
    loading.value = false
  }
})

async function decide(decision: 'allow' | 'deny') {
  if (!context.value || deciding.value) return
  deciding.value = true
  error.value = null
  try {
    const res = await fetch(`/api/op/consent/${encodeURIComponent(context.value.id)}/decide`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ decision }),
    })
    if (res.status === 401 || res.status === 403) {
      const body = await res.json().catch(() => null) as { login?: string } | null
      window.location.assign(body?.login ?? '/')
      return
    }
    if (!res.ok) {
      const body = await res.json().catch(() => null) as { error_description?: string } | null
      error.value = body?.error_description ?? 'The decision could not be recorded. Start the sign-in again.'
      deciding.value = false
      return
    }
    const { redirect } = await res.json() as { redirect: string }
    window.location.assign(redirect)
  } catch {
    error.value = 'Network error. Is the server running?'
    deciding.value = false
  }
}
</script>

<template>
  <div class="min-h-screen flex items-center justify-center px-4 py-12 bg-cream dark:bg-slate-900">
    <!-- Loading state -->
    <div v-if="loading" class="flex flex-col items-center gap-4">
      <div class="w-8 h-8 border-2 border-brand-300 border-t-brand-600 rounded-full animate-spin" />
    </div>

    <!-- Consent card -->
    <div v-else class="w-full max-w-md" data-testid="op-consent">
      <div class="text-center mb-8">
        <BrandLogo kind="logo" class="h-10 mx-auto mb-4" />
        <h1 class="text-xl font-serif font-bold text-slate-900 dark:text-white">
          {{ context ? context.issuerName : 'Authorize' }}
        </h1>
      </div>

      <!-- Error -->
      <div v-if="error" class="mb-4 p-3 rounded-lg bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800">
        <p class="text-sm text-red-700 dark:text-red-300" data-testid="op-consent-error">{{ error }}</p>
      </div>

      <template v-if="context">
        <div class="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 p-5 mb-6">
          <p class="text-sm text-slate-700 dark:text-slate-200 mb-4" data-testid="op-consent-lead">
            <span class="font-semibold" data-testid="op-consent-client">{{ context.client.name }}</span>
            wants to sign you in with your {{ context.issuerName }} account.
          </p>

          <h2 class="text-xs font-semibold uppercase tracking-wider text-slate-400 dark:text-slate-500 mb-2">Shared with {{ context.client.name }}</h2>
          <ul class="mb-4 space-y-1" data-testid="op-consent-scopes">
            <li
              v-for="scope in context.scopes.filter(s => s !== 'openid')"
              :key="scope"
              class="flex items-center gap-2 text-sm text-slate-700 dark:text-slate-300"
            >
              <svg class="w-3.5 h-3.5 text-brand-600 dark:text-brand-300 shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
              {{ scopeLabel(scope) }}
            </li>
            <li
              v-for="claim in context.policyClaims"
              :key="claim"
              class="flex items-center gap-2 text-sm text-slate-700 dark:text-slate-300"
            >
              <svg class="w-3.5 h-3.5 text-brand-600 dark:text-brand-300 shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
              {{ policyClaimLabel(claim) }}
            </li>
          </ul>
          <!-- TODO.identity/03 — the honest per-client sharing: the
               EXACT roles this client's token carries for this account
               (the registry's per-client assignment through the client's
               policy allowlist), named before anything is released. -->
          <p
            v-if="context.policyClaims.includes('roles') || context.policyClaims.includes('groups')"
            class="mb-4 -mt-2 text-xs text-slate-500 dark:text-slate-400"
            data-testid="op-consent-role-claims"
          >
            <template v-if="context.roleClaims?.length">
              On {{ context.client.name }} you hold: <code class="font-mono" data-testid="op-consent-role-values">{{ context.roleClaims.join(', ') }}</code>
            </template>
            <template v-else>
              You hold no platform roles on {{ context.client.name }} — the service treats you as read-only until its administrator assigns one.
            </template>
          </p>

          <h2 class="text-xs font-semibold uppercase tracking-wider text-slate-400 dark:text-slate-500 mb-2">Signed in as</h2>
          <p class="flex items-center gap-2 text-sm text-slate-700 dark:text-slate-300" data-testid="op-consent-account">
            <img
              v-if="context.account.avatarUrl"
              :src="context.account.avatarUrl"
              :alt="context.account.name"
              class="w-6 h-6 rounded-full object-cover border border-slate-200 dark:border-slate-700"
              data-testid="op-consent-avatar"
            />
            <span class="font-medium">{{ context.account.name }}</span>
            <span class="text-slate-400 dark:text-slate-500"> &lt;{{ context.account.email }}&gt;</span>
          </p>
        </div>

        <div class="flex gap-3">
          <button
            data-testid="op-consent-allow"
            :disabled="deciding"
            @click="decide('allow')"
            class="flex-1 py-2.5 rounded-lg text-sm font-medium bg-brand-600 text-white hover:bg-brand-700 transition-colors disabled:opacity-50 flex items-center justify-center gap-2"
          >
            <div v-if="deciding" class="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
            Allow
          </button>
          <button
            data-testid="op-consent-deny"
            :disabled="deciding"
            @click="decide('deny')"
            class="flex-1 py-2.5 rounded-lg text-sm font-medium border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-900 dark:text-white hover:bg-slate-50 dark:hover:bg-slate-700 transition-colors disabled:opacity-50"
          >
            Deny
          </button>
        </div>

        <p class="mt-4 text-center text-[10px] text-slate-400 dark:text-slate-500">
          Denying returns you to {{ context.client.name }} without sharing anything.
        </p>
      </template>
    </div>
  </div>
</template>
