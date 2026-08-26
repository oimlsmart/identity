<script setup lang="ts">
// ═══════════════════════════════════════════════════════════════════
// The upstream provider registry's minimal admin surface
// (TODO.identity/08) — the honest form until TODO.identity/07's full
// console lands: list the providers, create/edit a row, the enable
// toggle, delete. The registry IS the configuration: adding a provider
// is a row, never a code fork.
//
// The secret discipline is visible in the form: the client secret is
// never typed here — `client_secret_ref` names an environment variable
// ('env:<NAME>'), resolved server-side per request.
// ═══════════════════════════════════════════════════════════════════
import { ref, onMounted } from 'vue'
import PageHeader from '../../components/PageHeader.vue'

interface ProviderRow {
  id: string
  kind: 'github' | 'oidc'
  displayName: string
  brandMark: string | null
  issuer: string | null
  clientId: string
  clientSecretRef: string | null
  scopes: string | null
  enabled: boolean
  apple: boolean
  createdAt: string
  createdBy: string | null
  updatedAt: string | null
}

const BRAND_MARKS = ['github', 'google', 'apple', 'microsoft', 'oidc']

const loading = ref(true)
const forbidden = ref(false)
const error = ref<string | null>(null)
const problems = ref<string[]>([])
const notice = ref<string | null>(null)
const rows = ref<ProviderRow[]>([])
const saving = ref(false)

// The form's working state (an empty form = the create posture; picking
// a row's "edit" fills it — the id locks, the rest is the upsert).
const form = ref({
  id: '',
  kind: 'oidc' as 'github' | 'oidc',
  display_name: '',
  brand_mark: '',
  issuer: '',
  client_id: '',
  client_secret_ref: '',
  scopes: '',
  enabled: false,
})
const editing = ref<string | null>(null)

function resetForm() {
  editing.value = null
  form.value = { id: '', kind: 'oidc', display_name: '', brand_mark: '', issuer: '', client_id: '', client_secret_ref: '', scopes: '', enabled: false }
}

function editRow(row: ProviderRow) {
  editing.value = row.id
  form.value = {
    id: row.id,
    kind: row.kind,
    display_name: row.displayName,
    brand_mark: row.brandMark ?? '',
    issuer: row.issuer ?? '',
    client_id: row.clientId,
    client_secret_ref: row.clientSecretRef ?? '',
    scopes: row.scopes ?? '',
    enabled: row.enabled,
  }
}

async function load(): Promise<void> {
  const res = await fetch('/api/op/providers', { credentials: 'include' })
  if (res.status === 401) {
    window.location.assign(`/?redirect=${encodeURIComponent('/op/admin/providers')}`)
    return
  }
  if (res.status === 403) {
    forbidden.value = true
    return
  }
  if (!res.ok) throw new Error(`HTTP ${res.status}`)
  rows.value = await res.json() as ProviderRow[]
}

onMounted(async () => {
  try {
    await load()
  } catch (err) {
    error.value = `The registry could not be loaded: ${(err as Error).message}`
  } finally {
    loading.value = false
  }
})

async function save() {
  if (saving.value) return
  saving.value = true
  error.value = null
  problems.value = []
  notice.value = null
  try {
    const res = await fetch('/api/op/providers', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({
        id: form.value.id,
        kind: form.value.kind,
        display_name: form.value.display_name,
        brand_mark: form.value.brand_mark || null,
        issuer: form.value.issuer || null,
        client_id: form.value.client_id,
        client_secret_ref: form.value.client_secret_ref || null,
        scopes: form.value.scopes || null,
        enabled: form.value.enabled,
      }),
    })
    const body = await res.json().catch(() => null) as { problems?: string[]; error?: string } | null
    if (!res.ok) {
      problems.value = body?.problems ?? []
      error.value = body?.error ?? 'The save was refused.'
      return
    }
    notice.value = editing.value ? `Provider ${form.value.id} updated.` : `Provider ${form.value.id} registered.`
    resetForm()
    await load()
  } catch (err) {
    error.value = `Network error: ${(err as Error).message}`
  } finally {
    saving.value = false
  }
}

async function toggle(row: ProviderRow) {
  const res = await fetch(`/api/op/providers/${encodeURIComponent(row.id)}/status`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify({ enabled: !row.enabled }),
  })
  if (res.ok) await load()
  else error.value = `The enable toggle on ${row.id} was refused.`
}

async function remove(row: ProviderRow) {
  if (!window.confirm(`Remove the provider "${row.displayName}" (${row.id})? Linked identities are kept but its sign-ins stop working.`)) return
  const res = await fetch(`/api/op/providers/${encodeURIComponent(row.id)}`, { method: 'DELETE', credentials: 'include' })
  if (res.ok) {
    notice.value = `Provider ${row.id} removed.`
    if (editing.value === row.id) resetForm()
    await load()
  } else {
    error.value = `The removal of ${row.id} was refused.`
  }
}
</script>

<template>
  <div class="max-w-3xl mx-auto px-6 py-10 w-full">
    <!-- Loading state -->
    <div v-if="loading" class="flex flex-col items-center gap-4 py-24">
      <div class="w-8 h-8 border-2 border-brand-300 border-t-brand-600 rounded-full animate-spin" />
    </div>

    <!-- The honest refusal (the API's 403) -->
    <div v-else-if="forbidden" class="max-w-md mx-auto py-16">
      <div class="text-center mb-8">
        <h1 class="text-xl font-serif font-bold text-slate-900 dark:text-white">Sign-in providers</h1>
      </div>
      <div class="p-3 rounded-lg bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800">
        <p class="text-sm text-amber-800 dark:text-amber-300" data-testid="op-providers-forbidden">
          The provider registry is an administrator surface — your account does not hold the administrator role.
        </p>
      </div>
    </div>

    <div v-else data-testid="op-providers">
      <PageHeader
        title="Sign-in providers"
        description="The upstream registry — GitHub, Google, Apple, Entra, generic OIDC. Enabled rows render on the sign-in page."
      />

      <div v-if="error" class="mb-4 p-3 rounded-lg bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800">
        <p class="text-sm text-red-700 dark:text-red-300" data-testid="op-providers-error">{{ error }}</p>
        <ul v-if="problems.length" class="mt-1 list-disc list-inside text-xs text-red-600 dark:text-red-400" data-testid="op-providers-problems">
          <li v-for="problem in problems" :key="problem">{{ problem }}</li>
        </ul>
      </div>
      <div v-if="notice" class="mb-4 p-3 rounded-lg bg-emerald-50 dark:bg-emerald-900/20 border border-emerald-200 dark:border-emerald-800">
        <p class="text-sm text-emerald-800 dark:text-emerald-300" data-testid="op-providers-notice">{{ notice }}</p>
      </div>

      <!-- The registry -->
      <div class="rounded-xl border border-slate-200/80 dark:border-slate-700 bg-white dark:bg-slate-800 p-6 mb-6">
        <h2 class="text-xs font-semibold uppercase tracking-wider text-slate-400 dark:text-slate-500 mb-3">Registered providers</h2>
        <p v-if="!rows.length" class="text-sm text-slate-500 dark:text-slate-400" data-testid="op-providers-empty">
          No providers registered yet — create the first one below.
        </p>
        <ul v-else class="space-y-2" data-testid="op-providers-list">
          <li
            v-for="row in rows"
            :key="row.id"
            :data-testid="`op-provider-${row.id}`"
            class="rounded-lg border border-slate-200 dark:border-slate-700 px-3 py-2"
          >
            <div class="flex items-center justify-between gap-3">
              <div class="min-w-0">
                <p class="text-sm font-medium text-slate-900 dark:text-white">
                  {{ row.displayName }}
                  <span class="ml-1 text-[10px] uppercase tracking-wide text-slate-400">{{ row.kind }}<template v-if="row.apple"> · apple</template></span>
                </p>
                <p class="text-[11px] text-slate-400 dark:text-slate-500 truncate">
                  {{ row.id }} · client {{ row.clientId }}<template v-if="row.issuer"> · {{ row.issuer }}</template>
                  <template v-if="row.clientSecretRef"> · secret {{ row.clientSecretRef }}</template>
                  <template v-else> · no secret ref</template>
                </p>
              </div>
              <div class="flex items-center gap-2 shrink-0">
                <button
                  :data-testid="`op-provider-${row.id}-toggle`"
                  @click="toggle(row)"
                  class="text-xs font-medium rounded-md px-2 py-1 border transition-colors"
                  :class="row.enabled
                    ? 'border-emerald-300 dark:border-emerald-700 text-emerald-700 dark:text-emerald-300'
                    : 'border-slate-200 dark:border-slate-600 text-slate-500 dark:text-slate-400'"
                >
                  {{ row.enabled ? 'enabled' : 'disabled' }}
                </button>
                <button :data-testid="`op-provider-${row.id}-edit`" @click="editRow(row)" class="text-xs font-medium text-brand-600 dark:text-brand-300 hover:underline">Edit</button>
                <button :data-testid="`op-provider-${row.id}-delete`" @click="remove(row)" class="text-xs font-medium text-red-600 dark:text-red-400 hover:underline">Delete</button>
              </div>
            </div>
          </li>
        </ul>
      </div>

      <!-- The create/edit form -->
      <form @submit.prevent="save" class="rounded-xl border border-slate-200/80 dark:border-slate-700 bg-white dark:bg-slate-800 p-6 space-y-3" data-testid="op-provider-form">
        <h2 class="text-xs font-semibold uppercase tracking-wider text-slate-400 dark:text-slate-500">
          {{ editing ? `Edit ${editing}` : 'Register a provider' }}
        </h2>
        <div class="grid sm:grid-cols-2 gap-3">
          <div>
            <label class="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">id (slug, rides URLs)</label>
            <input v-model="form.id" :disabled="!!editing" required data-testid="op-provider-field-id" placeholder="google"
              class="w-full px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white disabled:opacity-60" />
          </div>
          <div>
            <label class="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">kind</label>
            <select v-model="form.kind" data-testid="op-provider-field-kind"
              class="w-full px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white">
              <option value="oidc">oidc (Google / Apple / Entra / generic)</option>
              <option value="github">github</option>
            </select>
          </div>
          <div>
            <label class="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">display name</label>
            <input v-model="form.display_name" required data-testid="op-provider-field-name" placeholder="Google"
              class="w-full px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white" />
          </div>
          <div>
            <label class="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">brand mark</label>
            <select v-model="form.brand_mark" data-testid="op-provider-field-mark"
              class="w-full px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white">
              <option value="">generic</option>
              <option v-for="mark in BRAND_MARKS" :key="mark" :value="mark">{{ mark }}</option>
            </select>
          </div>
          <div class="sm:col-span-2">
            <label class="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">issuer (oidc kind — the discovery root; Apple: https://appleid.apple.com)</label>
            <input v-model="form.issuer" :disabled="form.kind === 'github'" data-testid="op-provider-field-issuer" placeholder="https://accounts.google.com"
              class="w-full px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white disabled:opacity-60" />
          </div>
          <div>
            <label class="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">client id</label>
            <input v-model="form.client_id" required data-testid="op-provider-field-client" placeholder="….apps.googleusercontent.com"
              class="w-full px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white" />
          </div>
          <div>
            <label class="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">client secret ref (never the secret)</label>
            <input v-model="form.client_secret_ref" data-testid="op-provider-field-secret" placeholder="env:GOOGLE_CLIENT_SECRET"
              class="w-full px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white" />
          </div>
          <div class="sm:col-span-2">
            <label class="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">scopes (optional override; defaults per kind)</label>
            <input v-model="form.scopes" data-testid="op-provider-field-scopes" placeholder="openid profile email"
              class="w-full px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white" />
          </div>
        </div>
        <label class="flex items-center gap-2 text-sm text-slate-700 dark:text-slate-300">
          <input v-model="form.enabled" type="checkbox" data-testid="op-provider-field-enabled" class="rounded border-slate-300" />
          Enabled (visible on the sign-in page; flows run)
        </label>
        <div class="flex items-center gap-3">
          <button type="submit" :disabled="saving" data-testid="op-provider-save"
            class="py-2 px-4 rounded-lg text-sm font-medium bg-brand-600 text-white hover:bg-brand-700 transition-colors disabled:opacity-50">
            {{ saving ? 'Saving…' : editing ? 'Save changes' : 'Register provider' }}
          </button>
          <button v-if="editing" type="button" @click="resetForm" class="text-sm text-slate-500 hover:underline">Cancel edit</button>
        </div>
      </form>
    </div>
  </div>
</template>
