<script setup lang="ts">
// ═══════════════════════════════════════════════════════════════════
// The relying-party console (TODO.identity/07 over TODO.identity/01's
// oidc_clients registry) — the federation's registered instances: their
// redirect URIs, their claims policy (which claims the ID token carries
// for that client), the enable/disable state, and the registration
// wizard. A confidential client's secret is GENERATED server-side and
// shown exactly ONCE (only its hash survives); the copy affordance is
// the handover.
//
// Every rule is SERVER-ENFORCED (routes/op.ts's registry surface); this
// page only renders what the API answers. The secret never appears in a
// list or detail response — the one showing is the registration's.
// ═══════════════════════════════════════════════════════════════════
import { onMounted, ref } from 'vue'
import BrandLogo from '../../components/BrandLogo.vue'
import OpAdminNav from '../../components/OpAdminNav.vue'
import { useBranding } from '../../branding'

interface ClientRow {
  clientId: string
  name: string
  redirectUris: string[]
  claimsPolicy: { claims: string[]; roles?: string[] } | null
  confidential: boolean
  status: 'active' | 'disabled'
  createdAt: string
  createdBy: string | null
}

const CLAIM_OPTIONS = ['roles', 'groups', 'org']

const { branding } = useBranding()

const loading = ref(true)
const forbidden = ref(false)
const error = ref<string | null>(null)
const notice = ref<string | null>(null)
const rows = ref<ClientRow[]>([])
const saving = ref(false)
/** The role vocabulary for the claims policy's role allowlist
 *  (TODO.identity/03): the instance map's keys. */
const roleOptions = ref<string[]>([])

// The form's working state (an empty form = the registration posture;
// picking a row's "Edit" fills it — the client_id locks, the rest is the
// upsert).
const form = ref({
  client_id: '',
  name: '',
  redirect_uris: '', // one exact URI per line
  claims: [] as string[],
  /** The role allowlist (only meaningful when a role claim is checked);
   *  EMPTY = unbounded (the policy does not bound the role set). */
  roles: [] as string[],
  confidential: true,
})
const editing = ref<string | null>(null)
/** The re-key decision in edit mode: off keeps the stored secret hash. */
const rekey = ref(false)

/** The generated secret, shown ONCE for the registration/re-key that
 *  produced it. Cleared on the next action. */
const lastSecret = ref<{ clientId: string; secret: string } | null>(null)

function resetForm() {
  editing.value = null
  rekey.value = false
  form.value = { client_id: '', name: '', redirect_uris: '', claims: [], roles: [], confidential: true }
}

function editRow(row: ClientRow) {
  editing.value = row.clientId
  rekey.value = false
  lastSecret.value = null
  form.value = {
    client_id: row.clientId,
    name: row.name,
    redirect_uris: row.redirectUris.join('\n'),
    claims: [...(row.claimsPolicy?.claims ?? [])],
    roles: [...(row.claimsPolicy?.roles ?? [])],
    confidential: row.confidential,
  }
}

async function api(path: string, init?: RequestInit): Promise<Response> {
  return fetch(path, {
    credentials: 'include',
    ...(init?.body ? { headers: { 'content-type': 'application/json' } } : {}),
    ...init,
  })
}

async function load(): Promise<void> {
  const res = await api('/api/op/clients')
  if (res.status === 401) {
    window.location.assign(`/?redirect=${encodeURIComponent('/op/admin/clients')}`)
    return
  }
  if (res.status === 403) {
    forbidden.value = true
    return
  }
  if (!res.ok) throw new Error(`the client registry failed (${res.status})`)
  rows.value = await res.json() as ClientRow[]
}

/** The form's URI list, validated inline (persistent): every line must
 *  be an absolute URI. */
const uriProblems = ref<string[]>([])
function validateUris(): string[] {
  const uris = form.value.redirect_uris.split('\n').map(u => u.trim()).filter(Boolean)
  const problems: string[] = []
  if (!uris.length) problems.push('At least one redirect URI is required.')
  for (const uri of uris) {
    try { new URL(uri) } catch { problems.push(`Not an absolute URI: ${uri}`) }
  }
  uriProblems.value = problems
  return problems
}

async function save() {
  if (saving.value) return
  error.value = null
  notice.value = null
  lastSecret.value = null
  if (validateUris().length) return
  saving.value = true
  try {
    const uris = form.value.redirect_uris.split('\n').map(u => u.trim()).filter(Boolean)
    // The secret posture: a NEW confidential client (or a re-key) asks the
    // server to GENERATE the secret (shown once, in the response); an
    // edit without re-key keeps the stored hash; a switch to public makes
    // the client secret-less.
    const wantsSecret = form.value.confidential && (!editing.value || rekey.value)
    const carriesRoles = form.value.claims.includes('roles') || form.value.claims.includes('groups')
    const payload: Record<string, unknown> = {
      client_id: form.value.client_id.trim(),
      name: form.value.name.trim(),
      redirect_uris: uris,
      // The role allowlist rides along only when a role claim is checked
      // and the set is non-empty; otherwise the policy does not bound the
      // role set (TODO.identity/03's semantics).
      claims_policy: {
        claims: form.value.claims,
        ...(carriesRoles && form.value.roles.length ? { roles: form.value.roles } : {}),
      },
    }
    if (wantsSecret) payload.generate_secret = true
    else if (!form.value.confidential) payload.secret = null
    const res = await api('/api/op/clients', { method: 'POST', body: JSON.stringify(payload) })
    const body = await res.json().catch(() => ({})) as { error?: string; secret?: string; clientId?: string }
    if (!res.ok) {
      error.value = body.error ?? `The save was refused (${res.status}).`
      return
    }
    if (body.secret) {
      lastSecret.value = { clientId: body.clientId ?? form.value.client_id.trim(), secret: body.secret }
      notice.value = editing.value
        ? `Re-keyed ${body.clientId} — the new secret is below, shown only now.`
        : `Registered ${body.clientId} — its secret is below, shown only now.`
    } else {
      notice.value = editing.value ? `${body.clientId} updated.` : `Registered ${body.clientId} (a public client — PKCE only).`
    }
    resetForm()
    await load()
  } catch {
    error.value = 'Network error. Is the server running?'
  } finally {
    saving.value = false
  }
}

async function toggle(row: ClientRow) {
  if (saving.value) return
  saving.value = true
  error.value = null
  notice.value = null
  try {
    const res = await api(`/api/op/clients/${encodeURIComponent(row.clientId)}/status`, {
      method: 'POST',
      body: JSON.stringify({ status: row.status === 'active' ? 'disabled' : 'active' }),
    })
    if (!res.ok) {
      const body = await res.json().catch(() => ({})) as { error?: string }
      error.value = body.error ?? `The toggle on ${row.clientId} was refused.`
      return
    }
    notice.value = row.status === 'active'
      ? `${row.clientId} disabled — authorize and token now refuse it; the rows are kept.`
      : `${row.clientId} enabled.`
    await load()
  } catch {
    error.value = 'Network error. Is the server running?'
  } finally {
    saving.value = false
  }
}

function copySecret() {
  if (lastSecret.value) void navigator.clipboard.writeText(lastSecret.value.secret)
}

onMounted(async () => {
  try {
    const session = await fetch('/api/auth/session', { credentials: 'include' })
    if (!session.ok) {
      window.location.assign(`/?redirect=${encodeURIComponent('/op/admin/clients')}`)
      return
    }
    const rolesRes = await api('/api/users/roles')
    if (rolesRes.ok) roleOptions.value = Object.keys(await rolesRes.json() as Record<string, string[]>)
    await load()
  } catch (e) {
    error.value = (e as Error).message || 'Network error. Is the server running?'
  } finally {
    loading.value = false
  }
})
</script>

<template>
  <div class="min-h-screen px-4 py-12 bg-cream dark:bg-slate-900">
    <div v-if="loading" class="flex flex-col items-center gap-4">
      <div class="w-8 h-8 border-2 border-brand-300 border-t-brand-600 rounded-full animate-spin" />
    </div>

    <div v-else-if="forbidden" class="w-full max-w-md mx-auto">
      <div class="text-center mb-8">
        <BrandLogo kind="logo" class="h-10 mx-auto mb-4" />
        <h1 class="text-xl font-serif font-bold text-slate-900 dark:text-white">Relying parties</h1>
      </div>
      <div class="p-3 rounded-lg bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800">
        <p class="text-sm text-amber-800 dark:text-amber-300" data-testid="op-clients-forbidden">
          The relying-party registry is an administrator surface — your account does not hold the administrator role.
        </p>
      </div>
    </div>

    <div v-else class="w-full max-w-3xl mx-auto" data-testid="op-clients">
      <div class="text-center mb-6">
        <BrandLogo kind="logo" class="h-10 mx-auto mb-4" />
        <h1 class="text-xl font-serif font-bold text-slate-900 dark:text-white">Relying parties</h1>
        <p class="mt-2 text-sm text-slate-500 dark:text-slate-400">
          The instances that may ask {{ branding.productName }} to sign their users in (the OIDC client registry).
        </p>
        <OpAdminNav current="clients" class="mt-3" />
      </div>

      <div v-if="error" class="mb-4 p-3 rounded-lg bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800">
        <p class="text-sm text-red-700 dark:text-red-300" data-testid="op-clients-error">{{ error }}</p>
      </div>
      <div v-if="notice" class="mb-4 p-3 rounded-lg bg-emerald-50 dark:bg-emerald-900/20 border border-emerald-200 dark:border-emerald-800">
        <p class="text-sm text-emerald-800 dark:text-emerald-300" data-testid="op-clients-notice">{{ notice }}</p>
      </div>

      <!-- The generated secret, shown ONCE -->
      <div v-if="lastSecret" class="mb-4 p-4 rounded-lg border border-amber-300 dark:border-amber-700 bg-amber-50 dark:bg-amber-900/20" data-testid="op-client-secret-card">
        <p class="text-xs font-semibold text-amber-900 dark:text-amber-200 mb-1">
          The client secret for {{ lastSecret.clientId }} — shown only now
        </p>
        <div class="flex items-center gap-2">
          <code class="flex-1 text-[11px] font-mono bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded px-2 py-1.5 break-all text-slate-700 dark:text-slate-300" data-testid="op-client-secret">{{ lastSecret.secret }}</code>
          <button
            type="button"
            data-testid="op-client-secret-copy"
            class="shrink-0 px-3 py-1.5 text-xs font-semibold rounded-lg bg-brand-600 text-white hover:bg-brand-700 transition-colors"
            @click="copySecret"
          >Copy</button>
        </div>
        <p class="mt-1 text-[11px] text-slate-500 dark:text-slate-400">
          Store it as the instance’s OIDC client secret now. Only its hash is kept here; leaving this page loses it
          (a re-key mints a new one and retires the old).
        </p>
      </div>

      <!-- The registry -->
      <section class="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 p-5 mb-6">
        <h2 class="text-xs font-semibold uppercase tracking-wider text-slate-400 dark:text-slate-500 mb-3">Registered instances</h2>
        <p v-if="!rows.length" class="text-sm text-slate-500 dark:text-slate-400" data-testid="op-clients-empty">
          No relying parties registered yet — register the first instance below.
        </p>
        <ul v-else class="space-y-3" data-testid="op-clients-list">
          <li v-for="row in rows" :key="row.clientId" class="rounded-lg border border-slate-200 dark:border-slate-700 px-3 py-3" :data-testid="`op-client-${row.clientId}`">
            <div class="flex items-start justify-between gap-3">
              <div class="min-w-0">
                <p class="text-sm font-medium text-slate-900 dark:text-white">
                  {{ row.name }}
                  <span class="ml-1 text-[10px] px-1.5 py-0.5 rounded font-semibold"
                    :class="row.confidential ? 'bg-slate-100 dark:bg-slate-700 text-slate-600 dark:text-slate-300' : 'bg-sky-100 dark:bg-sky-900/40 text-sky-700 dark:text-sky-300'"
                    :data-testid="`op-client-kind-${row.clientId}`">{{ row.confidential ? 'confidential' : 'public' }}</span>
                  <span v-if="row.status !== 'active'" class="ml-1 text-[10px] px-1.5 py-0.5 rounded bg-red-100 dark:bg-red-900/40 text-red-600 dark:text-red-400 font-semibold">disabled</span>
                </p>
                <p class="text-[11px] text-slate-400 dark:text-slate-500">
                  {{ row.clientId }}
                  · claims: {{ row.claimsPolicy?.claims.join(', ') || 'profile + email only' }}<template v-if="row.claimsPolicy?.roles?.length"> (roles limited to: {{ row.claimsPolicy.roles.join(', ') }})</template>
                  <template v-if="row.createdBy"> · registered by {{ row.createdBy }}</template>
                </p>
                <ul class="mt-1" :data-testid="`op-client-uris-${row.clientId}`">
                  <li v-for="uri in row.redirectUris" :key="uri" class="text-[11px] font-mono text-slate-500 dark:text-slate-400 truncate">{{ uri }}</li>
                </ul>
              </div>
              <div class="flex items-center gap-2 shrink-0">
                <button
                  :data-testid="`op-client-toggle-${row.clientId}`"
                  class="text-xs font-medium rounded-md px-2 py-1 border transition-colors"
                  :class="row.status === 'active'
                    ? 'border-emerald-300 dark:border-emerald-700 text-emerald-700 dark:text-emerald-300'
                    : 'border-slate-200 dark:border-slate-600 text-slate-500 dark:text-slate-400'"
                  @click="toggle(row)"
                >{{ row.status === 'active' ? 'active' : 'disabled' }}</button>
                <button :data-testid="`op-client-edit-${row.clientId}`" class="text-xs font-medium text-brand-600 dark:text-brand-300 hover:underline" @click="editRow(row)">Edit</button>
              </div>
            </div>
          </li>
        </ul>
      </section>

      <!-- The registration wizard / the edit form -->
      <form class="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 p-5 space-y-3" data-testid="op-client-form" @submit.prevent="save">
        <h2 class="text-xs font-semibold uppercase tracking-wider text-slate-400 dark:text-slate-500">
          {{ editing ? `Edit ${editing}` : 'Register an instance' }}
        </h2>
        <div class="grid sm:grid-cols-2 gap-3">
          <div>
            <label class="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">client id (slug, rides the OAuth parameters)</label>
            <input
              v-model="form.client_id"
              :disabled="!!editing"
              required
              data-testid="op-client-field-id"
              placeholder="tl-example"
              class="w-full px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white disabled:opacity-60"
            />
          </div>
          <div>
            <label class="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">name (the consent page shows it)</label>
            <input
              v-model="form.name"
              required
              data-testid="op-client-field-name"
              placeholder="Example test-laboratory instance"
              class="w-full px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white"
            />
          </div>
          <div class="sm:col-span-2">
            <label class="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">redirect URIs (exact, one per line — an unregistered one is refused, never redirected to)</label>
            <textarea
              v-model="form.redirect_uris"
              rows="3"
              required
              data-testid="op-client-field-uris"
              placeholder="https://tl.example.org/api/auth/callback/oidc"
              class="w-full px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm font-mono text-slate-900 dark:text-white"
              @blur="validateUris"
              @input="validateUris"
            />
            <ul v-if="uriProblems.length" class="mt-1 list-disc list-inside text-xs text-red-600 dark:text-red-400" data-testid="op-client-uri-problems">
              <li v-for="problem in uriProblems" :key="problem">{{ problem }}</li>
            </ul>
          </div>
          <fieldset class="sm:col-span-2">
            <legend class="text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">claims policy (the claims this instance’s ID tokens may carry)</legend>
            <div class="flex flex-wrap gap-x-4 gap-y-1" data-testid="op-client-field-claims">
              <label v-for="claim in CLAIM_OPTIONS" :key="claim" class="flex items-center gap-1.5 text-sm text-slate-700 dark:text-slate-300">
                <input v-model="form.claims" type="checkbox" :value="claim" :data-testid="`op-client-claim-${claim}`" class="rounded border-slate-300" />
                {{ claim }}
              </label>
            </div>
            <p class="mt-1 text-[11px] text-slate-400 dark:text-slate-500">
              With no claim checked the ID token carries the profile and email only — role claims are a per-client privilege.
            </p>
            <!-- The role allowlist (TODO.identity/03): bounds WHICH roles
                 the emitted claims may hold. Only meaningful when a role
                 claim is on; empty = unbounded. -->
            <div v-if="form.claims.includes('roles') || form.claims.includes('groups')" class="mt-2" data-testid="op-client-field-role-allowlist">
              <p class="text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">role allowlist (empty = the policy does not bound the role set)</p>
              <div class="flex flex-wrap gap-x-4 gap-y-1">
                <label v-for="r in roleOptions" :key="r" class="flex items-center gap-1.5 text-sm text-slate-700 dark:text-slate-300">
                  <input v-model="form.roles" type="checkbox" :value="r" :data-testid="`op-client-role-${r}`" class="rounded border-slate-300" />
                  {{ r }}
                </label>
              </div>
            </div>
          </fieldset>
          <div class="sm:col-span-2 space-y-1">
            <label class="flex items-center gap-2 text-sm text-slate-700 dark:text-slate-300">
              <input v-model="form.confidential" type="checkbox" data-testid="op-client-field-confidential" class="rounded border-slate-300" />
              Confidential client (holds a secret; the server generates it and shows it once)
            </label>
            <label v-if="editing && form.confidential" class="flex items-center gap-2 text-sm text-slate-700 dark:text-slate-300">
              <input v-model="rekey" type="checkbox" data-testid="op-client-field-rekey" class="rounded border-slate-300" />
              Re-key: generate a new secret (the old one stops working at once)
            </label>
          </div>
        </div>
        <div class="flex items-center gap-3">
          <button
            type="submit"
            :disabled="saving"
            data-testid="op-client-save"
            class="py-2 px-4 rounded-lg text-sm font-medium bg-brand-600 text-white hover:bg-brand-700 transition-colors disabled:opacity-50"
          >{{ saving ? 'Saving…' : editing ? 'Save changes' : 'Register the instance' }}</button>
          <button v-if="editing" type="button" class="text-sm text-slate-500 hover:underline" data-testid="op-client-cancel" @click="resetForm">Cancel edit</button>
        </div>
      </form>
    </div>
  </div>
</template>
