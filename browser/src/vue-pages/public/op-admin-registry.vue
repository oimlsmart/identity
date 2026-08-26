<script setup lang="ts">
// ═══════════════════════════════════════════════════════════════════
// The identity registry's account directory (TODO.identity/07) — the
// administrator's list of every account on the identity service: search
// by name, email, or linked handle; filter by status and role; the
// last-sign-in column; the invite action (the one-time setup link shows
// once). A row's "Open" deep-links to the account's detail page.
//
// The per-client role assignment is TODO.identity/03's surface (in
// flight); this directory serves the merged role model (the account's
// role set) and stays honest about the seam.
//
// Every rule is SERVER-ENFORCED (routes/op-registry.ts +
// routes/op-accounts.ts); this page only renders what the APIs answer.
// ═══════════════════════════════════════════════════════════════════
import { onMounted, ref, watch } from 'vue'
import PageHeader from '../../components/PageHeader.vue'
import { useBranding } from '../../branding'

interface RegistryRow {
  id: string
  email: string
  name: string
  role: string
  roles: string[]
  orgId: string | null
  active: boolean
  provider: string
  lastLogin: string | null
  passwordSet: boolean
  links: Array<{ provider: string; providerAccountId: string }>
}

const { branding } = useBranding()

const loading = ref(true)
const forbidden = ref(false)
const error = ref<string | null>(null)
const notice = ref<string | null>(null)
const account = ref<{ id: string; name: string; email: string } | null>(null)

const rows = ref<RegistryRow[]>([])
const roleOptions = ref<string[]>([])

// The filters (server-side; the input reloads on a short debounce).
const search = ref('')
const status = ref<'all' | 'active' | 'deactivated'>('all')
const role = ref('')
let searchTimer: ReturnType<typeof setTimeout> | null = null

// The invite form + the ONE-TIME setup link of the last issued invite
// (TODO.identity/02's enrollment — no mailer is in scope; the admin
// copies the link and hands it over). Shown once, cleared on the next
// action.
const inviteName = ref('')
const inviteEmail = ref('')
const inviteRole = ref('viewer')
const inviting = ref(false)
const lastInvite = ref<{ email: string; name: string; setupUrl: string; expiresAt: string } | null>(null)

async function api(path: string, init?: RequestInit): Promise<Response> {
  return fetch(path, {
    credentials: 'include',
    ...(init?.body ? { headers: { 'content-type': 'application/json' } } : {}),
    ...init,
  })
}

async function load(): Promise<void> {
  const params = new URLSearchParams()
  if (search.value.trim()) params.set('q', search.value.trim())
  if (status.value !== 'all') params.set('status', status.value)
  if (role.value) params.set('role', role.value)
  const res = await api(`/api/op/registry/users${params.size ? `?${params}` : ''}`)
  if (res.status === 401) {
    window.location.assign(`/?redirect=${encodeURIComponent('/op/admin/registry')}`)
    return
  }
  if (res.status === 403) {
    forbidden.value = true
    return
  }
  if (!res.ok) throw new Error(`the registry failed (${res.status})`)
  rows.value = await res.json() as RegistryRow[]
}

function queueReload() {
  if (searchTimer) clearTimeout(searchTimer)
  searchTimer = setTimeout(() => { void load() }, 250)
}
watch([search, status, role], queueReload)

async function invite() {
  if (inviting.value) return
  inviting.value = true
  error.value = null
  notice.value = null
  lastInvite.value = null
  try {
    const res = await api('/api/op/accounts', {
      method: 'POST',
      body: JSON.stringify({
        name: inviteName.value.trim(),
        email: inviteEmail.value.trim(),
        role: inviteRole.value,
      }),
    })
    if (!res.ok) {
      const body = await res.json().catch(() => ({})) as { error?: string }
      error.value = body.error ?? `The invite failed (${res.status}).`
      return
    }
    const created = await res.json() as {
      account: { id: string; email: string; name: string }
      setupUrl: string
      expiresAt: string
    }
    lastInvite.value = {
      email: created.account.email,
      name: created.account.name,
      setupUrl: created.setupUrl,
      expiresAt: created.expiresAt,
    }
    notice.value = `${created.account.name} is invited. Hand over the one-time setup link below (24 hours); it is shown only now.`
    inviteName.value = ''
    inviteEmail.value = ''
    await load()
  } catch {
    error.value = 'Network error. Is the server running?'
  } finally {
    inviting.value = false
  }
}

function copySetupUrl() {
  if (lastInvite.value) void navigator.clipboard.writeText(lastInvite.value.setupUrl)
}

/** The last-sign-in cell: the date, or the honest "never". */
function lastSignIn(row: RegistryRow): string {
  return row.lastLogin ? row.lastLogin.slice(0, 16).replace('T', ' ') : 'never'
}

onMounted(async () => {
  try {
    const session = await fetch('/api/auth/session', { credentials: 'include' })
    if (!session.ok) {
      window.location.assign(`/?redirect=${encodeURIComponent('/op/admin/registry')}`)
      return
    }
    account.value = await session.json() as { id: string; name: string; email: string }
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
  <div class="max-w-5xl mx-auto px-6 py-10 w-full">
    <div v-if="loading" class="flex flex-col items-center gap-4 py-24">
      <div class="w-8 h-8 border-2 border-brand-300 border-t-brand-600 rounded-full animate-spin" />
    </div>

    <!-- The honest refusal (the API's 403) -->
    <div v-else-if="forbidden" class="max-w-md mx-auto py-16">
      <div class="text-center mb-8">
        <h1 class="text-xl font-serif font-bold text-slate-900 dark:text-white">Identity registry</h1>
      </div>
      <div class="p-3 rounded-lg bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800">
        <p class="text-sm text-amber-800 dark:text-amber-300" data-testid="op-reg-forbidden">
          The identity registry is an administrator surface — your account does not hold the administrator role.
        </p>
      </div>
    </div>

    <div v-else data-testid="op-reg">
      <PageHeader title="Identity registry">
        <template #description>
          <span data-testid="op-reg-identity"><template v-if="account">{{ account.name }} &lt;{{ account.email }}&gt; — </template>{{ branding.productName }}</span>
        </template>
      </PageHeader>

      <div v-if="error" class="mb-4 p-3 rounded-lg bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800">
        <p class="text-sm text-red-700 dark:text-red-300" data-testid="op-reg-error">{{ error }}</p>
      </div>
      <div v-if="notice" class="mb-4 p-3 rounded-lg bg-emerald-50 dark:bg-emerald-900/20 border border-emerald-200 dark:border-emerald-800">
        <p class="text-sm text-emerald-800 dark:text-emerald-300" data-testid="op-reg-notice">{{ notice }}</p>
      </div>

      <!-- The issued invite's one-time setup link (shown once) -->
      <div v-if="lastInvite" class="mb-4 p-4 rounded-lg border border-brand-300 dark:border-brand-700 bg-brand-50 dark:bg-brand-900/20" data-testid="op-reg-invite-link-card">
        <p class="text-xs font-semibold text-brand-900 dark:text-brand-200 mb-1">
          The one-time setup link for {{ lastInvite.name }} &lt;{{ lastInvite.email }}&gt;
          <span class="font-normal text-slate-500 dark:text-slate-400">(expires {{ lastInvite.expiresAt.slice(0, 16).replace('T', ' ') }}UTC)</span>
        </p>
        <div class="flex items-center gap-2">
          <code class="flex-1 text-[11px] font-mono bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded px-2 py-1.5 truncate text-slate-700 dark:text-slate-300" data-testid="op-reg-invite-setup-url">{{ lastInvite.setupUrl }}</code>
          <button
            type="button"
            data-testid="op-reg-invite-setup-copy"
            class="shrink-0 px-3 py-1.5 text-xs font-semibold rounded-lg bg-brand-600 text-white hover:bg-brand-700 transition-colors"
            @click="copySetupUrl"
          >Copy</button>
        </div>
        <p class="mt-1 text-[11px] text-slate-500 dark:text-slate-400">
          It opens the account-setup page once, for 24 hours. Send it by a channel where you can verify the person — this link sets their password.
        </p>
      </div>

      <!-- The invite action -->
      <section class="rounded-xl border border-slate-200/80 dark:border-slate-700 bg-white dark:bg-slate-800 p-6 mb-6" data-testid="op-reg-invite">
        <h2 class="text-xs font-semibold uppercase tracking-wider text-slate-400 dark:text-slate-500 mb-3">Invite an account</h2>
        <div class="grid grid-cols-1 sm:grid-cols-4 gap-2">
          <input
            v-model="inviteName"
            type="text"
            data-testid="op-reg-invite-name"
            class="px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-500"
            placeholder="Full name"
          />
          <input
            v-model="inviteEmail"
            type="email"
            data-testid="op-reg-invite-email"
            class="px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-500"
            placeholder="Email"
          />
          <select
            v-model="inviteRole"
            data-testid="op-reg-invite-role"
            class="px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-500"
          >
            <option v-for="r in roleOptions" :key="r" :value="r">{{ r }}</option>
          </select>
          <button
            :disabled="inviting || !inviteName.trim() || !inviteEmail.includes('@')"
            data-testid="op-reg-invite-submit"
            class="py-2 rounded-lg text-sm font-medium bg-brand-600 text-white hover:bg-brand-700 transition-colors disabled:opacity-50"
            @click="invite"
          >{{ inviting ? 'Inviting…' : 'Invite' }}</button>
        </div>
        <p class="mt-2 text-[11px] text-slate-400 dark:text-slate-500">
          Enrollment is invite-only: the account is created now, the one-time setup link (24 hours) is handed over out-of-band.
        </p>
      </section>

      <!-- Search + filters -->
      <section class="rounded-xl border border-slate-200/80 dark:border-slate-700 bg-white dark:bg-slate-800 p-6" data-testid="op-reg-directory">
        <div class="flex flex-wrap items-center gap-2 mb-4">
          <input
            v-model="search"
            type="search"
            data-testid="op-reg-search"
            class="flex-1 min-w-56 px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-500"
            placeholder="Search name, email, or linked handle…"
          />
          <select
            v-model="status"
            data-testid="op-reg-filter-status"
            class="px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-500"
          >
            <option value="all">every status</option>
            <option value="active">active</option>
            <option value="deactivated">deactivated</option>
          </select>
          <select
            v-model="role"
            data-testid="op-reg-filter-role"
            class="px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-500"
          >
            <option value="">every role</option>
            <option v-for="r in roleOptions" :key="r" :value="r">{{ r }}</option>
          </select>
        </div>

        <p v-if="!rows.length" class="text-sm text-slate-500 dark:text-slate-400" data-testid="op-reg-empty">
          No accounts match — adjust the search or filters, or invite the account above.
        </p>

        <!-- The directory: CARDS below md, the table from md up (the
             responsive audit: the table's six columns sideways-scroll
             their own box on a phone; the card stacks the same fields.
             The card testids carry the `op-reg-card-` prefix — the
             table's set stays singular for the desktop e2e legs). -->
        <ul v-if="rows.length" class="md:hidden space-y-2" data-testid="op-reg-cards">
          <li
            v-for="row in rows"
            :key="row.id"
            class="rounded-lg border border-slate-200 dark:border-slate-700 px-3 py-2"
            :data-testid="`op-reg-card-${row.id}`"
          >
            <div class="flex items-start justify-between gap-3">
              <div class="min-w-0">
                <p class="font-medium text-sm text-slate-900 dark:text-white break-words">
                  {{ row.name }}
                  <span v-if="!row.active" class="ml-1 text-[10px] px-1.5 py-0.5 rounded bg-red-100 dark:bg-red-900/40 text-red-600 dark:text-red-400 font-semibold">deactivated</span>
                </p>
                <p class="text-[11px] text-slate-400 dark:text-slate-500 break-all">
                  {{ row.email }} · {{ row.provider }}
                  <router-link
                    v-if="row.orgId"
                    :to="`/op/admin/registry/orgs/${row.orgId}`"
                    class="ml-1 text-brand-600 dark:text-brand-300 hover:underline"
                    :data-testid="`op-reg-card-org-link-${row.id}`"
                  >· {{ row.orgId }}</router-link>
                </p>
              </div>
              <router-link
                :to="`/op/admin/registry/users/${row.id}`"
                class="shrink-0 text-xs font-medium text-brand-600 dark:text-brand-300 hover:underline"
                :data-testid="`op-reg-card-open-${row.id}`"
              >Open</router-link>
            </div>
            <p class="mt-1.5 text-xs text-slate-600 dark:text-slate-300" :data-testid="`op-reg-card-roles-${row.id}`">
              <span class="text-slate-400 dark:text-slate-500">Roles:</span> {{ row.roles.join(', ') }}
            </p>
            <p class="text-[11px] text-slate-500 dark:text-slate-400">
              <span v-if="row.passwordSet">password</span><span v-else>no password yet</span><template v-if="row.links.length"> · {{ row.links.map(l => l.provider).join(', ') }}</template>
              · <span :class="row.active ? 'text-emerald-600 dark:text-emerald-400' : 'text-red-500 dark:text-red-400'" :data-testid="`op-reg-card-status-${row.id}`">{{ row.active ? 'active' : 'deactivated' }}</span>
              · <span :data-testid="`op-reg-card-lastsignin-${row.id}`">{{ lastSignIn(row) }}</span>
            </p>
          </li>
        </ul>

        <div v-if="rows.length" class="hidden md:block overflow-x-auto">
          <table class="w-full text-sm" data-testid="op-reg-list">
            <thead>
              <tr class="text-left text-[11px] uppercase tracking-wider text-slate-400 dark:text-slate-500 border-b border-slate-200 dark:border-slate-700">
                <th class="py-2 pr-3 font-semibold">Account</th>
                <th class="py-2 pr-3 font-semibold">Roles</th>
                <th class="py-2 pr-3 font-semibold">Sign-in methods</th>
                <th class="py-2 pr-3 font-semibold">Status</th>
                <th class="py-2 pr-3 font-semibold">Last sign-in</th>
                <th class="py-2 font-semibold"><span class="sr-only">Open</span></th>
              </tr>
            </thead>
            <tbody>
              <tr
                v-for="row in rows"
                :key="row.id"
                class="border-b border-slate-100 dark:border-slate-700/60 last:border-0"
                :data-testid="`op-reg-user-${row.id}`"
              >
                <td class="py-2 pr-3">
                  <p class="font-medium text-slate-900 dark:text-white">
                    {{ row.name }}
                    <span v-if="!row.active" class="ml-1 text-[10px] px-1.5 py-0.5 rounded bg-red-100 dark:bg-red-900/40 text-red-600 dark:text-red-400 font-semibold">deactivated</span>
                  </p>
                  <p class="text-[11px] text-slate-400 dark:text-slate-500">
                    {{ row.email }} · {{ row.provider }}
                    <router-link
                      v-if="row.orgId"
                      :to="`/op/admin/registry/orgs/${row.orgId}`"
                      class="ml-1 text-brand-600 dark:text-brand-300 hover:underline"
                      :data-testid="`op-reg-org-link-${row.id}`"
                    >· {{ row.orgId }}</router-link>
                  </p>
                </td>
                <td class="py-2 pr-3 text-xs text-slate-600 dark:text-slate-300" :data-testid="`op-reg-roles-${row.id}`">{{ row.roles.join(', ') }}</td>
                <td class="py-2 pr-3 text-xs text-slate-600 dark:text-slate-300">
                  <span v-if="row.passwordSet">password</span><span v-else>no password yet</span><template v-if="row.links.length"> · {{ row.links.map(l => l.provider).join(', ') }}</template>
                </td>
                <td class="py-2 pr-3 text-xs" :data-testid="`op-reg-status-${row.id}`">
                  <span :class="row.active ? 'text-emerald-600 dark:text-emerald-400' : 'text-red-500 dark:text-red-400'">{{ row.active ? 'active' : 'deactivated' }}</span>
                </td>
                <td class="py-2 pr-3 text-xs text-slate-500 dark:text-slate-400" :data-testid="`op-reg-lastsignin-${row.id}`">{{ lastSignIn(row) }}</td>
                <td class="py-2 text-right">
                  <router-link
                    :to="`/op/admin/registry/users/${row.id}`"
                    class="text-xs font-medium text-brand-600 dark:text-brand-300 hover:underline"
                    :data-testid="`op-reg-open-${row.id}`"
                  >Open</router-link>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>
    </div>
  </div>
</template>
