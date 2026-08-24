<script setup lang="ts">
// ═══════════════════════════════════════════════════════════════════
// The registry's account detail page (TODO.identity/07) — one account
// on the identity service: the profile and its role set, the linked
// identities (with the administrator's "link on behalf", its documented
// justification on the record), the live sessions (the administrator can
// end one), the invite/resend of the one-time setup link, and the honest
// deactivate/reactivate (history kept, sign-ins refused, sessions stop
// resolving). The account's own audit trail closes the page.
//
// The PER-CLIENT role assignments (TODO.identity/03) ride the merged
// surface: the detail aggregate reads them, the editor is the
// user-registry console's (deep-linked below). The "what the instances
// receive" panel names each registered relying party whose claims policy
// carries the roles claim.
//
// Every rule is SERVER-ENFORCED (routes/op-registry.ts, routes/users.ts,
// routes/op-accounts.ts); this page only renders what the APIs answer.
// ═══════════════════════════════════════════════════════════════════
import { computed, onMounted, ref } from 'vue'
import { useRoute } from 'vue-router'
import BrandLogo from '../../components/BrandLogo.vue'
import OpAdminNav from '../../components/OpAdminNav.vue'
import { useBranding } from '../../branding'

interface AuditEvent {
  id: string
  timestamp: string
  action: string
  user_name?: string
  metadata?: Record<string, unknown>
}

interface LinkRow {
  id: string
  provider: string
  providerAccountId: string
  linkedAt: string
  linkedBy: string | null
}

interface ClientRoleRow {
  clientId: string
  roles: string[]
  assignedBy: string | null
  updatedAt: string
}

interface SessionRow {
  id: string
  createdAt: string
  expiresAt: string
  current: boolean
}

interface Detail {
  account: {
    id: string
    email: string
    name: string
    role: string
    roles: string[]
    orgId: string | null
    orgName: string | null
    active: boolean
  }
  passwordSet: boolean
  links: LinkRow[]
  sessions: SessionRow[]
  clientRoles: ClientRoleRow[]
  activity: AuditEvent[]
}

interface ClientRow {
  clientId: string
  name: string
  claimsPolicy: { claims: string[]; roles?: string[] } | null
  status: string
}

interface ProviderRow {
  id: string
  displayName: string
  enabled: boolean
}

const route = useRoute()
const { branding } = useBranding()
const userId = computed(() => String(route.params.id ?? ''))

const loading = ref(true)
const forbidden = ref(false)
const notFound = ref(false)
const error = ref<string | null>(null)
const notice = ref<string | null>(null)
const acting = ref<string | null>(null)

const detail = ref<Detail | null>(null)
const roleMap = ref<Record<string, string[]>>({})
const clients = ref<ClientRow[]>([])
const providers = ref<ProviderRow[]>([])

// The roles editor's working state.
const checkedRoles = ref<string[]>([])
const primaryRole = ref('')

// The link-on-behalf form.
const linkProvider = ref('')
const linkHandle = ref('')
const linkJustification = ref('')

// The unlink affordance's per-row open state + optional reason.
const unlinkOpen = ref<Record<string, boolean>>({})
const unlinkReason = ref<Record<string, string>>({})

// The deactivation's two-step confirm.
const deactivateArmed = ref(false)

// The erasure's two-step confirm (the offboarding runbook's delete path —
// irreversible, so the confirm names what happens).
const eraseArmed = ref(false)

// The ONE-TIME setup link of the last (re)issued enrollment, shown once.
const lastSetup = ref<{ setupUrl: string; expiresAt: string } | null>(null)

const isSelf = ref(false)

/** The relying parties whose claims policy carries the roles claim (the
 *  "what the instances receive" panel's rows). */
const roleCarryingClients = computed(() => clients.value.filter(cl => cl.claimsPolicy?.claims.includes('roles')))
const otherClients = computed(() => clients.value.filter(cl => !cl.claimsPolicy?.claims.includes('roles')))

async function api(path: string, init?: RequestInit): Promise<Response> {
  return fetch(path, {
    credentials: 'include',
    ...(init?.body ? { headers: { 'content-type': 'application/json' } } : {}),
    ...init,
  })
}

async function load(): Promise<void> {
  const res = await api(`/api/op/registry/users/${encodeURIComponent(userId.value)}`)
  if (res.status === 401) {
    window.location.assign(`/?redirect=${encodeURIComponent(`/op/admin/registry/users/${userId.value}`)}`)
    return
  }
  if (res.status === 403) {
    forbidden.value = true
    return
  }
  if (res.status === 404) {
    notFound.value = true
    return
  }
  if (!res.ok) throw new Error(`the account failed (${res.status})`)
  detail.value = await res.json() as Detail
  checkedRoles.value = [...detail.value.account.roles]
  primaryRole.value = detail.value.account.roles.includes(detail.value.account.role)
    ? detail.value.account.role
    : detail.value.account.roles[0]!
}

async function saveRoles() {
  if (acting.value || !detail.value) return
  if (!checkedRoles.value.length) {
    error.value = 'An account holds at least one role — deactivate it instead when it should hold none.'
    return
  }
  acting.value = 'roles'
  error.value = null
  notice.value = null
  try {
    const primary = checkedRoles.value.includes(primaryRole.value) ? primaryRole.value : checkedRoles.value[0]!
    const res = await api(`/api/users/${encodeURIComponent(userId.value)}/roles`, {
      method: 'PUT',
      body: JSON.stringify({ role: primary, roles: checkedRoles.value }),
    })
    if (!res.ok) {
      const body = await res.json().catch(() => ({})) as { error?: string }
      error.value = body.error ?? `The role assignment failed (${res.status}).`
      return
    }
    notice.value = 'Roles saved — the assignment takes effect on the account’s next request, and rides the ID tokens of the relying parties whose policy carries the roles claim.'
    await load()
  } catch {
    error.value = 'Network error. Is the server running?'
  } finally {
    acting.value = null
  }
}

async function resendSetup() {
  if (acting.value) return
  acting.value = 'enrollment'
  error.value = null
  notice.value = null
  lastSetup.value = null
  try {
    const res = await api(`/api/op/accounts/${encodeURIComponent(userId.value)}/enrollment`, { method: 'POST' })
    if (!res.ok) {
      const body = await res.json().catch(() => ({})) as { error?: string }
      error.value = body.error ?? `The setup link failed (${res.status}).`
      return
    }
    lastSetup.value = await res.json() as { setupUrl: string; expiresAt: string }
    notice.value = 'A fresh one-time setup link (24 hours) is below — hand it over by a channel where you can verify the person.'
  } catch {
    error.value = 'Network error. Is the server running?'
  } finally {
    acting.value = null
  }
}

async function setActive(active: boolean) {
  if (acting.value) return
  acting.value = 'active'
  error.value = null
  notice.value = null
  try {
    const res = await api(`/api/users/${encodeURIComponent(userId.value)}/active`, {
      method: 'PUT',
      body: JSON.stringify({ active }),
    })
    if (!res.ok) {
      const body = await res.json().catch(() => ({})) as { error?: string }
      error.value = body.error ?? `(${res.status})`
      return
    }
    notice.value = active
      ? 'Reactivated — the account signs in again.'
      : 'Deactivated — sign-ins are refused and the account’s sessions stopped resolving. The history is kept.'
    deactivateArmed.value = false
    await load()
  } catch {
    error.value = 'Network error. Is the server running?'
  } finally {
    acting.value = null
  }
}

/** The erasure (DELETE /api/op/accounts/:id): the account is anonymized
 *  in place and every credential, link and token removed. Irreversible;
 *  the account's row vanishes from the registry, so the act ends back on
 *  the directory. */
async function eraseAccount() {
  if (acting.value) return
  acting.value = 'erase'
  error.value = null
  notice.value = null
  try {
    const res = await api(`/api/op/accounts/${encodeURIComponent(userId.value)}`, { method: 'DELETE' })
    if (!res.ok) {
      const body = await res.json().catch(() => ({})) as { error?: string }
      error.value = body.error ?? `The erasure failed (${res.status}).`
      acting.value = null
      return
    }
    window.location.assign('/op/admin/registry')
  } catch {
    error.value = 'Network error. Is the server running?'
    acting.value = null
  }
}

async function linkOnBehalf() {
  if (acting.value) return
  const justification = linkJustification.value.trim()
  if (!justification) {
    error.value = 'A justification note is required — the link bypasses the account holder’s own flow, so the reason goes on the record.'
    return
  }
  acting.value = 'link'
  error.value = null
  notice.value = null
  try {
    const res = await api(`/api/op/registry/users/${encodeURIComponent(userId.value)}/links`, {
      method: 'POST',
      body: JSON.stringify({
        provider: linkProvider.value,
        provider_account_id: linkHandle.value.trim(),
        justification,
      }),
    })
    if (!res.ok) {
      const body = await res.json().catch(() => ({})) as { error?: string }
      error.value = body.error ?? `The link failed (${res.status}).`
      return
    }
    notice.value = `Linked ${linkProvider.value} account ${linkHandle.value.trim()} — the justification is on the activity record.`
    linkHandle.value = ''
    linkJustification.value = ''
    await load()
  } catch {
    error.value = 'Network error. Is the server running?'
  } finally {
    acting.value = null
  }
}

async function unlink(link: LinkRow) {
  if (acting.value) return
  acting.value = link.provider
  error.value = null
  notice.value = null
  try {
    const reason = (unlinkReason.value[link.provider] ?? '').trim()
    const res = await api(`/api/op/registry/users/${encodeURIComponent(userId.value)}/links/${encodeURIComponent(link.provider)}`, {
      method: 'DELETE',
      ...(reason ? { body: JSON.stringify({ reason }) } : {}),
    })
    if (!res.ok) {
      const body = await res.json().catch(() => ({})) as { error?: string }
      error.value = body.error ?? `The unlink failed (${res.status}).`
      return
    }
    notice.value = `The ${link.provider} link is removed — a sign-in with it is now refused honestly.`
    unlinkOpen.value[link.provider] = false
    await load()
  } catch {
    error.value = 'Network error. Is the server running?'
  } finally {
    acting.value = null
  }
}

async function revokeSession(session: SessionRow) {
  if (acting.value) return
  acting.value = session.id
  error.value = null
  notice.value = null
  try {
    const res = await api(`/api/op/registry/users/${encodeURIComponent(userId.value)}/sessions/${encodeURIComponent(session.id)}/revoke`, { method: 'POST' })
    if (!res.ok) {
      const body = await res.json().catch(() => ({})) as { error?: string }
      error.value = body.error ?? `The revocation failed (${res.status}).`
      return
    }
    notice.value = 'Session ended — it stops resolving at once.'
    await load()
  } catch {
    error.value = 'Network error. Is the server running?'
  } finally {
    acting.value = null
  }
}

function copySetupUrl() {
  if (lastSetup.value) void navigator.clipboard.writeText(lastSetup.value.setupUrl)
}

/** One readable line per audit event (the account's own trail). */
function activityLine(event: AuditEvent): string {
  const meta = event.metadata ?? {}
  switch (event.action) {
    case 'account.invite': return `invited the account (${String(meta.email ?? '')}, role ${String(meta.role ?? '')})`
    case 'account.enrollment': return 'issued a fresh setup link'
    case 'account.enrolled': return 'completed the setup (password set)'
    case 'account.password': return 'changed the password'
    case 'account.password_reset': return 'requested a password reset email'
    case 'account.avatar': return 'updated the profile picture'
    case 'account.avatar_removed': return 'removed the profile picture'
    case 'account.deleted': return `erased the account (${String(meta.email ?? '')}) — the row is an anonymized tombstone`
    case 'account.session_revoked': return meta.by === 'administrator' ? 'ended a session (administrator)' : 'ended a session'
    case 'account.link_on_behalf': return `linked ${String(meta.provider ?? '')} account ${String(meta.provider_account_id ?? '')} on behalf — ${String(meta.justification ?? '')}`
    case 'account.link_removed': return `removed the ${String(meta.provider ?? '')} link${meta.reason ? ` — ${String(meta.reason)}` : ''}`
    case 'user.roles': return `assigned roles: ${(meta.roles as string[] ?? []).join(', ')}`
    case 'user.deactivated': return 'deactivated the account'
    case 'user.reactivated': return 'reactivated the account'
    case 'upstream_sign_in': return `signed in with ${String(meta.provider ?? '')} (${String(meta.handle ?? '')})`
    case 'upstream_link': return `linked ${String(meta.provider ?? '')} (${String(meta.handle ?? '')}) from the account page`
    case 'upstream_unlink': return `unlinked ${String(meta.provider ?? '')}`
    default: return event.action
  }
}

onMounted(async () => {
  try {
    const session = await fetch('/api/auth/session', { credentials: 'include' })
    if (!session.ok) {
      window.location.assign(`/?redirect=${encodeURIComponent(`/op/admin/registry/users/${userId.value}`)}`)
      return
    }
    const me = await session.json() as { id: string }
    isSelf.value = me.id === userId.value
    const [rolesRes, clientsRes, providersRes] = await Promise.all([
      api('/api/users/roles'),
      api('/api/op/clients'),
      api('/api/op/providers'),
    ])
    if (rolesRes.ok) roleMap.value = await rolesRes.json() as Record<string, string[]>
    if (clientsRes.ok) clients.value = await clientsRes.json() as ClientRow[]
    if (providersRes.ok) providers.value = (await providersRes.json() as ProviderRow[]).filter(p => p.enabled)
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
        <h1 class="text-xl font-serif font-bold text-slate-900 dark:text-white">Registry account</h1>
      </div>
      <div class="p-3 rounded-lg bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800">
        <p class="text-sm text-amber-800 dark:text-amber-300" data-testid="op-reg-user-forbidden">
          The identity registry is an administrator surface — your account does not hold the administrator role.
        </p>
      </div>
    </div>

    <div v-else-if="notFound" class="w-full max-w-md mx-auto text-center">
      <BrandLogo kind="logo" class="h-10 mx-auto mb-4" />
      <h1 class="text-xl font-serif font-bold text-slate-900 dark:text-white mb-2">No such account</h1>
      <p class="text-sm text-slate-500 dark:text-slate-400" data-testid="op-reg-user-notfound">
        This account id is not on the registry.
        <router-link to="/op/admin/registry" class="text-brand-600 dark:text-brand-300 hover:underline">Back to the identity registry</router-link>
      </p>
    </div>

    <div v-else-if="detail" class="w-full max-w-3xl mx-auto" data-testid="op-reg-user">
      <div class="text-center mb-6">
        <BrandLogo kind="logo" class="h-10 mx-auto mb-4" />
        <h1 class="text-xl font-serif font-bold text-slate-900 dark:text-white">{{ detail.account.name }}</h1>
        <p class="mt-2 text-sm text-slate-500 dark:text-slate-400" data-testid="op-reg-user-context">
          {{ detail.account.email }} · {{ branding.productName }}
        </p>
        <OpAdminNav current="registry" class="mt-3" />
        <p class="mt-2 text-xs">
          <router-link to="/op/admin/registry" class="text-brand-600 dark:text-brand-300 hover:underline" data-testid="op-reg-user-back">← the identity registry</router-link>
        </p>
      </div>

      <div v-if="error" class="mb-4 p-3 rounded-lg bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800">
        <p class="text-sm text-red-700 dark:text-red-300" data-testid="op-reg-user-error">{{ error }}</p>
      </div>
      <div v-if="notice" class="mb-4 p-3 rounded-lg bg-emerald-50 dark:bg-emerald-900/20 border border-emerald-200 dark:border-emerald-800">
        <p class="text-sm text-emerald-800 dark:text-emerald-300" data-testid="op-reg-user-notice">{{ notice }}</p>
      </div>

      <!-- The re-issued setup link, shown once -->
      <div v-if="lastSetup" class="mb-4 p-4 rounded-lg border border-brand-300 dark:border-brand-700 bg-brand-50 dark:bg-brand-900/20" data-testid="op-reg-setup-link-card">
        <p class="text-xs font-semibold text-brand-900 dark:text-brand-200 mb-1">
          The one-time setup link
          <span class="font-normal text-slate-500 dark:text-slate-400">(expires {{ lastSetup.expiresAt.slice(0, 16).replace('T', ' ') }}UTC)</span>
        </p>
        <div class="flex items-center gap-2">
          <code class="flex-1 text-[11px] font-mono bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded px-2 py-1.5 truncate text-slate-700 dark:text-slate-300" data-testid="op-reg-setup-url">{{ lastSetup.setupUrl }}</code>
          <button
            type="button"
            data-testid="op-reg-setup-copy"
            class="shrink-0 px-3 py-1.5 text-xs font-semibold rounded-lg bg-brand-600 text-white hover:bg-brand-700 transition-colors"
            @click="copySetupUrl"
          >Copy</button>
        </div>
      </div>

      <!-- The profile + the role set -->
      <section class="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 p-5 mb-6" data-testid="op-reg-profile">
        <h2 class="text-xs font-semibold uppercase tracking-wider text-slate-400 dark:text-slate-500 mb-3">Profile and roles</h2>
        <dl class="grid sm:grid-cols-2 gap-x-6 gap-y-1 text-sm mb-4">
          <div><dt class="text-[11px] text-slate-400 dark:text-slate-500">Name</dt><dd class="text-slate-900 dark:text-white" data-testid="op-reg-profile-name">{{ detail.account.name }}</dd></div>
          <div><dt class="text-[11px] text-slate-400 dark:text-slate-500">Email</dt><dd class="text-slate-900 dark:text-white" data-testid="op-reg-profile-email">{{ detail.account.email }}</dd></div>
          <div>
            <dt class="text-[11px] text-slate-400 dark:text-slate-500">Organization</dt>
            <dd class="text-slate-900 dark:text-white" data-testid="op-reg-profile-org">{{ detail.account.orgName ?? detail.account.orgId ?? 'none' }}</dd>
          </div>
          <div>
            <dt class="text-[11px] text-slate-400 dark:text-slate-500">Status</dt>
            <dd :class="detail.account.active ? 'text-emerald-600 dark:text-emerald-400' : 'text-red-500 dark:text-red-400'" data-testid="op-reg-profile-status">
              {{ detail.account.active ? 'active' : 'deactivated' }}
            </dd>
          </div>
        </dl>

        <fieldset>
          <legend class="text-[11px] text-slate-400 dark:text-slate-500 mb-1">The role set (the primary role gates the account’s console section)</legend>
          <div class="flex flex-wrap gap-x-4 gap-y-1 mb-2" data-testid="op-reg-roles-editor">
            <label v-for="r in Object.keys(roleMap)" :key="r" class="flex items-center gap-1.5 text-sm text-slate-700 dark:text-slate-300">
              <input
                v-model="checkedRoles"
                type="checkbox"
                :value="r"
                :data-testid="`op-reg-role-check-${r}`"
                class="rounded border-slate-300"
              />
              {{ r }}
            </label>
          </div>
          <div class="flex items-center gap-2">
            <label class="text-xs text-slate-500 dark:text-slate-400" for="op-reg-primary">Primary role</label>
            <select
              id="op-reg-primary"
              v-model="primaryRole"
              data-testid="op-reg-primary"
              class="px-2 py-1.5 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-xs text-slate-900 dark:text-white"
            >
              <option v-for="r in checkedRoles" :key="r" :value="r">{{ r }}</option>
            </select>
            <button
              :disabled="acting === 'roles'"
              data-testid="op-reg-roles-save"
              class="px-3 py-1.5 text-xs font-semibold rounded-lg bg-brand-600 text-white hover:bg-brand-700 transition-colors disabled:opacity-50"
              @click="saveRoles"
            >Save roles</button>
          </div>
          <p class="mt-2 text-[11px] text-slate-400 dark:text-slate-500" data-testid="op-reg-roles-note">
            The role set is account-wide; the org_admin role is assignable only for a registered participant org (the server enforces it).
          </p>
        </fieldset>
      </section>

      <!-- What the instances receive (the honest per-client seam) -->
      <section class="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 p-5 mb-6" data-testid="op-reg-claims">
        <h2 class="text-xs font-semibold uppercase tracking-wider text-slate-400 dark:text-slate-500 mb-3">What the instances receive</h2>
        <p v-if="!clients.length" class="text-sm text-slate-500 dark:text-slate-400" data-testid="op-reg-claims-empty">
          No relying parties are registered yet — register one on the
          <router-link to="/op/admin/clients" class="text-brand-600 dark:text-brand-300 hover:underline">relying parties console</router-link>.
        </p>
        <template v-else>
          <ul class="space-y-1 mb-2" data-testid="op-reg-claims-list">
            <li v-for="cl in roleCarryingClients" :key="cl.clientId" class="text-xs text-slate-600 dark:text-slate-300" :data-testid="`op-reg-claims-client-${cl.clientId}`">
              <strong>{{ cl.name }}</strong> ({{ cl.clientId }}) receives this account’s roles in its ID tokens
              <span class="text-slate-400">(claims: {{ cl.claimsPolicy?.claims.join(', ') }}<template v-if="cl.claimsPolicy?.roles?.length">; only: {{ cl.claimsPolicy.roles.join(', ') }}</template>)</span>
            </li>
            <li v-for="cl in otherClients" :key="cl.clientId" class="text-xs text-slate-400 dark:text-slate-500" :data-testid="`op-reg-claims-client-${cl.clientId}`">
              <strong>{{ cl.name }}</strong> ({{ cl.clientId }}) receives the profile and email claims only
            </li>
          </ul>
          <!-- The per-client assignments (TODO.identity/03's rows), read
               here, edited on the user-registry console. -->
          <div class="mb-2" data-testid="op-reg-client-roles">
            <p v-if="!detail.clientRoles.length" class="text-[11px] text-slate-400 dark:text-slate-500" data-testid="op-reg-client-roles-empty">
              No per-client assignments — every relying party above receives the account-wide role set shown in the profile section.
            </p>
            <ul v-else class="space-y-1">
              <li v-for="a in detail.clientRoles" :key="a.clientId" class="text-xs text-slate-600 dark:text-slate-300" :data-testid="`op-reg-client-roles-${a.clientId}`">
                On <strong>{{ clients.find(cl => cl.clientId === a.clientId)?.name ?? a.clientId }}</strong>:
                {{ a.roles.length ? a.roles.join(', ') : 'no roles (the instance’s no-claim posture)' }}
                <span class="text-slate-400">— assigned{{ a.assignedBy ? ` by ${a.assignedBy}` : '' }}, {{ a.updatedAt.slice(0, 10) }}</span>
              </li>
            </ul>
            <p class="mt-1 text-[11px] text-slate-400 dark:text-slate-500" data-testid="op-reg-claims-seam">
              Per-client assignments are edited on the
              <router-link to="/op/admin/users" class="text-brand-600 dark:text-brand-300 hover:underline" data-testid="op-reg-client-roles-edit">user-registry console</router-link>;
              a client’s claims policy (its own allowlist included) is edited on the
              <router-link to="/op/admin/clients" class="text-brand-600 dark:text-brand-300 hover:underline">relying parties console</router-link>.
            </p>
          </div>
        </template>
      </section>

      <!-- Sign-in methods: the password state + the linked identities -->
      <section class="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 p-5 mb-6" data-testid="op-reg-methods">
        <h2 class="text-xs font-semibold uppercase tracking-wider text-slate-400 dark:text-slate-500 mb-3">Sign-in methods</h2>
        <p class="text-xs text-slate-600 dark:text-slate-300 mb-3" data-testid="op-reg-password-state">
          {{ detail.passwordSet ? 'A password is set.' : 'No password yet — the account sets it from the one-time setup link.' }}
        </p>

        <p v-if="!detail.links.length" class="text-sm text-slate-500 dark:text-slate-400" data-testid="op-reg-no-links">
          No linked identities — the account signs in with its password only.
        </p>
        <ul v-else class="space-y-2 mb-3" data-testid="op-reg-links">
          <li v-for="link in detail.links" :key="link.id" class="rounded-lg border border-slate-200 dark:border-slate-700 px-3 py-2" :data-testid="`op-reg-link-${link.provider}`">
            <div class="flex items-center justify-between gap-3">
              <p class="text-xs text-slate-600 dark:text-slate-300">
                <strong>{{ link.provider }}</strong> account <code class="font-mono">{{ link.providerAccountId }}</code>
                · linked {{ link.linkedAt.slice(0, 10) }}<template v-if="link.linkedBy"> by {{ link.linkedBy }}</template>
              </p>
              <button
                :data-testid="`op-reg-unlink-open-${link.provider}`"
                class="shrink-0 text-xs font-medium text-red-600 dark:text-red-400 hover:underline"
                @click="unlinkOpen[link.provider] = !unlinkOpen[link.provider]"
              >Unlink</button>
            </div>
            <div v-if="unlinkOpen[link.provider]" class="mt-2 flex items-center gap-2">
              <input
                v-model="unlinkReason[link.provider]"
                type="text"
                :data-testid="`op-reg-unlink-reason-${link.provider}`"
                class="flex-1 px-3 py-1.5 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-xs text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-500"
                placeholder="The reason (optional, on the record)…"
              />
              <button
                :data-testid="`op-reg-unlink-${link.provider}`"
                :disabled="acting === link.provider"
                class="px-3 py-1.5 text-xs font-semibold rounded-lg bg-red-600 text-white hover:bg-red-700 transition-colors disabled:opacity-50"
                @click="unlink(link)"
              >Confirm unlink</button>
            </div>
          </li>
        </ul>

        <!-- The administrator's link on behalf -->
        <div class="border-t border-slate-100 dark:border-slate-700 pt-3" data-testid="op-reg-link-form">
          <h3 class="text-xs font-semibold text-slate-700 dark:text-slate-300 mb-2">Link on behalf of the account holder</h3>
          <div class="grid sm:grid-cols-2 gap-2">
            <select
              v-model="linkProvider"
              data-testid="op-reg-link-provider"
              class="px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-500"
            >
              <option value="" disabled>Provider…</option>
              <option v-for="p in providers" :key="p.id" :value="p.id" :data-testid="`op-reg-link-provider-${p.id}`">{{ p.displayName }}</option>
            </select>
            <input
              v-model="linkHandle"
              type="text"
              data-testid="op-reg-link-handle"
              class="px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-500"
              placeholder="The provider’s account id (the handle)…"
            />
            <input
              v-model="linkJustification"
              type="text"
              data-testid="op-reg-link-justification"
              class="sm:col-span-2 px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-500"
              placeholder="The justification (required — it goes on the activity record)…"
            />
            <button
              :disabled="acting === 'link' || !linkProvider || !linkHandle.trim() || !linkJustification.trim()"
              data-testid="op-reg-link-submit"
              class="sm:col-span-2 py-2 rounded-lg text-sm font-medium bg-brand-600 text-white hover:bg-brand-700 transition-colors disabled:opacity-50"
              @click="linkOnBehalf"
            >Link the identity</button>
          </div>
          <p class="mt-2 text-[11px] text-slate-400 dark:text-slate-500">
            This binds the upstream account without the holder driving the provider’s consent flow; the match rule is unchanged
            (provider + account id, never an email), and the justification is audited.
          </p>
        </div>
      </section>

      <!-- The live sessions -->
      <section class="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 p-5 mb-6" data-testid="op-reg-sessions">
        <h2 class="text-xs font-semibold uppercase tracking-wider text-slate-400 dark:text-slate-500 mb-3">Sessions</h2>
        <p v-if="!detail.sessions.length" class="text-sm text-slate-500 dark:text-slate-400" data-testid="op-reg-sessions-empty">
          No live sessions.
        </p>
        <ul v-else class="space-y-2" data-testid="op-reg-sessions-list">
          <li v-for="s in detail.sessions" :key="s.id" class="flex items-center justify-between gap-3 rounded-lg border border-slate-200 dark:border-slate-700 px-3 py-2" :data-testid="`op-reg-session-${s.id}`">
            <p class="text-xs text-slate-600 dark:text-slate-300">
              signed in {{ s.createdAt.slice(0, 16).replace('T', ' ') }} · expires {{ s.expiresAt.slice(0, 16).replace('T', ' ') }}
            </p>
            <button
              :data-testid="`op-reg-revoke-${s.id}`"
              :disabled="acting === s.id"
              class="shrink-0 text-xs font-medium text-red-600 dark:text-red-400 hover:underline disabled:opacity-50"
              @click="revokeSession(s)"
            >End session</button>
          </li>
        </ul>
      </section>

      <!-- Invite / resend + deactivation -->
      <section class="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 p-5 mb-6" data-testid="op-reg-actions">
        <h2 class="text-xs font-semibold uppercase tracking-wider text-slate-400 dark:text-slate-500 mb-3">Access</h2>
        <div class="flex flex-wrap items-center gap-3">
          <button
            :disabled="acting === 'enrollment'"
            data-testid="op-reg-resend"
            class="px-3 py-1.5 text-xs font-semibold rounded-lg border border-slate-200 dark:border-slate-700 text-slate-600 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-700 transition-colors disabled:opacity-50"
            @click="resendSetup"
          >{{ detail.passwordSet ? 'Issue a password-reset link' : 'Resend the setup link' }}</button>

          <template v-if="detail.account.active">
            <button
              v-if="!deactivateArmed"
              :disabled="isSelf"
              data-testid="op-reg-deactivate"
              class="px-3 py-1.5 text-xs font-semibold rounded-lg bg-red-600 text-white hover:bg-red-700 transition-colors disabled:opacity-50"
              @click="deactivateArmed = true"
            >Deactivate…</button>
            <button
              v-else
              :disabled="acting === 'active'"
              data-testid="op-reg-deactivate-confirm"
              class="px-3 py-1.5 text-xs font-semibold rounded-lg bg-red-600 text-white hover:bg-red-700 transition-colors disabled:opacity-50"
              @click="setActive(false)"
            >Confirm deactivation</button>
          </template>
          <button
            v-else
            :disabled="acting === 'active'"
            data-testid="op-reg-reactivate"
            class="px-3 py-1.5 text-xs font-semibold rounded-lg bg-emerald-600 text-white hover:bg-emerald-700 transition-colors disabled:opacity-50"
            @click="setActive(true)"
          >Reactivate</button>
        </div>
        <p class="mt-2 text-[11px] text-slate-400 dark:text-slate-500">
          <template v-if="isSelf">You cannot deactivate your own account here.</template>
          Deactivation is honest: the history is kept, sign-ins are refused, and the live sessions stop resolving at once.
        </p>

        <!-- The erasure (the offboarding runbook's delete path): two-step,
             irreversible, never on your own account. -->
        <div class="mt-4 pt-4 border-t border-slate-100 dark:border-slate-700">
          <div class="flex gap-2">
            <button
              v-if="!eraseArmed"
              :disabled="acting === 'erase' || isSelf"
              data-testid="op-reg-erase"
              class="px-3 py-1.5 text-xs font-semibold rounded-lg border border-red-300 dark:border-red-800 text-red-700 dark:text-red-300 hover:bg-red-50 dark:hover:bg-red-900/20 transition-colors disabled:opacity-50"
              @click="eraseArmed = true"
            >Delete account…</button>
            <template v-else>
              <button
                :disabled="acting === 'erase'"
                data-testid="op-reg-erase-confirm"
                class="px-3 py-1.5 text-xs font-semibold rounded-lg bg-red-600 text-white hover:bg-red-700 transition-colors disabled:opacity-50"
                @click="eraseAccount"
              >{{ acting === 'erase' ? 'Erasing…' : 'Confirm: erase the account permanently' }}</button>
              <button
                class="px-3 py-1.5 text-xs rounded-lg border border-slate-200 dark:border-slate-700 text-slate-600 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-700 transition-colors"
                @click="eraseArmed = false"
              >Cancel</button>
            </template>
          </div>
          <p v-if="eraseArmed" class="mt-2 text-[11px] text-red-600 dark:text-red-400" data-testid="op-reg-erase-warning">
            Erasure removes the person from the account: the password, the linked identities, the setup and verification links, the per-client role assignments, the live sessions and tokens, and the uploaded picture all go; the row stays as an anonymized tombstone so the audit trail still resolves. This cannot be undone.
          </p>
          <p v-if="isSelf" class="mt-1 text-[11px] text-slate-400 dark:text-slate-500">You cannot erase your own account here.</p>
        </div>
      </section>

      <!-- The account's own audit trail -->
      <section class="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 p-5" data-testid="op-reg-activity">
        <h2 class="text-xs font-semibold uppercase tracking-wider text-slate-400 dark:text-slate-500 mb-3">
          Activity
          <router-link to="/op/admin/activity" class="ml-2 font-normal normal-case text-brand-600 dark:text-brand-300 hover:underline">the registry’s full activity →</router-link>
        </h2>
        <p v-if="!detail.activity.length" class="text-sm text-slate-500 dark:text-slate-400" data-testid="op-reg-activity-empty">
          Nothing on the record yet for this account.
        </p>
        <ul v-else class="space-y-1" data-testid="op-reg-activity-list">
          <li v-for="event in detail.activity" :key="event.id" class="text-[11px] text-slate-500 dark:text-slate-400" :data-testid="`op-reg-event-${event.id}`">
            {{ event.timestamp.slice(0, 16).replace('T', ' ') }} — {{ event.user_name ?? 'the account' }}: {{ activityLine(event) }}
          </li>
        </ul>
      </section>
    </div>
  </div>
</template>
