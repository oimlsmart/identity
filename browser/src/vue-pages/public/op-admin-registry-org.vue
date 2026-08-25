<script setup lang="ts">
// ═══════════════════════════════════════════════════════════════════
// The registry's PER-ORG view (TODO.identity/11 — the multi-org
// membership model): one organization on the participants register with
// its MEMBERS (the memberships: the per-org role sets + the lifecycle
// states, the org_admins marked), its join-request queue (every state),
// and the identity admin's membership acts (invite an existing account,
// edit the per-org roles, disable/re-activate — routes/op-memberships.ts
// enforces the bounds; this page only renders what the APIs answer).
//
// The audience is the identity administrator (admin/cs_admin — the
// registry console's gate). The org admin's own people console is
// /op/admin/users (the org-scoped grant).
// ═══════════════════════════════════════════════════════════════════
import { computed, onMounted, ref } from 'vue'
import { useRoute } from 'vue-router'
import PageHeader from '../../components/PageHeader.vue'
import OpAdminNav from '../../components/OpAdminNav.vue'
import { useBranding } from '../../branding'

interface OrgInfo {
  id: string
  name: string
  shortName: string
  kind: string
  country: string
  registered: boolean
  roles: string[]
}

interface MemberRow {
  userId: string
  name: string
  email: string | null
  provider: string | null
  accountActive: boolean
  orgId: string
  roles: string[]
  state: 'invited' | 'active' | 'disabled'
  isPrimary: boolean
  invitedBy: string | null
  createdAt: string
  activatedAt: string | null
  disabledAt: string | null
  disabledBy: string | null
}

interface JoinRequestRow {
  id: string
  name: string
  email: string
  requestedRole: string
  note: string | null
  status: 'pending' | 'approved' | 'refused'
  decidedBy: string | null
  decidedAt: string | null
  refusalReason: string | null
  createdAt: string
}

interface OrgView {
  org: OrgInfo
  members: MemberRow[]
  requests: JoinRequestRow[]
}

const route = useRoute()
const { branding } = useBranding()
const orgId = computed(() => String(route.params.id ?? ''))

const loading = ref(true)
const forbidden = ref(false)
const notFound = ref(false)
const error = ref<string | null>(null)
const notice = ref<string | null>(null)
const acting = ref<string | null>(null)

const view = ref<OrgView | null>(null)

// The identity admin's acts.
const memberRolesOpen = ref<string | null>(null)
const memberRoleDrafts = ref<Record<string, string[]>>({})
const addEmail = ref('')
const addRoleChecks = ref<string[]>([])

/** The org's administrators (the org_admin memberships — the scheme
 *  operator's delegation). */
const orgAdmins = computed(() => view.value?.members.filter(m => m.roles.includes('org_admin')) ?? [])

/** The role options the org's kind bounds, plus org_admin (the wide
 *  grant's delegation act — the server re-checks the eligibility). */
const roleOptions = computed(() => (view.value ? [...view.value.org.roles, 'org_admin'] : []))

function fmtDate(iso: string | null): string {
  if (!iso) return '—'
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })
}

async function api(path: string, init?: RequestInit): Promise<Response> {
  return fetch(path, {
    credentials: 'include',
    ...(init?.body ? { headers: { 'content-type': 'application/json' } } : {}),
    ...init,
  })
}

async function load(): Promise<void> {
  const res = await api(`/api/op/registry/orgs/${encodeURIComponent(orgId.value)}`)
  if (res.status === 401) {
    window.location.assign(`/?redirect=${encodeURIComponent(`/op/admin/registry/orgs/${orgId.value}`)}`)
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
  if (!res.ok) throw new Error(`the organization failed (${res.status})`)
  view.value = await res.json() as OrgView
}

function openMemberRoles(m: MemberRow) {
  memberRolesOpen.value = memberRolesOpen.value === m.userId ? null : m.userId
  memberRoleDrafts.value[m.userId] = [...m.roles]
}

async function saveMemberRoles(m: MemberRow) {
  if (acting.value) return
  acting.value = m.userId
  error.value = null
  notice.value = null
  try {
    const res = await api(`/api/op/org-memberships/${encodeURIComponent(m.userId)}/${encodeURIComponent(m.orgId)}/roles`, {
      method: 'PUT',
      body: JSON.stringify({ roles: memberRoleDrafts.value[m.userId] ?? [] }),
    })
    if (!res.ok) {
      const body = await res.json().catch(() => ({})) as { error?: string }
      error.value = body.error ?? `The role assignment failed (${res.status}).`
      return
    }
    notice.value = `${m.name}'s roles updated.`
    memberRolesOpen.value = null
    await load()
  } catch {
    error.value = 'Network error. Is the server running?'
  } finally {
    acting.value = null
  }
}

async function setMemberState(m: MemberRow, state: 'active' | 'disabled') {
  if (acting.value) return
  acting.value = m.userId
  error.value = null
  notice.value = null
  try {
    const res = await api(`/api/op/org-memberships/${encodeURIComponent(m.userId)}/${encodeURIComponent(m.orgId)}/state`, {
      method: 'POST',
      body: JSON.stringify({ state }),
    })
    if (!res.ok) {
      const body = await res.json().catch(() => ({})) as { error?: string }
      error.value = body.error ?? `(${res.status})`
      return
    }
    notice.value = state === 'disabled'
      ? `${m.name}'s membership is disabled — their sessions stopped acting as ${view.value?.org.name ?? 'this organization'}.`
      : `${m.name}'s membership is active again.`
    await load()
  } catch {
    error.value = 'Network error. Is the server running?'
  } finally {
    acting.value = null
  }
}

/** Invite an EXISTING account into the org (the holder accepts from the
 *  account console). */
async function inviteMember() {
  if (acting.value) return
  acting.value = 'invite'
  error.value = null
  notice.value = null
  try {
    const res = await api('/api/op/org-memberships', {
      method: 'POST',
      body: JSON.stringify({ email: addEmail.value.trim(), org_id: orgId.value, roles: addRoleChecks.value }),
    })
    if (!res.ok) {
      const body = await res.json().catch(() => ({})) as { error?: string }
      error.value = body.error ?? `The membership invite failed (${res.status}).`
      return
    }
    notice.value = `${addEmail.value.trim()} is invited — the invitation waits on their account console.`
    addEmail.value = ''
    addRoleChecks.value = []
    await load()
  } catch {
    error.value = 'Network error. Is the server running?'
  } finally {
    acting.value = null
  }
}

onMounted(async () => {
  try {
    const session = await fetch('/api/auth/session', { credentials: 'include' })
    if (!session.ok) {
      window.location.assign(`/?redirect=${encodeURIComponent(`/op/admin/registry/orgs/${orgId.value}`)}`)
      return
    }
    await load()
  } catch (e) {
    error.value = (e as Error).message || 'Network error. Is the server running?'
  } finally {
    loading.value = false
  }
})
</script>

<template>
  <div class="max-w-3xl mx-auto px-6 py-10 w-full">
    <div v-if="loading" class="flex flex-col items-center gap-4 py-24">
      <div class="w-8 h-8 border-2 border-brand-300 border-t-brand-600 rounded-full animate-spin" />
    </div>

    <div v-else-if="forbidden" class="max-w-md mx-auto py-16">
      <div class="text-center mb-8">
        <h1 class="text-xl font-serif font-bold text-slate-900 dark:text-white">Registry organization</h1>
      </div>
      <div class="p-3 rounded-lg bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800">
        <p class="text-sm text-amber-800 dark:text-amber-300" data-testid="op-reg-org-forbidden">
          The registry's organization view is an administrator surface — your account does not hold the administrator role.
        </p>
      </div>
    </div>

    <div v-else-if="notFound" class="max-w-md mx-auto py-16 text-center">
      <p class="text-sm text-slate-500 dark:text-slate-400" data-testid="op-reg-org-notfound">
        This organization is not on the participants register.
      </p>
    </div>

    <div v-else-if="view" data-testid="op-reg-org">
      <p class="mb-2 text-sm" data-testid="op-reg-org-back">
        <router-link to="/op/admin/registry" class="text-brand-600 hover:text-brand-700 dark:text-brand-300 dark:hover:text-brand-200 font-medium transition-colors">← the identity registry</router-link>
      </p>
      <PageHeader :title="view.org.name" title-test-id="op-reg-org-name">
        <template #description>
          <span data-testid="op-reg-org-context">
            {{ view.org.kind }}<template v-if="view.org.country"> · {{ view.org.country }}</template>
            <span
              class="ml-2 px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wider"
              :class="view.org.registered ? 'bg-emerald-100 dark:bg-emerald-900/30 text-emerald-700 dark:text-emerald-300' : 'bg-amber-100 dark:bg-amber-900/30 text-amber-700 dark:text-amber-300'"
              data-testid="op-reg-org-registered"
            >{{ view.org.registered ? 'registered participant' : 'not registered' }}</span>
            — {{ branding.productName }}
          </span>
        </template>
      </PageHeader>
      <OpAdminNav current="registry" />

      <div v-if="error" class="mb-4 p-3 rounded-lg bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800">
        <p class="text-sm text-red-700 dark:text-red-300" data-testid="op-reg-org-error">{{ error }}</p>
      </div>
      <div v-if="notice" class="mb-4 p-3 rounded-lg bg-emerald-50 dark:bg-emerald-900/20 border border-emerald-200 dark:border-emerald-800">
        <p class="text-sm text-emerald-800 dark:text-emerald-300" data-testid="op-reg-org-notice">{{ notice }}</p>
      </div>

      <!-- The members: the memberships with their per-org role sets. -->
      <section class="rounded-xl border border-slate-200/80 dark:border-slate-700 bg-white dark:bg-slate-800 p-6 mb-6" data-testid="op-reg-org-members">
        <h2 class="text-xs font-semibold uppercase tracking-wider text-slate-400 dark:text-slate-500 mb-1">Members</h2>
        <p class="text-xs text-slate-500 dark:text-slate-400 mb-3" data-testid="op-reg-org-admins">
          <template v-if="orgAdmins.length">
            Organization administrator{{ orgAdmins.length > 1 ? 's' : '' }}:
            <span v-for="(a, i) in orgAdmins" :key="a.userId" :data-testid="`op-reg-org-admin-${a.userId}`">{{ i ? ', ' : '' }}{{ a.name }} &lt;{{ a.email }}&gt;</span>
          </template>
          <template v-else>No organization administrator yet — the scheme operator creates one from the organization administration console.</template>
        </p>
        <p v-if="!view.members.length" class="text-sm text-slate-500 dark:text-slate-400" data-testid="op-reg-org-members-empty">
          No memberships yet.
        </p>
        <ul v-else class="space-y-2" data-testid="op-reg-org-members-list">
          <li
            v-for="m in view.members"
            :key="m.userId"
            class="rounded-lg border border-slate-200 dark:border-slate-700 px-3 py-2"
            :data-testid="`op-reg-org-member-${m.userId}`"
          >
            <div class="flex items-center justify-between gap-3 flex-wrap">
              <div class="min-w-0">
                <p class="text-sm font-medium text-slate-900 dark:text-white break-words">
                  <router-link
                    :to="`/op/admin/registry/users/${m.userId}`"
                    class="hover:underline text-brand-700 dark:text-brand-300"
                    :data-testid="`op-reg-org-member-open-${m.userId}`"
                  >{{ m.name }}</router-link>
                  <span class="font-normal text-slate-500 dark:text-slate-400">&lt;{{ m.email }}&gt;</span>
                  <span v-if="m.isPrimary" class="ml-1 text-[10px] px-1.5 py-0.5 rounded bg-slate-100 dark:bg-slate-700 text-slate-500 dark:text-slate-300 font-semibold uppercase tracking-wider">primary</span>
                  <span v-if="m.state === 'invited'" class="ml-1 text-[10px] px-1.5 py-0.5 rounded bg-amber-100 dark:bg-amber-900/30 text-amber-700 dark:text-amber-300 font-semibold uppercase tracking-wider">invited</span>
                  <span v-if="m.state === 'disabled'" class="ml-1 text-[10px] px-1.5 py-0.5 rounded bg-red-100 dark:bg-red-900/40 text-red-600 dark:text-red-400 font-semibold uppercase tracking-wider">disabled</span>
                  <span v-if="!m.accountActive" class="ml-1 text-[10px] px-1.5 py-0.5 rounded bg-red-100 dark:bg-red-900/40 text-red-600 dark:text-red-400 font-semibold">account deactivated</span>
                </p>
                <p class="text-[11px] text-slate-400 dark:text-slate-500" :data-testid="`op-reg-org-member-roles-${m.userId}`">
                  {{ m.roles.join(', ') || 'no organization roles' }}
                  <template v-if="m.state === 'invited' && m.invitedBy"> · invited by {{ m.invitedBy }}</template>
                  <template v-if="m.state === 'disabled'"> · disabled {{ fmtDate(m.disabledAt) }}<template v-if="m.disabledBy"> by {{ m.disabledBy }}</template></template>
                </p>
              </div>
              <div class="shrink-0 flex items-center gap-3 text-xs font-medium">
                <button
                  :data-testid="`op-reg-org-member-roles-edit-${m.userId}`"
                  :disabled="acting === m.userId"
                  class="text-brand-600 dark:text-brand-300 hover:underline disabled:opacity-50"
                  @click="openMemberRoles(m)"
                >{{ memberRolesOpen === m.userId ? 'Close' : 'Roles' }}</button>
                <button
                  v-if="m.state !== 'invited'"
                  :data-testid="`op-reg-org-member-toggle-${m.userId}`"
                  :disabled="acting === m.userId"
                  class="hover:underline disabled:opacity-50"
                  :class="m.state === 'active' ? 'text-red-600 dark:text-red-400' : 'text-emerald-600 dark:text-emerald-400'"
                  @click="setMemberState(m, m.state === 'active' ? 'disabled' : 'active')"
                >{{ m.state === 'active' ? 'Disable' : 'Re-activate' }}</button>
              </div>
            </div>
            <div v-if="memberRolesOpen === m.userId" class="mt-2 border-t border-slate-100 dark:border-slate-700 pt-2" :data-testid="`op-reg-org-member-editor-${m.userId}`">
              <div class="flex flex-wrap gap-x-4 gap-y-1 mb-2">
                <label v-for="r in roleOptions" :key="r" class="flex items-center gap-1.5 text-xs text-slate-700 dark:text-slate-300">
                  <input
                    type="checkbox"
                    :value="r"
                    v-model="memberRoleDrafts[m.userId]"
                    :data-testid="`op-reg-org-member-check-${m.userId}-${r}`"
                    class="rounded border-slate-300 dark:border-slate-600 text-brand-600 focus:ring-brand-500"
                  />
                  {{ r }}
                </label>
              </div>
              <button
                :disabled="acting === m.userId"
                :data-testid="`op-reg-org-member-save-${m.userId}`"
                class="px-3 py-1.5 rounded-lg text-xs font-medium bg-brand-600 text-white hover:bg-brand-700 transition-colors disabled:opacity-50"
                @click="saveMemberRoles(m)"
              >Save the roles</button>
            </div>
          </li>
        </ul>

        <!-- The invite (an existing account; the holder accepts). -->
        <div class="mt-4 border-t border-slate-100 dark:border-slate-700 pt-3" data-testid="op-reg-org-invite">
          <h3 class="text-xs font-semibold text-slate-700 dark:text-slate-300 mb-2">Invite an existing account</h3>
          <div class="grid sm:grid-cols-2 gap-2">
            <input
              v-model="addEmail"
              type="email"
              data-testid="op-reg-org-invite-email"
              class="px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-500"
              placeholder="The account’s email"
            />
            <button
              :disabled="acting === 'invite' || !addEmail.includes('@')"
              data-testid="op-reg-org-invite-submit"
              class="py-2 rounded-lg text-sm font-medium bg-brand-600 text-white hover:bg-brand-700 transition-colors disabled:opacity-50"
              @click="inviteMember"
            >{{ acting === 'invite' ? 'Inviting…' : 'Invite the membership' }}</button>
          </div>
          <div class="mt-2 flex flex-wrap gap-x-4 gap-y-1">
            <label v-for="r in roleOptions" :key="r" class="flex items-center gap-1.5 text-xs text-slate-700 dark:text-slate-300">
              <input
                type="checkbox"
                :value="r"
                v-model="addRoleChecks"
                :data-testid="`op-reg-org-invite-role-${r}`"
                class="rounded border-slate-300 dark:border-slate-600 text-brand-600 focus:ring-brand-500"
              />
              {{ r }}
            </label>
          </div>
          <p class="mt-2 text-[11px] text-slate-400 dark:text-slate-500">
            The invitation waits on the account holder's console until they accept or decline it. A person with
            no account yet comes in through the join-request queue below (its approval creates the account).
          </p>
        </div>
      </section>

      <!-- The org's join-request queue (every state, newest first). -->
      <section class="rounded-xl border border-slate-200/80 dark:border-slate-700 bg-white dark:bg-slate-800 p-6" data-testid="op-reg-org-requests">
        <h2 class="text-xs font-semibold uppercase tracking-wider text-slate-400 dark:text-slate-500 mb-3">Join requests</h2>
        <p v-if="!view.requests.length" class="text-sm text-slate-500 dark:text-slate-400" data-testid="op-reg-org-requests-empty">
          No join requests naming this organization.
        </p>
        <ul v-else class="space-y-1" data-testid="op-reg-org-requests-list">
          <li
            v-for="r in view.requests"
            :key="r.id"
            class="flex items-center justify-between rounded-lg border border-slate-100 dark:border-slate-700/60 px-3 py-2"
            :data-testid="`op-reg-org-request-${r.id}`"
          >
            <p class="text-xs text-slate-600 dark:text-slate-300">
              {{ r.name }} &lt;{{ r.email }}&gt; · {{ r.requestedRole }}
            </p>
            <p class="shrink-0 pl-3 text-xs">
              <span v-if="r.status === 'pending'" class="text-amber-600 dark:text-amber-400">pending</span>
              <span v-else-if="r.status === 'approved'" class="text-emerald-600 dark:text-emerald-400">approved</span>
              <span v-else class="text-red-600 dark:text-red-400">refused<template v-if="r.refusalReason">: {{ r.refusalReason }}</template></span>
            </p>
          </li>
        </ul>
        <p v-if="view.requests.some(r => r.status === 'pending')" class="mt-3 text-[11px] text-slate-400 dark:text-slate-500">
          The decisions happen on the
          <router-link to="/op/admin/users" class="text-brand-600 dark:text-brand-300 hover:underline">organization administration console</router-link>.
        </p>
      </section>
    </div>
  </div>
</template>
