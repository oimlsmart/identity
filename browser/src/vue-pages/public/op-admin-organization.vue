<script setup lang="ts">
// ═══════════════════════════════════════════════════════════════════
// TODO.sota/02 — the ORG ADMINISTRATORS' CONSOLE: the delegated
// administration surface the grants always allowed but no page served.
// The org admin sees THEIR org's members, the join queue, and the
// audit slice; the system_admin picks any organization. Every action
// rides an existing, grant-gated endpoint — the page is a reader and
// an actor through the proven seams, never a new authority.
// ═══════════════════════════════════════════════════════════════════
import { computed, onMounted, ref } from 'vue'
import { useRoute } from 'vue-router'
import PageHeader from '../../components/PageHeader.vue'
import { t } from '../../i18n'
import { api } from '../../lib/api-client'

const route = useRoute()

const loading = ref(true)
const error = ref<string | null>(null)
const notice = ref<string | null>(null)
const acting = ref<string | null>(null)

// TODO.sota/06 — the step-up surface: a privileged act's 403 opens the
// modal; the password mints the stamp; the act retries.
const stepUpOpen = ref(false)
const stepUpPassword = ref('')
const stepUpBusy = ref(false)
const stepUpError = ref<string | null>(null)
const stepUpRetry = ref<(() => Promise<void>) | null>(null)
async function demandStepUp(retry: () => Promise<void>): Promise<void> {
  stepUpRetry.value = retry
  stepUpError.value = null
  stepUpOpen.value = true
}
async function submitStepUp(password: string): Promise<void> {
  stepUpBusy.value = true
  stepUpError.value = null
  try {
    const res = await fetch('/api/op/step-up', {
      method: 'POST', headers: { 'content-type': 'application/json' }, credentials: 'include',
      body: JSON.stringify({ password }),
    })
    if (!res.ok) {
      stepUpError.value = t('stepup.wrong')
      return
    }
    const body = await res.json().catch(() => null) as { stamp?: string; expiresInSec?: number } | null
    if (body?.stamp) {
      try { sessionStorage.setItem('op_step_up', body.stamp) } catch { /* private mode: the cookie fallback */ }
      if (body.expiresInSec) {
        try { setTimeout(() => sessionStorage.removeItem('op_step_up'), body.expiresInSec * 1000) } catch { /* same */ }
      }
    }
    stepUpOpen.value = false
    await stepUpRetry.value?.()
  } catch {
    stepUpError.value = t('error.network')
  } finally {
    stepUpBusy.value = false
  }
}

interface Envelope { grant: 'wide' | 'org'; orgId: string | null; orgName: string | null; requests: JoinRequestRow[] }
let envelope = ref<Envelope | null>(null)

/** The wide grant's selected org (a system_admin picks any); the org
 *  grant's own org pins it. */
const selectedOrgId = ref<string | null>(null)

interface RegistryOrg { id: string; name: string; kind: string }
const registryOrgs = ref<RegistryOrg[]>([])

interface MemberRow { id: string; name: string; email: string; role: string; orgId: string | null; active: boolean }
const members = ref<MemberRow[]>([])
const roleMap = ref<Record<string, string[]>>({})
const roleDraft = ref<Record<string, string>>({})

interface ActivityRow { action: string; timestamp: string; metadata: Record<string, unknown> }
const activity = ref<ActivityRow[]>([])

interface JoinRequestRow {
  id: string; name: string; email: string; orgId: string | null; orgName: string | null
  status: 'pending' | 'approved' | 'refused'
}
const refuseOpen = ref<Record<string, boolean>>({})
const refuseReason = ref<Record<string, string>>({})
const lastInvite = ref<{ email: string; setupUrl: string } | null>(null)

const pending = computed(() => envelope.value?.requests.filter(r => r.status === 'pending') ?? [])
const shownMembers = computed(() =>
  selectedOrgId.value ? members.value.filter(m => m.orgId === selectedOrgId.value) : members.value)

async function loadAll(): Promise<void> {
  const queueRes = await api('/api/op/join-requests')
  if (queueRes.status === 401) {
    window.location.assign(`/?redirect=${encodeURIComponent(route.fullPath)}`)
    return
  }
  if (queueRes.status === 403) {
    error.value = t('admin.users.consoleGrant')
    loading.value = false
    return
  }
  if (!queueRes.ok) throw new Error(`the join-request queue failed (${queueRes.status})`)
  envelope.value = await queueRes.json() as Envelope
  selectedOrgId.value = envelope.value.orgId

  const [usersRes, rolesRes] = await Promise.all([api('/api/users'), api('/api/users/roles')])
  if (usersRes.ok) {
    members.value = await usersRes.json() as MemberRow[]
    for (const m of members.value) roleDraft.value[m.id] = m.role
  }
  if (rolesRes.ok) roleMap.value = await rolesRes.json() as Record<string, string[]>

  if (envelope.value.grant === 'wide') {
    const orgsRes = await api('/api/op/registry/orgs')
    if (orgsRes.ok) {
      registryOrgs.value = await orgsRes.json() as RegistryOrg[]
      if (!selectedOrgId.value && registryOrgs.value.length) selectedOrgId.value = registryOrgs.value[0]!.id
    }
  }
  await loadActivity()
  loading.value = false
}

async function loadActivity(): Promise<void> {
  if (!selectedOrgId.value) {
    activity.value = []
    return
  }
  const res = await api(`/api/op/org-memberships/activity?org_id=${encodeURIComponent(selectedOrgId.value)}`)
  if (res.ok) activity.value = ((await res.json()) as { activity: ActivityRow[] }).activity ?? []
}

async function pickOrg(): Promise<void> {
  await loadActivity()
}

async function saveRole(row: MemberRow): Promise<void> {
  if (acting.value) return
  const role = roleDraft.value[row.id] ?? row.role
  if (role === row.role) return
  acting.value = row.id
  error.value = null
  try {
    const res = await api(`/api/users/${encodeURIComponent(row.id)}/roles`, {
      method: 'PUT',
      headers: (() => { try { const st = sessionStorage.getItem('op_step_up'); return st ? { 'x-op-step-up': st } : undefined } catch { return undefined } })(),
      body: JSON.stringify({ role, roles: [role] }),
    })
    if (!res.ok) {
      const body = await res.json().catch(() => ({})) as { error?: string; stepUp?: boolean }
      if (body.stepUp) {
        await demandStepUp(() => saveRole(row))
        return
      }
      error.value = body.error ?? t('admin.org.actionFailed')
      return
    }
    notice.value = t('admin.org.roleSaved', { name: row.name, role })
    await loadAll()
  } catch {
    error.value = t('error.network')
  } finally {
    acting.value = null
  }
}

async function toggleActive(row: MemberRow): Promise<void> {
  if (acting.value) return
  acting.value = row.id
  error.value = null
  try {
    const res = await api(`/api/users/${encodeURIComponent(row.id)}/active`, {
      method: 'PUT',
      body: JSON.stringify({ active: !row.active }),
    })
    if (!res.ok) {
      const body = await res.json().catch(() => ({})) as { error?: string }
      error.value = body.error ?? t('admin.org.actionFailed')
      return
    }
    await loadAll()
  } catch {
    error.value = t('error.network')
  } finally {
    acting.value = null
  }
}

async function approve(row: JoinRequestRow): Promise<void> {
  if (acting.value) return
  acting.value = row.id
  error.value = null
  notice.value = null
  lastInvite.value = null
  try {
    const payload: Record<string, unknown> = {}
    if (!row.orgId && selectedOrgId.value) payload.org_id = selectedOrgId.value
    const res = await api(`/api/op/join-requests/${encodeURIComponent(row.id)}/approve`, {
      method: 'POST',
      body: JSON.stringify(payload),
    })
    if (!res.ok) {
      const body = await res.json().catch(() => ({})) as { error?: string }
      error.value = body.error ?? t('admin.org.actionFailed')
      return
    }
    const decided = await res.json() as { invite?: { setupUrl?: string } }
    if (decided.invite?.setupUrl) lastInvite.value = { email: row.email, setupUrl: decided.invite.setupUrl }
    notice.value = decided.invite?.setupUrl
      ? t('admin.users.approvedShown', { name: row.name })
      : t('admin.org.approved', { name: row.name })
    await loadAll()
  } catch {
    error.value = t('error.network')
  } finally {
    acting.value = null
  }
}

async function refuse(row: JoinRequestRow): Promise<void> {
  if (acting.value) return
  const reason = (refuseReason.value[row.id] ?? '').trim()
  if (!reason) {
    error.value = t('admin.users.needReason')
    return
  }
  acting.value = row.id
  error.value = null
  try {
    const res = await api(`/api/op/join-requests/${encodeURIComponent(row.id)}/refuse`, {
      method: 'POST',
      body: JSON.stringify({ reason }),
    })
    if (!res.ok) {
      const body = await res.json().catch(() => ({})) as { error?: string }
      error.value = body.error ?? t('admin.org.actionFailed')
      return
    }
    notice.value = t('admin.users.refused', { name: row.name })
    refuseOpen.value[row.id] = false
    await loadAll()
  } catch {
    error.value = t('error.network')
  } finally {
    acting.value = null
  }
}

onMounted(async () => {
  try {
    await loadAll()
  } catch (err) {
    error.value = (err as Error).message
    loading.value = false
  }
})
</script>

<template>
  <div class="max-w-4xl mx-auto px-4 py-8" data-testid="op-org-admin">
    <PageHeader :title="t('admin.org.title')" :subtitle="envelope?.orgName ?? (envelope?.grant === 'wide' ? t('admin.users.wideView') : '')" />

    <div v-if="error" class="mb-4 p-3 rounded-lg bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800">
      <p class="text-sm text-red-700 dark:text-red-300" data-testid="org-admin-error">{{ error }}</p>
    </div>
    <div v-if="notice" class="mb-4 p-3 rounded-lg bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800">
      <p class="text-sm text-green-700 dark:text-green-300" data-testid="org-admin-notice">{{ notice }}</p>
      <p v-if="lastInvite" class="mt-2 text-xs break-all text-slate-600 dark:text-slate-400" data-testid="org-admin-invite">
        <a :href="lastInvite.setupUrl" class="text-brand-600 dark:text-brand-300 hover:underline">{{ lastInvite.email }} — {{ t('admin.users.setupLink') }}</a>
      </p>
    </div>

    <div v-if="loading" class="py-16 flex justify-center">
      <div class="w-8 h-8 border-2 border-brand-300 border-t-brand-600 rounded-full animate-spin" />
    </div>

    <template v-else>
      <div v-if="envelope?.grant === 'wide'" class="mb-6">
        <label class="block text-xs font-medium text-slate-600 dark:text-slate-300 mb-1" for="org-admin-org">{{ t('admin.org.pickOrg') }}</label>
        <select
          id="org-admin-org" v-model="selectedOrgId"
          class="px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white"
          data-testid="org-admin-org"
          @change="pickOrg"
        >
          <option v-for="o in registryOrgs" :key="o.id" :value="o.id">{{ o.name }}</option>
        </select>
      </div>

      <section class="mb-8" data-testid="org-admin-members">
        <h2 class="text-sm font-semibold text-slate-700 dark:text-slate-300 mb-2">{{ t('admin.org.members') }}</h2>
        <div class="rounded-lg border border-slate-200 dark:border-slate-700 divide-y divide-slate-100 dark:divide-slate-700">
          <div v-for="m in shownMembers" :key="m.id" class="p-3 flex flex-wrap items-center gap-2">
            <div class="flex-1 min-w-[12rem]">
              <p class="text-sm font-medium text-slate-900 dark:text-white">{{ m.name }}</p>
              <p class="text-xs text-slate-500 dark:text-slate-400">{{ m.email }}<span v-if="!m.active"> · {{ t('admin.org.inactive') }}</span></p>
            </div>
            <select
              v-model="roleDraft[m.id]"
              class="px-2 py-1.5 rounded-lg border border-slate-200 dark:border-slate-600 bg-white dark:bg-slate-700 text-xs text-slate-900 dark:text-white"
              :data-testid="`org-admin-role-${m.id}`"
            >
              <option v-for="role in Object.keys(roleMap)" :key="role" :value="role">{{ role }}</option>
            </select>
            <button
              :disabled="acting === m.id || (roleDraft[m.id] ?? m.role) === m.role"
              class="px-3 py-1.5 text-xs font-semibold rounded-lg bg-brand-600 text-white hover:bg-brand-700 disabled:opacity-50"
              :data-testid="`org-admin-role-save-${m.id}`"
              @click="saveRole(m)"
            >{{ t('admin.org.save') }}</button>
            <button
              :disabled="acting === m.id"
              class="px-3 py-1.5 text-xs rounded-lg border border-slate-200 dark:border-slate-600 text-slate-600 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-700 disabled:opacity-50"
              :data-testid="`org-admin-active-${m.id}`"
              @click="toggleActive(m)"
            >{{ m.active ? t('admin.org.deactivate') : t('admin.org.activate') }}</button>
          </div>
          <p v-if="!shownMembers.length" class="p-3 text-sm text-slate-500 dark:text-slate-400">{{ t('admin.org.noMembers') }}</p>
        </div>
      </section>

      <section class="mb-8" data-testid="org-admin-queue">
        <h2 class="text-sm font-semibold text-slate-700 dark:text-slate-300 mb-2">{{ t('admin.users.queueOrg', { org: envelope?.orgName ?? '' }) }}</h2>
        <div class="rounded-lg border border-slate-200 dark:border-slate-700 divide-y divide-slate-100 dark:divide-slate-700">
          <div v-for="r in pending" :key="r.id" class="p-3">
            <p class="text-sm font-medium text-slate-900 dark:text-white">{{ r.name }} <span class="font-normal text-slate-500 dark:text-slate-400">· {{ r.email }}</span></p>
            <div class="mt-2 flex items-center gap-2 flex-wrap">
              <button
                :disabled="acting === r.id"
                class="px-3 py-1.5 text-xs font-semibold rounded-lg bg-brand-600 text-white hover:bg-brand-700 disabled:opacity-50"
                :data-testid="`org-admin-approve-${r.id}`"
                @click="approve(r)"
              >{{ t('admin.users.approve') }}</button>
              <button
                :disabled="acting === r.id"
                class="px-3 py-1.5 text-xs rounded-lg border border-slate-200 dark:border-slate-600 text-slate-600 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-700 disabled:opacity-50"
                :data-testid="`org-admin-refuse-open-${r.id}`"
                @click="refuseOpen[r.id] = !refuseOpen[r.id]"
              >{{ t('admin.users.refuse') }}</button>
            </div>
            <div v-if="refuseOpen[r.id]" class="mt-2 flex items-center gap-2">
              <input
                v-model="refuseReason[r.id]" type="text"
                class="flex-1 px-3 py-1.5 rounded-lg border border-slate-200 dark:border-slate-600 bg-white dark:bg-slate-800 text-xs text-slate-900 dark:text-white"
                :data-testid="`org-admin-refuse-reason-${r.id}`"
                :placeholder="t('admin.users.reasonPlaceholder')"
              />
              <button
                :disabled="acting === r.id"
                class="px-3 py-1.5 text-xs font-semibold rounded-lg border border-red-200 dark:border-red-800 text-red-700 dark:text-red-300 hover:bg-red-50 dark:hover:bg-red-900/20 disabled:opacity-50"
                :data-testid="`org-admin-refuse-${r.id}`"
                @click="refuse(r)"
              >{{ t('admin.users.confirmRefusal') }}</button>
            </div>
          </div>
          <p v-if="!pending.length" class="p-3 text-sm text-slate-500 dark:text-slate-400">{{ t('admin.users.noRequests') }}</p>
        </div>
      </section>

      <section data-testid="org-admin-activity">
        <h2 class="text-sm font-semibold text-slate-700 dark:text-slate-300 mb-2">{{ t('admin.org.activity') }}</h2>
        <div class="rounded-lg border border-slate-200 dark:border-slate-700 divide-y divide-slate-100 dark:divide-slate-700">
          <div v-for="(a, i) in activity.slice(0, 20)" :key="i" class="p-3 text-xs text-slate-600 dark:text-slate-400">
            <span class="font-medium text-slate-900 dark:text-white">{{ a.action }}</span>
            <span class="ml-2">{{ new Date(a.timestamp).toLocaleString() }}</span>
          </div>
          <p v-if="!activity.length" class="p-3 text-sm text-slate-500 dark:text-slate-400">{{ t('admin.org.noActivity') }}</p>
        </div>
      </section>
    </template>
  </div>
  <!-- TODO.sota/06 — the step-up modal, INLINED (the page's own
       template; the estate's modal pattern): the password mints the
       stamp; the blocked act retries. -->
  <div v-if="stepUpOpen" class="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/50 px-4" data-testid="step-up-modal">
    <div class="w-full max-w-sm bg-white dark:bg-slate-800 rounded-xl border border-slate-200 dark:border-slate-700 p-6">
      <h2 class="text-base font-serif font-bold text-slate-900 dark:text-white" data-testid="step-up-title">{{ t('stepup.title') }}</h2>
      <p class="mt-2 text-sm text-slate-600 dark:text-slate-400" data-testid="step-up-why">{{ t('stepup.why') }}</p>
      <form class="mt-4" @submit.prevent="submitStepUp(stepUpPassword)">
        <label class="block text-xs font-medium text-slate-600 dark:text-slate-300 mb-1" for="step-up-password">{{ t('stepup.passwordLabel') }}</label>
        <input
          id="step-up-password" v-model="stepUpPassword" type="password" required
          class="w-full px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-500"
          data-testid="step-up-password"
        />
        <p v-if="stepUpError" class="mt-2 text-sm text-red-600 dark:text-red-400" data-testid="step-up-error">{{ stepUpError }}</p>
        <div class="mt-4 flex gap-2">
          <button
            type="submit" :disabled="stepUpBusy"
            class="flex-1 px-4 py-2 rounded-lg text-sm font-medium bg-brand-600 text-white hover:bg-brand-700 transition-colors disabled:opacity-50"
            data-testid="step-up-submit"
          >{{ stepUpBusy ? t('stepup.working') : t('stepup.submit') }}</button>
          <button
            type="button" :disabled="stepUpBusy"
            class="px-4 py-2 rounded-lg text-sm border border-slate-200 dark:border-slate-600 text-slate-600 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-700 disabled:opacity-50"
            data-testid="step-up-cancel"
            @click="stepUpOpen = false"
          >{{ t('stepup.cancel') }}</button>
        </div>
      </form>
    </div>
  </div>
</template>
