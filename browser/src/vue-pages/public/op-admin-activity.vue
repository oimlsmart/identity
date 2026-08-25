<script setup lang="ts">
// ═══════════════════════════════════════════════════════════════════
// The registry's activity feed (TODO.identity/07) — the audit journal's
// identity slice, newest first: every administrative act on the
// registry (invites, role assignments, links, session revocations,
// client and provider registry writes) and the sign-in events, with the
// actor named. Account targets deep-link to the account's detail page.
//
// The rows are the SERVER's audit journal (routes write auditEvents on
// every act; this page only renders them).
// ═══════════════════════════════════════════════════════════════════
import { computed, onMounted, ref, watch } from 'vue'
import PageHeader from '../../components/PageHeader.vue'
import OpAdminNav from '../../components/OpAdminNav.vue'
import { useBranding } from '../../branding'

interface AuditEvent {
  id: string
  timestamp: string
  entity_type: string
  entity_id: string
  action: string
  user_id?: string
  user_name?: string
  metadata?: Record<string, unknown>
}

const { branding } = useBranding()

const loading = ref(true)
const forbidden = ref(false)
const error = ref<string | null>(null)
const events = ref<AuditEvent[]>([])
const search = ref('')
const category = ref('')
let searchTimer: ReturnType<typeof setTimeout> | null = null

const CATEGORIES: Array<{ key: string; label: string; match: (e: AuditEvent) => boolean }> = [
  { key: 'accounts', label: 'Accounts (invites, enrollment, passwords)', match: e => e.action.startsWith('account.') },
  { key: 'roles', label: 'Role assignments', match: e => ['user.create', 'user.roles', 'user.deactivated', 'user.reactivated'].includes(e.action) },
  { key: 'links', label: 'Linked identities', match: e => e.action.startsWith('upstream_link') || e.action.startsWith('upstream_unlink') || e.action.startsWith('account.link') },
  { key: 'signins', label: 'Sign-ins and refusals', match: e => e.action.startsWith('upstream_sign_in') || e.action.startsWith('upstream_refused') },
  { key: 'clients', label: 'Relying parties (the client registry)', match: e => e.action.startsWith('client.') },
  { key: 'providers', label: 'Sign-in providers', match: e => e.action.startsWith('provider.') },
  { key: 'organizations', label: 'Organization administration', match: e => e.action.startsWith('org_invite.') || e.action.startsWith('org_join.') },
]

const visible = computed(() =>
  category.value ? events.value.filter(e => CATEGORIES.find(c => c.key === category.value)?.match(e)) : events.value,
)

async function load(): Promise<void> {
  const params = new URLSearchParams({ limit: '200' })
  if (search.value.trim()) params.set('q', search.value.trim())
  const res = await fetch(`/api/op/registry/activity?${params}`, { credentials: 'include' })
  if (res.status === 401) {
    window.location.assign(`/?redirect=${encodeURIComponent('/op/admin/activity')}`)
    return
  }
  if (res.status === 403) {
    forbidden.value = true
    return
  }
  if (!res.ok) throw new Error(`the activity feed failed (${res.status})`)
  events.value = await res.json() as AuditEvent[]
}

function queueReload() {
  if (searchTimer) clearTimeout(searchTimer)
  searchTimer = setTimeout(() => { void load() }, 250)
}
watch(search, queueReload)

/** One readable line per event. */
function describe(event: AuditEvent): string {
  const meta = event.metadata ?? {}
  switch (event.action) {
    case 'account.invite': return `invited ${String(meta.email ?? event.entity_id)} (role ${String(meta.role ?? '')})`
    case 'account.enrollment': return `issued a fresh setup link for ${String(meta.email ?? event.entity_id)}`
    case 'account.enrolled': return 'completed the account setup (the password is set)'
    case 'account.password': return 'changed the account password'
    case 'account.password_reset': return `a password reset email was requested for ${String(meta.email ?? event.entity_id)}`
    case 'account.avatar': return 'updated the profile picture'
    case 'account.avatar_removed': return 'removed the profile picture'
    case 'account.deleted': return `erased the account ${String(meta.email ?? event.entity_id)} — the row is an anonymized tombstone`
    case 'account.updated': {
      const before = (meta.before ?? {}) as Record<string, unknown>
      const after = (meta.after ?? {}) as Record<string, unknown>
      const fields = Object.keys(after).filter(k => JSON.stringify(before[k]) !== JSON.stringify(after[k])).join(', ')
      return `edited the account ${String((after.email ?? before.email) ?? event.entity_id)} (${fields})`
    }
    case 'account.deactivated': {
      const revoked = (meta.revoked ?? {}) as Record<string, unknown>
      return `deactivated the account (revoked: ${Number(revoked.sessions ?? 0)} session(s), ${Number(revoked.accessTokens ?? 0)} token(s))`
    }
    case 'account.reactivated': return 'reactivated the account'
    case 'account.session_revoked': return meta.by === 'administrator' ? 'ended an account session (administrator)' : 'ended a session'
    case 'account.sessions_revoked': return meta.by === 'administrator'
      ? `ended every session of ${String(meta.email ?? event.entity_id)} (${Number(meta.count ?? 0)}, administrator)`
      : `signed out ${Number(meta.count ?? 0)} other session(s)`
    case 'account.sign_in': return `signed in with the password`
    case 'account.sign_in_failed': return `a password sign-in failed for ${String(meta.email ?? event.entity_id)} (${meta.reason === 'deactivated' ? 'the account is deactivated' : 'invalid credentials'})`
    case 'account.client_roles': {
      const roles = (meta.roles as string[] ?? [])
      return `granted roles on ${String(meta.client_id ?? '')}: ${roles.length ? roles.join(', ') : 'none (the explicit no-claim posture)'}`
    }
    case 'account.client_roles_cleared': return `cleared the role grant on ${String(meta.client_id ?? '')} (the account-wide set is the default again)`
    case 'account.link_on_behalf': return `linked ${String(meta.provider ?? '')} account ${String(meta.provider_account_id ?? '')} on behalf of ${String(meta.email ?? event.entity_id)} — ${String(meta.justification ?? '')}`
    case 'account.link_removed': return `removed the ${String(meta.provider ?? '')} link of ${String(meta.email ?? event.entity_id)}${meta.reason ? ` — ${String(meta.reason)}` : ''}`
    case 'user.create': return `created the account ${String(meta.email ?? '')} (${(meta.roles as string[] ?? []).join(', ')})`
    case 'user.roles': return `assigned roles: ${(meta.roles as string[] ?? []).join(', ')}`
    case 'user.deactivated': return 'deactivated the account'
    case 'user.reactivated': return 'reactivated the account'
    case 'upstream_sign_in': return `signed in with ${String(meta.provider ?? '')} (${String(meta.handle ?? '')})`
    case 'upstream_link': return `linked ${String(meta.provider ?? '')} (${String(meta.handle ?? '')})`
    case 'upstream_unlink': return `unlinked ${String(meta.provider ?? '')}`
    case 'upstream_refused': return `a ${String(meta.provider ?? '')} sign-in was refused (${String(meta.reason ?? '')}): ${String(meta.handle ?? '')}`
    case 'upstream_link_conflict': return `a ${String(meta.provider ?? '')} link hit a conflict: ${String(meta.handle ?? '')}`
    case 'client.registered': return `registered the relying party ${event.entity_id} (${meta.confidential ? 'confidential' : 'public'}; claims: ${(meta.claims as string[] ?? []).join(', ') || 'profile + email'})`
    case 'client.token_issued': return `the token endpoint issued tokens for ${event.entity_id} (scope ${String(meta.scope ?? '')})`
    case 'client.token_refused': return `the token endpoint refused ${event.entity_id} (${String(meta.error ?? '')})`
    case 'client.updated': return `updated the relying party ${event.entity_id}${meta.rekeyed ? ' (re-keyed)' : ''}${meta.made_public ? ' (made public)' : ''}`
    case 'client.status': return `set the relying party ${event.entity_id} to ${String(meta.status ?? '')}`
    case 'provider.registered': return `registered the sign-in provider ${event.entity_id}`
    case 'provider.updated': return `updated the sign-in provider ${event.entity_id}`
    case 'provider.status': return `${meta.enabled ? 'enabled' : 'disabled'} the sign-in provider ${event.entity_id}`
    case 'provider.removed': return `removed the sign-in provider ${event.entity_id}`
    case 'org_invite.issued': return `issued the organization invite for ${String(meta.email ?? '')} (${String(meta.role ?? '')})`
    default: return event.action
  }
}

/** The deep link for an event's target, when one exists. */
function targetLink(event: AuditEvent): string | null {
  if (event.entity_type === 'account' || event.entity_type === 'users') return `/op/admin/registry/users/${event.entity_id}`
  if (event.entity_type === 'client') return '/op/admin/clients'
  if (event.entity_type === 'provider') return '/op/admin/providers'
  return null
}

onMounted(async () => {
  try {
    const session = await fetch('/api/auth/session', { credentials: 'include' })
    if (!session.ok) {
      window.location.assign(`/?redirect=${encodeURIComponent('/op/admin/activity')}`)
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
        <h1 class="text-xl font-serif font-bold text-slate-900 dark:text-white">Registry activity</h1>
      </div>
      <div class="p-3 rounded-lg bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800">
        <p class="text-sm text-amber-800 dark:text-amber-300" data-testid="op-act-forbidden">
          The registry’s activity is an administrator surface — your account does not hold the administrator role.
        </p>
      </div>
    </div>

    <div v-else data-testid="op-act">
      <PageHeader
        title="Registry activity"
        :description="`Every administrative act on ${branding.productName}, and the sign-in events — newest first.`"
      />
      <OpAdminNav current="activity" />

      <div v-if="error" class="mb-4 p-3 rounded-lg bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800">
        <p class="text-sm text-red-700 dark:text-red-300" data-testid="op-act-error">{{ error }}</p>
      </div>

      <section class="rounded-xl border border-slate-200/80 dark:border-slate-700 bg-white dark:bg-slate-800 p-6">
        <div class="flex flex-wrap items-center gap-2 mb-4">
          <input
            v-model="search"
            type="search"
            data-testid="op-act-filter"
            class="flex-1 min-w-56 px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-500"
            placeholder="Filter by actor, action, or account…"
          />
          <select
            v-model="category"
            data-testid="op-act-category"
            class="px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-500"
          >
            <option value="">every category</option>
            <option v-for="c in CATEGORIES" :key="c.key" :value="c.key" :data-testid="`op-act-category-${c.key}`">{{ c.label }}</option>
          </select>
        </div>

        <p v-if="!visible.length" class="text-sm text-slate-500 dark:text-slate-400" data-testid="op-act-empty">
          Nothing on the record yet for this view — the registry’s acts land here as they happen.
        </p>
        <ul v-else class="space-y-2" data-testid="op-act-list">
          <li
            v-for="event in visible"
            :key="event.id"
            class="rounded-lg border border-slate-100 dark:border-slate-700/60 px-3 py-2"
            :data-testid="`op-act-event-${event.id}`"
          >
            <p class="text-xs text-slate-700 dark:text-slate-300">
              <span class="text-slate-400 dark:text-slate-500">{{ event.timestamp.slice(0, 16).replace('T', ' ') }}</span>
              · <strong>{{ event.user_name ?? 'the system' }}</strong>:
              {{ describe(event) }}
            </p>
            <p class="text-[10px] text-slate-400 dark:text-slate-500 mt-0.5">
              <code class="font-mono">{{ event.action }}</code>
              <template v-if="targetLink(event)">
                · <router-link :to="targetLink(event)!" class="text-brand-600 dark:text-brand-300 hover:underline" :data-testid="`op-act-open-${event.id}`">open the record</router-link>
              </template>
            </p>
          </li>
        </ul>
      </section>
    </div>
  </div>
</template>
