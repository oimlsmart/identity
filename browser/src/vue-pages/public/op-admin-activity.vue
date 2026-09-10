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
import { useBranding } from '../../branding'
import { t } from '../../i18n'

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
  { key: 'accounts', label: t('admin.act.cat.accounts'), match: e => e.action.startsWith('account.') },
  { key: 'roles', label: t('admin.act.cat.roles'), match: e => ['user.create', 'user.roles', 'user.deactivated', 'user.reactivated'].includes(e.action) },
  { key: 'links', label: t('admin.act.cat.links'), match: e => e.action.startsWith('upstream_link') || e.action.startsWith('upstream_unlink') || e.action.startsWith('account.link') },
  { key: 'signins', label: t('admin.act.cat.signins'), match: e => e.action.startsWith('upstream_sign_in') || e.action.startsWith('upstream_refused') },
  { key: 'clients', label: t('admin.act.cat.clients'), match: e => e.action.startsWith('client.') },
  { key: 'providers', label: t('admin.act.cat.providers'), match: e => e.action.startsWith('provider.') },
  { key: 'organizations', label: t('admin.act.cat.organizations'), match: e => e.action.startsWith('org_invite.') || e.action.startsWith('org_join_request.') },
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
  if (!res.ok) throw new Error(t('admin.act.loadFailed', { status: res.status }))
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
    case 'account.invite': return t('admin.act.e.invite', { email: String(meta.email ?? event.entity_id), role: String(meta.role ?? '') })
    case 'account.enrollment': return t('admin.act.e.enrollment', { email: String(meta.email ?? event.entity_id) })
    case 'account.enrolled': return t('admin.act.e.enrolled')
    case 'account.password': return t('admin.act.e.password')
    case 'account.password_reset': return t('admin.act.e.passwordReset', { email: String(meta.email ?? event.entity_id) })
    case 'account.avatar': return t('admin.act.e.avatar')
    case 'account.avatar_removed': return t('admin.act.e.avatarRemoved')
    case 'account.deleted': return t('admin.act.e.deleted', { email: String(meta.email ?? event.entity_id) })
    case 'account.updated': {
      const before = (meta.before ?? {}) as Record<string, unknown>
      const after = (meta.after ?? {}) as Record<string, unknown>
      const fields = Object.keys(after).filter(k => JSON.stringify(before[k]) !== JSON.stringify(after[k])).join(', ')
      return t('admin.act.e.updated', { email: String((after.email ?? before.email) ?? event.entity_id), fields })
    }
    case 'account.deactivated': {
      const revoked = (meta.revoked ?? {}) as Record<string, unknown>
      return t('admin.act.e.deactivated', { sessions: Number(revoked.sessions ?? 0), tokens: Number(revoked.accessTokens ?? 0) })
    }
    case 'account.reactivated': return t('admin.act.e.reactivated')
    case 'account.session_revoked': return meta.by === 'administrator' ? t('admin.act.e.sessionRevokedAdmin') : t('admin.act.e.sessionRevoked')
    case 'account.sessions_revoked': return meta.by === 'administrator'
      ? t('admin.act.e.sessionsRevokedAdmin', { email: String(meta.email ?? event.entity_id), count: Number(meta.count ?? 0) })
      : t('admin.act.e.sessionsRevoked', { count: Number(meta.count ?? 0) })
    case 'account.sign_in': return t('admin.act.e.signIn')
    case 'account.sign_in_failed': return t('admin.act.e.signInFailed', { email: String(meta.email ?? event.entity_id), reason: meta.reason === 'deactivated' ? t('admin.act.e.reasonDeactivated') : t('admin.act.e.reasonInvalid') })
    case 'account.client_roles': {
      const roles = (meta.roles as string[] ?? [])
      return t('admin.act.e.clientRoles', { client: String(meta.client_id ?? ''), roles: roles.length ? roles.join(', ') : t('admin.act.e.noRoles') })
    }
    case 'account.client_roles_cleared': return t('admin.act.e.clientRolesCleared', { client: String(meta.client_id ?? '') })
    case 'account.link_on_behalf': return t('admin.act.e.linkOnBehalf', { provider: String(meta.provider ?? ''), handle: String(meta.provider_account_id ?? ''), email: String(meta.email ?? event.entity_id), justification: String(meta.justification ?? '') })
    case 'account.link_removed': return t('admin.act.e.linkRemoved', { provider: String(meta.provider ?? ''), email: String(meta.email ?? event.entity_id) }) + (meta.reason ? ` — ${String(meta.reason)}` : '')
    case 'user.create': return t('admin.act.e.userCreate', { email: String(meta.email ?? ''), roles: (meta.roles as string[] ?? []).join(', ') })
    case 'user.roles': return t('admin.act.e.userRoles', { roles: (meta.roles as string[] ?? []).join(', ') })
    case 'user.deactivated': return t('admin.act.e.userDeactivated')
    case 'user.reactivated': return t('admin.act.e.userReactivated')
    case 'upstream_sign_in': return t('admin.act.e.upstreamSignIn', { provider: String(meta.provider ?? ''), handle: String(meta.handle ?? '') })
    case 'upstream_link': return t('admin.act.e.upstreamLink', { provider: String(meta.provider ?? ''), handle: String(meta.handle ?? '') })
    case 'upstream_unlink': return t('admin.act.e.upstreamUnlink', { provider: String(meta.provider ?? '') })
    case 'upstream_refused': return t('admin.act.e.upstreamRefused', { provider: String(meta.provider ?? ''), reason: String(meta.reason ?? ''), handle: String(meta.handle ?? '') })
    case 'upstream_link_conflict': return t('admin.act.e.upstreamConflict', { provider: String(meta.provider ?? ''), handle: String(meta.handle ?? '') })
    case 'client.registered': {
      if (meta.class === 'device') {
        const device = (meta.device ?? {}) as Record<string, unknown>
        return t('admin.act.e.clientRegDevice', { client: event.entity_id, device: String(device.id ?? ''), org: String(device.org ?? ''), model: String(device.instrument_model ?? '') })
      }
      if (meta.class === 'service') {
        const service = (meta.service ?? {}) as Record<string, unknown>
        return t('admin.act.e.clientRegService', { client: event.entity_id, service: String(service.id ?? ''), org: String(service.org ?? ''), audience: String(service.audience ?? ''), scopes: (service.scopes as string[] ?? []).join(' ') })
      }
      return t('admin.act.e.clientRegistered', { client: event.entity_id, kind: meta.confidential ? t('admin.act.e.confidential') : t('admin.act.e.public'), claims: (meta.claims as string[] ?? []).join(', ') || t('admin.act.e.defaultClaims') })
    }
    case 'client.token_issued': return meta.class === 'device'
      ? t('admin.act.e.tokenIssuedDevice', { client: event.entity_id, device: String((meta.device as string | undefined) ?? ''), org: String((meta.org as string | undefined) ?? '') })
      : meta.class === 'service'
        ? t('admin.act.e.tokenIssuedService', { client: event.entity_id, service: String((meta.service as string | undefined) ?? ''), audience: String((meta.audience as string | undefined) ?? ''), scopes: (meta.scopes as string[] ?? []).join(' ') })
        : t('admin.act.e.tokenIssued', { client: event.entity_id, scope: String(meta.scope ?? '') })
    case 'client.token_refused': return t('admin.act.e.tokenRefused', { client: event.entity_id, error: String(meta.error ?? '') })
    case 'client.updated': return meta.class === 'device'
      ? t('admin.act.e.clientUpdatedDevice', { client: event.entity_id }) + (meta.rekeyed ? t('admin.act.e.rekeyedFull') : '')
      : meta.class === 'service'
        ? t('admin.act.e.clientUpdatedService', { client: event.entity_id }) + (meta.rekeyed ? t('admin.act.e.rekeyedFull') : '')
        : t('admin.act.e.clientUpdated', { client: event.entity_id }) + (meta.rekeyed ? t('admin.act.e.rekeyed') : '') + (meta.made_public ? t('admin.act.e.madePublic') : '')
    case 'client.status': return t('admin.act.e.clientStatus', { kind: meta.class === 'device' ? t('admin.act.e.kindDevice') : meta.class === 'service' ? t('admin.act.e.kindService') : t('admin.act.e.kindRp'), client: event.entity_id, status: String(meta.status ?? '') })
    case 'provider.registered': return t('admin.act.e.providerRegistered', { provider: event.entity_id })
    case 'provider.updated': return t('admin.act.e.providerUpdated', { provider: event.entity_id })
    case 'provider.status': return t('admin.act.e.providerStatus', { state: meta.enabled ? t('admin.act.e.enabled') : t('admin.act.e.disabled'), provider: event.entity_id })
    case 'provider.removed': return t('admin.act.e.providerRemoved', { provider: event.entity_id })
    case 'org_invite.issued': return t('admin.act.e.orgInvite', { email: String(meta.email ?? ''), role: String(meta.role ?? '') })
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
    // The session gate and the first data read are INDEPENDENT — one
    // latency phase (TODO.restructure/02). load() re-checks the 401
    // posture itself.
    const [session] = await Promise.all([fetch('/api/auth/session', { credentials: 'include' }), load()])
    if (!session.ok) {
      window.location.assign(`/?redirect=${encodeURIComponent('/op/admin/activity')}`)
      return
    }
  } catch (e) {
    error.value = (e as Error).message || t('error.network')
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
        <h1 class="text-xl font-serif font-bold text-slate-900 dark:text-white">{{ t('admin.act.title') }}</h1>
      </div>
      <div class="p-3 rounded-lg bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800">
        <p class="text-sm text-amber-800 dark:text-amber-300" data-testid="op-act-forbidden">
          {{ t('admin.act.forbidden') }}
        </p>
      </div>
    </div>

    <div v-else data-testid="op-act">
      <PageHeader
        :title="t('admin.act.title')"
        :description="`Every administrative act on ${branding.productName}, and the sign-in events — newest first.`"
      />

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
            :placeholder="t('admin.act.filterPlaceholder')"
          />
          <select
            v-model="category"
            data-testid="op-act-category"
            class="max-w-full min-w-0 px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-500"
          >
            <option value="">{{ t('admin.act.everyCategory') }}</option>
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
