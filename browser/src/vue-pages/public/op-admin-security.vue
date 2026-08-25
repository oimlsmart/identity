<script setup lang="ts">
// ═══════════════════════════════════════════════════════════════════
// The security + audit surface (TODO.identity-sso/01, surface 5) —
// three panels over the SAME audit journal (routes/op-dashboard.ts):
//
//   1. the security signals: failed-login bursts (the threshold is
//      stated on the panel), token-endpoint refusals, rate-limit trips,
//      new upstream links, new client registrations;
//   2. the queryable audit log: text/action/entity-type/date filters,
//      and the CSV export of the CURRENT filter view (an attachment);
//   3. the live access review: the quarterly review's rule set
//      (scripts/op-access-review.ts) answered from the live registry —
//      the privileged holders, the per-client privileged grants, the
//      findings, the posture.
//
// The retention statement rides the API and shows under the log. Every
// rule is SERVER-ENFORCED; this page only renders what the APIs answer.
// ═══════════════════════════════════════════════════════════════════
import { onMounted, ref, watch } from 'vue'
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

interface Security {
  generatedAt: string
  retention: string
  windows: { day: string; week: string }
  signals: {
    failedSignIns: { day: number; week: number; threshold: number; rule: string; bursts: Array<{ key: string; account: string | null; count24h: number }> }
    tokenRefusals: { day: number; week: number; byError: Record<string, number>; byClient: Record<string, number> }
    rateLimited: { day: number; week: number; byCaller: Record<string, number>; byPath: Record<string, number> }
    newLinks: { week: number; events: Array<{ at: string; action: string; account: string; provider: string; by: string }> }
    newClients: { week: number; events: Array<{ at: string; clientId: string; by: string }> }
  }
}

interface AuditAnswer {
  generatedAt: string
  retention: string
  total: number
  returned: number
  events: AuditEvent[]
}

interface AccessReview {
  generatedAt: string
  source: string
  privilegedRoles: string[]
  privilegedHolders: Array<{
    id: string; name: string; email: string; roles: string[]
    active: boolean; lastLogin: string | null; emailVerifiedAt: string | null
  }>
  perClientPrivileged: Array<{ account: string; clientId: string; roles: string[]; assignedBy: string | null; updatedAt: string | null }>
  findings: string[]
  posture: {
    accounts: { total: number; active: number }
    clients: { total: number; active: number }
    providers: { total: number; enabled: number }
    signingKeys: { history: number; active: number }
  }
}

const { branding } = useBranding()

const loading = ref(true)
const forbidden = ref(false)
const error = ref<string | null>(null)
const security = ref<Security | null>(null)
const review = ref<AccessReview | null>(null)

// The queryable log's state.
const audit = ref<AuditAnswer | null>(null)
const auditError = ref<string | null>(null)
const q = ref('')
const actionPrefix = ref('')
const entityType = ref('')
const from = ref('')
const to = ref('')
let searchTimer: ReturnType<typeof setTimeout> | null = null

const ACTION_PREFIXES = [
  { value: '', label: 'every action' },
  { value: 'account.', label: 'account.* (the registry’s acts)' },
  { value: 'account.sign_in', label: 'sign-ins (password)' },
  { value: 'upstream_', label: 'upstream_* (linked methods)' },
  { value: 'client.', label: 'client.* (relying parties)' },
  { value: 'provider.', label: 'provider.* (sign-in providers)' },
  { value: 'org_', label: 'org_* (organization administration)' },
  { value: 'rate_limited', label: 'rate_limited' },
]

const ENTITY_TYPES = [
  { value: '', label: 'every entity type' },
  { value: 'account', label: 'account' },
  { value: 'auth', label: 'auth' },
  { value: 'client', label: 'client' },
  { value: 'provider', label: 'provider' },
  { value: 'op', label: 'op (the rate limiter)' },
  { value: 'users', label: 'users' },
]

function auditParams(): URLSearchParams {
  const params = new URLSearchParams({ limit: '200' })
  if (q.value.trim()) params.set('q', q.value.trim())
  if (actionPrefix.value) params.set('action', actionPrefix.value)
  if (entityType.value) params.set('entity_type', entityType.value)
  if (from.value) params.set('from', `${from.value}T00:00:00.000Z`)
  if (to.value) params.set('to', `${to.value}T23:59:59.999Z`)
  return params
}

async function loadAudit(): Promise<void> {
  auditError.value = null
  const res = await fetch(`/api/op/dashboard/audit?${auditParams()}`, { credentials: 'include' })
  if (!res.ok) {
    auditError.value = `the audit log failed (${res.status})`
    return
  }
  audit.value = await res.json() as AuditAnswer
}

function queueAuditReload() {
  if (searchTimer) clearTimeout(searchTimer)
  searchTimer = setTimeout(() => { void loadAudit() }, 250)
}
watch([q, actionPrefix, entityType, from, to], queueAuditReload)

/** The export rides the CURRENT filter view (format=csv; the browser
 *  downloads the attachment). */
function exportCsv() {
  const params = auditParams()
  params.set('format', 'csv')
  params.delete('limit')
  window.location.assign(`/api/op/dashboard/audit?${params}`)
}

function stamp(iso: string): string {
  return iso.slice(0, 16).replace('T', ' ') + 'Z'
}

/** One readable line per journal row (the log's detail column). */
function describe(event: AuditEvent): string {
  const meta = event.metadata ?? {}
  switch (event.action) {
    case 'account.sign_in': return `signed in with the password`
    case 'account.sign_in_failed': return `a password sign-in failed for ${String(meta.email ?? event.entity_id)} (${meta.reason === 'deactivated' ? 'the account is deactivated' : 'invalid credentials'})`
    case 'account.sessions_revoked': return meta.by === 'administrator' ? `the administrator ended every session of ${String(meta.email ?? event.entity_id)} (${String(meta.count ?? 0)})` : `signed out ${String(meta.count ?? 0)} other session(s)`
    case 'account.session_revoked': return meta.by === 'administrator' ? 'a session ended (the administrator)' : 'a session ended'
    case 'upstream_sign_in': return `signed in with ${String(meta.provider ?? '')} (${String(meta.handle ?? '')})`
    case 'upstream_refused': return `a ${String(meta.provider ?? '')} sign-in was refused (${String(meta.reason ?? '')})`
    case 'upstream_link': return `linked ${String(meta.provider ?? '')} (${String(meta.handle ?? '')})`
    case 'account.link_on_behalf': return `linked ${String(meta.provider ?? '')} on behalf of ${String(meta.email ?? event.entity_id)} — ${String(meta.justification ?? '')}`
    case 'client.token_issued': return `issued tokens (scope ${String(meta.scope ?? '')})`
    case 'client.token_refused': return `the token endpoint refused (${String(meta.error ?? '')})`
    case 'client.registered': return `registered the relying party`
    case 'client.updated': return `updated the relying party`
    case 'client.status': return `set the relying party to ${String(meta.status ?? '')}`
    case 'rate_limited': return `the rate limiter tripped on ${String(meta.path ?? '')}`
    default: return event.action
  }
}

/** The deep link for a row's target, when one exists. */
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
      window.location.assign(`/?redirect=${encodeURIComponent('/op/admin/security')}`)
      return
    }
    const res = await fetch('/api/op/dashboard/security', { credentials: 'include' })
    if (res.status === 401) {
      window.location.assign(`/?redirect=${encodeURIComponent('/op/admin/security')}`)
      return
    }
    if (res.status === 403) {
      forbidden.value = true
      return
    }
    if (!res.ok) throw new Error(`the security signals failed (${res.status})`)
    security.value = await res.json() as Security
    // The log + the review follow; neither holds the signals back.
    void loadAudit()
    const reviewRes = await fetch('/api/op/dashboard/access-review', { credentials: 'include' })
    if (reviewRes.ok) review.value = await reviewRes.json() as AccessReview
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

    <div v-else-if="forbidden" class="max-w-md mx-auto py-16">
      <div class="text-center mb-8">
        <h1 class="text-xl font-serif font-bold text-slate-900 dark:text-white">Security and audit</h1>
      </div>
      <div class="p-3 rounded-lg bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800">
        <p class="text-sm text-amber-800 dark:text-amber-300" data-testid="op-sec-forbidden">
          The security and audit surface is an administrator surface — your account does not hold the administrator role.
        </p>
      </div>
    </div>

    <div v-else data-testid="op-sec">
      <PageHeader
        title="Security and audit"
        :description="`The signals over ${branding.productName}'s own audit journal, the queryable log, and the live access review.`"
      />
      <OpAdminNav current="security" />

      <div v-if="error" class="mb-4 p-3 rounded-lg bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800">
        <p class="text-sm text-red-700 dark:text-red-300" data-testid="op-sec-error">{{ error }}</p>
      </div>

      <template v-if="security">
        <!-- The signals -->
        <section class="grid sm:grid-cols-2 gap-3 mb-6" data-testid="op-sec-signals">
          <div class="rounded-xl border border-slate-200/80 dark:border-slate-700 bg-white dark:bg-slate-800 p-4" data-testid="op-sec-failed-logins">
            <h2 class="text-xs font-semibold uppercase tracking-wider text-slate-400 dark:text-slate-500">Failed sign-ins</h2>
            <p class="mt-1 text-2xl font-semibold" :class="security.signals.failedSignIns.day ? 'text-amber-600 dark:text-amber-400' : 'text-slate-900 dark:text-white'">{{ security.signals.failedSignIns.day }}</p>
            <p class="text-[11px] text-slate-500 dark:text-slate-400">{{ security.windows.day }} · {{ security.signals.failedSignIns.week }} over {{ security.windows.week }}</p>
            <p class="mt-1 text-[11px] text-slate-400 dark:text-slate-500">{{ security.signals.failedSignIns.rule }}.</p>
            <ul v-if="security.signals.failedSignIns.bursts.length" class="mt-2 space-y-1" data-testid="op-sec-bursts">
              <li v-for="burst in security.signals.failedSignIns.bursts" :key="burst.key" class="text-xs text-red-600 dark:text-red-400 font-medium" :data-testid="`op-sec-burst-${burst.key}`">
                {{ burst.account ?? burst.key }} — {{ burst.count24h }} failed in 24 h
              </li>
            </ul>
            <p v-else class="mt-2 text-[11px] text-emerald-600 dark:text-emerald-400" data-testid="op-sec-bursts-none">no bursts in the window</p>
          </div>

          <div class="rounded-xl border border-slate-200/80 dark:border-slate-700 bg-white dark:bg-slate-800 p-4" data-testid="op-sec-token-refusals">
            <h2 class="text-xs font-semibold uppercase tracking-wider text-slate-400 dark:text-slate-500">Token-endpoint refusals</h2>
            <p class="mt-1 text-2xl font-semibold" :class="security.signals.tokenRefusals.day ? 'text-amber-600 dark:text-amber-400' : 'text-slate-900 dark:text-white'">{{ security.signals.tokenRefusals.day }}</p>
            <p class="text-[11px] text-slate-500 dark:text-slate-400">{{ security.windows.day }} · {{ security.signals.tokenRefusals.week }} over {{ security.windows.week }}</p>
            <p v-if="Object.keys(security.signals.tokenRefusals.byError).length" class="mt-2 text-[11px] text-slate-500 dark:text-slate-400" data-testid="op-sec-token-refusals-split">
              <template v-for="(n, code) in security.signals.tokenRefusals.byError" :key="code">{{ code }} ×{{ n }} </template>
            </p>
            <p v-else class="mt-2 text-[11px] text-emerald-600 dark:text-emerald-400">none in the window</p>
          </div>

          <div class="rounded-xl border border-slate-200/80 dark:border-slate-700 bg-white dark:bg-slate-800 p-4" data-testid="op-sec-rate-limits">
            <h2 class="text-xs font-semibold uppercase tracking-wider text-slate-400 dark:text-slate-500">Rate-limit trips</h2>
            <p class="mt-1 text-2xl font-semibold" :class="security.signals.rateLimited.day ? 'text-amber-600 dark:text-amber-400' : 'text-slate-900 dark:text-white'">{{ security.signals.rateLimited.day }}</p>
            <p class="text-[11px] text-slate-500 dark:text-slate-400">{{ security.windows.day }} · {{ security.signals.rateLimited.week }} over {{ security.windows.week }}</p>
            <p v-if="Object.keys(security.signals.rateLimited.byCaller).length" class="mt-2 text-[11px] text-slate-500 dark:text-slate-400" data-testid="op-sec-rate-limits-split">
              <template v-for="(n, caller) in security.signals.rateLimited.byCaller" :key="caller">{{ caller }} ×{{ n }} </template>
            </p>
            <p v-else class="mt-2 text-[11px] text-emerald-600 dark:text-emerald-400">none in the window</p>
          </div>

          <div class="rounded-xl border border-slate-200/80 dark:border-slate-700 bg-white dark:bg-slate-800 p-4" data-testid="op-sec-new-links">
            <h2 class="text-xs font-semibold uppercase tracking-wider text-slate-400 dark:text-slate-500">New links and clients ({{ security.windows.week }})</h2>
            <p class="mt-1 text-sm text-slate-700 dark:text-slate-300" data-testid="op-sec-new-links-count">
              {{ security.signals.newLinks.week }} upstream link(s) · {{ security.signals.newClients.week }} client registration(s)
            </p>
            <ul class="mt-2 space-y-1" data-testid="op-sec-new-links-list">
              <li v-for="event in security.signals.newLinks.events" :key="`l-${event.at}-${event.account}`" class="text-[11px] text-slate-500 dark:text-slate-400">
                {{ stamp(event.at) }} — {{ event.account }} linked {{ event.provider }} ({{ event.by }})
              </li>
              <li v-for="event in security.signals.newClients.events" :key="`c-${event.at}-${event.clientId}`" class="text-[11px] text-slate-500 dark:text-slate-400">
                {{ stamp(event.at) }} — relying party {{ event.clientId }} registered ({{ event.by }})
              </li>
            </ul>
            <p v-if="!security.signals.newLinks.week && !security.signals.newClients.week" class="mt-2 text-[11px] text-emerald-600 dark:text-emerald-400">none in the window</p>
          </div>
        </section>
      </template>

      <!-- The queryable audit log -->
      <section class="rounded-xl border border-slate-200/80 dark:border-slate-700 bg-white dark:bg-slate-800 p-6 mb-6" data-testid="op-sec-audit">
        <h2 class="text-xs font-semibold uppercase tracking-wider text-slate-400 dark:text-slate-500 mb-3">The audit log</h2>
        <div class="flex flex-wrap items-center gap-2 mb-3">
          <input
            v-model="q"
            type="search"
            data-testid="op-sec-audit-q"
            class="flex-1 min-w-48 px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-500"
            placeholder="Filter by actor, action, target, or email…"
          />
          <select v-model="actionPrefix" data-testid="op-sec-audit-action" class="px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white">
            <option v-for="opt in ACTION_PREFIXES" :key="opt.value" :value="opt.value">{{ opt.label }}</option>
          </select>
          <select v-model="entityType" data-testid="op-sec-audit-entity" class="px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white">
            <option v-for="opt in ENTITY_TYPES" :key="opt.value" :value="opt.value">{{ opt.label }}</option>
          </select>
          <input v-model="from" type="date" data-testid="op-sec-audit-from" class="px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white" aria-label="from (UTC day)" />
          <input v-model="to" type="date" data-testid="op-sec-audit-to" class="px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white" aria-label="to (UTC day)" />
          <button
            type="button"
            data-testid="op-sec-audit-export"
            class="px-3 py-2 rounded-lg text-xs font-semibold bg-brand-600 text-white hover:bg-brand-700 transition-colors"
            @click="exportCsv"
          >Export CSV</button>
        </div>

        <div v-if="auditError" class="mb-3 p-3 rounded-lg bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800">
          <p class="text-sm text-red-700 dark:text-red-300" data-testid="op-sec-audit-error">{{ auditError }}</p>
        </div>
        <p v-if="audit" class="mb-2 text-[11px] text-slate-400 dark:text-slate-500" data-testid="op-sec-audit-count">
          {{ audit.returned }} of {{ audit.total }} matching row(s) — newest first.
        </p>
        <p v-if="audit && !audit.events.length" class="text-sm text-slate-500 dark:text-slate-400" data-testid="op-sec-audit-empty">
          Nothing on the record for this filter view.
        </p>
        <ul v-if="audit?.events.length" class="space-y-2" data-testid="op-sec-audit-list">
          <li v-for="event in audit.events" :key="event.id" class="rounded-lg border border-slate-100 dark:border-slate-700/60 px-3 py-2" :data-testid="`op-sec-audit-event-${event.id}`">
            <p class="text-xs text-slate-700 dark:text-slate-300">
              <span class="text-slate-400 dark:text-slate-500">{{ stamp(event.timestamp) }}</span>
              · <strong>{{ event.user_name ?? 'the system' }}</strong>:
              {{ describe(event) }}
            </p>
            <p class="text-[10px] text-slate-400 dark:text-slate-500 mt-0.5">
              <code class="font-mono">{{ event.entity_type }}/{{ event.action }}</code>
              <template v-if="targetLink(event)">
                · <router-link :to="targetLink(event)!" class="text-brand-600 dark:text-brand-300 hover:underline">open the record</router-link>
              </template>
            </p>
          </li>
        </ul>
        <p v-if="audit" class="mt-3 text-[11px] text-slate-400 dark:text-slate-500" data-testid="op-sec-audit-retention">{{ audit.retention }}</p>
      </section>

      <!-- The live access review -->
      <section class="rounded-xl border border-slate-200/80 dark:border-slate-700 bg-white dark:bg-slate-800 p-6" data-testid="op-sec-review">
        <h2 class="text-xs font-semibold uppercase tracking-wider text-slate-400 dark:text-slate-500 mb-1">The access review, live</h2>
        <p class="text-[11px] text-slate-400 dark:text-slate-500 mb-4" data-testid="op-sec-review-source">
          <template v-if="review">{{ review.source }}. Generated {{ stamp(review.generatedAt) }}.</template>
        </p>
        <template v-if="review">
          <h3 class="text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1">Privileged holders ({{ review.privilegedHolders.length }}) — {{ review.privilegedRoles.join(', ') }}</h3>
          <ul class="mb-4 space-y-1" data-testid="op-sec-review-holders">
            <li v-for="holder in review.privilegedHolders" :key="holder.id" class="text-xs text-slate-700 dark:text-slate-300" :data-testid="`op-sec-review-holder-${holder.id}`">
              <strong>{{ holder.name }}</strong> &lt;{{ holder.email }}&gt; — {{ holder.roles.join(', ') }}
              <span v-if="!holder.active" class="ml-1 text-red-500 dark:text-red-400 font-semibold">DISABLED</span>
              <span class="text-slate-400 dark:text-slate-500"> · last sign-in {{ holder.lastLogin ? stamp(holder.lastLogin) : 'never' }}</span>
            </li>
          </ul>
          <template v-if="review.perClientPrivileged.length">
            <h3 class="text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1">Per-client privileged assignments ({{ review.perClientPrivileged.length }})</h3>
            <ul class="mb-4 space-y-1" data-testid="op-sec-review-client-grants">
              <li v-for="grant in review.perClientPrivileged" :key="`${grant.account}-${grant.clientId}`" class="text-xs text-slate-700 dark:text-slate-300">
                {{ grant.account }} — {{ grant.roles.join(', ') }} on {{ grant.clientId }}
              </li>
            </ul>
          </template>
          <h3 class="text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1">Findings ({{ review.findings.length }})</h3>
          <ul v-if="review.findings.length" class="mb-4 space-y-1" data-testid="op-sec-review-findings">
            <li v-for="finding in review.findings" :key="finding" class="text-xs text-amber-700 dark:text-amber-300">{{ finding }}</li>
          </ul>
          <p v-else class="mb-4 text-xs text-emerald-600 dark:text-emerald-400" data-testid="op-sec-review-findings-none">none</p>
          <p class="text-[11px] text-slate-400 dark:text-slate-500" data-testid="op-sec-review-posture">
            {{ review.posture.accounts.active }}/{{ review.posture.accounts.total }} accounts active ·
            {{ review.posture.clients.active }}/{{ review.posture.clients.total }} clients active ·
            {{ review.posture.providers.enabled }}/{{ review.posture.providers.total }} providers enabled ·
            {{ review.posture.signingKeys.active }}/{{ review.posture.signingKeys.history }} signing keys active
          </p>
        </template>
        <p v-else class="text-sm text-slate-500 dark:text-slate-400" data-testid="op-sec-review-loading">Computing the review from the live registry…</p>
      </section>
    </div>
  </div>
</template>
