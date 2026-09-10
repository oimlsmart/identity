<script setup lang="ts">
// ═══════════════════════════════════════════════════════════════════
// The aggregate live-sessions surface (TODO.identity-sso/01, surface 2)
// — "who is signed in NOW": every live OP session across accounts with
// its user agent + IP, issued/last-seen/expiry, the presenting
// administrator's own row marked. The act ladder per row, each audited
// and each distinct:
//
//   End session        — revoke THIS session (routes/op-registry.ts's
//                        per-account revoke);
//   End all sessions   — the LIGHT act: every session of the account
//                        (the dashboard API's revoke-all). Issued
//                        relying-party access tokens keep their own
//                        short lifetimes (an hour at most);
//   Deactivate account — the HEAVY act (routes/users.ts): sessions +
//                        tokens + pending codes revoked AND issuance
//                        blocked; the row stays for the audit trail.
//
// The view NEVER exposes a token value (the API never carries one).
// Every rule is SERVER-ENFORCED; this page only renders what the APIs
// answer.
// ═══════════════════════════════════════════════════════════════════
import { computed, onMounted, ref } from 'vue'
import PageHeader from '../../components/PageHeader.vue'
import { useBranding } from '../../branding'
import { api } from '../../lib/api-client'
import { t } from '../../i18n'

interface SessionRow {
  id: string
  account: { id: string; name: string | null; email: string | null; active: boolean | null }
  createdAt: string
  expiresAt: string
  lastSeenAt: string | null
  userAgent: string | null
  ip: string | null
  current: boolean
}

const { branding } = useBranding()

const loading = ref(true)
const forbidden = ref(false)
const error = ref<string | null>(null)
const notice = ref<string | null>(null)
const rows = ref<SessionRow[]>([])
const retention = ref('')
const generatedAt = ref('')
const filter = ref('')
const acting = ref<string | null>(null)
/** The two-step confirms, armed per account/session id. */
const revokeAllArmed = ref<string | null>(null)
const deactivateArmedFor = ref<string | null>(null)

const visible = computed(() => {
  const q = filter.value.trim().toLowerCase()
  if (!q) return rows.value
  return rows.value.filter(r =>
    [r.account.name ?? '', r.account.email ?? '', r.userAgent ?? '', r.ip ?? '']
      .some(s => s.toLowerCase().includes(q)),
  )
})

function stamp(iso: string): string {
  return iso.slice(0, 16).replace('T', ' ') + 'Z'
}

/** The user agent's honest one-liner (truncated; the full string rides
 *  the title). */
function agent(row: SessionRow): string {
  return row.userAgent ?? t('admin.sess.notRecorded')
}

async function load(): Promise<void> {
  const res = await api('/api/op/dashboard/sessions')
  if (res.status === 401) {
    window.location.assign(`/?redirect=${encodeURIComponent('/op/admin/sessions')}`)
    return
  }
  if (res.status === 403) {
    forbidden.value = true
    return
  }
  if (!res.ok) throw new Error(t('admin.sess.loadFailed', { status: res.status }))
  const body = await res.json() as { generatedAt: string; retention: string; sessions: SessionRow[] }
  rows.value = body.sessions
  retention.value = body.retention
  generatedAt.value = body.generatedAt
}

async function revokeOne(row: SessionRow) {
  if (acting.value) return
  acting.value = row.id
  error.value = null
  notice.value = null
  try {
    const res = await api(`/api/op/registry/users/${encodeURIComponent(row.account.id)}/sessions/${encodeURIComponent(row.id)}/revoke`, { method: 'POST' })
    if (!res.ok) {
      const body = await res.json().catch(() => ({})) as { error?: string }
      error.value = body.error ?? t('admin.sess.refusedRevoke', { status: res.status })
      return
    }
    notice.value = row.account.email ? t('admin.sess.noticeEndedWithEmail', { email: row.account.email }) : t('admin.sess.noticeEnded')
    await load()
  } catch {
    error.value = t('error.network')
  } finally {
    acting.value = null
  }
}

async function revokeAll(row: SessionRow) {
  if (acting.value) return
  if (revokeAllArmed.value !== row.account.id) {
    revokeAllArmed.value = row.account.id
    return
  }
  revokeAllArmed.value = null
  acting.value = row.account.id
  error.value = null
  notice.value = null
  try {
    const res = await api(`/api/op/dashboard/accounts/${encodeURIComponent(row.account.id)}/sessions/revoke-all`, { method: 'POST' })
    if (!res.ok) {
      const body = await res.json().catch(() => ({})) as { error?: string }
      error.value = body.error ?? t('admin.sess.refusedRevoke', { status: res.status })
      return
    }
    const body = await res.json() as { revoked: number }
    notice.value = t('admin.sess.noticeEndAll', { account: row.account.name ?? row.account.email ?? t('admin.sess.theAccount'), count: body.revoked })
    await load()
  } catch {
    error.value = t('error.network')
  } finally {
    acting.value = null
  }
}

async function deactivate(row: SessionRow) {
  if (acting.value) return
  if (deactivateArmedFor.value !== row.account.id) {
    deactivateArmedFor.value = row.account.id
    return
  }
  deactivateArmedFor.value = null
  acting.value = row.account.id
  error.value = null
  notice.value = null
  try {
    const res = await api(`/api/users/${encodeURIComponent(row.account.id)}/active`, {
      method: 'PUT',
      body: JSON.stringify({ active: false }),
    })
    if (!res.ok) {
      const body = await res.json().catch(() => ({})) as { error?: string }
      error.value = body.error ?? t('admin.sess.refusedDeactivate', { status: res.status })
      return
    }
    notice.value = t('admin.sess.noticeDeactivated', { account: row.account.name ?? row.account.email ?? t('admin.sess.theAccount') })
    await load()
  } catch {
    error.value = t('error.network')
  } finally {
    acting.value = null
  }
}

onMounted(async () => {
  try {
    // The session gate and the first data read are INDEPENDENT — one
    // latency phase (TODO.restructure/02). load() re-checks the 401
    // posture itself.
    const [session] = await Promise.all([fetch('/api/auth/session', { credentials: 'include' }), load()])
    if (!session.ok) {
      window.location.assign(`/?redirect=${encodeURIComponent('/op/admin/sessions')}`)
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
  <div class="max-w-5xl mx-auto px-6 py-10 w-full">
    <div v-if="loading" class="flex flex-col items-center gap-4 py-24">
      <div class="w-8 h-8 border-2 border-brand-300 border-t-brand-600 rounded-full animate-spin" />
    </div>

    <div v-else-if="forbidden" class="max-w-md mx-auto py-16">
      <div class="text-center mb-8">
        <h1 class="text-xl font-serif font-bold text-slate-900 dark:text-white">{{ t('admin.sess.title') }}</h1>
      </div>
      <div class="p-3 rounded-lg bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800">
        <p class="text-sm text-amber-800 dark:text-amber-300" data-testid="op-sess-forbidden">
          {{ t('admin.sess.forbidden') }}
        </p>
      </div>
    </div>

    <div v-else data-testid="op-sess">
      <PageHeader
        :title="t('admin.sess.title')"
        :description="t('admin.sess.description', { product: branding.productName })"
      />

      <div v-if="error" class="mb-4 p-3 rounded-lg bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800">
        <p class="text-sm text-red-700 dark:text-red-300" data-testid="op-sess-error">{{ error }}</p>
      </div>
      <div v-if="notice" class="mb-4 p-3 rounded-lg bg-emerald-50 dark:bg-emerald-900/20 border border-emerald-200 dark:border-emerald-800">
        <p class="text-sm text-emerald-800 dark:text-emerald-300" data-testid="op-sess-notice">{{ notice }}</p>
      </div>

      <section class="rounded-xl border border-slate-200/80 dark:border-slate-700 bg-white dark:bg-slate-800 p-6" data-testid="op-sess-table-card">
        <div class="flex flex-wrap items-center gap-2 mb-4">
          <input
            v-model="filter"
            type="search"
            data-testid="op-sess-filter"
            class="flex-1 min-w-56 px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-500"
            :placeholder="t('admin.sess.filterPlaceholder')"
          />
          <p class="text-[11px] text-slate-400 dark:text-slate-500" data-testid="op-sess-generated">as of {{ stamp(generatedAt) }}</p>
        </div>

        <p v-if="!visible.length" class="text-sm text-slate-500 dark:text-slate-400" data-testid="op-sess-empty">
          {{ t('admin.sess.empty') }}
        </p>

        <ul v-else class="space-y-3" data-testid="op-sess-list">
          <li
            v-for="row in visible"
            :key="row.id"
            class="rounded-lg border border-slate-200 dark:border-slate-700 px-3 py-3"
            :data-testid="`op-sess-row-${row.id}`"
          >
            <div class="flex items-start justify-between gap-3">
              <div class="min-w-0">
                <p class="text-sm font-medium text-slate-900 dark:text-white">
                  <router-link
                    v-if="row.account.email"
                    :to="`/op/admin/registry/users/${row.account.id}`"
                    class="hover:underline"
                    :data-testid="`op-sess-account-${row.id}`"
                  >{{ row.account.name ?? row.account.email }}</router-link>
                  <span v-else>{{ row.account.name ?? row.account.id }}</span>
                  <span v-if="row.current" class="ml-1 text-[10px] px-1.5 py-0.5 rounded bg-brand-100 dark:bg-brand-900/40 text-brand-700 dark:text-brand-300 font-semibold" :data-testid="`op-sess-current-${row.id}`">{{ t('admin.sess.currentBadge') }}</span>
                  <span v-if="row.account.active === false" class="ml-1 text-[10px] px-1.5 py-0.5 rounded bg-red-100 dark:bg-red-900/40 text-red-600 dark:text-red-400 font-semibold">{{ t('admin.sess.deactivatedBadge') }}</span>
                </p>
                <p class="text-[11px] text-slate-400 dark:text-slate-500">{{ row.account.email ?? 'the account row is gone' }}</p>
                <p class="mt-1 text-[11px] text-slate-500 dark:text-slate-400" :title="row.userAgent ?? undefined" :data-testid="`op-sess-agent-${row.id}`">
                  {{ agent(row) }}<template v-if="row.ip"> · {{ row.ip }}</template><template v-else> · {{ t('admin.sess.ipNotRecorded') }}</template>
                </p>
                <p class="text-[11px] text-slate-400 dark:text-slate-500" :data-testid="`op-sess-times-${row.id}`">
                  {{ t('admin.sess.lineMeta', { at: stamp(row.createdAt), last: row.lastSeenAt ? stamp(row.lastSeenAt) : t('admin.sess.notRecordedShort'), expires: stamp(row.expiresAt) }) }}
                </p>
              </div>
              <div class="flex flex-col items-end gap-1 shrink-0">
                <button
                  :disabled="acting !== null"
                  :data-testid="`op-sess-revoke-${row.id}`"
                  class="text-xs font-medium text-brand-600 dark:text-brand-300 hover:underline disabled:opacity-50"
                  @click="revokeOne(row)"
                >{{ t('admin.sess.endOne') }}</button>
                <button
                  :disabled="acting !== null"
                  :data-testid="`op-sess-revoke-all-${row.account.id}`"
                  class="text-xs font-medium hover:underline disabled:opacity-50"
                  :class="revokeAllArmed === row.account.id ? 'text-amber-700 dark:text-amber-300 font-semibold' : 'text-slate-500 dark:text-slate-400'"
                  @click="revokeAll(row)"
                >{{ revokeAllArmed === row.account.id ? t('admin.sess.endAllConfirm') : t('admin.sess.endAll') }}</button>
                <button
                  v-if="row.account.active !== false && !row.current"
                  :disabled="acting !== null"
                  :data-testid="`op-sess-deactivate-${row.account.id}`"
                  class="text-xs font-medium hover:underline disabled:opacity-50"
                  :class="deactivateArmedFor === row.account.id ? 'text-red-700 dark:text-red-300 font-semibold' : 'text-red-500 dark:text-red-400'"
                  @click="deactivate(row)"
                >{{ deactivateArmedFor === row.account.id ? t('admin.sess.deactivateConfirm') : t('admin.sess.deactivate') }}</button>
              </div>
            </div>
          </li>
        </ul>

        <p class="mt-4 text-[11px] text-slate-400 dark:text-slate-500">
          {{ t('admin.sess.ladder', { product: branding.productName }) }}
        </p>
        <p class="mt-1 text-[11px] text-slate-400 dark:text-slate-500" data-testid="op-sess-retention">{{ retention }}</p>
      </section>
    </div>
  </div>
</template>
