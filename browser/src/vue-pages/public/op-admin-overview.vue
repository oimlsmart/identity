<script setup lang="ts">
// ═══════════════════════════════════════════════════════════════════
// The admin console's overview (TODO.identity-sso/01, surface 1) — the
// tiles: accounts by lifecycle state, the live-session count, today's
// anomaly counts; the 14-day sign-in series (succeeded/failed, UTC
// days); and the SLO panel read from the heartbeat workflow's own
// history (the probe's results live on GitHub, never in the OP — the
// panel degrades to the honest link when the read fails).
//
// Every number is the SERVER's (routes/op-dashboard.ts over the audit
// journal + the store seam); this page only renders what the API
// answers. The retention statement rides the API and shows under the
// panels.
// ═══════════════════════════════════════════════════════════════════
import { computed, onMounted, ref } from 'vue'
import PageHeader from '../../components/PageHeader.vue'
import { useBranding } from '../../branding'
import { t } from '../../i18n'

interface Overview {
  generatedAt: string
  retention: string
  accounts: { total: number; active: number; deactivated: number; invited: number }
  signIns: {
    days: Array<{ date: string; succeeded: number; failed: number }>
    totals: { succeeded: number; failed: number }
    note: string
  }
  anomaliesToday: { failedSignIns: number; rateLimited: number; tokenRefusals: number; newLinks: number; newClients: number }
  liveSessions: number
}

interface Heartbeat {
  available: boolean
  reason?: string
  source: { repo: string; workflow: string; runsUrl: string }
  window?: { runs: number; since: string | null; note: string }
  totals?: { completed: number; succeeded: number; failed: number; successRate: number | null }
  lastRun?: { at: string; conclusion: string | null; url: string } | null
  failures?: Array<{ at: string; url: string }>
  fetchedAt: string
}

const { branding } = useBranding()

const loading = ref(true)
const forbidden = ref(false)
const error = ref<string | null>(null)
const overview = ref<Overview | null>(null)
const heartbeat = ref<Heartbeat | null>(null)
const heartbeatFailed = ref(false)

/** The series' normalized bar heights (the max day sets the scale). */
const seriesMax = computed(() =>
  Math.max(1, ...(overview.value?.signIns.days.map(d => d.succeeded + d.failed) ?? [])),
)

/** A day bucket's short label (every other day, "MM-DD"). */
function dayLabel(date: string, index: number): string {
  return index % 2 === 0 ? date.slice(5) : ''
}

/** The heartbeat's one-line posture. */
const heartbeatTone = computed(() => {
  const hb = heartbeat.value
  if (!hb?.available || !hb.totals) return 'unknown'
  if (hb.lastRun?.conclusion && hb.lastRun.conclusion !== 'success') return 'red'
  if (hb.totals.successRate !== null && hb.totals.successRate < 0.99) return 'amber'
  return 'green'
})

function pct(rate: number): string {
  return `${(rate * 100).toFixed(1)}%`
}

function stamp(iso: string): string {
  return iso.slice(0, 16).replace('T', ' ') + 'Z'
}

onMounted(async () => {
  // The SLO panel reads the heartbeat workflow's own history — a
  // separate fetch FIRED FIRST so it rides the same latency phase as the
  // session+overview pair (its GitHub read is the slow one; the tiles
  // never wait on it — its own catch lands whenever it lands).
  void (async () => {
    try {
      const hb = await fetch('/api/op/dashboard/heartbeat', { credentials: 'include' })
      if (!hb.ok) throw new Error(String(hb.status))
      heartbeat.value = await hb.json() as Heartbeat
    } catch {
      heartbeatFailed.value = true
    }
  })()
  try {
    // The session gate and the overview are INDEPENDENT reads — one
    // latency phase, never a two-hop waterfall (TODO.restructure/02).
    const [session, res] = await Promise.all([
      fetch('/api/auth/session', { credentials: 'include' }),
      fetch('/api/op/dashboard/overview', { credentials: 'include' }),
    ])
    if (!session.ok || res.status === 401) {
      window.location.assign(`/?redirect=${encodeURIComponent('/op/admin/overview')}`)
      return
    }
    if (res.status === 403) {
      forbidden.value = true
      return
    }
    if (!res.ok) throw new Error(t('admin.dash.loadFailed', { status: res.status }))
    overview.value = await res.json() as Overview
    loading.value = false
  } catch (e) {
    error.value = (e as Error).message || t('error.network')
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
        <h1 class="text-xl font-serif font-bold text-slate-900 dark:text-white">{{ t('admin.dash.title') }}</h1>
      </div>
      <div class="p-3 rounded-lg bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800">
        <p class="text-sm text-amber-800 dark:text-amber-300" data-testid="op-dash-forbidden">
          {{ t('admin.dash.forbidden') }}
        </p>
      </div>
    </div>

    <div v-else data-testid="op-dash">
      <PageHeader
        :title="t('admin.dash.title')"
        :description="t('admin.dash.description', { product: branding.productName })"
      />

      <div v-if="error" class="mb-4 p-3 rounded-lg bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800">
        <p class="text-sm text-red-700 dark:text-red-300" data-testid="op-dash-error">{{ error }}</p>
      </div>

      <template v-if="overview">
        <!-- The tiles -->
        <section class="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-6" data-testid="op-dash-tiles">
          <div class="rounded-xl border border-slate-200/80 dark:border-slate-700 bg-white dark:bg-slate-800 p-4" data-testid="op-dash-tile-accounts">
            <p class="text-[11px] uppercase tracking-wider text-slate-400 dark:text-slate-500 font-semibold">{{ t('admin.dash.tileAccounts') }}</p>
            <p class="mt-1 text-2xl font-semibold text-slate-900 dark:text-white">{{ overview.accounts.total }}</p>
            <p class="mt-1 text-[11px] text-slate-500 dark:text-slate-400" data-testid="op-dash-tile-accounts-split">
              {{ t('admin.dash.accountsSplit', { active: overview.accounts.active, invited: overview.accounts.invited, deactivated: overview.accounts.deactivated }) }}
            </p>
          </div>
          <div class="rounded-xl border border-slate-200/80 dark:border-slate-700 bg-white dark:bg-slate-800 p-4" data-testid="op-dash-tile-signins">
            <p class="text-[11px] uppercase tracking-wider text-slate-400 dark:text-slate-500 font-semibold">{{ t('admin.dash.tileSignins') }}</p>
            <p class="mt-1 text-2xl font-semibold text-slate-900 dark:text-white">{{ overview.signIns.totals.succeeded }}</p>
            <p class="mt-1 text-[11px] text-slate-500 dark:text-slate-400">
              <span :class="overview.signIns.totals.failed ? 'text-red-500 dark:text-red-400 font-semibold' : ''">{{ t('admin.dash.failedCount', { count: overview.signIns.totals.failed }) }}</span>
            </p>
          </div>
          <div class="rounded-xl border border-slate-200/80 dark:border-slate-700 bg-white dark:bg-slate-800 p-4" data-testid="op-dash-tile-sessions">
            <p class="text-[11px] uppercase tracking-wider text-slate-400 dark:text-slate-500 font-semibold">{{ t('admin.dash.tileSessions') }}</p>
            <p class="mt-1 text-2xl font-semibold text-slate-900 dark:text-white" data-testid="op-dash-live-sessions">{{ overview.liveSessions }}</p>
            <p class="mt-1 text-[11px] text-brand-600 dark:text-brand-300">
              <router-link to="/op/admin/sessions" class="hover:underline" data-testid="op-dash-open-sessions">who is signed in now</router-link>
            </p>
          </div>
          <div class="rounded-xl border border-slate-200/80 dark:border-slate-700 bg-white dark:bg-slate-800 p-4" data-testid="op-dash-tile-anomalies">
            <p class="text-[11px] uppercase tracking-wider text-slate-400 dark:text-slate-500 font-semibold">{{ t('admin.dash.tileAnomalies') }}</p>
            <p class="mt-1 text-2xl font-semibold text-slate-900 dark:text-white" data-testid="op-dash-anomalies-total">
              {{ overview.anomaliesToday.failedSignIns + overview.anomaliesToday.rateLimited + overview.anomaliesToday.tokenRefusals }}
            </p>
            <p class="mt-1 text-[11px] text-slate-500 dark:text-slate-400" data-testid="op-dash-anomalies-split">
              {{ t('admin.dash.anomaliesSplit', { failedSignIns: overview.anomaliesToday.failedSignIns, rateLimits: overview.anomaliesToday.rateLimited, tokenRefusals: overview.anomaliesToday.tokenRefusals }) }}
            </p>
          </div>
        </section>

        <!-- The sign-in series -->
        <section class="rounded-xl border border-slate-200/80 dark:border-slate-700 bg-white dark:bg-slate-800 p-6 mb-6" data-testid="op-dash-signins">
          <h2 class="text-xs font-semibold uppercase tracking-wider text-slate-400 dark:text-slate-500 mb-1">{{ t('admin.dash.sectionSignins') }}</h2>
          <p class="text-[11px] text-slate-400 dark:text-slate-500 mb-4">{{ overview.signIns.note }}.</p>
          <div class="flex items-end gap-1 h-24" data-testid="op-dash-signins-chart">
            <div v-for="(day, i) in overview.signIns.days" :key="day.date" class="flex-1 flex flex-col items-center justify-end h-full min-w-0">
              <div class="w-full max-w-6 flex flex-col justify-end rounded-sm overflow-hidden" style="height: 100%">
                <div
                  class="w-full bg-red-400 dark:bg-red-500/80"
                  :style="{ height: `${(day.failed / seriesMax) * 100}%` }"
                  :title="t('admin.dash.dayFailed', { date: day.date, count: day.failed })"
                />
                <div
                  class="w-full bg-emerald-400 dark:bg-emerald-500/80"
                  :style="{ height: `${(day.succeeded / seriesMax) * 100}%` }"
                  :title="t('admin.dash.daySucceeded', { date: day.date, count: day.succeeded })"
                />
              </div>
              <p class="mt-1 text-[9px] text-slate-400 dark:text-slate-500 truncate w-full text-center">{{ dayLabel(day.date, i) }}</p>
            </div>
          </div>
          <p v-if="!overview.signIns.totals.succeeded && !overview.signIns.totals.failed" class="mt-2 text-xs text-slate-500 dark:text-slate-400" data-testid="op-dash-signins-empty">
            {{ t('admin.dash.signinsEmpty') }}
          </p>
        </section>

        <!-- The SLO panel -->
        <section class="rounded-xl border border-slate-200/80 dark:border-slate-700 bg-white dark:bg-slate-800 p-6" data-testid="op-dash-slo">
          <h2 class="text-xs font-semibold uppercase tracking-wider text-slate-400 dark:text-slate-500 mb-1">{{ t('admin.dash.sectionSlo') }}</h2>
          <p class="text-[11px] text-slate-400 dark:text-slate-500 mb-4">
            The stated SLO is 99.9% monthly, measured by the identity-heartbeat workflow’s 15-minute probes of the public OIDC surface; the probe’s results live in the workflow’s own history, read at the source.
          </p>

          <p v-if="!heartbeat && !heartbeatFailed" class="text-sm text-slate-500 dark:text-slate-400" data-testid="op-dash-slo-loading">{{ t('admin.dash.sloLoading') }}</p>

          <div v-else-if="heartbeat?.available && heartbeat.totals" data-testid="op-dash-slo-live">
            <div class="flex flex-wrap items-baseline gap-x-6 gap-y-2">
              <p class="text-2xl font-semibold" :class="{
                'text-emerald-600 dark:text-emerald-400': heartbeatTone === 'green',
                'text-amber-600 dark:text-amber-400': heartbeatTone === 'amber',
                'text-red-600 dark:text-red-400': heartbeatTone === 'red',
              }" data-testid="op-dash-slo-rate">
                {{ heartbeat.totals.successRate !== null ? pct(heartbeat.totals.successRate) : t('admin.dash.sloNoProbes') }}
              </p>
              <p class="text-xs text-slate-500 dark:text-slate-400" data-testid="op-dash-slo-window">
                {{ t('admin.dash.sloProbes', { succeeded: heartbeat.totals.succeeded, completed: heartbeat.totals.completed, note: heartbeat.window?.note ?? '' }) }}<template v-if="heartbeat.window?.since">{{ t('admin.dash.sloSince', { since: stamp(heartbeat.window.since) }) }}</template>
              </p>
            </div>
            <p v-if="heartbeat.lastRun" class="mt-2 text-xs text-slate-500 dark:text-slate-400" data-testid="op-dash-slo-last">
              {{ t('admin.dash.sloLastProbe', { at: stamp(heartbeat.lastRun.at) }) }}:
              <span :class="heartbeat.lastRun.conclusion === 'success' ? 'text-emerald-600 dark:text-emerald-400 font-semibold' : 'text-red-600 dark:text-red-400 font-semibold'">{{ heartbeat.lastRun.conclusion ?? t('admin.dash.sloRunning') }}</span>
            </p>
            <ul v-if="heartbeat.failures?.length" class="mt-2 space-y-1" data-testid="op-dash-slo-failures">
              <li v-for="failure in heartbeat.failures" :key="failure.url" class="text-[11px] text-red-600 dark:text-red-400">
                {{ stamp(failure.at) }} — <a :href="failure.url" target="_blank" rel="noopener" class="underline">{{ t('admin.dash.sloFailedRun') }}</a>
              </li>
            </ul>
          </div>

          <div v-else class="p-3 rounded-lg bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800" data-testid="op-dash-slo-unavailable">
            <p class="text-sm text-amber-800 dark:text-amber-300">
              {{ t('admin.dash.sloUnreadable') }}{{ heartbeat?.reason ? ` — ${heartbeat.reason}` : '' }}.
            </p>
          </div>

          <p class="mt-3 text-[11px] text-slate-400 dark:text-slate-500">
            The record:
            <a v-if="heartbeat" :href="heartbeat.source.runsUrl" target="_blank" rel="noopener" class="text-brand-600 dark:text-brand-300 hover:underline" data-testid="op-dash-slo-link">the identity-heartbeat workflow</a>
            <a v-else href="https://github.com/oimlsmart/identity/actions/workflows/identity-heartbeat.yml" target="_blank" rel="noopener" class="text-brand-600 dark:text-brand-300 hover:underline" data-testid="op-dash-slo-link">the identity-heartbeat workflow</a>
            — a red probe also opens the standing issue.
          </p>
        </section>

        <p class="mt-4 text-[11px] text-slate-400 dark:text-slate-500" data-testid="op-dash-retention">{{ overview.retention }}</p>
      </template>
    </div>
  </div>
</template>
