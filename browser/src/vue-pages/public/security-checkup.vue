<script setup lang="ts">
// ═══════════════════════════════════════════════════════════════════
// THE SECURITY CHECKUP (2026-10-13, the Google parity): the account's
// hygiene in one guided read — every check names its finding and the
// act that settles it, the score ring summarizes. The acts live where
// they live (the account console's sections — the links go there);
// this page is the review, never a second settings surface.
// ═══════════════════════════════════════════════════════════════════
import { onMounted, ref, computed } from 'vue'
import { useRoute } from 'vue-router'
import BrandLogo from '../../components/BrandLogo.vue'
import { useBranding } from '../../branding'
import { t } from '../../i18n'

interface Check { id: string; ok: boolean; detail: Record<string, number>; act: string; label: string; fix: string }
interface SessionRow { id: string; current: boolean; lastSeenAt: string | null; createdAt: string; userAgent: string | null }
interface GrantRow { id: string; clientId: string; scope: string; createdAt: string }

const { branding } = useBranding()
const route = useRoute()
const loading = ref(true)
const error = ref<string | null>(null)
const score = ref<number | null>(null)
const checks = ref<Check[]>([])
const sessions = ref<SessionRow[]>([])
const grants = ref<GrantRow[]>([])
const factors = ref(0)

const scoreColor = computed(() => {
  if ((score.value ?? 0) >= 100) return 'text-emerald-600 dark:text-emerald-400'
  if ((score.value ?? 0) >= 60) return 'text-amber-600 dark:text-amber-400'
  return 'text-red-600 dark:text-red-400'
})
const openChecks = computed(() => checks.value.filter(c => !c.ok))

onMounted(async () => {
  try {
    const res = await fetch('/api/op/account/security-checkup', { credentials: 'include' })
    if (res.status === 401) {
      window.location.href = '/'
      return
    }
    if (!res.ok) throw new Error(String(res.status))
    const body = await res.json() as { score: number; checks: Check[]; sessions: SessionRow[]; grants: GrantRow[]; factors: number }
    score.value = body.score
    checks.value = body.checks
    sessions.value = body.sessions
    grants.value = body.grants
    factors.value = body.factors
  } catch {
    error.value = t('checkup.error')
  } finally {
    loading.value = false
  }
})
</script>

<template>
  <div class="min-h-screen flex items-center justify-center px-4 py-12 bg-cream dark:bg-slate-900">
    <div v-if="loading" class="flex flex-col items-center gap-4">
      <div class="w-8 h-8 border-2 border-brand-300 border-t-brand-600 rounded-full animate-spin" />
    </div>

    <div v-else class="w-full max-w-2xl" data-testid="checkup-page">
      <div class="text-center mb-8">
        <BrandLogo kind="logo" class="h-10 mx-auto mb-4" />
        <h1 class="text-xl font-serif font-bold text-slate-900 dark:text-white">{{ t('checkup.title') }}</h1>
        <p class="mt-2 text-sm text-slate-500 dark:text-slate-400">{{ branding.productName }}</p>
      </div>

      <div v-if="error" class="mb-4 p-3 rounded-lg bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800">
        <p class="text-sm text-red-700 dark:text-red-300" data-testid="checkup-error">{{ error }}</p>
      </div>

      <template v-else>
        <!-- The score ring -->
        <div class="rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 p-6 mb-4 flex items-center gap-6" data-testid="checkup-score">
          <div class="relative w-20 h-20 shrink-0">
            <svg viewBox="0 0 36 36" class="w-20 h-20 -rotate-90">
              <circle cx="18" cy="18" r="15.9" fill="none" stroke="#e2e8f0" stroke-width="3" class="dark:stroke-slate-700" />
              <circle cx="18" cy="18" r="15.9" fill="none" stroke="currentColor" stroke-width="3"
                :class="scoreColor"
                stroke-linecap="round"
                :stroke-dasharray="`${(score ?? 0) * 0.999} 999`" />
            </svg>
            <div class="absolute inset-0 flex items-center justify-center">
              <span class="text-xl font-bold" :class="scoreColor" data-testid="checkup-score-value">{{ score }}</span>
            </div>
          </div>
          <div>
            <h2 class="text-sm font-semibold text-slate-900 dark:text-white">{{ t('checkup.scoreTitle') }}</h2>
            <p class="text-xs text-slate-500 dark:text-slate-400 mt-1">
              {{ openChecks.length === 0 ? t('checkup.allGood') : t('checkup.openItems', { count: openChecks.length }) }}
            </p>
            <p class="text-xs text-slate-400 dark:text-slate-500 mt-1">{{ t('checkup.factors', { count: factors }) }}</p>
          </div>
        </div>

        <!-- The checks: every one names its finding and the act -->
        <div class="space-y-2 mb-4">
          <div
            v-for="check in checks"
            :key="check.id"
            class="rounded-lg border p-4 flex items-start justify-between gap-3"
            :class="check.ok
              ? 'border-emerald-200 dark:border-emerald-800 bg-emerald-50/50 dark:bg-emerald-900/10'
              : 'border-amber-200 dark:border-amber-800 bg-amber-50/50 dark:bg-amber-900/10'"
            :data-testid="`checkup-check-${check.id}`"
          >
            <div>
              <p class="text-sm font-medium" :class="check.ok ? 'text-emerald-800 dark:text-emerald-300' : 'text-amber-800 dark:text-amber-300'">
                <span aria-hidden="true">{{ check.ok ? '✓' : '!' }}</span>
                {{ check.label }}
              </p>
              <p v-if="!check.ok" class="text-xs text-slate-500 dark:text-slate-400 mt-0.5">{{ check.fix }}</p>
            </div>
            <router-link :to="check.act" class="text-xs font-medium text-brand-600 dark:text-brand-300 hover:underline shrink-0" :data-testid="`checkup-fix-${check.id}`">
              {{ t('checkup.fix') }} →
            </router-link>
          </div>
        </div>

        <!-- The sessions + the grants: the review lists, the acts in the console -->
        <div class="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 p-4 mb-4">
          <h3 class="text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400 mb-2">{{ t('checkup.sessions') }}</h3>
          <ul class="text-xs text-slate-600 dark:text-slate-300 space-y-1">
            <li v-for="session in sessions" :key="session.id" class="flex items-center gap-2" data-testid="checkup-session">
              <span class="font-medium">{{ session.userAgent ?? t('checkup.unknownClient') }}</span>
              <span v-if="session.current" class="text-[10px] px-1.5 py-0.5 rounded bg-brand-100 dark:bg-brand-900 text-brand-700 dark:text-brand-300">{{ t('checkup.thisDevice') }}</span>
              <span class="text-slate-400">{{ session.lastSeenAt ?? session.createdAt }}</span>
            </li>
          </ul>
          <router-link to="/op/account#sessions" class="text-xs text-brand-600 dark:text-brand-300 hover:underline mt-2 inline-block">{{ t('checkup.manageSessions') }} →</router-link>
        </div>

        <div v-if="grants.length" class="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 p-4">
          <h3 class="text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400 mb-2">{{ t('checkup.grants') }}</h3>
          <ul class="text-xs text-slate-600 dark:text-slate-300 space-y-1">
            <li v-for="grant in grants" :key="grant.id" data-testid="checkup-grant">
              <span class="font-medium">{{ grant.clientId }}</span> — <span class="font-mono">{{ grant.scope }}</span>
            </li>
          </ul>
          <router-link to="/op/account#factors" class="text-xs text-brand-600 dark:text-brand-300 hover:underline mt-2 inline-block">{{ t('checkup.manageGrants') }} →</router-link>
        </div>
      </template>
    </div>
  </div>
</template>
