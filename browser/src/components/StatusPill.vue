<script setup lang="ts">
// ═══════════════════════════════════════════════════════════════════
// StatusPill — the footer's live status affordance (the ISO-benchmark
// structural item 1, their strongest auth-surface play neutralized):
// a pill fed by the estate's OWN status service through /api/
// status-summary, linking to the public status page. Until the probe
// lands, the plain "Service status" link stands (no guessed state);
// an unreachable upstream reads "status unknown" — never a fake green.
// ═══════════════════════════════════════════════════════════════════
import { onMounted } from 'vue'
import { t } from '../i18n'
import { resolveStatusSummary, useStatusSummary, type EstateState } from '../status-summary'

const { summary } = useStatusSummary()
onMounted(() => { void resolveStatusSummary() })

const DOTS: Record<EstateState, string> = {
  operational: 'bg-green-500',
  degraded: 'bg-amber-500',
  down: 'bg-red-500',
  unknown: 'bg-slate-400',
}
const LABELS: Record<EstateState, Parameters<typeof t>[0]> = {
  operational: 'shell.status.operational',
  degraded: 'shell.status.degraded',
  down: 'shell.status.down',
  unknown: 'shell.status.unknown',
}
</script>

<template>
  <!-- Pre-probe: the plain link (the honest static affordance). -->
  <a v-if="!summary" href="https://status.oimlsmart.org/" target="_blank" rel="noopener" class="hover:underline" data-testid="shell-status">{{ t('shell.footer.status') }}</a>
  <a
    v-else
    :href="summary.pageUrl"
    target="_blank"
    rel="noopener"
    class="inline-flex items-center gap-1.5 rounded-full border border-slate-300 dark:border-slate-600 px-2.5 py-0.5 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors"
    data-testid="shell-status-pill"
    :data-state="summary.state"
  >
    <span class="w-2 h-2 rounded-full" :class="DOTS[summary.state]" aria-hidden="true" />
    {{ t(LABELS[summary.state]) }}
  </a>
</template>
