<script setup lang="ts">
// ═══════════════════════════════════════════════════════════════════
// StatusBanner — the incident banner atop the sign-in page (the
// ISO-benchmark structural item 1's banner posture): when the estate's
// own status projection reports degraded or down services, a dignified
// strip says so and links to the status page. Green and unknown render
// NOTHING — the absence of the banner is never a claim. The pill (the
// footer) and this banner share the one probe (status-summary.ts).
// ═══════════════════════════════════════════════════════════════════
import { computed, onMounted } from 'vue'
import { t } from '../i18n'
import { resolveStatusSummary, useStatusSummary } from '../status-summary'

const { summary } = useStatusSummary()
onMounted(() => { void resolveStatusSummary() })

const active = computed(() => summary.value && (summary.value.state === 'degraded' || summary.value.state === 'down'))
const tone = computed(() =>
  summary.value?.state === 'down'
    ? 'bg-red-50 dark:bg-red-950/40 border-red-300 dark:border-red-800 text-red-900 dark:text-red-200'
    : 'bg-amber-50 dark:bg-amber-950/40 border-amber-300 dark:border-amber-800 text-amber-900 dark:text-amber-200',
)
</script>

<template>
  <div v-if="active" class="border-b" :class="tone" data-testid="status-banner" :data-state="summary!.state">
    <div class="max-w-6xl mx-auto px-4 sm:px-6 py-2.5 text-sm flex flex-wrap items-center justify-center gap-x-2 gap-y-1 text-center">
      <span>{{ summary!.state === 'down' ? t('login.statusBanner.down') : t('login.statusBanner.degraded') }}</span>
      <a :href="summary!.pageUrl" target="_blank" rel="noopener" class="font-medium underline underline-offset-4" data-testid="status-banner-link">{{ t('login.statusBanner.link') }}</a>
    </div>
  </div>
</template>
