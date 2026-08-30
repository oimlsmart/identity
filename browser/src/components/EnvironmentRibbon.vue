<script setup lang="ts">
// ═══════════════════════════════════════════════════════════════════
// EnvironmentRibbon — the thin honesty strip on a non-production
// posture (the ISO-benchmark quick win, smart's
// TODO.identity-features/11 item 5; ISO's Training/Test/Dev ribbon,
// mirrored): the deployment declares ENVIRONMENT_LABEL, /api/config
// projects it, and the shell shows it — production declares nothing
// and shows nothing. The label is the deployment's own word (never
// translated); the note beside it follows the locale.
// ═══════════════════════════════════════════════════════════════════
import { onMounted } from 'vue'
import { t } from '../i18n'
import { resolveBranding, useEnvironmentLabel } from '../branding'

const { environmentLabel } = useEnvironmentLabel()
onMounted(() => { void resolveBranding() })
</script>

<template>
  <div
    v-if="environmentLabel"
    data-testid="env-ribbon"
    class="bg-amber-100 dark:bg-amber-950/60 border-b border-amber-300 dark:border-amber-800 text-amber-900 dark:text-amber-200 text-[11px] leading-5 text-center px-4 py-0.5"
  >
    <span class="font-semibold uppercase tracking-wide">{{ environmentLabel }}</span>
    <span class="text-amber-700 dark:text-amber-300/80"> — {{ t('shell.environment.note') }}</span>
  </div>
</template>
