<script setup lang="ts">
// ═══════════════════════════════════════════════════════════════════
// NameFields — the ONE given/family pair (0043): every surface that
// collects a person's name mounts it, so the labels, the autocomplete
// hints and the two-column rhythm are declared once. The join doors,
// the registry-verified flow, the self-host register page and the
// admin consoles share it. The `tid` prefix names the inputs' ids and
// testids (`${tid}-given-name`, `${tid}-family-name`), so each host
// keeps its selectors; `compact` shrinks the pair for inline rows.
// ═══════════════════════════════════════════════════════════════════
import { t } from '../i18n'

const given = defineModel<string>('given', { required: true })
const family = defineModel<string>('family', { required: true })
defineProps<{
  /** The id/testid prefix (`join` → join-given-name / join-family-name). */
  tid: string
  /** The inline-row posture (the admin consoles' compact inputs). */
  compact?: boolean
}>()
</script>

<template>
  <div class="grid grid-cols-2 gap-3">
    <div>
      <label class="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1" :for="`${tid}-given-name`">{{ t('name.given.label') }}</label>
      <input
        :id="`${tid}-given-name`"
        v-model="given"
        type="text"
        required
        autocomplete="given-name"
        :data-testid="`${tid}-given-name`"
        class="w-full px-3 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-500"
        :class="compact ? 'py-1.5 text-xs' : 'py-2 text-sm'"
        placeholder="Jane"
      />
    </div>
    <div>
      <label class="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1" :for="`${tid}-family-name`">{{ t('name.family.label') }}</label>
      <input
        :id="`${tid}-family-name`"
        v-model="family"
        type="text"
        required
        autocomplete="family-name"
        :data-testid="`${tid}-family-name`"
        class="w-full px-3 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-500"
        :class="compact ? 'py-1.5 text-xs' : 'py-2 text-sm'"
        placeholder="Doe"
      />
    </div>
  </div>
</template>
