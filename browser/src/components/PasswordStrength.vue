<script setup lang="ts">
// ═══════════════════════════════════════════════════════════════════
// PasswordStrength — THE one honest strength meter (the DRY ruling):
// every surface where a password is chosen mounts it. The classes
// mirror server/auth/passwords.ts — DISPLAY only (the server re-judges
// the policy at submit; a drift here can only ever under-advise, never
// admit a weaker password). Length carries the score.
// ═══════════════════════════════════════════════════════════════════
import { computed } from 'vue'
import { t } from '../i18n'

const props = defineProps<{
  /** The candidate password (read-only; the host owns the field). */
  password: string
  /** The id/testid prefix (`account-password` → account-password-meter). */
  tid: string
}>()

const strength = computed(() => {
  const pw = props.password
  const len = pw.length
  let variety = 0
  if (/[a-z]/.test(pw)) variety++
  if (/[A-Z]/.test(pw)) variety++
  if (/[0-9]/.test(pw)) variety++
  if (/[^a-zA-Z0-9]/.test(pw)) variety++
  if (len < 12) return { score: 0, label: t('account.password.strength.tooShort'), hint: t('account.password.strength.hintShort', { count: 12 - len }) }
  if (len < 16 && variety < 3) return { score: 1, label: t('account.password.strength.fair'), hint: t('account.password.strength.hintLonger') }
  if (len < 20) return { score: 2, label: t('account.password.strength.good'), hint: variety < 3 ? t('account.password.strength.hintMix') : t('account.password.strength.hintMore') }
  return { score: 3, label: t('account.password.strength.strong'), hint: '' }
})

const METER_COLORS = ['bg-red-400', 'bg-amber-400', 'bg-brand-400', 'bg-green-500']
</script>

<template>
  <div v-if="password" class="mt-2" :data-testid="`${tid}-meter`">
    <div class="flex gap-1 mb-1">
      <div
        v-for="step in 4"
        :key="step"
        class="h-1 flex-1 rounded-full"
        :class="step - 1 <= strength.score && password.length >= 12 ? METER_COLORS[strength.score] : (strength.score === 0 && step === 1 ? METER_COLORS[0] : 'bg-slate-200 dark:bg-slate-700')"
      />
    </div>
    <p class="text-xs text-slate-500 dark:text-slate-400">
      <span class="font-medium" :data-testid="`${tid}-meter-label`">{{ strength.label }}</span>
      <span v-if="strength.hint"> · {{ strength.hint }}</span>
    </p>
  </div>
</template>
