<script setup lang="ts">
// ═══════════════════════════════════════════════════════════════════
// ShellFooter — the IdShell's one-line footer as ONE island (it follows
// the locale now, so it can no longer be static markup): the service
// tagline, the status link, the locale switch (the ISO-benchmark quick
// win, smart's TODO.identity-features/11 item 3), and — on the bare
// sign-in posture, which has no header to carry it — the theme toggle.
// The <footer> element itself stays in IdShell.astro.
// ═══════════════════════════════════════════════════════════════════
import ThemeToggle from '@oimlsmart/site-shell/components/ThemeToggle.vue'
import LocaleSwitch from './LocaleSwitch.vue'
import { t } from '../i18n'

defineProps<{
  /** The sign-in page's chromeless posture (the theme toggle rides the
   *  footer there — no header to carry it). */
  bare?: boolean
}>()
</script>

<template>
  <div class="max-w-6xl mx-auto px-4 sm:px-6 py-5 flex flex-wrap items-center justify-between gap-2 text-xs text-slate-500 dark:text-slate-400" data-testid="shell-footer">
    <span>{{ t('shell.footer.tagline') }}</span>
    <span class="flex items-center gap-3">
      <a href="/api/health" class="hover:underline" data-testid="shell-status">{{ t('shell.footer.status') }}</a>
      <LocaleSwitch />
      <ThemeToggle v-if="bare" />
    </span>
  </div>
</template>
