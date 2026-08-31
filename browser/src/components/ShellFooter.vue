<script setup lang="ts">
// ═══════════════════════════════════════════════════════════════════
// ShellFooter — the IdShell's one-line footer as ONE island (it follows
// the locale now, so it can no longer be static markup): the service
// tagline, the status link, the locale switch (the ISO-benchmark quick
// win, smart's TODO.identity-features/11 item 3), and — on the bare
// sign-in posture, which has no header to carry it — the theme toggle.
// The <footer> element itself stays in IdShell.astro.
// ═══════════════════════════════════════════════════════════════════
import { onMounted } from 'vue'
import ThemeToggle from '@oimlsmart/site-shell/components/ThemeToggle.vue'
import LocaleSwitch from './LocaleSwitch.vue'
import { t } from '../i18n'
import { resolveBranding, useBranding } from '../branding'

defineProps<{
  /** The sign-in page's chromeless posture (the theme toggle rides the
   *  footer there — no header to carry it). */
  bare?: boolean
}>()

// The support affordance (item 6) reads the deployment's SUPPORT_URL
// through the branding contract — one shared probe (IdPage mounts one
// too; resolveBranding dedupes).
const { branding } = useBranding()
onMounted(() => { void resolveBranding() })
</script>

<template>
  <div class="max-w-6xl mx-auto px-4 sm:px-6 py-5 flex flex-wrap items-center justify-between gap-2 text-xs text-slate-600 dark:text-slate-400" data-testid="shell-footer">
    <span>{{ t('shell.footer.tagline') }}</span>
    <span class="flex items-center gap-3">
      <!-- The estate's legal pages (the ISO-benchmark quick win, item 2):
           plain links to the www site's own pages. -->
      <a href="https://www.oimlsmart.org/privacy/" target="_blank" rel="noopener" class="hover:underline" data-testid="shell-privacy">{{ t('shell.footer.privacy') }}</a>
      <a href="https://www.oimlsmart.org/terms/" target="_blank" rel="noopener" class="hover:underline" data-testid="shell-terms">{{ t('shell.footer.terms') }}</a>
      <!-- The support affordance (item 6): a plain link when the
           deployment declares SUPPORT_URL — never a third-party widget
           on the credential surface. -->
      <a v-if="branding.supportUrl" :href="branding.supportUrl" target="_blank" rel="noopener" class="hover:underline" data-testid="shell-support">{{ t('shell.footer.supportPrompt') }}</a>
      <a href="/api/health" class="hover:underline" data-testid="shell-status">{{ t('shell.footer.status') }}</a>
      <LocaleSwitch />
      <ThemeToggle v-if="bare" />
    </span>
  </div>
</template>
