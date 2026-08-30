<script setup lang="ts">
// ═══════════════════════════════════════════════════════════════════
// LocaleSwitch — the shell's EN/FR switcher (the ISO-benchmark quick
// win, smart's TODO.identity-features/11 item 3): the catalogs shipped
// lockstep-typed from the wave-02 extraction but nothing switched them.
// The language names are SELF-NAMED (English / Français) — a language
// name is never translated. The choice persists through the i18n
// layer's scoped localStorage (per-account where signed in, the
// unscoped key where anonymous — i18n/index.ts's setLocaleUser) and
// syncs <html lang> so assistive technology hears the switch.
// ═══════════════════════════════════════════════════════════════════
import { onMounted, watch } from 'vue'
import { t, useLocale, type Locale } from '../i18n'

const { locale, locales, setLocale } = useLocale()

const NAMES: Record<Locale, string> = { en: 'English', fr: 'Français' }

function syncHtmlLang(code: Locale): void {
  document.documentElement.lang = code
}

onMounted(() => syncHtmlLang(locale.value))
watch(locale, syncHtmlLang)
</script>

<template>
  <span class="inline-flex items-center gap-1.5" role="group" :aria-label="t('shell.locale.label')" data-testid="locale-switch">
    <template v-for="(code, i) in locales" :key="code">
      <span v-if="i > 0" class="text-slate-300 dark:text-slate-600" aria-hidden="true">·</span>
      <button
        type="button"
        :data-testid="`locale-${code}`"
        :aria-pressed="locale === code"
        class="hover:underline"
        :class="locale === code ? 'font-semibold text-slate-700 dark:text-slate-200' : ''"
        @click="setLocale(code)"
      >{{ NAMES[code] }}</button>
    </template>
  </span>
</template>
