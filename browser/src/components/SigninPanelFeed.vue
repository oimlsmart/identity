<script setup lang="ts">
// ═══════════════════════════════════════════════════════════════════
// SigninPanelFeed — the editorial panel's rotating content (the
// ISO-benchmark structural item 4): the scheduled, priority-weighted
// feed from /api/panels, the bundled document as the offline default.
// The renderer is deliberately plain — a badge, a heading, the body,
// an optional CTA — on the panel's navy: no third-party anything on
// the credential surface.
// ═══════════════════════════════════════════════════════════════════
import { onMounted } from 'vue'
import { resolvePanels, useSigninPanel } from '../signin-panels'

const { panel } = useSigninPanel()
onMounted(() => { void resolvePanels() })
</script>

<template>
  <div v-if="panel" class="mt-10 pt-8 border-t border-white/15" data-testid="login-panel-feed">
    <p class="text-xs font-semibold uppercase tracking-widest text-brand-300" data-testid="login-panel-badge">{{ panel.badge }}</p>
    <h3 class="mt-2 font-serif text-xl font-semibold leading-snug text-white" data-testid="login-panel-heading">{{ panel.heading }}</h3>
    <p class="mt-2 text-sm leading-relaxed text-brand-100/80 max-w-md" data-testid="login-panel-body">{{ panel.body }}</p>
    <p v-if="panel.cta" class="mt-3">
      <a :href="panel.cta.href" class="text-sm font-medium text-brand-200 hover:text-white underline underline-offset-4" data-testid="login-panel-cta">{{ panel.cta.label }}</a>
    </p>
  </div>
</template>
