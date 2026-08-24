<script setup lang="ts">
// ═══════════════════════════════════════════════════════════════════
// LaunchIcon — the SSO home's card glyphs. The named set is the
// registry's vocabulary (server/auth/op/launch.ts's LAUNCH_ICONS
// validates it at write): grid (a console hub), monitor (a demo
// surface), scale (a metrology institute), flask (a testing
// laboratory), chat (an assistant), external (the default launch
// glyph). Stroke-only, currentColor — the house's inline-SVG idiom (the
// sign-in page's provider buttons), emoji-free.
// ═══════════════════════════════════════════════════════════════════
import { computed } from 'vue'

const props = defineProps<{ name?: string | null }>()

// The path set per name (24 viewBox, stroke 1.8, round caps). An
// unknown name can never arrive (the write path refuses it); the
// default glyph stands in regardless.
const GLYPHS: Record<string, string[]> = {
  grid: [
    'M4 4h6.5v6.5H4z',
    'M13.5 4H20v6.5h-6.5z',
    'M4 13.5h6.5V20H4z',
    'M13.5 13.5H20V20h-6.5z',
  ],
  monitor: [
    'M3.5 5h17v11h-17z',
    'M12 16v3.5',
    'M8.5 19.5h7',
  ],
  scale: [
    'M12 4v16',
    'M8.5 20h7',
    'M4.5 6.5h15',
    'M7 6.5L4.6 12.2a2.7 2.7 0 0 0 4.8 0L7 6.5z',
    'M17 6.5l-2.4 5.7a2.7 2.7 0 0 0 4.8 0L17 6.5z',
  ],
  flask: [
    'M9.5 3.5h5',
    'M10 3.5v4.9l-5.3 9.3a2 2 0 0 0 1.8 3h11a2 2 0 0 0 1.8-3L14 8.4V3.5',
    'M7.3 14h9.4',
  ],
  chat: [
    'M4 6.8A2.8 2.8 0 0 1 6.8 4h10.4A2.8 2.8 0 0 1 20 6.8v6.4a2.8 2.8 0 0 1-2.8 2.8H9.4L4 20.5V6.8z',
  ],
  external: [
    'M13.5 4.5h6v6',
    'M19.5 4.5L11 13',
    'M19 13.5v5A1.5 1.5 0 0 1 17.5 20h-11A1.5 1.5 0 0 1 5 18.5v-11A1.5 1.5 0 0 1 6.5 6h5',
  ],
}

const paths = computed(() => GLYPHS[props.name ?? ''] ?? GLYPHS.external!)
</script>

<template>
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
    <path v-for="d in paths" :key="d" :d="d" />
  </svg>
</template>
