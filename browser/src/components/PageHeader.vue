<script setup lang="ts">
/**
 * PageHeader — the house page-header idiom (see vue-pages/requirements.vue,
 * certificates.vue): serif brand-900 title, subtle slate description, and
 * right-aligned actions. No bordered/eyebrow headers.
 *
 * Slots: `badges` (inline next to the title — StatusBadge etc.),
 * `description` (rich description; falls back to the prop), default
 * (right-hand action buttons).
 *
 * Palette classes only — dark mode comes from the app-main inversion
 * (src/styles/main.css); do not add dark: surface overrides here.
 */
defineProps<{
  title: string
  description?: string
  /** When set, renders a "← back" link above the title; the parent
      owns the navigation (via the `back` event) to keep routing local. */
  backLabel?: string
}>()

const emit = defineEmits<{ back: [] }>()
</script>

<template>
  <header class="mb-8">
    <button
      v-if="backLabel"
      type="button"
      class="text-sm text-brand-600 hover:text-brand-700 font-medium mb-2 transition-colors"
      @click="emit('back')"
    >← {{ backLabel }}</button>
    <div class="flex items-start justify-between gap-4 flex-wrap">
      <div class="min-w-0">
        <div class="flex items-center gap-3 flex-wrap">
          <h1 class="text-2xl lg:text-3xl font-serif font-bold text-brand-900 tracking-tight">{{ title }}</h1>
          <slot name="badges" />
        </div>
        <div v-if="description || $slots.description" class="text-sm text-slate-500 mt-2">
          <slot name="description">{{ description }}</slot>
        </div>
      </div>
      <div v-if="$slots.default" class="flex items-center gap-2 flex-shrink-0 flex-wrap">
        <slot />
      </div>
    </div>
  </header>
</template>
