<script setup lang="ts">
// ═══════════════════════════════════════════════════════════════════
// BrandLogo, identity-service shape: the horizontal lockup (kind="logo"
// — the login/consent/admin surfaces) and the compact mark (kind="mark").
// The image follows the resolved branding and the color scheme (the
// house shell's class-based dark mode: tokens.css's @custom-variant);
// when an asset fails to load the fallback is the product NAME as text
// — the honest placeholder, never a broken image.
// ═══════════════════════════════════════════════════════════════════
import { computed, ref, watch } from 'vue'
import { useBranding } from '../branding'

const props = withDefaults(defineProps<{
  kind?: 'logo' | 'mark'
  /** Alt-text override; defaults to the service's product name. */
  alt?: string
}>(), { kind: 'logo', alt: undefined })

defineOptions({ inheritAttrs: false })

const { branding } = useBranding()

const failed = ref(false)

const light = computed(() => (props.kind === 'mark' ? branding.value.markLight : branding.value.logoLight))
const dark = computed(() => (props.kind === 'mark' ? branding.value.markDark : branding.value.logoDark))
const altText = computed(() => props.alt ?? branding.value.productName)

// A brand swap re-arms the image (the new asset may exist).
watch([light, dark], () => { failed.value = false })
</script>

<template>
  <!-- The caller's class lands on BOTH variants; exactly one is visible
       at a time (the dark: pair), so layout behaves as a single image. -->
  <span v-if="failed" v-bind="$attrs" class="font-serif font-bold">{{ altText }}</span>
  <template v-else>
    <img v-if="light" :src="light" :alt="altText" v-bind="$attrs" class="dark:hidden" @error="failed = true" />
    <img v-if="dark" :src="dark" :alt="altText" v-bind="$attrs" class="hidden dark:block" @error="failed = true" />
  </template>
</template>
