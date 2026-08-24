<script setup lang="ts">
// ═══════════════════════════════════════════════════════════════════
// IdPage — the identity shell's one island idiom: mount the named
// src/vue-pages component (lazy glob) with the shared Suspense
// fallback. No Gate, no bootstrap: every identity page runs its own
// session check (the 401 → /app/login redirect lives in the page).
// ═══════════════════════════════════════════════════════════════════
import { defineAsyncComponent, onMounted, type Component } from 'vue'
import { resolveBranding } from '../branding'

const props = defineProps<{ page: string }>()

// The pages brand before anyone signs in (the login page is the first
// surface a user meets): resolve the instance brand on mount. Cached
// module-level; every later page reuses the same resolution.
onMounted(() => { void resolveBranding() })

const pages = import.meta.glob('../vue-pages/**/*.vue')
const loader = pages[`../vue-pages/${props.page}.vue`]
if (!loader) throw new Error(`IdPage: no src/vue-pages entry for "${props.page}"`)
const PageComponent = defineAsyncComponent(loader as () => Promise<Component>)
</script>

<template>
  <Suspense>
    <PageComponent />
    <template #fallback>
      <div class="flex items-center justify-center py-32">
        <div class="w-8 h-8 border-2 border-brand-300 border-t-brand-600 rounded-full animate-spin" />
      </div>
    </template>
  </Suspense>
</template>
