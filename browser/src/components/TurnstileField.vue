<script setup lang="ts">
// ═══════════════════════════════════════════════════════════════════
// The bot gate's widget half (TODO.modern/01): the public-facing forms
// (login, register, join) render this when /api/config carries a
// turnstile site key — the gate's server half flips on BOTH
// declarations, so an unarmed deployment never mounts this component
// at all. The token rides the POST body as `cf-turnstile-response`
// (the field name Cloudflare's own forms use; the gate reads exactly
// it). The parent resets the widget after a refused attempt — a spent
// token never repeats.
// ═══════════════════════════════════════════════════════════════════
import { onMounted, onUnmounted, ref } from 'vue'

interface TurnstileApi {
  render: (el: HTMLElement, opts: Record<string, unknown>) => string
  getResponse: (id: string) => string
  reset: (id?: string) => void
  remove: (id: string) => void
}

const props = defineProps<{ siteKey: string }>()

const host = ref<HTMLElement | null>(null)
const widgetId = ref<string | null>(null)
const token = ref('')

let scriptPromise: Promise<TurnstileApi> | null = null

function loadTurnstile(): Promise<TurnstileApi> {
  const existing = (window as { turnstile?: TurnstileApi }).turnstile
  if (existing) return Promise.resolve(existing)
  if (scriptPromise) return scriptPromise
  scriptPromise = new Promise((resolve, reject) => {
    const script = document.createElement('script')
    script.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit'
    script.async = true
    script.onload = () => {
      const api = (window as { turnstile?: TurnstileApi }).turnstile
      if (api) resolve(api)
      else reject(new Error('the turnstile script loaded without the API'))
    }
    script.onerror = () => reject(new Error('the turnstile script failed to load'))
    document.head.appendChild(script)
  })
  return scriptPromise
}

onMounted(async () => {
  try {
    const api = await loadTurnstile()
    if (!host.value) return
    widgetId.value = api.render(host.value, {
      sitekey: props.siteKey,
      callback: (value: string) => { token.value = value },
      'expired-callback': () => { token.value = '' },
      theme: 'auto',
    })
  } catch {
    // The script's absence leaves the widget empty: the submit's
    // getToken() answers '' and the page asks the human to retry —
    // the gate itself stays the honest arbiter server-side.
  }
})

onUnmounted(() => {
  if (widgetId.value !== null) {
    (window as { turnstile?: TurnstileApi }).turnstile?.remove(widgetId.value)
    widgetId.value = null
  }
})

/** The current token — '' when the human has not completed the
 *  challenge (the caller refuses the submit and says so). */
function getToken(): string {
  if (widgetId.value !== null) return (window as { turnstile?: TurnstileApi }).turnstile?.getResponse(widgetId.value) || token.value
  return token.value
}

/** A refused attempt never re-presents its token. */
function reset(): void {
  token.value = ''
  if (widgetId.value !== null) (window as { turnstile?: TurnstileApi }).turnstile?.reset(widgetId.value)
}

defineExpose({ getToken, reset })
</script>

<template>
  <div ref="host" data-testid="turnstile-widget" class="min-h-[65px]" />
</template>
