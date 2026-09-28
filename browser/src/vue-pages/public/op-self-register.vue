<script setup lang="ts">
// ═══════════════════════════════════════════════════════════════════
// The Ommisa member tier's self-enrollment page (the four-gate flow's
// human surface):
//
//   the start form  — the country → the organization → the name + the
//                     work email, behind the Turnstile field. The
//                     submit rides leg 1 (the eligibility reads) and
//                     bounces to the attribution upstream.
//   ?sent=1         — "check your inbox" (the shown-once link rides
//                     only when no mailer stands).
//   ?error=…        — the honest sentence + the start again.
//   ?token=…        — the emailed click: the proof posts on load, and
//                     the setup step collects the password (the name
//                     and the email ride the link's own signature).
//
// NOTHING is stored until the verified click — the page is a reader,
// never a writer, until then.
// ═══════════════════════════════════════════════════════════════════
import { computed, onMounted, ref } from 'vue'
import { useRoute } from 'vue-router'
import BrandLogo from '../../components/BrandLogo.vue'
import TurnstileField from '../../components/TurnstileField.vue'
import { fetchTurnstileSiteKey } from '../../components/turnstile'
import { t } from '../../i18n'

interface PickerOrg { name: string; domains: string[]; website_domains?: string[]; web_domains?: string[]; verification: string; admin_queue: boolean }
interface PickerCountry { country: string; country_fr: string; iso?: string; orgs: PickerOrg[] }

const route = useRoute()

const loading = ref(true)
const busy = ref(false)
const error = ref<string | null>(null)
const notice = ref<string | null>(null)
const devLink = ref<string | null>(null)

// The start form's state.
const countries = ref<PickerCountry[]>([])
const country = ref('')
const org = ref('')
const name = ref('')
const email = ref('')
const turnstileSiteKey = ref<string | null>(null)
const turnstileField = ref<InstanceType<typeof TurnstileField> | null>(null)

// The verified setup's state (the token leg). `token` = the emailed
// LINK (the second proof still owed); `setup` = the SECOND sign-in's
// proof (the password form's credential).
const token = typeof route.query.token === 'string' ? route.query.token : ''
const setup = typeof route.query.setup === 'string' ? route.query.setup : ''
const activeToken = setup || token
const secondRequired = ref(false)
const secondProviders = ref<AttributionProvider[] | null>(null)
const verifiedEmail = ref<string | null>(null)
const verifiedOrg = ref<string | null>(null)
const setupDone = ref(false)

// The sent posture is a COMPLETION screen: the flow's own terminal —
// the start form never re-renders beneath it (the 2026-09-29 ruling).
const sentTerminal = ref(false)

const orgs = computed<PickerOrg[]>(() =>
  countries.value.find(c => c.country === country.value)?.orgs ?? [])

// The attribution CHOICE (the interstitial): the start leg's answer
// carries one bounce per enabled human-proof upstream. The applicant
// picks WHO attests them — before any assignment, the page explains
// WHY the check exists (the anti-mailer-gun gate: one attributable
// login buys one confirmation email; the upstream identity itself is
// never stored, never linked).
interface AttributionProvider { id: string; name: string; next: string }
const attribution = ref<AttributionProvider[] | null>(null)

// The country autocomplete: type instead of scroll. The query filters
// the sorted list (the XX class stays last); picking sets the country.
const countryQuery = ref('')
const countryOpen = ref(false)
const countryMatches = computed<PickerCountry[]>(() => {
  const q = countryQuery.value.trim().toLowerCase()
  const list = sortedCountries.value
  if (!q) return list
  return list.filter(c =>
    c.country.toLowerCase().includes(q) || c.country_fr.toLowerCase().includes(q) || c.iso?.toLowerCase() === q)
})
function pickCountry(c: PickerCountry): void {
  country.value = c.country
  countryQuery.value = c.country
  countryOpen.value = false
  org.value = ''
}
function onCountryKeydown(e: KeyboardEvent): void {
  if (e.key === 'Escape') { countryOpen.value = false; return }
  if (e.key !== 'ArrowDown' && e.key !== 'Enter') return
  e.preventDefault()
  const first = countryMatches.value[0]
  if (first) pickCountry(first)
}

/** The pickers render ALPHABETICALLY (the artifact's own order is
 *  member-states-first — the page's reader wants the alphabet), with
 *  the Other-organizations class (the ISO 3166 user-assigned XX)
 *  pinned LAST — never a country claim. */
const sortedCountries = computed<PickerCountry[]>(() =>
  [...countries.value].sort((a, b) => {
    const ax = a.iso === 'XX' ? 1 : 0
    const bx = b.iso === 'XX' ? 1 : 0
    return ax - bx || a.country.localeCompare(b.country)
  }))

/** The selected organization's auto-approved email domains — every
 *  domain the registry claims for it, shown so the reader knows which
 *  address will be accepted before they type it. */
const orgDomains = computed<string[]>(() => {
  const picked = orgs.value.find(o => o.name === org.value)
  if (!picked) return []
  return [...new Set([...picked.domains, ...(picked.website_domains ?? []), ...(picked.web_domains ?? [])])].sort()
})

/** The typed address's verdict against the shown domains (the instant
 *  client-side mirror of the server's dot-boundary check). */
const emailMatchesOrg = computed<boolean>(() => {
  const d = email.value.split('@')[1]?.toLowerCase()
  if (!d) return false
  return orgDomains.value.some(e => d === e || d.endsWith('.' + e))
})

function continueAttribution(p: AttributionProvider): void {
  window.location.assign(p.next)
}

async function start(): Promise<void> {
  if (busy.value) return
  // The bot gate (armed only): the widget's token rides the POST body.
  let turnstileToken: string | undefined
  if (turnstileSiteKey.value) {
    turnstileToken = turnstileField.value?.getToken() ?? ''
    if (!turnstileToken) {
      error.value = t('selfreg.turnstileRequired')
      return
    }
  }
  busy.value = true
  error.value = null
  try {
    const res = await fetch('/api/op/self-register/start', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ country: country.value, org: org.value, name: name.value, email: email.value, ...(turnstileToken !== undefined ? { 'cf-turnstile-response': turnstileToken } : {}) }),
    })
    const body = await res.json() as { ok?: boolean; providers?: AttributionProvider[]; queued?: boolean; error?: string }
    if (res.status === 403) turnstileField.value?.reset() // a spent token never repeats
    if (body.queued) {
      notice.value = body.error ?? t('selfreg.queuedFallback')
      return
    }
    if (!res.ok || !body.providers?.length) {
      error.value = body.error ?? t('selfreg.failed')
      return
    }
    attribution.value = body.providers
  } catch {
    error.value = t('error.network')
  } finally {
    busy.value = false
  }
}

async function verifySecond(): Promise<void> {
  if (busy.value) return
  busy.value = true
  error.value = null
  try {
    const res = await fetch(`/api/op/self-register/second-proof?token=${encodeURIComponent(token)}`)
    const body = await res.json() as { ok?: boolean; providers?: AttributionProvider[]; error?: string }
    if (res.ok && body.providers?.length) {
      secondProviders.value = body.providers
    } else {
      error.value = body.error ?? t('selfreg.failed')
    }
  } catch {
    error.value = t('error.network')
  } finally {
    busy.value = false
  }
}

async function complete(): Promise<void> {
  if (busy.value) return
  busy.value = true
  error.value = null
  try {
    const res = await fetch('/api/op/self-register/complete', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ token: activeToken, password: password.value }),
    })
    const body = await res.json() as { ok?: boolean; error?: string }
    if (res.ok && body.ok) {
      setupDone.value = true
      return
    }
    error.value = body.error ?? t('selfreg.failed')
  } catch {
    error.value = t('error.network')
  } finally {
    busy.value = false
  }
}

const password = ref('')
async function verifyToken(): Promise<void> {
  try {
    const res = await fetch('/api/op/self-register/verify', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ token: activeToken }),
    })
    const body = await res.json() as { ok?: boolean; email?: string; org?: string; secondProof?: boolean; error?: string }
    if (res.ok && body.ok) {
      verifiedEmail.value = body.email ?? null
      verifiedOrg.value = body.org ?? null
      secondRequired.value = body.secondProof === true
    } else {
      error.value = body.error ?? t('selfreg.failed')
    }
  } catch {
    error.value = t('error.network')
  }
}

onMounted(async () => {
  const queryError = typeof route.query.error === 'string' ? route.query.error : null
  if (queryError === 'exists') error.value = t('selfreg.errorExists')
  else if (queryError === 'expired') error.value = t('selfreg.errorExpired')
  else if (queryError === 'queued') error.value = t('selfreg.queuedFallback')

  if (typeof route.query.link === 'string' && route.query.link) devLink.value = route.query.link
  if (typeof route.query.sent === 'string') {
    notice.value = t('selfreg.sent')
    sentTerminal.value = true
  }
  if (route.query.error === 'second-proof') error.value = t('selfreg.errorSecondProof')

  try {
    const cfg = await fetch('/api/config').then(r => r.json()) as { turnstile?: { siteKey?: string | null } }
    turnstileSiteKey.value = cfg.turnstile?.siteKey ?? null
  } catch { /* the field hides; the server still judges */ }
  void fetchTurnstileSiteKey

  try {
    const res = await fetch('/api/op/self-register/catalog')
    if (res.ok) {
      const body = await res.json() as { countries: PickerCountry[] }
      countries.value = body.countries
    } else {
      error.value = t('selfreg.catalogFailed')
    }
  } catch {
    error.value = t('error.network')
  }

  if (activeToken) await verifyToken()
  loading.value = false
})
</script>

<template>
  <div class="min-h-screen flex items-center justify-center px-4 py-12 bg-cream dark:bg-slate-900">
    <div class="w-full max-w-md" data-testid="selfreg-page">
      <div class="text-center mb-8">
        <BrandLogo kind="logo" class="h-10 mx-auto mb-4" />
        <h1 class="text-2xl font-serif font-bold text-slate-900 dark:text-white" data-testid="selfreg-heading">{{ t('selfreg.heading') }}</h1>
        <p class="mt-2 text-sm text-slate-600 dark:text-slate-400" data-testid="selfreg-subtitle">{{ t('selfreg.subtitle') }}</p>
      </div>

      <div v-if="error" class="mb-4 p-3 rounded-lg bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800">
        <p class="text-sm text-red-700 dark:text-red-300" data-testid="selfreg-error">{{ error }}</p>
        <p v-if="!token" class="mt-2 text-sm text-slate-600 dark:text-slate-400">{{ t('selfreg.queueHint') }}
          <router-link to="/op/join" class="text-brand-600 dark:text-brand-300 hover:underline" data-testid="selfreg-join-link">{{ t('selfreg.queueLink') }}</router-link>
        </p>
      </div>

      <div v-if="notice" class="mb-4 p-3 rounded-lg bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800">
        <p class="text-sm text-green-700 dark:text-green-300" data-testid="selfreg-notice">{{ notice }}</p>
        <p v-if="devLink" class="mt-2 text-xs break-all text-slate-600 dark:text-slate-400" data-testid="selfreg-dev-link">
          <a :href="devLink" class="text-brand-600 dark:text-brand-300 hover:underline">{{ t('selfreg.devLink') }}</a>
        </p>
      </div>

      <div v-if="loading" class="flex flex-col items-center gap-4">
        <div class="w-8 h-8 border-2 border-brand-300 border-t-brand-600 rounded-full animate-spin" />
      </div>

      <!-- The sent COMPLETION screen: terminal — the form never
           re-renders beneath it. -->
      <div v-else-if="sentTerminal" class="bg-white dark:bg-slate-800 rounded-xl border border-green-200 dark:border-green-800 p-6 text-center" data-testid="selfreg-sent-screen">
        <div class="w-12 h-12 mx-auto mb-4 rounded-full bg-green-100 dark:bg-green-900/30 flex items-center justify-center">
          <svg class="w-6 h-6 text-green-600 dark:text-green-400" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" /></svg>
        </div>
        <h2 class="text-lg font-serif font-bold text-slate-900 dark:text-white" data-testid="selfreg-sent-title">{{ t('selfreg.sentTitle') }}</h2>
        <p class="mt-2 text-sm text-slate-600 dark:text-slate-400" data-testid="selfreg-sent-body">{{ t('selfreg.sent') }}</p>
        <p v-if="devLink" class="mt-4 text-xs break-all text-slate-600 dark:text-slate-400" data-testid="selfreg-dev-link">
          <a :href="devLink" class="text-brand-600 dark:text-brand-300 hover:underline">{{ t('selfreg.devLink') }}</a>
        </p>
      </div>

      <!-- The verified setup: the SECOND PROOF step, then the password
           step (the name and the email ride the link's signature). -->
      <div v-else-if="activeToken" class="bg-white dark:bg-slate-800 rounded-xl border border-slate-200 dark:border-slate-700 p-6">
        <template v-if="setupDone">
          <p class="text-sm text-green-700 dark:text-green-300" data-testid="selfreg-done">{{ t('selfreg.done') }}</p>
          <p class="mt-3 text-sm">
            <router-link to="/" class="text-brand-600 dark:text-brand-300 hover:underline" data-testid="selfreg-done-signin">{{ t('selfreg.doneSignin') }}</router-link>
          </p>
        </template>
        <template v-else-if="verifiedEmail && secondRequired && !setup">
          <p class="text-sm text-slate-600 dark:text-slate-400 mb-4" data-testid="selfreg-verified">{{ t('selfreg.verifiedFor', { email: verifiedEmail, org: verifiedOrg ?? '' }) }}</p>
          <h2 class="text-base font-serif font-bold text-slate-900 dark:text-white" data-testid="selfreg-second-title">{{ t('selfreg.second.title') }}</h2>
          <p class="mt-2 text-sm text-slate-600 dark:text-slate-400" data-testid="selfreg-second-why">{{ t('selfreg.second.why') }}</p>
          <div class="mt-4 space-y-2" v-if="secondProviders === null">
            <button
              type="button" :disabled="busy"
              class="w-full px-4 py-2 rounded-lg text-sm font-medium bg-brand-600 text-white hover:bg-brand-700 transition-colors disabled:opacity-50"
              data-testid="selfreg-second-begin"
              @click="verifySecond"
            >{{ busy ? t('selfreg.working') : t('selfreg.second.begin') }}</button>
          </div>
          <div class="mt-4 space-y-2" v-else>
            <button
              v-for="p in secondProviders" :key="p.id" type="button"
              class="w-full px-4 py-2 rounded-lg text-sm font-medium border border-slate-200 dark:border-slate-600 bg-white dark:bg-slate-700 text-slate-900 dark:text-white hover:bg-brand-50 dark:hover:bg-slate-600 transition-colors"
              :data-testid="`selfreg-second-${p.id}`"
              @click="continueAttribution(p)"
            >{{ t('selfreg.continueWith', { provider: p.name }) }}</button>
          </div>
        </template>
        <template v-else-if="verifiedEmail">
          <p class="text-sm text-slate-600 dark:text-slate-400 mb-4" data-testid="selfreg-verified">
            {{ t('selfreg.verifiedFor', { email: verifiedEmail, org: verifiedOrg ?? '' }) }}
          </p>
          <form @submit.prevent="complete">
            <label class="block text-xs font-medium text-slate-600 dark:text-slate-300 mb-1" for="selfreg-password">{{ t('selfreg.passwordLabel') }}</label>
            <input
              id="selfreg-password" v-model="password" type="password" required minlength="12"
              class="w-full px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-500"
              data-testid="selfreg-password"
            />
            <p class="mt-1 text-xs text-slate-400 dark:text-slate-500">{{ t('selfreg.passwordHint') }}</p>
            <button
              type="submit" :disabled="busy"
              class="mt-4 w-full px-4 py-2 rounded-lg text-sm font-medium bg-brand-600 text-white hover:bg-brand-700 transition-colors disabled:opacity-50"
              data-testid="selfreg-complete"
            >{{ busy ? t('selfreg.working') : t('selfreg.completeLabel') }}</button>
          </form>
        </template>
        <template v-else>
          <p v-if="!error" class="text-sm text-slate-600 dark:text-slate-400" data-testid="selfreg-proving">{{ t('selfreg.proving') }}</p>
        </template>
      </div>

      <!-- The attribution INTERSTITIAL: the why, then the choice. The
           page explains itself before it hands the applicant to an
           upstream login — the check proves a human, never an account. -->
      <div v-else-if="attribution" class="bg-white dark:bg-slate-800 rounded-xl border border-slate-200 dark:border-slate-700 p-6" data-testid="selfreg-attribution">
        <h2 class="text-lg font-serif font-bold text-slate-900 dark:text-white" data-testid="selfreg-attribution-title">{{ t('selfreg.attributionTitle') }}</h2>
        <p class="mt-3 text-sm text-slate-600 dark:text-slate-400" data-testid="selfreg-attribution-why">{{ t('selfreg.attributionWhy') }}</p>
        <p class="mt-3 text-sm rounded-lg border border-amber-200 dark:border-amber-800 bg-amber-50 dark:bg-amber-900/20 p-3 text-amber-800 dark:text-amber-200" data-testid="selfreg-attribution-note">{{ t('selfreg.attributionNote') }}</p>
        <p class="mt-4 text-sm font-medium text-slate-900 dark:text-white">{{ t('selfreg.attributionChoose') }}</p>
        <div class="mt-3 space-y-2">
          <button
            v-for="p in attribution" :key="p.id" type="button"
            class="w-full px-4 py-2 rounded-lg text-sm font-medium border border-slate-200 dark:border-slate-600 bg-white dark:bg-slate-700 text-slate-900 dark:text-white hover:bg-brand-50 dark:hover:bg-slate-600 transition-colors"
            :data-testid="`selfreg-attribution-${p.id}`"
            @click="continueAttribution(p)"
          >{{ t('selfreg.continueWith', { provider: p.name }) }}</button>
        </div>
        <button
          type="button"
          class="mt-4 w-full text-sm text-slate-500 dark:text-slate-400 hover:underline"
          data-testid="selfreg-attribution-back"
          @click="attribution = null"
        >{{ t('selfreg.backToForm') }}</button>
      </div>

      <!-- The start form (the pickers → the name → the work email →
           Turnstile → the attribution choice). -->
      <form v-else class="space-y-4" @submit.prevent="start">
        <div class="relative">
          <label class="block text-xs font-medium text-slate-600 dark:text-slate-300 mb-1" for="selfreg-country">{{ t('selfreg.countryLabel') }}</label>
          <input
            id="selfreg-country" v-model="countryQuery" type="text" role="combobox"
            :aria-expanded="countryOpen" autocomplete="off"
            :placeholder="t('selfreg.countryPlaceholder')"
            class="w-full px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-500"
            data-testid="selfreg-country"
            @focus="countryOpen = true"
            @input="countryOpen = true"
            @keydown="onCountryKeydown"
          />
          <ul
            v-if="countryOpen && countryMatches.length"
            class="absolute z-20 left-0 right-0 mt-1 max-h-60 overflow-y-auto rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 shadow-lg"
            data-testid="selfreg-country-options"
          >
            <li v-for="c in countryMatches" :key="c.country">
              <button
                type="button"
                :data-country="c.country"
                class="w-full text-left px-3 py-2 text-sm text-slate-900 dark:text-white hover:bg-brand-50 dark:hover:bg-slate-700"
                @click="pickCountry(c)"
              >{{ c.country }} — {{ c.country_fr }}</button>
            </li>
          </ul>
        </div>
        <div>
          <label class="block text-xs font-medium text-slate-600 dark:text-slate-300 mb-1" for="selfreg-org">{{ t('selfreg.orgLabel') }}</label>
          <select
            id="selfreg-org" v-model="org" required :disabled="!country"
            class="w-full px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white disabled:opacity-50"
            data-testid="selfreg-org"
          >
            <option value="" disabled>{{ t('selfreg.orgPlaceholder') }}</option>
            <option v-for="o in orgs" :key="o.name" :value="o.name">{{ o.name }}</option>
          </select>
          <p v-if="orgDomains.length" class="mt-1 text-xs text-slate-500 dark:text-slate-400" data-testid="selfreg-org-domains">
            {{ t('selfreg.orgDomains', { domains: orgDomains.join(', ') }) }}
          </p>
        </div>
        <div>
          <label class="block text-xs font-medium text-slate-600 dark:text-slate-300 mb-1" for="selfreg-name">{{ t('selfreg.nameLabel') }}</label>
          <input
            id="selfreg-name" v-model="name" type="text" required
            class="w-full px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white"
            data-testid="selfreg-name"
          />
        </div>
        <div>
          <label class="block text-xs font-medium text-slate-600 dark:text-slate-300 mb-1" for="selfreg-email">{{ t('selfreg.emailLabel') }}</label>
          <input
            id="selfreg-email" v-model="email" type="email" required
            class="w-full px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white"
            data-testid="selfreg-email"
          />
          <p class="mt-1 text-xs" :class="email && email.includes('@') ? (emailMatchesOrg ? 'text-green-600 dark:text-green-400' : 'text-amber-600 dark:text-amber-400') : 'text-slate-400 dark:text-slate-500'" :data-state="email && email.includes('@') ? (emailMatchesOrg ? 'match' : 'no-match') : undefined">
            {{ email && email.includes('@') ? (emailMatchesOrg ? t('selfreg.emailMatch') : t('selfreg.emailNoMatch', { domains: orgDomains.join(', ') })) : t('selfreg.emailHint') }}
          </p>
        </div>
        <TurnstileField v-if="turnstileSiteKey" ref="turnstileField" :site-key="turnstileSiteKey" />
        <button
          type="submit" :disabled="busy"
          class="w-full px-4 py-2 rounded-lg text-sm font-medium bg-brand-600 text-white hover:bg-brand-700 transition-colors disabled:opacity-50"
          data-testid="selfreg-submit"
        >{{ busy ? t('selfreg.working') : t('selfreg.submitLabel') }}</button>
        <p class="text-xs text-center text-slate-400 dark:text-slate-500">{{ t('selfreg.queueHint') }}
          <router-link to="/op/join" class="text-brand-600 dark:text-brand-300 hover:underline" data-testid="selfreg-join-link2">{{ t('selfreg.queueLink') }}</router-link>
        </p>
      </form>
    </div>
  </div>
</template>
