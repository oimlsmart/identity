<script setup lang="ts">
// ═══════════════════════════════════════════════════════════════════
// The SSO home (the post-login landing; the spec: smart's
// TODO.identity-extract/02a "post-login landing") — the launcher at
// /op/home, on the Okta-dashboard / Entra-MyApps convention:
//
//   THE CARDS   one per service the signed-in account can enter (the
//               feed's honest computation, server/routes/op-home.ts):
//               the icon, the name, the one-line description, and the
//               launch (the service's sign-in start — the live OP
//               session lets them straight in). A service the account
//               cannot enter NEVER renders a working launch: the
//               'roles' posture hides it; the 'request' posture shows
//               the plain request-access state (the intake records the
//               ask on the audit chain — the registry's activity feed
//               carries it).
//   THE ACCOUNT the account-console entry (profile, sign-in methods,
//   MENU ENTRY  sessions, activity) — /op/account, native on this host.
//   THE ADMIN   /op/admin for admin/cs_admin only (the feed's flag —
//   AREA        the admin area stays a separate section, never mixed
//               into the user surfaces).
//
// The sign-in page at / stays the unauthenticated posture; a live
// session there redirects here (login.vue's skip). All copy rides the
// EN/FR catalogs (home.* namespace).
// ═══════════════════════════════════════════════════════════════════
import { onMounted, ref } from 'vue'
import PageHeader from '../components/PageHeader.vue'
import LaunchIcon from '../components/LaunchIcon.vue'
import { t } from '../i18n'

interface HomeService {
  clientId: string
  name: string
  description: string | null
  icon: string | null
  launchUrl?: string
  state: 'launch' | 'request'
  requested: boolean
}

interface HomeFeed {
  account: { id: string; name: string; email: string; avatarUrl: string | null; role: string }
  admin: boolean
  services: HomeService[]
}

const loading = ref(true)
const error = ref<string | null>(null)
const feed = ref<HomeFeed | null>(null)
/** The client id with a request in flight (the button's busy state). */
const requesting = ref<string | null>(null)
/** The one-line confirmation after a request lands (the card's own
 *  state already flipped; this names the record honestly). */
const requestNotice = ref<string | null>(null)

onMounted(async () => {
  try {
    const res = await fetch('/api/op/home', { credentials: 'include' })
    if (res.status === 401) {
      window.location.assign(`/?redirect=${encodeURIComponent('/op/home')}`)
      return
    }
    if (!res.ok) throw new Error(String(res.status))
    feed.value = await res.json() as HomeFeed
  } catch {
    error.value = t('home.loadError')
  } finally {
    loading.value = false
  }
})

/** The request-access act: the intake records it (idempotently), the
 *  card flips to the requested state. A refusal renders honestly. */
async function requestAccess(service: HomeService) {
  if (requesting.value) return
  requesting.value = service.clientId
  requestNotice.value = null
  try {
    const res = await fetch('/api/op/home/requests', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ client_id: service.clientId }),
    })
    if (res.ok) {
      service.requested = true
      requestNotice.value = t('home.requestSent')
    } else {
      const body = await res.json().catch(() => null) as { error?: string } | null
      error.value = body?.error ?? t('home.networkError')
    }
  } catch {
    error.value = t('home.networkError')
  } finally {
    requesting.value = null
  }
}
</script>

<template>
  <div class="max-w-5xl mx-auto px-6 py-10 w-full" data-testid="home">
    <div v-if="loading" class="flex flex-col items-center gap-4 py-24">
      <div class="w-8 h-8 border-2 border-brand-300 border-t-brand-600 rounded-full animate-spin" />
    </div>

    <template v-else-if="feed">
      <PageHeader :title="t('home.title')" :description="t('home.description')" />

      <div v-if="error" class="mb-4 p-3 rounded-lg bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800">
        <p class="text-sm text-red-700 dark:text-red-300" data-testid="home-error">{{ error }}</p>
      </div>
      <div v-if="requestNotice" class="mb-4 p-3 rounded-lg bg-emerald-50 dark:bg-emerald-900/20 border border-emerald-200 dark:border-emerald-800">
        <p class="text-sm text-emerald-800 dark:text-emerald-300" data-testid="home-request-notice">{{ requestNotice }}</p>
      </div>

      <!-- The launcher: one card per service the account can enter (or
           may ask to enter). -->
      <p v-if="!feed.services.length" class="text-sm text-slate-500 dark:text-slate-400" data-testid="home-empty">
        {{ t('home.empty') }}
      </p>
      <div v-else class="grid gap-4 sm:grid-cols-2 lg:grid-cols-3" data-testid="home-services">
        <template v-for="service in feed.services" :key="service.clientId">
          <!-- The launchable card: the whole card is the launch. -->
          <a
            v-if="service.state === 'launch'"
            :href="service.launchUrl"
            class="group rounded-xl border border-slate-200/80 dark:border-slate-700 bg-white dark:bg-slate-800 p-5 flex flex-col gap-3 hover:border-brand-300 dark:hover:border-brand-600 hover:shadow-md transition-all no-underline"
            :data-testid="`home-card-${service.clientId}`"
          >
            <span class="w-10 h-10 rounded-lg bg-brand-50 dark:bg-brand-900/40 text-brand-600 dark:text-brand-300 flex items-center justify-center">
              <LaunchIcon :name="service.icon" class="w-5 h-5" />
            </span>
            <span class="min-h-0">
              <span class="block text-sm font-semibold text-slate-900 dark:text-white">{{ service.name }}</span>
              <span v-if="service.description" class="mt-1 block text-xs text-slate-500 dark:text-slate-400 leading-relaxed">{{ service.description }}</span>
            </span>
            <span class="mt-auto flex items-center gap-1 text-xs font-medium text-brand-600 dark:text-brand-300 group-hover:underline">
              {{ t('home.launch') }}
              <LaunchIcon name="external" class="w-3.5 h-3.5" />
            </span>
          </a>

          <!-- The request-access state: no working launch, ever. -->
          <div
            v-else
            class="rounded-xl border border-dashed border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800/50 p-5 flex flex-col gap-3"
            :data-testid="`home-card-${service.clientId}`"
          >
            <span class="w-10 h-10 rounded-lg bg-slate-100 dark:bg-slate-700/60 text-slate-400 dark:text-slate-500 flex items-center justify-center">
              <LaunchIcon :name="service.icon" class="w-5 h-5" />
            </span>
            <span class="min-h-0">
              <span class="block text-sm font-semibold text-slate-700 dark:text-slate-300">{{ service.name }}</span>
              <span v-if="service.description" class="mt-1 block text-xs text-slate-500 dark:text-slate-400 leading-relaxed">{{ service.description }}</span>
            </span>
            <span class="mt-auto">
              <span class="block text-[11px] text-slate-400 dark:text-slate-500 mb-1.5">{{ t('home.noAccess') }}</span>
              <button
                type="button"
                :disabled="service.requested || requesting === service.clientId"
                class="text-xs font-medium rounded-md px-2.5 py-1.5 border transition-colors disabled:opacity-60"
                :class="service.requested
                  ? 'border-emerald-300 dark:border-emerald-700 text-emerald-700 dark:text-emerald-300 cursor-default'
                  : 'border-slate-300 dark:border-slate-600 text-slate-600 dark:text-slate-300 hover:border-brand-400 hover:text-brand-600 dark:hover:text-brand-300'"
                :data-testid="`home-request-${service.clientId}`"
                @click="requestAccess(service)"
              >{{ service.requested ? t('home.requested') : requesting === service.clientId ? t('home.requesting') : t('home.request') }}</button>
            </span>
          </div>
        </template>
      </div>

      <!-- The account menu entry + the admin area (a separate section,
           never mixed into the service cards). -->
      <section class="mt-10 grid gap-4 sm:grid-cols-2" data-testid="home-sections">
        <a
          href="/op/account"
          class="group rounded-xl border border-slate-200/80 dark:border-slate-700 bg-white dark:bg-slate-800 p-5 flex items-center gap-4 hover:border-brand-300 dark:hover:border-brand-600 hover:shadow-md transition-all no-underline"
          data-testid="home-account"
        >
          <span v-if="feed.account.avatarUrl" class="shrink-0">
            <img :src="feed.account.avatarUrl" :alt="feed.account.name" class="w-9 h-9 rounded-full object-cover border border-slate-200 dark:border-slate-700" />
          </span>
          <span v-else class="w-9 h-9 shrink-0 rounded-full bg-brand-100 dark:bg-brand-900/40 text-brand-700 dark:text-brand-200 flex items-center justify-center text-xs font-bold">
            {{ feed.account.name.charAt(0).toUpperCase() }}
          </span>
          <span class="min-w-0">
            <span class="block text-sm font-semibold text-slate-900 dark:text-white">{{ t('home.account.title') }}</span>
            <span class="block text-xs text-slate-500 dark:text-slate-400 truncate">{{ t('home.account.description') }}</span>
          </span>
          <span class="ml-auto text-slate-300 dark:text-slate-600 group-hover:text-brand-500 transition-colors" aria-hidden="true">→</span>
        </a>
        <a
          v-if="feed.admin"
          href="/op/admin"
          class="group rounded-xl border border-slate-200/80 dark:border-slate-700 bg-white dark:bg-slate-800 p-5 flex items-center gap-4 hover:border-brand-300 dark:hover:border-brand-600 hover:shadow-md transition-all no-underline"
          data-testid="home-admin"
        >
          <span class="w-9 h-9 shrink-0 rounded-lg bg-slate-100 dark:bg-slate-700 text-slate-500 dark:text-slate-300 flex items-center justify-center">
            <LaunchIcon name="grid" class="w-4.5 h-4.5" />
          </span>
          <span class="min-w-0">
            <span class="block text-sm font-semibold text-slate-900 dark:text-white">{{ t('home.admin.title') }}</span>
            <span class="block text-xs text-slate-500 dark:text-slate-400 truncate">{{ t('home.admin.description') }}</span>
          </span>
          <span class="ml-auto text-slate-300 dark:text-slate-600 group-hover:text-brand-500 transition-colors" aria-hidden="true">→</span>
        </a>
      </section>
    </template>

    <div v-else class="p-3 rounded-lg bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800">
      <p class="text-sm text-red-700 dark:text-red-300" data-testid="home-load-error">{{ error }}</p>
    </div>
  </div>
</template>
