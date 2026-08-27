<script setup lang="ts">
// ═══════════════════════════════════════════════════════════════════
// The relying-party console (TODO.identity/07 over TODO.identity/01's
// oidc_clients registry) — the federation's registered instances: their
// redirect URIs, their claims policy (which claims the ID token carries
// for that client), the enable/disable state, and the registration
// wizard. A confidential client's secret is GENERATED server-side and
// shown exactly ONCE (only its hash survives); the copy affordance is
// the handover.
//
// THE DEVICE CLASS (the machine cone — server/auth/op/device-clients.ts)
// renders HONESTLY: a device client is a non-human, per-device client
// (client_credentials only) — no launch card, no redirect URIs, no
// user-facing claims policy; the row carries the device badge and the
// bound device's line instead, and the form's device mode swaps the
// human-cone fieldsets for the device binding (the id, its org, the
// instrument model reference). The class is fixed at registration (the
// picker locks in edit mode); a device is always confidential (the
// secret is the device's credential — the re-key is the rotation).
//
// Every rule is SERVER-ENFORCED (routes/op.ts's registry surface); this
// page only renders what the API answers. The secret never appears in a
// list or detail response — the one showing is the registration's.
// ═══════════════════════════════════════════════════════════════════
import { onMounted, ref } from 'vue'
import PageHeader from '../../components/PageHeader.vue'
import { useBranding } from '../../branding'
import { t } from '../../i18n'

interface ClientRow {
  clientId: string
  name: string
  /** The machine cone: 'device' = the per-device, non-human class;
   *  'application' = the relying-party posture. */
  class: 'device' | 'application'
  /** The bound device (the device class only): the id (the token's
   *  sub), its org, the instrument model reference. */
  device: { id: string; org: string; instrument_model: string } | null
  redirectUris: string[]
  claimsPolicy: { claims: string[]; roles?: string[] } | null
  /** The SSO home's launch card (null = not on the launcher). */
  launch: { url: string; icon: string | null; description: string | null; visibility: 'roles' | 'request' | 'open' } | null
  confidential: boolean
  status: 'active' | 'disabled'
  createdAt: string
  createdBy: string | null
}

/** The per-client activity (TODO.identity-sso/01, surface 4): issuance
 *  per UTC day from the audit journal, the refusal count, the registry's
 *  own events. Merged into the registry rows by clientId. */
interface ClientActivity {
  clientId: string
  activity: {
    days: Array<{ date: string; issued: number }>
    totalIssued14d: number
    lastIssuedAt: string | null
    refusals14d: number
  }
  registryEvents: Array<{ at: string; action: string; by: string }>
}

const CLAIM_OPTIONS = ['roles', 'groups', 'org', 'picture']
/** The launcher card's named icon set (server/auth/op/launch.ts
 *  validates it at write; the launcher's LaunchIcon owns the glyphs). */
const LAUNCH_ICON_OPTIONS = ['grid', 'monitor', 'scale', 'flask', 'chat', 'external']
/** The not-admitted posture: 'roles' hides the card, 'request' shows
 *  the request-access state, 'open' never gates. */
const LAUNCH_VISIBILITY_OPTIONS = ['roles', 'request', 'open'] as const

const { branding } = useBranding()

const loading = ref(true)
const forbidden = ref(false)
const error = ref<string | null>(null)
const notice = ref<string | null>(null)
const rows = ref<ClientRow[]>([])
/** The per-client activity, keyed by clientId (null until the read
 *  lands; the strip then hides honestly). */
const activity = ref<Record<string, ClientActivity> | null>(null)
const saving = ref(false)
/** The role vocabulary for the claims policy's role allowlist
 *  (TODO.identity/03): the instance map's keys. */
const roleOptions = ref<string[]>([])
/** The organization registry's orgs (the device binding's org select —
 *  the token's org claim must name an org the OP knows; the server
 *  re-validates at write). */
const orgOptions = ref<Array<{ id: string; name: string }>>([])

// The form's working state (an empty form = the registration posture;
// picking a row's "Edit" fills it — the client_id locks, the rest is the
// upsert).
const form = ref({
  client_id: '',
  name: '',
  redirect_uris: '', // one exact URI per line
  claims: [] as string[],
  /** The role allowlist (only meaningful when a role claim is checked);
   *  EMPTY = unbounded (the policy does not bound the role set). */
  roles: [] as string[],
  confidential: true,
  /** The SSO home's launch card: off = the client never appears on the
   *  launcher (launch: null on save when a card was stored). */
  launchOn: false,
  launch_url: '',
  launch_description: '',
  launch_icon: 'external',
  launch_visibility: 'roles' as 'roles' | 'request' | 'open',
  /** The machine cone: ON registers the device class (fixed at
   *  registration — the picker locks in edit mode). */
  classDevice: false,
  device_id: '',
  device_org: '',
  device_model: '',
})
const editing = ref<string | null>(null)
/** The re-key decision in edit mode: off keeps the stored secret hash. */
const rekey = ref(false)

/** The generated secret, shown ONCE for the registration/re-key that
 *  produced it. Cleared on the next action. */
const lastSecret = ref<{ clientId: string; secret: string } | null>(null)

function resetForm() {
  editing.value = null
  rekey.value = false
  form.value = {
    client_id: '', name: '', redirect_uris: '', claims: [], roles: [], confidential: true,
    launchOn: false, launch_url: '', launch_description: '', launch_icon: 'external', launch_visibility: 'roles',
    classDevice: false, device_id: '', device_org: '', device_model: '',
  }
}

function editRow(row: ClientRow) {
  editing.value = row.clientId
  rekey.value = false
  lastSecret.value = null
  form.value = {
    client_id: row.clientId,
    name: row.name,
    redirect_uris: row.redirectUris.join('\n'),
    claims: [...(row.claimsPolicy?.claims ?? [])],
    roles: [...(row.claimsPolicy?.roles ?? [])],
    confidential: row.confidential,
    launchOn: !!row.launch,
    launch_url: row.launch?.url ?? '',
    launch_description: row.launch?.description ?? '',
    launch_icon: row.launch?.icon ?? 'external',
    launch_visibility: row.launch?.visibility ?? 'roles',
    classDevice: row.class === 'device',
    device_id: row.device?.id ?? '',
    device_org: row.device?.org ?? '',
    device_model: row.device?.instrument_model ?? '',
  }
}

async function api(path: string, init?: RequestInit): Promise<Response> {
  return fetch(path, {
    credentials: 'include',
    ...(init?.body ? { headers: { 'content-type': 'application/json' } } : {}),
    ...init,
  })
}

async function load(): Promise<void> {
  const res = await api('/api/op/clients')
  if (res.status === 401) {
    window.location.assign(`/?redirect=${encodeURIComponent('/op/admin/clients')}`)
    return
  }
  if (res.status === 403) {
    forbidden.value = true
    return
  }
  if (!res.ok) throw new Error(`the client registry failed (${res.status})`)
  rows.value = await res.json() as ClientRow[]
}

/** The activity read (the dashboard API): merged by clientId. A failure
 *  never blocks the registry itself — the strips just stay hidden. */
async function loadActivity(): Promise<void> {
  const res = await api('/api/op/dashboard/clients')
  if (!res.ok) return
  const body = await res.json() as { clients: ClientActivity[] }
  activity.value = Object.fromEntries(body.clients.map(row => [row.clientId, row]))
}

/** The strip's one-liner for a row. */
function activityLine(clientId: string): string {
  const a = activity.value?.[clientId]
  if (!a) return ''
  const issued = `${a.activity.totalIssued14d} token issuance(s) in 14 d`
  const last = a.activity.lastIssuedAt ? ` · last ${a.activity.lastIssuedAt.slice(0, 16).replace('T', ' ')}Z` : ' · none yet'
  const refused = a.activity.refusals14d ? ` · ${a.activity.refusals14d} token refusal(s)` : ''
  return issued + last + refused
}

/** The form's URI list, validated inline (persistent): every line must
 *  be an absolute URI. The device class skips this — it never carries
 *  redirect URIs (the server enforces it). */
const uriProblems = ref<string[]>([])
function validateUris(): string[] {
  if (form.value.classDevice) {
    uriProblems.value = []
    return []
  }
  const uris = form.value.redirect_uris.split('\n').map(u => u.trim()).filter(Boolean)
  const problems: string[] = []
  if (!uris.length) problems.push('At least one redirect URI is required.')
  for (const uri of uris) {
    try { new URL(uri) } catch { problems.push(`Not an absolute URI: ${uri}`) }
  }
  uriProblems.value = problems
  return problems
}

/** The device binding's inline validation (the server re-validates at
 *  write — the org must resolve on the registry; this keeps the honest
 *  refusal next to the field). */
const deviceProblems = ref<string[]>([])
function validateDeviceForm(): string[] {
  const problems: string[] = []
  if (form.value.classDevice) {
    if (!form.value.device_id.trim()) problems.push(t('admin.clients.deviceIdRequired'))
    if (!form.value.device_org.trim()) problems.push(t('admin.clients.deviceOrgRequired'))
    if (!form.value.device_model.trim()) problems.push(t('admin.clients.deviceModelRequired'))
  }
  deviceProblems.value = problems
  return problems
}

/** The launch card's inline validation (the server re-validates at
 *  write; this keeps the honest refusal next to the field). */
const launchProblems = ref<string[]>([])
function validateLaunchForm(): string[] {
  const problems: string[] = []
  if (form.value.launchOn) {
    const url = form.value.launch_url.trim()
    if (!url) problems.push('The launch URL is required (the service’s sign-in start).')
    else {
      try {
        const parsed = new URL(url)
        if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') problems.push('The launch URL must be an http(s) URL.')
      } catch { problems.push(`Not an absolute URL: ${url}`) }
    }
  }
  launchProblems.value = problems
  return problems
}

async function save() {
  if (saving.value) return
  error.value = null
  notice.value = null
  lastSecret.value = null
  if (validateUris().length || validateLaunchForm().length || validateDeviceForm().length) return
  saving.value = true
  try {
    // The secret posture: a NEW confidential client (or a re-key) asks the
    // server to GENERATE the secret (shown once, in the response); an
    // edit without re-key keeps the stored hash; a switch to public makes
    // the client secret-less. The DEVICE class is always confidential (the
    // secret is the device's credential) — never the public switch.
    const wantsSecret = (form.value.confidential || form.value.classDevice) && (!editing.value || rekey.value)
    const payload: Record<string, unknown> = form.value.classDevice
      ? {
          // The machine cone: the class + the device binding; never
          // redirect URIs, never a claims policy, never a launch card
          // (the server refuses them on the class — honestly).
          client_id: form.value.client_id.trim(),
          name: form.value.name.trim(),
          class: 'device',
          device: {
            id: form.value.device_id.trim(),
            org: form.value.device_org.trim(),
            instrument_model: form.value.device_model.trim(),
          },
        }
      : {
          client_id: form.value.client_id.trim(),
          name: form.value.name.trim(),
          redirect_uris: form.value.redirect_uris.split('\n').map(u => u.trim()).filter(Boolean),
          // The role allowlist rides along only when a role claim is checked
          // and the set is non-empty; otherwise the policy does not bound the
          // role set (TODO.identity/03's semantics).
          claims_policy: {
            claims: form.value.claims,
            ...(form.value.claims.includes('roles') || form.value.claims.includes('groups')
              ? (form.value.roles.length ? { roles: form.value.roles } : {})
              : {}),
          },
        }
    // The launch card: on = the card as declared; an edit with the card
    // off takes the client OFF the launcher (null — idempotent); a fresh
    // registration with the card off omits the field (the row defaults
    // off the launcher). The device class never carries one.
    if (!form.value.classDevice) {
      if (form.value.launchOn) {
        payload.launch = {
          url: form.value.launch_url.trim(),
          icon: form.value.launch_icon,
          ...(form.value.launch_description.trim() ? { description: form.value.launch_description.trim() } : {}),
          visibility: form.value.launch_visibility,
        }
      } else if (editing.value) {
        payload.launch = null
      }
    }
    if (wantsSecret) payload.generate_secret = true
    else if (!form.value.confidential && !form.value.classDevice) payload.secret = null
    const res = await api('/api/op/clients', { method: 'POST', body: JSON.stringify(payload) })
    const body = await res.json().catch(() => ({})) as { error?: string; secret?: string; clientId?: string }
    if (!res.ok) {
      error.value = body.error ?? `The save was refused (${res.status}).`
      return
    }
    if (body.secret) {
      lastSecret.value = { clientId: body.clientId ?? form.value.client_id.trim(), secret: body.secret }
      notice.value = editing.value
        ? `Re-keyed ${body.clientId} — the new secret is below, shown only now.`
        : `Registered ${body.clientId} — its secret is below, shown only now.`
    } else {
      notice.value = editing.value ? `${body.clientId} updated.` : `Registered ${body.clientId} (a public client — PKCE only).`
    }
    resetForm()
    await load()
  } catch {
    error.value = 'Network error. Is the server running?'
  } finally {
    saving.value = false
  }
}

async function toggle(row: ClientRow) {
  if (saving.value) return
  saving.value = true
  error.value = null
  notice.value = null
  try {
    const res = await api(`/api/op/clients/${encodeURIComponent(row.clientId)}/status`, {
      method: 'POST',
      body: JSON.stringify({ status: row.status === 'active' ? 'disabled' : 'active' }),
    })
    if (!res.ok) {
      const body = await res.json().catch(() => ({})) as { error?: string }
      error.value = body.error ?? `The toggle on ${row.clientId} was refused.`
      return
    }
    notice.value = row.status === 'active'
      ? `${row.clientId} disabled — authorize and token now refuse it; the rows are kept.`
      : `${row.clientId} enabled.`
    await load()
  } catch {
    error.value = 'Network error. Is the server running?'
  } finally {
    saving.value = false
  }
}

function copySecret() {
  if (lastSecret.value) void navigator.clipboard.writeText(lastSecret.value.secret)
}

onMounted(async () => {
  try {
    const session = await fetch('/api/auth/session', { credentials: 'include' })
    if (!session.ok) {
      window.location.assign(`/?redirect=${encodeURIComponent('/op/admin/clients')}`)
      return
    }
    const rolesRes = await api('/api/users/roles')
    if (rolesRes.ok) roleOptions.value = Object.keys(await rolesRes.json() as Record<string, string[]>)
    // The device binding's org select rides the organization registry
    // (the admin surface's own list — the server re-validates at write).
    const orgsRes = await api('/api/op/registry/orgs')
    if (orgsRes.ok) {
      orgOptions.value = (await orgsRes.json() as Array<{ id: string; name: string }>).map(o => ({ id: o.id, name: o.name }))
    }
    await load()
    void loadActivity()
  } catch (e) {
    error.value = (e as Error).message || 'Network error. Is the server running?'
  } finally {
    loading.value = false
  }
})
</script>

<template>
  <div class="max-w-3xl mx-auto px-6 py-10 w-full">
    <div v-if="loading" class="flex flex-col items-center gap-4 py-24">
      <div class="w-8 h-8 border-2 border-brand-300 border-t-brand-600 rounded-full animate-spin" />
    </div>

    <div v-else-if="forbidden" class="max-w-md mx-auto py-16">
      <div class="text-center mb-8">
        <h1 class="text-xl font-serif font-bold text-slate-900 dark:text-white">Relying parties</h1>
      </div>
      <div class="p-3 rounded-lg bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800">
        <p class="text-sm text-amber-800 dark:text-amber-300" data-testid="op-clients-forbidden">
          The relying-party registry is an administrator surface — your account does not hold the administrator role.
        </p>
      </div>
    </div>

    <div v-else data-testid="op-clients">
      <PageHeader
        title="Relying parties"
        :description="`The instances that may ask ${branding.productName} to sign their users in (the OIDC client registry).`"
      />

      <div v-if="error" class="mb-4 p-3 rounded-lg bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800">
        <p class="text-sm text-red-700 dark:text-red-300" data-testid="op-clients-error">{{ error }}</p>
      </div>
      <div v-if="notice" class="mb-4 p-3 rounded-lg bg-emerald-50 dark:bg-emerald-900/20 border border-emerald-200 dark:border-emerald-800">
        <p class="text-sm text-emerald-800 dark:text-emerald-300" data-testid="op-clients-notice">{{ notice }}</p>
      </div>

      <!-- The generated secret, shown ONCE -->
      <div v-if="lastSecret" class="mb-4 p-4 rounded-lg border border-amber-300 dark:border-amber-700 bg-amber-50 dark:bg-amber-900/20" data-testid="op-client-secret-card">
        <p class="text-xs font-semibold text-amber-900 dark:text-amber-200 mb-1">
          The client secret for {{ lastSecret.clientId }} — shown only now
        </p>
        <div class="flex items-center gap-2">
          <code class="flex-1 text-[11px] font-mono bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded px-2 py-1.5 break-all text-slate-700 dark:text-slate-300" data-testid="op-client-secret">{{ lastSecret.secret }}</code>
          <button
            type="button"
            data-testid="op-client-secret-copy"
            class="shrink-0 px-3 py-1.5 text-xs font-semibold rounded-lg bg-brand-600 text-white hover:bg-brand-700 transition-colors"
            @click="copySecret"
          >Copy</button>
        </div>
        <p class="mt-1 text-[11px] text-slate-500 dark:text-slate-400">
          Store it as the instance’s OIDC client secret now. Only its hash is kept here; leaving this page loses it
          (a re-key mints a new one and retires the old).
        </p>
      </div>

      <!-- The registry -->
      <section class="rounded-xl border border-slate-200/80 dark:border-slate-700 bg-white dark:bg-slate-800 p-6 mb-6">
        <h2 class="text-xs font-semibold uppercase tracking-wider text-slate-400 dark:text-slate-500 mb-3">Registered instances</h2>
        <p v-if="!rows.length" class="text-sm text-slate-500 dark:text-slate-400" data-testid="op-clients-empty">
          No relying parties registered yet — register the first instance below.
        </p>
        <ul v-else class="space-y-3" data-testid="op-clients-list">
          <li v-for="row in rows" :key="row.clientId" class="rounded-lg border border-slate-200 dark:border-slate-700 px-3 py-3" :data-testid="`op-client-${row.clientId}`">
            <div class="flex items-start justify-between gap-3">
              <div class="min-w-0">
                <p class="text-sm font-medium text-slate-900 dark:text-white">
                  {{ row.name }}
                  <span v-if="row.class === 'device'" class="ml-1 text-[10px] px-1.5 py-0.5 rounded font-semibold bg-violet-100 dark:bg-violet-900/40 text-violet-700 dark:text-violet-300"
                    :data-testid="`op-client-class-${row.clientId}`">{{ t('admin.clients.deviceBadge') }}</span>
                  <span v-else class="ml-1 text-[10px] px-1.5 py-0.5 rounded font-semibold"
                    :class="row.confidential ? 'bg-slate-100 dark:bg-slate-700 text-slate-600 dark:text-slate-300' : 'bg-sky-100 dark:bg-sky-900/40 text-sky-700 dark:text-sky-300'"
                    :data-testid="`op-client-kind-${row.clientId}`">{{ row.confidential ? 'confidential' : 'public' }}</span>
                  <span v-if="row.status !== 'active'" class="ml-1 text-[10px] px-1.5 py-0.5 rounded bg-red-100 dark:bg-red-900/40 text-red-600 dark:text-red-400 font-semibold">disabled</span>
                </p>
                <!-- The device class's line: the bound device's claims (the
                     twin endpoints consume exactly these) — never the
                     human-cone metadata (no claims policy, no launch card,
                     no redirect URIs). -->
                <p v-if="row.device" class="text-[11px] text-slate-500 dark:text-slate-400" :data-testid="`op-client-device-${row.clientId}`">
                  {{ row.clientId }} · {{ t('admin.clients.deviceLine', { id: row.device.id, org: row.device.org, model: row.device.instrument_model }) }}
                  <template v-if="row.createdBy"> · registered by {{ row.createdBy }}</template>
                </p>
                <p v-else class="text-[11px] text-slate-400 dark:text-slate-500">
                  {{ row.clientId }}
                  · claims: {{ row.claimsPolicy?.claims.join(', ') || 'profile + email only' }}<template v-if="row.claimsPolicy?.roles?.length"> (roles limited to: {{ row.claimsPolicy.roles.join(', ') }})</template>
                  <template v-if="row.createdBy"> · registered by {{ row.createdBy }}</template>
                </p>
                <p v-if="row.class !== 'device'" class="text-[11px]" :class="row.launch ? 'text-slate-500 dark:text-slate-400' : 'text-slate-400 dark:text-slate-500'" :data-testid="`op-client-launch-${row.clientId}`">
                  <template v-if="row.launch">on the SSO home ({{ row.launch.visibility }}): {{ row.launch.url }}</template>
                  <template v-else>not on the SSO home</template>
                </p>
                <ul v-if="row.redirectUris.length" class="mt-1" :data-testid="`op-client-uris-${row.clientId}`">
                  <li v-for="uri in row.redirectUris" :key="uri" class="text-[11px] font-mono text-slate-500 dark:text-slate-400 truncate">{{ uri }}</li>
                </ul>
                <p v-if="activity?.[row.clientId]" class="mt-1 text-[11px] text-slate-400 dark:text-slate-500" :data-testid="`op-client-activity-${row.clientId}`">
                  {{ activityLine(row.clientId) }}
                </p>
              </div>
              <div class="flex items-center gap-2 shrink-0">
                <button
                  :data-testid="`op-client-toggle-${row.clientId}`"
                  class="text-xs font-medium rounded-md px-2 py-1 border transition-colors"
                  :class="row.status === 'active'
                    ? 'border-emerald-300 dark:border-emerald-700 text-emerald-700 dark:text-emerald-300'
                    : 'border-slate-200 dark:border-slate-600 text-slate-500 dark:text-slate-400'"
                  @click="toggle(row)"
                >{{ row.status === 'active' ? 'active' : 'disabled' }}</button>
                <button :data-testid="`op-client-edit-${row.clientId}`" class="text-xs font-medium text-brand-600 dark:text-brand-300 hover:underline" @click="editRow(row)">Edit</button>
              </div>
            </div>
          </li>
        </ul>
      </section>

      <!-- The registration wizard / the edit form -->
      <form class="rounded-xl border border-slate-200/80 dark:border-slate-700 bg-white dark:bg-slate-800 p-6 space-y-3" data-testid="op-client-form" @submit.prevent="save">
        <h2 class="text-xs font-semibold uppercase tracking-wider text-slate-400 dark:text-slate-500">
          {{ editing ? `Edit ${editing}` : 'Register an instance' }}
        </h2>
        <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
          <div>
            <label class="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">client id (slug, rides the OAuth parameters)</label>
            <input
              v-model="form.client_id"
              :disabled="!!editing"
              required
              data-testid="op-client-field-id"
              placeholder="tl-example"
              class="w-full px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white disabled:opacity-60"
            />
          </div>
          <div>
            <label class="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">name (the consent page shows it)</label>
            <input
              v-model="form.name"
              required
              data-testid="op-client-field-name"
              placeholder="Example test-laboratory instance"
              class="w-full px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white"
            />
          </div>
          <div class="sm:col-span-2">
            <label class="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">{{ t('admin.clients.classLegend') }}</label>
            <select
              :value="form.classDevice ? 'device' : 'application'"
              :disabled="!!editing"
              data-testid="op-client-field-class"
              class="w-full px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white disabled:opacity-60"
              @change="form.classDevice = ($event.target as HTMLSelectElement).value === 'device'"
            >
              <option value="application" data-testid="op-client-class-application">{{ t('admin.clients.classApp') }}</option>
              <option value="device" data-testid="op-client-class-device">{{ t('admin.clients.classDevice') }}</option>
            </select>
          </div>
          <!-- The machine cone's binding (the device class only): the id,
               the org, the instrument model reference — the claims the
               twin endpoints consume. -->
          <fieldset v-if="form.classDevice" class="sm:col-span-2" data-testid="op-client-field-device">
            <legend class="text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">{{ t('admin.clients.deviceLegend') }}</legend>
            <div class="grid grid-cols-1 sm:grid-cols-2 gap-2">
              <div>
                <label class="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">{{ t('admin.clients.deviceId') }}</label>
                <input
                  v-model="form.device_id"
                  data-testid="op-client-field-device-id"
                  placeholder="acme-lc500-sn-0001"
                  class="w-full px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm font-mono text-slate-900 dark:text-white"
                  @blur="validateDeviceForm"
                  @input="validateDeviceForm"
                />
              </div>
              <div>
                <label class="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">{{ t('admin.clients.deviceOrg') }}</label>
                <select
                  v-model="form.device_org"
                  data-testid="op-client-field-device-org"
                  class="w-full px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white"
                  @blur="validateDeviceForm"
                  @change="validateDeviceForm"
                >
                  <option value="" disabled>—</option>
                  <option v-for="org in orgOptions" :key="org.id" :value="org.id" :data-testid="`op-client-device-org-${org.id}`">{{ org.name }} ({{ org.id }})</option>
                  <!-- The honest edit edge: a stored binding whose org left
                       the registry still names it (the server decides the
                       re-write). -->
                  <option v-if="form.device_org && !orgOptions.some(o => o.id === form.device_org)" :value="form.device_org">{{ form.device_org }}</option>
                </select>
              </div>
              <div class="sm:col-span-2">
                <label class="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">{{ t('admin.clients.deviceModel') }}</label>
                <input
                  v-model="form.device_model"
                  data-testid="op-client-field-device-model"
                  placeholder="acme-lc500@2021"
                  class="w-full px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm font-mono text-slate-900 dark:text-white"
                  @blur="validateDeviceForm"
                  @input="validateDeviceForm"
                />
              </div>
            </div>
            <ul v-if="deviceProblems.length" class="mt-1 list-disc list-inside text-xs text-red-600 dark:text-red-400" data-testid="op-client-device-problems">
              <li v-for="problem in deviceProblems" :key="problem">{{ problem }}</li>
            </ul>
          </fieldset>
          <div v-if="!form.classDevice" class="sm:col-span-2">
            <label class="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">redirect URIs (exact, one per line — an unregistered one is refused, never redirected to)</label>
            <textarea
              v-model="form.redirect_uris"
              rows="3"
              required
              data-testid="op-client-field-uris"
              placeholder="https://tl.example.org/api/auth/callback/oidc"
              class="w-full px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm font-mono text-slate-900 dark:text-white"
              @blur="validateUris"
              @input="validateUris"
            />
            <ul v-if="uriProblems.length" class="mt-1 list-disc list-inside text-xs text-red-600 dark:text-red-400" data-testid="op-client-uri-problems">
              <li v-for="problem in uriProblems" :key="problem">{{ problem }}</li>
            </ul>
          </div>
          <fieldset v-if="!form.classDevice" class="sm:col-span-2">
            <legend class="text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">claims policy (the claims this instance’s ID tokens may carry)</legend>
            <div class="flex flex-wrap gap-x-4 gap-y-1" data-testid="op-client-field-claims">
              <label v-for="claim in CLAIM_OPTIONS" :key="claim" class="flex items-center gap-1.5 text-sm text-slate-700 dark:text-slate-300">
                <input v-model="form.claims" type="checkbox" :value="claim" :data-testid="`op-client-claim-${claim}`" class="rounded border-slate-300" />
                {{ claim }}
              </label>
            </div>
            <p class="mt-1 text-[11px] text-slate-400 dark:text-slate-500">
              With no claim checked the ID token carries the profile and email only — role claims are a per-client privilege.
            </p>
            <!-- The role allowlist (TODO.identity/03): bounds WHICH roles
                 the emitted claims may hold. Only meaningful when a role
                 claim is on; empty = unbounded. -->
            <div v-if="form.claims.includes('roles') || form.claims.includes('groups')" class="mt-2" data-testid="op-client-field-role-allowlist">
              <p class="text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">role allowlist (empty = the policy does not bound the role set)</p>
              <div class="flex flex-wrap gap-x-4 gap-y-1">
                <label v-for="r in roleOptions" :key="r" class="flex items-center gap-1.5 text-sm text-slate-700 dark:text-slate-300">
                  <input v-model="form.roles" type="checkbox" :value="r" :data-testid="`op-client-role-${r}`" class="rounded border-slate-300" />
                  {{ r }}
                </label>
              </div>
            </div>
          </fieldset>
          <fieldset v-if="!form.classDevice" class="sm:col-span-2">
            <legend class="text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">SSO home (the launcher card a signed-in account meets after sign-in)</legend>
            <label class="flex items-center gap-2 text-sm text-slate-700 dark:text-slate-300">
              <input v-model="form.launchOn" type="checkbox" data-testid="op-client-field-launch-on" class="rounded border-slate-300" />
              On the SSO home (the post-login launcher)
            </label>
            <div v-if="form.launchOn" class="mt-2 space-y-2" data-testid="op-client-field-launch">
              <div class="grid grid-cols-1 sm:grid-cols-2 gap-2">
                <div class="sm:col-span-2">
                  <label class="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">launch URL (the service’s sign-in start — the live OP session lets the user straight in)</label>
                  <input
                    v-model="form.launch_url"
                    data-testid="op-client-field-launch-url"
                    placeholder="https://tl.example.org/api/auth/signin/oidc"
                    class="w-full px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm font-mono text-slate-900 dark:text-white"
                    @blur="validateLaunchForm"
                    @input="validateLaunchForm"
                  />
                </div>
                <div class="sm:col-span-2">
                  <label class="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">description (one line on the card; optional)</label>
                  <input
                    v-model="form.launch_description"
                    data-testid="op-client-field-launch-description"
                    placeholder="The certification hub: applications, cases, certificates."
                    class="w-full px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white"
                  />
                </div>
                <div>
                  <label class="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">icon</label>
                  <select v-model="form.launch_icon" data-testid="op-client-field-launch-icon" class="w-full px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white">
                    <option v-for="icon in LAUNCH_ICON_OPTIONS" :key="icon" :value="icon">{{ icon }}</option>
                  </select>
                </div>
                <div>
                  <label class="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">visibility (when the account’s roles do not admit it)</label>
                  <select v-model="form.launch_visibility" data-testid="op-client-field-launch-visibility" class="w-full px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white">
                    <option v-for="v in LAUNCH_VISIBILITY_OPTIONS" :key="v" :value="v">{{ v }}</option>
                  </select>
                  <p class="mt-1 text-[11px] text-slate-400 dark:text-slate-500">
                    roles: the card hides. request: the card shows a plain request-access state. open: no gate, every signed-in account launches.
                  </p>
                </div>
              </div>
              <ul v-if="launchProblems.length" class="list-disc list-inside text-xs text-red-600 dark:text-red-400" data-testid="op-client-launch-problems">
                <li v-for="problem in launchProblems" :key="problem">{{ problem }}</li>
              </ul>
            </div>
          </fieldset>
          <div class="sm:col-span-2 space-y-1">
            <!-- The device class is ALWAYS confidential (the secret is the
                 device's credential) — the toggle never offers a public
                 device; the note states the rule honestly. -->
            <p v-if="form.classDevice" class="text-sm text-slate-700 dark:text-slate-300" data-testid="op-client-field-device-confidential">
              {{ t('admin.clients.deviceSecretNote') }}
            </p>
            <label v-else class="flex items-center gap-2 text-sm text-slate-700 dark:text-slate-300">
              <input v-model="form.confidential" type="checkbox" data-testid="op-client-field-confidential" class="rounded border-slate-300" />
              Confidential client (holds a secret; the server generates it and shows it once)
            </label>
            <label v-if="editing && (form.confidential || form.classDevice)" class="flex items-center gap-2 text-sm text-slate-700 dark:text-slate-300">
              <input v-model="rekey" type="checkbox" data-testid="op-client-field-rekey" class="rounded border-slate-300" />
              Re-key: generate a new secret (the old one stops working at once)
            </label>
          </div>
        </div>
        <div class="flex items-center gap-3">
          <button
            type="submit"
            :disabled="saving"
            data-testid="op-client-save"
            class="py-2 px-4 rounded-lg text-sm font-medium bg-brand-600 text-white hover:bg-brand-700 transition-colors disabled:opacity-50"
          >{{ saving ? 'Saving…' : editing ? 'Save changes' : 'Register the instance' }}</button>
          <button v-if="editing" type="button" class="text-sm text-slate-500 hover:underline" data-testid="op-client-cancel" @click="resetForm">Cancel edit</button>
        </div>
      </form>
    </div>
  </div>
</template>
