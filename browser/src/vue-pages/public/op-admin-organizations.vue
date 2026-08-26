<script setup lang="ts">
// ═══════════════════════════════════════════════════════════════════
// The organization registry's surface (TODO.identity-features/05 —
// organizations as first-class citizens): the identity administrator's
// Organizations page. The LIST (every registry org with its active
// member count, its organization administrators, and its lifecycle
// state) and the ADD act (the stable slug id — the participant org's
// OIML code — the display data, the contacts, the optional
// participant_ref annotation). The org's own page (the members, the
// edit/disable/remove acts) is /op/admin/registry/orgs/:id.
//
// The audience is the identity administrator (admin/cs_admin — the
// server enforces it; routes/op-registry.ts). The org admin NEVER
// reaches another org here: the API's 403 is the only answer, and this
// page renders the honest refusal.
//
// Every rule is SERVER-ENFORCED; this page only renders what the API
// answers.
// ═══════════════════════════════════════════════════════════════════
import { onMounted, ref } from 'vue'
import PageHeader from '../../components/PageHeader.vue'
import { useBranding } from '../../branding'
import { t } from '../../i18n'

interface OrgRow {
  id: string
  name: string
  shortName: string | null
  kind: string | null
  country: string | null
  participantRef: string | null
  state: 'active' | 'disabled'
  /** The per-kind standing (TODO.register/01): 'participant' |
   *  'declared' | 'ia-endorsed' | 'non-participant'. */
  standing: string
  /** The active endorsing IA org ids (the manufacturer kind only). */
  endorsedBy: string[]
  members: { active: number; invited: number; disabled: number }
  admins: Array<{ userId: string; name: string; email: string | null }>
  createdAt: string
  updatedAt: string | null
  disabledAt: string | null
  disabledBy: string | null
}

const { branding } = useBranding()

const loading = ref(true)
const forbidden = ref(false)
const error = ref<string | null>(null)
const notice = ref<string | null>(null)
const account = ref<{ id: string; name: string; email: string } | null>(null)

const rows = ref<OrgRow[]>([])

// The add act's form. The id is the stable slug (the participant org's
// OIML code); kind '' = the non-participant org.
const addId = ref('')
const addName = ref('')
const addShortName = ref('')
const addKind = ref('')
const addCountry = ref('')
const addParticipantRef = ref('')
const addContacts = ref<Array<{ name: string; email: string }>>([{ name: '', email: '' }])
const adding = ref(false)

const KIND_OPTIONS = ['issuing-authority', 'test-laboratory', 'utilizer', 'associate', 'manufacturer'] as const

/** The honest per-kind standing line for the list (TODO.register/01):
 *  a manufacturer row says what it is (declared / IA-endorsed, never a
 *  participant); the other rows read as before. */
function standingSuffix(row: OrgRow): string {
  if (row.kind !== 'manufacturer') return ''
  return row.standing === 'ia-endorsed'
    ? ` · ${t('admin.orgs.standingIaEndorsed', { ias: row.endorsedBy.join(', ') })}`
    : ` · ${t('admin.orgs.standingDeclared')}`
}

async function api(path: string, init?: RequestInit): Promise<Response> {
  return fetch(path, {
    credentials: 'include',
    ...(init?.body ? { headers: { 'content-type': 'application/json' } } : {}),
    ...init,
  })
}

async function load(): Promise<void> {
  const res = await api('/api/op/registry/orgs')
  if (res.status === 401) {
    window.location.assign(`/?redirect=${encodeURIComponent('/op/admin/organizations')}`)
    return
  }
  if (res.status === 403) {
    forbidden.value = true
    return
  }
  if (!res.ok) throw new Error(`the organization registry failed (${res.status})`)
  rows.value = await res.json() as OrgRow[]
}

function addContactRow() {
  addContacts.value.push({ name: '', email: '' })
}

function removeContactRow(i: number) {
  addContacts.value.splice(i, 1)
}

async function addOrganization() {
  if (adding.value) return
  adding.value = true
  error.value = null
  notice.value = null
  try {
    const contacts = addContacts.value
      .map(ct => ({ name: ct.name.trim() || undefined, email: ct.email.trim() }))
      .filter(ct => ct.email)
    const res = await api('/api/op/registry/orgs', {
      method: 'POST',
      body: JSON.stringify({
        id: addId.value.trim(),
        name: addName.value.trim(),
        short_name: addShortName.value.trim() || null,
        kind: addKind.value || null,
        country: addCountry.value.trim() || null,
        participant_ref: addParticipantRef.value.trim() || null,
        contacts,
      }),
    })
    if (!res.ok) {
      const body = await res.json().catch(() => ({})) as { error?: string }
      error.value = body.error ?? t('admin.user.failed', { status: res.status })
      return
    }
    const created = await res.json() as OrgRow
    notice.value = t('admin.orgs.added', { name: created.name })
    addId.value = ''
    addName.value = ''
    addShortName.value = ''
    addKind.value = ''
    addCountry.value = ''
    addParticipantRef.value = ''
    addContacts.value = [{ name: '', email: '' }]
    await load()
  } catch {
    error.value = t('account.networkError')
  } finally {
    adding.value = false
  }
}

onMounted(async () => {
  try {
    const session = await fetch('/api/auth/session', { credentials: 'include' })
    if (!session.ok) {
      window.location.assign(`/?redirect=${encodeURIComponent('/op/admin/organizations')}`)
      return
    }
    account.value = await session.json() as { id: string; name: string; email: string }
    await load()
  } catch (e) {
    error.value = (e as Error).message || t('account.networkError')
  } finally {
    loading.value = false
  }
})
</script>

<template>
  <div class="max-w-5xl mx-auto px-6 py-10 w-full">
    <div v-if="loading" class="flex flex-col items-center gap-4 py-24">
      <div class="w-8 h-8 border-2 border-brand-300 border-t-brand-600 rounded-full animate-spin" />
    </div>

    <!-- The honest refusal (the API's 403) -->
    <div v-else-if="forbidden" class="max-w-md mx-auto py-16">
      <div class="text-center mb-8">
        <h1 class="text-xl font-serif font-bold text-slate-900 dark:text-white">{{ t('admin.orgs.title') }}</h1>
      </div>
      <div class="p-3 rounded-lg bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800">
        <p class="text-sm text-amber-800 dark:text-amber-300" data-testid="op-orgs-forbidden">{{ t('admin.orgs.forbidden') }}</p>
      </div>
    </div>

    <div v-else data-testid="op-orgs">
      <PageHeader :title="t('admin.orgs.title')">
        <template #description>
          <span data-testid="op-orgs-identity"><template v-if="account">{{ account.name }} &lt;{{ account.email }}&gt; — </template>{{ branding.productName }}</span>
          <p class="mt-1 text-xs text-slate-400 dark:text-slate-500">{{ t('admin.orgs.description') }}</p>
        </template>
      </PageHeader>

      <div v-if="error" class="mb-4 p-3 rounded-lg bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800">
        <p class="text-sm text-red-700 dark:text-red-300" data-testid="op-orgs-error">{{ error }}</p>
      </div>
      <div v-if="notice" class="mb-4 p-3 rounded-lg bg-emerald-50 dark:bg-emerald-900/20 border border-emerald-200 dark:border-emerald-800">
        <p class="text-sm text-emerald-800 dark:text-emerald-300" data-testid="op-orgs-notice">{{ notice }}</p>
      </div>

      <!-- The add act -->
      <section class="rounded-xl border border-slate-200/80 dark:border-slate-700 bg-white dark:bg-slate-800 p-6 mb-6" data-testid="op-orgs-add">
        <h2 class="text-xs font-semibold uppercase tracking-wider text-slate-400 dark:text-slate-500 mb-3">{{ t('admin.orgs.addTitle') }}</h2>
        <div class="grid grid-cols-1 sm:grid-cols-2 gap-2">
          <input
            v-model="addId"
            type="text"
            data-testid="op-orgs-add-id"
            class="px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-500"
            :placeholder="t('admin.orgs.field.id')"
          />
          <input
            v-model="addName"
            type="text"
            data-testid="op-orgs-add-name"
            class="px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-500"
            :placeholder="t('admin.orgs.field.name')"
          />
          <input
            v-model="addShortName"
            type="text"
            data-testid="op-orgs-add-short-name"
            class="px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-500"
            :placeholder="t('admin.orgs.field.shortName')"
          />
          <select
            v-model="addKind"
            data-testid="op-orgs-add-kind"
            class="px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-500"
          >
            <option value="">{{ t('admin.orgs.kindNone') }}</option>
            <option v-for="k in KIND_OPTIONS" :key="k" :value="k">{{ k }}</option>
          </select>
          <input
            v-model="addCountry"
            type="text"
            data-testid="op-orgs-add-country"
            class="px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-500"
            :placeholder="t('admin.orgs.field.country')"
          />
          <input
            v-model="addParticipantRef"
            type="text"
            data-testid="op-orgs-add-participant-ref"
            class="px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-500"
            :placeholder="t('admin.orgs.field.participantRef')"
          />
        </div>
        <div class="mt-3" data-testid="op-orgs-add-contacts">
          <p class="text-xs font-semibold text-slate-700 dark:text-slate-300 mb-2">{{ t('admin.orgs.field.contacts') }}</p>
          <div v-for="(contact, i) in addContacts" :key="i" class="flex flex-wrap sm:flex-nowrap items-center gap-2 mb-2" :data-testid="`op-orgs-add-contact-${i}`">
            <input
              v-model="contact.name"
              type="text"
              :data-testid="`op-orgs-add-contact-name-${i}`"
              class="flex-1 min-w-40 px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-500"
              :placeholder="t('admin.orgs.contactName')"
            />
            <input
              v-model="contact.email"
              type="email"
              :data-testid="`op-orgs-add-contact-email-${i}`"
              class="flex-1 min-w-40 px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-500"
              :placeholder="t('admin.orgs.contactEmail')"
            />
            <button
              v-if="addContacts.length > 1"
              type="button"
              :data-testid="`op-orgs-add-contact-remove-${i}`"
              class="shrink-0 text-xs text-red-600 dark:text-red-400 hover:underline"
              @click="removeContactRow(i)"
            >{{ t('admin.orgs.contactRemove') }}</button>
          </div>
          <button
            type="button"
            data-testid="op-orgs-add-contact-add"
            class="text-xs text-brand-600 dark:text-brand-300 hover:underline"
            @click="addContactRow"
          >+ {{ t('admin.orgs.contactAdd') }}</button>
        </div>
        <div class="mt-3 flex items-center gap-3">
          <button
            :disabled="adding || !addId.trim() || !addName.trim()"
            data-testid="op-orgs-add-submit"
            class="px-4 py-2 rounded-lg text-sm font-medium bg-brand-600 text-white hover:bg-brand-700 transition-colors disabled:opacity-50"
            @click="addOrganization"
          >{{ adding ? t('admin.orgs.addBusy') : t('admin.orgs.addSubmit') }}</button>
        </div>
        <p class="mt-2 text-[11px] text-slate-400 dark:text-slate-500">{{ t('admin.orgs.addNote') }}</p>
      </section>

      <!-- The list -->
      <section class="rounded-xl border border-slate-200/80 dark:border-slate-700 bg-white dark:bg-slate-800 p-6" data-testid="op-orgs-directory">
        <p v-if="!rows.length" class="text-sm text-slate-500 dark:text-slate-400" data-testid="op-orgs-empty">
          {{ t('admin.orgs.empty') }}
        </p>

        <div v-else class="overflow-x-auto">
          <table class="w-full text-sm" data-testid="op-orgs-list">
            <thead>
              <tr class="text-left text-[11px] uppercase tracking-wider text-slate-400 dark:text-slate-500 border-b border-slate-200 dark:border-slate-700">
                <th class="py-2 pr-3 font-semibold">{{ t('admin.orgs.colOrganization') }}</th>
                <th class="py-2 pr-3 font-semibold">{{ t('admin.orgs.colMembers') }}</th>
                <th class="py-2 pr-3 font-semibold">{{ t('admin.orgs.colAdmins') }}</th>
                <th class="py-2 pr-3 font-semibold">{{ t('admin.orgs.colState') }}</th>
                <th class="py-2 font-semibold"><span class="sr-only">{{ t('admin.orgs.open') }}</span></th>
              </tr>
            </thead>
            <tbody>
              <tr
                v-for="row in rows"
                :key="row.id"
                class="border-b border-slate-100 dark:border-slate-700/60 last:border-0"
                :data-testid="`op-orgs-row-${row.id}`"
              >
                <td class="py-2 pr-3">
                  <p class="font-medium text-slate-900 dark:text-white">
                    {{ row.name }}
                    <span class="ml-1 text-[11px] font-normal text-slate-400 dark:text-slate-500">{{ row.id }}</span>
                  </p>
                  <p class="text-[11px] text-slate-400 dark:text-slate-500" :data-testid="`op-orgs-kind-${row.id}`">
                    {{ row.kind ?? t('admin.orgs.kindNone') }}<template v-if="row.country"> · {{ row.country }}</template>
                    <template v-if="row.participantRef"> · ⛓ {{ row.participantRef }}</template>
                    {{ standingSuffix(row) }}
                  </p>
                </td>
                <td class="py-2 pr-3 text-xs text-slate-600 dark:text-slate-300" :data-testid="`op-orgs-members-${row.id}`">
                  {{ row.members.active }}
                  <span v-if="row.members.invited" class="text-amber-600 dark:text-amber-400">· {{ t('admin.orgs.membersInvited', { count: row.members.invited }) }}</span>
                  <span v-if="row.members.disabled" class="text-red-500 dark:text-red-400">· {{ t('admin.orgs.membersDisabled', { count: row.members.disabled }) }}</span>
                </td>
                <td class="py-2 pr-3 text-xs text-slate-600 dark:text-slate-300" :data-testid="`op-orgs-admins-${row.id}`">
                  <template v-if="row.admins.length">{{ row.admins.map(a => a.name).join(', ') }}</template>
                  <span v-else class="text-slate-400 dark:text-slate-500">{{ t('admin.orgs.noAdmins') }}</span>
                </td>
                <td class="py-2 pr-3 text-xs" :data-testid="`op-orgs-state-${row.id}`">
                  <span :class="row.state === 'active' ? 'text-emerald-600 dark:text-emerald-400' : 'text-red-500 dark:text-red-400'">
                    {{ row.state === 'active' ? t('admin.orgs.stateActive') : t('admin.orgs.stateDisabled') }}
                  </span>
                </td>
                <td class="py-2 text-right">
                  <router-link
                    :to="`/op/admin/registry/orgs/${row.id}`"
                    class="text-xs font-medium text-brand-600 dark:text-brand-300 hover:underline"
                    :data-testid="`op-orgs-open-${row.id}`"
                  >{{ t('admin.orgs.open') }}</router-link>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>
    </div>
  </div>
</template>
