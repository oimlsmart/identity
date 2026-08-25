<script setup lang="ts">
// ═══════════════════════════════════════════════════════════════════
// "Request an account" (TODO.identity/10) — the OP's public,
// self-service join intake. The requester picks their organization FROM
// THE PARTICIPANTS REGISTER (the selector is fed by
// /api/op/organizations — REGISTERED orgs only, never a typed name) and
// asks for the role their work needs (the options are bounded by the
// org's kind — an IA's staff get ia_officer etc.). The request lands
// with the ORG's administrator — approval comes from the requester's
// own organization, never from BIML and never automatically.
//
// The "my organization is not listed" path names the org in free text
// and lands with BIML (the new-organizations queue): BIML verifies the
// participation (PD-03/PD-09), and the requester becomes the org's
// administrator once the org is registered.
//
// The MANUFACTURER path (TODO.register/01): "my organization
// manufactures measuring instruments". A manufacturer org is NOT an
// OIML-CS participant — its registry standing is DECLARED on
// self-registration (the founder's work email declares the domain
// hint), upgradeable to IA-endorsed by an issuing authority's
// confirmation. When the work email's domain matches an already
// registered manufacturer org's declared domain, the request JOINS it
// (its administrator decides); otherwise the org is created with the
// declared standing and the founder's administrator ask lands with
// BIML. The page says all of this honestly — the kind is the proof,
// never the claim.
// ═══════════════════════════════════════════════════════════════════
import { computed, onMounted, ref } from 'vue'
import BrandLogo from '../../components/BrandLogo.vue'
import { useBranding } from '../../branding'

interface SelectorOrg {
  id: string
  name: string
  shortName: string
  kind: 'issuing-authority' | 'test-laboratory' | 'utilizer' | 'associate'
  country: string
  roles: string[]
}

const { branding } = useBranding()

const loading = ref(true)
/** null while unknown; false when this instance is not the identity
 *  service (the feed 404s) — the page says so honestly. */
const served = ref<boolean | null>(null)
const orgs = ref<SelectorOrg[]>([])

const name = ref('')
const email = ref('')
const orgSearch = ref('')
const selectedOrgId = ref<string | null>(null)
const notListed = ref(false)
/** The TODO.register/01 manufacturer path. */
const manufacturer = ref(false)
const orgNameText = ref('')
const orgCountry = ref('')
const requestedRole = ref('')
const note = ref('')

const submitting = ref(false)
const error = ref<string | null>(null)
/** The success panel's copy once the request is filed. */
const filed = ref<{ queue: 'org' | 'biml' | 'manufacturer'; orgName: string; orgCreated?: boolean } | null>(null)

const KIND_LABELS: Record<SelectorOrg['kind'], string> = {
  'issuing-authority': 'Issuing Authority',
  'test-laboratory': 'Test Laboratory',
  utilizer: 'Utilizer',
  associate: 'Associate',
}

/** A one-line gloss per role id (the audience knows the vocabulary; the
 *  gloss disambiguates the NMI split). */
const ROLE_GLOSSES: Record<string, string> = {
  ia_officer: 'Issuing Authority officer — runs type evaluations end to end',
  case_officer: 'Case officer — reviews and dispatches, never the decision',
  certification_officer: 'Certification officer — the evaluation decision and issuance',
  signatory: 'Signatory — the report signature authority',
  tl_operator: 'Test laboratory operator — performs the dispatched tests',
  viewer: 'Read-only access — review certificates and reports',
  org_admin: 'Organization administrator — manages the organization’s people',
}

const selectedOrg = computed(() => orgs.value.find(o => o.id === selectedOrgId.value) ?? null)

/** The selector's visible options: the search box filters by name,
 *  short name, country and kind (registered orgs only — the feed never
 *  carries an unregistered one). */
const filteredOrgs = computed(() => {
  const q = orgSearch.value.trim().toLowerCase()
  if (!q) return orgs.value
  return orgs.value.filter(o =>
    o.name.toLowerCase().includes(q)
    || o.shortName.toLowerCase().includes(q)
    || o.country.toLowerCase().includes(q)
    || KIND_LABELS[o.kind].toLowerCase().includes(q),
  )
})

const roleOptions = computed(() => selectedOrg.value?.roles ?? [])

const canSubmit = computed(() => {
  if (submitting.value) return false
  if (!name.value.trim() || !email.value.includes('@')) return false
  if (manufacturer.value || notListed.value) return !!orgNameText.value.trim()
  return !!selectedOrg.value && !!requestedRole.value
})

function pickOrg(id: string) {
  selectedOrgId.value = id
  requestedRole.value = ''
}

/** The three intake paths are mutually exclusive (the register selector,
 *  the manufacturer path, the not-listed path). */
function setPath(path: 'register' | 'manufacturer' | 'not-listed') {
  notListed.value = path === 'not-listed'
  manufacturer.value = path === 'manufacturer'
  selectedOrgId.value = null
  requestedRole.value = ''
  error.value = null
}

async function submit() {
  if (!canSubmit.value) return
  submitting.value = true
  error.value = null
  try {
    const payload = manufacturer.value
      ? {
          name: name.value.trim(),
          email: email.value.trim(),
          org_kind: 'manufacturer',
          org_name_text: orgNameText.value.trim(),
          country: orgCountry.value.trim() || undefined,
          note: note.value.trim() || undefined,
        }
      : notListed.value
        ? {
            name: name.value.trim(),
            email: email.value.trim(),
            org_name_text: orgNameText.value.trim(),
            note: note.value.trim() || undefined,
          }
        : {
            name: name.value.trim(),
            email: email.value.trim(),
            org_id: selectedOrgId.value,
            requested_role: requestedRole.value,
            note: note.value.trim() || undefined,
          }
    const res = await fetch('/api/op/join-requests', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(payload),
    })
    if (!res.ok) {
      const body = await res.json().catch(() => ({})) as { error?: string }
      error.value = body.error ?? `The request could not be filed (${res.status}).`
      return
    }
    if (manufacturer.value) {
      const created = await res.json().catch(() => ({})) as { organization?: { name: string; created: boolean } }
      filed.value = {
        queue: 'manufacturer',
        orgName: created.organization?.name ?? orgNameText.value.trim(),
        orgCreated: created.organization?.created ?? false,
      }
    } else {
      filed.value = notListed.value
        ? { queue: 'biml', orgName: orgNameText.value.trim() }
        : { queue: 'org', orgName: selectedOrg.value?.name ?? 'your organization' }
    }
  } catch {
    error.value = 'Network error. Is the server running?'
  } finally {
    submitting.value = false
  }
}

onMounted(async () => {
  try {
    const res = await fetch('/api/op/organizations')
    if (res.status === 404) { served.value = false; return }
    if (!res.ok) throw new Error(String(res.status))
    orgs.value = await res.json() as SelectorOrg[]
    served.value = true
  } catch {
    served.value = false
  } finally {
    loading.value = false
  }
})
</script>

<template>
  <div class="min-h-screen flex items-center justify-center px-4 py-12 bg-cream dark:bg-slate-900">
    <div v-if="loading" class="flex flex-col items-center gap-4">
      <div class="w-8 h-8 border-2 border-brand-300 border-t-brand-600 rounded-full animate-spin" />
    </div>

    <div v-else class="w-full max-w-lg" data-testid="op-join">
      <div class="text-center mb-8">
        <BrandLogo kind="logo" class="h-10 mx-auto mb-4" />
        <h1 class="text-xl font-serif font-bold text-slate-900 dark:text-white">Request an account</h1>
        <p class="mt-2 text-sm text-slate-500 dark:text-slate-400">{{ branding.productName }}</p>
      </div>

      <!-- Not the identity service -->
      <div v-if="served === false" class="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 p-5">
        <p class="text-sm text-slate-700 dark:text-slate-300" data-testid="join-unavailable">
          This instance does not serve account requests. Accounts are issued by the OIML SMART
          identity service — your administrator will point you to it.
        </p>
      </div>

      <!-- Filed: the honest success state -->
      <div v-else-if="filed" class="rounded-lg border border-emerald-200 dark:border-emerald-800 bg-emerald-50 dark:bg-emerald-900/20 p-5" data-testid="join-success">
        <h2 class="text-sm font-semibold text-emerald-900 dark:text-emerald-200 mb-1">Your request is filed</h2>
        <p v-if="filed.queue === 'org'" class="text-sm text-emerald-800 dark:text-emerald-300">
          Your request is with <strong>{{ filed.orgName }}</strong>’s administrator. Approval comes from
          your organization — you will receive your invite when they approve it.
        </p>
        <p v-else-if="filed.queue === 'manufacturer' && filed.orgCreated" class="text-sm text-emerald-800 dark:text-emerald-300" data-testid="join-success-manufacturer-created">
          <strong>{{ filed.orgName }}</strong> is registered on the identity service with the
          <strong>declared</strong> manufacturer standing (not an OIML-CS participation). Your request to
          become its organization administrator is with the BIML secretariat — you will receive your
          invite once they approve it.
        </p>
        <p v-else-if="filed.queue === 'manufacturer'" class="text-sm text-emerald-800 dark:text-emerald-300" data-testid="join-success-manufacturer-join">
          Your work email’s domain matches <strong>{{ filed.orgName }}</strong>’s declared domain — your
          request to join it is with its administrator. Approval comes from your organization.
        </p>
        <p v-else class="text-sm text-emerald-800 dark:text-emerald-300">
          <strong>{{ filed.orgName }}</strong> is not on the participants register, so your request is with
          the BIML secretariat. They verify organizations joining the OIML-CS; once the participation is
          registered you become its organization administrator.
        </p>
      </div>

      <template v-else>
        <!-- The honest framing: approval comes from your organization -->
        <div class="mb-4 p-3 rounded-lg bg-brand-50 dark:bg-brand-900/20 border border-brand-200 dark:border-brand-800">
          <p class="text-sm text-brand-900 dark:text-brand-200" data-testid="join-framing">
            Accounts are issued per organization: your request goes to <strong>your organization’s
            administrator</strong>, who verifies and approves it. If your organization is not on the OIML-CS
            participants register yet, the BIML secretariat handles the request instead.
          </p>
        </div>

        <!-- Error -->
        <div v-if="error" class="mb-4 p-3 rounded-lg bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800">
          <p class="text-sm text-red-700 dark:text-red-300" data-testid="join-error">{{ error }}</p>
        </div>

        <form class="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 p-5 space-y-4" @submit.prevent="submit">
          <div>
            <label class="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1" for="join-name">Full name</label>
            <input
              id="join-name"
              v-model="name"
              type="text"
              required
              data-testid="join-name"
              class="w-full px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-500"
              placeholder="Dr. Jane Doe"
            />
          </div>
          <div>
            <label class="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1" for="join-email">Work email</label>
            <input
              id="join-email"
              v-model="email"
              type="email"
              required
              data-testid="join-email"
              class="w-full px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-500"
              placeholder="jane.doe@your-organization.example"
            />
          </div>

          <!-- The organization selector (the register, never a typed name) -->
          <div v-if="!notListed && !manufacturer">
            <label class="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1" for="join-org-search">Organization</label>
            <input
              id="join-org-search"
              v-model="orgSearch"
              type="text"
              data-testid="join-org-search"
              class="w-full px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-500"
              placeholder="Search the participants register…"
            />
            <ul v-if="filteredOrgs.length" class="mt-2 max-h-56 overflow-y-auto rounded-lg border border-slate-200 dark:border-slate-700 divide-y divide-slate-100 dark:divide-slate-700" data-testid="join-org-options">
              <li v-for="org in filteredOrgs" :key="org.id">
                <button
                  type="button"
                  :data-testid="`join-org-option-${org.id}`"
                  :aria-pressed="selectedOrgId === org.id"
                  class="w-full text-left px-3 py-2 text-sm transition-colors"
                  :class="selectedOrgId === org.id
                    ? 'bg-brand-50 dark:bg-brand-900/30 border-l-2 border-brand-500'
                    : 'bg-white dark:bg-slate-800 hover:bg-slate-50 dark:hover:bg-slate-700'"
                  @click="pickOrg(org.id)"
                >
                  <span class="font-medium text-slate-900 dark:text-white">{{ org.name }}</span>
                  <span class="block text-[11px] text-slate-400 dark:text-slate-500">{{ KIND_LABELS[org.kind] }}<template v-if="org.country"> · {{ org.country }}</template></span>
                </button>
              </li>
            </ul>
            <p v-else class="mt-2 text-xs text-slate-500 dark:text-slate-400" data-testid="join-org-empty">
              No registered organization matches — check the spelling, or use the “not listed” path below.
            </p>
            <p class="mt-2 text-xs text-slate-500 dark:text-slate-400">
              Only organizations on the OIML-CS participants register can be picked.
              <button type="button" class="text-brand-600 dark:text-brand-300 hover:underline" data-testid="join-manufacturer" @click="setPath('manufacturer')">
                My organization manufactures measuring instruments
              </button>
              ·
              <button type="button" class="text-brand-600 dark:text-brand-300 hover:underline" data-testid="join-not-listed" @click="setPath('not-listed')">
                My organization is not listed
              </button>
            </p>
          </div>

          <!-- The manufacturer path (TODO.register/01): the declared
               standing, honestly — never an OIML-CS participation. -->
          <div v-else-if="manufacturer">
            <label class="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1" for="join-mfr-name">Your organization’s name</label>
            <input
              id="join-mfr-name"
              v-model="orgNameText"
              type="text"
              required
              data-testid="join-mfr-name"
              class="w-full px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-500"
              placeholder="e.g. ACME Measuring Instruments"
            />
            <label class="block text-xs font-medium text-slate-700 dark:text-slate-300 mt-3 mb-1" for="join-mfr-country">
              Country <span class="text-slate-400">(optional)</span>
            </label>
            <input
              id="join-mfr-country"
              v-model="orgCountry"
              type="text"
              data-testid="join-mfr-country"
              class="w-full px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-500"
              placeholder="e.g. Example Member State"
            />
            <p class="mt-2 text-xs text-slate-500 dark:text-slate-400" data-testid="join-mfr-note">
              Your organization is registered with the <strong>declared</strong> manufacturer standing — a
              manufacturer is <strong>not an OIML-CS participant</strong> (no peer assessment, no scope).
              An Issuing Authority you applied to can endorse the relationship, upgrading the standing to
              <strong>IA-endorsed</strong>. If your work email’s domain matches an already-registered
              manufacturer organization, your request goes to its administrator to join it; otherwise the
              organization is created and you become its administrator once the BIML secretariat confirms
              the founding.
              <button type="button" class="text-brand-600 dark:text-brand-300 hover:underline" data-testid="join-mfr-back" @click="setPath('register')">
                Pick from the register instead
              </button>
            </p>
          </div>

          <!-- The not-listed path (BIML's queue) -->
          <div v-else>
            <label class="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1" for="join-org-name-text">Your organization’s name</label>
            <input
              id="join-org-name-text"
              v-model="orgNameText"
              type="text"
              required
              data-testid="join-org-name-text"
              class="w-full px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-500"
              placeholder="e.g. National Metrology Institute of …"
            />
            <p class="mt-2 text-xs text-slate-500 dark:text-slate-400" data-testid="join-not-listed-note">
              Your request goes to the <strong>BIML secretariat</strong>: they verify organizations joining
              the OIML-CS (the participation procedures PD-03/PD-09). Once your organization is registered,
              you become its organization administrator.
              <button type="button" class="text-brand-600 dark:text-brand-300 hover:underline" data-testid="join-listed" @click="setPath('register')">
                Pick from the register instead
              </button>
            </p>
          </div>

          <!-- The role asked for (bounded by the org's kind) -->
          <div v-if="!notListed && !manufacturer && selectedOrg">
            <label class="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1" for="join-role">Role you are asking for</label>
            <select
              id="join-role"
              v-model="requestedRole"
              required
              data-testid="join-role"
              class="w-full px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-500"
            >
              <option value="" disabled>Choose a role…</option>
              <option v-for="role in roleOptions" :key="role" :value="role" :data-testid="`join-role-option-${role}`">
                {{ role }} — {{ ROLE_GLOSSES[role] ?? role }}
              </option>
            </select>
            <p class="mt-1 text-[11px] text-slate-400 dark:text-slate-500">
              The options are bounded by the organization’s kind ({{ KIND_LABELS[selectedOrg.kind] }}); your
              administrator confirms the assignment.
            </p>
          </div>

          <div>
            <label class="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1" for="join-note">
              Note for the approver <span class="text-slate-400">(optional)</span>
            </label>
            <textarea
              id="join-note"
              v-model="note"
              rows="2"
              data-testid="join-note"
              class="w-full px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-500"
              placeholder="Anything that helps your administrator recognize the request (your team, your manager)."
            />
          </div>

          <button
            type="submit"
            :disabled="!canSubmit"
            data-testid="join-submit"
            class="w-full min-h-11 py-2 rounded-lg text-sm font-medium bg-brand-600 text-white hover:bg-brand-700 transition-colors disabled:opacity-50 flex items-center justify-center gap-2"
          >
            <div v-if="submitting" class="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
            {{ submitting ? 'Filing…' : 'Request the account' }}
          </button>
        </form>

        <p class="mt-4 text-center text-[10px] text-slate-400 dark:text-slate-500">
          Already have an account? <router-link to="/" class="text-brand-600 dark:text-brand-300 hover:underline" data-testid="join-signin">Sign in</router-link>
        </p>
      </template>
    </div>
  </div>
</template>
