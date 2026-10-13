<script setup lang="ts">
// ═══════════════════════════════════════════════════════════════════
// "Request an account" (TODO.identity/10) — the OP's public,
// self-service join intake, led by THE QUESTION (2026-10-13): before
// any form, the page asks what best describes you — six doors, and the
// answer dictates the form:
//
//   An OIML-CS Issuing Authority        → the register, IA orgs only
//   An OIML-CS Test Laboratory          → the register, TL orgs only
//   An OIML Member (Member State or     → the register, member orgs
//     Corresponding Member)               (the four member kinds)
//   A manufacturer of measuring         → the manufacturer path
//     instruments                         (TODO.register/01: the
//                                         DECLARED standing, never a
//                                         participant)
//   I work for the OIML/BIML            → the BIML door: an @oiml.org
//                                         address, the one-time setup
//                                         link proves the mailbox, no
//                                         queue
//   Others                              → the not-listed path (BIML's
//                                         new-organizations queue,
//                                         PD-03/PD-09)
//
// The register door forms pick the organization FROM THE PARTICIPANTS
// REGISTER (the selector is fed by /api/op/organizations — REGISTERED
// orgs only, never a typed name) and ask for the role the org's kind
// bounds (an IA's staff get ia_officer etc.). The request lands with
// the ORG's administrator — approval comes from the requester's own
// organization, never from BIML and never automatically. The
// manufacturer and Others doors keep their own honest copy. The BIML
// door's account is minted UNREACHABLE (the invite posture) into the
// operator's own org with the floor role — the link is the decision;
// the admins promote from there.
// ═══════════════════════════════════════════════════════════════════
import { computed, onMounted, ref } from 'vue'
import BrandLogo from '../../components/BrandLogo.vue'
import TurnstileField from '../../components/TurnstileField.vue'
import { fetchTurnstileSiteKey } from '../../components/turnstile'
import { useBranding } from '../../branding'
import { t } from '../../i18n'
import { orgKindLabelKey, orgRoleGlossKey } from '../../org-vocabulary'

type JoinDoor = 'ia' | 'tl' | 'member' | 'manufacturer' | 'biml' | 'others'
/** The registry-domain door is a HANDOFF, not a form: it routes to the
 *  member-registry verification flow (/op/self-register — eligibility →
 *  attribution → the emailed proof → setup; no queue when the domain
 *  matches). It renders as the seventh card. */

interface SelectorOrg {
  id: string
  name: string
  shortName: string
  kind: 'member-state' | 'corresponding-member' | 'issuing-authority' | 'test-laboratory' | 'utilizer' | 'associate'
  country: string
  roles: string[]
  email_domains: string[] | null
}

interface DoorDef {
  key: JoinDoor
  title: string
  blurb: string
}

const DOORS: ReadonlyArray<DoorDef> = [
  { key: 'ia', title: 'An OIML-CS Issuing Authority', blurb: 'Your authority issues OIML-CS certificates. Pick it from the register, then ask for your staff role.' },
  { key: 'tl', title: 'An OIML-CS Test Laboratory', blurb: 'Your laboratory tests measuring instruments for the OIML-CS. Pick it from the register, then ask for your staff role.' },
  { key: 'member', title: 'An OIML Member (Member State or Corresponding Member)', blurb: 'Your national body participates in the OIML. Its personnel join on the read/access posture.' },
  { key: 'manufacturer', title: 'A manufacturer of measuring instruments', blurb: 'Register your organization with the declared manufacturer standing — a manufacturer is not an OIML-CS participant.' },
  { key: 'biml', title: 'I work for the OIML/BIML', blurb: 'Bureau and OIML staff hold an @oiml.org address. The one-time setup link proves the mailbox — no waiting queue.' },
  { key: 'others', title: 'Others', blurb: 'None of these — name your organization and the BIML secretariat verifies the participation.' },
]

/** The register doors' picker filters (the org kinds each door offers).
 *  The manufacturer never picks from the register; the BIML and Others
 *  doors name no organization at all. */
const PICKER_KINDS: Partial<Record<JoinDoor, ReadonlyArray<string>>> = {
  ia: ['issuing-authority'],
  tl: ['test-laboratory'],
  member: ['member-state', 'corresponding-member', 'utilizer', 'associate'],
}

const { branding } = useBranding()

const loading = ref(true)
/** null while unknown; false when this instance is not the identity
 *  service (the feed 404s) — the page says so honestly. */
const served = ref<boolean | null>(null)
const orgs = ref<SelectorOrg[]>([])

/** THE QUESTION: null = the door step. */
const door = ref<JoinDoor | null>(null)

const givenName = ref('')
const familyName = ref('')
const email = ref('')
const orgSearch = ref('')
const selectedOrgId = ref<string | null>(null)
const orgNameText = ref('')
const orgCountry = ref('')
const requestedRole = ref('')
const note = ref('')

const submitting = ref(false)
const error = ref<string | null>(null)
// The bot gate's widget half — the field mounts only when armed.
const turnstileSiteKey = ref<string | null>(null)
const turnstileField = ref<InstanceType<typeof TurnstileField> | null>(null)
onMounted(async () => {
  turnstileSiteKey.value = await fetchTurnstileSiteKey()
})
/** The success panel's copy once the request is filed. 'biml-invite' is
 *  the BIML door's own posture (the link IS the decision — no queue). */
const filed = ref<{ queue: 'org' | 'biml' | 'manufacturer' | 'biml-invite'; orgName: string; orgCreated?: boolean; email?: string } | null>(null)

// The kind and role vocabulary rides the ONE shared module
// (TODO.restructure/07 — src/org-vocabulary.ts): the same labels and
// glosses the admin consoles render, EN/FR through the catalogs. The
// OIML Member category's personnel join on the read/access posture,
// never a workflow role; the glosses disambiguate the NMI split.
function kindLabel(kind: SelectorOrg['kind']): string {
  return t(orgKindLabelKey(kind))
}

function roleGloss(role: string): string {
  const key = orgRoleGlossKey(role)
  return key ? t(key) : role
}

const doorDef = computed(() => DOORS.find(d => d.key === door.value) ?? null)
const pickerKinds = computed(() => (door.value ? PICKER_KINDS[door.value] ?? null : null))
/** The picker's visible options: THIS door's kinds only. */
const doorOrgs = computed(() => {
  if (!pickerKinds.value) return []
  return orgs.value.filter(o => pickerKinds.value!.includes(o.kind))
})

const filteredOrgs = computed(() => {
  const q = orgSearch.value.trim().toLowerCase()
  if (!q) return doorOrgs.value
  return doorOrgs.value.filter(o =>
    o.name.toLowerCase().includes(q)
    || o.shortName.toLowerCase().includes(q)
    || o.country.toLowerCase().includes(q)
    || kindLabel(o.kind).toLowerCase().includes(q),
  )
})

const roleOptions = computed(() => selectedOrg.value?.roles ?? [])
const selectedOrg = computed(() => orgs.value.find(o => o.id === selectedOrgId.value) ?? null)

const canSubmit = computed(() => {
  if (submitting.value) return false
  if (!givenName.value.trim() || !familyName.value.trim() || !email.value.trim().includes('@')) return false
  if (door.value === 'manufacturer' || door.value === 'others') return !!orgNameText.value.trim()
  if (door.value === 'biml') return true
  return !!selectedOrg.value && !!requestedRole.value
})

function pickOrg(id: string) {
  selectedOrgId.value = id
  requestedRole.value = ''
}

/** The typed address against the picked org's pre-approved domains —
 *  tri-state: null = no data to compare (no notice). */
const orgDomains = computed(() => selectedOrg.value?.email_domains ?? null)
const emailDomain = computed(() => email.value.includes('@') ? email.value.split('@').pop()!.trim().toLowerCase() : '')
const domainMatch = computed<boolean | null>(() => {
  if (!orgDomains.value?.length || !emailDomain.value) return null
  return orgDomains.value.includes(emailDomain.value)
})

function pickDoor(key: JoinDoor) {
  door.value = key
  selectedOrgId.value = null
  requestedRole.value = ''
  orgSearch.value = ''
  error.value = null
}

function backToDoors() {
  door.value = null
  error.value = null
}

async function submit() {
  if (!canSubmit.value || !door.value) return
  submitting.value = true
  error.value = null
  try {
    let turnstileToken: string | undefined
    if (turnstileSiteKey.value) {
      turnstileToken = turnstileField.value?.getToken() ?? ''
      if (!turnstileToken) {
        error.value = 'Complete the verification challenge, then file the request again.'
        submitting.value = false
        return
      }
    }
    const shared = { given_name: givenName.value.trim(), family_name: familyName.value.trim(), email: email.value.trim(), note: note.value.trim() || undefined }
    const payload =
      door.value === 'manufacturer'
        ? { ...shared, org_kind: 'manufacturer', org_name_text: orgNameText.value.trim(), country: orgCountry.value.trim() || undefined }
        : door.value === 'biml'
          ? { ...shared, org_kind: 'biml' }
          : door.value === 'others'
            ? { ...shared, org_name_text: orgNameText.value.trim() }
            : { ...shared, org_id: selectedOrgId.value, requested_role: requestedRole.value }
    const res = await fetch('/api/op/join-requests', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ ...payload, ...(turnstileToken !== undefined ? { 'cf-turnstile-response': turnstileToken } : {}) }),
    })
    if (!res.ok) {
      turnstileField.value?.reset()
      const body = await res.json().catch(() => ({})) as { error?: string }
      error.value = body.error ?? `The request could not be filed (${res.status}).`
      return
    }
    if (door.value === 'manufacturer') {
      const created = await res.json().catch(() => ({})) as { organization?: { name: string; created: boolean } }
      filed.value = {
        queue: 'manufacturer',
        orgName: created.organization?.name ?? orgNameText.value.trim(),
        orgCreated: created.organization?.created ?? false,
      }
    } else if (door.value === 'biml') {
      const created = await res.json().catch(() => ({})) as { invited?: boolean; org?: string }
      filed.value = { queue: 'biml-invite', orgName: created.org ?? '', email: email.value.trim() }
    } else {
      filed.value = door.value === 'others'
        ? { queue: 'biml', orgName: orgNameText.value.trim() }
        : { queue: 'org', orgName: selectedOrg.value?.name ?? 'your organization' }
    }
  } catch {
    error.value = t('error.network')
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
        <p v-else-if="filed.queue === 'biml-invite'" class="text-sm text-emerald-800 dark:text-emerald-300" data-testid="join-success-biml-invite">
          Your setup link is on its way to <strong>{{ filed.email }}</strong> — it works once and stays
          valid for 24 hours. Until you complete it, the account cannot sign in: the link <em>is</em> the
          decision — the mailbox proof. No queue, no waiting. If the mail does not arrive, check the spam
          folder and file again.
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
        <!-- The honest framing: the answer decides where the request goes -->
        <div class="mb-4 p-3 rounded-lg bg-brand-50 dark:bg-brand-900/20 border border-brand-200 dark:border-brand-800">
          <p class="text-sm text-brand-900 dark:text-brand-200" data-testid="join-framing">
            Pick the description that matches you — it decides what the form asks and where the request
            goes: your <strong>organization’s administrator</strong>, the <strong>BIML secretariat</strong>,
            or (BIML and OIML staff) straight to your mailbox.
          </p>
        </div>

        <!-- Error -->
        <div v-if="error" class="mb-4 p-3 rounded-lg bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800">
          <p class="text-sm text-red-700 dark:text-red-300" data-testid="join-error">{{ error }}</p>
        </div>

        <!-- THE QUESTION: six doors + the registry handoff — the answer
             dictates the form -->
        <div v-if="!door" role="radiogroup" aria-label="What best describes you?" data-testid="join-doors">
          <h2 class="text-sm font-semibold text-slate-900 dark:text-white mb-3">What best describes you?</h2>
          <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <button
              v-for="d in DOORS"
              :key="d.key"
              type="button"
              role="radio"
              :aria-checked="false"
              :data-testid="`join-door-${d.key}`"
              class="text-left rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 p-4 hover:border-brand-500 dark:hover:border-brand-400 focus:outline-none focus:ring-2 focus:ring-brand-500 transition-colors"
              @click="pickDoor(d.key)"
            >
              <span class="block text-sm font-semibold text-slate-900 dark:text-white">{{ d.title }}</span>
              <span class="mt-1 block text-xs text-slate-500 dark:text-slate-400">{{ d.blurb }}</span>
            </button>
            <!-- The seventh card: the registry-domain HANDOFF (the
                 four-gate verification flow — no queue when the domain
                 matches). -->
            <router-link
              to="/op/self-register"
              data-testid="join-door-registry-domain"
              class="text-left rounded-lg border border-brand-200 dark:border-brand-800 bg-brand-50/50 dark:bg-brand-900/10 p-4 hover:border-brand-500 dark:hover:border-brand-400 focus:outline-none focus:ring-2 focus:ring-brand-500 transition-colors sm:col-span-2"
            >
              <span class="block text-sm font-semibold text-brand-800 dark:text-brand-200">My organization is in the OIML registry — verify with my work email</span>
              <span class="mt-1 block text-xs text-slate-500 dark:text-slate-400">The verified door: pick your country and organization from the OIML registry, prove your address — your account opens without a waiting queue when your email's domain matches.</span>
            </router-link>
          </div>
        </div>

        <!-- THE DOOR'S FORM -->
        <form v-else class="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 p-5 space-y-4" @submit.prevent="submit">
          <div>
            <button
              type="button"
              class="text-xs text-brand-600 dark:text-brand-300 hover:underline"
              data-testid="join-door-back"
              @click="backToDoors"
            >← Choose a different description</button>
            <h2 class="mt-1 text-sm font-semibold text-slate-900 dark:text-white" data-testid="join-door-title">{{ doorDef?.title }}</h2>
          </div>

          <div class="grid grid-cols-2 gap-3">
            <div>
              <label class="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1" for="join-given-name">Given names</label>
              <input
                id="join-given-name"
                v-model="givenName"
                type="text"
                required
                autocomplete="given-name"
                data-testid="join-given-name"
                class="w-full px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-500"
                placeholder="Jane"
              />
            </div>
            <div>
              <label class="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1" for="join-family-name">Family name</label>
              <input
                id="join-family-name"
                v-model="familyName"
                type="text"
                required
                autocomplete="family-name"
                data-testid="join-family-name"
                class="w-full px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-500"
                placeholder="Doe"
              />
            </div>
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
              :placeholder="door === 'biml' ? 'jane.doe@oiml.org' : 'jane.doe@your-organization.example'"
            />
          </div>

          <!-- The register doors: the organization selector (the register,
               never a typed name), THIS door's kinds only -->
          <div v-if="pickerKinds">
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
                  <span class="block text-[11px] text-slate-400 dark:text-slate-500">{{ kindLabel(org.kind) }}<template v-if="org.country"> · {{ org.country }}</template><template v-if="org.email_domains?.length"> · <span data-testid="join-org-domain">@{{ org.email_domains[0] }}</span></template></span>
                </button>
              </li>
            </ul>
            <p v-else class="mt-2 text-xs text-slate-500 dark:text-slate-400" data-testid="join-org-empty">
              No organization of this kind is on the register yet{{ orgSearch ? ' — check the spelling' : '' }}. If your organization should be here, use the “Others” door so the BIML secretariat can verify its participation.
            </p>
            <p v-if="!filteredOrgs.length" class="mt-2 text-xs">
              <button type="button" class="text-brand-600 dark:text-brand-300 hover:underline" data-testid="join-others-from-picker" @click="pickDoor('others')">
                My organization is none of these
              </button>
            </p>
          </div>

          <!-- The manufacturer door (TODO.register/01): the declared
               standing, honestly — never an OIML-CS participation. -->
          <div v-else-if="door === 'manufacturer'">
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
            </p>
          </div>

          <!-- The BIML door: the domain is the claim, the link is the proof -->
          <div v-else-if="door === 'biml'">
            <p class="text-xs text-slate-500 dark:text-slate-400" data-testid="join-biml-note">
              BIML and OIML staff hold an <strong>@oiml.org</strong> address. Filing here mints your account
              immediately and mails the one-time setup link to that address — the mailbox proof. The link
              works once and stays valid for 24 hours. The account starts with the floor role in the
              operator’s organization; the administrators grant more as your work requires.
            </p>
          </div>

          <!-- The Others door (BIML's new-organizations queue) -->
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
            </p>
          </div>

          <!-- THE PRE-APPROVED DOMAIN (0043): the picked org's verified
               domains, shown and honestly compared with the typed
               address. A mismatch never blocks — the request files and
               the deciding admin sees the same comparison. -->
          <div v-if="pickerKinds && selectedOrg && orgDomains?.length" class="text-xs rounded-lg p-3" :class="domainMatch === false ? 'bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800 text-amber-800 dark:text-amber-200' : 'bg-slate-50 dark:bg-slate-900/40 border border-slate-200 dark:border-slate-700 text-slate-600 dark:text-slate-300'" data-testid="join-domain-check">
            <p>
              <span class="font-medium">{{ selectedOrg.name }}</span>’s pre-approved domain{{ orgDomains.length > 1 ? 's' : '' }}:
              <span class="font-mono" data-testid="join-domain-list">{{ orgDomains.map(d => '@' + d).join(', ') }}</span>
            </p>
            <p v-if="domainMatch === true" class="mt-1 text-emerald-700 dark:text-emerald-300" data-testid="join-domain-match">
              ✓ your address is on the pre-approved domain — the request goes straight to your administrator.
            </p>
            <p v-else-if="domainMatch === false" class="mt-1" data-testid="join-domain-mismatch">
              Your address is <strong>not</strong> on the pre-approved domain — the request still files, and the administrator will verify your role in the organization before approving.
            </p>
          </div>

          <!-- The role asked for (the register doors, bounded by the org's kind) -->
          <div v-if="pickerKinds && selectedOrg">
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
                {{ role }} — {{ roleGloss(role) }}
              </option>
            </select>
            <p class="mt-1 text-[11px] text-slate-400 dark:text-slate-500">
              The options are bounded by the organization’s kind ({{ kindLabel(selectedOrg.kind) }}); your
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
              :placeholder="door === 'biml' ? 'Anything that helps the administrators recognize you (your team, your role at the Bureau).' : 'Anything that helps your administrator recognize the request (your team, your manager).'            "
            />
          </div>

          <TurnstileField v-if="turnstileSiteKey" ref="turnstileField" :site-key="turnstileSiteKey" />

          <button
            type="submit"
            :disabled="!canSubmit"
            data-testid="join-submit"
            class="w-full min-h-11 py-2 rounded-lg text-sm font-medium bg-brand-600 text-white hover:bg-brand-700 transition-colors disabled:opacity-50 flex items-center justify-center gap-2"
          >
            <div v-if="submitting" class="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
            {{ submitting ? 'Filing…' : (door === 'biml' ? 'Request my setup link' : 'Request the account') }}
          </button>
        </form>

        <p class="mt-4 text-center text-[10px] text-slate-400 dark:text-slate-500">
          Already have an account? <router-link to="/" class="text-brand-600 dark:text-brand-300 hover:underline" data-testid="join-signin">Sign in</router-link>
        </p>
      </template>
    </div>
  </div>
</template>
