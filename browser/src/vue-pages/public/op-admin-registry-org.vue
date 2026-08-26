<script setup lang="ts">
// ═══════════════════════════════════════════════════════════════════
// The registry's PER-ORG view (TODO.identity/11 — the multi-org
// membership model; TODO.identity-features/05 — the first-class org):
// one organization on the identity service's own registry with its
// MEMBERS (the memberships: the per-org role sets + the lifecycle
// states, the org_admins marked), its join-request queue (every state),
// the organization card (the display data + the participant link + the
// lifecycle stamps), the lifecycle ACTS (edit, disable/re-enable, the
// guarded remove), and the organization's own audit slice — the
// identity admin's membership acts (invite an existing account, edit
// the per-org roles, disable/re-activate — routes/op-memberships.ts
// enforces the bounds; routes/op-registry.ts enforces the org acts;
// this page only renders what the APIs answer).
//
// The audience is the identity administrator (admin/cs_admin — the
// registry console's gate). The org admin's own people console is
// /op/admin/users (the org-scoped grant).
// ═══════════════════════════════════════════════════════════════════
import { computed, onMounted, ref } from 'vue'
import { useRoute } from 'vue-router'
import PageHeader from '../../components/PageHeader.vue'
import { useBranding } from '../../branding'
import { t } from '../../i18n'

interface OrgInfo {
  id: string
  name: string
  shortName: string
  kind: string | null
  country: string
  contacts: Array<{ name: string | null; email: string }>
  participantRef: string | null
  state: 'active' | 'disabled'
  registered: boolean
  /** The per-kind standing (TODO.register/01). */
  standing: 'participant' | 'declared' | 'ia-endorsed' | 'non-participant'
  endorsedBy: string[]
  roles: string[]
  createdAt: string
  createdBy: string | null
  updatedAt: string | null
  updatedBy: string | null
  disabledAt: string | null
  disabledBy: string | null
}

/** The manufacturer standing's ACTIVE endorsement (TODO.register/01) —
 *  the endorsing IA with its display name resolved. */
interface EndorsementRow {
  iaOrgId: string
  iaName: string
  note: string | null
  createdAt: string
  createdBy: string | null
}

/** The org's signing key (TODO.trust-registry/01): the PUBLIC half + the
 *  custody chain (the administrator sees the actors; the public document
 *  carries the dates only). */
interface SigningKeyRow {
  kid: string
  label: string
  publicJwk: JsonWebKey & { kid?: string }
  createdAt: string
  createdBy: string | null
  rotatedAt: string | null
  rotatedBy: string | null
  successorKid: string | null
  revokedAt: string | null
  revokedBy: string | null
}

interface MemberRow {
  userId: string
  name: string
  email: string | null
  provider: string | null
  accountActive: boolean
  orgId: string
  roles: string[]
  state: 'invited' | 'active' | 'disabled'
  isPrimary: boolean
  invitedBy: string | null
  createdAt: string
  activatedAt: string | null
  disabledAt: string | null
  disabledBy: string | null
}

interface JoinRequestRow {
  id: string
  name: string
  email: string
  requestedRole: string
  note: string | null
  status: 'pending' | 'approved' | 'refused'
  decidedBy: string | null
  decidedAt: string | null
  refusalReason: string | null
  createdAt: string
}

interface OrgEvent {
  id: string
  timestamp: string
  action: string
  user_name?: string
  metadata?: Record<string, unknown>
}

interface OrgView {
  org: OrgInfo
  endorsements: EndorsementRow[]
  /** TODO.trust-registry/01: the org's signing keys (the custody chain
   *  whole — active, rotated, revoked). */
  signingKeys: SigningKeyRow[]
  members: MemberRow[]
  requests: JoinRequestRow[]
  activity: OrgEvent[]
}

const route = useRoute()
const { branding } = useBranding()
const orgId = computed(() => String(route.params.id ?? ''))

const loading = ref(true)
const forbidden = ref(false)
const notFound = ref(false)
const error = ref<string | null>(null)
const notice = ref<string | null>(null)
const acting = ref<string | null>(null)

const view = ref<OrgView | null>(null)

// The identity admin's acts.
const memberRolesOpen = ref<string | null>(null)
const memberRoleDrafts = ref<Record<string, string[]>>({})
const addEmail = ref('')
const addRoleChecks = ref<string[]>([])

// The org's own acts (TODO.identity-features/05): the edit form (the
// current values preloaded), the disable/re-enable confirmation, and
// the guarded remove.
const editOpen = ref(false)
const editName = ref('')
const editShortName = ref('')
const editKind = ref('')
const editCountry = ref('')
const editParticipantRef = ref('')
const editContacts = ref<Array<{ name: string; email: string }>>([])
const confirmDisable = ref(false)
const confirmRemove = ref(false)

// The signing-key acts (TODO.trust-registry/01): register (the label +
// the PUBLIC JWK), rotate (the successor), revoke (the terminal act —
// the row KEEPS its stamps; the at-the-time artifacts stay honest).
const keyLabel = ref('')
const keyJwk = ref('')
const keyRotateKid = ref<string | null>(null)
const keyRotateLabel = ref('')
const keyRotateJwk = ref('')
const keyRevokeKid = ref<string | null>(null)

/** The key status rendered honestly: the revocation stamps terminal,
 *  the rotation's overlap link, else active. */
function keyStatus(k: SigningKeyRow): string {
  if (k.revokedAt) return t('admin.org.keys.statusRevoked', { date: fmtDate(k.revokedAt), by: k.revokedBy ?? '—' })
  if (k.rotatedAt) return t('admin.org.keys.statusRotated', { date: fmtDate(k.rotatedAt), by: k.rotatedBy ?? '—', successor: k.successorKid ?? '—' })
  return t('admin.org.keys.statusActive')
}

/** The pasted public JWK, parsed honestly (the malformed JSON and the
 *  private-material leak refuse before the request flies). */
function parsePublicJwk(raw: string): JsonWebKey | { error: string } {
  let parsed: unknown
  try {
    parsed = JSON.parse(raw)
  } catch (e) {
    return { error: t('admin.org.keys.invalidJwk', { reason: (e as Error).message }) }
  }
  const j = parsed as Record<string, unknown>
  if (!j || typeof j !== 'object' || j.kty !== 'EC' || j.crv !== 'P-256' || typeof j.x !== 'string' || typeof j.y !== 'string') {
    return { error: t('admin.org.keys.invalidJwk', { reason: 'kty "EC", crv "P-256", x, y' }) }
  }
  if ('d' in j) return { error: t('admin.org.keys.privateRefusal') }
  return j as JsonWebKey
}

async function registerKey() {
  if (acting.value) return
  const jwk = parsePublicJwk(keyJwk.value)
  if ('error' in jwk && typeof jwk.error === 'string') { error.value = jwk.error; return }
  acting.value = 'key-register'
  error.value = null
  notice.value = null
  try {
    const res = await api('/api/op/org-keys', {
      method: 'POST',
      body: JSON.stringify({ org_id: orgId.value, label: keyLabel.value.trim(), public_jwk: jwk }),
    })
    if (!res.ok) {
      const body = await res.json().catch(() => ({})) as { error?: string }
      error.value = body.error ?? `The key registration failed (${res.status}).`
      return
    }
    notice.value = t('admin.org.keys.registered', { label: keyLabel.value.trim() })
    keyLabel.value = ''
    keyJwk.value = ''
    await load()
  } catch {
    error.value = t('account.networkError')
  } finally {
    acting.value = null
  }
}

async function rotateKey(k: SigningKeyRow) {
  if (acting.value) return
  const jwk = parsePublicJwk(keyRotateJwk.value)
  if ('error' in jwk && typeof jwk.error === 'string') { error.value = jwk.error; return }
  acting.value = `key-rotate-${k.kid}`
  error.value = null
  notice.value = null
  try {
    const res = await api(`/api/op/org-keys/${encodeURIComponent(orgId.value)}/${encodeURIComponent(k.kid)}/rotate`, {
      method: 'POST',
      body: JSON.stringify({ label: keyRotateLabel.value.trim(), public_jwk: jwk }),
    })
    if (!res.ok) {
      const body = await res.json().catch(() => ({})) as { error?: string }
      error.value = body.error ?? `The key rotation failed (${res.status}).`
      return
    }
    notice.value = t('admin.org.keys.rotated', { label: keyRotateLabel.value.trim() })
    keyRotateKid.value = null
    keyRotateLabel.value = ''
    keyRotateJwk.value = ''
    await load()
  } catch {
    error.value = t('account.networkError')
  } finally {
    acting.value = null
  }
}

async function revokeKey(k: SigningKeyRow) {
  if (acting.value) return
  acting.value = `key-revoke-${k.kid}`
  error.value = null
  notice.value = null
  try {
    const res = await api(`/api/op/org-keys/${encodeURIComponent(orgId.value)}/${encodeURIComponent(k.kid)}/revoke`, { method: 'POST' })
    if (!res.ok) {
      const body = await res.json().catch(() => ({})) as { error?: string }
      error.value = body.error ?? `The key revocation failed (${res.status}).`
      keyRevokeKid.value = null
      return
    }
    notice.value = t('admin.org.keys.revoked', { label: k.label })
    keyRevokeKid.value = null
    await load()
  } catch {
    error.value = t('account.networkError')
  } finally {
    acting.value = null
  }
}

const KIND_OPTIONS = ['issuing-authority', 'test-laboratory', 'utilizer', 'associate', 'manufacturer'] as const

/** The per-kind standing rendered honestly (TODO.register/01): the
 *  scheme's registration for a participant kind; the declared /
 *  IA-endorsed manufacturer standing (NEVER a participation); the plain
 *  non-participant. */
const standingText = computed(() => {
  const org = view.value?.org
  if (!org) return ''
  switch (org.standing) {
    case 'participant': return t('admin.org.standing.participant')
    case 'declared': return t('admin.org.standing.declared')
    case 'ia-endorsed': return t('admin.org.standing.iaEndorsed', { ias: org.endorsedBy.join(', ') })
    default: return t('admin.org.standing.nonParticipant')
  }
})

/** The org's administrators (the org_admin memberships — the scheme
 *  operator's delegation). */
const orgAdmins = computed(() => view.value?.members.filter(m => m.roles.includes('org_admin')) ?? [])

/** The role options the org's kind bounds, plus org_admin (the wide
 *  grant's delegation act — the server re-checks the eligibility). */
const roleOptions = computed(() => (view.value ? [...view.value.org.roles, 'org_admin'] : []))

/** The honest counts the disable confirmation names. */
const activeMembers = computed(() => view.value?.members.filter(m => m.state === 'active').length ?? 0)
const invitedMembers = computed(() => view.value?.members.filter(m => m.state === 'invited').length ?? 0)
/** The remove act's guard mirrors the server's: the org never held a
 *  membership and no join request names it. */
const removable = computed(() => (view.value?.members.length ?? 1) === 0 && (view.value?.requests.length ?? 1) === 0)

/** The org record's action label: the catalogued organization acts in
 *  words; the membership/join acts fall back to the action id (their
 *  consoles carry the full renderers). */
function actionLabel(e: OrgEvent): string {
  const meta = e.metadata ?? {}
  switch (e.action) {
    case 'organization.added': return t('admin.org.activity.action.organization.added')
    case 'organization.updated': return t('admin.org.activity.action.organization.updated', { fields: String(meta.fields ?? '') })
    case 'organization.disabled': return t('admin.org.activity.action.organization.disabled', { count: Number(meta.memberships_disabled ?? 0) })
    case 'organization.reactivated': return t('admin.org.activity.action.organization.reactivated')
    case 'organization.removed': return t('admin.org.activity.action.organization.removed')
    case 'organization.endorsed': return t('admin.org.activity.action.organization.endorsed', { ia: String(meta.ia_org_name ?? meta.ia_org_id ?? '') })
    case 'organization.endorsement_revoked': return t('admin.org.activity.action.organization.endorsement_revoked', { ia: String(meta.ia_org_name ?? meta.ia_org_id ?? '') })
    case 'organization.key_registered': return t('admin.org.activity.action.organization.key_registered', { kid: String(meta.kid ?? ''), label: String(meta.label ?? '') })
    case 'organization.key_rotated': return t('admin.org.activity.action.organization.key_rotated', { kid: String(meta.kid ?? ''), successor: String(meta.successor_kid ?? '') })
    case 'organization.key_revoked': return t('admin.org.activity.action.organization.key_revoked', { kid: String(meta.kid ?? '') })
    default: return e.action
  }
}

function fmtDate(iso: string | null): string {
  if (!iso) return '—'
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })
}

async function api(path: string, init?: RequestInit): Promise<Response> {
  return fetch(path, {
    credentials: 'include',
    ...(init?.body ? { headers: { 'content-type': 'application/json' } } : {}),
    ...init,
  })
}

async function load(): Promise<void> {
  const res = await api(`/api/op/registry/orgs/${encodeURIComponent(orgId.value)}`)
  if (res.status === 401) {
    window.location.assign(`/?redirect=${encodeURIComponent(`/op/admin/registry/orgs/${orgId.value}`)}`)
    return
  }
  if (res.status === 403) {
    forbidden.value = true
    return
  }
  if (res.status === 404) {
    notFound.value = true
    return
  }
  if (!res.ok) throw new Error(`the organization failed (${res.status})`)
  view.value = await res.json() as OrgView
}

function openMemberRoles(m: MemberRow) {
  memberRolesOpen.value = memberRolesOpen.value === m.userId ? null : m.userId
  memberRoleDrafts.value[m.userId] = [...m.roles]
}

async function saveMemberRoles(m: MemberRow) {
  if (acting.value) return
  acting.value = m.userId
  error.value = null
  notice.value = null
  try {
    const res = await api(`/api/op/org-memberships/${encodeURIComponent(m.userId)}/${encodeURIComponent(m.orgId)}/roles`, {
      method: 'PUT',
      body: JSON.stringify({ roles: memberRoleDrafts.value[m.userId] ?? [] }),
    })
    if (!res.ok) {
      const body = await res.json().catch(() => ({})) as { error?: string }
      error.value = body.error ?? `The role assignment failed (${res.status}).`
      return
    }
    notice.value = `${m.name}'s roles updated.`
    memberRolesOpen.value = null
    await load()
  } catch {
    error.value = 'Network error. Is the server running?'
  } finally {
    acting.value = null
  }
}

async function setMemberState(m: MemberRow, state: 'active' | 'disabled') {
  if (acting.value) return
  acting.value = m.userId
  error.value = null
  notice.value = null
  try {
    const res = await api(`/api/op/org-memberships/${encodeURIComponent(m.userId)}/${encodeURIComponent(m.orgId)}/state`, {
      method: 'POST',
      body: JSON.stringify({ state }),
    })
    if (!res.ok) {
      const body = await res.json().catch(() => ({})) as { error?: string }
      error.value = body.error ?? `(${res.status})`
      return
    }
    notice.value = state === 'disabled'
      ? `${m.name}'s membership is disabled — their sessions stopped acting as ${view.value?.org.name ?? 'this organization'}.`
      : `${m.name}'s membership is active again.`
    await load()
  } catch {
    error.value = 'Network error. Is the server running?'
  } finally {
    acting.value = null
  }
}

/** Invite an EXISTING account into the org (the holder accepts from the
 *  account console). */
async function inviteMember() {
  if (acting.value) return
  acting.value = 'invite'
  error.value = null
  notice.value = null
  try {
    const res = await api('/api/op/org-memberships', {
      method: 'POST',
      body: JSON.stringify({ email: addEmail.value.trim(), org_id: orgId.value, roles: addRoleChecks.value }),
    })
    if (!res.ok) {
      const body = await res.json().catch(() => ({})) as { error?: string }
      error.value = body.error ?? `The membership invite failed (${res.status}).`
      return
    }
    notice.value = `${addEmail.value.trim()} is invited — the invitation waits on their account console.`
    addEmail.value = ''
    addRoleChecks.value = []
    await load()
  } catch {
    error.value = t('account.networkError')
  } finally {
    acting.value = null
  }
}

// ── the organization card's acts (TODO.identity-features/05) ─────────

function openEdit() {
  if (!view.value) return
  editOpen.value = !editOpen.value
  confirmDisable.value = false
  confirmRemove.value = false
  const org = view.value.org
  editName.value = org.name
  editShortName.value = org.shortName === org.name ? '' : org.shortName
  editKind.value = org.kind ?? ''
  editCountry.value = org.country
  editParticipantRef.value = org.participantRef ?? ''
  editContacts.value = org.contacts.length
    ? org.contacts.map(ct => ({ name: ct.name ?? '', email: ct.email }))
    : [{ name: '', email: '' }]
}

async function saveEdit() {
  if (acting.value || !view.value) return
  acting.value = 'edit'
  error.value = null
  notice.value = null
  try {
    const contacts = editContacts.value
      .map(ct => ({ name: ct.name.trim() || undefined, email: ct.email.trim() }))
      .filter(ct => ct.email)
    const res = await api(`/api/op/registry/orgs/${encodeURIComponent(orgId.value)}`, {
      method: 'PUT',
      body: JSON.stringify({
        name: editName.value.trim(),
        short_name: editShortName.value.trim() || null,
        kind: editKind.value || null,
        country: editCountry.value.trim() || null,
        participant_ref: editParticipantRef.value.trim() || null,
        contacts,
      }),
    })
    if (!res.ok) {
      const body = await res.json().catch(() => ({})) as { error?: string }
      error.value = body.error ?? t('admin.user.failed', { status: res.status })
      return
    }
    notice.value = t('admin.org.acts.saved')
    editOpen.value = false
    await load()
  } catch {
    error.value = t('account.networkError')
  } finally {
    acting.value = null
  }
}

/** The lifecycle act: disable (the honest removal — the cascade answer
 *  names the memberships) / re-enable (the memberships stay disabled). */
async function setOrgState(state: 'active' | 'disabled') {
  if (acting.value) return
  acting.value = 'org-state'
  error.value = null
  notice.value = null
  try {
    const res = await api(`/api/op/registry/orgs/${encodeURIComponent(orgId.value)}/state`, {
      method: 'POST',
      body: JSON.stringify({ state }),
    })
    if (!res.ok) {
      const body = await res.json().catch(() => ({})) as { error?: string }
      error.value = body.error ?? t('admin.user.failed', { status: res.status })
      return
    }
    const answer = await res.json() as { membershipsDisabled?: number; membershipsStillDisabled?: number }
    notice.value = state === 'disabled'
      ? t('admin.org.acts.disabled', { count: answer.membershipsDisabled ?? 0 })
      : t('admin.org.acts.reactivated', { count: answer.membershipsStillDisabled ?? 0 })
    confirmDisable.value = false
    await load()
  } catch {
    error.value = t('account.networkError')
  } finally {
    acting.value = null
  }
}

/** The guarded hard delete: the org never held a membership and no join
 *  request names it (the server's 409 is the honest refusal otherwise).
 *  The org is gone — back to the Organizations surface. */
async function removeOrg() {
  if (acting.value) return
  acting.value = 'remove'
  error.value = null
  notice.value = null
  try {
    const res = await api(`/api/op/registry/orgs/${encodeURIComponent(orgId.value)}`, { method: 'DELETE' })
    if (!res.ok) {
      const body = await res.json().catch(() => ({})) as { error?: string }
      error.value = body.error ?? t('admin.user.failed', { status: res.status })
      confirmRemove.value = false
      return
    }
    window.location.assign('/op/admin/organizations')
  } catch {
    error.value = t('account.networkError')
    acting.value = null
  }
}

onMounted(async () => {
  try {
    const session = await fetch('/api/auth/session', { credentials: 'include' })
    if (!session.ok) {
      window.location.assign(`/?redirect=${encodeURIComponent(`/op/admin/registry/orgs/${orgId.value}`)}`)
      return
    }
    await load()
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
        <h1 class="text-xl font-serif font-bold text-slate-900 dark:text-white">Registry organization</h1>
      </div>
      <div class="p-3 rounded-lg bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800">
        <p class="text-sm text-amber-800 dark:text-amber-300" data-testid="op-reg-org-forbidden">
          The registry's organization view is an administrator surface — your account does not hold the administrator role.
        </p>
      </div>
    </div>

    <div v-else-if="notFound" class="max-w-md mx-auto py-16 text-center">
      <p class="text-sm text-slate-500 dark:text-slate-400" data-testid="op-reg-org-notfound">
        This organization is not on the organization registry.
      </p>
    </div>

    <div v-else-if="view" data-testid="op-reg-org">
      <p class="mb-2 text-sm" data-testid="op-reg-org-back">
        <router-link to="/op/admin/organizations" class="text-brand-600 hover:text-brand-700 dark:text-brand-300 dark:hover:text-brand-200 font-medium transition-colors">← {{ t('admin.orgs.title') }}</router-link>
      </p>
      <PageHeader :title="view.org.name" title-test-id="op-reg-org-name">
        <template #description>
          <span data-testid="op-reg-org-context">
            {{ view.org.kind ?? t('admin.org.details.kindNone') }}<template v-if="view.org.country"> · {{ view.org.country }}</template>
            <span
              class="ml-2 px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wider"
              :class="view.org.state === 'active' ? 'bg-emerald-100 dark:bg-emerald-900/30 text-emerald-700 dark:text-emerald-300' : 'bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-300'"
              data-testid="op-reg-org-state"
            >{{ view.org.state === 'active' ? t('admin.orgs.stateActive') : t('admin.orgs.stateDisabled') }}</span>
            <span
              v-if="view.org.participantRef"
              class="ml-1 px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wider bg-sky-100 dark:bg-sky-900/30 text-sky-700 dark:text-sky-300"
              data-testid="op-reg-org-participant-ref"
            >participant {{ view.org.participantRef }}</span>
            — {{ branding.productName }}
          </span>
        </template>
      </PageHeader>

      <div v-if="error" class="mb-4 p-3 rounded-lg bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800">
        <p class="text-sm text-red-700 dark:text-red-300" data-testid="op-reg-org-error">{{ error }}</p>
      </div>
      <div v-if="notice" class="mb-4 p-3 rounded-lg bg-emerald-50 dark:bg-emerald-900/20 border border-emerald-200 dark:border-emerald-800">
        <p class="text-sm text-emerald-800 dark:text-emerald-300" data-testid="op-reg-org-notice">{{ notice }}</p>
      </div>

      <!-- The organization card: the display data + the lifecycle acts. -->
      <section class="rounded-xl border border-slate-200/80 dark:border-slate-700 bg-white dark:bg-slate-800 p-6 mb-6" data-testid="op-reg-org-card">
        <div class="flex items-start justify-between gap-3 mb-3">
          <h2 class="text-xs font-semibold uppercase tracking-wider text-slate-400 dark:text-slate-500">{{ t('admin.org.details.title') }}</h2>
          <div class="shrink-0 flex items-center gap-3 text-xs font-medium">
            <button
              data-testid="op-reg-org-edit"
              :disabled="acting !== null"
              class="text-brand-600 dark:text-brand-300 hover:underline disabled:opacity-50"
              @click="openEdit"
            >{{ editOpen ? t('admin.user.memberships.rolesClose') : t('admin.org.acts.edit') }}</button>
            <button
              v-if="view.org.state === 'active'"
              data-testid="op-reg-org-disable"
              :disabled="acting !== null"
              class="text-red-600 dark:text-red-400 hover:underline disabled:opacity-50"
              @click="confirmDisable = !confirmDisable; confirmRemove = false; editOpen = false"
            >{{ t('admin.org.acts.disable') }}</button>
            <button
              v-else
              data-testid="op-reg-org-reactivate"
              :disabled="acting !== null"
              class="text-emerald-600 dark:text-emerald-400 hover:underline disabled:opacity-50"
              @click="setOrgState('active')"
            >{{ t('admin.org.acts.reactivate') }}</button>
            <button
              v-if="removable"
              data-testid="op-reg-org-remove"
              :disabled="acting !== null"
              class="text-red-600 dark:text-red-400 hover:underline disabled:opacity-50"
              @click="confirmRemove = !confirmRemove; confirmDisable = false; editOpen = false"
            >{{ t('admin.org.acts.remove') }}</button>
          </div>
        </div>

        <dl class="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-1 text-xs" data-testid="op-reg-org-details">
          <div class="flex gap-2"><dt class="text-slate-400 dark:text-slate-500 shrink-0">{{ t('admin.org.details.idLabel') }}</dt><dd class="font-mono text-slate-700 dark:text-slate-300" data-testid="op-reg-org-id">{{ view.org.id }}</dd></div>
          <div class="flex gap-2"><dt class="text-slate-400 dark:text-slate-500 shrink-0">{{ t('admin.org.details.kindLabel') }}</dt><dd class="text-slate-700 dark:text-slate-300" data-testid="op-reg-org-kind">{{ view.org.kind ?? t('admin.org.details.kindNone') }}</dd></div>
          <div class="flex gap-2"><dt class="text-slate-400 dark:text-slate-500 shrink-0">{{ t('admin.org.details.countryLabel') }}</dt><dd class="text-slate-700 dark:text-slate-300">{{ view.org.country || '—' }}</dd></div>
          <div class="flex gap-2"><dt class="text-slate-400 dark:text-slate-500 shrink-0">{{ t('admin.org.details.stateLabel') }}</dt><dd class="text-slate-700 dark:text-slate-300">{{ view.org.state === 'active' ? t('admin.orgs.stateActive') : t('admin.orgs.stateDisabled') }}<template v-if="view.org.state === 'disabled' && view.org.disabledAt"> ({{ t('admin.org.details.disabledBy', { date: fmtDate(view.org.disabledAt), by: view.org.disabledBy ?? '—' }) }})</template></dd></div>
          <div class="flex gap-2 sm:col-span-2">
            <dt class="text-slate-400 dark:text-slate-500 shrink-0">{{ t('admin.org.details.standingLabel') }}</dt>
            <dd class="text-slate-700 dark:text-slate-300" data-testid="op-reg-org-standing">{{ standingText }}</dd>
          </div>
          <div class="flex gap-2 sm:col-span-2">
            <dt class="text-slate-400 dark:text-slate-500 shrink-0">{{ t('admin.org.details.participantRefLabel') }}</dt>
            <dd class="text-slate-700 dark:text-slate-300" data-testid="op-reg-org-participant">{{ view.org.participantRef ?? t('admin.org.details.participantRefNone') }}</dd>
          </div>
          <div class="flex gap-2 sm:col-span-2">
            <dt class="text-slate-400 dark:text-slate-500 shrink-0">{{ t('admin.org.details.contactsLabel') }}</dt>
            <dd class="text-slate-700 dark:text-slate-300" data-testid="op-reg-org-contacts">
              <template v-if="view.org.contacts.length">
                <span v-for="(ct, i) in view.org.contacts" :key="i" class="inline-block mr-3"><template v-if="ct.name">{{ ct.name }} </template>&lt;{{ ct.email }}&gt;</span>
              </template>
              <span v-else class="text-slate-400 dark:text-slate-500">{{ t('admin.org.details.contactsEmpty') }}</span>
            </dd>
          </div>
          <div v-if="view.org.updatedAt" class="flex gap-2 sm:col-span-2">
            <dd class="text-slate-400 dark:text-slate-500" data-testid="op-reg-org-updated">{{ t('admin.org.details.updatedBy', { date: fmtDate(view.org.updatedAt), by: view.org.updatedBy ?? '—' }) }}</dd>
          </div>
        </dl>

        <!-- The edit form -->
        <div v-if="editOpen" class="mt-4 border-t border-slate-100 dark:border-slate-700 pt-3" data-testid="op-reg-org-edit-form">
          <div class="grid grid-cols-1 sm:grid-cols-2 gap-2">
            <input v-model="editName" type="text" data-testid="op-reg-org-edit-name" :placeholder="t('admin.orgs.field.name')" class="px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-500" />
            <input v-model="editShortName" type="text" data-testid="op-reg-org-edit-short-name" :placeholder="t('admin.orgs.field.shortName')" class="px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-500" />
            <select v-model="editKind" data-testid="op-reg-org-edit-kind" class="px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-500">
              <option value="">{{ t('admin.orgs.kindNone') }}</option>
              <option v-for="k in KIND_OPTIONS" :key="k" :value="k">{{ k }}</option>
            </select>
            <input v-model="editCountry" type="text" data-testid="op-reg-org-edit-country" :placeholder="t('admin.orgs.field.country')" class="px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-500" />
            <input v-model="editParticipantRef" type="text" data-testid="op-reg-org-edit-participant-ref" :placeholder="t('admin.orgs.field.participantRef')" class="px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-500 sm:col-span-2" />
          </div>
          <div class="mt-3">
            <p class="text-xs font-semibold text-slate-700 dark:text-slate-300 mb-2">{{ t('admin.orgs.field.contacts') }}</p>
            <div v-for="(contact, i) in editContacts" :key="i" class="flex flex-wrap sm:flex-nowrap items-center gap-2 mb-2" :data-testid="`op-reg-org-edit-contact-${i}`">
              <input v-model="contact.name" type="text" :data-testid="`op-reg-org-edit-contact-name-${i}`" :placeholder="t('admin.orgs.contactName')" class="flex-1 min-w-40 px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-500" />
              <input v-model="contact.email" type="email" :data-testid="`op-reg-org-edit-contact-email-${i}`" :placeholder="t('admin.orgs.contactEmail')" class="flex-1 min-w-40 px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-500" />
              <button v-if="editContacts.length > 1" type="button" :data-testid="`op-reg-org-edit-contact-remove-${i}`" class="shrink-0 text-xs text-red-600 dark:text-red-400 hover:underline" @click="editContacts.splice(i, 1)">{{ t('admin.orgs.contactRemove') }}</button>
            </div>
            <button type="button" data-testid="op-reg-org-edit-contact-add" class="text-xs text-brand-600 dark:text-brand-300 hover:underline" @click="editContacts.push({ name: '', email: '' })">+ {{ t('admin.orgs.contactAdd') }}</button>
          </div>
          <div class="mt-3">
            <button
              :disabled="acting === 'edit' || !editName.trim()"
              data-testid="op-reg-org-edit-save"
              class="px-3 py-1.5 rounded-lg text-xs font-medium bg-brand-600 text-white hover:bg-brand-700 transition-colors disabled:opacity-50"
              @click="saveEdit"
            >{{ acting === 'edit' ? t('admin.org.acts.saving') : t('admin.org.acts.save') }}</button>
          </div>
        </div>

        <!-- The disable confirmation (the honest cascade named) -->
        <div v-if="confirmDisable" class="mt-4 border-t border-slate-100 dark:border-slate-700 pt-3" data-testid="op-reg-org-disable-confirm">
          <p class="text-xs text-slate-600 dark:text-slate-300 mb-2">{{ t('admin.org.acts.disableNote') }}</p>
          <p class="text-xs text-slate-500 dark:text-slate-400 mb-2">{{ activeMembers }} active · {{ invitedMembers }} invited</p>
          <button
            :disabled="acting === 'org-state'"
            data-testid="op-reg-org-disable-submit"
            class="px-3 py-1.5 rounded-lg text-xs font-medium bg-red-600 text-white hover:bg-red-700 transition-colors disabled:opacity-50"
            @click="setOrgState('disabled')"
          >{{ t('admin.org.acts.disableConfirm') }}</button>
        </div>

        <!-- The remove confirmation (the guarded hard delete) -->
        <div v-if="confirmRemove" class="mt-4 border-t border-slate-100 dark:border-slate-700 pt-3" data-testid="op-reg-org-remove-confirm">
          <p class="text-xs text-slate-600 dark:text-slate-300 mb-2">{{ t('admin.org.acts.removeNote') }}</p>
          <button
            :disabled="acting === 'remove'"
            data-testid="op-reg-org-remove-submit"
            class="px-3 py-1.5 rounded-lg text-xs font-medium bg-red-600 text-white hover:bg-red-700 transition-colors disabled:opacity-50"
            @click="removeOrg"
          >{{ t('admin.org.acts.removeConfirm') }}</button>
        </div>
      </section>

      <!-- The manufacturer standing's endorsements (TODO.register/01):
           the ACTIVE IA confirmations, honestly — a manufacturer is
           never an OIML-CS participant. -->
      <section v-if="view.org.kind === 'manufacturer'" class="rounded-xl border border-slate-200/80 dark:border-slate-700 bg-white dark:bg-slate-800 p-6 mb-6" data-testid="op-reg-org-endorsements">
        <h2 class="text-xs font-semibold uppercase tracking-wider text-slate-400 dark:text-slate-500 mb-3">{{ t('admin.org.endorsements.title') }}</h2>
        <p v-if="!view.endorsements.length" class="text-sm text-slate-500 dark:text-slate-400" data-testid="op-reg-org-endorsements-empty">
          {{ t('admin.org.endorsements.empty') }}
        </p>
        <ul v-else class="space-y-1" data-testid="op-reg-org-endorsements-list">
          <li
            v-for="e in view.endorsements"
            :key="e.iaOrgId"
            class="text-xs text-slate-600 dark:text-slate-300"
            :data-testid="`op-reg-org-endorsement-${e.iaOrgId}`"
          >
            <span class="font-medium text-slate-900 dark:text-white">{{ e.iaName }}</span>
            — {{ t('admin.org.endorsements.item', { date: fmtDate(e.createdAt), by: e.createdBy ?? '—' }) }}
            <p v-if="e.note" class="text-slate-500 dark:text-slate-400 mt-0.5">“{{ e.note }}”</p>
          </li>
        </ul>
      </section>

      <!-- The org's signing keys (TODO.trust-registry/01): the custody
           chain whole — the PUBLIC halves, the rotation overlap links,
           the revocation stamps. The private material stays with the
           organization; this service publishes the public halves at the
           anonymous key-resolution endpoint (/op/keys/<org-id>.json). -->
      <section class="rounded-xl border border-slate-200/80 dark:border-slate-700 bg-white dark:bg-slate-800 p-6 mb-6" data-testid="op-reg-org-keys">
        <h2 class="text-xs font-semibold uppercase tracking-wider text-slate-400 dark:text-slate-500 mb-1">{{ t('admin.org.keys.title') }}</h2>
        <p class="text-xs text-slate-500 dark:text-slate-400 mb-3">{{ t('admin.org.keys.description', { url: `/op/keys/${view.org.id}.json` }) }}</p>
        <p v-if="!view.signingKeys.length" class="text-sm text-slate-500 dark:text-slate-400" data-testid="op-reg-org-keys-empty">
          {{ t('admin.org.keys.empty') }}
        </p>
        <ul v-else class="space-y-2" data-testid="op-reg-org-keys-list">
          <li
            v-for="k in view.signingKeys"
            :key="k.kid"
            class="rounded-lg border border-slate-200 dark:border-slate-700 px-3 py-2"
            :data-testid="`op-reg-org-key-${k.kid}`"
          >
            <div class="flex items-center justify-between gap-3 flex-wrap">
              <div class="min-w-0">
                <p class="text-sm font-medium text-slate-900 dark:text-white break-words">
                  {{ k.label }}
                  <span
                    v-if="k.revokedAt"
                    class="ml-1 px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wider bg-red-100 dark:bg-red-900/40 text-red-600 dark:text-red-400"
                    :data-testid="`op-reg-org-key-revoked-${k.kid}`"
                  >{{ t('admin.org.keys.badgeRevoked') }}</span>
                  <span
                    v-else-if="k.rotatedAt"
                    class="ml-1 px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wider bg-amber-100 dark:bg-amber-900/30 text-amber-700 dark:text-amber-300"
                    :data-testid="`op-reg-org-key-rotated-${k.kid}`"
                  >{{ t('admin.org.keys.badgeRotated') }}</span>
                  <span
                    v-else
                    class="ml-1 px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wider bg-emerald-100 dark:bg-emerald-900/30 text-emerald-700 dark:text-emerald-300"
                    :data-testid="`op-reg-org-key-active-${k.kid}`"
                  >{{ t('admin.org.keys.badgeActive') }}</span>
                </p>
                <p class="text-[11px] font-mono text-slate-400 dark:text-slate-500 break-all" :data-testid="`op-reg-org-key-kid-${k.kid}`">kid {{ k.kid }}</p>
                <p class="text-[11px] text-slate-500 dark:text-slate-400" :data-testid="`op-reg-org-key-stamps-${k.kid}`">
                  {{ t('admin.org.keys.item', { date: fmtDate(k.createdAt), by: k.createdBy ?? '—' }) }} · {{ keyStatus(k) }}
                </p>
              </div>
              <div class="shrink-0 flex items-center gap-3 text-xs font-medium">
                <button
                  v-if="!k.revokedAt && !k.rotatedAt && view.org.state === 'active'"
                  :data-testid="`op-reg-org-key-rotate-${k.kid}`"
                  :disabled="acting !== null"
                  class="text-brand-600 dark:text-brand-300 hover:underline disabled:opacity-50"
                  @click="keyRotateKid = keyRotateKid === k.kid ? null : k.kid; keyRotateLabel = ''; keyRotateJwk = ''; keyRevokeKid = null"
                >{{ keyRotateKid === k.kid ? t('admin.user.memberships.rolesClose') : t('admin.org.keys.rotate') }}</button>
                <button
                  v-if="!k.revokedAt"
                  :data-testid="`op-reg-org-key-revoke-${k.kid}`"
                  :disabled="acting !== null"
                  class="text-red-600 dark:text-red-400 hover:underline disabled:opacity-50"
                  @click="keyRevokeKid = keyRevokeKid === k.kid ? null : k.kid; keyRotateKid = null"
                >{{ t('admin.org.keys.revoke') }}</button>
              </div>
            </div>

            <!-- The rotation form (the successor's PUBLIC half; the
                 predecessor keeps its row with the overlap stamps). -->
            <div v-if="keyRotateKid === k.kid" class="mt-2 border-t border-slate-100 dark:border-slate-700 pt-2" :data-testid="`op-reg-org-key-rotate-form-${k.kid}`">
              <p class="text-xs text-slate-500 dark:text-slate-400 mb-2">{{ t('admin.org.keys.rotateNote') }}</p>
              <input v-model="keyRotateLabel" type="text" :data-testid="`op-reg-org-key-rotate-label-${k.kid}`" :placeholder="t('admin.org.keys.fieldLabel')" class="mb-2 w-full px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-500" />
              <textarea v-model="keyRotateJwk" rows="3" :data-testid="`op-reg-org-key-rotate-jwk-${k.kid}`" :placeholder="t('admin.org.keys.fieldJwk')" class="mb-2 w-full px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-xs font-mono text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-500" />
              <button
                :disabled="acting !== null || !keyRotateLabel.trim() || !keyRotateJwk.trim()"
                :data-testid="`op-reg-org-key-rotate-submit-${k.kid}`"
                class="px-3 py-1.5 rounded-lg text-xs font-medium bg-brand-600 text-white hover:bg-brand-700 transition-colors disabled:opacity-50"
                @click="rotateKey(k)"
              >{{ acting === `key-rotate-${k.kid}` ? t('admin.org.keys.rotateBusy') : t('admin.org.keys.rotateSubmit') }}</button>
            </div>

            <!-- The revocation confirmation (the terminal act — the row
                 KEEPS its stamps; the at-the-time artifacts stay honest). -->
            <div v-if="keyRevokeKid === k.kid" class="mt-2 border-t border-slate-100 dark:border-slate-700 pt-2" :data-testid="`op-reg-org-key-revoke-confirm-${k.kid}`">
              <p class="text-xs text-slate-600 dark:text-slate-300 mb-2">{{ t('admin.org.keys.revokeNote') }}</p>
              <button
                :disabled="acting !== null"
                :data-testid="`op-reg-org-key-revoke-submit-${k.kid}`"
                class="px-3 py-1.5 rounded-lg text-xs font-medium bg-red-600 text-white hover:bg-red-700 transition-colors disabled:opacity-50"
                @click="revokeKey(k)"
              >{{ acting === `key-revoke-${k.kid}` ? t('admin.org.keys.revokeBusy') : t('admin.org.keys.revokeConfirm') }}</button>
            </div>
          </li>
        </ul>

        <!-- The register form (the org admin manages theirs; the estate
             admin sees all). -->
        <div v-if="view.org.state === 'active'" class="mt-4 border-t border-slate-100 dark:border-slate-700 pt-3" data-testid="op-reg-org-key-register">
          <h3 class="text-xs font-semibold text-slate-700 dark:text-slate-300 mb-2">{{ t('admin.org.keys.registerTitle') }}</h3>
          <input v-model="keyLabel" type="text" data-testid="op-reg-org-key-label" :placeholder="t('admin.org.keys.fieldLabel')" class="mb-2 w-full px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-500" />
          <textarea v-model="keyJwk" rows="3" data-testid="op-reg-org-key-jwk" :placeholder="t('admin.org.keys.fieldJwk')" class="mb-2 w-full px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-xs font-mono text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-500" />
          <button
            :disabled="acting !== null || !keyLabel.trim() || !keyJwk.trim()"
            data-testid="op-reg-org-key-register-submit"
            class="px-3 py-1.5 rounded-lg text-xs font-medium bg-brand-600 text-white hover:bg-brand-700 transition-colors disabled:opacity-50"
            @click="registerKey"
          >{{ acting === 'key-register' ? t('admin.org.keys.registerBusy') : t('admin.org.keys.registerSubmit') }}</button>
        </div>
      </section>

      <!-- The members: the memberships with their per-org role sets. -->
      <section class="rounded-xl border border-slate-200/80 dark:border-slate-700 bg-white dark:bg-slate-800 p-6 mb-6" data-testid="op-reg-org-members">
        <h2 class="text-xs font-semibold uppercase tracking-wider text-slate-400 dark:text-slate-500 mb-1">Members</h2>
        <p class="text-xs text-slate-500 dark:text-slate-400 mb-3" data-testid="op-reg-org-admins">
          <template v-if="orgAdmins.length">
            Organization administrator{{ orgAdmins.length > 1 ? 's' : '' }}:
            <span v-for="(a, i) in orgAdmins" :key="a.userId" :data-testid="`op-reg-org-admin-${a.userId}`">{{ i ? ', ' : '' }}{{ a.name }} &lt;{{ a.email }}&gt;</span>
          </template>
          <template v-else>No organization administrator yet — the scheme operator creates one from the organization administration console.</template>
        </p>
        <p v-if="!view.members.length" class="text-sm text-slate-500 dark:text-slate-400" data-testid="op-reg-org-members-empty">
          No memberships yet.
        </p>
        <ul v-else class="space-y-2" data-testid="op-reg-org-members-list">
          <li
            v-for="m in view.members"
            :key="m.userId"
            class="rounded-lg border border-slate-200 dark:border-slate-700 px-3 py-2"
            :data-testid="`op-reg-org-member-${m.userId}`"
          >
            <div class="flex items-center justify-between gap-3 flex-wrap">
              <div class="min-w-0">
                <p class="text-sm font-medium text-slate-900 dark:text-white break-words">
                  <router-link
                    :to="`/op/admin/registry/users/${m.userId}`"
                    class="hover:underline text-brand-700 dark:text-brand-300"
                    :data-testid="`op-reg-org-member-open-${m.userId}`"
                  >{{ m.name }}</router-link>
                  <span class="font-normal text-slate-500 dark:text-slate-400">&lt;{{ m.email }}&gt;</span>
                  <span v-if="m.isPrimary" class="ml-1 text-[10px] px-1.5 py-0.5 rounded bg-slate-100 dark:bg-slate-700 text-slate-500 dark:text-slate-300 font-semibold uppercase tracking-wider">primary</span>
                  <span v-if="m.state === 'invited'" class="ml-1 text-[10px] px-1.5 py-0.5 rounded bg-amber-100 dark:bg-amber-900/30 text-amber-700 dark:text-amber-300 font-semibold uppercase tracking-wider">invited</span>
                  <span v-if="m.state === 'disabled'" class="ml-1 text-[10px] px-1.5 py-0.5 rounded bg-red-100 dark:bg-red-900/40 text-red-600 dark:text-red-400 font-semibold uppercase tracking-wider">disabled</span>
                  <span v-if="!m.accountActive" class="ml-1 text-[10px] px-1.5 py-0.5 rounded bg-red-100 dark:bg-red-900/40 text-red-600 dark:text-red-400 font-semibold">account deactivated</span>
                </p>
                <p class="text-[11px] text-slate-400 dark:text-slate-500" :data-testid="`op-reg-org-member-roles-${m.userId}`">
                  {{ m.roles.join(', ') || 'no organization roles' }}
                  <template v-if="m.state === 'invited' && m.invitedBy"> · invited by {{ m.invitedBy }}</template>
                  <template v-if="m.state === 'disabled'"> · disabled {{ fmtDate(m.disabledAt) }}<template v-if="m.disabledBy"> by {{ m.disabledBy }}</template></template>
                </p>
              </div>
              <div class="shrink-0 flex items-center gap-3 text-xs font-medium">
                <button
                  :data-testid="`op-reg-org-member-roles-edit-${m.userId}`"
                  :disabled="acting === m.userId"
                  class="text-brand-600 dark:text-brand-300 hover:underline disabled:opacity-50"
                  @click="openMemberRoles(m)"
                >{{ memberRolesOpen === m.userId ? 'Close' : 'Roles' }}</button>
                <button
                  v-if="m.state !== 'invited'"
                  :data-testid="`op-reg-org-member-toggle-${m.userId}`"
                  :disabled="acting === m.userId"
                  class="hover:underline disabled:opacity-50"
                  :class="m.state === 'active' ? 'text-red-600 dark:text-red-400' : 'text-emerald-600 dark:text-emerald-400'"
                  @click="setMemberState(m, m.state === 'active' ? 'disabled' : 'active')"
                >{{ m.state === 'active' ? 'Disable' : 'Re-activate' }}</button>
              </div>
            </div>
            <div v-if="memberRolesOpen === m.userId" class="mt-2 border-t border-slate-100 dark:border-slate-700 pt-2" :data-testid="`op-reg-org-member-editor-${m.userId}`">
              <div class="flex flex-wrap gap-x-4 gap-y-1 mb-2">
                <label v-for="r in roleOptions" :key="r" class="flex items-center gap-1.5 text-xs text-slate-700 dark:text-slate-300">
                  <input
                    type="checkbox"
                    :value="r"
                    v-model="memberRoleDrafts[m.userId]"
                    :data-testid="`op-reg-org-member-check-${m.userId}-${r}`"
                    class="rounded border-slate-300 dark:border-slate-600 text-brand-600 focus:ring-brand-500"
                  />
                  {{ r }}
                </label>
              </div>
              <button
                :disabled="acting === m.userId"
                :data-testid="`op-reg-org-member-save-${m.userId}`"
                class="px-3 py-1.5 rounded-lg text-xs font-medium bg-brand-600 text-white hover:bg-brand-700 transition-colors disabled:opacity-50"
                @click="saveMemberRoles(m)"
              >Save the roles</button>
            </div>
          </li>
        </ul>

        <!-- The invite (an existing account; the holder accepts). -->
        <div class="mt-4 border-t border-slate-100 dark:border-slate-700 pt-3" data-testid="op-reg-org-invite">
          <h3 class="text-xs font-semibold text-slate-700 dark:text-slate-300 mb-2">Invite an existing account</h3>
          <div class="grid grid-cols-1 sm:grid-cols-2 gap-2">
            <input
              v-model="addEmail"
              type="email"
              data-testid="op-reg-org-invite-email"
              class="px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-500"
              placeholder="The account’s email"
            />
            <button
              :disabled="acting === 'invite' || !addEmail.includes('@')"
              data-testid="op-reg-org-invite-submit"
              class="py-2 rounded-lg text-sm font-medium bg-brand-600 text-white hover:bg-brand-700 transition-colors disabled:opacity-50"
              @click="inviteMember"
            >{{ acting === 'invite' ? 'Inviting…' : 'Invite the membership' }}</button>
          </div>
          <div class="mt-2 flex flex-wrap gap-x-4 gap-y-1">
            <label v-for="r in roleOptions" :key="r" class="flex items-center gap-1.5 text-xs text-slate-700 dark:text-slate-300">
              <input
                type="checkbox"
                :value="r"
                v-model="addRoleChecks"
                :data-testid="`op-reg-org-invite-role-${r}`"
                class="rounded border-slate-300 dark:border-slate-600 text-brand-600 focus:ring-brand-500"
              />
              {{ r }}
            </label>
          </div>
          <p class="mt-2 text-[11px] text-slate-400 dark:text-slate-500">
            The invitation waits on the account holder's console until they accept or decline it. A person with
            no account yet comes in through the join-request queue below (its approval creates the account).
          </p>
        </div>
      </section>

      <!-- The org's join-request queue (every state, newest first). -->
      <section class="rounded-xl border border-slate-200/80 dark:border-slate-700 bg-white dark:bg-slate-800 p-6 mb-6" data-testid="op-reg-org-requests">
        <h2 class="text-xs font-semibold uppercase tracking-wider text-slate-400 dark:text-slate-500 mb-3">Join requests</h2>
        <p v-if="!view.requests.length" class="text-sm text-slate-500 dark:text-slate-400" data-testid="op-reg-org-requests-empty">
          No join requests naming this organization.
        </p>
        <ul v-else class="space-y-1" data-testid="op-reg-org-requests-list">
          <li
            v-for="r in view.requests"
            :key="r.id"
            class="flex items-center justify-between rounded-lg border border-slate-100 dark:border-slate-700/60 px-3 py-2"
            :data-testid="`op-reg-org-request-${r.id}`"
          >
            <p class="text-xs text-slate-600 dark:text-slate-300">
              {{ r.name }} &lt;{{ r.email }}&gt; · {{ r.requestedRole }}
            </p>
            <p class="shrink-0 pl-3 text-xs">
              <span v-if="r.status === 'pending'" class="text-amber-600 dark:text-amber-400">pending</span>
              <span v-else-if="r.status === 'approved'" class="text-emerald-600 dark:text-emerald-400">approved</span>
              <span v-else class="text-red-600 dark:text-red-400">refused<template v-if="r.refusalReason">: {{ r.refusalReason }}</template></span>
            </p>
          </li>
        </ul>
        <p v-if="view.requests.some(r => r.status === 'pending')" class="mt-3 text-[11px] text-slate-400 dark:text-slate-500">
          The decisions happen on the
          <router-link to="/op/admin/users" class="text-brand-600 dark:text-brand-300 hover:underline">organization administration console</router-link>.
        </p>
      </section>

      <!-- The organization's own audit slice (TODO.identity-features/05):
           the lifecycle acts + the membership/join acts naming it. -->
      <section class="rounded-xl border border-slate-200/80 dark:border-slate-700 bg-white dark:bg-slate-800 p-6" data-testid="op-reg-org-activity">
        <h2 class="text-xs font-semibold uppercase tracking-wider text-slate-400 dark:text-slate-500 mb-3">{{ t('admin.org.activity.title') }}</h2>
        <p v-if="!view.activity.length" class="text-sm text-slate-500 dark:text-slate-400" data-testid="op-reg-org-activity-empty">
          {{ t('admin.org.activity.empty') }}
        </p>
        <ul v-else class="space-y-1" data-testid="op-reg-org-activity-list">
          <li
            v-for="e in view.activity"
            :key="e.id"
            class="text-xs text-slate-600 dark:text-slate-300"
            :data-testid="`op-reg-org-event-${e.id}`"
          >
            <span class="text-slate-400 dark:text-slate-500">{{ fmtDate(e.timestamp) }}</span>
            — <span class="font-medium">{{ e.user_name ?? '—' }}</span>
            {{ actionLabel(e) }}
          </li>
        </ul>
      </section>
    </div>
  </div>
</template>
