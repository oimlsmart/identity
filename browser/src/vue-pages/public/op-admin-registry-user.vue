<script setup lang="ts">
// ═══════════════════════════════════════════════════════════════════
// The registry's account detail page (TODO.identity/07, the heavy
// admin-view rebuild) — ONE account on the identity service, complete:
//
//   1. THE IDENTITY CARD — the lifecycle state (invited / active /
//      deactivated / erased), the profile (name, email + its
//      verification state, the avatar), the record stamps (on the
//      record since, last sign-in), the account-wide role set editor,
//      and the lifecycle acts (re-enroll / deactivate / reactivate /
//      erase — each with its honest confirmation, each audited).
//   2. THE APPS THE ACCOUNT CAN ACCESS — the launcher's visibility
//      rule read ADMIN-SIDE: per registered relying party, CAN ENTER
//      or NO with the reason named plainly (the claims-policy claim
//      gate + role allowlist vs the account's roles for the client).
//      The server computes it with the ONE rule the token endpoint
//      runs (routes/op-registry.ts → auth/op/claims.ts); this page
//      only renders the verdicts.
//   3. THE SIGN-IN METHODS + FACTORS — the password's presence, the
//      linked upstreams (unlink with an on-the-record reason; the
//      justified link-on-behalf), and the additional-factors slot
//      (the strong-auth wave fills it — the slot says so honestly).
//   4. THE LIVE SESSIONS — every live session with its sign-in
//      context, per-session revoke, and END ALL (the light act) vs
//      deactivation (the heavy act, the identity card).
//   5. THE PER-CLIENT ROLE GRANTS — the assignments with grant /
//      edit / revoke on this page (the writes ride
//      routes/op-accounts.ts, audited).
//   6. THE AUDIT TRAIL — the account's own events, newest first,
//      honestly paged (the total is in every answer).
//
// SLOT (the multi-org membership wave): the organizations/memberships
// section lands between the sign-in methods and the sessions — the
// marked placeholder in the template below. THIS wave fills it.
//
// Every rule is SERVER-ENFORCED (routes/op-registry.ts,
// routes/op-accounts.ts, routes/users.ts); this page only renders what
// the APIs answer. The lockout rule the codebase enforces and this
// page follows: an administrator can neither DEACTIVATE nor ERASE
// their own account (the server refuses both with 400; the page
// disables the acts and says why). End-all-sessions on your own
// account is allowed (it is sign-out-everywhere: recoverable by
// signing in again) and the page warns that this console goes too.
// ═══════════════════════════════════════════════════════════════════
import { computed, onMounted, ref } from 'vue'
import { useRoute } from 'vue-router'
import PageHeader from '../../components/PageHeader.vue'
import OpAdminNav from '../../components/OpAdminNav.vue'
import { useBranding } from '../../branding'
import { t, type MessageKey } from '../../i18n'

interface AuditEvent {
  id: string
  timestamp: string
  action: string
  user_name?: string
  metadata?: Record<string, unknown>
}

interface LinkRow {
  id: string
  provider: string
  providerAccountId: string
  linkedAt: string
  linkedBy: string | null
}

interface ClientRoleRow {
  clientId: string
  roles: string[]
  assignedBy: string | null
  updatedAt: string
}

interface SessionRow {
  id: string
  createdAt: string
  expiresAt: string
  lastSeenAt: string | null
  userAgent: string | null
  ip: string | null
  current: boolean
}

/** The app-access view's per-client verdict (the server computes it
 *  with the claims rule; `reason` is the stable code the catalog
 *  renders in words). */
interface AppAccessRow {
  clientId: string
  name: string
  status: string
  carriesRoleClaims: boolean
  held: string[]
  allowlist: string[] | null
  roles: string[]
  canEnter: boolean
  reason: 'ok' | 'client_disabled' | 'no_role_claims' | 'explicit_none' | 'outside_allowlist'
}

type LifecycleState = 'invited' | 'active' | 'deactivated' | 'erased'

interface Detail {
  account: {
    id: string
    email: string
    name: string
    role: string
    roles: string[]
    orgId: string | null
    orgName: string | null
    active: boolean
    provider: string
    avatarUrl: string | null
    emailVerifiedAt: string | null
    lastLogin: string | null
    firstSeenAt: string | null
    erasedAt: string | null
    state: LifecycleState
  }
  passwordSet: boolean
  links: LinkRow[]
  sessions: SessionRow[]
  /** TODO.identity-sso/02+03 (the strong-auth wave fills the slot): the
   *  account's factor registry — names + created/last-used, never any
   *  credential material. */
  factors: {
    passkeys: FactorPasskeyRow[]
    totp: FactorTotpRow[]
    recoveryCodes: { total: number; remaining: number; createdAt: string | null }
  }
  clientRoles: ClientRoleRow[]
  appAccess: AppAccessRow[]
  /** TODO.identity/11: the account's org memberships, every state. */
  memberships?: MembershipRow[]
  activity: AuditEvent[]
  activityTotal: number
}

interface FactorPasskeyRow {
  credentialId: string
  name: string
  createdAt: string
  lastUsedAt: string | null
}
interface FactorTotpRow { id: string; name: string; createdAt: string; lastUsedAt: string | null }

interface ProviderRow {
  id: string
  displayName: string
  enabled: boolean
}

/** A membership row (TODO.identity/11 — the detail aggregate's
 *  organizations block): the per-org role set + the lifecycle state. */
interface MembershipRow {
  orgId: string
  orgName: string
  roles: string[]
  state: 'invited' | 'active' | 'disabled'
  isPrimary: boolean
  invitedBy: string | null
  createdAt: string
  activatedAt: string | null
  disabledAt: string | null
  disabledBy: string | null
}

/** The public selector feed's org (GET /api/op/organizations) — the
 *  add-to-org form's options with the kind-bounded role sets. */
interface SelectableOrg {
  id: string
  name: string
  kind: string
  roles: string[]
}

const route = useRoute()
const { branding } = useBranding()
const userId = computed(() => String(route.params.id ?? ''))

const loading = ref(true)
const forbidden = ref(false)
const notFound = ref(false)
const error = ref<string | null>(null)
const notice = ref<string | null>(null)
const acting = ref<string | null>(null)

const detail = ref<Detail | null>(null)
const roleMap = ref<Record<string, string[]>>({})
const providers = ref<ProviderRow[]>([])

// The roles editor's working state.
const checkedRoles = ref<string[]>([])
const primaryRole = ref('')

// The link-on-behalf form.
const linkProvider = ref('')
const linkHandle = ref('')
const linkJustification = ref('')

// The unlink affordance's per-row open state + optional reason.
const unlinkOpen = ref<Record<string, boolean>>({})
const unlinkReason = ref<Record<string, string>>({})

// The deactivation's two-step confirm.
const deactivateArmed = ref(false)

// The erasure's two-step confirm (the offboarding runbook's delete path —
// irreversible, so the confirm names what happens).
const eraseArmed = ref(false)

// The end-all-sessions two-step confirm (the light act).
const revokeAllArmed = ref(false)

// The ONE-TIME setup link of the last (re)issued enrollment, shown once.
const lastSetup = ref<{ setupUrl: string; expiresAt: string } | null>(null)

const isSelf = ref(false)

// ── TODO.identity/11 — the memberships section (this wave fills the
//   slot): the per-org role edit, the lifecycle acts, and the
//   add-to-org invite (the holder accepts from the account console) ──
const registryOrgs = ref<SelectableOrg[]>([])
/** The per-membership roles editor: orgId → the checked roles. */
const memberRolesOpen = ref<string | null>(null)
const memberRoleDrafts = ref<Record<string, string[]>>({})
/** The add-to-org form. */
const addOrgId = ref('')
const addOrgRoles = ref<string[]>([])

/** The memberships (the aggregate's block; absent on an older server). */
const memberships = computed(() => detail.value?.memberships ?? [])

/** The orgs the account may still join: registered, no membership yet. */
const addableOrgs = computed(() => {
  const taken = new Set(memberships.value.map(m => m.orgId))
  return registryOrgs.value.filter(o => !taken.has(o.id))
})

/** The role options for the add form follow the chosen org's kind, plus
 *  org_admin for the identity admin (the scheme operator's delegation —
 *  the server enforces the registered-org eligibility). */
const addOrgRoleOptions = computed(() => {
  const org = registryOrgs.value.find(o => o.id === addOrgId.value)
  return org ? [...org.roles, 'org_admin'] : []
})

/** The per-membership editor's options: the org's kind-bounded set, plus
 *  org_admin (the wide grant's act — the membership API re-checks). */
function memberRoleOptions(orgId: string): string[] {
  const org = registryOrgs.value.find(o => o.id === orgId)
  return org ? [...org.roles, 'org_admin'] : Object.keys(roleMap.value)
}

function openMemberRoles(m: MembershipRow) {
  memberRolesOpen.value = memberRolesOpen.value === m.orgId ? null : m.orgId
  memberRoleDrafts.value[m.orgId] = [...m.roles]
}

async function saveMemberRoles(m: MembershipRow) {
  if (acting.value || !detail.value) return
  acting.value = `roles-${m.orgId}`
  error.value = null
  notice.value = null
  try {
    const res = await api(`/api/op/org-memberships/${encodeURIComponent(userId.value)}/${encodeURIComponent(m.orgId)}/roles`, {
      method: 'PUT',
      body: JSON.stringify({ roles: memberRoleDrafts.value[m.orgId] ?? [] }),
    })
    if (!res.ok) {
      const body = await res.json().catch(() => ({})) as { error?: string }
      error.value = body.error ?? t('admin.user.failed', { status: res.status })
      return
    }
    notice.value = t('admin.user.memberships.rolesSaved', { org: m.orgName })
    memberRolesOpen.value = null
    await load()
  } catch {
    error.value = t('account.networkError')
  } finally {
    acting.value = null
  }
}

async function setMemberState(m: MembershipRow, state: 'active' | 'disabled') {
  if (acting.value || !detail.value) return
  acting.value = `state-${m.orgId}`
  error.value = null
  notice.value = null
  try {
    const res = await api(`/api/op/org-memberships/${encodeURIComponent(userId.value)}/${encodeURIComponent(m.orgId)}/state`, {
      method: 'POST',
      body: JSON.stringify({ state }),
    })
    if (!res.ok) {
      const body = await res.json().catch(() => ({})) as { error?: string }
      error.value = body.error ?? t('admin.user.failed', { status: res.status })
      return
    }
    notice.value = state === 'disabled'
      ? t('admin.user.memberships.disabled', { org: m.orgName })
      : t('admin.user.memberships.reactivated', { org: m.orgName })
    await load()
  } catch {
    error.value = t('account.networkError')
  } finally {
    acting.value = null
  }
}

/** Add the account to another registered org (the invitation waits on
 *  the account console; the join-request approval is the directly-active
 *  path). */
async function addMembership() {
  if (acting.value || !detail.value) return
  acting.value = 'membership-add'
  error.value = null
  notice.value = null
  try {
    const res = await api('/api/op/org-memberships', {
      method: 'POST',
      body: JSON.stringify({
        email: detail.value.account.email,
        org_id: addOrgId.value,
        roles: addOrgRoles.value,
      }),
    })
    if (!res.ok) {
      const body = await res.json().catch(() => ({})) as { error?: string }
      error.value = body.error ?? t('admin.user.failed', { status: res.status })
      return
    }
    const name = registryOrgs.value.find(o => o.id === addOrgId.value)?.name ?? addOrgId.value
    notice.value = t('admin.user.memberships.added', { name: detail.value.account.name, org: name })
    addOrgId.value = ''
    addOrgRoles.value = []
    await load()
  } catch {
    error.value = t('account.networkError')
  } finally {
    acting.value = null
  }
}

// The per-client grant editor: the open state, the selected client, the
// working role set, and the per-row revoke arm.
const grantFormOpen = ref(false)
const grantClient = ref('')
const grantRoles = ref<string[]>([])
const revokeArmed = ref<Record<string, boolean>>({})

// The audit trail's pager (the aggregate carries the first page; the
// paged endpoint serves the older ones).
const activityEvents = ref<AuditEvent[]>([])
const activityTotal = ref(0)
const activityBusy = ref(false)
const ACTIVITY_PAGE = 25

/** The erased tombstone reads but takes no act. */
const erased = computed(() => detail.value?.account.state === 'erased')

/** The grant editor's client options: every registered client (the
 *  app-access view already names them, with each policy's allowlist). */
const grantClients = computed(() => detail.value?.appAccess ?? [])

/** The selected grant client's allowlist (null = unbounded). */
const grantAllowlist = computed(() => grantClients.value.find(cl => cl.clientId === grantClient.value)?.allowlist ?? null)

/** A role is grantable on the selected client when no allowlist bounds
 *  the policy or the role is on it (the server enforces the same). */
function grantRoleEnabled(role: string): boolean {
  return !grantAllowlist.value || grantAllowlist.value.includes(role)
}

const isOpAccount = computed(() => detail.value?.account.provider === 'password')

function fmtStamp(iso: string): string {
  return iso.slice(0, 16).replace('T', ' ')
}

/** The state badge's palette per lifecycle state. */
function stateBadgeClass(state: LifecycleState): string {
  switch (state) {
    case 'active': return 'bg-emerald-100 dark:bg-emerald-900/40 text-emerald-700 dark:text-emerald-300'
    case 'invited': return 'bg-amber-100 dark:bg-amber-900/40 text-amber-700 dark:text-amber-300'
    case 'deactivated': return 'bg-red-100 dark:bg-red-900/40 text-red-600 dark:text-red-400'
    case 'erased': return 'bg-slate-200 dark:bg-slate-700 text-slate-600 dark:text-slate-300'
  }
}

/** The avatar's initials fallback (the same posture as the account
 *  console: the uploaded/linked picture, else the initial). */
const accountInitial = computed(() => (detail.value?.account.name ?? '?').charAt(0).toUpperCase())

/** The app-access verdict's reason line (the reason code in words). */
function appReason(row: AppAccessRow): string {
  if (row.reason === 'ok') return t('admin.user.apps.yes', { roles: row.roles.join(', ') })
  const key = `admin.user.apps.no.${row.reason}` as MessageKey
  return t(key, { allowed: (row.allowlist ?? []).join(', '), held: row.held.join(', ') })
}

function clientName(clientId: string): string {
  return detail.value?.appAccess.find(cl => cl.clientId === clientId)?.name ?? clientId
}

async function api(path: string, init?: RequestInit): Promise<Response> {
  return fetch(path, {
    credentials: 'include',
    ...(init?.body ? { headers: { 'content-type': 'application/json' } } : {}),
    ...init,
  })
}

async function load(): Promise<void> {
  const res = await api(`/api/op/registry/users/${encodeURIComponent(userId.value)}`)
  if (res.status === 401) {
    window.location.assign(`/?redirect=${encodeURIComponent(`/op/admin/registry/users/${userId.value}`)}`)
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
  if (!res.ok) throw new Error(`the account failed (${res.status})`)
  detail.value = await res.json() as Detail
  checkedRoles.value = [...detail.value.account.roles]
  primaryRole.value = detail.value.account.roles.includes(detail.value.account.role)
    ? detail.value.account.role
    : detail.value.account.roles[0]!
  activityEvents.value = detail.value.activity
  activityTotal.value = detail.value.activityTotal
}

/** The trail's older pages (the paged endpoint; the total is in every
 *  answer, so the pager never lies). */
async function loadMoreActivity() {
  if (activityBusy.value) return
  activityBusy.value = true
  error.value = null
  try {
    const res = await api(`/api/op/registry/users/${encodeURIComponent(userId.value)}/activity?offset=${activityEvents.value.length}&limit=${ACTIVITY_PAGE}`)
    if (!res.ok) {
      error.value = t('admin.user.failed', { status: res.status })
      return
    }
    const page = await res.json() as { events: AuditEvent[]; total: number }
    activityEvents.value = [...activityEvents.value, ...page.events]
    activityTotal.value = page.total
  } catch {
    error.value = t('account.networkError')
  } finally {
    activityBusy.value = false
  }
}

async function saveRoles() {
  if (acting.value || !detail.value) return
  if (!checkedRoles.value.length) {
    error.value = t('admin.user.roles.oneRequired')
    return
  }
  acting.value = 'roles'
  error.value = null
  notice.value = null
  try {
    const primary = checkedRoles.value.includes(primaryRole.value) ? primaryRole.value : checkedRoles.value[0]!
    const res = await api(`/api/users/${encodeURIComponent(userId.value)}/roles`, {
      method: 'PUT',
      body: JSON.stringify({ role: primary, roles: checkedRoles.value }),
    })
    if (!res.ok) {
      const body = await res.json().catch(() => ({})) as { error?: string }
      error.value = body.error ?? t('admin.user.failed', { status: res.status })
      return
    }
    notice.value = t('admin.user.roles.saved')
    await load()
  } catch {
    error.value = t('account.networkError')
  } finally {
    acting.value = null
  }
}

async function resendSetup() {
  if (acting.value) return
  acting.value = 'enrollment'
  error.value = null
  notice.value = null
  lastSetup.value = null
  try {
    const res = await api(`/api/op/accounts/${encodeURIComponent(userId.value)}/enrollment`, { method: 'POST' })
    if (!res.ok) {
      const body = await res.json().catch(() => ({})) as { error?: string }
      error.value = body.error ?? t('admin.user.failed', { status: res.status })
      return
    }
    lastSetup.value = await res.json() as { setupUrl: string; expiresAt: string }
    notice.value = t('admin.user.acts.setupIssued')
  } catch {
    error.value = t('account.networkError')
  } finally {
    acting.value = null
  }
}

/** Deactivate / reactivate. The OP's own accounts ride the registry's
 *  status act (routes/op-accounts.ts — it revokes the live credentials
 *  at once); the demo/SSO rows the registry also lists ride the
 *  instance-wide users act (routes/users.ts). Both refuse the self-lockout
 *  server-side; the button is disabled for self too. */
async function setActive(active: boolean) {
  if (acting.value || !detail.value) return
  acting.value = 'active'
  error.value = null
  notice.value = null
  try {
    const id = encodeURIComponent(userId.value)
    const res = isOpAccount.value
      ? await api(`/api/op/accounts/${id}/status`, { method: 'POST', body: JSON.stringify({ active }) })
      : await api(`/api/users/${id}/active`, { method: 'PUT', body: JSON.stringify({ active }) })
    if (!res.ok) {
      const body = await res.json().catch(() => ({})) as { error?: string }
      error.value = body.error ?? t('admin.user.failed', { status: res.status })
      return
    }
    notice.value = active ? t('admin.user.acts.reactivated') : t('admin.user.acts.deactivated')
    deactivateArmed.value = false
    await load()
  } catch {
    error.value = t('account.networkError')
  } finally {
    acting.value = null
  }
}

/** The erasure (DELETE /api/op/accounts/:id): the account is anonymized
 *  in place and every credential, link and token removed. Irreversible;
 *  the account's row vanishes from the registry, so the act ends back on
 *  the directory. */
async function eraseAccount() {
  if (acting.value) return
  acting.value = 'erase'
  error.value = null
  notice.value = null
  try {
    const res = await api(`/api/op/accounts/${encodeURIComponent(userId.value)}`, { method: 'DELETE' })
    if (!res.ok) {
      const body = await res.json().catch(() => ({})) as { error?: string }
      error.value = body.error ?? t('admin.user.failed', { status: res.status })
      acting.value = null
      return
    }
    window.location.assign('/op/admin/registry')
  } catch {
    error.value = t('account.networkError')
    acting.value = null
  }
}

async function linkOnBehalf() {
  if (acting.value) return
  const justification = linkJustification.value.trim()
  if (!justification) {
    error.value = t('admin.user.methods.justificationRequired')
    return
  }
  acting.value = 'link'
  error.value = null
  notice.value = null
  try {
    const res = await api(`/api/op/registry/users/${encodeURIComponent(userId.value)}/links`, {
      method: 'POST',
      body: JSON.stringify({
        provider: linkProvider.value,
        provider_account_id: linkHandle.value.trim(),
        justification,
      }),
    })
    if (!res.ok) {
      const body = await res.json().catch(() => ({})) as { error?: string }
      error.value = body.error ?? t('admin.user.failed', { status: res.status })
      return
    }
    notice.value = t('admin.user.methods.linked', { provider: linkProvider.value, handle: linkHandle.value.trim() })
    linkHandle.value = ''
    linkJustification.value = ''
    await load()
  } catch {
    error.value = t('account.networkError')
  } finally {
    acting.value = null
  }
}

async function unlink(link: LinkRow) {
  if (acting.value) return
  acting.value = link.provider
  error.value = null
  notice.value = null
  try {
    const reason = (unlinkReason.value[link.provider] ?? '').trim()
    const res = await api(`/api/op/registry/users/${encodeURIComponent(userId.value)}/links/${encodeURIComponent(link.provider)}`, {
      method: 'DELETE',
      ...(reason ? { body: JSON.stringify({ reason }) } : {}),
    })
    if (!res.ok) {
      const body = await res.json().catch(() => ({})) as { error?: string }
      error.value = body.error ?? t('admin.user.failed', { status: res.status })
      return
    }
    notice.value = t('admin.user.methods.unlinked', { provider: link.provider })
    unlinkOpen.value[link.provider] = false
    await load()
  } catch {
    error.value = t('account.networkError')
  } finally {
    acting.value = null
  }
}

/** The admin's factor revocation (the slot's acts): the registry's own
 *  endpoints carry the act; the account's chain audits it. */
async function revokeFactor(kind: 'passkey' | 'totp', id: string) {
  if (acting.value) return
  acting.value = `${kind}-${id}`
  error.value = null
  notice.value = null
  try {
    const res = await api(`/api/op/registry/users/${encodeURIComponent(userId.value)}/factors/${kind === 'passkey' ? 'passkeys' : 'totp'}/${encodeURIComponent(id)}`, { method: 'DELETE' })
    if (!res.ok) {
      const body = await res.json().catch(() => ({})) as { error?: string }
      error.value = body.error ?? t('admin.user.failed', { status: res.status })
      return
    }
    notice.value = kind === 'passkey' ? t('admin.user.factors.revokedPasskey') : t('admin.user.factors.revokedTotp')
    await load()
  } catch {
    error.value = t('account.networkError')
  } finally {
    acting.value = null
  }
}

async function revokeSession(session: SessionRow) {
  if (acting.value) return
  acting.value = session.id
  error.value = null
  notice.value = null
  try {
    const res = await api(`/api/op/registry/users/${encodeURIComponent(userId.value)}/sessions/${encodeURIComponent(session.id)}/revoke`, { method: 'POST' })
    if (!res.ok) {
      const body = await res.json().catch(() => ({})) as { error?: string }
      error.value = body.error ?? t('admin.user.failed', { status: res.status })
      return
    }
    notice.value = t('admin.user.sessions.ended')
    await load()
  } catch {
    error.value = t('account.networkError')
  } finally {
    acting.value = null
  }
}

/** The light act: end EVERY live session of the account at once (the
 *  account itself is untouched; deactivation is the heavy act). */
async function revokeAllSessions() {
  if (acting.value) return
  acting.value = 'revoke-all'
  error.value = null
  notice.value = null
  try {
    const res = await api(`/api/op/registry/users/${encodeURIComponent(userId.value)}/sessions/revoke-all`, { method: 'POST' })
    if (!res.ok) {
      const body = await res.json().catch(() => ({})) as { error?: string }
      error.value = body.error ?? t('admin.user.failed', { status: res.status })
      return
    }
    const { revoked } = await res.json() as { revoked: number }
    notice.value = t('admin.user.sessions.endAllDone', { count: revoked })
    revokeAllArmed.value = false
    await load()
  } catch {
    error.value = t('account.networkError')
  } finally {
    acting.value = null
  }
}

/** The grant editor: open it for a fresh grant or prefilled from the
 *  row being edited. */
function openGrantForm(clientId?: string) {
  const existing = clientId ? detail.value?.clientRoles.find(a => a.clientId === clientId) : null
  grantClient.value = clientId ?? ''
  grantRoles.value = existing ? [...existing.roles] : []
  grantFormOpen.value = true
}

/** Switching the form's client prefills from that client's existing
 *  grant (a re-grant overwrites honestly — the PUT upserts). */
function grantClientChanged() {
  const existing = detail.value?.clientRoles.find(a => a.clientId === grantClient.value)
  grantRoles.value = existing ? [...existing.roles] : []
}

async function saveGrant() {
  if (acting.value || !grantClient.value) return
  acting.value = 'grant'
  error.value = null
  notice.value = null
  try {
    const roles = [...new Set(grantRoles.value)]
    const res = await api(`/api/op/accounts/${encodeURIComponent(userId.value)}/client-roles/${encodeURIComponent(grantClient.value)}`, {
      method: 'PUT',
      body: JSON.stringify({ roles }),
    })
    if (!res.ok) {
      const body = await res.json().catch(() => ({})) as { error?: string }
      error.value = body.error ?? t('admin.user.failed', { status: res.status })
      return
    }
    notice.value = roles.length
      ? t('admin.user.grants.granted', { client: grantClient.value, roles: roles.join(', ') })
      : t('admin.user.grants.grantedNone', { client: grantClient.value })
    grantFormOpen.value = false
    await load()
  } catch {
    error.value = t('account.networkError')
  } finally {
    acting.value = null
  }
}

/** Revoke the grant: the per-client row goes, the account-wide default
 *  applies there again (never a lockout — the account keeps its roles). */
async function revokeGrant(clientId: string) {
  if (acting.value) return
  acting.value = `revoke-${clientId}`
  error.value = null
  notice.value = null
  try {
    const res = await api(`/api/op/accounts/${encodeURIComponent(userId.value)}/client-roles/${encodeURIComponent(clientId)}`, { method: 'DELETE' })
    if (!res.ok) {
      const body = await res.json().catch(() => ({})) as { error?: string }
      error.value = body.error ?? t('admin.user.failed', { status: res.status })
      return
    }
    notice.value = t('admin.user.grants.revoked', { client: clientId })
    revokeArmed.value[clientId] = false
    await load()
  } catch {
    error.value = t('account.networkError')
  } finally {
    acting.value = null
  }
}

function copySetupUrl() {
  if (lastSetup.value) void navigator.clipboard.writeText(lastSetup.value.setupUrl)
}

/** One readable line per audit event (the account's own trail), in the
 *  active locale. */
function activityLine(event: AuditEvent): string {
  const meta = event.metadata ?? {}
  switch (event.action) {
    case 'account.invite': return t('admin.user.activity.action.account.invite', { email: String(meta.email ?? ''), role: String(meta.role ?? '') })
    case 'account.enrollment': return t('admin.user.activity.action.account.enrollment')
    case 'account.enrolled': return t('admin.user.activity.action.account.enrolled')
    case 'account.password': return t('admin.user.activity.action.account.password')
    case 'account.password_reset': return t('admin.user.activity.action.account.password_reset')
    case 'account.avatar': return t('admin.user.activity.action.account.avatar')
    case 'account.avatar_removed': return t('admin.user.activity.action.account.avatar_removed')
    case 'account.updated': {
      const before = (meta.before ?? {}) as Record<string, unknown>
      const after = (meta.after ?? {}) as Record<string, unknown>
      const fields = Object.keys(after).filter(k => JSON.stringify(before[k]) !== JSON.stringify(after[k])).join(', ')
      return t('admin.user.activity.action.account.updated', { fields })
    }
    case 'account.deleted': return t('admin.user.activity.action.account.deleted', { email: String(meta.email ?? '') })
    case 'account.session_revoked': return t(meta.by === 'administrator' ? 'admin.user.activity.action.account.session_revoked_admin' : 'admin.user.activity.action.account.session_revoked')
    case 'account.sessions_revoked': return t(meta.by === 'administrator' ? 'admin.user.activity.action.account.sessions_revoked_admin' : 'admin.user.activity.action.account.sessions_revoked', { count: Number(meta.count ?? 0) })
    case 'account.sign_in': return t('admin.user.activity.action.account.sign_in')
    case 'account.link_on_behalf': return t('admin.user.activity.action.account.link_on_behalf', { provider: String(meta.provider ?? ''), handle: String(meta.provider_account_id ?? ''), justification: String(meta.justification ?? '') })
    case 'account.link_removed': {
      const reason = typeof meta.reason === 'string' && meta.reason ? meta.reason : null
      return reason
        ? t('admin.user.activity.action.account.link_removed_reason', { provider: String(meta.provider ?? ''), reason })
        : t('admin.user.activity.action.account.link_removed', { provider: String(meta.provider ?? '') })
    }
    case 'account.client_roles': {
      const roles = (meta.roles as string[] ?? [])
      return t('admin.user.activity.action.account.client_roles', { client: String(meta.client_id ?? ''), roles: roles.length ? roles.join(', ') : t('admin.user.grants.noRoles') })
    }
    case 'account.client_roles_cleared': return t('admin.user.activity.action.account.client_roles_cleared', { client: String(meta.client_id ?? '') })
    case 'account.deactivated': return t('admin.user.activity.action.account.deactivated')
    case 'account.reactivated': return t('admin.user.activity.action.account.reactivated')
    case 'user.roles': return t('admin.user.activity.action.user.roles', { roles: (meta.roles as string[] ?? []).join(', ') })
    case 'user.deactivated': return t('admin.user.activity.action.user.deactivated')
    case 'user.reactivated': return t('admin.user.activity.action.user.reactivated')
    case 'upstream_sign_in': return t('admin.user.activity.action.upstream_sign_in', { provider: String(meta.provider ?? ''), handle: String(meta.handle ?? '') })
    case 'upstream_link': return t('admin.user.activity.action.upstream_link', { provider: String(meta.provider ?? ''), handle: String(meta.handle ?? '') })
    case 'upstream_unlink': return t('admin.user.activity.action.upstream_unlink', { provider: String(meta.provider ?? '') })
    default: return event.action
  }
}

onMounted(async () => {
  try {
    const session = await fetch('/api/auth/session', { credentials: 'include' })
    if (!session.ok) {
      window.location.assign(`/?redirect=${encodeURIComponent(`/op/admin/registry/users/${userId.value}`)}`)
      return
    }
    const me = await session.json() as { id: string }
    isSelf.value = me.id === userId.value
    const [rolesRes, providersRes, orgsRes] = await Promise.all([
      api('/api/users/roles'),
      api('/api/op/providers'),
      // TODO.identity/11: the registered orgs (the memberships section's
      // add-to-org + role-editor options).
      fetch('/api/op/organizations'),
    ])
    if (rolesRes.ok) roleMap.value = await rolesRes.json() as Record<string, string[]>
    if (providersRes.ok) providers.value = (await providersRes.json() as ProviderRow[]).filter(p => p.enabled)
    if (orgsRes.ok) registryOrgs.value = await orgsRes.json() as SelectableOrg[]
    await load()
  } catch (e) {
    error.value = (e as Error).message || t('account.networkError')
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
        <h1 class="text-xl font-serif font-bold text-slate-900 dark:text-white">{{ t('admin.user.title') }}</h1>
      </div>
      <div class="p-3 rounded-lg bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800">
        <p class="text-sm text-amber-800 dark:text-amber-300" data-testid="op-reg-user-forbidden">
          {{ t('admin.user.forbidden') }}
        </p>
      </div>
    </div>

    <div v-else-if="notFound" class="max-w-md mx-auto py-16 text-center">
      <h1 class="text-xl font-serif font-bold text-slate-900 dark:text-white mb-2">{{ t('admin.user.notFoundTitle') }}</h1>
      <p class="text-sm text-slate-500 dark:text-slate-400" data-testid="op-reg-user-notfound">
        {{ t('admin.user.notFound') }}
        <router-link to="/op/admin/registry" class="text-brand-600 dark:text-brand-300 hover:underline">{{ t('admin.user.back') }}</router-link>
      </p>
    </div>

    <div v-else-if="detail" data-testid="op-reg-user">
      <p class="mb-2 text-sm">
        <router-link to="/op/admin/registry" class="text-brand-600 hover:text-brand-700 dark:text-brand-300 dark:hover:text-brand-200 font-medium transition-colors" data-testid="op-reg-user-back">← {{ t('admin.user.back') }}</router-link>
      </p>
      <PageHeader :title="detail.account.name">
        <template #description>
          <span data-testid="op-reg-user-context">{{ detail.account.email }} · {{ branding.productName }}</span>
        </template>
      </PageHeader>
      <OpAdminNav current="registry" />

      <div v-if="error" class="mb-4 p-3 rounded-lg bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800">
        <p class="text-sm text-red-700 dark:text-red-300" data-testid="op-reg-user-error">{{ error }}</p>
      </div>
      <div v-if="notice" class="mb-4 p-3 rounded-lg bg-emerald-50 dark:bg-emerald-900/20 border border-emerald-200 dark:border-emerald-800">
        <p class="text-sm text-emerald-800 dark:text-emerald-300" data-testid="op-reg-user-notice">{{ notice }}</p>
      </div>

      <!-- The re-issued setup link, shown once -->
      <div v-if="lastSetup" class="mb-4 p-4 rounded-lg border border-brand-300 dark:border-brand-700 bg-brand-50 dark:bg-brand-900/20" data-testid="op-reg-setup-link-card">
        <p class="text-xs font-semibold text-brand-900 dark:text-brand-200 mb-1">
          {{ t('admin.user.setupLink.title') }}
          <span class="font-normal text-slate-500 dark:text-slate-400">({{ t('admin.user.setupLink.expires', { date: fmtStamp(lastSetup.expiresAt) }) }})</span>
        </p>
        <div class="flex items-center gap-2">
          <code class="flex-1 text-[11px] font-mono bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded px-2 py-1.5 truncate text-slate-700 dark:text-slate-300" data-testid="op-reg-setup-url">{{ lastSetup.setupUrl }}</code>
          <button
            type="button"
            data-testid="op-reg-setup-copy"
            class="shrink-0 px-3 py-1.5 text-xs font-semibold rounded-lg bg-brand-600 text-white hover:bg-brand-700 transition-colors"
            @click="copySetupUrl"
          >{{ t('admin.user.setupLink.copy') }}</button>
        </div>
        <p class="mt-1 text-[11px] text-slate-500 dark:text-slate-400">{{ t('admin.user.setupLink.note') }}</p>
      </div>

      <!-- 1. THE IDENTITY CARD: the profile, the lifecycle state, the
           role set, and the lifecycle acts. -->
      <section class="rounded-xl border border-slate-200/80 dark:border-slate-700 bg-white dark:bg-slate-800 p-6 mb-6" data-testid="op-reg-profile">
        <div class="flex items-start justify-between gap-4 mb-4">
          <div class="flex items-center gap-3 min-w-0">
            <img v-if="detail.account.avatarUrl" :src="detail.account.avatarUrl" :alt="detail.account.name" class="w-10 h-10 rounded-full object-cover shrink-0" data-testid="op-reg-profile-avatar" />
            <span v-else class="w-10 h-10 rounded-full bg-brand-100 dark:bg-brand-800 flex items-center justify-center text-sm font-bold text-brand-600 dark:text-brand-300 shrink-0" data-testid="op-reg-profile-initial">{{ accountInitial }}</span>
            <div class="min-w-0">
              <h2 class="text-base font-semibold text-slate-900 dark:text-white truncate" data-testid="op-reg-profile-name">{{ detail.account.name }}</h2>
              <p class="text-xs text-slate-500 dark:text-slate-400 truncate">{{ detail.account.email }}</p>
            </div>
          </div>
          <span class="shrink-0 text-[11px] px-2 py-0.5 rounded-full font-semibold" :class="stateBadgeClass(detail.account.state)" data-testid="op-reg-profile-status">
            {{ t(`admin.user.card.state.${detail.account.state}` as MessageKey) }}
          </span>
        </div>

        <p v-if="erased" class="mb-4 p-3 rounded-lg bg-slate-50 dark:bg-slate-900/40 border border-slate-200 dark:border-slate-700 text-xs text-slate-600 dark:text-slate-300" data-testid="op-reg-profile-erased">
          {{ t('admin.user.card.erasedNote', { date: detail.account.erasedAt ? fmtStamp(detail.account.erasedAt) : '—' }) }}
        </p>

        <dl class="grid sm:grid-cols-2 gap-x-6 gap-y-1 text-sm mb-4">
          <div><dt class="text-[11px] text-slate-400 dark:text-slate-500">{{ t('admin.user.card.nameLabel') }}</dt><dd class="text-slate-900 dark:text-white">{{ detail.account.name }}</dd></div>
          <div>
            <dt class="text-[11px] text-slate-400 dark:text-slate-500">{{ t('admin.user.card.emailLabel') }}</dt>
            <dd class="text-slate-900 dark:text-white" data-testid="op-reg-profile-email">
              {{ detail.account.email }}
              <span
                class="ml-1 text-[10px] px-1.5 py-0.5 rounded font-semibold"
                :class="detail.account.emailVerifiedAt ? 'bg-emerald-100 dark:bg-emerald-900/40 text-emerald-700 dark:text-emerald-300' : 'bg-slate-100 dark:bg-slate-700 text-slate-500 dark:text-slate-400'"
                data-testid="op-reg-profile-email-verified"
              >{{ t(detail.account.emailVerifiedAt ? 'account.profile.verified' : 'account.profile.unverified') }}</span>
            </dd>
          </div>
          <div>
            <dt class="text-[11px] text-slate-400 dark:text-slate-500">{{ t('admin.user.card.orgLabel') }}</dt>
            <dd class="text-slate-900 dark:text-white" data-testid="op-reg-profile-org">{{ detail.account.orgName ?? detail.account.orgId ?? t('admin.user.card.orgNone') }}</dd>
          </div>
          <div>
            <dt class="text-[11px] text-slate-400 dark:text-slate-500">{{ t('admin.user.card.idLabel') }}</dt>
            <dd class="text-slate-900 dark:text-white"><code class="text-[11px] font-mono" data-testid="op-reg-profile-id">{{ detail.account.id }}</code></dd>
          </div>
          <div>
            <dt class="text-[11px] text-slate-400 dark:text-slate-500">{{ t('admin.user.card.onRecord') }}</dt>
            <dd class="text-slate-900 dark:text-white" data-testid="op-reg-profile-since">{{ detail.account.firstSeenAt ? fmtStamp(detail.account.firstSeenAt) : t('admin.user.card.onRecordUnknown') }}</dd>
          </div>
          <div>
            <dt class="text-[11px] text-slate-400 dark:text-slate-500">{{ t('admin.user.card.lastSignIn') }}</dt>
            <dd class="text-slate-900 dark:text-white" data-testid="op-reg-profile-lastlogin">{{ detail.account.lastLogin ? fmtStamp(detail.account.lastLogin) : t('admin.user.card.lastSignInNever') }}</dd>
          </div>
        </dl>

        <!-- The role set (never on a tombstone) -->
        <fieldset v-if="!erased">
          <legend class="text-[11px] text-slate-400 dark:text-slate-500 mb-1">{{ t('admin.user.roles.legend') }}</legend>
          <div class="flex flex-wrap gap-x-4 gap-y-1 mb-2" data-testid="op-reg-roles-editor">
            <label v-for="r in Object.keys(roleMap)" :key="r" class="flex items-center gap-1.5 text-sm text-slate-700 dark:text-slate-300">
              <input
                v-model="checkedRoles"
                type="checkbox"
                :value="r"
                :data-testid="`op-reg-role-check-${r}`"
                class="rounded border-slate-300"
              />
              {{ r }}
            </label>
          </div>
          <div class="flex items-center gap-2">
            <label class="text-xs text-slate-500 dark:text-slate-400" for="op-reg-primary">{{ t('admin.user.roles.primary') }}</label>
            <select
              id="op-reg-primary"
              v-model="primaryRole"
              data-testid="op-reg-primary"
              class="px-2 py-1.5 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-xs text-slate-900 dark:text-white"
            >
              <option v-for="r in checkedRoles" :key="r" :value="r">{{ r }}</option>
            </select>
            <button
              :disabled="acting === 'roles'"
              data-testid="op-reg-roles-save"
              class="px-3 py-1.5 text-xs font-semibold rounded-lg bg-brand-600 text-white hover:bg-brand-700 transition-colors disabled:opacity-50"
              @click="saveRoles"
            >{{ t('admin.user.roles.save') }}</button>
          </div>
          <p class="mt-2 text-[11px] text-slate-400 dark:text-slate-500" data-testid="op-reg-roles-note">
            {{ t('admin.user.roles.note') }}
          </p>
        </fieldset>

        <!-- The lifecycle acts (never on a tombstone): the enrollment
             link, the honest deactivation, the erasure. -->
        <div v-if="!erased" class="mt-4 pt-4 border-t border-slate-100 dark:border-slate-700" data-testid="op-reg-actions">
          <h3 class="text-xs font-semibold text-slate-700 dark:text-slate-300 mb-2">{{ t('admin.user.acts.title') }}</h3>
          <div class="flex flex-wrap items-center gap-3">
            <button
              :disabled="acting === 'enrollment'"
              data-testid="op-reg-resend"
              class="px-3 py-1.5 text-xs font-semibold rounded-lg border border-slate-200 dark:border-slate-700 text-slate-600 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-700 transition-colors disabled:opacity-50"
              @click="resendSetup"
            >{{ t(detail.passwordSet ? 'admin.user.acts.issueReset' : 'admin.user.acts.resendSetup') }}</button>

            <template v-if="detail.account.active">
              <button
                v-if="!deactivateArmed"
                :disabled="isSelf"
                data-testid="op-reg-deactivate"
                class="px-3 py-1.5 text-xs font-semibold rounded-lg bg-red-600 text-white hover:bg-red-700 transition-colors disabled:opacity-50"
                @click="deactivateArmed = true"
              >{{ t('admin.user.acts.deactivate') }}</button>
              <template v-else>
                <button
                  :disabled="acting === 'active'"
                  data-testid="op-reg-deactivate-confirm"
                  class="px-3 py-1.5 text-xs font-semibold rounded-lg bg-red-600 text-white hover:bg-red-700 transition-colors disabled:opacity-50"
                  @click="setActive(false)"
                >{{ t('admin.user.acts.deactivateConfirm') }}</button>
                <button
                  class="px-3 py-1.5 text-xs rounded-lg border border-slate-200 dark:border-slate-700 text-slate-600 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-700 transition-colors"
                  @click="deactivateArmed = false"
                >{{ t('account.profile.cancel') }}</button>
              </template>
            </template>
            <button
              v-else
              :disabled="acting === 'active'"
              data-testid="op-reg-reactivate"
              class="px-3 py-1.5 text-xs font-semibold rounded-lg bg-emerald-600 text-white hover:bg-emerald-700 transition-colors disabled:opacity-50"
              @click="setActive(true)"
            >{{ t('admin.user.acts.reactivate') }}</button>
          </div>
          <p class="mt-2 text-[11px] text-slate-400 dark:text-slate-500">
            <span v-if="isSelf" data-testid="op-reg-self-deactivate-note">{{ t('admin.user.acts.selfNoDeactivate') }} </span>
            {{ t('admin.user.acts.deactivateNote') }}
          </p>

          <!-- The erasure (the offboarding runbook's delete path): the OP's
               own accounts only, two-step, irreversible, never on your own
               account (the lockout rule, server-enforced). -->
          <div v-if="isOpAccount" class="mt-4 pt-4 border-t border-slate-100 dark:border-slate-700">
            <div class="flex gap-2">
              <button
                v-if="!eraseArmed"
                :disabled="acting === 'erase' || isSelf"
                data-testid="op-reg-erase"
                class="px-3 py-1.5 text-xs font-semibold rounded-lg border border-red-300 dark:border-red-800 text-red-700 dark:text-red-300 hover:bg-red-50 dark:hover:bg-red-900/20 transition-colors disabled:opacity-50"
                @click="eraseArmed = true"
              >{{ t('admin.user.acts.erase') }}</button>
              <template v-else>
                <button
                  :disabled="acting === 'erase'"
                  data-testid="op-reg-erase-confirm"
                  class="px-3 py-1.5 text-xs font-semibold rounded-lg bg-red-600 text-white hover:bg-red-700 transition-colors disabled:opacity-50"
                  @click="eraseAccount"
                >{{ acting === 'erase' ? t('admin.user.acts.erasing') : t('admin.user.acts.eraseConfirm') }}</button>
                <button
                  class="px-3 py-1.5 text-xs rounded-lg border border-slate-200 dark:border-slate-700 text-slate-600 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-700 transition-colors"
                  @click="eraseArmed = false"
                >{{ t('account.profile.cancel') }}</button>
              </template>
            </div>
            <p v-if="eraseArmed" class="mt-2 text-[11px] text-red-600 dark:text-red-400" data-testid="op-reg-erase-warning">
              {{ t('admin.user.acts.eraseWarning') }}
            </p>
            <p v-if="isSelf" class="mt-1 text-[11px] text-slate-400 dark:text-slate-500" data-testid="op-reg-self-erase-note">{{ t('admin.user.acts.selfNoErase') }}</p>
          </div>
        </div>
      </section>

      <!-- 2. THE APPS THE ACCOUNT CAN ACCESS: the launcher's visibility
           rule read admin-side (the server computes it with the claims
           rule the token endpoint runs). -->
      <section v-if="!erased" class="rounded-xl border border-slate-200/80 dark:border-slate-700 bg-white dark:bg-slate-800 p-6 mb-6" data-testid="op-reg-apps">
        <h2 class="text-xs font-semibold uppercase tracking-wider text-slate-400 dark:text-slate-500 mb-1">{{ t('admin.user.apps.title') }}</h2>
        <p class="text-[11px] text-slate-400 dark:text-slate-500 mb-3">{{ t('admin.user.apps.description') }}</p>
        <p v-if="!detail.appAccess.length" class="text-sm text-slate-500 dark:text-slate-400" data-testid="op-reg-apps-empty">
          {{ t('admin.user.apps.empty') }}
          <router-link to="/op/admin/clients" class="text-brand-600 dark:text-brand-300 hover:underline">→ {{ t('admin.user.apps.consoleLink') }}</router-link>
        </p>
        <ul v-else class="space-y-2" data-testid="op-reg-apps-list">
          <li v-for="row in detail.appAccess" :key="row.clientId" class="rounded-lg border border-slate-200 dark:border-slate-700 px-3 py-2" :data-testid="`op-reg-app-${row.clientId}`">
            <div class="flex items-center justify-between gap-3">
              <p class="text-xs text-slate-700 dark:text-slate-200 min-w-0">
                <strong>{{ row.name }}</strong>
                <code class="ml-1 text-[11px] font-mono text-slate-400 dark:text-slate-500">{{ row.clientId }}</code>
              </p>
              <span
                class="shrink-0 text-[10px] px-1.5 py-0.5 rounded font-semibold"
                :class="row.canEnter ? 'bg-emerald-100 dark:bg-emerald-900/40 text-emerald-700 dark:text-emerald-300' : 'bg-slate-100 dark:bg-slate-700 text-slate-500 dark:text-slate-400'"
                :data-testid="`op-reg-app-badge-${row.clientId}`"
              >{{ t(row.canEnter ? 'admin.user.apps.badge.yes' : 'admin.user.apps.badge.no') }}</span>
            </div>
            <p class="mt-1 text-[11px] text-slate-500 dark:text-slate-400" :data-testid="`op-reg-app-reason-${row.clientId}`">{{ appReason(row) }}</p>
          </li>
        </ul>
        <p v-if="detail.appAccess.length" class="mt-3 text-[11px] text-slate-400 dark:text-slate-500" data-testid="op-reg-apps-footnote">
          {{ t('admin.user.apps.footnote') }}
        </p>
      </section>

      <!-- 3. THE SIGN-IN METHODS + FACTORS: the password state, the
           linked identities (unlink / the justified link on behalf),
           and the additional-factors slot the strong-auth wave fills. -->
      <section v-if="!erased" class="rounded-xl border border-slate-200/80 dark:border-slate-700 bg-white dark:bg-slate-800 p-6 mb-6" data-testid="op-reg-methods">
        <h2 class="text-xs font-semibold uppercase tracking-wider text-slate-400 dark:text-slate-500 mb-3">{{ t('admin.user.methods.title') }}</h2>
        <p class="text-xs text-slate-600 dark:text-slate-300 mb-3" data-testid="op-reg-password-state">
          {{ t(detail.passwordSet ? 'admin.user.methods.passwordSet' : 'admin.user.methods.passwordUnset') }}
        </p>

        <p v-if="!detail.links.length" class="text-sm text-slate-500 dark:text-slate-400" data-testid="op-reg-no-links">
          {{ t('admin.user.methods.noLinks') }}
        </p>
        <ul v-else class="space-y-2 mb-3" data-testid="op-reg-links">
          <li v-for="link in detail.links" :key="link.id" class="rounded-lg border border-slate-200 dark:border-slate-700 px-3 py-2" :data-testid="`op-reg-link-${link.provider}`">
            <div class="flex items-center justify-between gap-3">
              <p class="text-xs text-slate-600 dark:text-slate-300">
                <strong>{{ link.provider }}</strong> <code class="font-mono">{{ link.providerAccountId }}</code>
                · {{ link.linkedBy
                  ? t('admin.user.methods.linkedLine', { date: link.linkedAt.slice(0, 10), by: link.linkedBy })
                  : t('account.methods.linkedAt', { date: link.linkedAt.slice(0, 10) }) }}
              </p>
              <button
                :data-testid="`op-reg-unlink-open-${link.provider}`"
                class="shrink-0 text-xs font-medium text-red-600 dark:text-red-400 hover:underline"
                @click="unlinkOpen[link.provider] = !unlinkOpen[link.provider]"
              >{{ t('admin.user.methods.unlink') }}</button>
            </div>
            <div v-if="unlinkOpen[link.provider]" class="mt-2 flex items-center gap-2">
              <input
                v-model="unlinkReason[link.provider]"
                type="text"
                :data-testid="`op-reg-unlink-reason-${link.provider}`"
                class="flex-1 px-3 py-1.5 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-xs text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-500"
                :placeholder="t('admin.user.methods.unlinkReasonPlaceholder')"
              />
              <button
                :data-testid="`op-reg-unlink-${link.provider}`"
                :disabled="acting === link.provider"
                class="px-3 py-1.5 text-xs font-semibold rounded-lg bg-red-600 text-white hover:bg-red-700 transition-colors disabled:opacity-50"
                @click="unlink(link)"
              >{{ t('admin.user.methods.unlinkConfirm') }}</button>
            </div>
          </li>
        </ul>

        <!-- The administrator's link on behalf -->
        <div class="border-t border-slate-100 dark:border-slate-700 pt-3" data-testid="op-reg-link-form">
          <h3 class="text-xs font-semibold text-slate-700 dark:text-slate-300 mb-2">{{ t('admin.user.methods.linkTitle') }}</h3>
          <div class="grid sm:grid-cols-2 gap-2">
            <select
              v-model="linkProvider"
              data-testid="op-reg-link-provider"
              class="px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-500"
            >
              <option value="" disabled>{{ t('admin.user.methods.providerPlaceholder') }}</option>
              <option v-for="p in providers" :key="p.id" :value="p.id" :data-testid="`op-reg-link-provider-${p.id}`">{{ p.displayName }}</option>
            </select>
            <input
              v-model="linkHandle"
              type="text"
              data-testid="op-reg-link-handle"
              class="px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-500"
              :placeholder="t('admin.user.methods.handlePlaceholder')"
            />
            <input
              v-model="linkJustification"
              type="text"
              data-testid="op-reg-link-justification"
              class="sm:col-span-2 px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-500"
              :placeholder="t('admin.user.methods.justificationPlaceholder')"
            />
            <button
              :disabled="acting === 'link' || !linkProvider || !linkHandle.trim() || !linkJustification.trim()"
              data-testid="op-reg-link-submit"
              class="sm:col-span-2 py-2 rounded-lg text-sm font-medium bg-brand-600 text-white hover:bg-brand-700 transition-colors disabled:opacity-50"
              @click="linkOnBehalf"
            >{{ t('admin.user.methods.linkSubmit') }}</button>
          </div>
          <p class="mt-2 text-[11px] text-slate-400 dark:text-slate-500">
            {{ t('admin.user.methods.linkNote') }}
          </p>
        </div>

        <!-- The additional factors (TODO.identity-sso/02+03 fills the
             slot): the account's passkeys + authenticator apps with their
             names + created/last-used, each revocable by the admin; the
             recovery set's honest counts. The account's own last-method
             guard does not bind the administrator (the email reset is the
             recovery path behind a stranding). -->
        <div class="mt-4 border-t border-slate-100 dark:border-slate-700 pt-3" data-testid="op-reg-factors">
          <h3 class="text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1">{{ t('admin.user.factors.title') }}</h3>
          <template v-if="detail">
            <ul v-if="detail.factors.passkeys.length + detail.factors.totp.length > 0" class="space-y-1.5 mb-2" data-testid="op-reg-factors-list">
              <li
                v-for="pk in detail.factors.passkeys"
                :key="pk.credentialId"
                class="flex items-center justify-between rounded-lg border border-slate-100 dark:border-slate-700 px-3 py-2"
                :data-testid="`op-reg-factor-passkey-${pk.credentialId}`"
              >
                <div class="min-w-0">
                  <p class="text-xs font-medium text-slate-800 dark:text-slate-200">{{ pk.name }} <span class="text-slate-400 font-normal">· passkey</span></p>
                  <p class="text-[11px] text-slate-400 dark:text-slate-500">
                    {{ t('admin.user.factors.added', { date: fmtStamp(pk.createdAt) }) }} ·
                    {{ pk.lastUsedAt ? t('admin.user.factors.lastUsed', { date: fmtStamp(pk.lastUsedAt) }) : t('admin.user.factors.neverUsed') }}
                  </p>
                </div>
                <button
                  type="button"
                  :disabled="acting === `passkey-${pk.credentialId}`"
                  :data-testid="`op-reg-factor-passkey-${pk.credentialId}-revoke`"
                  class="shrink-0 px-2.5 py-1 rounded-lg text-[11px] font-medium border border-slate-200 dark:border-slate-600 text-slate-600 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-700 transition-colors disabled:opacity-50"
                  @click="revokeFactor('passkey', pk.credentialId)"
                >{{ acting === `passkey-${pk.credentialId}` ? t('admin.user.factors.revoking') : t('admin.user.factors.revoke') }}</button>
              </li>
              <li
                v-for="app in detail.factors.totp"
                :key="app.id"
                class="flex items-center justify-between rounded-lg border border-slate-100 dark:border-slate-700 px-3 py-2"
                :data-testid="`op-reg-factor-totp-${app.id}`"
              >
                <div class="min-w-0">
                  <p class="text-xs font-medium text-slate-800 dark:text-slate-200">{{ app.name }} <span class="text-slate-400 font-normal">· {{ t('admin.user.factors.totpKind') }}</span></p>
                  <p class="text-[11px] text-slate-400 dark:text-slate-500">
                    {{ t('admin.user.factors.added', { date: fmtStamp(app.createdAt) }) }} ·
                    {{ app.lastUsedAt ? t('admin.user.factors.lastUsed', { date: fmtStamp(app.lastUsedAt) }) : t('admin.user.factors.neverUsed') }}
                  </p>
                </div>
                <button
                  type="button"
                  :disabled="acting === `totp-${app.id}`"
                  :data-testid="`op-reg-factor-totp-${app.id}-revoke`"
                  class="shrink-0 px-2.5 py-1 rounded-lg text-[11px] font-medium border border-slate-200 dark:border-slate-600 text-slate-600 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-700 transition-colors disabled:opacity-50"
                  @click="revokeFactor('totp', app.id)"
                >{{ acting === `totp-${app.id}` ? t('admin.user.factors.revoking') : t('admin.user.factors.revoke') }}</button>
              </li>
            </ul>
            <p v-else class="text-[11px] text-slate-400 dark:text-slate-500 mb-2" data-testid="op-reg-factors-empty">{{ t('admin.user.factors.empty') }}</p>
            <p v-if="detail.factors.recoveryCodes.total > 0" class="text-[11px] text-slate-400 dark:text-slate-500" data-testid="op-reg-factors-recovery">
              {{ t('admin.user.factors.recoveryState', { remaining: detail.factors.recoveryCodes.remaining, total: detail.factors.recoveryCodes.total, date: fmtStamp(detail.factors.recoveryCodes.createdAt!) }) }}
            </p>
          </template>
        </div>
      </section>

      <!-- ════════════════════════════════════════════════════════════
           THE ORGANIZATIONS (TODO.identity/11 — the multi-org
           membership model, this wave fills the slot): the account's
           memberships with their per-org role sets + the lifecycle
           states, the identity admin's acts (edit the per-org roles,
           disable/re-activate, add to another registered org — the
           invitation waits on the holder's console). Its own section
           card, its own testids, per the slot's contract.
           ════════════════════════════════════════════════════════════ -->
      <section v-if="!erased" class="rounded-xl border border-slate-200/80 dark:border-slate-700 bg-white dark:bg-slate-800 p-6 mb-6" data-testid="op-reg-memberships">
        <h2 class="text-xs font-semibold uppercase tracking-wider text-slate-400 dark:text-slate-500 mb-1">{{ t('admin.user.memberships.title') }}</h2>
        <p class="text-xs text-slate-500 dark:text-slate-400 mb-3">{{ t('admin.user.memberships.description') }}</p>
        <p v-if="!memberships.length" class="text-sm text-slate-500 dark:text-slate-400" data-testid="op-reg-memberships-empty">
          {{ t('admin.user.memberships.empty') }}
        </p>
        <ul v-else class="space-y-2 mb-2" data-testid="op-reg-memberships-list">
          <li
            v-for="m in memberships"
            :key="m.orgId"
            class="rounded-lg border border-slate-200 dark:border-slate-700 px-3 py-2"
            :data-testid="`op-reg-membership-${m.orgId}`"
          >
            <div class="flex items-center justify-between gap-3">
              <div class="min-w-0">
                <p class="text-sm font-medium text-slate-900 dark:text-white">
                  <router-link
                    :to="`/op/admin/registry/orgs/${m.orgId}`"
                    class="hover:underline text-brand-700 dark:text-brand-300"
                    :data-testid="`op-reg-membership-org-${m.orgId}`"
                  >{{ m.orgName }}</router-link>
                  <span v-if="m.isPrimary" class="ml-1 text-[10px] px-1.5 py-0.5 rounded bg-slate-100 dark:bg-slate-700 text-slate-500 dark:text-slate-300 font-semibold uppercase tracking-wider">{{ t('admin.user.memberships.primaryBadge') }}</span>
                  <span v-if="m.state === 'invited'" class="ml-1 text-[10px] px-1.5 py-0.5 rounded bg-amber-100 dark:bg-amber-900/30 text-amber-700 dark:text-amber-300 font-semibold uppercase tracking-wider" :data-testid="`op-reg-membership-invited-${m.orgId}`">{{ t('admin.user.memberships.stateInvited') }}</span>
                  <span v-if="m.state === 'disabled'" class="ml-1 text-[10px] px-1.5 py-0.5 rounded bg-red-100 dark:bg-red-900/40 text-red-600 dark:text-red-400 font-semibold uppercase tracking-wider" :data-testid="`op-reg-membership-disabled-${m.orgId}`">{{ t('admin.user.memberships.stateDisabled') }}</span>
                </p>
                <p class="text-[11px] text-slate-400 dark:text-slate-500" :data-testid="`op-reg-membership-roles-${m.orgId}`">
                  {{ m.roles.length ? m.roles.join(', ') : t('admin.user.memberships.noRoles') }}
                  <template v-if="m.state === 'invited' && m.invitedBy"> · {{ t('admin.user.memberships.invitedBy', { by: m.invitedBy }) }}</template>
                  <template v-if="m.state === 'disabled' && m.disabledBy"> · {{ t('admin.user.memberships.disabledBy', { by: m.disabledBy }) }}</template>
                </p>
              </div>
              <div class="shrink-0 flex items-center gap-3 text-xs font-medium">
                <button
                  :data-testid="`op-reg-membership-roles-edit-${m.orgId}`"
                  :disabled="acting === `roles-${m.orgId}`"
                  class="text-brand-600 dark:text-brand-300 hover:underline disabled:opacity-50"
                  @click="openMemberRoles(m)"
                >{{ memberRolesOpen === m.orgId ? t('admin.user.memberships.rolesClose') : t('admin.user.memberships.rolesEdit') }}</button>
                <button
                  v-if="m.state !== 'invited' && !(isSelf && m.state === 'active')"
                  :data-testid="`op-reg-membership-toggle-${m.orgId}`"
                  :disabled="acting === `state-${m.orgId}`"
                  class="hover:underline disabled:opacity-50"
                  :class="m.state === 'active' ? 'text-red-600 dark:text-red-400' : 'text-emerald-600 dark:text-emerald-400'"
                  @click="setMemberState(m, m.state === 'active' ? 'disabled' : 'active')"
                >{{ m.state === 'active' ? t('admin.user.memberships.disable') : t('admin.user.memberships.reactivate') }}</button>
              </div>
            </div>
            <div v-if="memberRolesOpen === m.orgId" class="mt-2 border-t border-slate-100 dark:border-slate-700 pt-2" :data-testid="`op-reg-membership-editor-${m.orgId}`">
              <div class="flex flex-wrap gap-x-4 gap-y-1 mb-2">
                <label v-for="r in memberRoleOptions(m.orgId)" :key="r" class="flex items-center gap-1.5 text-xs text-slate-700 dark:text-slate-300">
                  <input
                    type="checkbox"
                    :value="r"
                    v-model="memberRoleDrafts[m.orgId]"
                    :data-testid="`op-reg-membership-check-${m.orgId}-${r}`"
                    class="rounded border-slate-300 dark:border-slate-600 text-brand-600 focus:ring-brand-500"
                  />
                  {{ r }}
                </label>
              </div>
              <button
                :disabled="acting === `roles-${m.orgId}`"
                :data-testid="`op-reg-membership-save-${m.orgId}`"
                class="px-3 py-1.5 rounded-lg text-xs font-medium bg-brand-600 text-white hover:bg-brand-700 transition-colors disabled:opacity-50"
                @click="saveMemberRoles(m)"
              >{{ t('admin.user.memberships.rolesSave') }}</button>
            </div>
          </li>
        </ul>

        <!-- Add to another registered org (the membership invite). -->
        <div v-if="addableOrgs.length" class="mt-3 border-t border-slate-100 dark:border-slate-700 pt-3" data-testid="op-reg-membership-add">
          <h3 class="text-xs font-semibold text-slate-700 dark:text-slate-300 mb-2">{{ t('admin.user.memberships.addTitle') }}</h3>
          <div class="grid sm:grid-cols-2 gap-2">
            <select
              v-model="addOrgId"
              data-testid="op-reg-membership-add-org"
              class="px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-500"
              @change="addOrgRoles = []"
            >
              <option value="" disabled>{{ t('admin.user.memberships.addOrg') }}</option>
              <option v-for="o in addableOrgs" :key="o.id" :value="o.id" :data-testid="`op-reg-membership-add-option-${o.id}`">{{ o.name }}</option>
            </select>
            <button
              :disabled="acting === 'membership-add' || !addOrgId"
              data-testid="op-reg-membership-add-submit"
              class="py-2 rounded-lg text-sm font-medium bg-brand-600 text-white hover:bg-brand-700 transition-colors disabled:opacity-50"
              @click="addMembership"
            >{{ acting === 'membership-add' ? t('admin.user.memberships.addBusy') : t('admin.user.memberships.addSubmit') }}</button>
          </div>
          <div v-if="addOrgId" class="mt-2 flex flex-wrap gap-x-4 gap-y-1">
            <label v-for="r in addOrgRoleOptions" :key="r" class="flex items-center gap-1.5 text-xs text-slate-700 dark:text-slate-300">
              <input
                type="checkbox"
                :value="r"
                v-model="addOrgRoles"
                :data-testid="`op-reg-membership-add-role-${r}`"
                class="rounded border-slate-300 dark:border-slate-600 text-brand-600 focus:ring-brand-500"
              />
              {{ r }}
            </label>
          </div>
          <p class="mt-2 text-[11px] text-slate-400 dark:text-slate-500">{{ t('admin.user.memberships.addNote') }}</p>
        </div>
      </section>

      <!-- 4. THE LIVE SESSIONS: per-session revoke + END ALL (the light
           act) vs deactivation (the heavy act, the identity card). -->
      <section v-if="!erased" class="rounded-xl border border-slate-200/80 dark:border-slate-700 bg-white dark:bg-slate-800 p-6 mb-6" data-testid="op-reg-sessions">
        <h2 class="text-xs font-semibold uppercase tracking-wider text-slate-400 dark:text-slate-500 mb-3">{{ t('admin.user.sessions.title') }}</h2>
        <p v-if="!detail.sessions.length" class="text-sm text-slate-500 dark:text-slate-400" data-testid="op-reg-sessions-empty">
          {{ t('admin.user.sessions.empty') }}
        </p>
        <template v-else>
          <ul class="space-y-2 mb-3" data-testid="op-reg-sessions-list">
            <li v-for="s in detail.sessions" :key="s.id" class="rounded-lg border border-slate-200 dark:border-slate-700 px-3 py-2" :data-testid="`op-reg-session-${s.id}`">
              <div class="flex items-center justify-between gap-3">
                <p class="text-xs text-slate-600 dark:text-slate-300">
                  {{ t('account.sessions.signedIn', { date: fmtStamp(s.createdAt) }) }} · {{ t('account.sessions.expires', { date: fmtStamp(s.expiresAt) }) }}
                  · {{ t('account.sessions.lastActive', { date: s.lastSeenAt ? fmtStamp(s.lastSeenAt) : t('account.sessions.notRecorded') }) }}
                </p>
                <button
                  :data-testid="`op-reg-revoke-${s.id}`"
                  :disabled="acting === s.id"
                  class="shrink-0 text-xs font-medium text-red-600 dark:text-red-400 hover:underline disabled:opacity-50"
                  @click="revokeSession(s)"
                >{{ t('admin.user.sessions.end') }}</button>
              </div>
              <p v-if="s.userAgent || s.ip" class="mt-0.5 text-[11px] text-slate-400 dark:text-slate-500 truncate">
                {{ s.userAgent ?? t('account.sessions.notRecorded') }}<template v-if="s.ip"> · {{ s.ip }}</template>
              </p>
            </li>
          </ul>
          <div class="border-t border-slate-100 dark:border-slate-700 pt-3">
            <div class="flex items-center gap-2">
              <button
                v-if="!revokeAllArmed"
                data-testid="op-reg-revoke-all"
                class="px-3 py-1.5 text-xs font-semibold rounded-lg border border-slate-200 dark:border-slate-700 text-slate-600 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-700 transition-colors"
                @click="revokeAllArmed = true"
              >{{ t('admin.user.sessions.endAll') }}</button>
              <template v-else>
                <button
                  :disabled="acting === 'revoke-all'"
                  data-testid="op-reg-revoke-all-confirm"
                  class="px-3 py-1.5 text-xs font-semibold rounded-lg bg-red-600 text-white hover:bg-red-700 transition-colors disabled:opacity-50"
                  @click="revokeAllSessions"
                >{{ t('admin.user.sessions.endAllConfirm') }}</button>
                <button
                  class="px-3 py-1.5 text-xs rounded-lg border border-slate-200 dark:border-slate-700 text-slate-600 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-700 transition-colors"
                  @click="revokeAllArmed = false"
                >{{ t('account.profile.cancel') }}</button>
              </template>
            </div>
            <p class="mt-2 text-[11px] text-slate-400 dark:text-slate-500">
              <span v-if="isSelf" class="text-amber-600 dark:text-amber-400" data-testid="op-reg-revoke-all-self">{{ t('admin.user.sessions.selfWarn') }} </span>
              {{ t('admin.user.sessions.endAllNote') }}
            </p>
          </div>
        </template>
      </section>

      <!-- 5. THE PER-CLIENT ROLE GRANTS: grant / edit / revoke on this
           page (the writes ride routes/op-accounts.ts, audited). -->
      <section v-if="!erased" class="rounded-xl border border-slate-200/80 dark:border-slate-700 bg-white dark:bg-slate-800 p-6 mb-6" data-testid="op-reg-grants">
        <h2 class="text-xs font-semibold uppercase tracking-wider text-slate-400 dark:text-slate-500 mb-1">{{ t('admin.user.grants.title') }}</h2>
        <p class="text-[11px] text-slate-400 dark:text-slate-500 mb-3">{{ t('admin.user.grants.description') }}</p>

        <p v-if="!detail.clientRoles.length" class="text-sm text-slate-500 dark:text-slate-400 mb-3" data-testid="op-reg-client-roles-empty">
          {{ t('admin.user.grants.empty') }}
        </p>
        <ul v-else class="space-y-2 mb-3" data-testid="op-reg-grants-list">
          <li v-for="a in detail.clientRoles" :key="a.clientId" class="rounded-lg border border-slate-200 dark:border-slate-700 px-3 py-2" :data-testid="`op-reg-grant-${a.clientId}`">
            <div class="flex items-center justify-between gap-3">
              <p class="text-xs text-slate-600 dark:text-slate-300">
                <strong>{{ clientName(a.clientId) }}</strong>:
                {{ a.roles.length ? a.roles.join(', ') : t('admin.user.grants.noRoles') }}
                <span class="text-slate-400 dark:text-slate-500">
                  — {{ a.assignedBy ? t('admin.user.grants.assignedBy', { by: a.assignedBy, date: a.updatedAt.slice(0, 10) }) : t('admin.user.grants.assignedOn', { date: a.updatedAt.slice(0, 10) }) }}
                </span>
              </p>
              <div class="flex items-center gap-3 shrink-0">
                <button
                  :data-testid="`op-reg-grant-edit-${a.clientId}`"
                  class="text-xs font-medium text-brand-600 dark:text-brand-300 hover:underline"
                  @click="openGrantForm(a.clientId)"
                >{{ t('admin.user.grants.reassign') }}</button>
                <button
                  :data-testid="`op-reg-grant-revoke-${a.clientId}`"
                  class="text-xs font-medium text-red-600 dark:text-red-400 hover:underline"
                  @click="revokeArmed[a.clientId] = !revokeArmed[a.clientId]"
                >{{ t('admin.user.grants.revoke') }}</button>
              </div>
            </div>
            <div v-if="revokeArmed[a.clientId]" class="mt-2 flex items-center gap-2">
              <button
                :data-testid="`op-reg-grant-revoke-confirm-${a.clientId}`"
                :disabled="acting === `revoke-${a.clientId}`"
                class="px-3 py-1.5 text-xs font-semibold rounded-lg bg-red-600 text-white hover:bg-red-700 transition-colors disabled:opacity-50"
                @click="revokeGrant(a.clientId)"
              >{{ t('admin.user.grants.revokeConfirm') }}</button>
              <button
                class="px-3 py-1.5 text-xs rounded-lg border border-slate-200 dark:border-slate-700 text-slate-600 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-700 transition-colors"
                @click="revokeArmed[a.clientId] = false"
              >{{ t('account.profile.cancel') }}</button>
            </div>
          </li>
        </ul>

        <button
          v-if="!grantFormOpen && grantClients.length"
          data-testid="op-reg-grant-open"
          class="px-3 py-1.5 text-xs font-semibold rounded-lg border border-slate-200 dark:border-slate-700 text-slate-600 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-700 transition-colors"
          @click="openGrantForm()"
        >{{ t('admin.user.grants.grant') }}</button>

        <div v-if="grantFormOpen" class="rounded-lg border border-brand-200 dark:border-brand-800 bg-brand-50/50 dark:bg-brand-900/10 p-3" data-testid="op-reg-grant-form">
          <div class="grid sm:grid-cols-2 gap-2 mb-2">
            <label class="text-xs text-slate-500 dark:text-slate-400">
              {{ t('admin.user.grants.clientLabel') }}
              <select
                v-model="grantClient"
                data-testid="op-reg-grant-client"
                class="mt-1 w-full px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-500"
                @change="grantClientChanged"
              >
                <option value="" disabled>{{ t('admin.user.grants.clientLabel') }}…</option>
                <option v-for="cl in grantClients" :key="cl.clientId" :value="cl.clientId" :data-testid="`op-reg-grant-client-${cl.clientId}`">{{ cl.name }} ({{ cl.clientId }})</option>
              </select>
            </label>
            <fieldset v-if="grantClient">
              <legend class="text-xs text-slate-500 dark:text-slate-400 mb-1">{{ t('admin.user.grants.rolesLabel') }}</legend>
              <div class="flex flex-wrap gap-x-4 gap-y-1">
                <label v-for="r in Object.keys(roleMap)" :key="r" class="flex items-center gap-1.5 text-sm" :class="grantRoleEnabled(r) ? 'text-slate-700 dark:text-slate-300' : 'text-slate-400 dark:text-slate-600'">
                  <input
                    v-model="grantRoles"
                    type="checkbox"
                    :value="r"
                    :disabled="!grantRoleEnabled(r)"
                    :data-testid="`op-reg-grant-role-${r}`"
                    class="rounded border-slate-300"
                  />
                  {{ r }}
                </label>
              </div>
              <p v-if="grantAllowlist" class="mt-1 text-[11px] text-slate-400 dark:text-slate-500" data-testid="op-reg-grant-allowlist-note">
                {{ t('admin.user.grants.allowlistNote', { roles: grantAllowlist.join(', ') }) }}
              </p>
            </fieldset>
          </div>
          <div class="flex items-center gap-2">
            <button
              :disabled="acting === 'grant' || !grantClient"
              data-testid="op-reg-grant-save"
              class="px-3 py-1.5 text-xs font-semibold rounded-lg bg-brand-600 text-white hover:bg-brand-700 transition-colors disabled:opacity-50"
              @click="saveGrant"
            >{{ t('admin.user.grants.save') }}</button>
            <button
              class="px-3 py-1.5 text-xs rounded-lg border border-slate-200 dark:border-slate-700 text-slate-600 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-700 transition-colors"
              @click="grantFormOpen = false"
            >{{ t('account.profile.cancel') }}</button>
          </div>
        </div>

        <p class="mt-3 text-[11px] text-slate-400 dark:text-slate-500" data-testid="op-reg-grants-seam">
          {{ t('admin.user.grants.policyNote') }}
          <router-link to="/op/admin/clients" class="text-brand-600 dark:text-brand-300 hover:underline" data-testid="op-reg-grants-policy-link">→ {{ t('admin.user.apps.consoleLink') }}</router-link>
        </p>
      </section>

      <!-- 6. THE AUDIT TRAIL: the account's own events, newest first,
           honestly paged (the total is in every answer). -->
      <section class="rounded-xl border border-slate-200/80 dark:border-slate-700 bg-white dark:bg-slate-800 p-6" data-testid="op-reg-activity">
        <h2 class="text-xs font-semibold uppercase tracking-wider text-slate-400 dark:text-slate-500 mb-3">
          {{ t('admin.user.activity.title') }}
          <router-link to="/op/admin/activity" class="ml-2 font-normal normal-case text-brand-600 dark:text-brand-300 hover:underline">{{ t('admin.user.activity.feedLink') }} →</router-link>
        </h2>
        <p v-if="!activityEvents.length" class="text-sm text-slate-500 dark:text-slate-400" data-testid="op-reg-activity-empty">
          {{ t('admin.user.activity.empty') }}
        </p>
        <template v-else>
          <ul class="space-y-1" data-testid="op-reg-activity-list">
            <li v-for="event in activityEvents" :key="event.id" class="text-[11px] text-slate-500 dark:text-slate-400" :data-testid="`op-reg-event-${event.id}`">
              {{ fmtStamp(event.timestamp) }} — {{ event.user_name ?? t('admin.user.activity.actorAccount') }}: {{ activityLine(event) }}
            </li>
          </ul>
          <div class="mt-3 flex items-center gap-3">
            <button
              v-if="activityEvents.length < activityTotal"
              :disabled="activityBusy"
              data-testid="op-reg-activity-more"
              class="px-3 py-1.5 text-xs font-semibold rounded-lg border border-slate-200 dark:border-slate-700 text-slate-600 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-700 transition-colors disabled:opacity-50"
              @click="loadMoreActivity"
            >{{ t('admin.user.activity.more', { count: activityTotal - activityEvents.length }) }}</button>
            <span class="text-[11px] text-slate-400 dark:text-slate-500" data-testid="op-reg-activity-showing">
              {{ t('admin.user.activity.showing', { shown: activityEvents.length, total: activityTotal }) }}
            </span>
          </div>
        </template>
      </section>
    </div>
  </div>
</template>
