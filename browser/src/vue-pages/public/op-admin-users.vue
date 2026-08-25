<script setup lang="ts">
// ═══════════════════════════════════════════════════════════════════
// The organization-administration console (TODO.identity/10) — the OP's
// account-topology surface, two audiences:
//
//   - the ORGANIZATION ADMINISTRATOR (org.users.manage, org-scoped):
//     their org's join-request queue (approve → the invite is issued,
//     the TODO.identity/02 enrollment seam; refuse with a reason) and
//     their org's people (the org-scoped users slice: invite a
//     colleague, reassign the kind-bounded roles, deactivate);
//   - the SCHEME OPERATOR (users.manage — BIML): the NEW ORGANIZATIONS
//     queue (a request naming an unregistered org — verify the
//     participation, then approve onto the now-registered org to create
//     its administrator, or refuse honestly with the participation
//     pointer), every queue's oversight, and the org-admin creation
//     form (one admin per registered org — the eligibility rule).
//
// Every scoping rule is SERVER-ENFORCED (routes/users.ts +
// routes/op-join.ts); this page only renders what the APIs answer.
// ═══════════════════════════════════════════════════════════════════
import { computed, onMounted, ref } from 'vue'
import PageHeader from '../../components/PageHeader.vue'
import OpAdminNav from '../../components/OpAdminNav.vue'
import { useBranding } from '../../branding'
import { APP_ROLES } from '@oimlsmart/platform-server/vocab'

interface JoinRequestRow {
  id: string
  name: string
  email: string
  orgId: string | null
  orgName: string | null
  orgKind: string | null
  orgNameText: string | null
  requestedRole: string
  note: string | null
  status: 'pending' | 'approved' | 'refused'
  decidedBy: string | null
  decidedAt: string | null
  refusalReason: string | null
  emailDomainMatch: boolean | null
  createdAt: string
}

interface UserRow {
  id: string
  email: string
  name: string
  role: string
  roles: string[]
  orgId: string | null
  active: boolean
  provider: string
  lastLogin: string | null
}

interface SelectorOrg {
  id: string
  name: string
  shortName: string
  kind: string
  country: string
  roles: string[]
}

/** A member of the org (GET /api/op/org-memberships, TODO.identity/11):
 *  the membership (per-org roles + lifecycle state) joined with the
 *  account's display fields. The org grant's slice carries PRIMARY and
 *  SECONDARY memberships alike (an account belonging to several orgs
 *  shows here with THIS org's role set). */
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
  disabledAt: string | null
  disabledBy: string | null
}

// ── TODO.identity/03 — the identity registry (the wide grant's surface) ──

/** A registry account row (GET /api/op/accounts): EVERY sign-in account
 *  on the identity service (TODO.identity-features/06 — the OP's own
 *  password accounts AND the seed-managed demo cast, marked by
 *  `provider`) with the per-client role assignments and the last
 *  sign-in. The registry's ACTS (edit, client roles, setup link,
 *  deactivation) serve the OP's own accounts only — the server answers
 *  404 for the demo cast, so the row's buttons render for
 *  `provider === 'password'` only. */
interface RegistryAccount {
  id: string
  email: string
  name: string
  role: string
  roles: string[]
  orgId: string | null
  active: boolean
  provider: string
  passwordSet: boolean
  links: Array<{ provider: string; linkedAt: string; linkedBy: string | null }>
  lastSignIn: string | null
  clientRoles: Array<{ clientId: string; roles: string[]; assignedBy: string | null; updatedAt: string | null }>
}

/** A registered relying party (GET /api/op/clients — the public view). */
interface RegistryClient {
  clientId: string
  name: string
  claimsPolicy: { claims: string[]; roles?: string[] } | null
  status: 'active' | 'disabled'
}

const { branding } = useBranding()

const loading = ref(true)
const error = ref<string | null>(null)
const notice = ref<string | null>(null)
const account = ref<{ id: string; name: string; email: string; roles: string[] } | null>(null)

/** The caller's queue grant (the API's envelope): 'wide' = the scheme
 *  operator (BIML), 'org' = the organization administrator. */
const grant = ref<'wide' | 'org' | null>(null)
const grantOrgId = ref<string | null>(null)
const grantOrgName = ref<string | null>(null)

const requests = ref<JoinRequestRow[]>([])
const unregistered = ref<JoinRequestRow[]>([])
const users = ref<UserRow[]>([])
const roleMap = ref<Record<string, string[]>>({})
const registryOrgs = ref<SelectorOrg[]>([])

// ── TODO.identity/11 — the org's MEMBERSHIPS (the people slice is
//    membership-driven: per-org roles + the lifecycle states) ──
const members = ref<MemberRow[]>([])
/** The per-member roles editor: userId → the checked roles. */
const memberRolesOpen = ref<string | null>(null)
const memberRoleDrafts = ref<Record<string, string[]>>({})
/** The "add an existing account" form (the membership invite — the
 *  holder accepts from their account console). */
const addEmail = ref('')
const addRoleChecks = ref<string[]>([])

const acting = ref<string | null>(null)
/** Per-request refusal drafts + open state. */
const refuseOpen = ref<Record<string, boolean>>({})
const refuseReason = ref<Record<string, string>>({})
/** Per-unregistered-request approval org pick. */
const approveOrgId = ref<Record<string, string>>({})
/** The mail outcome of an invite/reset send (TODO.identity/09): sent,
 *  the posture (send_email / https / console), the error when it failed. */
interface InviteMail {
  posture: string
  sent: boolean
  error: string | null
}

/** The ONE-TIME setup link of the last issued invite (02's enrollment).
 *  TODO.identity/09: the link is EMAILED when a mail provider is
 *  configured (the mail block says so) and copied out-of-band when not
 *  (the console posture — the card says it plainly). Shown once,
 *  cleared on the next action. */
const lastInvite = ref<{ email: string; name: string; setupUrl: string; expiresAt: string; mail?: InviteMail | null } | null>(null)

// The invite forms.
const inviteName = ref('')
const inviteEmail = ref('')
const inviteRole = ref('')
const orgAdminName = ref('')
const orgAdminEmail = ref('')
const orgAdminOrg = ref('')

// ── the identity registry (TODO.identity/03) — the wide grant's
//    account surface: invite, edit, per-client roles, deactivation ──
const registry = ref<RegistryAccount[]>([])
const clients = ref<RegistryClient[]>([])
const regInviteName = ref('')
const regInviteEmail = ref('')
const regInviteRole = ref('viewer')
const regInviteOrg = ref('')
/** The inline edit: the account being edited + the draft fields. */
const editingId = ref<string | null>(null)
const editName = ref('')
const editEmail = ref('')
/** The per-client roles editor (one account at a time); the working
 *  drafts key `${accountId}::${clientId}` → the checked roles. */
const rolesEditorFor = ref<string | null>(null)
const clientRoleDrafts = ref<Record<string, string[]>>({})

const isWide = computed(() => grant.value === 'wide')
/** The first section's pending rows: the org grant's own queue; the
 *  scheme operator sees the ORG-BOUND requests here (the unregistered
 *  ones live in the new-organizations queue — they need the register
 *  picker, never a bare approve). */
const pendingOrgRequests = computed(() =>
  requests.value.filter(r => r.status === 'pending' && (grant.value === 'org' || r.orgId !== null)),
)
const decidedRequests = computed(() => requests.value.filter(r => r.status !== 'pending'))
const pendingUnregistered = computed(() => unregistered.value.filter(r => r.status === 'pending'))

/** The org-admin accounts the scheme operator can see (one per
 *  registered org — the eligibility rule's visible state). */
const orgAdminAccounts = computed(() => users.value.filter(u => u.roles.includes('org_admin')))

async function api(path: string, init?: RequestInit): Promise<Response> {
  return fetch(path, {
    credentials: 'include',
    ...(init?.body ? { headers: { 'content-type': 'application/json' } } : {}),
    ...init,
  })
}

async function load(): Promise<void> {
  const [queueRes, usersRes, rolesRes, orgsRes] = await Promise.all([
    api('/api/op/join-requests'),
    api('/api/users'),
    api('/api/users/roles'),
    api('/api/op/organizations'),
  ])
  if (queueRes.status === 401) {
    window.location.assign(`/?redirect=${encodeURIComponent('/op/admin/users')}`)
    return
  }
  if (queueRes.status === 403) {
    error.value = 'This console is for organization administrators and the scheme operator — your account holds neither grant.'
    loading.value = false
    return
  }
  if (!queueRes.ok) throw new Error(`the join-request queue failed (${queueRes.status})`)
  const envelope = await queueRes.json() as {
    grant: 'wide' | 'org'
    orgId: string | null
    orgName: string | null
    requests: JoinRequestRow[]
  }
  grant.value = envelope.grant
  grantOrgId.value = envelope.orgId
  grantOrgName.value = envelope.orgName
  requests.value = envelope.requests

  if (usersRes.ok) users.value = await usersRes.json() as UserRow[]
  if (rolesRes.ok) roleMap.value = await rolesRes.json() as Record<string, string[]>
  if (orgsRes.ok) registryOrgs.value = await orgsRes.json() as SelectorOrg[]

  // TODO.identity/11 — the org grant's people slice is the org's
  // MEMBERSHIPS (the server pins the slice to the caller's org).
  if (grant.value === 'org') {
    const membersRes = await api('/api/op/org-memberships')
    if (membersRes.ok) members.value = ((await membersRes.json()) as { members: MemberRow[] }).members
  }

  if (isWide.value) {
    const unreg = await api('/api/op/join-requests?scope=unregistered')
    if (unreg.ok) unregistered.value = ((await unreg.json()) as { requests: JoinRequestRow[] }).requests
    // TODO.identity/03 — the identity registry: the OP's own accounts
    // (per-client roles + the audit-chain last sign-in) and the client
    // registry (the assignment targets + their claims policies).
    const [regRes, clientsRes] = await Promise.all([api('/api/op/accounts'), api('/api/op/clients')])
    if (regRes.ok) registry.value = await regRes.json() as RegistryAccount[]
    if (clientsRes.ok) {
      clients.value = ((await clientsRes.json()) as RegistryClient[]).filter(cl => cl.status === 'active')
    }
  }
}

async function approve(row: JoinRequestRow) {
  if (acting.value) return
  acting.value = row.id
  error.value = null
  notice.value = null
  lastInvite.value = null
  try {
    const payload: Record<string, unknown> = {}
    if (!row.orgId) {
      const orgId = approveOrgId.value[row.id]
      if (!orgId) {
        error.value = 'Pick the organization’s register entry before approving — the participation must be registered first.'
        return
      }
      payload.org_id = orgId
    }
    const res = await api(`/api/op/join-requests/${encodeURIComponent(row.id)}/approve`, {
      method: 'POST',
      body: JSON.stringify(payload),
    })
    if (!res.ok) {
      const body = await res.json().catch(() => ({})) as { error?: string }
      error.value = body.error ?? `The approval failed (${res.status}).`
      return
    }
    const decided = await res.json() as JoinRequestRow & {
      invite?: { setupUrl?: string; expiresAt?: string; mail?: InviteMail | null }
      /** TODO.identity/11: the EXISTING account's path — the membership
       *  landed directly (no invite, no setup link). */
      membership?: { userId: string; orgId: string; roles: string[]; state: string }
    }
    if (decided.invite?.setupUrl) {
      lastInvite.value = { email: row.email, name: row.name, setupUrl: decided.invite.setupUrl, expiresAt: decided.invite.expiresAt ?? '', mail: decided.invite.mail ?? null }
    }
    notice.value = decided.membership
      ? `${row.name} is now a member of ${row.orgName ?? row.orgId}: their existing account joined it as ${decided.membership.roles.join(', ') || 'a member'} — no new setup link was needed.`
      : decided.invite?.mail?.sent
        ? `Invite issued: ${row.name}'s account is created and the setup email is on its way to ${row.email} (the link lives 24 h).`
        : `Invite issued: ${row.name}'s account is created. Hand over the one-time setup link below (24 h); it is shown only now.`
    await load()
  } catch {
    error.value = 'Network error. Is the server running?'
  } finally {
    acting.value = null
  }
}

async function refuse(row: JoinRequestRow) {
  if (acting.value) return
  const reason = (refuseReason.value[row.id] ?? '').trim()
  if (!reason) {
    error.value = 'A refusal needs a reason — the requester sees it.'
    return
  }
  acting.value = row.id
  error.value = null
  notice.value = null
  try {
    const res = await api(`/api/op/join-requests/${encodeURIComponent(row.id)}/refuse`, {
      method: 'POST',
      body: JSON.stringify({ reason }),
    })
    if (!res.ok) {
      const body = await res.json().catch(() => ({})) as { error?: string }
      error.value = body.error ?? `The refusal failed (${res.status}).`
      return
    }
    notice.value = `Request refused — ${row.name} is told why.`
    refuseOpen.value[row.id] = false
    await load()
  } catch {
    error.value = 'Network error. Is the server running?'
  } finally {
    acting.value = null
  }
}

async function inviteColleague() {
  if (acting.value) return
  acting.value = 'invite'
  error.value = null
  notice.value = null
  lastInvite.value = null
  try {
    const res = await api('/api/op/org-invites', {
      method: 'POST',
      body: JSON.stringify({
        name: inviteName.value.trim(),
        email: inviteEmail.value.trim(),
        role: inviteRole.value,
      }),
    })
    if (!res.ok) {
      const body = await res.json().catch(() => ({})) as { error?: string }
      error.value = body.error ?? `The invite failed (${res.status}).`
      return
    }
    const created = await res.json() as { user: UserRow; invite?: { setupUrl?: string; expiresAt?: string; mail?: InviteMail | null } }
    if (created.invite?.setupUrl) {
      lastInvite.value = { email: created.user.email, name: created.user.name, setupUrl: created.invite.setupUrl, expiresAt: created.invite.expiresAt ?? '', mail: created.invite.mail ?? null }
    }
    notice.value = created.invite?.mail?.sent
      ? `${inviteName.value.trim()} is invited: the setup email is on its way to ${created.user.email} (the link lives 24 h).`
      : `${inviteName.value.trim()} is invited: hand over the one-time setup link below (24 h).`
    inviteName.value = ''
    inviteEmail.value = ''
    inviteRole.value = ''
    await load()
  } catch {
    error.value = 'Network error. Is the server running?'
  } finally {
    acting.value = null
  }
}

async function createOrgAdmin() {
  if (acting.value) return
  acting.value = 'orgadmin'
  error.value = null
  notice.value = null
  lastInvite.value = null
  try {
    const res = await api('/api/op/org-invites', {
      method: 'POST',
      body: JSON.stringify({
        name: orgAdminName.value.trim(),
        email: orgAdminEmail.value.trim(),
        role: 'org_admin',
        org_id: orgAdminOrg.value,
      }),
    })
    if (!res.ok) {
      const body = await res.json().catch(() => ({})) as { error?: string }
      error.value = body.error ?? `Could not create the organization administrator (${res.status}).`
      return
    }
    const created = await res.json() as { user: UserRow; invite?: { setupUrl?: string; expiresAt?: string; mail?: InviteMail | null } }
    if (created.invite?.setupUrl) {
      lastInvite.value = { email: created.user.email, name: created.user.name, setupUrl: created.invite.setupUrl, expiresAt: created.invite.expiresAt ?? '', mail: created.invite.mail ?? null }
    }
    const orgName = registryOrgs.value.find(o => o.id === orgAdminOrg.value)?.name ?? orgAdminOrg.value
    notice.value = created.invite?.mail?.sent
      ? `${orgAdminName.value.trim()} is ${orgName}'s organization administrator: the setup email is on its way to ${created.user.email} (the link lives 24 h).`
      : `${orgAdminName.value.trim()} is ${orgName}'s organization administrator: hand over the one-time setup link below (24 h).`
    orgAdminName.value = ''
    orgAdminEmail.value = ''
    orgAdminOrg.value = ''
    await load()
  } catch {
    error.value = 'Network error. Is the server running?'
  } finally {
    acting.value = null
  }
}

// ── the identity registry's acts (TODO.identity/03) ─────────────────
// Every rule is SERVER-ENFORCED (routes/op-accounts.ts); the page only
// renders what the APIs answer and names the refusals it gets back.

function draftKey(accountId: string, clientId: string): string {
  return `${accountId}::${clientId}`
}

/** The roles assignable on a client: its claims-policy role allowlist
 *  when the client declares one, else the platform vocabulary. */
function assignableRoles(client: RegistryClient): string[] {
  return client.claimsPolicy?.roles ?? [...APP_ROLES]
}

/** The account's CURRENT assignment for the client (null = no row — the
 *  account's OP-side default set carries for this client). */
function assignmentFor(acc: RegistryAccount, clientId: string): string[] | null {
  return acc.clientRoles.find(a => a.clientId === clientId)?.roles ?? null
}

/** The set the client's ID token will actually carry (the server's rule:
 *  the assignment or the account default, intersected with the client's
 *  policy allowlist). */
function effectiveRolesFor(acc: RegistryAccount, client: RegistryClient): string[] {
  const base = assignmentFor(acc, client.clientId) ?? acc.roles
  const allow = client.claimsPolicy?.roles
  return base.filter(r => !allow || allow.includes(r))
}

/** Whether the client receives role claims at all (its policy's claim
 *  gate) — without it the assignment never leaves the OP. */
function clientReceivesRoles(client: RegistryClient): boolean {
  return !!client.claimsPolicy?.claims.some(cl => cl === 'roles' || cl === 'groups')
}

/** The client-role state line for an account: the honest summary of
 *  what this client gets. */
function clientRoleState(acc: RegistryAccount, client: RegistryClient): string {
  const assigned = assignmentFor(acc, client.clientId)
  const effective = effectiveRolesFor(acc, client)
  if (!clientReceivesRoles(client)) return 'no role claims — the client’s policy carries none'
  if (assigned === null) return `the account default (${acc.roles.join(', ') || 'none'})`
  if (assigned.length === 0) return 'explicitly no roles on this client'
  return `assigned: ${assigned.join(', ')}${effective.length === assigned.length ? '' : ` (the policy passes ${effective.join(', ') || 'none'})`}`
}

async function registryInvite() {
  if (acting.value) return
  acting.value = 'registry-invite'
  error.value = null
  notice.value = null
  lastInvite.value = null
  try {
    const res = await api('/api/op/accounts', {
      method: 'POST',
      body: JSON.stringify({
        name: regInviteName.value.trim(),
        email: regInviteEmail.value.trim(),
        role: regInviteRole.value,
        roles: [regInviteRole.value],
        org_id: regInviteOrg.value || null,
      }),
    })
    if (!res.ok) {
      const body = await res.json().catch(() => ({})) as { error?: string }
      error.value = body.error ?? `The invite failed (${res.status}).`
      return
    }
    const created = await res.json() as {
      account: { id: string; email: string; name: string }
      setupUrl?: string
      expiresAt?: string
      mail?: InviteMail | null
    }
    if (created.setupUrl) {
      lastInvite.value = { email: created.account.email, name: created.account.name, setupUrl: created.setupUrl, expiresAt: created.expiresAt ?? '', mail: created.mail ?? null }
    }
    notice.value = created.mail?.sent
      ? `${created.account.name} is invited: the setup email is on its way to ${created.account.email} (the link lives 24 h), then assign their roles per client.`
      : `${created.account.name} is invited: hand over the one-time setup link below (24 h), then assign their roles per client.`
    regInviteName.value = ''
    regInviteEmail.value = ''
    regInviteRole.value = 'viewer'
    regInviteOrg.value = ''
    await load()
  } catch {
    error.value = 'Network error. Is the server running?'
  } finally {
    acting.value = null
  }
}

function startEdit(acc: RegistryAccount) {
  editingId.value = acc.id
  editName.value = acc.name
  editEmail.value = acc.email
}

async function saveEdit(acc: RegistryAccount) {
  if (acting.value) return
  acting.value = acc.id
  error.value = null
  notice.value = null
  try {
    const res = await api(`/api/op/accounts/${encodeURIComponent(acc.id)}`, {
      method: 'PUT',
      body: JSON.stringify({ name: editName.value.trim(), email: editEmail.value.trim() }),
    })
    if (!res.ok) {
      const body = await res.json().catch(() => ({})) as { error?: string }
      error.value = body.error ?? `The edit failed (${res.status}).`
      return
    }
    notice.value = `${editName.value.trim()} updated.`
    editingId.value = null
    await load()
  } catch {
    error.value = 'Network error. Is the server running?'
  } finally {
    acting.value = null
  }
}

/** Open/close the per-client roles editor; the drafts start from the
 *  CURRENT assignment ([] when none — an explicit set is the admin's
 *  act; the default carries until then). */
function toggleRolesEditor(acc: RegistryAccount) {
  if (rolesEditorFor.value === acc.id) {
    rolesEditorFor.value = null
    return
  }
  rolesEditorFor.value = acc.id
  const drafts: Record<string, string[]> = {}
  for (const client of clients.value) {
    drafts[draftKey(acc.id, client.clientId)] = [...(assignmentFor(acc, client.clientId) ?? [])]
  }
  clientRoleDrafts.value = drafts
}

function toggleDraftRole(accountId: string, clientId: string, role: string) {
  const key = draftKey(accountId, clientId)
  const draft = clientRoleDrafts.value[key] ?? []
  clientRoleDrafts.value = {
    ...clientRoleDrafts.value,
    [key]: draft.includes(role) ? draft.filter(r => r !== role) : [...draft, role],
  }
}

async function saveClientRoles(acc: RegistryAccount, clientId: string) {
  if (acting.value) return
  acting.value = acc.id
  error.value = null
  notice.value = null
  try {
    const roles = clientRoleDrafts.value[draftKey(acc.id, clientId)] ?? []
    const res = await api(`/api/op/accounts/${encodeURIComponent(acc.id)}/client-roles/${encodeURIComponent(clientId)}`, {
      method: 'PUT',
      body: JSON.stringify({ roles }),
    })
    if (!res.ok) {
      const body = await res.json().catch(() => ({})) as { error?: string }
      error.value = body.error ?? `The assignment failed (${res.status}).`
      return
    }
    const clientName = clients.value.find(cl => cl.clientId === clientId)?.name ?? clientId
    notice.value = roles.length
      ? `${acc.name} holds ${roles.join(', ')} on ${clientName}.`
      : `${acc.name} holds no roles on ${clientName} (the explicit none — the account default no longer carries there).`
    await load()
  } catch {
    error.value = 'Network error. Is the server running?'
  } finally {
    acting.value = null
  }
}

async function clearClientRoles(acc: RegistryAccount, clientId: string) {
  if (acting.value) return
  acting.value = acc.id
  error.value = null
  notice.value = null
  try {
    const res = await api(`/api/op/accounts/${encodeURIComponent(acc.id)}/client-roles/${encodeURIComponent(clientId)}`, {
      method: 'DELETE',
    })
    if (!res.ok) {
      const body = await res.json().catch(() => ({})) as { error?: string }
      error.value = body.error ?? `(${res.status})`
      return
    }
    const clientName = clients.value.find(cl => cl.clientId === clientId)?.name ?? clientId
    notice.value = `${acc.name}'s assignment on ${clientName} cleared — the account default carries there again.`
    await load()
  } catch {
    error.value = 'Network error. Is the server running?'
  } finally {
    acting.value = null
  }
}

/** The honest deactivation: the row stays (the history), sign-ins
 *  refuse, sessions + issued tokens are revoked (the server revokes). */
async function setRegistryActive(acc: RegistryAccount, active: boolean) {
  if (acting.value) return
  acting.value = acc.id
  error.value = null
  notice.value = null
  try {
    const res = await api(`/api/op/accounts/${encodeURIComponent(acc.id)}/status`, {
      method: 'POST',
      body: JSON.stringify({ active }),
    })
    if (!res.ok) {
      const body = await res.json().catch(() => ({})) as { error?: string }
      error.value = body.error ?? `(${res.status})`
      return
    }
    notice.value = active
      ? `${acc.name} reactivated — they can sign in again.`
      : `${acc.name} deactivated — sign-ins refuse and every session was revoked.`
    await load()
  } catch {
    error.value = 'Network error. Is the server running?'
  } finally {
    acting.value = null
  }
}

/** A fresh one-time setup link (the password-reset / expired-link path). */
async function freshSetupLink(acc: RegistryAccount) {
  if (acting.value) return
  acting.value = acc.id
  error.value = null
  notice.value = null
  lastInvite.value = null
  try {
    const res = await api(`/api/op/accounts/${encodeURIComponent(acc.id)}/enrollment`, { method: 'POST' })
    if (!res.ok) {
      const body = await res.json().catch(() => ({})) as { error?: string }
      error.value = body.error ?? `(${res.status})`
      return
    }
    const body = await res.json() as { setupUrl: string; expiresAt: string; mail?: InviteMail | null }
    lastInvite.value = { email: acc.email, name: acc.name, setupUrl: body.setupUrl, expiresAt: body.expiresAt, mail: body.mail ?? null }
    notice.value = body.mail?.sent
      ? `A fresh one-time setup link for ${acc.name}: the reset email is on its way to ${acc.email} (24 h).`
      : `A fresh one-time setup link for ${acc.name}: hand it over out-of-band (24 h).`
  } catch {
    error.value = 'Network error. Is the server running?'
  } finally {
    acting.value = null
  }
}

/** The last sign-in's display (the audit chain's ISO stamp). */
function lastSignInLabel(acc: RegistryAccount): string {
  if (!acc.lastSignIn) return 'never signed in'
  return `last signed in ${acc.lastSignIn.slice(0, 16).replace('T', ' ')}UTC`
}

function orgNameOf(orgId: string | null): string {
  if (!orgId) return '—'
  return registryOrgs.value.find(o => o.id === orgId)?.name ?? orgId
}

// ── TODO.identity/11 — the membership acts (the org console's people
//    slice): the per-org role edit, the lifecycle (disable/re-activate),
//    and the existing-account invite. Every bound is SERVER-ENFORCED
//    (routes/op-memberships.ts): the org grant never names org_admin,
//    never touches an org_admin membership, never reaches another org.

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
    notice.value = `${m.name}'s roles in ${orgNameOf(m.orgId)} updated.`
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
      ? `${m.name}'s membership in ${orgNameOf(m.orgId)} is disabled — their sessions stopped acting as this organization.`
      : `${m.name}'s membership in ${orgNameOf(m.orgId)} is active again.`
    await load()
  } catch {
    error.value = 'Network error. Is the server running?'
  } finally {
    acting.value = null
  }
}

/** Add an EXISTING account to the org (the membership invite — the
 *  holder accepts from their account console; the join-request approval
 *  is the directly-active path). */
async function inviteExistingMember() {
  if (acting.value) return
  acting.value = 'member-invite'
  error.value = null
  notice.value = null
  try {
    const res = await api('/api/op/org-memberships', {
      method: 'POST',
      body: JSON.stringify({ email: addEmail.value.trim(), roles: addRoleChecks.value }),
    })
    if (!res.ok) {
      const body = await res.json().catch(() => ({})) as { error?: string }
      error.value = body.error ?? `The membership invite failed (${res.status}).`
      return
    }
    notice.value = `${addEmail.value.trim()} is invited to join ${grantOrgName.value ?? 'your organization'} — the invitation shows on their account console until they accept or decline it.`
    addEmail.value = ''
    addRoleChecks.value = []
    await load()
  } catch {
    error.value = 'Network error. Is the server running?'
  } finally {
    acting.value = null
  }
}

/** Copy the issued invite's one-time setup link (the handover). */
function copySetupUrl() {
  if (lastInvite.value) void navigator.clipboard.writeText(lastInvite.value.setupUrl)
}

onMounted(async () => {
  try {
    const session = await fetch('/api/auth/session', { credentials: 'include' })
    if (!session.ok) {
      window.location.assign(`/?redirect=${encodeURIComponent('/op/admin/users')}`)
      return
    }
    account.value = await session.json() as { id: string; name: string; email: string; roles: string[] }
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

    <div v-else data-testid="op-admin-users">
      <PageHeader title="Organization administration">
        <template #description>
          <span data-testid="op-admin-identity">
            <template v-if="account">{{ account.name }} &lt;{{ account.email }}&gt; — </template>{{ branding.productName }}
            <template v-if="grant === 'org' && grantOrgName"> · {{ grantOrgName }}</template>
            <template v-else-if="grant === 'wide'"> · the scheme operator’s view</template>
          </span>
        </template>
      </PageHeader>

      <!-- The console's tab bar — the wide grant only (the org admin's
           grant would 403 on the sibling surfaces, honestly but
           noisily). -->
      <OpAdminNav v-if="isWide" current="users" />

      <!-- Error / notice -->
      <div v-if="error" class="mb-4 p-3 rounded-lg bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800">
        <p class="text-sm text-red-700 dark:text-red-300" data-testid="op-admin-error">{{ error }}</p>
      </div>
      <div v-if="notice" class="mb-4 p-3 rounded-lg bg-emerald-50 dark:bg-emerald-900/20 border border-emerald-200 dark:border-emerald-800">
        <p class="text-sm text-emerald-800 dark:text-emerald-300" data-testid="op-admin-notice">{{ notice }}</p>
      </div>

      <!-- The issued invite's one-time setup link (02's enrollment).
           TODO.identity/09: EMAILED when a mail provider is configured
           (the status line says so); the copy-link path stays as the
           fallback, and leads when no provider is configured. Shown
           once, for the last issued invite only. -->
      <div v-if="lastInvite" class="mb-4 p-4 rounded-lg border border-brand-300 dark:border-brand-700 bg-brand-50 dark:bg-brand-900/20" data-testid="invite-setup-link">
        <p
          v-if="lastInvite.mail"
          class="mb-2 text-[11px] font-medium"
          :class="lastInvite.mail.sent ? 'text-emerald-700 dark:text-emerald-400' : 'text-amber-700 dark:text-amber-400'"
          data-testid="invite-mail-status"
        >
          <template v-if="lastInvite.mail.sent">
            The setup email was sent to {{ lastInvite.email }}. The link below is the same one the email carries, kept here as the fallback.
          </template>
          <template v-else-if="lastInvite.mail.posture === 'console'">
            No mail provider is configured on this deployment: copy the link below and hand it over out-of-band.
          </template>
          <template v-else>
            The setup email could not be sent ({{ lastInvite.mail.error }}). Copy the link below instead.
          </template>
        </p>
        <p class="text-xs font-semibold text-brand-900 dark:text-brand-200 mb-1">
          The one-time setup link for {{ lastInvite.name }} &lt;{{ lastInvite.email }}&gt;
          <span class="font-normal text-slate-500 dark:text-slate-400">(expires {{ lastInvite.expiresAt.slice(0, 16).replace('T', ' ') }}UTC)</span>
        </p>
        <div class="flex items-center gap-2">
          <code class="flex-1 text-[11px] font-mono bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded px-2 py-1.5 truncate text-slate-700 dark:text-slate-300" data-testid="invite-setup-url">{{ lastInvite.setupUrl }}</code>
          <button
            type="button"
            data-testid="invite-setup-copy"
            class="shrink-0 px-3 py-1.5 text-xs font-semibold rounded-lg bg-brand-600 text-white hover:bg-brand-700 transition-colors"
            @click="copySetupUrl"
          >Copy</button>
        </div>
        <p class="mt-1 text-[11px] text-slate-500 dark:text-slate-400">
          It opens the account-setup page once, for 24 hours. Send it by a channel where you can verify the person — this link sets their password.
        </p>
      </div>

      <template v-if="grant">
        <!-- ═══ The join-request queue (the org admin's own; BIML's
             oversight of the org-bound ones) ═══ -->
        <section class="rounded-xl border border-slate-200/80 dark:border-slate-700 bg-white dark:bg-slate-800 p-6 mb-6" data-testid="org-queue">
          <h2 class="text-xs font-semibold uppercase tracking-wider text-slate-400 dark:text-slate-500 mb-3">
            {{ grant === 'org' ? `Join requests — ${grantOrgName ?? 'your organization'}` : 'Join requests — every organization' }}
          </h2>
          <p class="text-xs text-slate-500 dark:text-slate-400 mb-3">
            <template v-if="grant === 'org'">
              Your organization’s staff asked for accounts. Approval issues the invite; the decision is yours
              (the email-domain match, when shown, is a hint — never the proof).
            </template>
            <template v-else>
              Every registered organization’s pending requests (the scheme operator’s oversight — the
              organizations’ own administrators decide first; you act when an organization asks you to).
            </template>
          </p>
          <p v-if="!pendingOrgRequests.length" class="text-sm text-slate-500 dark:text-slate-400" data-testid="org-queue-empty">
            No pending requests.
          </p>
          <ul v-else class="space-y-3">
            <li
              v-for="row in pendingOrgRequests"
              :key="row.id"
              class="rounded-lg border border-slate-200 dark:border-slate-700 px-3 py-3"
              :data-testid="`join-request-${row.id}`"
            >
              <div class="flex items-start justify-between gap-3 flex-wrap">
                <div class="min-w-0">
                  <p class="text-sm font-medium text-slate-900 dark:text-white">
                    {{ row.name }} <span class="font-normal text-slate-500 dark:text-slate-400">&lt;{{ row.email }}&gt;</span>
                  </p>
                  <p class="text-[11px] text-slate-400 dark:text-slate-500">
                    asks for <code class="font-mono">{{ row.requestedRole }}</code>
                    <template v-if="isWide && row.orgName"> · <strong class="text-slate-500 dark:text-slate-400">{{ row.orgName }}</strong></template>
                    · filed {{ row.createdAt.slice(0, 10) }}
                    <template v-if="row.emailDomainMatch === true"> · <span class="text-emerald-600 dark:text-emerald-400">email domain matches the register</span></template>
                    <template v-else-if="row.emailDomainMatch === false"> · <span class="text-amber-600 dark:text-amber-400">email domain does not match the register</span></template>
                  </p>
                  <p v-if="row.note" class="text-xs text-slate-500 dark:text-slate-400 mt-1">“{{ row.note }}”</p>
                </div>
                <div class="flex items-center gap-2 shrink-0">
                  <button
                    :data-testid="`join-approve-${row.id}`"
                    :disabled="acting === row.id"
                    class="px-3 py-1.5 text-xs font-semibold rounded-lg bg-brand-600 text-white hover:bg-brand-700 transition-colors disabled:opacity-50"
                    @click="approve(row)"
                  >Approve</button>
                  <button
                    :data-testid="`join-refuse-open-${row.id}`"
                    :disabled="acting === row.id"
                    class="px-3 py-1.5 text-xs font-semibold rounded-lg border border-slate-200 dark:border-slate-700 text-slate-600 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-700 transition-colors disabled:opacity-50"
                    @click="refuseOpen[row.id] = !refuseOpen[row.id]"
                  >Refuse</button>
                </div>
              </div>
              <div v-if="refuseOpen[row.id]" class="mt-2 flex items-center gap-2">
                <input
                  v-model="refuseReason[row.id]"
                  type="text"
                  :data-testid="`join-refuse-reason-${row.id}`"
                  class="flex-1 px-3 py-1.5 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-xs text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-500"
                  placeholder="The reason (the requester sees it)…"
                />
                <button
                  :data-testid="`join-refuse-${row.id}`"
                  :disabled="acting === row.id"
                  class="px-3 py-1.5 text-xs font-semibold rounded-lg bg-red-600 text-white hover:bg-red-700 transition-colors disabled:opacity-50"
                  @click="refuse(row)"
                >Confirm refusal</button>
              </div>
            </li>
          </ul>

          <!-- The decision trail -->
          <ul v-if="decidedRequests.length" class="mt-4 space-y-1" data-testid="org-queue-decided">
            <li v-for="row in decidedRequests" :key="row.id" class="text-[11px] text-slate-400 dark:text-slate-500">
              {{ row.createdAt.slice(0, 10) }} — {{ row.name }} &lt;{{ row.email }}&gt;:
              <span :class="row.status === 'approved' ? 'text-emerald-600 dark:text-emerald-400' : 'text-red-500 dark:text-red-400'">{{ row.status }}</span>
              by {{ row.decidedBy }}<template v-if="row.refusalReason"> — {{ row.refusalReason }}</template>
            </li>
          </ul>
        </section>

        <!-- ═══ The people slice (org admin only — the wide grant's
             account surface is the identity registry below) ═══ -->
        <section v-if="grant === 'org'" class="rounded-xl border border-slate-200/80 dark:border-slate-700 bg-white dark:bg-slate-800 p-6 mb-6" data-testid="org-users">
          <h2 class="text-xs font-semibold uppercase tracking-wider text-slate-400 dark:text-slate-500 mb-3">
            People — {{ grantOrgName ?? 'your organization' }}
          </h2>
          <p v-if="!members.length" class="text-sm text-slate-500 dark:text-slate-400 mb-2" data-testid="org-users-empty">
            No members yet — the queue's approvals and the forms below grow this list.
          </p>
          <ul class="space-y-2" data-testid="org-users-list">
            <li
              v-for="m in members"
              :key="m.userId"
              class="rounded-lg border border-slate-200 dark:border-slate-700 px-3 py-2"
              :data-testid="`org-user-${m.userId}`"
            >
              <div class="flex items-center justify-between gap-3">
                <div class="min-w-0">
                  <p class="text-sm font-medium text-slate-900 dark:text-white">
                    {{ m.name }}
                    <span class="font-normal text-slate-500 dark:text-slate-400">&lt;{{ m.email }}&gt;</span>
                    <span v-if="!m.accountActive" class="text-[10px] px-1.5 py-0.5 rounded bg-red-100 dark:bg-red-900/40 text-red-600 dark:text-red-400 font-semibold">account deactivated</span>
                    <span v-if="!m.isPrimary" class="text-[10px] px-1.5 py-0.5 rounded bg-brand-100 dark:bg-brand-900/40 text-brand-700 dark:text-brand-200 font-semibold" :data-testid="`org-user-secondary-${m.userId}`">also a member elsewhere</span>
                  </p>
                  <p class="text-[11px] text-slate-400 dark:text-slate-500" :data-testid="`org-user-roles-${m.userId}`">
                    {{ m.roles.join(', ') || 'no organization roles' }}<template v-if="m.provider"> · {{ m.provider }}</template>
                  </p>
                </div>
                <div class="shrink-0 flex items-center gap-3 text-xs font-medium">
                  <span
                    v-if="m.state === 'invited'"
                    class="px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wider bg-amber-100 dark:bg-amber-900/30 text-amber-700 dark:text-amber-300"
                    :data-testid="`org-user-invited-${m.userId}`"
                  >invited</span>
                  <span
                    v-else-if="m.state === 'disabled'"
                    class="px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wider bg-red-100 dark:bg-red-900/40 text-red-600 dark:text-red-400"
                    :data-testid="`org-user-disabled-${m.userId}`"
                  >disabled</span>
                  <button
                    :data-testid="`org-user-roles-edit-${m.userId}`"
                    :disabled="acting === m.userId"
                    class="text-brand-600 dark:text-brand-300 hover:underline disabled:opacity-50"
                    @click="openMemberRoles(m)"
                  >{{ memberRolesOpen === m.userId ? 'Close' : 'Roles' }}</button>
                  <button
                    v-if="m.state !== 'invited' && m.userId !== account?.id"
                    :data-testid="`org-user-membership-toggle-${m.userId}`"
                    :disabled="acting === m.userId"
                    class="hover:underline disabled:opacity-50"
                    :class="m.state === 'active' ? 'text-red-600 dark:text-red-400' : 'text-emerald-600 dark:text-emerald-400'"
                    @click="setMemberState(m, m.state === 'active' ? 'disabled' : 'active')"
                  >{{ m.state === 'active' ? 'Disable membership' : 'Re-activate membership' }}</button>
                </div>
              </div>
              <!-- The per-org roles editor (kind-bounded; the server
                   re-checks). -->
              <div v-if="memberRolesOpen === m.userId" class="mt-2 border-t border-slate-100 dark:border-slate-700 pt-2" :data-testid="`org-user-roles-editor-${m.userId}`">
                <div class="flex flex-wrap gap-x-4 gap-y-1 mb-2">
                  <label v-for="r in Object.keys(roleMap)" :key="r" class="flex items-center gap-1.5 text-xs text-slate-700 dark:text-slate-300">
                    <input
                      type="checkbox"
                      :value="r"
                      v-model="memberRoleDrafts[m.userId]"
                      :data-testid="`org-user-role-check-${m.userId}-${r}`"
                      class="rounded border-slate-300 dark:border-slate-600 text-brand-600 focus:ring-brand-500"
                    />
                    {{ r }}
                  </label>
                </div>
                <button
                  :disabled="acting === m.userId"
                  :data-testid="`org-user-roles-save-${m.userId}`"
                  class="px-3 py-1.5 rounded-lg text-xs font-medium bg-brand-600 text-white hover:bg-brand-700 transition-colors disabled:opacity-50"
                  @click="saveMemberRoles(m)"
                >Save the roles</button>
              </div>
            </li>
          </ul>

          <!-- Add an EXISTING account (the membership invite — the holder
               accepts from their account console). -->
          <div class="mt-4 border-t border-slate-100 dark:border-slate-700 pt-4" data-testid="org-member-add">
            <h3 class="text-xs font-semibold text-slate-700 dark:text-slate-300 mb-2">Add an existing account</h3>
            <div class="grid grid-cols-1 sm:grid-cols-2 gap-2">
              <input
                v-model="addEmail"
                type="email"
                data-testid="member-add-email"
                class="px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-500"
                placeholder="The account’s email"
              />
              <button
                :disabled="acting === 'member-invite' || !addEmail.includes('@')"
                data-testid="member-add-submit"
                class="py-2 rounded-lg text-sm font-medium bg-brand-600 text-white hover:bg-brand-700 transition-colors disabled:opacity-50"
                @click="inviteExistingMember"
              >{{ acting === 'member-invite' ? 'Inviting…' : 'Invite the membership' }}</button>
            </div>
            <div class="mt-2 flex flex-wrap gap-x-4 gap-y-1">
              <label v-for="r in Object.keys(roleMap)" :key="r" class="flex items-center gap-1.5 text-xs text-slate-700 dark:text-slate-300">
                <input
                  type="checkbox"
                  :value="r"
                  v-model="addRoleChecks"
                  :data-testid="`member-add-role-${r}`"
                  class="rounded border-slate-300 dark:border-slate-600 text-brand-600 focus:ring-brand-500"
                />
                {{ r }}
              </label>
            </div>
            <p class="mt-2 text-[11px] text-slate-400 dark:text-slate-500">
              For a person who already holds an OIML SMART account (any organization’s). The invitation waits on
              their account console until they accept or decline it; the roles are this organization’s own set,
              bounded by its kind — the server enforces both.
            </p>
          </div>

          <!-- The invite form (org admin: kind-bounded roles; the server
               pins the account to the org) -->
          <div v-if="grant === 'org'" class="mt-4 border-t border-slate-100 dark:border-slate-700 pt-4" data-testid="org-invite">
            <h3 class="text-xs font-semibold text-slate-700 dark:text-slate-300 mb-2">Invite a colleague</h3>
            <div class="grid grid-cols-1 sm:grid-cols-2 gap-2">
              <input
                v-model="inviteName"
                type="text"
                data-testid="invite-name"
                class="px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-500"
                placeholder="Full name"
              />
              <input
                v-model="inviteEmail"
                type="email"
                data-testid="invite-email"
                class="px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-500"
                placeholder="Work email"
              />
              <select
                v-model="inviteRole"
                data-testid="invite-role"
                class="px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-500"
              >
                <option value="" disabled>Role…</option>
                <option v-for="role in Object.keys(roleMap)" :key="role" :value="role">{{ role }}</option>
              </select>
              <button
                :disabled="acting === 'invite' || !inviteName.trim() || !inviteEmail.includes('@') || !inviteRole"
                data-testid="invite-submit"
                class="py-2 rounded-lg text-sm font-medium bg-brand-600 text-white hover:bg-brand-700 transition-colors disabled:opacity-50"
                @click="inviteColleague"
              >Invite</button>
            </div>
            <p class="mt-2 text-[11px] text-slate-400 dark:text-slate-500">
              The role options are bounded by your organization’s kind; the account is pinned to your
              organization — the server enforces both.
            </p>
          </div>
        </section>

        <!-- ═══ TODO.identity/03 — the identity registry (the scheme
             operator's account surface): every OP account, its per-client
             roles, the last sign-in from the audit chain, and the admin
             acts (invite, edit, assign, deactivate/reactivate) ═══ -->
        <section v-if="isWide" class="rounded-xl border border-slate-200/80 dark:border-slate-700 bg-white dark:bg-slate-800 p-6 mb-6" data-testid="registry">
          <h2 class="text-xs font-semibold uppercase tracking-wider text-slate-400 dark:text-slate-500 mb-3">
            The identity registry
          </h2>
          <p class="text-xs text-slate-500 dark:text-slate-400 mb-3">
            Every account on the identity service. Roles are assigned <strong>per registered client</strong>
            (the relying-party registry): an account's own role set is its federation-wide default, a
            per-client assignment overrides it for that client, and a client whose claims policy declares
            a role allowlist never receives a role outside it — the token shaping enforces both.
            The demo cast is listed for the audit too (marked <em>demo cast</em>): it is seed-managed —
            the invite/edit/roles/setup-link/deactivation acts apply to the OP's password accounts; a demo
            row's detail page carries its acts.
          </p>

          <!-- The invite form (02's enrollment seam; 10's org binding) -->
          <div class="mb-4 border border-slate-100 dark:border-slate-700 rounded-lg p-3" data-testid="registry-invite">
            <h3 class="text-xs font-semibold text-slate-700 dark:text-slate-300 mb-2">Invite an account</h3>
            <div class="grid grid-cols-1 sm:grid-cols-2 gap-2">
              <input
                v-model="regInviteName"
                type="text"
                data-testid="registry-invite-name"
                class="px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-500"
                placeholder="Full name"
              />
              <input
                v-model="regInviteEmail"
                type="email"
                data-testid="registry-invite-email"
                class="px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-500"
                placeholder="Email"
              />
              <select
                v-model="regInviteRole"
                data-testid="registry-invite-role"
                class="px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-500"
              >
                <option v-for="role in APP_ROLES" :key="role" :value="role">{{ role }}</option>
              </select>
              <select
                v-model="regInviteOrg"
                data-testid="registry-invite-org"
                class="px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-500"
              >
                <option value="">No organization binding</option>
                <option v-for="org in registryOrgs" :key="org.id" :value="org.id">{{ org.name }}</option>
              </select>
              <button
                :disabled="acting === 'registry-invite' || !regInviteName.trim() || !regInviteEmail.includes('@')"
                data-testid="registry-invite-submit"
                class="py-2 rounded-lg text-sm font-medium bg-brand-600 text-white hover:bg-brand-700 transition-colors disabled:opacity-50 sm:col-span-2"
                @click="registryInvite"
              >Invite — issue the one-time setup link</button>
            </div>
            <p class="mt-2 text-[11px] text-slate-400 dark:text-slate-500">
              The account's own role is its federation-wide default (viewer holds no privileges beyond the
              account page). The per-client assignments below decide what each instance actually receives.
            </p>
          </div>

          <!-- The accounts -->
          <p v-if="!registry.length" class="text-sm text-slate-500 dark:text-slate-400" data-testid="registry-empty">
            No accounts yet — the first one arrives by the invite above.
          </p>
          <ul v-else class="space-y-2" data-testid="registry-list">
            <li
              v-for="acc in registry"
              :key="acc.id"
              class="rounded-lg border border-slate-200 dark:border-slate-700 px-3 py-2"
              :data-testid="`registry-user-${acc.id}`"
            >
              <!-- The row: identity + state + the acts -->
              <div class="flex items-start justify-between gap-3 flex-wrap">
                <div class="min-w-0">
                  <p class="text-sm font-medium text-slate-900 dark:text-white">
                    {{ acc.name }}
                    <span class="font-normal text-slate-500 dark:text-slate-400" :data-testid="`registry-email-${acc.id}`">&lt;{{ acc.email }}&gt;</span>
                    <span v-if="!acc.active" class="text-[10px] px-1.5 py-0.5 rounded bg-red-100 dark:bg-red-900/40 text-red-600 dark:text-red-400 font-semibold">deactivated</span>
                    <span v-if="acc.provider !== 'password'" class="text-[10px] px-1.5 py-0.5 rounded bg-slate-100 dark:bg-slate-700 text-slate-500 dark:text-slate-400 font-semibold" :data-testid="`registry-provider-${acc.id}`">demo cast</span>
                  </p>
                  <p class="text-[11px] text-slate-400 dark:text-slate-500" :data-testid="`registry-meta-${acc.id}`">
                    default roles: {{ acc.roles.join(', ') }}<template v-if="acc.orgId"> · {{ orgNameOf(acc.orgId) }}</template>
                    <template v-if="acc.provider === 'password'"> · {{ acc.passwordSet ? 'password set' : 'password not set' }}</template><template v-else> · demo sign-in (seed-managed)</template><template v-if="acc.links.length"> · linked: {{ acc.links.map(l => l.provider).join(', ') }}</template>
                  </p>
                  <p class="text-[11px] text-slate-400 dark:text-slate-500" :data-testid="`registry-lastsignin-${acc.id}`">
                    {{ lastSignInLabel(acc) }}
                  </p>
                  <p v-if="acc.clientRoles.length" class="text-[11px] text-slate-500 dark:text-slate-400" :data-testid="`registry-clientroles-${acc.id}`">
                    per-client: {{ acc.clientRoles.map(a => `${a.clientId} → ${a.roles.length ? a.roles.join(', ') : '∅ (none)'}`).join(' · ') }}
                  </p>
                </div>
                <div class="flex items-center gap-2 shrink-0 flex-wrap">
                  <router-link
                    :to="`/op/admin/registry/users/${acc.id}`"
                    :data-testid="`registry-detail-${acc.id}`"
                    class="text-xs font-medium text-brand-600 dark:text-brand-300 hover:underline"
                  >Detail</router-link>
                  <!-- The registry's acts serve the OP's own accounts
                       (the server 404s the demo cast — seed-managed);
                       the buttons never offer an act that refuses. -->
                  <button
                    v-if="acc.provider === 'password'"
                    :data-testid="`registry-edit-${acc.id}`"
                    :disabled="acting === acc.id"
                    class="text-xs font-medium text-brand-600 dark:text-brand-300 hover:underline disabled:opacity-50"
                    @click="startEdit(acc)"
                  >Edit</button>
                  <button
                    v-if="acc.provider === 'password'"
                    :data-testid="`registry-roles-open-${acc.id}`"
                    :disabled="acting === acc.id"
                    class="text-xs font-medium text-brand-600 dark:text-brand-300 hover:underline disabled:opacity-50"
                    @click="toggleRolesEditor(acc)"
                  >{{ rolesEditorFor === acc.id ? 'Close client roles' : 'Client roles' }}</button>
                  <button
                    v-if="acc.provider === 'password'"
                    :data-testid="`registry-enroll-${acc.id}`"
                    :disabled="acting === acc.id"
                    class="text-xs font-medium text-slate-500 dark:text-slate-400 hover:underline disabled:opacity-50"
                    @click="freshSetupLink(acc)"
                  >Fresh setup link</button>
                  <button
                    v-if="acc.provider === 'password' && acc.id !== account?.id"
                    :data-testid="`registry-toggle-${acc.id}`"
                    :disabled="acting === acc.id"
                    class="text-xs font-medium hover:underline disabled:opacity-50"
                    :class="acc.active ? 'text-red-600 dark:text-red-400' : 'text-emerald-600 dark:text-emerald-400'"
                    @click="setRegistryActive(acc, !acc.active)"
                  >{{ acc.active ? 'Deactivate' : 'Reactivate' }}</button>
                </div>
              </div>

              <!-- The inline edit -->
              <div v-if="editingId === acc.id" class="mt-2 border-t border-slate-100 dark:border-slate-700 pt-2" :data-testid="`registry-edit-form-${acc.id}`">
                <div class="flex items-center gap-2 flex-wrap">
                  <input
                    v-model="editName"
                    type="text"
                    :data-testid="`registry-edit-name-${acc.id}`"
                    class="px-3 py-1.5 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-xs text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-500"
                    placeholder="Full name"
                  />
                  <input
                    v-model="editEmail"
                    type="email"
                    :data-testid="`registry-edit-email-${acc.id}`"
                    class="px-3 py-1.5 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-xs text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-500"
                    placeholder="Email"
                  />
                  <button
                    :data-testid="`registry-edit-save-${acc.id}`"
                    :disabled="acting === acc.id || !editName.trim() || !editEmail.includes('@')"
                    class="px-3 py-1.5 text-xs font-semibold rounded-lg bg-brand-600 text-white hover:bg-brand-700 transition-colors disabled:opacity-50"
                    @click="saveEdit(acc)"
                  >Save</button>
                  <button
                    :data-testid="`registry-edit-cancel-${acc.id}`"
                    class="px-3 py-1.5 text-xs font-medium text-slate-500 dark:text-slate-400 hover:underline"
                    @click="editingId = null"
                  >Cancel</button>
                </div>
              </div>

              <!-- The per-client roles editor -->
              <div v-if="rolesEditorFor === acc.id" class="mt-2 border-t border-slate-100 dark:border-slate-700 pt-2" :data-testid="`registry-roles-${acc.id}`">
                <p class="text-[11px] text-slate-500 dark:text-slate-400 mb-2">
                  The roles this account holds <strong>per client</strong>. No assignment: the account default
                  ({{ acc.roles.join(', ') || 'none' }}) carries. Saving an empty set is the explicit “no roles
                  on this client”; clearing restores the default. A client’s claims policy bounds what may be
                  assigned (its ID token never carries a role it is not configured to receive).
                </p>
                <p v-if="!clients.length" class="text-xs text-slate-400 dark:text-slate-500" :data-testid="`registry-roles-noclients-${acc.id}`">
                  No active clients are registered — the client registry (the deployment’s OP_CLIENT_SEED /
                  the clients API) names them first.
                </p>
                <div
                  v-for="client in clients"
                  :key="client.clientId"
                  class="mb-2 rounded-lg border border-slate-100 dark:border-slate-700 px-3 py-2"
                  :data-testid="`registry-roles-client-${acc.id}-${client.clientId}`"
                >
                  <p class="text-xs font-medium text-slate-700 dark:text-slate-300">
                    {{ client.name }} <code class="font-mono text-slate-400 dark:text-slate-500">{{ client.clientId }}</code>
                  </p>
                  <p class="text-[11px] text-slate-400 dark:text-slate-500 mb-1" :data-testid="`registry-roles-state-${acc.id}-${client.clientId}`">
                    {{ clientRoleState(acc, client) }}
                  </p>
                  <div class="flex items-center gap-3 flex-wrap">
                    <label
                      v-for="role in assignableRoles(client)"
                      :key="role"
                      class="flex items-center gap-1 text-[11px] text-slate-600 dark:text-slate-300"
                    >
                      <input
                        type="checkbox"
                        :checked="(clientRoleDrafts[`${acc.id}::${client.clientId}`] ?? []).includes(role)"
                        :data-testid="`registry-role-check-${acc.id}-${client.clientId}-${role}`"
                        @change="toggleDraftRole(acc.id, client.clientId, role)"
                      />
                      {{ role }}
                    </label>
                    <button
                      :data-testid="`registry-roles-save-${acc.id}-${client.clientId}`"
                      :disabled="acting === acc.id"
                      class="px-2.5 py-1 text-[11px] font-semibold rounded-lg bg-brand-600 text-white hover:bg-brand-700 transition-colors disabled:opacity-50"
                      @click="saveClientRoles(acc, client.clientId)"
                    >Save</button>
                    <button
                      v-if="assignmentFor(acc, client.clientId) !== null"
                      :data-testid="`registry-roles-clear-${acc.id}-${client.clientId}`"
                      :disabled="acting === acc.id"
                      class="px-2.5 py-1 text-[11px] font-medium text-slate-500 dark:text-slate-400 hover:underline disabled:opacity-50"
                      @click="clearClientRoles(acc, client.clientId)"
                    >Clear — restore the default</button>
                  </div>
                </div>
              </div>
            </li>
          </ul>
        </section>

        <!-- ═══ BIML: the new-organizations queue ═══ -->
        <section v-if="isWide" class="rounded-xl border border-slate-200/80 dark:border-slate-700 bg-white dark:bg-slate-800 p-6 mb-6" data-testid="biml-orgs-queue">
          <h2 class="text-xs font-semibold uppercase tracking-wider text-slate-400 dark:text-slate-500 mb-3">
            New organizations — the BIML queue
          </h2>
          <p class="text-xs text-slate-500 dark:text-slate-400 mb-3">
            Requests naming an organization that is NOT on the participants register. Verify the
            participation (PD-03/PD-09); once the organization is registered, approve the request onto its
            register entry — the requester becomes its organization administrator. Otherwise refuse with
            the reason (the participation pointer).
          </p>
          <p v-if="!pendingUnregistered.length" class="text-sm text-slate-500 dark:text-slate-400" data-testid="biml-orgs-empty">
            No new-organization requests waiting.
          </p>
          <ul v-else class="space-y-3">
            <li
              v-for="row in pendingUnregistered"
              :key="row.id"
              class="rounded-lg border border-amber-200 dark:border-amber-800 bg-amber-50 dark:bg-amber-900/10 px-3 py-3"
              :data-testid="`join-request-${row.id}`"
            >
              <p class="text-sm font-medium text-slate-900 dark:text-white">
                {{ row.name }} <span class="font-normal text-slate-500 dark:text-slate-400">&lt;{{ row.email }}&gt;</span>
              </p>
              <p class="text-xs text-slate-600 dark:text-slate-300 mt-0.5">
                organization: <strong :data-testid="`join-request-orgname-${row.id}`">{{ row.orgNameText }}</strong>
                <span class="text-slate-400"> (not on the register)</span> · filed {{ row.createdAt.slice(0, 10) }}
              </p>
              <p v-if="row.note" class="text-xs text-slate-500 dark:text-slate-400 mt-1">“{{ row.note }}”</p>
              <div class="mt-2 flex items-center gap-2 flex-wrap">
                <select
                  v-model="approveOrgId[row.id]"
                  :data-testid="`join-approve-org-${row.id}`"
                  class="px-3 py-1.5 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-xs text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-500"
                >
                  <option value="" disabled>Approve onto the registered org…</option>
                  <option v-for="org in registryOrgs" :key="org.id" :value="org.id">{{ org.name }}</option>
                </select>
                <button
                  :data-testid="`join-approve-${row.id}`"
                  :disabled="acting === row.id || !approveOrgId[row.id]"
                  class="px-3 py-1.5 text-xs font-semibold rounded-lg bg-brand-600 text-white hover:bg-brand-700 transition-colors disabled:opacity-50"
                  @click="approve(row)"
                >Approve — create the org admin</button>
                <button
                  :data-testid="`join-refuse-open-${row.id}`"
                  :disabled="acting === row.id"
                  class="px-3 py-1.5 text-xs font-semibold rounded-lg border border-slate-200 dark:border-slate-700 text-slate-600 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-700 transition-colors disabled:opacity-50"
                  @click="refuseOpen[row.id] = !refuseOpen[row.id]"
                >Refuse</button>
              </div>
              <div v-if="refuseOpen[row.id]" class="mt-2 flex items-center gap-2">
                <input
                  v-model="refuseReason[row.id]"
                  type="text"
                  :data-testid="`join-refuse-reason-${row.id}`"
                  class="flex-1 px-3 py-1.5 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-xs text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-500"
                  placeholder="e.g. the organization is not an OIML-CS participant — see PD-03/PD-09 for joining…"
                />
                <button
                  :data-testid="`join-refuse-${row.id}`"
                  :disabled="acting === row.id"
                  class="px-3 py-1.5 text-xs font-semibold rounded-lg bg-red-600 text-white hover:bg-red-700 transition-colors disabled:opacity-50"
                  @click="refuse(row)"
                >Confirm refusal</button>
              </div>
            </li>
          </ul>
        </section>

        <!-- ═══ BIML: create an org admin for a registered org ═══ -->
        <section v-if="isWide" class="rounded-xl border border-slate-200/80 dark:border-slate-700 bg-white dark:bg-slate-800 p-6 mb-6" data-testid="biml-org-admins">
          <h2 class="text-xs font-semibold uppercase tracking-wider text-slate-400 dark:text-slate-500 mb-3">
            Organization administrators
          </h2>
          <p class="text-xs text-slate-500 dark:text-slate-400 mb-3">
            One administrator per registered participant org, created after verification (B 18:2025 §10.2).
            Current: {{ orgAdminAccounts.length ? orgAdminAccounts.map(a => `${a.name} (${orgNameOf(a.orgId)})`).join(', ') : 'none yet' }}.
          </p>
          <div class="grid grid-cols-1 sm:grid-cols-2 gap-2">
            <input
              v-model="orgAdminName"
              type="text"
              data-testid="orgadmin-name"
              class="px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-500"
              placeholder="Full name"
            />
            <input
              v-model="orgAdminEmail"
              type="email"
              data-testid="orgadmin-email"
              class="px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-500"
              placeholder="Work email"
            />
            <select
              v-model="orgAdminOrg"
              data-testid="orgadmin-org"
              class="px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-500"
            >
              <option value="" disabled>Registered organization…</option>
              <option v-for="org in registryOrgs" :key="org.id" :value="org.id" :data-testid="`orgadmin-org-${org.id}`">{{ org.name }}</option>
            </select>
            <button
              :disabled="acting === 'orgadmin' || !orgAdminName.trim() || !orgAdminEmail.includes('@') || !orgAdminOrg"
              data-testid="orgadmin-submit"
              class="py-2 rounded-lg text-sm font-medium bg-brand-600 text-white hover:bg-brand-700 transition-colors disabled:opacity-50"
              @click="createOrgAdmin"
            >Create the org admin</button>
          </div>
        </section>
      </template>

      <p class="text-[11px] text-slate-400 dark:text-slate-500">
        <router-link to="/op/account" class="text-brand-600 dark:text-brand-300 hover:underline">Your account</router-link>
        · the register’s view of administration is on the
        <router-link to="/app/cs/participants" class="text-brand-600 dark:text-brand-300 hover:underline">participants page</router-link>
      </p>
    </div>
  </div>
</template>
