<script setup lang="ts">
// ═══════════════════════════════════════════════════════════════════
// The account-holder console (TODO.identity/06) — the identity
// provider's self-service surface at /op/account, the
// Keycloak-account-console standard grown on item 02's page:
//
//   PROFILE         the display name (edited inline), the primary email
//                   with its verification state and the verify-new-email
//                   ceremony (the link is SHOWN honestly while no mailer
//                   is configured; TODO.identity/09 owns the send), the
//                   avatar (uploaded through the client-side CROP step —
//                   components/AvatarCropDialog.vue — or from a linked
//                   provider's; initials otherwise — served publicly by
//                   convention at /op/avatar/<id>, the OIDC `picture`
//                   claim's target, and the section says so plainly);
//   ORGANIZATIONS   (TODO.identity/11 — the multi-org model) the
//                   account's memberships with their per-org role sets and
//                   states, the ACTIVE-ORG switch (the account acts as one
//                   org at a time; tokens carry the active org's roles),
//                   the invitations (accept/decline), and the request to
//                   join another registered organization;
//   SIGN-IN METHODS the password and the linked upstream identities
//                   (TODO.identity/08's registry surface) with icons,
//                   the linked account's id and date, link/unlink and
//                   password remove; THE GUARD: one method always
//                   remains, refused honestly with the explanation;
//   PASSWORD        set/change with the current-password check, the
//                   honest strength meter, and every OTHER session
//                   revoked on change (the count is named);
//   SESSIONS        every live session with created / last-active /
//                   user agent / IP, revoke one or sign out everywhere
//                   else;
//   ACTIVITY        the account's own sign-in and security events from
//                   the OP's audit chain, newest first.
//
// On a non-identity deployment the OP routes answer 404 and the page
// says so plainly (the routes exist in the one build; the profile
// decides). All copy rides the EN/FR catalogs (account.* namespace).
// ═══════════════════════════════════════════════════════════════════
import { computed, onMounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import PageHeader from '../components/PageHeader.vue'
import UpstreamProviderIcon from '../components/UpstreamProviderIcon.vue'
import AvatarCropDialog from '../components/AvatarCropDialog.vue'
import { AVATAR_ACCEPT_TYPES } from '../lib/avatar-crop'
import AccountFactors, { type FactorsPayload } from '../components/AccountFactors.vue'
import { t, type MessageKey } from '../i18n'

interface AccountContext {
  account: {
    id: string
    email: string
    emailVerifiedAt: string | null
    name: string
    role: string
    avatarUrl: string | null
  }
  passwordSet: boolean
  sessions: Array<{
    id: string
    createdAt: string
    expiresAt: string
    lastSeenAt: string | null
    userAgent: string | null
    ip: string | null
    current: boolean
  }>
  pendingEmailChange: { newEmail: string; expiresAt: string; delivery: string } | null
  /** TODO.identity/11: the organizations block (the multi-org model). */
  organizations?: {
    /** The session's stamped context (null = the primary binding). */
    activeOrg: string | null
    /** The org the claims carry right now (the context rule's answer). */
    effectiveOrg: string | null
    memberships: MembershipRow[]
    requests: OrgRequestRow[]
  }
  /** The avatar feature's honest availability + its byte cap (the
   *  server names both; the console never hides a limit in prose). */
  features?: { avatarUploads: boolean; avatarMaxBytes: number }
}

/** A membership row (TODO.identity/11): the account × org × per-org role
 *  set with the lifecycle state. */
interface MembershipRow {
  orgId: string
  orgName: string
  orgKind: string | null
  roles: string[]
  state: 'invited' | 'active' | 'disabled'
  isPrimary: boolean
  invitedBy: string | null
  createdAt: string
  disabledAt: string | null
  disabledBy: string | null
}

/** The account's own join-request row (the membership-request path). */
interface OrgRequestRow {
  id: string
  orgId: string | null
  orgName: string | null
  orgNameText: string | null
  requestedRole: string
  status: 'pending' | 'approved' | 'refused'
  refusalReason: string | null
  createdAt: string
  decidedAt: string | null
}

/** The public selector feed's org (GET /api/op/organizations). */
interface SelectableOrg {
  id: string
  name: string
  shortName: string
  kind: string
  country: string
  roles: string[]
}

/** TODO.identity/08's links API row. */
interface LinkRow {
  provider: string
  displayName: string
  brandMark: string | null
  providerAccountId: string
  linkedAt: string
  linkedBy: string | null
}
interface PublicProvider { id: string; kind: string; displayName: string; brandMark: string | null }

/** The activity feed's row (the OP's audit chain, the account's own). */
interface ActivityEvent {
  id: string
  timestamp: string
  action: string
  metadata: Record<string, unknown>
}

const route = useRoute()
const router = useRouter()

const loading = ref(true)
/** 'unavailable' = a non-identity deployment (the OP routes 404). */
const posture = ref<'ok' | 'unavailable'>('ok')
const context = ref<AccountContext | null>(null)
const links = ref<LinkRow[]>([])
const providers = ref<PublicProvider[]>([])
const activity = ref<ActivityEvent[] | null>(null)
const notice = ref<string | null>(null)
const error = ref<string | null>(null)

/** The factor registry's payload (TODO.identity-sso/02+03): the console's
 *  FACTORS section reads it through the AccountFactors component, and the
 *  sign-in-methods guard counts the passkeys (a passkey is a way in). */
const factors = ref<FactorsPayload | null>(null)

// The profile edit.
const nameEditing = ref(false)
const nameDraft = ref('')
const nameBusy = ref(false)
const nameError = ref<string | null>(null)

// The email change.
const emailDraft = ref('')
const emailBusy = ref(false)
const emailError = ref<string | null>(null)
/** The requested change: the mailed line, or the honestly-shown link. */
const emailResult = ref<{ delivery: string; newEmail: string; expiresAt: string; verificationUrl?: string } | null>(null)

// The password form.
const currentPassword = ref('')
const nextPassword = ref('')
const confirmPassword = ref('')
const passwordBusy = ref(false)

const sessionBusy = ref<string | null>(null)
const revokeOthersBusy = ref(false)
const acting = ref<string | null>(null) // a provider id, or 'password'

// ── the organizations (TODO.identity/11 — the multi-org model) ───────
/** An org id while its act runs ('request' while the join ask flies). */
const orgBusy = ref<string | null>(null)
const selectableOrgs = ref<SelectableOrg[]>([])
const joinOrgId = ref('')
const joinRole = ref('')
const joinNote = ref('')

/** The organizations block (null until the context loads). */
const orgBlock = computed(() => context.value?.organizations ?? null)

/** The display name for an org id (the memberships' resolved names,
 *  then the register feed's — a not-yet-member asking to join still
 *  sees the name). */
function orgName(orgId: string | null): string {
  if (!orgId) return ''
  return orgBlock.value?.memberships.find(m => m.orgId === orgId)?.orgName
    ?? selectableOrgs.value.find(o => o.id === orgId)?.name
    ?? orgId
}

/** The org currently acted as (the effective context's display name). */
const actingAsName = computed(() => orgName(orgBlock.value?.effectiveOrg ?? null))

/** The orgs the account may still ask to join: registered, not already
 *  a membership, not already waiting on a pending ask. */
const joinableOrgs = computed(() => {
  const taken = new Set((orgBlock.value?.memberships ?? []).map(m => m.orgId))
  const asked = new Set((orgBlock.value?.requests ?? []).filter(r => r.status === 'pending' && r.orgId).map(r => r.orgId!))
  return selectableOrgs.value.filter(o => !taken.has(o.id) && !asked.has(o.id))
})

/** The role options follow the selected org's kind (the feed carries
 *  the bounded set). */
const joinRoles = computed(() => selectableOrgs.value.find(o => o.id === joinOrgId.value)?.roles ?? [])

/** The context switch (the GitHub pattern): the session acts AS the
 *  chosen org from the next request on. The page reloads so every
 *  surface (the header, the role line, the admin entry points)
 *  re-resolves under the new context. */
async function switchOrg(orgId: string | null) {
  if (orgBusy.value) return
  orgBusy.value = orgId ?? 'primary'
  error.value = null
  notice.value = null
  try {
    const res = await fetch('/api/op/account/active-org', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ org_id: orgId }),
    })
    if (!res.ok) {
      const body = await res.json().catch(() => null) as { error?: string } | null
      error.value = body?.error ?? t('account.networkError')
      orgBusy.value = null
      return
    }
    window.location.reload()
  } catch {
    error.value = t('account.networkError')
    orgBusy.value = null
  }
}

async function answerInvitation(orgId: string, accept: boolean) {
  if (orgBusy.value) return
  orgBusy.value = orgId
  error.value = null
  notice.value = null
  try {
    const res = await fetch(`/api/op/account/memberships/${encodeURIComponent(orgId)}/${accept ? 'accept' : 'decline'}`, {
      method: 'POST',
      credentials: 'include',
    })
    if (!res.ok) {
      const body = await res.json().catch(() => null) as { error?: string } | null
      error.value = body?.error ?? t('account.networkError')
      orgBusy.value = null
      return
    }
    notice.value = accept
      ? t('account.organizations.accepted', { org: orgName(orgId) })
      : t('account.organizations.declined', { org: orgName(orgId) })
    await load()
    orgBusy.value = null
  } catch {
    error.value = t('account.networkError')
    orgBusy.value = null
  }
}

/** Ask to join another registered organization (the org's administrator
 *  decides — the ask lands in its queue). */
async function requestMembership() {
  if (orgBusy.value) return
  error.value = null
  notice.value = null
  if (!joinOrgId.value || !joinRole.value) return
  orgBusy.value = 'request'
  try {
    const res = await fetch('/api/op/account/membership-requests', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ org_id: joinOrgId.value, requested_role: joinRole.value, note: joinNote.value.trim() || null }),
    })
    if (!res.ok) {
      const body = await res.json().catch(() => null) as { error?: string } | null
      error.value = body?.error ?? t('account.networkError')
      orgBusy.value = null
      return
    }
    notice.value = t('account.organizations.requested', { org: orgName(joinOrgId.value) || joinOrgId.value })
    joinOrgId.value = ''
    joinRole.value = ''
    joinNote.value = ''
    await load()
    orgBusy.value = null
  } catch {
    error.value = t('account.networkError')
    orgBusy.value = null
  }
}

/** The enabled providers the account has NOT yet linked. */
const linkable = computed(() => providers.value.filter(p => !links.value.some(l => l.provider === p.id)))

/** THE GUARD, client-side (the server holds the same rule): removing
 *  this method would strand the account with no way in. The passkeys
 *  count (TODO.identity-sso/02): a passkey is a PRIMARY sign-in method. */
const passkeyCount = computed(() => factors.value?.passkeys.length ?? 0)
const passwordIsLastMethod = computed(() => (context.value?.passwordSet ?? false) && links.value.length === 0 && passkeyCount.value === 0)
const linkIsLastMethod = computed(() => links.value.length === 1 && !(context.value?.passwordSet ?? false) && passkeyCount.value === 0)
/** The factors section's revoke guard: the sole passkey is the last way in. */
const lastPasskeyIsLastMethod = computed(() => passkeyCount.value === 1 && !(context.value?.passwordSet ?? false) && links.value.length === 0)

/** The avatar's initials fallback (the avatar itself is the uploaded
 *  picture, or a linked provider's). */
const initials = computed(() => {
  const name = context.value?.account.name ?? ''
  const parts = name.trim().split(/\s+/).filter(Boolean)
  return ((parts[0]?.[0] ?? '') + (parts[parts.length - 1]?.[0] ?? '')).toUpperCase() || '?'
})

// ── the avatar upload ────────────────────────────────────────────────
// The size cap + the raster-type allowlist are mirrored client-side for
// the fast honest refusal; the server re-judges both (and sniffs the
// bytes) — the page is never the only gate. The picked file passes
// through the CROP step (components/AvatarCropDialog.vue): the square
// framing, then the final 256 px PNG rendered client-side (canvas →
// blob) — the route is never trusted to fix the image.
const avatarInput = ref<HTMLInputElement | null>(null)
const avatarBusy = ref(false)
const avatarError = ref<string | null>(null)
/** The picked file waiting on its crop (the dialog is open while set). */
const cropFile = ref<File | null>(null)
/** Cache-buster for the serving URL after an upload/remove (the avatar
 *  route answers no-cache; the src must still change for the refetch). */
const avatarBust = ref(0)

/** The avatar img's src: the OP's own serving route gets the cache-bust;
 *  a linked provider's URL passes through untouched. */
const avatarSrc = computed(() => {
  const url = context.value?.account.avatarUrl
  if (!url) return null
  return url.startsWith('/') ? `${url}?v=${avatarBust.value}` : url
})

/** The upload affordance shows only where the server says the blob store
 *  is bound (a deployment without one shows the honest note instead). */
const avatarUploads = computed(() => context.value?.features?.avatarUploads ?? false)
const avatarMaxMb = computed(() => Math.round(((context.value?.features?.avatarMaxBytes ?? 2 * 1024 * 1024) / 1024 / 1024) * 10) / 10)

function pickAvatar() {
  avatarError.value = null
  avatarInput.value?.click()
}

/** The picked file: the fast honest refusals (the server's cap + type
 *  allowlist, mirrored), then the CROP step opens — the upload only runs
 *  on the dialog's confirm, with the blob the crop produced. */
function onAvatarPicked(e: Event) {
  const file = (e.target as HTMLInputElement).files?.[0]
  ;(e.target as HTMLInputElement).value = '' // the same file again must re-fire
  if (!file || avatarBusy.value) return
  avatarError.value = null
  notice.value = null
  const maxBytes = context.value?.features?.avatarMaxBytes ?? 2 * 1024 * 1024
  if (file.size > maxBytes) {
    avatarError.value = t('account.profile.avatarTooLarge', { max: avatarMaxMb.value })
    return
  }
  if (!(AVATAR_ACCEPT_TYPES as readonly string[]).includes(file.type)) {
    avatarError.value = t('account.profile.avatarWrongType')
    return
  }
  cropFile.value = file
}

async function onCropConfirm(blob: Blob) {
  cropFile.value = null
  // The defensive mirror of the server's cap: the crop output is a small
  // square PNG, far under the cap in practice — the check stays because
  // the console never hides a limit (and the server re-judges anyway).
  const maxBytes = context.value?.features?.avatarMaxBytes ?? 2 * 1024 * 1024
  if (blob.size > maxBytes) {
    avatarError.value = t('account.profile.avatarTooLarge', { max: avatarMaxMb.value })
    return
  }
  avatarBusy.value = true
  try {
    const res = await fetch('/api/op/account/avatar', {
      method: 'PUT',
      headers: { 'content-type': blob.type },
      credentials: 'include',
      body: blob,
    })
    if (!res.ok) {
      const body = await res.json().catch(() => null) as { error?: string } | null
      avatarError.value = body?.error ?? t('account.networkError')
      avatarBusy.value = false
      return
    }
    avatarBust.value = Date.now()
    notice.value = t('account.profile.avatarSaved')
    await load()
    avatarBusy.value = false
  } catch {
    avatarError.value = t('account.networkError')
    avatarBusy.value = false
  }
}

async function removeAvatar() {
  if (avatarBusy.value) return
  avatarBusy.value = true
  avatarError.value = null
  notice.value = null
  try {
    const res = await fetch('/api/op/account/avatar', { method: 'DELETE', credentials: 'include' })
    if (!res.ok) {
      const body = await res.json().catch(() => null) as { error?: string } | null
      avatarError.value = body?.error ?? t('account.networkError')
      avatarBusy.value = false
      return
    }
    avatarBust.value = Date.now()
    notice.value = t('account.profile.avatarRemoved')
    await load()
    avatarBusy.value = false
  } catch {
    avatarError.value = t('account.networkError')
    avatarBusy.value = false
  }
}

// The meter mirrors server/auth/passwords.ts's classes — DISPLAY only
// (the server re-judges the policy at submit; a drift here can only ever
// under-advise, never admit a weaker password).
const strength = computed(() => {
  const pw = nextPassword.value
  const len = pw.length
  let variety = 0
  if (/[a-z]/.test(pw)) variety++
  if (/[A-Z]/.test(pw)) variety++
  if (/[0-9]/.test(pw)) variety++
  if (/[^a-zA-Z0-9]/.test(pw)) variety++
  if (len < 12) return { score: 0, label: t('account.password.strength.tooShort'), hint: t('account.password.strength.hintShort', { count: 12 - len }) }
  if (len < 16 && variety < 3) return { score: 1, label: t('account.password.strength.fair'), hint: t('account.password.strength.hintLonger') }
  if (len < 20) return { score: 2, label: t('account.password.strength.good'), hint: variety < 3 ? t('account.password.strength.hintMix') : t('account.password.strength.hintMore') }
  return { score: 3, label: t('account.password.strength.strong'), hint: '' }
})
const METER_COLORS = ['bg-red-400', 'bg-amber-400', 'bg-brand-400', 'bg-green-500']

/** The activity row's label: the catalog's per-action copy when it
 *  exists, the raw action otherwise (the feed never renders blank).
 *  TODO.identity-sso/02+03: the sign-in event's label follows the
 *  metadata's method (password+factor combinations read honestly). */
function activityLabel(event: ActivityEvent): string {
  let key = `account.activity.action.${event.action}` as MessageKey
  if (event.action === 'account.sign_in' && typeof event.metadata.method === 'string') {
    const variant = `account.activity.action.account.sign_in.${event.metadata.method.replaceAll('+', '_')}` as MessageKey
    // The catalog resolves known variants; an unknown one falls back to
    // the base label (t() answers the key itself when missing).
    if (t(variant) !== variant) key = variant
  }
  const params: Record<string, string | number> = {}
  if (typeof event.metadata.to === 'string') params.to = event.metadata.to
  if (typeof event.metadata.provider === 'string') params.provider = event.metadata.provider
  if (typeof event.metadata.count === 'number') params.count = event.metadata.count
  // TODO.identity/11: the org acts resolve the org's name from the
  // memberships (the audit metadata carries the org id).
  if (typeof event.metadata.org_id === 'string') params.org = orgName(event.metadata.org_id) || event.metadata.org_id
  if (typeof event.metadata.name === 'string') params.name = event.metadata.name
  const resolved = t(key, params)
  return resolved === key ? event.action : resolved
}

/** The link-mode refusals (the upstream callback's ?error= values),
 *  plain language, never a stack trace (08's mapping, keyed now). */
function linkErrorMessage(key: string, providerId: string): string {
  const name = providers.value.find(p => p.id === providerId)?.displayName ?? providerId
  if (key === 'link_taken' || key === 'provider_linked' || key === 'link_session') {
    return t(`account.linkError.${key}` as MessageKey, { name })
  }
  if (key.startsWith('upstream_')) return t('account.linkError.upstream', { name, reason: key.slice('upstream_'.length) })
  return t('account.linkError.generic')
}

function fmtDate(iso: string): string {
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })
}

async function load(quiet = false) {
  // A quiet reload (the factors section's @changed) never flips the
  // spinner: the v-if swap would UNMOUNT the factors component and drop
  // its local state mid-ceremony (the shown-once recovery dialog — the
  // id-11 leg-1 lesson).
  if (!quiet) loading.value = true
  try {
    const res = await fetch('/api/op/account', { credentials: 'include' })
    if (res.status === 404) {
      posture.value = 'unavailable'
      loading.value = false
      return
    }
    if (res.status === 401) {
      router.replace(`/?redirect=${encodeURIComponent('/op/account')}`)
      return
    }
    if (!res.ok) throw new Error(`HTTP ${res.status}`)
    context.value = await res.json() as AccountContext
    const [linksRes, providersRes, activityRes, orgsRes, factorsRes] = await Promise.all([
      fetch('/api/op/account/links', { credentials: 'include' }),
      fetch('/api/op/providers/public'),
      fetch('/api/op/account/activity', { credentials: 'include' }),
      // The registered-orgs feed (public) — the join form's selector.
      fetch('/api/op/organizations'),
      // TODO.identity-sso/02+03: the factor registry (the console's FACTORS section).
      fetch('/api/op/account/factors', { credentials: 'include' }),
    ])
    if (linksRes.ok) links.value = await linksRes.json() as LinkRow[]
    providers.value = providersRes.ok ? await providersRes.json() as PublicProvider[] : []
    activity.value = activityRes.ok ? await activityRes.json() as ActivityEvent[] : []
    selectableOrgs.value = orgsRes.ok ? await orgsRes.json() as SelectableOrg[] : []
    factors.value = factorsRes.ok ? await factorsRes.json() as FactorsPayload : null
    loading.value = false
  } catch {
    error.value = t('account.loadError')
    loading.value = false
  }
}

async function loadQuiet(): Promise<void> {
  await load(true)
}

onMounted(async () => {
  await load()
  if (posture.value !== 'ok') return
  // The upstream callback's flashes (TODO.identity/08's keys).
  const linked = route.query.linked as string | undefined
  if (linked) {
    const name = providers.value.find(p => p.id === linked)?.displayName ?? linked
    notice.value = t('account.notice.linked', { name })
  }
  const errorKey = route.query.error as string | undefined
  if (errorKey) error.value = linkErrorMessage(errorKey, (route.query.provider as string | undefined) ?? '')
})

// ── the profile ──────────────────────────────────────────────────────

function startNameEdit() {
  nameDraft.value = context.value?.account.name ?? ''
  nameError.value = null
  nameEditing.value = true
}

async function saveName() {
  if (nameBusy.value) return
  const name = nameDraft.value.trim()
  if (!name) {
    nameError.value = t('account.profile.nameRequired')
    return
  }
  nameBusy.value = true
  error.value = null
  notice.value = null
  try {
    const res = await fetch('/api/op/account/profile', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ name }),
    })
    if (!res.ok) {
      const body = await res.json().catch(() => null) as { error?: string } | null
      nameError.value = body?.error ?? t('account.networkError')
      nameBusy.value = false
      return
    }
    nameEditing.value = false
    notice.value = t('account.profile.saved')
    await load()
    nameBusy.value = false
  } catch {
    nameError.value = t('account.networkError')
    nameBusy.value = false
  }
}

const emailDraftValid = computed(() => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(emailDraft.value.trim()))

async function requestEmailChange() {
  if (emailBusy.value) return
  emailError.value = null
  notice.value = null
  const email = emailDraft.value.trim().toLowerCase()
  if (!emailDraftValid.value) {
    emailError.value = t('account.profile.emailInvalid')
    return
  }
  emailBusy.value = true
  try {
    const res = await fetch('/api/op/account/email', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ email }),
    })
    if (!res.ok) {
      const body = await res.json().catch(() => null) as { error?: string } | null
      emailError.value = body?.error ?? t('account.networkError')
      emailBusy.value = false
      return
    }
    emailResult.value = await res.json() as { delivery: string; newEmail: string; expiresAt: string; verificationUrl?: string }
    emailDraft.value = ''
    await load()
    emailBusy.value = false
  } catch {
    emailError.value = t('account.networkError')
    emailBusy.value = false
  }
}

// ── the sign-in methods ──────────────────────────────────────────────

function startLink(providerId: string) {
  window.location.assign(`/op/upstream/${encodeURIComponent(providerId)}/link`)
}

async function unlink(providerId: string) {
  if (acting.value) return
  acting.value = providerId
  error.value = null
  notice.value = null
  try {
    const res = await fetch(`/api/op/account/links/${encodeURIComponent(providerId)}`, {
      method: 'DELETE',
      credentials: 'include',
    })
    if (!res.ok) {
      const body = await res.json().catch(() => null) as { error?: string } | null
      error.value = body?.error ?? t('account.linkError.generic')
    } else {
      links.value = links.value.filter(l => l.provider !== providerId)
      notice.value = t('account.methods.unlinked')
      await load()
    }
  } catch {
    error.value = t('account.networkError')
  } finally {
    acting.value = null
  }
}

async function removePassword() {
  if (acting.value) return
  acting.value = 'password'
  error.value = null
  notice.value = null
  try {
    const res = await fetch('/api/op/account/password', { method: 'DELETE', credentials: 'include' })
    if (!res.ok) {
      const body = await res.json().catch(() => null) as { error?: string } | null
      error.value = body?.error ?? t('account.networkError')
    } else {
      notice.value = t('account.methods.passwordRemoved')
      await load()
    }
  } catch {
    error.value = t('account.networkError')
  } finally {
    acting.value = null
  }
}

// ── the password ─────────────────────────────────────────────────────

async function changePassword() {
  if (passwordBusy.value) return
  error.value = null
  notice.value = null
  if (nextPassword.value.length < 12) {
    error.value = t('account.password.tooShort')
    return
  }
  if (nextPassword.value !== confirmPassword.value) {
    error.value = t('account.password.mismatch')
    return
  }
  passwordBusy.value = true
  try {
    const res = await fetch('/api/op/account/password', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({
        ...(context.value?.passwordSet ? { current: currentPassword.value } : {}),
        next: nextPassword.value,
      }),
    })
    if (!res.ok) {
      const body = await res.json().catch(() => null) as { error?: string } | null
      error.value = body?.error ?? 'The password could not be changed.'
      passwordBusy.value = false
      return
    }
    const body = await res.json() as { otherSessionsRevoked?: number }
    currentPassword.value = ''
    nextPassword.value = ''
    confirmPassword.value = ''
    notice.value = body.otherSessionsRevoked
      ? t('account.password.changedRevoked', { count: body.otherSessionsRevoked })
      : t('account.password.changed')
    await load()
    passwordBusy.value = false
  } catch {
    error.value = t('account.networkError')
    passwordBusy.value = false
  }
}

// ── the sessions ─────────────────────────────────────────────────────

async function revokeSession(id: string, current: boolean) {
  if (sessionBusy.value) return
  sessionBusy.value = id
  error.value = null
  try {
    const res = await fetch(`/api/op/account/sessions/${encodeURIComponent(id)}/revoke`, {
      method: 'POST',
      credentials: 'include',
    })
    if (!res.ok) {
      const body = await res.json().catch(() => null) as { error?: string } | null
      error.value = body?.error ?? 'The session could not be revoked.'
      sessionBusy.value = null
      return
    }
    if (current) {
      // Revoking the current session ends THIS sign-in — to the login page.
      router.replace('/')
      return
    }
    notice.value = t('account.sessions.revoked')
    await load()
    sessionBusy.value = null
  } catch {
    error.value = t('account.networkError')
    sessionBusy.value = null
  }
}

async function revokeOthers() {
  if (revokeOthersBusy.value) return
  revokeOthersBusy.value = true
  error.value = null
  notice.value = null
  try {
    const res = await fetch('/api/op/account/sessions/revoke-others', { method: 'POST', credentials: 'include' })
    if (!res.ok) {
      error.value = t('account.networkError')
      revokeOthersBusy.value = false
      return
    }
    const body = await res.json() as { revoked: number }
    notice.value = t('account.sessions.revokeOthersDone', { count: body.revoked })
    await load()
    revokeOthersBusy.value = false
  } catch {
    error.value = t('account.networkError')
    revokeOthersBusy.value = false
  }
}
</script>

<template>
  <div class="max-w-3xl mx-auto px-6 py-8" data-testid="op-account">
    <PageHeader
      :title="t('account.title')"
      :description="t('account.description')"
    />

    <!-- The non-identity deployment's honest card. -->
    <section
      v-if="posture === 'unavailable'"
      class="bg-white dark:bg-slate-800 rounded-xl border border-slate-200/80 dark:border-slate-700 p-6"
      data-testid="account-unavailable"
    >
      <p class="text-sm text-slate-600 dark:text-slate-300">{{ t('account.unavailable') }}</p>
    </section>

    <div v-else>
      <div v-if="loading" class="flex justify-center py-8">
        <div class="w-8 h-8 border-2 border-brand-300 border-t-brand-600 rounded-full animate-spin" />
      </div>

      <template v-else-if="context">
        <!-- The flash + the error boxes. -->
        <div v-if="notice" class="mb-4 p-3 rounded-lg bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800">
          <p class="text-sm text-green-700 dark:text-green-300" data-testid="op-account-notice">{{ notice }}</p>
        </div>
        <div v-if="error" class="mb-4 p-3 rounded-lg bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800">
          <p class="text-sm text-red-700 dark:text-red-300" data-testid="op-account-error">{{ error }}</p>
        </div>

        <!-- 1 · The profile. -->
        <section id="profile" class="bg-white dark:bg-slate-800 rounded-xl border border-slate-200/80 dark:border-slate-700 p-6 mb-6" data-testid="account-profile">
          <h2 class="text-sm font-semibold text-slate-900 dark:text-white mb-4">{{ t('account.profile.title') }}</h2>
          <div class="flex items-start gap-4">
            <!-- The avatar: the uploaded picture, the linked provider's
                 picture, the initials otherwise. The upload rides the
                 server's own cap + type allowlist (named honestly). -->
            <div class="shrink-0">
              <img
                v-if="avatarSrc"
                :src="avatarSrc"
                :alt="context.account.name"
                class="w-12 h-12 rounded-full border border-slate-200 dark:border-slate-700 object-cover"
                data-testid="account-avatar"
              />
              <div
                v-else
                class="w-12 h-12 rounded-full bg-brand-100 dark:bg-brand-900/40 text-brand-700 dark:text-brand-200 flex items-center justify-center text-sm font-semibold"
                data-testid="account-avatar-initials"
              >{{ initials }}</div>
              <div v-if="avatarUploads" class="mt-2 flex flex-col items-center gap-1">
                <input
                  ref="avatarInput"
                  type="file"
                  accept="image/png,image/jpeg,image/webp,image/gif"
                  class="hidden"
                  data-testid="account-avatar-input"
                  @change="onAvatarPicked"
                />
                <button
                  type="button"
                  :disabled="avatarBusy"
                  data-testid="account-avatar-change"
                  class="text-xs font-medium text-brand-600 dark:text-brand-300 hover:underline disabled:opacity-50"
                  @click="pickAvatar"
                >{{ avatarBusy ? t('account.profile.avatarBusy') : t('account.profile.avatarChange') }}</button>
                <button
                  v-if="context.account.avatarUrl?.startsWith('/')"
                  type="button"
                  :disabled="avatarBusy"
                  data-testid="account-avatar-remove"
                  class="text-xs font-medium text-slate-500 dark:text-slate-400 hover:underline disabled:opacity-50"
                  @click="removeAvatar"
                >{{ t('account.profile.avatarRemove') }}</button>
              </div>
            </div>
            <div class="min-w-0 flex-1">
              <!-- The display name: read + inline edit. -->
              <div v-if="!nameEditing" class="flex items-center gap-3">
                <p class="text-sm font-medium text-slate-900 dark:text-white" data-testid="account-name">{{ context.account.name }}</p>
                <button
                  class="text-xs font-medium text-brand-600 dark:text-brand-300 hover:underline"
                  data-testid="account-profile-edit"
                  @click="startNameEdit"
                >{{ t('account.profile.edit') }}</button>
              </div>
              <form v-else class="flex items-center gap-2" @submit.prevent="saveName">
                <input
                  v-model="nameDraft"
                  type="text"
                  required
                  maxlength="200"
                  data-testid="account-profile-name-input"
                  class="w-64 px-3 py-1.5 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-500"
                  @input="nameError = null"
                />
                <button
                  type="submit"
                  :disabled="nameBusy"
                  data-testid="account-profile-save"
                  class="px-3 py-1.5 rounded-lg text-xs font-medium bg-brand-600 text-white hover:bg-brand-700 transition-colors disabled:opacity-50"
                >{{ nameBusy ? t('account.profile.saving') : t('account.profile.save') }}</button>
                <button
                  type="button"
                  class="px-3 py-1.5 rounded-lg text-xs font-medium border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-700 transition-colors"
                  data-testid="account-profile-cancel"
                  @click="nameEditing = false"
                >{{ t('account.profile.cancel') }}</button>
              </form>
              <p v-if="nameError" class="mt-1 text-xs text-red-600 dark:text-red-400" data-testid="account-profile-name-error">{{ nameError }}</p>

              <!-- The primary email + its verification state. -->
              <p class="mt-2 text-sm text-slate-700 dark:text-slate-300">
                <span class="text-slate-400 dark:text-slate-500">{{ t('account.profile.emailLabel') }}:</span>
                <span class="font-medium" data-testid="account-email">{{ context.account.email }}</span>
                <span
                  v-if="context.account.emailVerifiedAt"
                  class="ml-2 px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wider bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-300"
                  data-testid="account-email-verified"
                >{{ t('account.profile.verified') }}</span>
                <span
                  v-else
                  class="ml-2 px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wider bg-amber-100 dark:bg-amber-900/30 text-amber-700 dark:text-amber-300"
                  data-testid="account-email-unverified"
                >{{ t('account.profile.unverified') }}</span>
              </p>
              <p class="mt-1 text-xs text-slate-400 dark:text-slate-500" data-testid="account-email-verification-note">
                {{ context.account.emailVerifiedAt ? t('account.profile.verifiedNote') : t('account.profile.unverifiedNote') }}
              </p>
              <p class="mt-1 text-xs text-slate-400 dark:text-slate-500">{{ t('account.profile.roleLine', { role: context.account.role }) }}</p>
              <p class="mt-1 text-xs text-slate-400 dark:text-slate-500" data-testid="account-avatar-note">
                {{ avatarUploads ? t('account.profile.avatarNoteUpload', { max: avatarMaxMb }) : t('account.profile.avatarNote') }}
              </p>
              <!-- The public-by-convention posture, stated plainly: the
                   picture (or the initials fallback) serves from the
                   public /op/avatar/<id> route the OIDC `picture` claim
                   names — the RP's <img> loads it without a session. -->
              <p class="mt-1 text-xs text-slate-400 dark:text-slate-500" data-testid="account-avatar-public-note">
                {{ t('account.profile.avatarPublic') }}
              </p>
              <p v-if="avatarError" class="mt-1 text-xs text-red-600 dark:text-red-400" data-testid="account-avatar-error">{{ avatarError }}</p>

              <!-- The pending change, when one waits on its link. -->
              <p
                v-if="context.pendingEmailChange"
                class="mt-3 text-xs text-slate-600 dark:text-slate-300 rounded-lg bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800 p-2"
                data-testid="account-email-pending"
              >
                {{ t('account.profile.emailPending', { email: context.pendingEmailChange.newEmail, expires: fmtDate(context.pendingEmailChange.expiresAt) }) }}
              </p>

              <!-- The verify-new-email ceremony. -->
              <form class="mt-4 max-w-sm" @submit.prevent="requestEmailChange">
                <label class="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">{{ t('account.profile.newEmailLabel') }}</label>
                <div class="flex items-center gap-2">
                  <input
                    v-model="emailDraft"
                    type="email"
                    data-testid="account-email-input"
                    class="flex-1 px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-500"
                    @input="emailError = null"
                  />
                  <button
                    type="submit"
                    :disabled="emailBusy || !emailDraftValid"
                    data-testid="account-email-submit"
                    class="shrink-0 px-3 py-2 rounded-lg text-xs font-medium border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-700 transition-colors disabled:opacity-50"
                  >{{ emailBusy ? t('account.profile.emailBusy') : t('account.profile.emailSubmit') }}</button>
                </div>
                <p v-if="emailError" class="mt-1 text-xs text-red-600 dark:text-red-400" data-testid="account-email-error">{{ emailError }}</p>
              </form>

              <!-- The requested change: the mailed line, or the honestly-shown link. -->
              <div
                v-if="emailResult"
                class="mt-3 rounded-lg border p-3 text-xs"
                :class="emailResult.delivery === 'mailer'
                  ? 'bg-green-50 dark:bg-green-900/20 border-green-200 dark:border-green-800 text-green-700 dark:text-green-300'
                  : 'bg-amber-50 dark:bg-amber-900/20 border-amber-200 dark:border-amber-800 text-amber-800 dark:text-amber-200'"
                data-testid="account-email-delivery"
              >
                <p v-if="emailResult.delivery === 'mailer'">{{ t('account.profile.emailMailed', { email: emailResult.newEmail }) }}</p>
                <template v-else>
                  <p>{{ t('account.profile.emailShown') }}</p>
                  <a
                    v-if="emailResult.verificationUrl"
                    :href="emailResult.verificationUrl"
                    class="inline-block mt-2 font-medium text-brand-700 dark:text-brand-300 hover:underline break-all"
                    data-testid="account-email-link"
                  >{{ t('account.profile.emailShownAction') }}</a>
                </template>
              </div>
            </div>
          </div>
        </section>

        <!-- 2 · The organizations (TODO.identity/11 — the multi-org model). -->
        <section id="organizations" class="bg-white dark:bg-slate-800 rounded-xl border border-slate-200/80 dark:border-slate-700 p-6 mb-6" data-testid="account-organizations">
          <h2 class="text-sm font-semibold text-slate-900 dark:text-white mb-1">{{ t('account.organizations.title') }}</h2>
          <p class="text-xs text-slate-500 dark:text-slate-400 mb-4">{{ t('account.organizations.description') }}</p>

          <!-- The current context, honestly named. -->
          <p class="mb-4 text-xs text-slate-600 dark:text-slate-300" data-testid="account-active-context">
            <template v-if="actingAsName">{{ t('account.organizations.actingAs', { org: actingAsName }) }}</template>
            <template v-else>{{ t('account.organizations.actingAsNone') }}</template>
          </p>

          <p v-if="orgBlock && !orgBlock.memberships.length" class="text-sm text-slate-500 dark:text-slate-400 mb-4" data-testid="account-orgs-empty">
            {{ t('account.organizations.empty') }}
          </p>

          <ul v-if="orgBlock?.memberships.length" class="space-y-2 mb-4" data-testid="account-orgs-list">
            <li
              v-for="m in orgBlock.memberships"
              :key="m.orgId"
              class="rounded-lg border border-slate-200 dark:border-slate-700 px-4 py-3"
              :data-testid="`account-org-${m.orgId}`"
            >
              <div class="flex items-center justify-between gap-3">
                <div class="min-w-0">
                  <p class="text-sm font-medium text-slate-900 dark:text-white">
                    {{ m.orgName }}
                    <span v-if="m.isPrimary" class="ml-1 text-[10px] font-semibold uppercase tracking-wider text-slate-400 dark:text-slate-500" :data-testid="`account-org-primary-${m.orgId}`">{{ t('account.organizations.primaryBadge') }}</span>
                    <span
                      v-if="m.state === 'active' && (orgBlock.effectiveOrg === m.orgId)"
                      class="ml-1 px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wider bg-brand-100 dark:bg-brand-900/40 text-brand-700 dark:text-brand-200"
                      :data-testid="`account-org-acting-${m.orgId}`"
                    >{{ t('account.organizations.actingBadge') }}</span>
                  </p>
                  <p class="text-xs text-slate-400 dark:text-slate-500" :data-testid="`account-org-roles-${m.orgId}`">
                    {{ m.roles.length ? m.roles.join(', ') : t('account.organizations.noRoles') }}
                  </p>
                </div>
                <div class="shrink-0 flex items-center gap-2">
                  <!-- The state badge. -->
                  <span
                    v-if="m.state === 'invited'"
                    class="px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wider bg-amber-100 dark:bg-amber-900/30 text-amber-700 dark:text-amber-300"
                    :data-testid="`account-org-invited-${m.orgId}`"
                  >{{ t('account.organizations.stateInvited') }}</span>
                  <span
                    v-else-if="m.state === 'disabled'"
                    class="px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wider bg-red-100 dark:bg-red-900/40 text-red-600 dark:text-red-400"
                    :data-testid="`account-org-disabled-${m.orgId}`"
                  >{{ t('account.organizations.stateDisabled') }}</span>
                  <!-- The context switch. -->
                  <button
                    v-if="m.state === 'active' && orgBlock.activeOrg !== m.orgId && !(orgBlock.activeOrg === null && m.isPrimary)"
                    type="button"
                    :disabled="orgBusy === m.orgId"
                    :data-testid="`account-org-switch-${m.orgId}`"
                    class="px-3 py-1.5 rounded-lg text-xs font-medium border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-700 transition-colors disabled:opacity-50"
                    @click="switchOrg(m.orgId)"
                  >{{ orgBusy === m.orgId ? t('account.organizations.switchBusy') : t('account.organizations.switch', { org: m.orgName }) }}</button>
                  <button
                    v-if="m.state === 'active' && orgBlock.activeOrg === m.orgId && !m.isPrimary"
                    type="button"
                    :disabled="orgBusy === 'primary'"
                    :data-testid="`account-org-return-${m.orgId}`"
                    class="px-3 py-1.5 rounded-lg text-xs font-medium border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-700 transition-colors disabled:opacity-50"
                    @click="switchOrg(null)"
                  >{{ orgBusy === 'primary' ? t('account.organizations.switchBusy') : t('account.organizations.returnPrimary') }}</button>
                </div>
              </div>
              <!-- The invitation's answer. -->
              <div v-if="m.state === 'invited'" class="mt-2 flex items-center gap-2" :data-testid="`account-org-invitation-${m.orgId}`">
                <p class="text-xs text-amber-700 dark:text-amber-300 mr-2">
                  {{ t('account.organizations.invitedNote', { by: m.invitedBy ?? '—' }) }}
                </p>
                <button
                  type="button"
                  :disabled="orgBusy === m.orgId"
                  :data-testid="`account-org-accept-${m.orgId}`"
                  class="px-3 py-1.5 rounded-lg text-xs font-medium bg-brand-600 text-white hover:bg-brand-700 transition-colors disabled:opacity-50"
                  @click="answerInvitation(m.orgId, true)"
                >{{ t('account.organizations.accept') }}</button>
                <button
                  type="button"
                  :disabled="orgBusy === m.orgId"
                  :data-testid="`account-org-decline-${m.orgId}`"
                  class="px-3 py-1.5 rounded-lg text-xs font-medium border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-700 transition-colors disabled:opacity-50"
                  @click="answerInvitation(m.orgId, false)"
                >{{ t('account.organizations.decline') }}</button>
              </div>
              <p v-if="m.state === 'disabled'" class="mt-2 text-xs text-red-600 dark:text-red-400" :data-testid="`account-org-disabled-note-${m.orgId}`">
                {{ t('account.organizations.disabledNote', { date: m.disabledAt ? fmtDate(m.disabledAt) : '—', by: m.disabledBy ?? '—' }) }}
              </p>
            </li>
          </ul>

          <!-- The account's own asks (the state is honest: pending /
               refused with the reason / approved → the membership above). -->
          <ul v-if="orgBlock?.requests.length" class="space-y-1 mb-4" data-testid="account-org-requests">
            <li
              v-for="r in orgBlock.requests"
              :key="r.id"
              class="flex items-center justify-between rounded-lg border border-slate-100 dark:border-slate-700/60 px-3 py-2"
              :data-testid="`account-org-request-${r.id}`"
            >
              <p class="text-xs text-slate-600 dark:text-slate-300">
                {{ r.orgName ?? r.orgNameText ?? r.orgId }} · {{ r.requestedRole }}
              </p>
              <p class="shrink-0 pl-3 text-xs" :data-testid="`account-org-request-status-${r.id}`">
                <span v-if="r.status === 'pending'" class="text-amber-600 dark:text-amber-400">{{ t('account.organizations.requestPending', { date: fmtDate(r.createdAt) }) }}</span>
                <span v-else-if="r.status === 'refused'" class="text-red-600 dark:text-red-400">{{ t('account.organizations.requestRefused', { reason: r.refusalReason ?? '' }) }}</span>
                <span v-else class="text-emerald-600 dark:text-emerald-400">{{ t('account.organizations.requestApproved') }}</span>
              </p>
            </li>
          </ul>

          <!-- The join ask: another registered organization. -->
          <div v-if="joinableOrgs.length" class="border-t border-slate-100 dark:border-slate-700/60 pt-4" data-testid="account-org-join">
            <h3 class="text-xs font-semibold text-slate-700 dark:text-slate-200 mb-2">{{ t('account.organizations.requestTitle') }}</h3>
            <div class="grid sm:grid-cols-2 gap-2 max-w-lg">
              <select
                v-model="joinOrgId"
                data-testid="account-org-join-org"
                class="px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-500"
                @change="joinRole = ''"
              >
                <option value="" disabled>{{ t('account.organizations.orgLabel') }}</option>
                <option v-for="o in joinableOrgs" :key="o.id" :value="o.id" :data-testid="`account-org-join-option-${o.id}`">{{ o.name }}</option>
              </select>
              <select
                v-model="joinRole"
                :disabled="!joinOrgId"
                data-testid="account-org-join-role"
                class="px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-500 disabled:opacity-50"
              >
                <option value="" disabled>{{ t('account.organizations.roleLabel') }}</option>
                <option v-for="r in joinRoles" :key="r" :value="r">{{ r }}</option>
              </select>
            </div>
            <input
              v-model="joinNote"
              type="text"
              maxlength="500"
              data-testid="account-org-join-note"
              class="mt-2 w-full max-w-lg px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-500"
              :placeholder="t('account.organizations.noteLabel')"
            />
            <button
              type="button"
              :disabled="orgBusy === 'request' || !joinOrgId || !joinRole"
              data-testid="account-org-join-submit"
              class="mt-2 px-4 py-2 rounded-lg text-sm font-medium bg-brand-600 text-white hover:bg-brand-700 transition-colors disabled:opacity-50"
              @click="requestMembership"
            >{{ orgBusy === 'request' ? t('account.organizations.requestBusy') : t('account.organizations.requestSubmit') }}</button>
          </div>
        </section>

        <!-- 3 · The sign-in methods (the password + TODO.identity/08's links). -->
        <section id="methods" class="bg-white dark:bg-slate-800 rounded-xl border border-slate-200/80 dark:border-slate-700 p-6 mb-6" data-testid="account-links">
          <h2 class="text-sm font-semibold text-slate-900 dark:text-white mb-1">{{ t('account.methods.title') }}</h2>
          <p class="text-xs text-slate-500 dark:text-slate-400 mb-4">{{ t('account.methods.description') }}</p>

          <ul class="space-y-2 mb-4" data-testid="account-methods-list">
            <!-- The password is a method too. -->
            <li
              class="flex items-center justify-between rounded-lg border border-slate-200 dark:border-slate-700 px-4 py-3"
              data-testid="account-method-password"
            >
              <div class="flex items-center gap-3 min-w-0">
                <svg class="w-4 h-4 shrink-0 text-slate-500 dark:text-slate-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
                <div class="min-w-0">
                  <p class="text-sm font-medium text-slate-900 dark:text-white">{{ t('account.methods.passwordLabel') }}</p>
                  <p class="text-xs text-slate-400 dark:text-slate-500" data-testid="account-method-password-state">
                    {{ context.passwordSet ? t('account.methods.passwordSet') : t('account.methods.passwordUnset') }}
                  </p>
                </div>
              </div>
              <div v-if="context.passwordSet" class="shrink-0 text-right">
                <button
                  :disabled="acting === 'password' || passwordIsLastMethod"
                  data-testid="account-method-password-remove"
                  @click="removePassword"
                  class="px-3 py-1.5 rounded-lg text-xs font-medium border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-700 transition-colors disabled:opacity-50"
                >{{ acting === 'password' ? t('account.methods.removing') : t('account.methods.remove') }}</button>
                <p v-if="passwordIsLastMethod" class="mt-1 max-w-56 text-[10px] text-slate-400 dark:text-slate-500" data-testid="account-password-guard">
                  {{ t('account.methods.lastOne') }}
                </p>
              </div>
            </li>

            <!-- The linked upstream identities. -->
            <li
              v-for="link in links"
              :key="link.provider"
              class="flex items-center justify-between rounded-lg border border-slate-200 dark:border-slate-700 px-4 py-3"
              :data-testid="`op-account-link-${link.provider}`"
            >
              <div class="flex items-center gap-3 min-w-0">
                <span class="shrink-0 text-slate-700 dark:text-slate-200"><UpstreamProviderIcon :brand-mark="link.brandMark" /></span>
                <div class="min-w-0">
                  <p class="text-sm font-medium text-slate-900 dark:text-white" :data-testid="`account-link-${link.provider}-label`">
                    {{ link.displayName }}
                  </p>
                  <p class="text-xs text-slate-400 dark:text-slate-500 truncate">
                    {{ t('account.methods.accountId', { id: link.providerAccountId }) }} · {{ t('account.methods.linkedAt', { date: fmtDate(link.linkedAt) }) }}<span v-if="link.linkedBy"> {{ t('account.methods.linkedBy', { by: link.linkedBy }) }}</span>
                  </p>
                </div>
              </div>
              <div class="shrink-0 text-right">
                <button
                  :disabled="acting === link.provider || linkIsLastMethod"
                  :data-testid="`op-account-unlink-${link.provider}`"
                  @click="unlink(link.provider)"
                  class="px-3 py-1.5 rounded-lg border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-700 transition-colors disabled:opacity-50 text-xs font-medium"
                >{{ t('account.methods.unlink') }}</button>
                <p v-if="linkIsLastMethod" class="mt-1 max-w-56 text-[10px] text-slate-400 dark:text-slate-500" data-testid="account-link-guard">
                  {{ t('account.methods.lastOne') }}
                </p>
              </div>
            </li>
          </ul>
          <p v-if="!links.length" class="text-sm text-slate-500 dark:text-slate-400 mb-4" data-testid="op-account-no-links">
            {{ t('account.methods.noLinks') }}
          </p>
          <div v-if="linkable.length" class="space-y-2">
            <button
              v-for="provider in linkable"
              :key="provider.id"
              :data-testid="`op-account-link-${provider.id}-action`"
              @click="startLink(provider.id)"
              class="px-4 py-2 rounded-lg text-sm font-medium border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-900 dark:text-white hover:bg-slate-50 dark:hover:bg-slate-700 transition-colors flex items-center gap-2"
            >
              <UpstreamProviderIcon :brand-mark="provider.brandMark" />
              {{ t('account.methods.linkAction', { provider: provider.displayName }) }}
            </button>
          </div>
        </section>

        <!-- 3 · The factor registry (TODO.identity-sso/02+03): passkeys,
             authenticator apps, recovery codes. -->
        <AccountFactors
          :email-verified="!!context.account.emailVerifiedAt"
          :factors="factors"
          :last-passkey-is-last-method="lastPasskeyIsLastMethod"
          @changed="loadQuiet"
        />

        <!-- 4 · The password. -->
        <section id="password" class="bg-white dark:bg-slate-800 rounded-xl border border-slate-200/80 dark:border-slate-700 p-6 mb-6" data-testid="account-password">
          <h2 class="text-sm font-semibold text-slate-900 dark:text-white mb-1">{{ t('account.password.title') }}</h2>
          <p class="text-xs text-slate-500 dark:text-slate-400 mb-1" data-testid="account-password-state">
            {{ context.passwordSet ? t('account.password.stateSet') : t('account.password.stateUnset') }}
            {{ t('account.password.policy') }}
          </p>
          <p class="text-xs text-slate-500 dark:text-slate-400 mb-4">{{ t('account.password.revokeNote') }}</p>
          <form @submit.prevent="changePassword" class="space-y-3 max-w-sm">
            <div v-if="context.passwordSet">
              <label class="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">{{ t('account.password.currentLabel') }}</label>
              <input
                v-model="currentPassword"
                type="password"
                required
                autocomplete="current-password"
                data-testid="account-password-current"
                class="w-full px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-500"
              />
            </div>
            <div>
              <label class="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">{{ t('account.password.nextLabel') }}</label>
              <input
                v-model="nextPassword"
                type="password"
                required
                autocomplete="new-password"
                data-testid="account-password-next"
                class="w-full px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-500"
                :placeholder="t('account.password.policy')"
              />
              <!-- The honest meter: length carries the score. -->
              <div v-if="nextPassword" class="mt-2" data-testid="account-password-meter">
                <div class="flex gap-1 mb-1">
                  <div
                    v-for="step in 4"
                    :key="step"
                    class="h-1 flex-1 rounded-full"
                    :class="step - 1 <= strength.score && nextPassword.length >= 12 ? METER_COLORS[strength.score] : (strength.score === 0 && step === 1 ? METER_COLORS[0] : 'bg-slate-200 dark:bg-slate-700')"
                  />
                </div>
                <p class="text-xs text-slate-500 dark:text-slate-400">
                  <span class="font-medium" data-testid="account-password-meter-label">{{ strength.label }}</span>
                  <span v-if="strength.hint"> · {{ strength.hint }}</span>
                </p>
              </div>
            </div>
            <div>
              <label class="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">{{ t('account.password.confirmLabel') }}</label>
              <input
                v-model="confirmPassword"
                type="password"
                required
                autocomplete="new-password"
                data-testid="account-password-confirm"
                class="w-full px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-sm text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-brand-500"
              />
            </div>
            <button
              type="submit"
              :disabled="passwordBusy"
              data-testid="account-password-submit"
              class="px-4 py-2 rounded-lg text-sm font-medium bg-brand-600 text-white hover:bg-brand-700 transition-colors disabled:opacity-50 flex items-center gap-2"
            >
              <div v-if="passwordBusy" class="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
              {{ passwordBusy ? t('account.password.busy') : (context.passwordSet ? t('account.password.submitChange') : t('account.password.submitSet')) }}
            </button>
          </form>
        </section>

        <!-- 5 · The active sessions. -->
        <section id="sessions" class="bg-white dark:bg-slate-800 rounded-xl border border-slate-200/80 dark:border-slate-700 p-6 mb-6" data-testid="account-sessions">
          <div class="flex items-start justify-between gap-4 mb-1">
            <h2 class="text-sm font-semibold text-slate-900 dark:text-white">{{ t('account.sessions.title') }}</h2>
            <button
              v-if="context.sessions.length > 1"
              :disabled="revokeOthersBusy"
              data-testid="account-sessions-revoke-others"
              @click="revokeOthers"
              class="shrink-0 px-3 py-1.5 rounded-lg text-xs font-medium border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-700 transition-colors disabled:opacity-50"
            >{{ revokeOthersBusy ? t('account.sessions.revokeOthersBusy') : t('account.sessions.revokeOthers') }}</button>
          </div>
          <p class="text-xs text-slate-500 dark:text-slate-400 mb-4">{{ t('account.sessions.description') }}</p>
          <p v-if="context.sessions.length === 1" class="text-xs text-slate-400 dark:text-slate-500 mb-2" data-testid="account-sessions-only-current">
            {{ t('account.sessions.onlyCurrent') }}
          </p>
          <ul class="space-y-2" data-testid="account-session-list">
            <li
              v-for="session in context.sessions"
              :key="session.id"
              class="flex items-center justify-between rounded-lg border border-slate-200 dark:border-slate-700 px-4 py-3"
              :data-testid="`account-session-${session.id}`"
            >
              <div class="min-w-0">
                <p class="text-sm font-medium text-slate-900 dark:text-white">
                  {{ t('account.sessions.signedIn', { date: fmtDate(session.createdAt) }) }}
                  <span v-if="session.current" class="ml-2 text-[10px] font-semibold uppercase tracking-wider text-brand-600 dark:text-brand-300" data-testid="account-session-current">{{ t('account.sessions.current') }}</span>
                </p>
                <p class="text-xs text-slate-400 dark:text-slate-500">
                  {{ t('account.sessions.expires', { date: fmtDate(session.expiresAt) }) }} ·
                  {{ session.lastSeenAt ? t('account.sessions.lastActive', { date: fmtDate(session.lastSeenAt) }) : t('account.sessions.notRecorded') }}
                </p>
                <p class="text-xs text-slate-400 dark:text-slate-500 truncate" :data-testid="`account-session-${session.id}-agent`">
                  {{ session.userAgent ?? t('account.sessions.notRecorded') }}<span v-if="session.ip"> · {{ session.ip }}</span>
                </p>
              </div>
              <button
                :disabled="sessionBusy === session.id"
                :data-testid="`account-session-${session.id}-revoke`"
                @click="revokeSession(session.id, session.current)"
                class="shrink-0 px-3 py-1.5 rounded-lg text-xs font-medium border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-700 transition-colors disabled:opacity-50"
              >{{ t('account.sessions.revoke') }}</button>
            </li>
          </ul>
        </section>

        <!-- 6 · The activity feed. -->
        <section id="activity" class="bg-white dark:bg-slate-800 rounded-xl border border-slate-200/80 dark:border-slate-700 p-6" data-testid="account-activity">
          <h2 class="text-sm font-semibold text-slate-900 dark:text-white mb-1">{{ t('account.activity.title') }}</h2>
          <p class="text-xs text-slate-500 dark:text-slate-400 mb-4">{{ t('account.activity.description') }}</p>
          <p v-if="activity && !activity.length" class="text-sm text-slate-500 dark:text-slate-400" data-testid="account-activity-empty">
            {{ t('account.activity.empty') }}
          </p>
          <ul v-else-if="activity" class="space-y-2" data-testid="account-activity-list">
            <li
              v-for="event in activity"
              :key="event.id"
              class="flex items-center justify-between rounded-lg border border-slate-200 dark:border-slate-700 px-4 py-2.5"
              :data-testid="`account-activity-${event.action.replaceAll('.', '-')}`"
            >
              <p class="text-sm text-slate-700 dark:text-slate-300">{{ activityLabel(event) }}</p>
              <p class="shrink-0 pl-4 text-xs text-slate-400 dark:text-slate-500">{{ fmtDate(event.timestamp) }}</p>
            </li>
          </ul>
        </section>
      </template>

      <!-- The crop step of "Change the picture": the square framing runs
           client-side; the confirm emits the final PNG blob and the
           upload rides the route's own (unchanged) gates. -->
      <AvatarCropDialog
        v-if="cropFile"
        :file="cropFile"
        :max-bytes="context?.features?.avatarMaxBytes ?? 2 * 1024 * 1024"
        :busy="avatarBusy"
        @confirm="onCropConfirm"
        @cancel="cropFile = null"
      />
    </div>
  </div>
</template>
