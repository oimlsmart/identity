// ═══════════════════════════════════════════════════════════════════
// The organization-registry resolver (TODO.identity-features/05 —
// organizations as first-class citizens): the identity service's OWN
// org registry (the org_registry table, read through the store seam) is
// the identity plane's membership graph — every organization the
// account topology names, with its lifecycle.
//
// THE LINK, NEVER THE MERGE (the spec's §4): the platform's participant
// registry (the IAs/TLs with their OIML codes, the CS data pipeline) is
// the SCHEME's SSOT; this registry is the IDENTITY plane's. For a
// participant org the OIML code IS the id (the identity org for the IA
// with code EX1 has id "EX1"), so the platform resolves the org claim's
// value directly — the mapping is identity, never a lookup table. The
// row's OPTIONAL participantRef documents which participant record the
// org mirrors (the annotation, never a key); a non-participant org (the
// estate operator's own org, a scheme consumer) carries a free slug and
// kind NULL.
//
// THE LIFECYCLE: the identity administrator adds, edits, disables and
// (guarded) removes the orgs (routes/op-registry.ts). An org is ACTIVE
// or DISABLED — a disabled org admits nothing new (no memberships, no
// assignments, no join selector entry) and its memberships went disabled
// with it (the cascade). `registered` projects the PARTICIPANT posture
// the join flow's gates read: active AND carrying a participant kind
// (the public self-service intake is the scheme's participation flow —
// a non-participant org is never on it).
//
// The dev/e2e demonstration register seeds from the vendored snapshot
// (server/seed-org-register.ts); production starts EMPTY and the
// identity administrator adds the organizations deliberately (the
// migration 0013's header carries the doctrine).
//
// THE MANUFACTURER KIND (TODO.register/01): a manufacturer org is NOT a
// scheme-registered participant in the PD-03 sense — no peer assessment,
// no scope accreditation. Its registry STANDING is "declared" on
// self-registration (the join intake's manufacturer path: the founder's
// work email declares the domain hint, the org profile is complete) and
// upgrades to "IA-endorsed" when an issuing authority it applied to
// confirms the relationship (the endorsement act, routes/
// op-endorsements.ts — the orgEndorsements entity collection, riding the
// org-registry lifecycle's audit chain). A manufacturer row NEVER reads
// `registered` (the participant posture is the scheme's): the kind
// bounds the roles and the standing semantics differ by kind — the
// registry never lets a manufacturer row masquerade as a participant
// row.
//
// WORKER-SAFE: the ServerStore seam only — no node built-ins.
// ═══════════════════════════════════════════════════════════════════

import type { OrgRegistryOrg, ServerStore } from '@oimlsmart/platform-server/store'

/** The registry's organization kinds: the participants model's four
 *  participant kinds (data/oiml-cs/framework/participants.yaml) plus
 *  'manufacturer' (TODO.register/01) — a first-class registry kind that
 *  is NEVER a PD-03 participant. */
export type RegistryOrgKind = 'issuing-authority' | 'test-laboratory' | 'utilizer' | 'associate' | 'manufacturer'

const REGISTRY_ORG_KINDS = new Set<string>(['issuing-authority', 'test-laboratory', 'utilizer', 'associate', 'manufacturer'])

/** The PD-03 PARTICIPANT kinds (B 18 §10.2): the four the participants
 *  register carries. 'manufacturer' is deliberately NOT among them. */
const PARTICIPANT_KINDS = new Set<string>(['issuing-authority', 'test-laboratory', 'utilizer', 'associate'])

/** The write-time kind validation (the add/edit routes): the four
 *  participant kinds + 'manufacturer', or null/undefined for a
 *  non-participant org. */
export function isRegistryOrgKind(value: unknown): value is RegistryOrgKind {
  return typeof value === 'string' && REGISTRY_ORG_KINDS.has(value)
}

/** The registry standing (TODO.register/01 — the per-kind honesty): the
 *  scheme's registration for a participant kind; 'declared' for a
 *  self-registered manufacturer; 'ia-endorsed' once an issuing authority
 *  confirmed the relationship; 'non-participant' for a kind-NULL org.
 *  The lifecycle STATE (active/disabled) is orthogonal and renders
 *  separately — a disabled org's standing label never resurrects it. */
export type RegistryOrgStanding = 'participant' | 'declared' | 'ia-endorsed' | 'non-participant'

/** One IA's confirmation of a manufacturer relationship (the standing's
 *  upgrade act). The rows live in the entity store (the orgEndorsements
 *  collection — the same generic seam auditEvents rides): a revocation
 *  KEEPS the row with its stamps (the audit trail is the history). */
export interface OrgEndorsement {
  id: string
  /** The manufacturer org endorsed. */
  orgId: string
  /** The issuing-authority org that confirmed the relationship. */
  iaOrgId: string
  note: string | null
  createdAt: string
  createdBy: string | null
  revokedAt: string | null
  revokedBy: string | null
}

/** One organization on the identity registry, projected for the account
 *  surfaces (the join selector, the admin consoles). */
export interface RegistryOrg {
  id: string
  name: string
  shortName: string
  /** The participant kind, NULL for a non-participant org (an unknown
   *  kind value reads as NULL honestly — the admin edits it into shape;
   *  the role bounds never trust it). */
  kind: RegistryOrgKind | null
  country: string
  contacts: Array<{ name: string | null; email: string }>
  /** The first contact's email domain when declared — the email-domain
   *  HINT the deciding admin sees (a hint, never the proof). */
  emailDomain: string | null
  /** The participant-link annotation (which participant record the org
   *  mirrors — documentation, never resolved). */
  participantRef: string | null
  state: 'active' | 'disabled'
  /** The PARTICIPANT posture the join flow gates on: an active org that
   *  carries a PARTICIPANT kind (a manufacturer or a non-participant org
   *  is never on the public participation intake). */
  registered: boolean
  /** The per-kind standing (TODO.register/01): the honest label the admin
   *  consoles render — a manufacturer row says what it is (declared /
   *  ia-endorsed), never the participant posture. */
  standing: RegistryOrgStanding
  /** The active endorsements' IA org ids (the manufacturer kind only —
   *  empty for every other kind). */
  endorsedBy: string[]
  /** The account roles assignable within the org (orgAssignableRoles —
   *  the kind's bound, or the plain member's viewer for a
   *  non-participant org). */
  roles: string[]
  createdAt: string
  createdBy: string | null
  updatedAt: string | null
  updatedBy: string | null
  disabledAt: string | null
  disabledBy: string | null
}

/** The account roles an org kind bounds (TODO.identity/10 spec: "an
 *  IA's staff get ia_officer etc."). The org-admin role is NEVER in a
 *  kind's set — org admins are created by the identity administrator
 *  after verification, never by the join form or the org-scoped
 *  console. */
export function orgKindRoles(kind: RegistryOrgKind): string[] {
  switch (kind) {
    // The IA desk + the NMI split-role vocabulary (auth/rbac.ts).
    case 'issuing-authority': return ['ia_officer', 'case_officer', 'certification_officer', 'signatory', 'viewer']
    case 'test-laboratory': return ['tl_operator', 'viewer']
    // Acceptance participants review and accept certificates: the
    // read-only viewer account is their staff role, and
    // scheme_participant (TODO.adoption/11) is the staffer who declares
    // ANRs for the participant. The register's participant depth
    // (TODO.adoption/10) follows the ORG BINDING, never the role — a
    // viewer bound to a registered Utilizer/Associate reads it.
    case 'utilizer':
    case 'associate': return ['viewer', 'scheme_participant']
    // TODO.register/01 — the manufacturer bound: the applicant-facing set
    // (the platform's `applicant` role — applications, sample shipments,
    // the engagement's requester side — plus the plain member's viewer).
    // NEVER an ia_*/tl_*/admin role: a manufacturer org is not a scheme
    // participant, and the bound is where the honesty is enforced.
    case 'manufacturer': return ['applicant', 'viewer']
  }
}

/** The roles assignable WITHIN an org (the per-org membership sets, the
 *  delegated invites): the participant kind's bound, or the plain
 *  member's `viewer` for a non-participant org (its people sign in and
 *  act as it; the scheme's staff roles never land there). org_admin is
 *  never in the set — it is the identity administrator's delegation
 *  act. */
export function orgAssignableRoles(org: Pick<RegistryOrg, 'kind'>): string[] {
  return org.kind ? orgKindRoles(org.kind) : ['viewer']
}

/** The domain part of an email address, lower-cased ('' when malformed). */
export function emailDomain(email: string): string {
  const at = email.lastIndexOf('@')
  return at > 0 ? email.slice(at + 1).trim().toLowerCase() : ''
}

// ── the IA endorsements (TODO.register/01 — the manufacturer standing's
//    upgrade act) ─────────────────────────────────────────────────────
// The endorsement rows ride the entity store's generic seam (the same
// collection machinery auditEvents uses) — the kind's standing is a
// DATA-LEVEL extension of the registry, no store-seam change. A
// revocation keeps the row with its stamps; the standing reads the
// ACTIVE rows only.

const ENDORSEMENT_STORE = 'orgEndorsements'

function parseEndorsement(data: string): OrgEndorsement | null {
  try {
    const parsed = JSON.parse(data) as OrgEndorsement
    if (typeof parsed?.id !== 'string' || typeof parsed?.orgId !== 'string' || typeof parsed?.iaOrgId !== 'string') return null
    return parsed
  } catch {
    return null
  }
}

/** Every endorsement row (active and revoked), or one org's slice when
 *  `orgId` is given. */
export async function listOrgEndorsements(store: ServerStore, orgId?: string): Promise<OrgEndorsement[]> {
  const rows = (await store.listEntities(ENDORSEMENT_STORE))
    .map(row => parseEndorsement(row.data))
    .filter((e): e is OrgEndorsement => !!e)
  return orgId ? rows.filter(e => e.orgId === orgId) : rows
}

/** Record an IA's confirmation (the create is the act; the duplicate
 *  guard is the caller's — listOrgEndorsements first). */
export async function createOrgEndorsement(
  store: ServerStore,
  input: { orgId: string; iaOrgId: string; note: string | null; createdBy: string | null },
): Promise<OrgEndorsement> {
  const endorsement: OrgEndorsement = {
    id: crypto.randomUUID(),
    orgId: input.orgId,
    iaOrgId: input.iaOrgId,
    note: input.note,
    createdAt: new Date().toISOString(),
    createdBy: input.createdBy,
    revokedAt: null,
    revokedBy: null,
  }
  await store.putEntity(ENDORSEMENT_STORE, endorsement.id, endorsement.orgId, JSON.stringify(endorsement))
  return endorsement
}

/** Withdraw an endorsement (the row KEEPS its history: the revocation
 *  stamps land on it, never a delete). Answers the updated row, null
 *  when the id is unknown. */
export async function revokeOrgEndorsement(store: ServerStore, id: string, actor: string | null): Promise<OrgEndorsement | null> {
  const row = await store.getEntity(ENDORSEMENT_STORE, id)
  const endorsement = row ? parseEndorsement(row.data) : null
  if (!endorsement) return null
  const revoked: OrgEndorsement = { ...endorsement, revokedAt: new Date().toISOString(), revokedBy: actor }
  await store.putEntity(ENDORSEMENT_STORE, id, revoked.orgId, JSON.stringify(revoked))
  return revoked
}

/** The ACTIVE endorsements grouped by manufacturer org id (the standing
 *  projection's feed — one read per listing). */
async function activeEndorsementsByOrg(store: ServerStore): Promise<Map<string, string[]>> {
  const map = new Map<string, string[]>()
  for (const e of await listOrgEndorsements(store)) {
    if (e.revokedAt) continue
    map.set(e.orgId, [...(map.get(e.orgId) ?? []), e.iaOrgId])
  }
  return map
}

/** The per-kind standing label (TODO.register/01): a manufacturer's is
 *  'declared' until an IA's confirmation upgrades it — it is NEVER the
 *  participant standing. */
function standingOf(kind: RegistryOrgKind | null, endorsedBy: string[]): RegistryOrgStanding {
  if (kind === null) return 'non-participant'
  if (kind === 'manufacturer') return endorsedBy.length ? 'ia-endorsed' : 'declared'
  return 'participant'
}

/** The store row's projection (the defensive narrowing: an unknown kind
 *  reads as a non-participant org, never as a bound to trust). */
function projectOrg(row: OrgRegistryOrg, endorsedBy: string[] = []): RegistryOrg {
  const kind = row.kind && REGISTRY_ORG_KINDS.has(row.kind) ? row.kind as RegistryOrgKind : null
  const org: RegistryOrg = {
    id: row.id,
    name: row.name,
    shortName: row.shortName ?? row.name,
    kind,
    country: row.country ?? '',
    contacts: row.contacts,
    emailDomain: row.contacts.length ? emailDomain(row.contacts[0]!.email) || null : null,
    participantRef: row.participantRef,
    state: row.state,
    registered: row.state === 'active' && kind !== null && PARTICIPANT_KINDS.has(kind),
    standing: standingOf(kind, endorsedBy),
    endorsedBy: kind === 'manufacturer' ? endorsedBy : [],
    roles: [],
    createdAt: row.createdAt,
    createdBy: row.createdBy,
    updatedAt: row.updatedAt,
    updatedBy: row.updatedBy,
    disabledAt: row.disabledAt,
    disabledBy: row.disabledBy,
  }
  org.roles = orgAssignableRoles(org)
  return org
}

/** Every organization on the identity registry, every state, name-ordered. */
export async function listRegistryOrganizations(store: ServerStore): Promise<RegistryOrg[]> {
  const endorsed = await activeEndorsementsByOrg(store)
  return (await store.listOrgRegistryOrgs()).map(row => projectOrg(row, endorsed.get(row.id) ?? []))
}

/** One registry org by id (null when the registry does not carry it). */
export async function resolveRegistryOrg(store: ServerStore, orgId: string): Promise<RegistryOrg | null> {
  const row = await store.getOrgRegistryOrg(orgId)
  if (!row) return null
  const endorsed = (await listOrgEndorsements(store, orgId)).filter(e => !e.revokedAt).map(e => e.iaOrgId)
  return projectOrg(row, endorsed)
}

/** THE PARTICIPANT GATE (B 18 §10.2 / PD-03, the identity plane's
 *  posture): the org is an ACTIVE registry organization carrying a
 *  participant kind — the join selector's offer, the public submit's
 *  re-check, the membership-request's gate. */
export async function isRegisteredParticipant(store: ServerStore, orgId: string): Promise<boolean> {
  const org = await resolveRegistryOrg(store, orgId)
  return org?.registered ?? false
}

/** THE MEMBERSHIP-GRAPH GATE: the org is an ACTIVE registry organization
 *  (any kind — a non-participant org's people hold memberships and its
 *  delegated administrator too). The write paths' admission rule. */
export async function isActiveRegistryOrg(store: ServerStore, orgId: string): Promise<boolean> {
  const org = await store.getOrgRegistryOrg(orgId)
  return org?.state === 'active'
}

/** THE JOIN-INTAKE GATE (TODO.register/01): the org admits accounts
 *  through the join flow — an active PARTICIPANT org (PD-03) or an
 *  active MANUFACTURER org (the declared standing admits its own people;
 *  the manufacturer NEVER reads registered — the participant posture
 *  stays the scheme's). */
export function admitsJoinFlow(org: Pick<RegistryOrg, 'registered' | 'kind' | 'state'>): boolean {
  return org.registered || (org.kind === 'manufacturer' && org.state === 'active')
}

/** The manufacturer org id minter (the self-registration path creates
 *  the row): the stable slug from the display name under the mfr- prefix
 *  (the platform's sample `mfr-acme` is the shape), deduplicated with a
 *  counter. Answers a free id matching the registry's slug rule. */
export async function mintManufacturerOrgId(store: ServerStore, name: string): Promise<string> {
  const slug = name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 48)
  const base = `mfr-${slug || 'organization'}`
  for (let i = 0; ; i++) {
    const candidate = (i === 0 ? base : `${base}-${i + 1}`).slice(0, 64)
    if (!(await store.getOrgRegistryOrg(candidate))) return candidate
  }
}

/** The email-domain HINT for the deciding admin: does the requester's
 *  work-email domain match the org's declared contact domain? Answers
 *  null when either side declares no domain (no hint shown). A hint,
 *  never the proof (TODO.identity/10). */
export function emailDomainHint(org: RegistryOrg, requesterEmail: string): boolean | null {
  const domain = emailDomain(requesterEmail)
  if (!domain || !org.emailDomain) return null
  return domain === org.emailDomain
}
