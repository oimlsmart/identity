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
// THE OIML MEMBER CATEGORY (TODO.identity-features/10, the taxonomy
// correction): "OIML Member" is its own category — the member-state
// (ratified the OIML Convention) and corresponding-member kinds — and
// the Utilizer/Associate are DESIGNATED BODIES (their own org rows,
// signing the Declaration per PD-08), never statuses on a member. A
// member state participates in the OIML-CS by PROPOSING an issuing
// authority (the IA row's proposed_by) and DESIGNATING a utilizer (the
// utilizer row's designated_by); a corresponding member designates an
// associate; a test laboratory carries its IA association
// (designated_by → the IA). The designated bodies carry the CS status
// facet (the Declaration's standing: signed-active / suspended /
// withdrawn). The link's kind enforcement is validateOrgLinks on the
// write path; the member kinds' personnel hold the read/access posture
// (orgKindRoles → the plain member's viewer), never workflow authority.
// The same legal body MAY hold several roles — the registry carries
// each role as its own LINKED row, never merged.
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

/** The registry's organization kinds (TODO.identity-features/10 — the
 *  OIML Member category, the taxonomy correction): the OIML MEMBER
 *  category's two kinds ('member-state' — ratified the OIML Convention;
 *  'corresponding-member' — the countries/economies not yet members),
 *  the OIML-CS participant kinds (the IA + its TLs, and the DESIGNATED
 *  BODIES — the utilizer/associate are their OWN organizations signing
 *  the Declaration per PD-08, never a status on a member), plus
 *  'manufacturer' (TODO.register/01) — a first-class registry kind that
 *  is NEVER a PD-03 participant. */
export type RegistryOrgKind = 'member-state' | 'corresponding-member' | 'issuing-authority' | 'test-laboratory' | 'utilizer' | 'associate' | 'manufacturer'

const REGISTRY_ORG_KINDS = new Set<string>(['member-state', 'corresponding-member', 'issuing-authority', 'test-laboratory', 'utilizer', 'associate', 'manufacturer'])

/** The OIML MEMBER kinds (the category): the member states + the
 *  corresponding members. Their personnel hold accounts and reach the
 *  estate's services (the member tier by construction); they carry NO
 *  workflow authority. */
const MEMBER_KINDS = new Set<string>(['member-state', 'corresponding-member'])

/** The OIML Member category's kind check. */
export function isMemberKind(kind: RegistryOrgKind | null): boolean {
  return kind !== null && MEMBER_KINDS.has(kind)
}

/** The PD-03 PARTICIPANT kinds (B 18 §10.2): the four the participants
 *  register carries. 'manufacturer' is deliberately NOT among them, and
 *  the MEMBER kinds neither — the OIML membership is not a CS
 *  participation. */
const PARTICIPANT_KINDS = new Set<string>(['issuing-authority', 'test-laboratory', 'utilizer', 'associate'])

/** The write-time kind validation (the add/edit routes): the four
 *  participant kinds + 'manufacturer', or null/undefined for a
 *  non-participant org. */
export function isRegistryOrgKind(value: unknown): value is RegistryOrgKind {
  return typeof value === 'string' && REGISTRY_ORG_KINDS.has(value)
}

/** The registry standing (TODO.register/01 — the per-kind honesty;
 *  TODO.identity-features/10 — the member category): the scheme's
 *  registration for a participant kind; 'member' for the OIML MEMBER
 *  kinds (the Convention's fact, never a CS participation); 'declared'
 *  for a self-registered manufacturer; 'ia-endorsed' once an issuing
 *  authority confirmed the relationship; 'non-participant' for a
 *  kind-NULL org. The lifecycle STATE (active/disabled) is orthogonal
 *  and renders separately — a disabled org's standing label never
 *  resurrects it. */
export type RegistryOrgStanding = 'participant' | 'member' | 'declared' | 'ia-endorsed' | 'non-participant'

/** The designated bodies' Declaration standing (TODO.identity-features/10
 *  — the CS status facet): the utilizer/associate rows carry it (signed
 *  the Declaration and active / suspended / withdrawn). The status is
 *  the CS layer's fact projected onto the identity plane; NULL reads
 *  "not recorded", honestly. */
export type RegistryOrgCsStatus = 'signed-active' | 'suspended' | 'withdrawn'

const CS_STATUSES = new Set<string>(['signed-active', 'suspended', 'withdrawn'])

/** The designation link each kind carries (TODO.identity-features/10):
 *  the DESIGNATED bodies' `designatedBy` (a utilizer's designator is its
 *  MEMBER STATE, an associate's its CORRESPONDING MEMBER, a test
 *  laboratory's its associated ISSUING AUTHORITY — the participants
 *  model's designated_by: issuing_authority) and the issuing
 *  authority's `proposedBy` (its proposing MEMBER STATE). The member
 *  kinds designate/propose — they are never themselves designated or
 *  proposed, and the manufacturer kind neither. The enforcement is
 *  validateOrgLinks on the write path. */
export const ORG_LINK_RULES: Readonly<Partial<Record<RegistryOrgKind, { field: 'designatedBy' | 'proposedBy'; targetKind: RegistryOrgKind }>>> = {
  utilizer: { field: 'designatedBy', targetKind: 'member-state' },
  associate: { field: 'designatedBy', targetKind: 'corresponding-member' },
  'test-laboratory': { field: 'designatedBy', targetKind: 'issuing-authority' },
  'issuing-authority': { field: 'proposedBy', targetKind: 'member-state' },
}

/** The link/cs-status envelope the write path validates (the add act's
 *  full set; the edit act's MERGED row — the patch semantics resolve
 *  before this runs). */
export interface OrgLinkFields {
  kind: RegistryOrgKind | null
  designatedBy?: string | null
  proposedBy?: string | null
  csStatus?: string | null
}

/** THE DESIGNATION-LINK ENFORCEMENT (TODO.identity-features/10, the
 *  server-side rule): a designation link to a wrong-kind designator
 *  refuses — a utilizer's designator is a member state, an associate's
 *  a corresponding member, a TL's its IA, an IA's proposer a member
 *  state; the OTHER link column and a link on a linkless kind (the
 *  members, the manufacturer, the non-participant) refuse too. The
 *  target must RESOLVE to an active registry org of the required kind
 *  (a dangling link is a data error the administrator fixes, never a
 *  row the chain renders). The CS status facet rides the designated
 *  bodies only. Answers the error message, or null when the envelope
 *  is honest. NULL links are always admitted ("not recorded"). */
export async function validateOrgLinks(store: ServerStore, input: OrgLinkFields): Promise<string | null> {
  const { kind } = input
  const designatedBy = input.designatedBy ?? null
  const proposedBy = input.proposedBy ?? null
  const csStatus = input.csStatus ?? null
  const rule = kind ? ORG_LINK_RULES[kind] : undefined

  if (designatedBy && rule?.field !== 'designatedBy') {
    return kind
      ? `a ${kind} organization carries no designated_by link — the designated bodies (a utilizer, an associate, a test laboratory) carry it; a member state or corresponding member DESIGNATES, it is never designated`
      : 'a non-participant organization carries no designation links'
  }
  if (proposedBy && rule?.field !== 'proposedBy') {
    return kind
      ? `a ${kind} organization carries no proposed_by link — an issuing authority's proposing member state carries it; a member state PROPOSES, it is never proposed`
      : 'a non-participant organization carries no designation links'
  }
  if (csStatus && kind !== 'utilizer' && kind !== 'associate') {
    return `the CS status facet rides the designated bodies only (a utilizer or an associate's Declaration standing) — a ${kind ?? 'non-participant'} organization never carries it`
  }
  if (csStatus && !CS_STATUSES.has(csStatus)) {
    return `cs_status must be one of signed-active, suspended, withdrawn (the Declaration's standing)`
  }
  if (rule) {
    const targetId = rule.field === 'designatedBy' ? designatedBy : proposedBy
    if (targetId) {
      const target = await store.getOrgRegistryOrg(targetId)
      const targetKnown = target && REGISTRY_ORG_KINDS.has(target.kind ?? '') ? (target.kind as RegistryOrgKind) : null
      if (!target || target.state !== 'active' || targetKnown !== rule.targetKind) {
        const what = rule.field === 'designatedBy' ? 'designator' : 'proposer'
        return !target
          ? `the ${what} '${targetId}' is not on the organization registry — add the ${rule.targetKind} organization first (the chain never names a dangling row)`
          : target.state !== 'active'
            ? `the ${what} '${targetId}' is disabled — a designation names an active ${rule.targetKind} organization`
            : `a ${kind}'s ${what} is a ${rule.targetKind} organization — '${targetId}' is ${targetKnown ?? 'a non-participant organization'}`
      }
    }
  }
  return null
}

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
  /** The designation link (TODO.identity-features/10): the designated
   *  bodies' designating org (a utilizer's member state, an associate's
   *  corresponding member, a TL's associated IA); NULL = not recorded. */
  designatedBy: string | null
  /** The proposing member state's org id (the issuing-authority kind);
   *  NULL = not recorded. */
  proposedBy: string | null
  /** The Declaration's standing on the designated bodies (the CS status
   *  facet); NULL = not recorded. */
  csStatus: RegistryOrgCsStatus | null
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
    // The OIML MEMBER kinds (TODO.identity-features/10): the personnel's
    // READ/ACCESS posture — the plain member's viewer (the AI service +
    // the related services answer the member tier by construction, from
    // the org binding). NEVER workflow authority: no CS role lands on a
    // member org's people — when the same legal body also holds an
    // IA/TL/utilizer/associate role, that role is its OWN linked org row
    // with its own bound, never a widening here.
    case 'member-state':
    case 'corresponding-member': return ['viewer']
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

/** The per-kind standing label: a participant kind's is the scheme's
 *  registration; the OIML MEMBER kinds read 'member' (the Convention's
 *  fact — TODO.identity-features/10); a manufacturer's is 'declared'
 *  until an IA's confirmation upgrades it — it is NEVER the participant
 *  standing. */
function standingOf(kind: RegistryOrgKind | null, endorsedBy: string[]): RegistryOrgStanding {
  if (kind === null) return 'non-participant'
  if (kind === 'manufacturer') return endorsedBy.length ? 'ia-endorsed' : 'declared'
  if (MEMBER_KINDS.has(kind)) return 'member'
  return 'participant'
}

/** The store row's projection (the defensive narrowing: an unknown kind
 *  reads as a non-participant org, never as a bound to trust; an unknown
 *  CS status reads as not-recorded, honestly). */
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
    designatedBy: row.designatedBy ?? null,
    proposedBy: row.proposedBy ?? null,
    csStatus: row.csStatus && CS_STATUSES.has(row.csStatus) ? row.csStatus as RegistryOrgCsStatus : null,
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

/** THE JOIN-INTAKE GATE (TODO.register/01; TODO.identity-features/10 —
 *  the member paths): the org admits accounts through the join flow —
 *  an active PARTICIPANT org (PD-03), an active MANUFACTURER org (the
 *  declared standing admits its own people; the manufacturer NEVER
 *  reads registered — the participant posture stays the scheme's), or
 *  an active OIML MEMBER org (the member state's or corresponding
 *  member's personnel request accounts against their member org — the
 *  read/access posture, never workflow authority). */
export function admitsJoinFlow(org: Pick<RegistryOrg, 'registered' | 'kind' | 'state'>): boolean {
  return org.registered
    || (org.kind === 'manufacturer' && org.state === 'active')
    || (MEMBER_KINDS.has(org.kind ?? '') && org.state === 'active')
}

/** THE JOIN-SELECTOR OFFER (TODO.identity-features/10): the orgs the
 *  public join page's selector lists — the active PARTICIPANT orgs (the
 *  scheme's participation flow) and the active OIML MEMBER orgs (the
 *  member state's / corresponding member's personnel ask against their
 *  member org). A manufacturer org is NEVER on it (the manufacturer
 *  path's self-registration declares the org, never picks it). */
export function onJoinSelector(org: Pick<RegistryOrg, 'registered' | 'kind' | 'state'>): boolean {
  return org.registered || (MEMBER_KINDS.has(org.kind ?? '') && org.state === 'active')
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
