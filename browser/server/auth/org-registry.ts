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
// WORKER-SAFE: the ServerStore seam only — no node built-ins.
// ═══════════════════════════════════════════════════════════════════

import type { OrgRegistryOrg, ServerStore } from '@oimlsmart/platform-server/store'

/** The registry's organization kinds (the participants model's four
 *  participant kinds — data/oiml-cs/framework/participants.yaml). */
export type RegistryOrgKind = 'issuing-authority' | 'test-laboratory' | 'utilizer' | 'associate'

const REGISTRY_ORG_KINDS = new Set<string>(['issuing-authority', 'test-laboratory', 'utilizer', 'associate'])

/** The write-time kind validation (the add/edit routes): the four
 *  participant kinds, or null/undefined for a non-participant org. */
export function isRegistryOrgKind(value: unknown): value is RegistryOrgKind {
  return typeof value === 'string' && REGISTRY_ORG_KINDS.has(value)
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
   *  carries a participant kind (a non-participant org is never on the
   *  public intake). */
  registered: boolean
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

/** The store row's projection (the defensive narrowing: an unknown kind
 *  reads as a non-participant org, never as a bound to trust). */
function projectOrg(row: OrgRegistryOrg): RegistryOrg {
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
    registered: row.state === 'active' && kind !== null,
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
  return (await store.listOrgRegistryOrgs()).map(projectOrg)
}

/** One registry org by id (null when the registry does not carry it). */
export async function resolveRegistryOrg(store: ServerStore, orgId: string): Promise<RegistryOrg | null> {
  const row = await store.getOrgRegistryOrg(orgId)
  return row ? projectOrg(row) : null
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

/** The email-domain HINT for the deciding admin: does the requester's
 *  work-email domain match the org's declared contact domain? Answers
 *  null when either side declares no domain (no hint shown). A hint,
 *  never the proof (TODO.identity/10). */
export function emailDomainHint(org: RegistryOrg, requesterEmail: string): boolean | null {
  const domain = emailDomain(requesterEmail)
  if (!domain || !org.emailDomain) return null
  return domain === org.emailDomain
}
