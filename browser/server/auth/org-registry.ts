// ═══════════════════════════════════════════════════════════════════
// The participants-register resolver (TODO.identity/10) — the account
// topology's view of the OIML-CS participants registry (B 18:2025 §10.2,
// PD-08 cl. 4): which organizations are REGISTERED participants, what
// KIND each is, and which account roles that kind bounds.
//
// The register is read from the ENTITY STORE (the seeded registry —
// server/seed-core.ts's organizations + participants phases), never from
// a second list: the Executive Secretary's registry work and the join
// selector read the same rows. An org is REGISTERED when the register
// carries its completed admission:
//
//   - a signed Declaration (IAs, Utilizers, Associates — PD-08's
//     register IS the signed Declaration set), or
//   - a participation case at ACTIVE (the pipeline's terminal state —
//     the TL leg, whose admission is the PD-04 case, never a
//     Declaration of its own).
//
// An org mid-pipeline (SUBMITTED … DECLARATION_PENDING) is NOT
// registered — the join selector never offers it, and an org-admin
// assignment naming it is refused (the eligibility rule).
//
// WORKER-SAFE: the ServerStore seam only — no node built-ins.
// ═══════════════════════════════════════════════════════════════════

import type { ServerStore } from '@oimlsmart/platform-server/store'

/** The registry's organization kinds (the participants model's four
 *  participant kinds — data/oiml-cs/framework/participants.yaml). */
export type RegistryOrgKind = 'issuing-authority' | 'test-laboratory' | 'utilizer' | 'associate'

/** One organization on the participants register, projected for the
 *  account surfaces (the join selector, the admin consoles). */
export interface RegistryOrg {
  id: string
  name: string
  shortName: string
  kind: RegistryOrgKind
  country: string
  /** The contact's email domain when declared — the email-domain HINT
   *  the deciding admin sees (a hint, never the proof). */
  emailDomain: string | null
  /** Whether the org is a REGISTERED participant (the eligibility
   *  rule). Only registered orgs are selectable / admin-assignable. */
  registered: boolean
  /** The account roles this org's kind bounds (orgKindRoles). */
  roles: string[]
}

/** The account roles an org kind bounds (TODO.identity/10 spec: "an
 *  IA's staff get ia_officer etc."). The org-admin role is NEVER in a
 *  kind's set — org admins are created by BIML after verification, one
 *  per org, never by the join form or the org-scoped console. */
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

// ── the entity shapes (parsed defensively — an unexpected row is
//    skipped, never trusted) ──────────────────────────────────────────

interface OrgEntity {
  id: string
  kind?: string
  name?: string
  short_name?: string
  country?: string
  contact?: { email?: string }
}

interface DeclarationEntity {
  participant_id?: string
  status?: string
}

interface ApplicationEntity {
  applicant_organization_id?: string
  status?: string
}

function parseEntity<T>(data: string): T | null {
  try {
    const parsed = JSON.parse(data) as unknown
    return parsed && typeof parsed === 'object' ? parsed as T : null
  } catch {
    return null
  }
}

/** The domain part of an email address, lower-cased ('' when malformed). */
export function emailDomain(email: string): string {
  const at = email.lastIndexOf('@')
  return at > 0 ? email.slice(at + 1).trim().toLowerCase() : ''
}

/**
 * Read the participants register from the entity store. Answers every
 * registry organization (IAs + TLs from `organizations`, Utilizers and
 * Associates from their own stores) with its registered flag — the
 * join selector lists the registered ones, the admin surfaces explain
 * the rest.
 */
export async function listRegistryOrganizations(store: ServerStore): Promise<RegistryOrg[]> {
  const [orgRows, utilizerRows, associateRows, declarationRows, applicationRows] = await Promise.all([
    store.listEntities('organizations'),
    store.listEntities('utilizers'),
    store.listEntities('associates'),
    store.listEntities('participantDeclarations'),
    store.listEntities('participantApplications'),
  ])

  // The register: signed Declarations + ACTIVE participation cases.
  const signedBy = new Set<string>()
  for (const row of declarationRows) {
    const d = parseEntity<DeclarationEntity>(row.data)
    if (d?.participant_id && d.status === 'signed') signedBy.add(d.participant_id)
  }
  const activeCase = new Set<string>()
  for (const row of applicationRows) {
    const a = parseEntity<ApplicationEntity>(row.data)
    if (a?.applicant_organization_id && a.status === 'ACTIVE') activeCase.add(a.applicant_organization_id)
  }
  const isRegistered = (id: string) => signedBy.has(id) || activeCase.has(id)

  const out: RegistryOrg[] = []
  for (const row of orgRows) {
    const o = parseEntity<OrgEntity>(row.data)
    if (!o?.id || (o.kind !== 'issuing-authority' && o.kind !== 'test-laboratory') || !o.name) continue
    out.push({
      id: o.id,
      name: o.name,
      shortName: o.short_name ?? o.name,
      kind: o.kind,
      country: o.country ?? '',
      emailDomain: o.contact?.email ? emailDomain(o.contact.email) || null : null,
      registered: isRegistered(o.id),
      roles: orgKindRoles(o.kind),
    })
  }
  for (const [rows, kind] of [[utilizerRows, 'utilizer'], [associateRows, 'associate']] as const) {
    for (const row of rows) {
      const o = parseEntity<OrgEntity>(row.data)
      if (!o?.id || !o.name) continue
      out.push({
        id: o.id,
        name: o.name,
        shortName: o.short_name ?? o.name,
        kind,
        country: o.country ?? '',
        emailDomain: o.contact?.email ? emailDomain(o.contact.email) || null : null,
        registered: isRegistered(o.id),
        roles: orgKindRoles(kind),
      })
    }
  }
  return out.sort((a, b) => a.name.localeCompare(b.name))
}

/** One registry org by id (null when the register does not carry it). */
export async function resolveRegistryOrg(store: ServerStore, orgId: string): Promise<RegistryOrg | null> {
  const all = await listRegistryOrganizations(store)
  return all.find(o => o.id === orgId) ?? null
}

/** THE ELIGIBILITY RULE (B 18 §10.2 / PD-03): an organization admin —
 *  and any org account through the delegated flow — can be created only
 *  for a REGISTERED participant org. */
export async function isRegisteredParticipant(store: ServerStore, orgId: string): Promise<boolean> {
  const org = await resolveRegistryOrg(store, orgId)
  return org?.registered ?? false
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
