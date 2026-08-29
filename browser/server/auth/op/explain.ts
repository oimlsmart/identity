// ═══════════════════════════════════════════════════════════════════
// THE EFFECTIVE-PERMISSION EXPLAINER (TODO.identity-features/09, wave
// B) — the org administrator's "what can this member see and do",
// answered with the COMPUTED effective set, never a reimplementation:
//
//   - the ROLES HELD resolve through the kernel's resolveOrgContext —
//     the ONE rule the session payload and the OIDC claims emission
//     both run (server/auth/op/memberships.ts), so the explainer's
//     answer can never drift from what the member's sessions carry;
//   - the PERMISSIONS come from the instance's effective RBAC map (the
//     same map the routes' grant computation reads), each named with
//     the role it came from and its catalog label (vocab's
//     PERMISSION_INFO);
//   - the CONE's effect is the wave-A grammar's (the kernel's
//     OrgMemberCone): 'assigned' narrows the READ class to the org's
//     rows NAMING the member; 'read-only' refuses the WRITE class
//     whatever the roles grant — the cone only ever NARROWS;
//   - the data-visibility DRY-RUN evaluates synthesized rows against
//     the kernel's visibility vocabulary (ORG_FIELDS / orgIdOf /
//     CATALOG_STORES) with the cone applied the way the platform's
//     gates apply it (smart's entities.ts — the enforcement stays
//     there; the kernel's vocabulary is the shared declarative core).
//
// THE SEAM, HONESTLY: the platform's visibleTo / writeAllowed are the
// enforcement and live with the platform (they read the entity store —
// the parent-resolution legs). The explainer does NOT import them; it
// evaluates the SAME declared rules over SYNTHESIZED rows (a row naming
// the org, a row naming the member, a row naming another org), and the
// assigned cone's person keys are the wave-A design's named set (the
// run's operators/evidence, the assignment via its runs, the
// engagement's inquirer — the console's cone picker copy says the same
// in prose). Should the gate itself ever publish through the kernel,
// this module switches to importing it — until then the unit suite pins
// the projection's answers against the documented semantics.
//
// THE OVERSIGHT CARVE-OUT (the design's invariant 3): the read gate
// binds ORG-SCOPED primary roles only (the platform's isOrgBound: the
// session payload's PRIMARY role ∈ the org-bound set, and an org
// resolved) — the estate's staff and the scheme's oversight read
// everything regardless, and a cone never hides a row from them. The
// read-only modifier is the exception by construction: the write gate
// refuses on it BEFORE the org-bound check, so it binds every context
// that carries the cone.
//
// PURE + WORKER-SAFE: no store, no I/O, no node built-ins — the route
// reads the rows and passes them in.
// ═══════════════════════════════════════════════════════════════════

import {
  ORG_FIELDS,
  CATALOG_STORES,
  orgIdOf,
  resolveOrgContext,
  encodeOrgMemberCone,
  type OrgMemberCone,
  type OrgMembership,
} from '@oimlsmart/platform-server/store'
import {
  PERMISSION_INFO,
  IA_DESK_ROLES,
  type ActionPermission,
  type RolePermissionMap,
} from '@oimlsmart/platform-server/vocab'
import { orgAssignableRoles, type RegistryOrg } from '../org-registry'

/** The org-scoped primary roles — the platform's read/write gates bind
 *  these (smart's entities.ts ORG_BOUND_ROLES: the applicant, the
 *  laboratory operator, and the IA desk family — the kernel's
 *  IA_DESK_ROLES). A member whose PRIMARY role is not among them reads
 *  everything the platform shows an authenticated account; the cone
 *  never narrows their read (the oversight carve-out). */
export const ORG_BOUND_PRIMARY_ROLES: readonly string[] = ['applicant', 'tl_operator', ...IA_DESK_ROLES]

/** The assigned cone's person-level keys per entity class (wave A's
 *  named set — the audit's person-level fields turned literal; a class
 *  NOT here carries no person-level field, so the assigned cone admits
 *  none of its rows). The string is the honest prose the panel shows. */
export const CONE_PERSON_KEYS: Record<string, string> = {
  testRuns: 'the run’s operators or evidence sign-off name the account',
  testAssignments: 'a test run under the assignment names the account',
  engagements: 'the engagement’s inquirer is the account’s email',
}

/** The closed reason vocabulary of the dry-run verdicts (the console
 *  maps each to its i18n copy; the codes are the API's contract). */
export type VisibilityReason =
  | 'oversight'          // visible — the primary role is not org-scoped; the read gate never narrows this member
  | 'shared'             // visible — the class carries no org fields; shared reference data, the cone never narrows it
  | 'catalog'            // visible — the instrument catalog is shared reference data on read (writes are org-gated)
  | 'org-field'          // visible — the row names the member's organization
  | 'org-field-miss'     // hidden — no org field on the row names the member's organization
  | 'assigned-miss'      // hidden — the row names the organization but not the member (the assigned cone)
  | 'assigned-no-key'    // hidden — the class carries no person-level key; the assigned cone admits none of its rows
  | 'assigned-hit'       // visible — the row names the member (the class's person key)

export interface VisibilityVerdict {
  visible: boolean
  reason: VisibilityReason
  /** The org field the verdict turned on (the org-field reasons). */
  field?: string
}

export type VisibilityClass = 'org-scoped' | 'shared-catalog' | 'shared-reference'

export interface VisibilityClassReport {
  store: string
  class: VisibilityClass
  /** The org fields the read gate matches (org-scoped classes). */
  orgFields: string[]
  /** The assigned cone's person-level key for the class (null = none —
   *  the assigned cone admits none of the class's rows). */
  personKey: string | null
  /** A row naming the member's organization (not the member). */
  ownOrg: VisibilityVerdict
  /** A row naming the member's organization AND the member (only for
   *  the person-keyed classes; null elsewhere). */
  named: VisibilityVerdict | null
  /** A row naming another organization. */
  foreignOrg: VisibilityVerdict
}

/** A held permission, attributed: the role(s) it came from, its catalog
 *  label, and the cone's effect on it. Every catalog permission is a
 *  write-side ACT, so the read-only modifier suspends them all; the
 *  assigned scope leaves the grant standing over the rows that name the
 *  member. */
export interface ExplainedPermission {
  id: ActionPermission
  label: string
  fromRoles: string[]
  effective: boolean
  effect: 'held' | 'scoped-to-named-rows' | 'read-only-refused'
}

export interface ExplainedRole {
  id: string
  /** Where the context's role comes from: the membership's per-org set,
   *  or the account level (an org-free account's roles ride every
   *  context, honestly). */
  source: 'membership' | 'account'
  /** The instance's RBAC map knows the role (a drifted row reports
   *  known: false and contributes nothing — assignment-time honesty). */
  known: boolean
  permissions: Array<{ id: ActionPermission; label: string }>
}

export interface MemberExplanation {
  member: {
    userId: string
    name: string
    email: string | null
    state: OrgMembership['state']
    isPrimary: boolean
    accountActive: boolean
  }
  org: { id: string; name: string; kind: RegistryOrg['kind'] }
  /** Whether the member ACTS as the org today (the membership is active
   *  and the account is too). An invited/disabled membership (or a
   *  deactivated account) answers the empty effective set with the
   *  note — never a peek at another context. */
  acting: boolean
  stateNote: 'active' | 'membership-invited' | 'membership-disabled' | 'account-deactivated'
  /** The resolved org context (resolveOrgContext — the same resolution
   *  the session payload and the claims emission run). */
  context: { orgId: string | null; cone: OrgMemberCone | null }
  roles: ExplainedRole[]
  /** The union of the granted permissions, attributed. */
  permissions: ExplainedPermission[]
  /** The org kind's bound over the membership's set (org_admin excepted
   *  — the scheme operator's delegation act, never the kind's). */
  kindBound: { assignable: string[]; orgAdminRow: boolean; outside: string[] }
  cone: {
    posture: string
    read: { scope: OrgMemberCone['scope']; effect: 'org-rows' | 'named-rows-only' }
    write: { refused: boolean; effect: 'role-set' | 'read-only-refused' }
  }
  visibility: { orgBound: boolean; classes: VisibilityClassReport[] }
}

/** The account-shaped input (the RAW account row — never the session
 *  payload; resolveOrgContext's contract). */
export interface ExplainAccount {
  id: string
  name: string
  email: string | null
  role: string
  roles?: string[] | null
  orgId: string | null
  active: boolean
}

/**
 * THE EXPLANATION. Given the org, the member's RAW account row, the
 * explained membership, the account's PRIMARY membership (the context
 * rule's fallthrough), and the instance's effective RBAC map, compute
 * what the member can see and do acting AS the org. No reads, no
 * writes — the caller (the route) gathers the rows.
 */
export function explainOrgMember(input: {
  org: Pick<RegistryOrg, 'id' | 'name' | 'kind'>
  account: ExplainAccount
  membership: OrgMembership
  primary: OrgMembership | null
  map: RolePermissionMap
}): MemberExplanation {
  const { org, account, membership, primary, map } = input
  const cone = membership.cone

  // The acting posture: only an ACTIVE membership on an ACTIVE account
  // acts as the org. resolveOrgContext's own fallthrough would answer
  // the PRIMARY context for an inactive membership — another org's
  // posture, never this explanation's answer, so the explainer refuses
  // it explicitly.
  const stateNote: MemberExplanation['stateNote'] = !account.active
    ? 'account-deactivated'
    : membership.state === 'invited'
      ? 'membership-invited'
      : membership.state === 'disabled'
        ? 'membership-disabled'
        : 'active'
  const acting = stateNote === 'active'

  const resolved = acting
    ? resolveOrgContext(
        { role: account.role, roles: account.roles ?? null, orgId: account.orgId },
        { activeOrg: org.id, active: membership, primary },
      )
    : { orgId: null, roles: [] as string[], cone: null }

  // The roles held, attributed to their source (the membership's per-org
  // set first — the context union's account layer is the rest).
  const membershipRoles = new Set(membership.roles)
  const roles: ExplainedRole[] = resolved.roles.map(id => ({
    id,
    source: membershipRoles.has(id) ? 'membership' : 'account',
    known: id in map,
    permissions: (map[id] ?? []).map(p => ({ id: p, label: PERMISSION_INFO[p]?.label ?? p })),
  }))

  // The union, each permission named with the role(s) it came from.
  const union = new Map<ActionPermission, string[]>()
  for (const role of roles) {
    for (const p of role.permissions) {
      union.set(p.id, [...(union.get(p.id) ?? []), role.id])
    }
  }
  const permissions: ExplainedPermission[] = [...union.entries()].map(([id, fromRoles]) => ({
    id,
    label: PERMISSION_INFO[id]?.label ?? id,
    fromRoles,
    effective: !cone.readOnly,
    effect: cone.readOnly ? 'read-only-refused' : cone.scope === 'assigned' ? 'scoped-to-named-rows' : 'held',
  }))

  const assignable = orgAssignableRoles(org)
  const kindBound = {
    assignable,
    orgAdminRow: membership.roles.includes('org_admin'),
    outside: membership.roles.filter(r => !assignable.includes(r) && r !== 'org_admin'),
  }

  // The data-visibility dry-run. The gate's org-bound posture keys on
  // the session payload's PRIMARY role (the account's `role` column —
  // the context switch never restamps it) plus the resolved org.
  const orgBound = acting && resolved.orgId !== null && ORG_BOUND_PRIMARY_ROLES.includes(account.role)
  const visibility: VisibilityClassReport[] = []
  const classes: Array<{ store: string; cls: VisibilityClass; orgFields: string[] }> = [
    ...Object.keys(ORG_FIELDS).sort().map(store => ({ store, cls: 'org-scoped' as const, orgFields: ORG_FIELDS[store]! })),
    ...[...CATALOG_STORES].sort().map(store => ({ store, cls: 'shared-catalog' as const, orgFields: [] })),
    { store: '(every other entity class)', cls: 'shared-reference' as const, orgFields: [] },
  ]
  for (const { store, cls, orgFields } of classes) {
    const personKey = CONE_PERSON_KEYS[store] ?? null
    if (!orgBound) {
      const verdict: VisibilityVerdict = { visible: true, reason: cls === 'org-scoped' ? 'oversight' : cls === 'shared-catalog' ? 'catalog' : 'shared' }
      visibility.push({ store, class: cls, orgFields, personKey, ownOrg: verdict, named: personKey ? { ...verdict } : null, foreignOrg: { ...verdict } })
      continue
    }
    if (cls !== 'org-scoped') {
      const verdict: VisibilityVerdict = { visible: true, reason: cls === 'shared-catalog' ? 'catalog' : 'shared' }
      visibility.push({ store, class: cls, orgFields, personKey, ownOrg: verdict, named: null, foreignOrg: { ...verdict } })
      continue
    }
    // The synthesized rows: one naming the member's org, one naming
    // another org — the org-field leg evaluates through the kernel's
    // orgIdOf (the same vocabulary the gate reads).
    const field = orgFields[0]!
    const ownRow = { [field]: org.id }
    const foreignRow = { [field]: 'another-org' }
    const ownOrgVisible = orgIdOf(store, ownRow) === org.id
    const foreign: VisibilityVerdict = orgIdOf(store, foreignRow) === org.id
      ? { visible: true, reason: 'org-field', field }
      : { visible: false, reason: 'org-field-miss', field }
    let ownOrg: VisibilityVerdict
    let named: VisibilityVerdict | null = null
    if (cone.scope === 'assigned') {
      // The assigned cone: the org-level row alone is not enough — the
      // row must NAME the member, and only the person-keyed classes
      // carry such a field at all.
      ownOrg = personKey
        ? { visible: false, reason: 'assigned-miss', field }
        : { visible: false, reason: 'assigned-no-key', field }
      named = personKey ? { visible: true, reason: 'assigned-hit', field } : null
    } else {
      ownOrg = ownOrgVisible ? { visible: true, reason: 'org-field', field } : { visible: false, reason: 'org-field-miss', field }
      // The named row rides the org field under the org-wide scope (the
      // person key is irrelevant when the org's rows all pass) — the
      // report carries it so the narrowing invariant is checkable
      // straight off the payload (an assigned posture's yes never
      // exceeds this posture's).
      named = personKey ? { ...ownOrg } : null
    }
    visibility.push({ store, class: cls, orgFields, personKey, ownOrg, named, foreignOrg: foreign })
  }

  return {
    member: {
      userId: membership.userId,
      name: account.name,
      email: account.email,
      state: membership.state,
      isPrimary: membership.isPrimary,
      accountActive: account.active,
    },
    org: { id: org.id, name: org.name, kind: org.kind },
    acting,
    stateNote,
    context: { orgId: resolved.orgId, cone: resolved.cone },
    roles,
    permissions,
    kindBound,
    cone: {
      posture: encodeOrgMemberCone(cone) ?? 'org-wide',
      read: { scope: cone.scope, effect: cone.scope === 'assigned' ? 'named-rows-only' : 'org-rows' },
      write: { refused: cone.readOnly, effect: cone.readOnly ? 'read-only-refused' : 'role-set' },
    },
    visibility: { orgBound, classes: visibility },
  }
}

/** The route's account adapter: the admin-row the store's listUsers
 *  returns (the RAW account row — never the session payload, per
 *  resolveOrgContext's contract) IS the explanation's account input. */
export function explainAccountOf(user: {
  id: string
  email: string
  name: string
  role: string
  roles: string[]
  orgId: string | null
  active: boolean
} | null): ExplainAccount | null {
  if (!user) return null
  return { id: user.id, name: user.name, email: user.email, role: user.role, roles: user.roles, orgId: user.orgId, active: user.active }
}
