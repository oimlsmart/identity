// ═══════════════════════════════════════════════════════════════════
// The role → permission map (TODO.federation/12): which ROLES hold
// which ACTION PERMISSIONS (auth/permissions.ts) on this instance.
//
// The map is PROFILE DATA. A deployment profile (TODO.federation/01)
// carries an `rbac:` section — `{ <role>: [permissions] }` — that
// REPLACES the shipped default wholesale (the profile owns its role
// model; a per-role merge would invite silent drift). fed-01's profile
// loader passes the section to resolveRolePermissions(); until that
// lands, the server reads the section through the INSTANCE_PROFILE /
// INSTANCE_RBAC_JSON carriers (server/rbac-node.ts). The shipped
// DEFAULT below reproduces the hub's historical behavior exactly: every
// role keeps the actions it exercises today, and the hub profile ships
// this map unchanged (the byte-identical acceptance — the existing
// suite is the proof).
//
// The map also declares the NMI split-role vocabulary (B 18: an NMI's
// officers hold DISTINCT authorities — item 12's e2e): `case_officer`
// (review + dispatch, never the decision), `certification_officer`
// (the decision: finalize + issue), `signatory` (the report signature).
// The hub ships them UNUSED (no hub account holds them); an NMI profile
// assigns them to its officers and may strip ia_officer down to a
// reviewer. Declaring the vocabulary in the default map keeps every
// profile's assignable-role set available to the admin UI and to the
// users API's validation.
//
// OIDC (TODO.federation/10): the identity layer maps claims to roles
// through rolesFromClaims() below — the documented seam between the
// items. Item 10 owns the claim SOURCE (which claim key, per the
// profile's identity section); this module owns the claim→role
// semantics (never invent a role the map does not know).
//
// PLAIN TypeScript — no Vue, no node built-ins (the browser bundle, the
// node server and the Worker all import it).
// ═══════════════════════════════════════════════════════════════════

import {
  ACTION_PERMISSIONS,
  isActionPermission,
  type ActionPermission,
} from './permissions'

/** role id → the permissions it holds. */
export type RolePermissionMap = Record<string, readonly ActionPermission[]>

/** The shipped hub default — today's behavior, enumerated. admin and
 *  cs_admin hold the whole catalog (today they write everything the org
 *  gate passes); the integrity test pins that. */
export const DEFAULT_ROLE_PERMISSIONS: RolePermissionMap = {
  // The applicant (manufacturer org): its own application, shipments, and
  // its side of the engagement funnel (sign / decline / withdraw).
  // TODO.register/03 — and the instrument register: the manufacturer
  // registers the serial numbers of the instruments it produces under a
  // certificate its organization holds (the scope check applies — an
  // out-of-scope declaration is refused with the reason), and marks
  // their lifecycle.
  applicant: ['application.submit', 'samples.ship', 'engagement.respond', 'serial.register'],
  // The issuing authority's officer: the whole desk end to end (today's
  // ia_officer — review, samples, dispatch, TR review, the evaluation,
  // issuance, the IA-side lifecycle acts certificate-detail exposes, and
  // the LOCAL registration act: with no separate BIML endpoint the IA's
  // "Register with BIML" walks the certificate PENDING_REGISTRATION →
  // ACTIVE itself (the single-instance posture; biml_registration.service).
  // The engagement funnel (TODO.federation/02) is the IA's pre-application
  // desk.
  ia_officer: [
    'application.review', 'application.accept',
    'samples.request', 'samples.register', 'samples.manage',
    'dispatch.issue', 'tr.review', 'er.review', 'er.finalize',
    'certificate.issue', 'certificate.register', 'certificate.manage',
    'engagement.manage',
    // TODO.adoption/02 — records mode: register the offline-produced
    // evaluation chain (the Excel bridge).
    'records.register',
    // TODO.adoption/07 — the IA is the REQUESTER on the dispatch quote
    // leg and on ia_tl negotiations: it accepts or declines the
    // laboratory's quotation.
    'negotiation.accept',
    // TODO.adoption/09 — the payment records: the IA records an incoming
    // IA↔TL arrangement invoice and marks its own settlements paid (the
    // certificate fee's marked-paid act is the IA's).
    'payment.invoice', 'payment.mark_paid',
  ],
  // ── the NMI split (the vocabulary every profile may assign) ──
  // Review + dispatch + the engagement desk, never the decision.
  case_officer: [
    'application.review', 'application.accept',
    'samples.request', 'samples.register', 'samples.manage',
    'dispatch.issue', 'tr.review', 'er.review',
    'engagement.manage',
    // TODO.adoption/07 — the case officer works the dispatch quote leg's
    // commercial decision with the officer.
    'negotiation.accept',
  ],
  // The decision: finalize the evaluation, issue and manage the
  // certificate (plus the review legs the decision reads) — and the local
  // registration fallback, mirroring the IA's single-instance act.
  certification_officer: [
    'application.review', 'tr.review', 'er.review', 'er.finalize',
    'certificate.issue', 'certificate.register', 'certificate.manage',
    // TODO.adoption/02 — the records-mode registration carries the
    // offline evaluation's decision: the deciding roles hold it.
    'records.register',
    // TODO.adoption/09 — the deciding roles hold the IA's payment-record
    // acts (the certificate fee's marked-paid record among them).
    'payment.invoice', 'payment.mark_paid',
  ],
  // The report-signature authority.
  signatory: ['tr.sign'],
  // The laboratory: answer the dispatch, run the tests, sign and submit
  // the report, hold sample custody, run the verification pathways.
  tl_operator: [
    'dispatch.respond', 'run.perform', 'tr.sign', 'tr.submit',
    'samples.custody', 'verification.perform', 'markings.manage',
    // TODO.adoption/02 — records mode: register the offline-produced
    // test report (the laboratory's own records).
    'records.register',
    // TODO.adoption/07 — the laboratory is the quoting PROVIDER: it
    // answers a dispatched test request with a quotation and drives its
    // side of ia_tl / tl_applicant negotiations.
    'negotiation.quote',
    // TODO.adoption/09 — the laboratory invoices the IA (the IA↔TL
    // arrangement record) and uploads its side of the evidence.
    'payment.invoice',
  ],
  // The register operator (BIML): registration + the post-registration
  // lifecycle its review console exposes.
  // TODO.adoption/09 — and the collection desk: the hub's own certificate
  // fee records are marked paid as the settlement arrives (B 18:2018 §9 b)
  // names collecting the registration fees a BIML responsibility).
  biml_officer: ['certificate.register', 'certificate.manage', 'payment.mark_paid'],
  // The CS organs (TODO.roadmap/44): the MC votes, the RC recommends,
  // the Executive Secretary administers the registry and operations —
  // INCLUDING the post-issuance certificate acts the scheme-operations
  // console performs (deregistration withdraws the certificate).
  mc_member: ['participants.decide'],
  rc_member: ['participants.review'],
  executive_secretary: ['participants.review', 'participants.manage', 'operations.manage', 'certificate.manage', 'anr.review'],
  // TODO.adoption/11 — the Utilizer/Associate staffer declares ANRs for
  // the participant it acts for; the review stays with the CS registry.
  scheme_participant: ['anr.declare'],
  // TODO.adoption/05 — the market-surveillance authority account: a
  // READ-ONLY register audience. No action permission (the role never
  // acts); the register's per-scheme access tiers show it the full
  // certificate view the public never gets (services/register-tiers.ts).
  market_surveillance: [],
  // Platform operations: the whole catalog (today's behavior — a
  // non-org-bound cs_admin writes anything; keep it explicit).
  cs_admin: [...ACTION_PERMISSIONS],
  admin: [...ACTION_PERMISSIONS],
  // TODO.identity/10 — delegated organization administration: the
  // organization administrator (ONE per registered participant org,
  // created by BIML after verification) manages its own org's people —
  // invites, kind-bounded role assignments, deactivation — through the
  // ORG-SCOPED permission (the users API scopes every read/write to the
  // account's org binding; the role alone never widens the slice). The
  // role carries no workflow authority.
  org_admin: ['org.users.manage'],
  // The read-only account holds no action permission.
  viewer: [],
}

/** The assignable role vocabulary of a map (the users API + the admin
 *  UI validate assignments against it). */
export function mapRoles(map: RolePermissionMap): string[] {
  return Object.keys(map)
}

/**
 * Validate + normalize a profile's `rbac:` section into a map. The
 * section REPLACES the default map when present (pass null/undefined
 * for the default). Honest failures: an unknown permission id is a
 * configuration bug and throws naming it; a role with an empty list is
 * allowed (a deliberate no-authority role, cf. viewer).
 */
export function resolveRolePermissions(profileRbac?: unknown): RolePermissionMap {
  if (profileRbac === undefined || profileRbac === null) return DEFAULT_ROLE_PERMISSIONS
  if (typeof profileRbac !== 'object' || Array.isArray(profileRbac)) {
    throw new Error('rbac: the profile’s rbac section must be a map of role → permission list')
  }
  const out: RolePermissionMap = {}
  for (const [role, perms] of Object.entries(profileRbac as Record<string, unknown>)) {
    if (!Array.isArray(perms)) {
      throw new Error(`rbac: role '${role}' must list its permissions (an array)`)
    }
    const valid: ActionPermission[] = []
    for (const p of perms) {
      if (typeof p !== 'string' || !isActionPermission(p)) {
        throw new Error(`rbac: role '${role}' names unknown permission '${String(p)}' — the catalog (auth/permissions.ts) is the closed vocabulary`)
      }
      if (!valid.includes(p)) valid.push(p)
    }
    out[role] = valid
  }
  return out
}

/** The user's effective role set: the primary role first, then any
 *  additional assigned roles, deduped (the session payload's `roles`
 *  carries the full assigned set; `role` stays the section-gating
 *  primary). */
export function effectiveRolesOf(user: { role?: string | null; roles?: readonly string[] | null }): string[] {
  const out: string[] = []
  if (user.role) out.push(user.role)
  for (const r of user.roles ?? []) {
    if (r && !out.includes(r)) out.push(r)
  }
  return out
}

/** The permission set a role list holds under a map (union; unknown
 *  roles contribute nothing — honesty lives at assignment time). */
export function permissionsForRoles(
  roles: readonly string[],
  map: RolePermissionMap = DEFAULT_ROLE_PERMISSIONS,
): Set<ActionPermission> {
  const out = new Set<ActionPermission>()
  for (const role of roles) {
    for (const p of map[role] ?? []) out.add(p)
  }
  return out
}

/** Whether the role set holds ANY of the listed permissions (a
 *  transition's any-of set) — or the one permission when a single id is
 *  passed. */
export function rolesCan(
  roles: readonly string[],
  required: readonly ActionPermission[],
  map: RolePermissionMap = DEFAULT_ROLE_PERMISSIONS,
): boolean {
  const held = permissionsForRoles(roles, map)
  return required.some(p => held.has(p))
}

/** The roles holding a permission under the map (the denial hint's
 *  "held by: …" — a disabled action names the roles that CAN do it). */
export function roleHolders(
  permission: ActionPermission,
  map: RolePermissionMap = DEFAULT_ROLE_PERMISSIONS,
): string[] {
  return Object.entries(map)
    .filter(([, perms]) => perms.includes(permission))
    .map(([role]) => role)
    .sort()
}

// ── The OIDC seam (TODO.federation/10 calls this) ────────────────────

/**
 * Map OIDC claims to this instance's roles. Contract with item 10:
 * item 10 owns the claim SOURCE (which claim carries the roles — a
 * profile's identity section names it, default 'roles' then 'groups');
 * THIS function owns the semantics: read the claim(s), accept an array
 * or a space-delimited string (the two OIDC conventions), and keep only
 * roles the instance's map knows — a claim can never invent a role, and
 * an unknown role is dropped, never erroring the login (the approval
 * queue, item 10, handles first-seen users; roles are only ever
 * PROPOSED by claims and land subject to the instance's assignment
 * rules).
 */
export function rolesFromClaims(
  claims: Record<string, unknown>,
  map: RolePermissionMap = DEFAULT_ROLE_PERMISSIONS,
  claimKeys: readonly string[] = ['roles', 'groups'],
): string[] {
  const known = new Set(mapRoles(map))
  const out: string[] = []
  for (const key of claimKeys) {
    const raw = claims[key]
    const values: string[] = Array.isArray(raw)
      ? raw.filter((v): v is string => typeof v === 'string')
      : typeof raw === 'string'
        ? raw.split(/\s+/)
        : []
    for (const v of values) {
      if (known.has(v) && !out.includes(v)) out.push(v)
    }
  }
  return out
}
