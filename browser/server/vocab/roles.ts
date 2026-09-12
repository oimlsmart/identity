// ═══════════════════════════════════════════════════════════════════
// Role model (TODO.new-paradigm/01) — shared by router guards, nav
// filtering and the login redirect. Plain module (no Vue) so it can be
// imported from anywhere without composable context.
// ═══════════════════════════════════════════════════════════════════

export const APP_ROLES = [
  'applicant',
  'ia_officer',
  'tl_operator',
  'biml_officer',
  'cs_admin',
  'mc_member',
  'rc_member',
  'executive_secretary',
  'admin',
  'viewer',
  // TODO.federation/12 — the NMI split-role vocabulary (the RBAC default
  // map, auth/rbac.ts, grants them their permission sets; section gating
  // below seats them at the IA console). No hub account holds them.
  'case_officer',
  'certification_officer',
  'signatory',
  // TODO.identity/10 — delegated organization administration: one org
  // admin per registered participant org (created by BIML), managing its
  // own org's people on the identity service (/op/admin/users).
  'org_admin',
  // TODO.adoption/11 — Utilizer/Associate staff: declare Additional
  // National Requirements for their country on the ANR registry console
  // (the declaration carries the participant it acts for; the CS
  // registry's approval is the moderation gate).
  'scheme_participant',
  // TODO.adoption/05 — the market-surveillance authority account: the
  // register's authority audience for the schemes that reserve their
  // full certificate view to the authorities (brief_public /
  // authority_only access tiers). Read-only by construction.
  'market_surveillance',
] as const
export type AppRole = (typeof APP_ROLES)[number]

/** The IA-desk role family (TODO.federation/12): the roles seated at the
 *  IA console, org-bound to their issuing authority — ia_officer and the
 *  NMI split roles. Server-side org/catalog legs test the FAMILY (never
 *  the literal 'ia_officer') so the split roles inherit the desk's org
 *  posture; the ACTION line between them is the RBAC map's. */
export const IA_DESK_ROLES: readonly string[] = ['ia_officer', 'case_officer', 'certification_officer', 'signatory']

/** Home route per role — mismatch redirects land here. */
export function roleHome(role: string | null | undefined): string {
  switch (role) {
    case 'applicant': return '/app/portal'
    case 'ia_officer': return '/app/ia'
    case 'tl_operator': return '/app/lab'
    case 'biml_officer': return '/app/biml'
    case 'cs_admin': return '/app/cs'
    case 'mc_member':
    case 'rc_member': return '/app/cs/approvals'
    case 'executive_secretary': return '/app/cs/participants'
    // TODO.adoption/11 — the Utilizer/Associate staffer lands on the ANR
    // registry console (the only /app/cs surface the role may enter).
    case 'scheme_participant': return '/app/cs/anr'
    // TODO.adoption/05 — the market-surveillance authority's surface is
    // the register (its read-only authority view).
    case 'market_surveillance': return '/app/register'
    // The NMI split roles work the IA console (TODO.federation/12).
    case 'case_officer':
    case 'certification_officer':
    case 'signatory': return '/app/ia'
    // TODO.identity/10 — the org admin's console lives on the identity
    // service (the account store); the page itself answers honestly on a
    // profile that does not serve organization administration.
    case 'org_admin': return '/op/admin/users'
    default: return '/app'
  }
}

export interface RoleSectionRule {
  /** Path prefix (matched exactly or followed by '/'). */
  prefix: string
  /** Roles allowed in the section; 'admin' is always allowed everywhere. */
  roles: AppRole[]
}

/**
 * Role-scoped app sections. Order matters — first match wins, so more
 * specific prefixes (/app/cs/lab-inbox, /app/cs/approvals) come before
 * their parent (/app/cs).
 * /app/standards/* (References + workflow lists) and /app/library stay
 * accessible to every authenticated role.
 *
 * TODO.roadmap/44 organ roles: the approval-pipeline board
 * (/app/cs/approvals) is the MC/RC working surface; the participant
 * registry + Declaration editor (/app/cs/participants) is the Executive
 * Secretary's surface. Both stay open to cs_admin (scheme operations).
 * TODO.roadmap/45: the scheme-operations console (/app/cs/operations —
 * appeals, complaints, misuse, deregistration) is the Executive
 * Secretary's post-issuance surface.
 */
export const ROLE_SECTION_RULES: RoleSectionRule[] = [
  // TODO.federation/02 — the engagement conversion hands off to the
  // application wizard (?engagement=<id>); in the NMI profile the IA
  // officer drives it for the applicant (the white-gloves seam — fed-03
  // completes the on-behalf-of provenance). More specific than
  // /app/portal, so it must come first (first match wins).
  { prefix: '/app/portal/applications/new', roles: ['applicant', 'ia_officer'] },
  // TODO.cs-e2e/05a — /app/portal/projects/<id> (the applicant's read-only
  // TEP view) rides the /app/portal prefix: the applicant's own section.
  { prefix: '/app/portal', roles: ['applicant'] },
  // TODO.cs-e2e/02 — the Type Evaluation Project hub: the IA officer's
  // working page, readable by cs_admin (scheme oversight). More specific
  // than /app/ia, so it must come first (first match wins).
  // TODO.federation/12: the NMI split roles (case/certification officer,
  // signatory) sit at the IA console — RBAC (auth/permissions.ts) draws
  // the finer line BETWEEN them inside these pages.
  { prefix: '/app/ia/projects', roles: ['ia_officer', 'cs_admin', 'case_officer', 'certification_officer', 'signatory'] },
  { prefix: '/app/ia', roles: ['ia_officer', 'case_officer', 'certification_officer', 'signatory'] },
  // TODO.cs-e2e/05a — /app/lab/projects/<id> (the laboratory's scoped TEP
  // context view) rides the /app/lab prefix: the laboratory's own section.
  { prefix: '/app/lab', roles: ['tl_operator'] },
  // TODO.register/02 — the register's owner view: the manufacturer org's
  // own rows, the IA desk's issued cone, the estate's all-seeing cone +
  // the holder-claim queue. The module path rule (auth/modules.ts) rides
  // the register module.
  { prefix: '/app/my-certificates', roles: ['applicant', 'ia_officer', 'case_officer', 'certification_officer', 'signatory', 'biml_officer', 'cs_admin'] },
  // TODO.deploying/10 — the BIML portal: the registry operator's surface
  // (open to cs_admin for scheme operations).
  { prefix: '/app/biml', roles: ['biml_officer', 'cs_admin'] },
  { prefix: '/app/cs/lab-inbox', roles: ['tl_operator'] },
  { prefix: '/app/cs/approvals', roles: ['mc_member', 'rc_member', 'executive_secretary', 'cs_admin'] },
  { prefix: '/app/cs/participants', roles: ['executive_secretary', 'cs_admin'] },
  { prefix: '/app/cs/operations', roles: ['executive_secretary', 'cs_admin'] },
  // TODO.adoption/11 — the ANR registry console: the Utilizer/Associate
  // staffer (scheme_participant) declares here; the CS registry moderates.
  // More specific than /app/cs, so it must come first (first match wins).
  { prefix: '/app/cs/anr', roles: ['scheme_participant', 'executive_secretary', 'cs_admin'] },
  // TODO.cs-e2e/13.15 — Data management is the workspace's own export/
  // import surface, and the profile indicator's degradation banner names
  // it as the way out for EVERY role; it must stay reachable by every
  // signed-in account or the banner would send users to a refused page.
  { prefix: '/app/cs/data', roles: [...APP_ROLES] },
  { prefix: '/app/cs', roles: ['cs_admin'] },
  // TODO.roadmap/29 — the v3 runtime surfaces (coverage pages, the
  // live-twin console) are scheme-operator surfaces.
  { prefix: '/app/coverage', roles: ['cs_admin'] },
  { prefix: '/app/twin', roles: ['cs_admin'] },
  // TODO.v3 — the twin lab: the scheme operator AND the test laboratory
  // (the guided run's tester is the TL's operator).
  { prefix: '/app/twin-lab', roles: ['cs_admin', 'tl_operator'] },
]

/** The section rule covering `path`, if any. */
export function sectionRuleFor(path: string): RoleSectionRule | undefined {
  return ROLE_SECTION_RULES.find(r => path === r.prefix || path.startsWith(r.prefix + '/'))
}

/** Whether `role` may enter `path` per ROLE_SECTION_RULES (admin bypasses). */
export function canAccessPath(role: string | null | undefined, path: string): boolean {
  const rule = sectionRuleFor(path)
  if (!rule) return true
  if (role === 'admin') return true
  return !!role && (rule.roles as string[]).includes(role)
}
