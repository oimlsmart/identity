// ═══════════════════════════════════════════════════════════════════
// The org-kind vocabulary (TODO.restructure/07) — the ONE presentation
// mapping for the registry's organization kinds and the org-bounded
// role ids. The SERVER keeps the semantics (server/auth/org-registry.ts:
// the kind taxonomy, orgKindRoles' bounds, the link rules); this module
// is the client's single source for what each kind and role is CALLED
// and what it is FOR — consumed by the organizations list, the registry
// org detail, the join intake, and the membership surfaces. Before this
// module three surfaces carried three divergent presentations (raw kind
// codes in the orgs list, a member-kinds-only kindText on the org
// detail, a local English-only map on the join page).
//
// The copy's doctrine: the OIML MEMBER kinds hold the read/access
// posture (the Convention's fact — never certificate workflow
// authority); the PARTICIPANT kinds (the IA, its TLs, the designated
// bodies) hold the OIML-CS workflow authority; the manufacturer is
// never a participant. One line each, EN/FR in the catalogs.
// ═══════════════════════════════════════════════════════════════════
import type { MessageKey } from './i18n'

const KIND_LABEL_KEYS: Record<string, MessageKey> = {
  'member-state': 'org.kind.member-state.label',
  'corresponding-member': 'org.kind.corresponding-member.label',
  'issuing-authority': 'org.kind.issuing-authority.label',
  'test-laboratory': 'org.kind.test-laboratory.label',
  utilizer: 'org.kind.utilizer.label',
  associate: 'org.kind.associate.label',
  manufacturer: 'org.kind.manufacturer.label',
}

const KIND_PURPOSE_KEYS: Record<string, MessageKey> = {
  'member-state': 'org.kind.member-state.purpose',
  'corresponding-member': 'org.kind.corresponding-member.purpose',
  'issuing-authority': 'org.kind.issuing-authority.purpose',
  'test-laboratory': 'org.kind.test-laboratory.purpose',
  utilizer: 'org.kind.utilizer.purpose',
  associate: 'org.kind.associate.purpose',
  manufacturer: 'org.kind.manufacturer.purpose',
}

const ROLE_GLOSS_KEYS: Record<string, MessageKey> = {
  ia_officer: 'org.role.ia_officer',
  case_officer: 'org.role.case_officer',
  certification_officer: 'org.role.certification_officer',
  signatory: 'org.role.signatory',
  tl_operator: 'org.role.tl_operator',
  viewer: 'org.role.viewer',
  org_admin: 'org.role.org_admin',
}

/** The kind's display label's catalog key; an unknown or absent kind
 *  reads as the honest non-participant line. */
export function orgKindLabelKey(kind: string | null): MessageKey {
  return (kind !== null ? KIND_LABEL_KEYS[kind] : undefined) ?? 'org.kind.none.label'
}

/** The one-line "what this kind is FOR" gloss's catalog key, or null
 *  when the kind carries no gloss (hover hints stay absent honestly). */
export function orgKindPurposeKey(kind: string | null): MessageKey | null {
  return kind !== null ? (KIND_PURPOSE_KEYS[kind] ?? null) : null
}

/** The org-bounded role's one-line gloss's catalog key, or null for an
 *  id outside the vocabulary (the caller renders the bare id). */
export function orgRoleGlossKey(role: string): MessageKey | null {
  return ROLE_GLOSS_KEYS[role] ?? null
}
