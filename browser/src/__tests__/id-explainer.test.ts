// ─────────────────────────────────────────────────────────────────────
// TODO.identity-features/09, wave B — the effective-permission
// explainer's COMPOSITION, proven pure (server/auth/op/explain.ts): no
// store, no HTTP — fabricated orgs/accounts/memberships in, the computed
// effective set out. The route-level legs (the grant gates, the
// cross-org pin, the live posture after the cone act) are the
// memberships suite's (id-memberships.test.ts).
//
// Covered:
//   THE ROLES HELD — resolveOrgContext's own resolution (the session
//     payload's rule), each role attributed to its source (the
//     membership's per-org set / the org-free account's riding layer);
//   THE PERMISSIONS — the union, each named with the role(s) it came
//     from and its catalog label; an unknown role contributes nothing,
//     honestly;
//   THE CONE'S EFFECT — org-wide leaves the grant standing; 'assigned'
//     scopes every act to the rows naming the member; 'read-only'
//     suspends every action permission (the whole catalog is write-side
//     acts) whatever the scope;
//   THE DRY-RUN — the org-scoped classes answer org-field / assigned /
//     no-key honestly, the catalog and shared classes never narrow, the
//     foreign-org row never shows;
//   THE NARROWING INVARIANT — no cone posture's answers exceed the
//     org-wide posture's, per class;
//   THE OVERSIGHT CARVE-OUT — a primary role outside the org-bound set
//     reads everything regardless of the cone, and the read-only
//     modifier STILL refuses its writes (the write gate's order);
//   THE STATE HONESTY — an invited/disabled membership or a deactivated
//     account acts as nothing (never a peek at another context);
//   THE KIND BOUND — a drifted role (outside the org kind's set) is
//     flagged; the org_admin row is named, never flagged.
// ─────────────────────────────────────────────────────────────────────

import { describe, expect, it } from 'vitest'
import { DEFAULT_ROLE_PERMISSIONS } from '@oimlsmart/platform-server/vocab'
import type { OrgMembership } from '@oimlsmart/platform-server/store'
import {
  explainOrgMember,
  ORG_BOUND_PRIMARY_ROLES,
  type ExplainAccount,
  type MemberExplanation,
  type VisibilityClassReport,
} from '../../server/auth/op/explain'

const ORG = { id: 'ut-nmi-nl', name: 'Example Metrology Authority (Netherlands)', kind: 'utilizer' as const }

function membership(over: Partial<OrgMembership> = {}): OrgMembership {
  return {
    id: 'm-1',
    userId: 'u-1',
    orgId: ORG.id,
    roles: ['scheme_participant'],
    cone: { scope: 'org-wide', readOnly: false },
    state: 'active',
    isPrimary: false,
    invitedBy: null,
    createdAt: '2026-08-01T00:00:00Z',
    activatedAt: '2026-08-01T00:00:00Z',
    disabledAt: null,
    disabledBy: null,
    ...over,
  }
}

/** The IA officer acting as the Utilizer (the secondary-membership
 *  shape the memberships suite drives end to end): the account's
 *  primary binding stays its IA, the explained context is the org's. */
const OFFICER = { id: 'u-1', name: 'IA Officer', email: 'ia@oiml.org', role: 'ia_officer', roles: ['ia_officer'], orgId: 'EX1', active: true }

function explain(over: { account?: ExplainAccount; membership?: Partial<OrgMembership>; org?: typeof ORG } = {}): MemberExplanation {
  return explainOrgMember({
    org: over.org ?? ORG,
    account: over.account ?? OFFICER,
    membership: membership(over.membership),
    primary: null,
    map: DEFAULT_ROLE_PERMISSIONS,
  })
}

function classOf(x: MemberExplanation, store: string): VisibilityClassReport {
  const found = x.visibility.classes.find(c => c.store === store)
  if (!found) throw new Error(`no dry-run row for ${store}`)
  return found
}

describe('the effective-permission explainer (the composition)', () => {
  it('the org-wide member: the roles attributed, the permissions named with their roles, the dry-run open at the org line', () => {
    const x = explain()
    expect(x.acting).toBe(true)
    expect(x.stateNote).toBe('active')
    expect(x.context).toMatchObject({ orgId: 'ut-nmi-nl', cone: { scope: 'org-wide', readOnly: false } })
    // The account is org-bound (its primary binding is the IA) — the
    // account-level roles do NOT ride the org's context.
    expect(x.roles).toEqual([
      { id: 'scheme_participant', source: 'membership', known: true, permissions: [{ id: 'anr.declare', label: expect.any(String) }] },
    ])
    expect(x.permissions).toEqual([
      { id: 'anr.declare', label: expect.any(String), fromRoles: ['scheme_participant'], effective: true, effect: 'held' },
    ])
    expect(x.kindBound).toEqual({ assignable: ['viewer', 'scheme_participant'], orgAdminRow: false, outside: [] })
    expect(x.cone).toEqual({
      posture: 'org-wide',
      read: { scope: 'org-wide', effect: 'org-rows' },
      write: { refused: false, effect: 'role-set' },
    })
    // The dry-run: org-bound (the account's primary is the IA desk)…
    expect(x.visibility.orgBound).toBe(true)
    // …an org-scoped class: the own-org row visible on the org field,
    // the foreign row never…
    const apps = classOf(x, 'applications')
    expect(apps.class).toBe('org-scoped')
    expect(apps.personKey).toBeNull() // no person-level field — the assigned cone admits none of its rows
    expect(apps.ownOrg).toEqual({ visible: true, reason: 'org-field', field: 'manufacturer_id' })
    expect(apps.named).toBeNull() // the named row only matters under the assigned scope
    expect(apps.foreignOrg).toEqual({ visible: false, reason: 'org-field-miss', field: 'manufacturer_id' })
    // …the catalog reads shared (writes stay org-gated — the platform's)…
    expect(classOf(x, 'measuringInstrumentModels')).toMatchObject({ class: 'shared-catalog', ownOrg: { visible: true, reason: 'catalog' } })
    // …and the shared reference data never narrows.
    expect(classOf(x, '(every other entity class)')).toMatchObject({ class: 'shared-reference', ownOrg: { visible: true, reason: 'shared' } })
  })

  it('the assigned cone: the org’s rows must NAME the member — the person-keyed classes honestly, the rest closed', () => {
    const x = explain({ membership: { cone: { scope: 'assigned', readOnly: false } } })
    expect(x.cone.posture).toBe('assigned')
    expect(x.cone.read).toEqual({ scope: 'assigned', effect: 'named-rows-only' })
    expect(x.cone.write).toEqual({ refused: false, effect: 'role-set' })
    // The grant stands, scoped to the named rows.
    expect(x.permissions[0]).toMatchObject({ effective: true, effect: 'scoped-to-named-rows' })
    // The person-keyed classes: the plain own-org row hides, the named
    // row shows.
    const runs = classOf(x, 'testRuns')
    expect(runs.personKey).toContain('operators')
    expect(runs.ownOrg).toMatchObject({ visible: false, reason: 'assigned-miss' })
    expect(runs.named).toEqual({ visible: true, reason: 'assigned-hit', field: 'laboratory_id' })
    // The class with no person-level key admits NOTHING under the cone.
    const certs = classOf(x, 'certificates')
    expect(certs.personKey).toBeNull()
    expect(certs.ownOrg).toMatchObject({ visible: false, reason: 'assigned-no-key' })
    expect(certs.named).toBeNull()
    // The foreign row and the shared classes: unchanged by the scope.
    expect(runs.foreignOrg).toMatchObject({ visible: false, reason: 'org-field-miss' })
    expect(classOf(x, 'measuringInstrumentSamples').ownOrg).toMatchObject({ visible: true, reason: 'catalog' })
  })

  it('the read-only modifier: every action permission suspends, reads follow the scope', () => {
    const x = explain({ membership: { cone: { scope: 'org-wide', readOnly: true } } })
    expect(x.cone.posture).toBe('read-only')
    expect(x.cone.write).toEqual({ refused: true, effect: 'read-only-refused' })
    expect(x.permissions.every(p => !p.effective && p.effect === 'read-only-refused')).toBe(true)
    // Reads are untouched by the modifier (org-wide scope here).
    expect(classOf(x, 'applications').ownOrg).toMatchObject({ visible: true, reason: 'org-field' })
  })

  it('THE NARROWING INVARIANT: no cone posture’s answers exceed the org-wide posture’s, per class and per row', () => {
    const wide = explain()
    for (const cone of [
      { scope: 'assigned', readOnly: false },
      { scope: 'org-wide', readOnly: true },
      { scope: 'assigned', readOnly: true },
    ] as const) {
      const narrowed = explain({ membership: { cone } })
      for (const cls of narrowed.visibility.classes) {
        const base = wide.visibility.classes.find(c => c.store === cls.store)!
        for (const key of ['ownOrg', 'named', 'foreignOrg'] as const) {
          if (cls[key]?.visible) expect(base[key]?.visible, `${cls.store}.${key} under ${cone.scope}+${cone.readOnly}`).toBe(true)
        }
      }
      for (const p of narrowed.permissions) {
        if (p.effective) expect(wide.permissions.find(w => w.id === p.id)?.effective).toBe(true)
      }
    }
  })

  it('the oversight carve-out: a non-org-bound primary role reads everything — and read-only STILL refuses its writes', () => {
    // The org-free estate account (admin) holding a viewer membership in
    // the org: the account-level roles ride the context (the honest
    // union), the read gate never narrows it, and the cone never hides a
    // row — but the read-only modifier refuses the writes (the write
    // gate checks it BEFORE the org-bound posture).
    const admin = { id: 'u-2', name: 'OIML Admin', email: 'admin@oiml.org', role: 'admin', roles: ['admin'], orgId: null, active: true }
    const x = explain({
      account: admin,
      membership: { userId: 'u-2', roles: ['viewer'], cone: { scope: 'assigned', readOnly: true } },
    })
    expect(x.roles.map(r => [r.id, r.source])).toEqual([['viewer', 'membership'], ['admin', 'account']])
    expect(x.visibility.orgBound).toBe(false)
    for (const cls of x.visibility.classes) {
      expect(cls.ownOrg.visible, cls.store).toBe(true)
      expect(cls.foreignOrg.visible, cls.store).toBe(true)
    }
    expect(classOf(x, 'applications').ownOrg.reason).toBe('oversight')
    // The admin role holds the whole catalog; the cone's modifier
    // suspends every one of them.
    expect(x.permissions.length).toBeGreaterThan(10)
    expect(x.permissions.every(p => !p.effective)).toBe(true)
    expect(x.cone.write).toEqual({ refused: true, effect: 'read-only-refused' })
  })

  it('the org-bound set is the platform’s gate set (the applicant, the laboratory, the IA desk)', () => {
    expect([...ORG_BOUND_PRIMARY_ROLES].sort()).toEqual(['applicant', 'case_officer', 'certification_officer', 'ia_officer', 'signatory', 'tl_operator'])
  })

  it('the state honesty: an invited or disabled membership — or a deactivated account — acts as nothing', () => {
    for (const [membershipOver, note] of [
      [{ state: 'invited' }, 'membership-invited'],
      [{ state: 'disabled' }, 'membership-disabled'],
    ] as const) {
      const x = explain({ membership: membershipOver })
      expect(x.acting).toBe(false)
      expect(x.stateNote).toBe(note)
      expect(x.context.orgId).toBeNull()
      expect(x.roles).toEqual([])
      expect(x.permissions).toEqual([])
    }
    const deactivated = explain({ account: { ...OFFICER, active: false } })
    expect(deactivated.acting).toBe(false)
    expect(deactivated.stateNote).toBe('account-deactivated')
    // …and the visibility dry-run does not narrow an account that acts
    // as nothing (there is no org context to narrow).
    expect(deactivated.visibility.orgBound).toBe(false)
  })

  it('the kind bound: a drifted role is flagged, the org_admin row is named — never flagged', () => {
    const drifted = explain({ membership: { roles: ['viewer', 'ia_officer'] } })
    expect(drifted.kindBound.outside).toEqual(['ia_officer'])
    expect(drifted.kindBound.orgAdminRow).toBe(false)
    const adminRow = explain({ membership: { roles: ['org_admin', 'viewer'] } })
    expect(adminRow.kindBound.orgAdminRow).toBe(true)
    expect(adminRow.kindBound.outside).toEqual([])
    // The org_admin row's permission is the org-scoped grant itself.
    expect(adminRow.permissions.map(p => p.id)).toEqual(['org.users.manage'])
  })

  it('an unknown role contributes nothing — honestly (the map is the closed vocabulary)', () => {
    const x = explain({ membership: { roles: ['wizard'] } })
    expect(x.roles[0]).toMatchObject({ id: 'wizard', known: false, permissions: [] })
    expect(x.permissions).toEqual([])
    expect(x.kindBound.outside).toEqual(['wizard'])
  })
})
