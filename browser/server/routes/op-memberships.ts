// ═══════════════════════════════════════════════════════════════════
// The membership administration API (TODO.identity/11 — the multi-org
// model) — the per-org membership management behind the org console's
// people slice and the identity admin's per-org view.
//
// TWO grants gate these routes (the same vocabulary as
// routes/users.ts's, resolved over the session's EFFECTIVE roles — the
// active-org context's set, so an org admin acting as another org holds
// no grant here until it switches back):
//
//   - `users.manage` — the identity admin (admin/cs_admin): every org,
//     every membership, including the org_admin memberships (the scheme
//     operator's delegation act, B 18:2025 §10.2);
//   - `org.users.manage` — the org admin, scoped to the org it ACTS AS
//     (the session's effective org): its own people's memberships and
//     per-org role sets — NEVER another org's rows (a cross-org row is
//     not found, never wider), NEVER the org_admin role itself, and
//     NEVER a membership holding it (the org's administrator account
//     stays the scheme operator's).
//
// The lifecycle: an org's admin INVITES an existing account (state
// 'invited' — the holder accepts from the account console; the
// join-request approval is the other path in, state 'active' because
// both consents are on record) → ACTIVE ⇄ DISABLED. The PRIMARY
// membership is never created/deleted here: the primary binding moves
// through the account's role/org assignment (the users surface), and
// the mirror keeps the legacy columns identical.
//
// Every mutation lands an auditEvents row naming the actor and the
// grant used. WORKER-SAFE: the store seam only, no node built-ins.
// ═══════════════════════════════════════════════════════════════════

import { Hono, type Context, type MiddlewareHandler } from 'hono'
import { env as runtimeEnv } from 'hono/adapter'
import { getStore, encodeOrgMemberCone, parseOrgMemberCone, type AuthUserPayload, type OrgMembership, type ServerStore, type UserAdminRow } from '@oimlsmart/platform-server/store'
import { getInstanceProfile } from '@oimlsmart/platform-server/profile'
import { effectiveRbacMap } from '@oimlsmart/platform-server/rbac'
import { effectiveRolesOf } from '@oimlsmart/platform-server/vocab'
import { orgAssignableRoles, resolveRegistryOrg } from '../auth/org-registry'
import { orgAuditSlice } from '../auth/op/org-audit'
import { explainAccountOf, explainOrgMember } from '../auth/op/explain'
import { sessionUser } from '@oimlsmart/platform-server/session'

/** The caller's grant over these routes: 'wide' (the identity admin) or
 *  'org' (the org admin, pinned to the org it acts AS). */
interface MembershipGrant {
  kind: 'wide' | 'org'
  orgId: string | null
  /** The permission exercised (the audit trail's record). */
  permission: 'users.manage' | 'org.users.manage'
}

/** A member row for the consoles: the membership + the account's
 *  display fields (never credential material). The cone rides as the
 *  parsed posture (TODO.identity-features/09) — the membership's own
 *  row carries the canonical string; the console renders the posture.
 *  The LIST caller (the people slice) passes the request's one users
 *  read (the endpoint-scaling doctrine — a per-member listUsers was one
 *  full scan per member); the single-membership acts keep the one read. */
async function memberView(store: ServerStore, membership: OrgMembership, usersById?: Map<string, UserAdminRow>) {
  const account = (usersById?.get(membership.userId)
    ?? (await store.listUsers()).find(u => u.id === membership.userId)) ?? null
  return {
    userId: membership.userId,
    name: account?.name ?? '(erased account)',
    email: account?.email ?? null,
    provider: account?.provider ?? null,
    accountActive: account?.active ?? false,
    orgId: membership.orgId,
    roles: membership.roles,
    cone: membership.cone,
    state: membership.state,
    isPrimary: membership.isPrimary,
    invitedBy: membership.invitedBy,
    createdAt: membership.createdAt,
    activatedAt: membership.activatedAt,
    disabledAt: membership.disabledAt,
    disabledBy: membership.disabledBy,
  }
}

export function createOpMembershipsRouter(): Hono {
  const router = new Hono()

  // ── the profile gate (the op.ts posture: one build, the profile
  //    decides) ─────────────────────────────────────────────────────
  const profileGate: MiddlewareHandler = async (c, next) => {
    if (!getInstanceProfile().modules.includes('identity')) {
      return c.json({ error: 'not found' }, 404)
    }
    await next()
  }
  router.use('/api/op/org-memberships', profileGate)
  router.use('/api/op/org-memberships/*', profileGate)

  /** The caller's grant, or the error response. */
  async function grant(c: Context): Promise<{ user: AuthUserPayload; grant: MembershipGrant } | { error: Response }> {
    const user = await sessionUser(c)
    if (!user) return { error: c.json({ error: 'authentication required' }, 401) }
    const map = effectiveRbacMap(runtimeEnv(c) as Record<string, string | undefined>)
    const held = new Set(effectiveRolesOf(user).flatMap(r => map[r] ?? []))
    if (held.has('users.manage')) return { user, grant: { kind: 'wide', orgId: user.orgId ?? null, permission: 'users.manage' } }
    if (held.has('org.users.manage')) {
      // The scoped grant keys on the EFFECTIVE org (the active context):
      // an org admin of several orgs manages the one it acts AS.
      if (!user.orgId) {
        return { error: c.json({ error: 'org.users.manage requires acting as an organization — switch to the organization’s context first' }, 403) }
      }
      return { user, grant: { kind: 'org', orgId: user.orgId, permission: 'org.users.manage' } }
    }
    return { error: c.json({ error: 'missing permission: org.users.manage', permission: 'org.users.manage' }, 403) }
  }

  /** The mutation audit (actor + the grant used + the org). */
  async function audit(
    actor: AuthUserPayload,
    grant: MembershipGrant,
    targetUserId: string,
    action: string,
    metadata: Record<string, unknown>,
  ): Promise<void> {
    try {
      const id = crypto.randomUUID()
      await getStore().putEntity('auditEvents', id, null, JSON.stringify({
        id,
        timestamp: new Date().toISOString(),
        standard_id: '',
        entity_type: 'org_memberships',
        entity_id: targetUserId,
        action,
        user_id: actor.id,
        user_name: actor.name,
        metadata: { permission: grant.permission, org_id: metadata.org_id ?? grant.orgId ?? null, ...metadata },
      }))
    } catch (err) {
      console.error(`[op] membership audit event ${action} failed to persist:`, (err as Error).message)
    }
  }

  /** The scope check for a route naming an org: the org grant only ever
   *  reaches its own org's rows. Answers the pinned org id, or the error
   *  response. */
  function scopeOrg(c: Context, grant: MembershipGrant, orgId: string | null): { orgId: string } | { error: Response } {
    if (grant.kind === 'org') {
      if (orgId && orgId !== grant.orgId) {
        return { error: c.json({ error: `the org-scoped grant reaches only your own organization ('${grant.orgId}')` }, 403) }
      }
      return { orgId: grant.orgId! }
    }
    if (!orgId) return { error: c.json({ error: 'org_id is required' }, 400) }
    return { orgId }
  }

  /** The role-set validation: the platform vocabulary is the route's
   *  caller's concern (the store trusts it) — here: the org must be an
   *  ACTIVE registry organization (TODO.identity-features/05 — the
   *  identity service's own registry, any kind; a disabled org's
   *  membership graph is suspended), the org's KIND bounds the set, and
   *  org_admin is the identity administrator's alone. */
  async function rolesRefusal(
    c: Context,
    grant: MembershipGrant,
    orgId: string,
    roles: string[],
  ): Promise<Response | null> {
    if (grant.kind === 'org' && roles.includes('org_admin')) {
      return c.json({
        error: 'the org_admin role is assigned by the scheme operator (BIML) only — one organization administrator per registered org (B 18:2025 §10.2)',
      }, 403)
    }
    const org = await resolveRegistryOrg(getStore(), orgId)
    if (!org) {
      return c.json({
        error: `organization '${orgId}' is not on the organization registry — the identity administrator adds it first (the Organizations surface)`,
      }, 400)
    }
    if (org.state !== 'active') {
      return c.json({
        error: `organization '${orgId}' is disabled — its membership graph is suspended until the identity administrator re-enables it`,
      }, 409)
    }
    const bounded = new Set(orgAssignableRoles(org))
    const outside = roles.filter(r => !bounded.has(r) && r !== 'org_admin')
    if (outside.length) {
      return c.json({
        error: `role(s) ${outside.map(r => `'${r}'`).join(', ')} are not assignable within a ${org.kind ?? 'non-participant organization'} — the org's kind bounds the set (assignable: ${[...bounded].join(', ')})`,
      }, 403)
    }
    return null
  }

  /** The org-grant never touches a membership HOLDING org_admin (the
   *  scheme operator's row). The wide grant's own org_admin assignment
   *  rides the eligibility rule (a registered org — rolesRefusal). */
  function targetRefusal(c: Context, grant: MembershipGrant, membership: OrgMembership): Response | null {
    if (grant.kind === 'org' && membership.roles.includes('org_admin')) {
      return c.json({ error: 'organization administrator memberships are managed by the scheme operator (BIML)' }, 403)
    }
    return null
  }

  // GET /api/op/org-memberships?org_id= — one org's members with their
  // per-org role sets + states (the org console's people slice; the
  // identity admin's per-org view). The org grant's slice is pinned to
  // its own org, never wider.
  router.get('/api/op/org-memberships', async (c) => {
    const gate = await grant(c)
    if ('error' in gate) return gate.error
    const scoped = scopeOrg(c, gate.grant, c.req.query('org_id')?.trim() || null)
    if ('error' in scoped) return scoped.error
    const store = getStore()
    const org = await resolveRegistryOrg(store, scoped.orgId)
    if (!org) return c.json({ error: `organization '${scoped.orgId}' is not on the organization registry` }, 404)
    // The accounts join reads the users table ONCE — the per-member
    // listUsers this replaces was one full scan per member (the
    // endpoint-scaling doctrine: prefetch once, group in memory).
    const [members, users] = await Promise.all([store.listOrgMembers(scoped.orgId), store.listUsers()])
    const usersById = new Map(users.map(u => [u.id, u]))
    return c.json({
      grant: gate.grant.kind,
      org: { id: org.id, name: org.name, shortName: org.shortName, kind: org.kind, country: org.country, state: org.state, registered: org.registered, roles: org.roles },
      members: await Promise.all(members.map(m => memberView(store, m, usersById))),
    })
  })

  // POST /api/op/org-memberships — invite an EXISTING account into the
  // org: { email, org_id?, roles }. The membership starts 'invited' —
  // the holder accepts from the account console (the honest consent); the
  // join-request approval is the directly-active path (the holder asked
  // first). A NEW person (no account yet) goes through the org-invites /
  // join-request flows instead — this route never creates accounts.
  router.post('/api/op/org-memberships', async (c) => {
    const gate = await grant(c)
    if ('error' in gate) return gate.error
    const { user, grant: g } = gate
    const body = await c.req.json<{ email?: string; org_id?: string | null; roles?: unknown }>().catch(() => null)
    const email = typeof body?.email === 'string' ? body.email.trim().toLowerCase() : ''
    if (!body || !email.includes('@')) {
      return c.json({ error: 'the account’s email is required' }, 400)
    }
    if (!Array.isArray(body.roles) || body.roles.some(r => typeof r !== 'string')) {
      return c.json({ error: 'roles must be a list of role ids ([] = a plain member with no org roles)' }, 400)
    }
    const roles = [...new Set(body.roles as string[])]
    const scoped = scopeOrg(c, g, typeof body.org_id === 'string' && body.org_id.trim() ? body.org_id.trim() : null)
    if ('error' in scoped) return scoped.error
    const refusal = await rolesRefusal(c, g, scoped.orgId, roles)
    if (refusal) return refusal

    const store = getStore()
    const account = await store.findUserByEmail(email)
    if (!account) {
      return c.json({
        error: `no account holds ${email} yet — invite the person first (the organization administration console's invite), then add their membership here`,
      }, 404)
    }
    if (account.id === user.id) {
      return c.json({ error: 'you cannot invite your own account — your memberships are yours alone' }, 400)
    }
    const membership = await store.createOrgMembership({
      userId: account.id,
      orgId: scoped.orgId,
      roles,
      state: 'invited',
      invitedBy: user.email,
    })
    if (!membership) {
      return c.json({ error: `${email} already holds a membership in this organization` }, 409)
    }
    await audit(user, g, account.id, 'membership.invited', { email, org_id: scoped.orgId, roles })
    return c.json(await memberView(store, membership), 201)
  })

  /** Resolve the target membership for the mutation routes: the org
   *  scope pins the org (the URL's :orgId must BE the caller's), the
   *  row must exist, and the org grant never touches an org_admin row. */
  async function targetMembership(
    c: Context,
    g: MembershipGrant,
  ): Promise<{ membership: OrgMembership } | { error: Response }> {
    const orgId = c.req.param('orgId')!
    if (g.kind === 'org' && orgId !== g.orgId) {
      return { error: c.json({ error: 'not found' }, 404) } // a cross-org row is not found, never wider
    }
    const membership = await getStore().getOrgMembership(c.req.param('userId')!, orgId)
    if (!membership) return { error: c.json({ error: 'not found' }, 404) }
    const refusal = targetRefusal(c, g, membership)
    if (refusal) return { error: refusal }
    return { membership }
  }

  // PUT /api/op/org-memberships/:userId/:orgId/roles — replace the
  // per-org role set: { roles: [...] }. A PRIMARY membership's write
  // mirrors into the account's legacy columns (the store's dual-write),
  // and never empties (the primary binding always carries a role — move
  // the binding first).
  router.put('/api/op/org-memberships/:userId/:orgId/roles', async (c) => {
    const gate = await grant(c)
    if ('error' in gate) return gate.error
    const { user, grant: g } = gate
    const body = await c.req.json<{ roles?: unknown }>().catch(() => null)
    if (!body || !Array.isArray(body.roles) || body.roles.some(r => typeof r !== 'string')) {
      return c.json({ error: 'roles must be a list of role ids' }, 400)
    }
    const roles = [...new Set(body.roles as string[])]
    const found = await targetMembership(c, g)
    if ('error' in found) return found.error
    const membership = found.membership
    if (membership.isPrimary && roles.length === 0) {
      return c.json({
        error: 'the primary membership always carries at least one role — the account’s primary organization binding moves through its role/org assignment',
      }, 400)
    }
    const refusal = await rolesRefusal(c, g, membership.orgId, roles)
    if (refusal) return refusal
    const store = getStore()
    const previous = membership.roles
    await store.setOrgMembershipRoles(membership.userId, membership.orgId, roles)
    await audit(user, g, membership.userId, 'membership.roles', { org_id: membership.orgId, roles, previous })
    return c.json(await memberView(store, (await store.getOrgMembership(membership.userId, membership.orgId))!))
  })

  // GET /api/op/org-memberships/activity?org_id= — the org admin's audit
  // slice (TODO.identity-features/09): their org's membership + cone +
  // join/invite + lifecycle acts, newest first, 50 deep — the SAME
  // computation the identity admin's per-org aggregate reads
  // (auth/op/org-audit.ts). The org grant's slice is pinned to its own
  // org, never wider (the scopeOrg rule). REGISTERED before the
  // '/:userId/…' routes — a static segment never falls into the param
  // bucket.
  router.get('/api/op/org-memberships/activity', async (c) => {
    const gate = await grant(c)
    if ('error' in gate) return gate.error
    const scoped = scopeOrg(c, gate.grant, c.req.query('org_id')?.trim() || null)
    if ('error' in scoped) return scoped.error
    const store = getStore()
    const org = await resolveRegistryOrg(store, scoped.orgId)
    if (!org) return c.json({ error: `organization '${scoped.orgId}' is not on the organization registry` }, 404)
    return c.json({ org: { id: org.id, name: org.name }, activity: await orgAuditSlice(store, scoped.orgId) })
  })

  // GET /api/op/org-memberships/:userId/:orgId/explain — the effective-
  // permission explainer (TODO.identity-features/09, wave B): "explain
  // member X" answered with the COMPUTED effective set — the roles held
  // (attributed to their source: the membership's set, the account
  // layer), the permissions they grant (each named with the role it came
  // from), the cone's effect on the read/write action classes, and the
  // data-visibility dry-run over synthesized rows (auth/op/explain.ts —
  // a PURE composition of the kernel's resolution functions; this route
  // only gathers the rows). A READ: the org grant explains any member of
  // its own org INCLUDING the org_admin row — the people list already
  // shows it; the org_admin refusal on the mutation routes guards ACTS,
  // never this read.
  router.get('/api/op/org-memberships/:userId/:orgId/explain', async (c) => {
    const gate = await grant(c)
    if ('error' in gate) return gate.error
    const g = gate.grant
    const orgId = c.req.param('orgId')!
    if (g.kind === 'org' && orgId !== g.orgId) {
      return c.json({ error: 'not found' }, 404) // a cross-org row is not found, never wider
    }
    const store = getStore()
    const membership = await store.getOrgMembership(c.req.param('userId')!, orgId)
    if (!membership) return c.json({ error: 'not found' }, 404)
    const org = await resolveRegistryOrg(store, orgId)
    if (!org) return c.json({ error: `organization '${orgId}' is not on the organization registry` }, 404)
    const account = explainAccountOf((await store.listUsers()).find(u => u.id === membership.userId) ?? null)
    if (!account) return c.json({ error: 'not found' }, 404) // the membership names an erased account — nothing to explain
    const primary = account.orgId ? await store.getOrgMembership(account.id, account.orgId) : null
    const map = effectiveRbacMap(runtimeEnv(c) as Record<string, string | undefined>)
    return c.json(explainOrgMember({ org, account, membership, primary, map }))
  })

  // PUT /api/op/org-memberships/:userId/:orgId/cone — the member's data
  // cone (TODO.identity-features/09): { cone: 'org-wide' | 'assigned' |
  // 'read-only' | 'assigned+read-only' | null }. The org admin's answer
  // to "what can this member see and do" — a NARROWING posture only: the
  // cone intersects the role set's grants, never widens them, and never
  // touches the roles (the kind bound stays the rolesRefusal's, above).
  // The org grant never touches an org_admin membership (the same
  // targetRefusal as the role act).
  router.put('/api/op/org-memberships/:userId/:orgId/cone', async (c) => {
    const gate = await grant(c)
    if ('error' in gate) return gate.error
    const { user, grant: g } = gate
    const body = await c.req.json<{ cone?: unknown }>().catch(() => null)
    if (!body || (body.cone !== null && typeof body.cone !== 'string')) {
      return c.json({ error: 'cone must be one of "org-wide", "assigned", "read-only", "assigned+read-only" — or null (the org-wide default)' }, 400)
    }
    const CANONICAL = new Set(['org-wide', 'assigned', 'read-only', 'assigned+read-only'])
    if (typeof body.cone === 'string' && !CANONICAL.has(body.cone)) {
      return c.json({ error: `unknown cone '${body.cone}' — the postures are "org-wide", "assigned", "read-only", "assigned+read-only"` }, 400)
    }
    const found = await targetMembership(c, g)
    if ('error' in found) return found.error
    const membership = found.membership
    const store = getStore()
    // The canonical column spelling: NULL for the org-wide default (the
    // column stays NULL — the expand-only posture), else the encoding.
    const canonical = body.cone === null || body.cone === 'org-wide'
      ? null
      : encodeOrgMemberCone(parseOrgMemberCone(body.cone))
    const previous = encodeOrgMemberCone(membership.cone)
    const updated = await store.setOrgMembershipCone(membership.userId, membership.orgId, canonical)
    await audit(user, g, membership.userId, 'membership.cone', {
      org_id: membership.orgId,
      email: (await store.listUsers()).find(u => u.id === membership.userId)?.email ?? null,
      cone: canonical ?? 'org-wide',
      previous: previous ?? 'org-wide',
    })
    return c.json(await memberView(store, updated!))
  })

  // POST /api/op/org-memberships/:userId/:orgId/state — the lifecycle
  // act: { state: 'active' | 'disabled' }. Disabling ends the account's
  // live sessions' context into the org (the store clears the stamps);
  // re-activation is deliberate, never automatic — and it refuses while
  // the ORG itself is disabled (TODO.identity-features/05: a disabled
  // org's membership graph stays suspended).
  router.post('/api/op/org-memberships/:userId/:orgId/state', async (c) => {
    const gate = await grant(c)
    if ('error' in gate) return gate.error
    const { user, grant: g } = gate
    const body = await c.req.json<{ state?: string }>().catch(() => null)
    if (!body || (body.state !== 'active' && body.state !== 'disabled')) {
      return c.json({ error: 'state must be "active" or "disabled"' }, 400)
    }
    if (c.req.param('userId') === user.id && body.state === 'disabled') {
      return c.json({ error: 'you cannot disable your own membership' }, 400)
    }
    const found = await targetMembership(c, g)
    if ('error' in found) return found.error
    const membership = found.membership
    if (membership.state === 'invited') {
      return c.json({
        error: 'the invitation is still waiting for the account holder — it cannot be disabled or activated here (the holder accepts or declines it)',
      }, 409)
    }
    const store = getStore()
    if (body.state === 'active') {
      const org = await store.getOrgRegistryOrg(membership.orgId)
      if (org?.state === 'disabled') {
        return c.json({
          error: `organization '${membership.orgId}' is disabled — the identity administrator re-enables the organization first; the membership's re-activation follows`,
        }, 409)
      }
    }
    const updated = await store.setOrgMembershipState(membership.userId, membership.orgId, body.state, user.email)
    await audit(user, g, membership.userId, body.state === 'disabled' ? 'membership.disabled' : 'membership.activated', {
      org_id: membership.orgId,
      email: (await store.listUsers()).find(u => u.id === membership.userId)?.email ?? null,
    })
    return c.json(await memberView(store, updated!))
  })

  return router
}
