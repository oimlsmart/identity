// ═══════════════════════════════════════════════════════════════════
// The users API (TODO.federation/12 — multi-user instances): list the
// instance's users, create LOCAL users, assign roles within the
// instance's role → permission map, deactivate/reactivate accounts.
//
// TWO grants gate these routes (the session's effective roles under the
// instance's RBAC map):
//
//   - `users.manage` — the INSTANCE-WIDE grant (admin/cs_admin in the
//     shipped default): every route behaves as it always has;
//   - `org.users.manage` — the ORG-SCOPED grant (TODO.identity/10, the
//     delegated organization administrator): every read and write is
//     scoped to the caller's OWN organization binding (user.orgId) —
//     the list answers only the org's users, creates land in the org
//     with a role the org's KIND bounds (server/auth/org-registry.ts),
//     and a target outside the org is not found (no cross-org slice
//     exists). Organization-administrator accounts themselves stay with
//     the scheme operator: the scoped grant can neither assign
//     `org_admin` nor modify an account holding it (one per org,
//     created by BIML after verification — B 18 §10.2 / PD-03).
//
// The ELIGIBILITY RULE lives here too (the wide grant's half): assigning
// `org_admin` requires the account's org to be a REGISTERED participant
// org (the participants register, read from the entity store) — a
// refusal names the rule.
//
// Refusals name the missing permission (honest 403, the same contract
// as the entity gate). Every mutation journals an audit event naming
// the actor and the permission used.
//
// OIDC (item 10): OIDC-LINKED users appear here the same as local ones
// (their roles come from the same map — claim-proposed roles land
// through rolesFromClaims, subject to assignment here).
// ═══════════════════════════════════════════════════════════════════

import { Hono, type Context } from 'hono'
import { env as runtimeEnv } from 'hono/adapter'
import { getStore, type AuthUserPayload } from '@oimlsmart/platform-server/store'
import { effectiveRbacMap } from '@oimlsmart/platform-server/rbac'
import { effectiveRolesOf, mapRoles, roleHolders, type RolePermissionMap } from '@oimlsmart/platform-server/vocab'
import { isRegisteredParticipant, orgKindRoles, resolveRegistryOrg } from '../auth/org-registry'
import { sessionUser } from '@oimlsmart/platform-server/session'

/** The caller's grant over these routes: 'wide' (users.manage — the
 *  whole instance) or 'org' (org.users.manage — scoped to the account's
 *  org binding, never wider). */
interface UserScope {
  kind: 'wide' | 'org'
  orgId: string | null
  /** The permission the caller exercised (the audit trail's record). */
  permission: 'users.manage' | 'org.users.manage'
}

export function createUsersRouter(): Hono<{ Variables: { user: AuthUserPayload; scope: UserScope } }> {
  const app = new Hono<{ Variables: { user: AuthUserPayload; scope: UserScope } }>()

  app.use('*', async (c, next) => {
    const user = await sessionUser(c)
    if (!user) return c.json({ error: 'authentication required' }, 401)
    const map = effectiveRbacMap(runtimeEnv(c) as Record<string, string | undefined>)
    const held = new Set(effectiveRolesOf(user).flatMap(r => map[r] ?? []))

    // TODO.identity/10 — the participants register's org-admin state read
    // (the hub's participants page): the registry's operators
    // (executive_secretary — participants.review/manage) read it alongside
    // the user admins. The route itself answers only per-org admin counts
    // + names — never the account list.
    if (c.req.path.endsWith('/org-admin-state')) {
      if (held.has('users.manage') || held.has('org.users.manage') || held.has('participants.review') || held.has('participants.manage')) {
        c.set('user', user)
        c.set('scope', { kind: 'wide', orgId: user.orgId ?? null, permission: 'users.manage' })
        await next()
        return
      }
      return c.json({
        error: 'missing permission: participants.review',
        permission: 'participants.review',
        roles: [...new Set([...roleHolders('participants.review', map), ...roleHolders('users.manage', map)])].sort(),
      }, 403)
    }

    if (held.has('users.manage')) {
      c.set('user', user)
      c.set('scope', { kind: 'wide', orgId: user.orgId ?? null, permission: 'users.manage' })
      await next()
      return
    }
    if (held.has('org.users.manage')) {
      // The scoped grant requires the account's org binding — an
      // org-less org admin is a misconfiguration, never a wider slice.
      if (!user.orgId) {
        return c.json({
          error: 'org.users.manage requires the account to be bound to an organization (orgId) — the scheme operator binds the org admin to its registered org',
          permission: 'org.users.manage',
        }, 403)
      }
      c.set('user', user)
      c.set('scope', { kind: 'org', orgId: user.orgId, permission: 'org.users.manage' })
      await next()
      return
    }
    return c.json({
      error: 'missing permission: users.manage',
      permission: 'users.manage',
      roles: roleHolders('users.manage', map),
    }, 403)
  })

  /** The mutation audit (actor + permission used, server-side). */
  async function audit(c: Context, targetUserId: string, action: string, metadata: Record<string, unknown>): Promise<void> {
    const user = c.get('user') as AuthUserPayload
    const scope = c.get('scope') as UserScope
    const id = crypto.randomUUID()
    await getStore().putEntity('auditEvents', id, null, JSON.stringify({
      id,
      timestamp: new Date().toISOString(),
      standard_id: '',
      entity_type: 'users',
      entity_id: targetUserId,
      action,
      user_id: user.id,
      user_name: user.name,
      metadata: { permission: scope.permission, ...(scope.kind === 'org' ? { org_id: scope.orgId } : {}), ...metadata },
    }))
  }

  // GET /api/users — the instance's users (the settings page's list).
  // The org scope answers the caller's OWN org's slice, never wider.
  app.get('/', async (c) => {
    const scope = c.get('scope') as UserScope
    const all = await getStore().listUsers()
    return c.json(scope.kind === 'org' ? all.filter(u => u.orgId === scope.orgId) : all)
  })

  // GET /api/users/roles — the assignable role vocabulary (the instance
  // map's keys) with their permission sets — the assignment UI's
  // options, and item 10's claim-mapping reference. The org scope
  // answers ONLY the roles the caller's org kind bounds (an unknown /
  // unregistered org answers an empty map — honestly no options).
  app.get('/roles', async (c) => {
    const scope = c.get('scope') as UserScope
    const map = effectiveRbacMap(runtimeEnv(c) as Record<string, string | undefined>)
    if (scope.kind === 'wide') return c.json(map)
    const org = await resolveRegistryOrg(getStore(), scope.orgId!)
    if (!org) return c.json({} satisfies RolePermissionMap)
    const bounded: RolePermissionMap = {}
    for (const role of orgKindRoles(org.kind)) {
      if (map[role]) bounded[role] = map[role]!
    }
    return c.json(bounded)
  })

  // GET /api/users/org-admin-state — the participants register's
  // per-org administration state (TODO.identity/10): which REGISTERED
  // participant orgs have an organization administrator on THIS
  // instance's account store, and who. Read by the participants page
  // (its own gate above admits the registry's operators).
  app.get('/org-admin-state', async (c) => {
    const users = await getStore().listUsers()
    const state: Record<string, { admins: Array<{ id: string; name: string; email: string; active: boolean }> }> = {}
    for (const u of users) {
      if (!u.orgId || !u.roles.includes('org_admin')) continue
      const entry = (state[u.orgId] ??= { admins: [] })
      entry.admins.push({ id: u.id, name: u.name, email: u.email, active: u.active })
    }
    return c.json(state)
  })

  /** The org-scoped guards for a WRITE naming a role set: the roles
   *  must be bounded by the caller's org kind and never name org_admin.
   *  Answers the error response, or null when the write may proceed. */
  async function scopedRolesAllowed(c: Context, scope: UserScope, roles: string[]): Promise<Response | null> {
    if (roles.includes('org_admin')) {
      return c.json({
        error: 'the org_admin role is assigned by the scheme operator (BIML) only — one organization administrator per registered org (B 18:2025 §10.2)',
      }, 403)
    }
    const org = await resolveRegistryOrg(getStore(), scope.orgId!)
    if (!org) {
      return c.json({ error: `organization '${scope.orgId}' is not on the participants register — no assignable roles` }, 403)
    }
    const bounded = new Set(orgKindRoles(org.kind))
    const outside = roles.filter(r => !bounded.has(r))
    if (outside.length) {
      return c.json({
        error: `role(s) ${outside.map(r => `'${r}'`).join(', ')} are not assignable within a ${org.kind} — the org's kind bounds the set (assignable: ${[...bounded].join(', ')})`,
      }, 403)
    }
    return null
  }

  /** THE ELIGIBILITY RULE (the wide grant's org_admin assignment): the
   *  target's org must be a REGISTERED participant org. Answers the
   *  error response, or null when the assignment stands. */
  async function orgAdminAssignmentAllowed(c: Context, orgId: string | null): Promise<Response | null> {
    if (!orgId) {
      return c.json({ error: 'an org_admin account must be bound to its organization (orgId)' }, 400)
    }
    if (!(await isRegisteredParticipant(getStore(), orgId))) {
      return c.json({
        error: `organization '${orgId}' is not a registered participant — an organization administrator can be created only for a registered participant org (PD-03 / B 18:2025 §10.2)`,
      }, 400)
    }
    return null
  }

  // POST /api/users — create a LOCAL user (the demo provider; signs in
  // with the instance's local password). Roles are validated against the
  // instance's map; the org scope additionally bounds them by the org's
  // kind and pins the account to the caller's org.
  app.post('/', async (c) => {
    const scope = c.get('scope') as UserScope
    const body = await c.req.json().catch(() => null) as {
      email?: string; name?: string; role?: string; roles?: string[]; orgId?: string | null
    } | null
    if (!body || typeof body.email !== 'string' || !body.email.includes('@') || typeof body.name !== 'string' || !body.name) {
      return c.json({ error: 'email and name are required' }, 400)
    }
    const map = effectiveRbacMap(runtimeEnv(c) as Record<string, string | undefined>)
    const known = new Set(mapRoles(map))
    const role = body.role ?? ''
    if (!known.has(role)) {
      return c.json({ error: `unknown role: ${role}`, knownRoles: [...known].sort() }, 400)
    }
    const extras = (body.roles ?? []).filter(r => r !== role)
    for (const r of extras) {
      if (!known.has(r)) return c.json({ error: `unknown role: ${r}`, knownRoles: [...known].sort() }, 400)
    }

    let orgId = body.orgId ?? null
    if (scope.kind === 'org') {
      // The org scope pins the account to the caller's org — a body
      // naming another org is refused, never silently re-homed.
      if (orgId && orgId !== scope.orgId) {
        return c.json({ error: `the org-scoped grant creates users only in your own organization ('${scope.orgId}')` }, 403)
      }
      orgId = scope.orgId
      const refusal = await scopedRolesAllowed(c, scope, [role, ...extras])
      if (refusal) return refusal
    } else if (role === 'org_admin' || extras.includes('org_admin')) {
      // The eligibility rule: org admins exist only for registered orgs.
      const refusal = await orgAdminAssignmentAllowed(c, orgId)
      if (refusal) return refusal
    }

    const existing = (await getStore().listUsers()).find(u => u.email === body.email)
    if (existing) return c.json({ error: `a user with email ${body.email} already exists` }, 409)
    const created = await getStore().createLocalUser({
      email: body.email,
      name: body.name,
      role,
      roles: [role, ...extras],
      orgId,
    })
    await audit(c, created.id, 'user.create', { email: created.email, roles: created.roles, orgId })
    return c.json(created, 201)
  })

  // PUT /api/users/:id/roles — reassign: { role, roles? } — the primary
  // (section-gating) role plus the full permission set. A reassignment
  // takes effect on the target's NEXT request (the session join).
  app.put('/:id/roles', async (c) => {
    const scope = c.get('scope') as UserScope
    const targetId = c.req.param('id')
    const body = await c.req.json().catch(() => null) as { role?: string; roles?: string[] } | null
    if (!body || typeof body.role !== 'string' || !body.role) {
      return c.json({ error: 'role is required' }, 400)
    }
    const map = effectiveRbacMap(runtimeEnv(c) as Record<string, string | undefined>)
    const known = new Set(mapRoles(map))
    if (!known.has(body.role)) {
      return c.json({ error: `unknown role: ${body.role}`, knownRoles: [...known].sort() }, 400)
    }
    const extras = (body.roles ?? []).filter(r => r !== body.role)
    for (const r of extras) {
      if (!known.has(r)) return c.json({ error: `unknown role: ${r}`, knownRoles: [...known].sort() }, 400)
    }
    const nextRoles = [body.role, ...extras]

    const target = await getStore().getUserById(targetId)
    if (scope.kind === 'org') {
      // The org slice: another org's account is not found (no cross-org
      // read exists), and the org's ADMINISTRATOR account stays with
      // the scheme operator.
      if (!target || target.orgId !== scope.orgId) return c.json({ error: 'not found' }, 404)
      const targetRoles = target.roles?.length ? target.roles : [target.role]
      if (targetRoles.includes('org_admin')) {
        return c.json({ error: 'organization administrator accounts are managed by the scheme operator (BIML)' }, 403)
      }
      const refusal = await scopedRolesAllowed(c, scope, nextRoles)
      if (refusal) return refusal
    } else if (nextRoles.includes('org_admin')) {
      const refusal = await orgAdminAssignmentAllowed(c, target?.orgId ?? null)
      if (refusal) return refusal
    }

    const ok = await getStore().setUserRoles(targetId, body.role, nextRoles)
    if (!ok) return c.json({ error: 'not found' }, 404)
    await audit(c, targetId, 'user.roles', { role: body.role, roles: nextRoles })
    return c.json({ ok: true })
  })

  // PUT /api/users/:id/active — deactivate/reactivate: { active }. A
  // deactivated user's sessions stop resolving immediately and sign-in
  // refuses. You cannot deactivate your own account (the lockout guard).
  app.put('/:id/active', async (c) => {
    const user = c.get('user') as AuthUserPayload
    const scope = c.get('scope') as UserScope
    const targetId = c.req.param('id')
    const body = await c.req.json().catch(() => null) as { active?: boolean } | null
    if (!body || typeof body.active !== 'boolean') {
      return c.json({ error: 'active (boolean) is required' }, 400)
    }
    if (targetId === user.id && !body.active) {
      return c.json({ error: 'you cannot deactivate your own account' }, 400)
    }
    if (scope.kind === 'org') {
      const target = await getStore().getUserById(targetId)
      if (!target || target.orgId !== scope.orgId) return c.json({ error: 'not found' }, 404)
      const targetRoles = target.roles?.length ? target.roles : [target.role]
      if (targetRoles.includes('org_admin')) {
        return c.json({ error: 'organization administrator accounts are managed by the scheme operator (BIML)' }, 403)
      }
    }
    const ok = await getStore().setUserActive(targetId, body.active)
    if (!ok) return c.json({ error: 'not found' }, 404)
    await audit(c, targetId, body.active ? 'user.reactivated' : 'user.deactivated', {})
    return c.json({ ok: true })
  })

  return app
}
