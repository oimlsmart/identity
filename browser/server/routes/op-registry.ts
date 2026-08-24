// ═══════════════════════════════════════════════════════════════════
// The administrator's identity registry API (TODO.identity/07) — the
// read/write surface behind the OP's registry console: the account
// search and detail, the linked-identity administration (link on behalf
// with its documented justification), administrator session revocation,
// and the registry's activity feed.
//
// The surface (profile-gated like every OP route — a non-identity
// deployment answers 404; admin-gated like routes/op.ts's client
// registry — the platform admin and the scheme operator):
//
//   GET    /api/op/registry/users?q=&status=&role=   — the enriched
//                                                      account list
//                                                      (search over
//                                                      name/email/linked
//                                                      handle; status +
//                                                      role filters;
//                                                      sign-in methods +
//                                                      last sign-in per
//                                                      row)
//   GET    /api/op/registry/users/:id                — the detail
//                                                      aggregate:
//                                                      profile (avatar,
//                                                      email verification,
//                                                      lifecycle state),
//                                                      sign-in methods,
//                                                      links, sessions,
//                                                      the APP-ACCESS view
//                                                      (per-client, the
//                                                      claims rule's
//                                                      admin-side read),
//                                                      the org memberships
//                                                      (TODO.identity/11),
//                                                      the first page of
//                                                      the account's audit
//                                                      trail + its total
//   GET    /api/op/registry/users/:id/activity?offset=&limit=
//                                                    — the account's audit
//                                                      trail, paged (newest
//                                                      first, the total in
//                                                      every answer)
//   GET    /api/op/registry/orgs/:orgId              — the per-ORG view
//                                                      (TODO.identity/11):
//                                                      the org's members +
//                                                      per-org roles + its
//                                                      org_admins, and its
//                                                      join-request queue
//   POST   /api/op/registry/users/:id/links          — the admin's
//                                                      "link on behalf"
//                                                      (justification
//                                                      REQUIRED — it
//                                                      lands in the
//                                                      audit metadata)
//   DELETE /api/op/registry/users/:id/links/:provider
//                                                    — the admin unlink
//   POST   /api/op/registry/users/:id/sessions/:sid/revoke
//                                                    — the admin ends one
//                                                      of the account's
//                                                      sessions
//   POST   /api/op/registry/users/:id/sessions/revoke-all
//                                                    — the admin ends
//                                                      EVERY live session
//                                                      of the account (the
//                                                      light act, short of
//                                                      deactivation)
//   DELETE /api/op/registry/users/:id/factors/passkeys/:cred
//   DELETE /api/op/registry/users/:id/factors/totp/:tid
//                                                    — the admin revokes
//                                                      one of the account's
//                                                      factors (TODO.identity-
//                                                      sso/02+03's slot on the
//                                                      per-user page)
//   GET    /api/op/registry/activity?limit=&q=       — the registry's
//                                                      activity feed
//                                                      (the auditEvents
//                                                      journal, newest
//                                                      first)
//
// What is deliberately NOT here (the merged neighbors own it): the
// invite + enrollment links + the PER-CLIENT role assignments
// (routes/op-accounts.ts, TODO.identity/03 — the detail aggregate READS
// its rows), the role assignment + deactivation writes
// (routes/users.ts — the page calls them directly), the client registry
// (routes/op.ts), the provider registry (routes/op-upstream.ts).
//
// Every mutation lands an auditEvents row naming the administrator; the
// audit never blocks the path (a store hiccup is logged, never thrown).
//
// WORKER-SAFE: the store seam only, no node built-ins.
// ═══════════════════════════════════════════════════════════════════

import { Hono, type Context, type MiddlewareHandler } from 'hono'
import { getStore, type AuthUserPayload, type UserAdminRow } from '@oimlsmart/platform-server/store'
import { getInstanceProfile } from '@oimlsmart/platform-server/profile'
import { listRegistryOrganizations, resolveRegistryOrg } from '../auth/org-registry'
import { accountRoleSet, rolesForClient } from '../auth/op/claims'
import { sessionUser } from '@oimlsmart/platform-server/session'

/** The audit actions the registry's activity feed surfaces: the identity
 *  registry's own journal rows (accounts, roles, links, sessions,
 *  sign-ins, clients, providers, join requests). Other workflow stores
 *  write auditEvents too; the feed keeps the identity slice. */
const REGISTRY_ENTITY_TYPES = new Set(['account', 'users', 'auth', 'client', 'provider'])
const REGISTRY_ACTION_PREFIXES = ['org_invite.', 'org_join.']

/** The account trail's page size (the detail aggregate's embedded first
 *  page + the paged endpoint's default). */
const ACTIVITY_PAGE = 25

/** The audit journal's parsed row (the shape every writer above
 *  serializes into the entity's data). */
interface AuditEvent {
  id: string
  timestamp: string
  entity_type: string
  entity_id: string
  action: string
  user_id?: string
  user_name?: string
  metadata?: Record<string, unknown>
}

function parseAuditEvent(data: string): AuditEvent | null {
  try {
    const parsed = JSON.parse(data) as AuditEvent
    if (typeof parsed?.id !== 'string' || typeof parsed?.action !== 'string') return null
    return parsed
  } catch {
    return null
  }
}

function isRegistryEvent(event: AuditEvent): boolean {
  return REGISTRY_ENTITY_TYPES.has(event.entity_type)
    || REGISTRY_ACTION_PREFIXES.some(p => event.action.startsWith(p))
}

export function createOpRegistryRouter(): Hono {
  const registry = new Hono()

  // ── the profile gate (the same posture as routes/op.ts: the routes
  // exist in the ONE build, the identity module decides) ──────────────
  const profileGate: MiddlewareHandler = async (c, next) => {
    if (!getInstanceProfile().modules.includes('identity')) {
      return c.json({ error: 'not found' }, 404)
    }
    await next()
  }
  registry.use('/api/op/registry/*', profileGate)

  /** The admin gate (the same rule as routes/op.ts's registry surface:
   *  the platform admin and the scheme operator run the registry). */
  async function requireAdmin(c: Context): Promise<{ user: AuthUserPayload | null; error: Response | null }> {
    const user = await sessionUser(c)
    if (!user) return { user: null, error: c.json({ error: 'authentication required' }, 401) }
    if (user.role !== 'admin' && user.role !== 'cs_admin') {
      return { user: null, error: c.json({ error: 'administrator role required' }, 403) }
    }
    return { user, error: null }
  }

  /** The registry mutations' audit trail (entity_type 'account' for the
   *  account-targeted acts — the same journal op-accounts.ts writes). */
  async function audit(
    action: string,
    entityId: string,
    actor: { userId?: string; userName?: string },
    metadata: Record<string, unknown>,
  ): Promise<void> {
    try {
      const id = crypto.randomUUID()
      await getStore().putEntity('auditEvents', id, null, JSON.stringify({
        id,
        timestamp: new Date().toISOString(),
        standard_id: '',
        entity_type: 'account',
        entity_id: entityId,
        action,
        user_id: actor.userId,
        user_name: actor.userName,
        metadata,
      }))
    } catch (err) {
      console.error(`[op] registry audit event ${action} failed to persist:`, (err as Error).message)
    }
  }

  /** A list row's sign-in posture (never any credential material). */
  async function listRow(user: UserAdminRow) {
    const store = getStore()
    const [methods, links] = await Promise.all([
      store.countSignInMethods(user.id),
      store.listIdentityLinks(user.id),
    ])
    return {
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
      roles: user.roles,
      orgId: user.orgId,
      active: user.active,
      provider: user.provider,
      lastLogin: user.lastLogin,
      passwordSet: methods.password,
      links: links.map(l => ({ provider: l.provider, providerAccountId: l.providerAccountId })),
    }
  }

  /** The account's own audit slice (the detail page's trail): the
   *  registry events naming this account, newest first. Shared by the
   *  detail aggregate (its first page + total) and the paged endpoint. */
  async function accountTrail(store: ReturnType<typeof getStore>, userId: string): Promise<AuditEvent[]> {
    return (await store.listEntities('auditEvents'))
      .map(row => parseAuditEvent(row.data))
      .filter((e): e is AuditEvent => !!e && e.entity_id === userId && isRegistryEvent(e))
      .sort((a, b) => b.timestamp.localeCompare(a.timestamp))
  }

  /** The account's lifecycle state, derived honestly from the row + the
   *  sign-in posture: 'erased' (the anonymized tombstone — provider
   *  'erased'), 'deactivated' (active flipped off, the history kept),
   *  'invited' (created, never set a password, never signed in — the
   *  setup link's window), else 'active'. */
  function lifecycleState(user: UserAdminRow, passwordSet: boolean): 'invited' | 'active' | 'deactivated' | 'erased' {
    if (user.provider === 'erased') return 'erased'
    if (!user.active) return 'deactivated'
    if (!passwordSet && !user.lastLogin) return 'invited'
    return 'active'
  }

  /** THE APP-ACCESS VIEW (the admin-side half of the launcher's
   *  visibility rule): for every registered relying party, CAN the
   *  account enter WITH ROLES, and WHY NOT when not. The computation is
   *  the ONE rule the token endpoint itself runs (auth/op/claims.ts's
   *  rolesForClient) — never a copy: the per-client assignment (null =
   *  the account-wide default, [] = the explicit none) through the
   *  client's claims policy (the claim gate + the optional role
   *  allowlist). `reason` is a stable code the page renders in words. */
  async function appAccessFor(store: ReturnType<typeof getStore>, user: UserAdminRow) {
    const accountRoles = accountRoleSet(user)
    const clients = (await store.listOidcClients()).sort((a, b) => a.name.localeCompare(b.name))
    const rows = []
    for (const client of clients) {
      const assigned = await store.getOpClientRoles(user.id, client.clientId)
      const held = assigned ?? accountRoles
      const carriesRoleClaims = !!client.claimsPolicy
        && (client.claimsPolicy.claims.includes('roles') || client.claimsPolicy.claims.includes('groups'))
      const allowlist = client.claimsPolicy?.roles ?? null
      const roles = rolesForClient(assigned, accountRoles, client.claimsPolicy)
      let reason: 'ok' | 'client_disabled' | 'no_role_claims' | 'explicit_none' | 'outside_allowlist' = 'ok'
      if (client.status !== 'active') reason = 'client_disabled'
      else if (!carriesRoleClaims) reason = 'no_role_claims'
      else if (assigned !== null && assigned.length === 0) reason = 'explicit_none'
      else if (roles.length === 0) reason = 'outside_allowlist'
      rows.push({
        clientId: client.clientId,
        name: client.name,
        status: client.status,
        carriesRoleClaims,
        /** The roles the account holds on this client PRE-allowlist (the
         *  assignment, or the account-wide set when no row exists). */
        held,
        /** The policy's role allowlist (null = unbounded). */
        allowlist,
        /** The roles the client's ID tokens actually carry (post-rule). */
        roles,
        canEnter: reason === 'ok',
        reason,
      })
    }
    return rows
  }

  // GET /api/op/registry/users — the enriched account list. The search
  // matches name, email, or a linked provider account id (the handle);
  // the filters keep the rows the question is about.
  registry.get('/api/op/registry/users', async (c) => {
    const gate = await requireAdmin(c)
    if (gate.error) return gate.error
    const q = (c.req.query('q') ?? '').trim().toLowerCase()
    const status = c.req.query('status') ?? ''
    const role = c.req.query('role') ?? ''

    const users = await getStore().listUsers()
    const rows = []
    for (const user of users) {
      if (status === 'active' && !user.active) continue
      if (status === 'deactivated' && user.active) continue
      if (role) {
        const roles = user.roles?.length ? user.roles : [user.role]
        if (!roles.includes(role)) continue
      }
      const row = await listRow(user)
      if (q) {
        const hay = [user.name, user.email, ...row.links.map(l => l.providerAccountId)]
        if (!hay.some(s => s.toLowerCase().includes(q))) continue
      }
      rows.push(row)
    }
    rows.sort((a, b) => a.name.localeCompare(b.name))
    return c.json(rows)
  })

  // GET /api/op/registry/users/:id — the detail aggregate the account
  // page renders: the profile WITH its lifecycle state (the avatar, the
  // email's verification state, the on-the-record + last-sign-in stamps),
  // the sign-in methods, the linked identities, the live sessions, the
  // APP-ACCESS view (per-client, the claims rule's admin-side read), and
  // the first page of the account's own audit trail with its honest total
  // (the paged endpoint below serves the rest).
  registry.get('/api/op/registry/users/:id', async (c) => {
    const gate = await requireAdmin(c)
    if (gate.error) return gate.error
    const store = getStore()
    // The admin row (not getUserById): the detail carries active +
    // lastLogin, which the session payload does not.
    const user = (await store.listUsers()).find(u => u.id === c.req.param('id'))
    if (!user) return c.json({ error: 'not found' }, 404)
    const [methods, links, sessions, org, clientRoles, memberships, registryOrgs, profile, trail, appAccess, passkeys, totp, recovery] = await Promise.all([
      store.countSignInMethods(user.id),
      store.listIdentityLinks(user.id),
      store.listUserSessions(user.id),
      user.orgId ? resolveRegistryOrg(store, user.orgId) : Promise.resolve(null),
      store.listOpClientRoles(user.id),
      // TODO.identity/11: the account's memberships + the register's
      // display names for them.
      store.listOrgMemberships(user.id),
      listRegistryOrganizations(store),
      // The session payload's half: the avatar + the provider (the row
      // projection the admin row does not carry).
      store.getUserById(user.id),
      accountTrail(store, user.id),
      appAccessFor(store, user),
      store.listWebauthnCredentials(user.id),
      store.listTotpSecrets(user.id),
      store.recoveryCodeState(user.id),
    ])
    const orgsById = new Map(registryOrgs.map(o => [o.id, o]))
    const factors = {
      passkeys: passkeys.map(p => ({ credentialId: p.credentialId, name: p.name, createdAt: p.createdAt, lastUsedAt: p.lastUsedAt })),
      totp: totp.filter(t => t.verifiedAt !== null).map(t => ({ id: t.id, name: t.name, createdAt: t.createdAt, lastUsedAt: t.lastUsedAt })),
      recoveryCodes: recovery,
    }
    return c.json({
      account: {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role,
        roles: user.roles?.length ? user.roles : [user.role],
        orgId: user.orgId,
        orgName: org?.name ?? null,
        active: user.active,
        provider: user.provider,
        avatarUrl: profile?.avatarUrl ?? null,
        emailVerifiedAt: user.emailVerifiedAt ?? null,
        lastLogin: user.lastLogin,
        // The record's own stamps: the FIRST event the journal holds for
        // the account (the invite row for an invited account; null when
        // nothing is on the record — an account seeded by declaration),
        // and the erasure's stamp for a tombstone.
        firstSeenAt: trail.at(-1)?.timestamp ?? null,
        erasedAt: trail.find(e => e.action === 'account.deleted')?.timestamp ?? null,
        state: lifecycleState(user, methods.password),
      },
      passwordSet: methods.password,
      links,
      sessions,
      // The factor registry's admin read (TODO.identity-sso/02+03 — the
      // per-user page's factors slot): names + created/last-used, never
      // any credential material; the recovery set's honest counts.
      factors,

      // The per-client role assignments (TODO.identity/03's rows; the
      // grant/revoke acts ride routes/op-accounts.ts). updatedAt is null
      // until the first re-grant — the row's createdAt is the honest
      // "granted" stamp then.
      clientRoles: clientRoles.map(a => ({ clientId: a.clientId, roles: a.roles, assignedBy: a.assignedBy, updatedAt: a.updatedAt ?? a.createdAt })),
      appAccess,
      // TODO.identity/11 — the account's org memberships (every state,
      // the register's display names resolved): the per-user page's
      // Memberships section.
      memberships: memberships.map(m => ({
        orgId: m.orgId,
        orgName: orgsById.get(m.orgId)?.name ?? m.orgId,
        roles: m.roles,
        state: m.state,
        isPrimary: m.isPrimary,
        invitedBy: m.invitedBy,
        createdAt: m.createdAt,
        activatedAt: m.activatedAt,
        disabledAt: m.disabledAt,
        disabledBy: m.disabledBy,
      })),
      activity: trail.slice(0, ACTIVITY_PAGE),
      activityTotal: trail.length,
    })
  })

  // GET /api/op/registry/users/:id/activity — the account's audit trail,
  // paged honestly: `offset` + `limit` (default 0/25, at most 100), the
  // newest first, the TOTAL in every answer so the pager never lies.
  registry.get('/api/op/registry/users/:id/activity', async (c) => {
    const gate = await requireAdmin(c)
    if (gate.error) return gate.error
    const store = getStore()
    const user = (await store.listUsers()).find(u => u.id === c.req.param('id'))
    if (!user) return c.json({ error: 'not found' }, 404)
    const offsetRaw = Number(c.req.query('offset') ?? '0')
    const limitRaw = Number(c.req.query('limit') ?? String(ACTIVITY_PAGE))
    const offset = Number.isFinite(offsetRaw) ? Math.max(Math.trunc(offsetRaw), 0) : 0
    const limit = Number.isFinite(limitRaw) ? Math.min(Math.max(Math.trunc(limitRaw), 1), 100) : ACTIVITY_PAGE
    const trail = await accountTrail(store, user.id)
    return c.json({ events: trail.slice(offset, offset + limit), total: trail.length, offset, limit })
  })

  // POST /api/op/registry/users/:id/links — the admin's "link on behalf":
  // bind an upstream provider account to this account WITHOUT the holder
  // driving the flow. The justification note is REQUIRED (the act bypasses
  // the holder's consent, so the reason is on the record); the match rule
  // is unchanged — (provider, provider_account_id), never an email.
  registry.post('/api/op/registry/users/:id/links', async (c) => {
    const gate = await requireAdmin(c)
    if (gate.error || !gate.user) return gate.error!
    const store = getStore()
    const user = await store.getUserById(c.req.param('id'))
    if (!user) return c.json({ error: 'not found' }, 404)
    const body = await c.req.json<{ provider?: string; provider_account_id?: string; justification?: string }>().catch(() => null)
    if (!body || typeof body.provider !== 'string' || !body.provider.trim()
      || typeof body.provider_account_id !== 'string' || !body.provider_account_id.trim()) {
      return c.json({ error: 'provider and provider_account_id are required' }, 400)
    }
    const justification = typeof body.justification === 'string' ? body.justification.trim() : ''
    if (!justification) {
      return c.json({ error: 'a justification note is required — the link bypasses the account holder’s own flow, so the reason goes on the record' }, 400)
    }
    const provider = await store.getIdentityProvider(body.provider.trim())
    if (!provider) {
      return c.json({ error: `unknown provider '${body.provider.trim()}' — the provider registry (Sign-in providers) carries the known ones` }, 400)
    }
    const link = await store.createIdentityLink({
      userId: user.id,
      provider: provider.id,
      providerAccountId: body.provider_account_id.trim(),
      linkedBy: gate.user!.email,
    })
    if (!link) {
      return c.json({ error: `the ${provider.id} account ${body.provider_account_id.trim()} is already linked — unlink it there first` }, 409)
    }
    await audit('account.link_on_behalf', user.id, { userId: gate.user!.id, userName: gate.user!.name }, {
      email: user.email,
      provider: provider.id,
      provider_account_id: link.providerAccountId,
      justification,
    })
    return c.json(link, 201)
  })

  // DELETE /api/op/registry/users/:id/links/:provider — the admin unlink
  // (a lost upstream account, a mistyped link on behalf). The reason is
  // optional; the act itself is always on the record.
  registry.delete('/api/op/registry/users/:id/links/:provider', async (c) => {
    const gate = await requireAdmin(c)
    if (gate.error || !gate.user) return gate.error!
    const store = getStore()
    const user = await store.getUserById(c.req.param('id'))
    if (!user) return c.json({ error: 'not found' }, 404)
    const provider = c.req.param('provider')
    const body = await c.req.json<{ reason?: string }>().catch(() => null)
    const removed = await store.deleteIdentityLink(user.id, provider)
    if (!removed) return c.json({ error: 'no such link' }, 404)
    await audit('account.link_removed', user.id, { userId: gate.user!.id, userName: gate.user!.name }, {
      email: user.email,
      provider,
      reason: typeof body?.reason === 'string' && body.reason.trim() ? body.reason.trim() : null,
    })
    return c.json({ ok: true })
  })

  // POST /api/op/registry/users/:id/sessions/:sid/revoke — the admin ends
  // one of the account's sessions (the store scopes the delete to the
  // account, so another account's session id is a no-op).
  registry.post('/api/op/registry/users/:id/sessions/:sid/revoke', async (c) => {
    const gate = await requireAdmin(c)
    if (gate.error || !gate.user) return gate.error!
    const store = getStore()
    const user = await store.getUserById(c.req.param('id'))
    if (!user) return c.json({ error: 'not found' }, 404)
    const revoked = await store.deleteSessionById(user.id, c.req.param('sid'))
    if (!revoked) return c.json({ error: 'no such session' }, 404)
    await audit('account.session_revoked', user.id, { userId: gate.user!.id, userName: gate.user!.name }, {
      email: user.email,
      session: c.req.param('sid'),
      by: 'administrator',
    })
    return c.json({ ok: true })
  })

  // POST /api/op/registry/users/:id/sessions/revoke-all — the admin ends
  // EVERY live session of the account at once (the light act, short of
  // deactivation: the account itself is untouched and signs in again the
  // next time; issued OIDC access tokens expire on their own short clock).
  // The count rides the audit event. On your OWN account this is the
  // sign-out-everywhere the account console already offers — allowed, and
  // it ends this console's session too (the page re-authenticates).
  registry.post('/api/op/registry/users/:id/sessions/revoke-all', async (c) => {
    const gate = await requireAdmin(c)
    if (gate.error || !gate.user) return gate.error!
    const store = getStore()
    const user = await store.getUserById(c.req.param('id'))
    if (!user) return c.json({ error: 'not found' }, 404)
    const sessions = await store.listUserSessions(user.id)
    let count = 0
    for (const session of sessions) {
      if (await store.deleteSessionById(user.id, session.id)) count += 1
    }
    await audit('account.sessions_revoked', user.id, { userId: gate.user!.id, userName: gate.user!.name }, {
      email: user.email,
      count,
      by: 'administrator',
    })
    return c.json({ ok: true, revoked: count })
  })

  // GET /api/op/registry/orgs/:orgId — the per-ORG view (TODO.identity/11,
  // the multi-org model): the register's org, its MEMBERSHIPS (the members
  // with their per-org role sets + lifecycle states — the org_admins among
  // them marked by the role), and its join-request queue (every state,
  // newest first). The mutations live in routes/op-memberships.ts (the
  // grant-checked surface); this aggregate is the registry's read.
  registry.get('/api/op/registry/orgs/:orgId', async (c) => {
    const gate = await requireAdmin(c)
    if (gate.error) return gate.error
    const store = getStore()
    const orgId = c.req.param('orgId')
    const org = await resolveRegistryOrg(store, orgId)
    if (!org) {
      return c.json({ error: `organization '${orgId}' is not on the participants register` }, 404)
    }
    const [memberships, users, requests] = await Promise.all([
      store.listOrgMembers(orgId),
      store.listUsers(),
      store.listOrgJoinRequests({ scope: 'org', orgId }),
    ])
    const byId = new Map(users.map(u => [u.id, u]))
    return c.json({
      org: { id: org.id, name: org.name, shortName: org.shortName, kind: org.kind, country: org.country, registered: org.registered, roles: org.roles },
      members: memberships.map(m => {
        const account = byId.get(m.userId) ?? null
        return {
          userId: m.userId,
          name: account?.name ?? '(erased account)',
          email: account?.email ?? null,
          provider: account?.provider ?? null,
          accountActive: account?.active ?? false,
          orgId: m.orgId,
          roles: m.roles,
          state: m.state,
          isPrimary: m.isPrimary,
          invitedBy: m.invitedBy,
          createdAt: m.createdAt,
          activatedAt: m.activatedAt,
          disabledAt: m.disabledAt,
          disabledBy: m.disabledBy,
        }
      }),
      requests: [...requests].sort((a, b) => b.createdAt.localeCompare(a.createdAt)),
    })
  // DELETE /api/op/registry/users/:id/factors/passkeys/:cred — the admin
  // revokes one of the account's passkeys (TODO.identity-sso/02's slot on
  // the per-user page). The account's own console's last-method guard
  // deliberately does NOT bind the admin (the administrator's duty is the
  // recovery path: the email reset stands behind a stranding). The audit
  // event lands on the account's chain either way.
  registry.delete('/api/op/registry/users/:id/factors/passkeys/:cred', async (c) => {
    const gate = await requireAdmin(c)
    if (gate.error || !gate.user) return gate.error!
    const store = getStore()
    const user = await store.getUserById(c.req.param('id'))
    if (!user) return c.json({ error: 'not found' }, 404)
    const cred = await store.getWebauthnCredential(c.req.param('cred'))
    if (!cred || cred.userId !== user.id) return c.json({ error: 'no such passkey' }, 404)
    await store.deleteWebauthnCredential(user.id, cred.credentialId)
    await audit('factor.passkey_revoked', user.id, { userId: gate.user!.id, userName: gate.user!.name }, {
      email: user.email,
      name: cred.name,
      credentialId: cred.credentialId,
      by: 'administrator',
    })
    return c.json({ ok: true })
  })

  // DELETE /api/op/registry/users/:id/factors/totp/:tid — the admin
  // revokes one of the account's authenticator apps (the same slot).
  registry.delete('/api/op/registry/users/:id/factors/totp/:tid', async (c) => {
    const gate = await requireAdmin(c)
    if (gate.error || !gate.user) return gate.error!
    const store = getStore()
    const user = await store.getUserById(c.req.param('id'))
    if (!user) return c.json({ error: 'not found' }, 404)
    const row = await store.getTotpSecret(c.req.param('tid'))
    if (!row || row.userId !== user.id) return c.json({ error: 'no such authenticator' }, 404)
    await store.deleteTotpSecret(user.id, row.id)
    await audit('factor.totp_revoked', user.id, { userId: gate.user!.id, userName: gate.user!.name }, {
      email: user.email,
      name: row.name,
      by: 'administrator',
    })
    return c.json({ ok: true })
  })

  // GET /api/op/registry/activity — the registry's activity feed: the
  // auditEvents journal's identity slice, newest first. `limit` caps the
  // answer (default 100, at most 500); `q` filters on the action, the
  // actor, the target, and the metadata's email.
  registry.get('/api/op/registry/activity', async (c) => {
    const gate = await requireAdmin(c)
    if (gate.error) return gate.error
    const limitRaw = Number(c.req.query('limit') ?? '100')
    const limit = Number.isFinite(limitRaw) ? Math.min(Math.max(Math.trunc(limitRaw), 1), 500) : 100
    const q = (c.req.query('q') ?? '').trim().toLowerCase()
    const events = (await getStore().listEntities('auditEvents'))
      .map(row => parseAuditEvent(row.data))
      .filter((e): e is AuditEvent => !!e && isRegistryEvent(e))
      .sort((a, b) => b.timestamp.localeCompare(a.timestamp))
    const filtered = q
      ? events.filter(e => [e.action, e.user_name ?? '', e.entity_id, String(e.metadata?.email ?? '')]
        .some(s => s.toLowerCase().includes(q)))
      : events
    return c.json(filtered.slice(0, limit))
  })

  return registry
}
