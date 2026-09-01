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
//   GET    /api/op/registry/orgs               — the ORGANIZATIONS list
//                                                (TODO.identity-features/05):
//                                                every registry org with its
//                                                member count, its org_admins,
//                                                and its lifecycle state
//   POST   /api/op/registry/orgs               — the add act (the stable slug
//                                                id — the participant org's
//                                                OIML code — the display data,
//                                                the contacts, the optional
//                                                participant_ref)
//   GET    /api/op/registry/orgs/:orgId        — the per-ORG view
//                                                (TODO.identity/11):
//                                                the org's members +
//                                                per-org roles + its
//                                                org_admins, its
//                                                join-request queue, and
//                                                (05) the org's own audit
//                                                slice
//   PUT    /api/op/registry/orgs/:orgId        — the edit act (the display
//                                                data; the id never moves)
//   POST   /api/op/registry/orgs/:orgId/state  — the lifecycle act: disable
//                                                (the honest removal — the
//                                                org's ACTIVE memberships
//                                                disable with it, the
//                                                per-org roles stop carrying;
//                                                the invited invitations wait,
//                                                blocked) / re-enable (the
//                                                memberships stay disabled —
//                                                re-activation is the
//                                                per-membership deliberate
//                                                act)
//   DELETE /api/op/registry/orgs/:orgId        — the erasure-adjacent hard
//                                                delete: only when the org
//                                                never held a membership and
//                                                no join request references
//                                                it (the honest 409 points at
//                                                disable otherwise)
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
import { getStore, type AuthUserPayload, type OpClientRoleAssignment, type OrgRegistryContact, type UserAdminRow } from '@oimlsmart/platform-server/store'
import { getInstanceProfile } from '@oimlsmart/platform-server/profile'
import { isRegistryOrgKind, listOrgEndorsements, listRegistryOrganizations, resolveRegistryOrg, validateOrgLinks, type RegistryOrg, type RegistryOrgKind } from '../auth/org-registry'
import { listOrgSigningKeys } from '../auth/org-signing-keys'
import { accountRoleSet, rolesForClient } from '../auth/op/claims'
import { orgAuditSlice } from '../auth/op/org-audit'
import { patListRow } from '../auth/op/tokens'
import { sessionUser } from '@oimlsmart/platform-server/session'

/** The audit actions the registry's activity feed surfaces: the identity
 *  registry's own journal rows (accounts, roles, links, sessions,
 *  sign-ins, clients, providers, join requests, and (TODO.identity-
 *  features/05) the organization lifecycle). Other workflow stores
 *  write auditEvents too; the feed keeps the identity slice. */
const REGISTRY_ENTITY_TYPES = new Set(['account', 'users', 'auth', 'client', 'provider', 'organization'])
// The join-request acts are spelled org_join_request.* (routes/op-join.ts)
// — the bare 'org_join.' prefix never matched a real action, so the global
// feed never surfaced the join decisions (the per-org slice did, via
// entity_type). The prefix names the WRITER's spelling, never a guess.
const REGISTRY_ACTION_PREFIXES = ['org_invite.', 'org_join_request.']

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
  // The status probe's rows never surface in the feeds (the activity
  // feed here, the account detail's trail): the honest cadence is not
  // registry news. The raw chain retains them — the dashboard's
  // queryable audit log (routes/op-dashboard.ts) carries them.
  if (event.action === 'account.sign_in_probe') return false
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
   *  account-targeted acts, 'organization' for the org lifecycle — the
   *  same journal op-accounts.ts writes). */
  async function audit(
    action: string,
    entityId: string,
    actor: { userId?: string; userName?: string },
    metadata: Record<string, unknown>,
    entityType: 'account' | 'organization' = 'account',
  ): Promise<void> {
    try {
      const id = crypto.randomUUID()
      await getStore().putEntity('auditEvents', id, null, JSON.stringify({
        id,
        timestamp: new Date().toISOString(),
        standard_id: '',
        entity_type: entityType,
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
  async function appAccessFor(store: ReturnType<typeof getStore>, user: UserAdminRow, assignments: OpClientRoleAssignment[]) {
    const accountRoles = accountRoleSet(user)
    const clients = (await store.listOidcClients()).sort((a, b) => a.name.localeCompare(b.name))
    // The account's per-client assignments arrive loaded (the caller's
    // ONE listOpClientRoles read — the aggregate carries them too) and
    // group by client; a per-client getOpClientRoles loop is one store
    // round-trip per registered client. A client without a row answers
    // null exactly like getOpClientRoles (the UNIQUE(user, client) key
    // makes the Map's last write a non-question).
    const assignedByClient = new Map(assignments.map(a => [a.clientId, a.roles]))
    const rows = []
    for (const client of clients) {
      const assigned = assignedByClient.get(client.clientId) ?? null
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
    // The per-row reads (the sign-in posture + the linked handles) run
    // CONCURRENTLY across the candidates — the seam carries no bulk
    // variant for them, so the wall time is the slowest row's, never
    // the sum of all rows'. The map preserves the list's order; the
    // sort below is stable, so the answer is byte-identical to the
    // sequential loop's.
    const built = await Promise.all(users.map(async (user) => {
      if (status === 'active' && !user.active) return null
      if (status === 'deactivated' && user.active) return null
      if (role) {
        const roles = user.roles?.length ? user.roles : [user.role]
        if (!roles.includes(role)) return null
      }
      const row = await listRow(user)
      if (q) {
        const hay = [user.name, user.email, ...row.links.map(l => l.providerAccountId)]
        if (!hay.some(s => s.toLowerCase().includes(q))) return null
      }
      return row
    }))
    const rows = built.filter((row): row is NonNullable<typeof row> => row !== null)
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
    // The per-client role assignments load ONCE — the response's
    // clientRoles field AND the app-access computation both read this
    // set (appAccessFor groups it by client, never a per-client loop).
    const clientRoles = await store.listOpClientRoles(user.id)
    const [methods, links, sessions, org, memberships, registryOrgs, profile, trail, appAccess, passkeys, totp, recovery] = await Promise.all([
      store.countSignInMethods(user.id),
      store.listIdentityLinks(user.id),
      store.listUserSessions(user.id),
      user.orgId ? resolveRegistryOrg(store, user.orgId) : Promise.resolve(null),
      // TODO.identity/11: the account's memberships + the register's
      // display names for them.
      store.listOrgMemberships(user.id),
      listRegistryOrganizations(store),
      // The session payload's half: the avatar + the provider (the row
      // projection the admin row does not carry).
      store.getUserById(user.id),
      accountTrail(store, user.id),
      appAccessFor(store, user, clientRoles),
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

  // ── the organization registry's lifecycle (TODO.identity-features/05 ─
  //    organizations as first-class citizens) ───────────────────────────
  // The identity administrator (admin/cs_admin — requireAdmin) adds,
  // edits, disables and (guarded) removes the registry's orgs. The org
  // admin NEVER reaches these routes: requireAdmin's 403 is the only
  // answer, never a scoped slice — the org admin's own-organization
  // management rides routes/op-memberships.ts's scoped grant.

  /** The stable slug's shape: the id lands in URLs and the OIDC org
   *  claim, and the participant org's OIML code rides it (EX1, 21). */
  const ORG_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/

  interface OrgPayloadFields {
    name?: string
    shortName?: string | null
    kind?: string | null
    country?: string | null
    contacts?: OrgRegistryContact[]
    participantRef?: string | null
    designatedBy?: string | null
    proposedBy?: string | null
    csStatus?: string | null
  }

  /** The add/edit payloads' shared validation: answers the validated
   *  fields (only the ones PRESENT — the edit's patch semantics), or
   *  the error response. `requireAll` is the add act's posture (id +
   *  name mandatory). */
  function orgPayload(
    c: Context,
    body: Record<string, unknown> | null,
    requireAll: boolean,
  ): { fields: OrgPayloadFields & { id?: string } } | { error: Response } {
    if (!body || typeof body !== 'object') {
      return { error: c.json({ error: 'a JSON body is required' }, 400) }
    }
    const fields: OrgPayloadFields & { id?: string } = {}
    if (body.id !== undefined) {
      const id = typeof body.id === 'string' ? body.id.trim() : ''
      if (!ORG_ID_PATTERN.test(id)) {
        return { error: c.json({ error: 'the organization id is the stable slug: letters, digits, dot/dash/underscore, starting with a letter or digit (the participant org’s OIML code rides it — EX1, 21)' }, 400) }
      }
      fields.id = id
    } else if (requireAll) {
      return { error: c.json({ error: 'id is required — the stable slug (for a participant org, its OIML code)' }, 400) }
    }
    if (body.name !== undefined) {
      const name = typeof body.name === 'string' ? body.name.trim() : ''
      if (!name) return { error: c.json({ error: 'the display name must not be empty' }, 400) }
      fields.name = name
    } else if (requireAll) {
      return { error: c.json({ error: 'name is required — the organization’s display name' }, 400) }
    }
    for (const [key, target] of [['short_name', 'shortName'], ['country', 'country'], ['participant_ref', 'participantRef'], ['designated_by', 'designatedBy'], ['proposed_by', 'proposedBy'], ['cs_status', 'csStatus']] as const) {
      if (body[key] === undefined) continue
      if (body[key] !== null && typeof body[key] !== 'string') {
        return { error: c.json({ error: `${key} must be a string (or null to clear)` }, 400) }
      }
      const value = typeof body[key] === 'string' ? (body[key] as string).trim() : ''
      fields[target] = value || null
    }
    if (body.kind !== undefined) {
      if (body.kind !== null && !isRegistryOrgKind(body.kind)) {
        return { error: c.json({ error: `kind must be one of member-state, corresponding-member, issuing-authority, test-laboratory, utilizer, associate, manufacturer (or null for a non-participant organization)` }, 400) }
      }
      fields.kind = body.kind === null ? null : (body.kind as string)
    }
    if (body.contacts !== undefined) {
      if (!Array.isArray(body.contacts)) {
        return { error: c.json({ error: 'contacts must be a list of { name?, email }' }, 400) }
      }
      const contacts: OrgRegistryContact[] = []
      for (const [i, entry] of body.contacts.entries()) {
        const rec = (entry && typeof entry === 'object' ? entry : {}) as Record<string, unknown>
        const email = typeof rec.email === 'string' ? rec.email.trim() : ''
        if (!email.includes('@')) {
          return { error: c.json({ error: `contacts[${i}] needs an email (the contact’s work address)` }, 400) }
        }
        contacts.push({ name: typeof rec.name === 'string' && rec.name.trim() ? rec.name.trim() : null, email })
      }
      fields.contacts = contacts
    }
    return { fields }
  }

  // GET /api/op/registry/orgs — the Organizations list: every registry
  // org (every state, name-ordered) with its ACTIVE member count, its
  // organization administrators (the active org_admin memberships), the
  // lifecycle state, the per-kind STANDING (TODO.register/01: a
  // manufacturer row says what it is — declared / ia-endorsed — never
  // the participant posture), and the designation chain's facets
  // (TODO.identity-features/10: the row's own links + the reverse
  // counts — proposed IAs, designated bodies, associated TLs).
  registry.get('/api/op/registry/orgs', async (c) => {
    const gate = await requireAdmin(c)
    if (gate.error) return gate.error
    const store = getStore()
    // The memberships load ONCE and group in memory — a per-org
    // listOrgMembers loop is one store round-trip per organization
    // (217 sequential reads against the production registry import:
    // the orgs page's measured 2–11s). The chain counts already
    // compute in memory below.
    const [orgs, users, allMemberships] = await Promise.all([
      listRegistryOrganizations(store), store.listUsers(), store.listAllOrgMemberships(),
    ])
    const byId = new Map(users.map(u => [u.id, u]))
    const membershipsByOrg = new Map<string, typeof allMemberships>()
    for (const m of allMemberships) membershipsByOrg.set(m.orgId, [...(membershipsByOrg.get(m.orgId) ?? []), m])
    const rows = []
    for (const org of orgs) {
      const memberships = membershipsByOrg.get(org.id) ?? []
      const active = memberships.filter(m => m.state === 'active')
      rows.push({
        id: org.id,
        name: org.name,
        shortName: org.shortName,
        kind: org.kind,
        country: org.country,
        participantRef: org.participantRef,
        designatedBy: org.designatedBy,
        proposedBy: org.proposedBy,
        csStatus: org.csStatus,
        state: org.state,
        standing: org.standing,
        endorsedBy: org.endorsedBy,
        // The designation chain's reverse (TODO.identity-features/10):
        // the orgs THIS org proposes/designates/associates, counted by
        // link class — the list renders "proposes 1 · designates 2"
        // honestly without resolving names (the per-org page resolves).
        chain: {
          proposedIas: orgs.filter(o => o.proposedBy === org.id).length,
          designatedBodies: orgs.filter(o => o.designatedBy === org.id && (o.kind === 'utilizer' || o.kind === 'associate')).length,
          associatedTls: orgs.filter(o => o.designatedBy === org.id && o.kind === 'test-laboratory').length,
        },
        members: {
          active: active.length,
          invited: memberships.filter(m => m.state === 'invited').length,
          disabled: memberships.filter(m => m.state === 'disabled').length,
        },
        admins: active.filter(m => m.roles.includes('org_admin')).map(m => ({
          userId: m.userId,
          name: byId.get(m.userId)?.name ?? '(erased account)',
          email: byId.get(m.userId)?.email ?? null,
        })),
        createdAt: org.createdAt,
        updatedAt: org.updatedAt,
        disabledAt: org.disabledAt,
        disabledBy: org.disabledBy,
      })
    }
    return c.json(rows)
  })

  // POST /api/op/registry/orgs — the add act: { id, name, short_name?,
  // kind?, country?, contacts?, participant_ref?, designated_by?,
  // proposed_by?, cs_status? }. The id is forever (the stable slug —
  // never editable later); the id conflict is the honest 409. The
  // designation links + the CS status facet validate against the KIND
  // (TODO.identity-features/10 — a utilizer's designator is a member
  // state, an associate's a corresponding member, a TL's its IA, an
  // IA's proposer a member state; everything else refuses).
  registry.post('/api/op/registry/orgs', async (c) => {
    const gate = await requireAdmin(c)
    if (gate.error || !gate.user) return gate.error!
    const body = await c.req.json<Record<string, unknown>>().catch(() => null)
    const parsed = orgPayload(c, body, true)
    if ('error' in parsed) return parsed.error
    const { id, name, ...rest } = parsed.fields
    const store = getStore()
    const linkError = await validateOrgLinks(store, {
      kind: (rest.kind ?? null) as RegistryOrgKind | null,
      designatedBy: rest.designatedBy,
      proposedBy: rest.proposedBy,
      csStatus: rest.csStatus,
    })
    if (linkError) return c.json({ error: linkError }, 400)
    const created = await store.createOrgRegistryOrg({ id: id!, name: name!, ...rest, createdBy: gate.user!.email })
    if (!created) {
      return c.json({ error: `the id '${id}' is taken — the organization already exists (open it to edit)` }, 409)
    }
    await audit('organization.added', created.id, { userId: gate.user!.id, userName: gate.user!.name }, {
      name: created.name,
      kind: created.kind,
      participant_ref: created.participantRef,
      designated_by: created.designatedBy,
      proposed_by: created.proposedBy,
    }, 'organization')
    return c.json(created, 201)
  })

  // PUT /api/op/registry/orgs/:orgId — the edit act: the display data +
  // the participant_ref annotation + the designation links / the CS
  // status facet (TODO.identity-features/10 — validated against the
  // MERGED row's kind: a kind change and a link change meet the same
  // rule). The id never moves (a rename is a
  // new org); present fields set, null clears, absent fields stand.
  registry.put('/api/op/registry/orgs/:orgId', async (c) => {
    const gate = await requireAdmin(c)
    if (gate.error || !gate.user) return gate.error!
    const store = getStore()
    const orgId = c.req.param('orgId')
    const org = await store.getOrgRegistryOrg(orgId)
    if (!org) return c.json({ error: 'not found' }, 404)
    const body = await c.req.json<Record<string, unknown>>().catch(() => null)
    const parsed = orgPayload(c, body, false)
    if ('error' in parsed) return parsed.error
    const patch = parsed.fields
    if (patch.id !== undefined && patch.id !== orgId) {
      return c.json({ error: 'the id is the stable slug — it never changes (a rename is a new organization)' }, 400)
    }
    const { id: _id, ...fields } = patch
    if (Object.keys(fields).length === 0) {
      return c.json({ error: 'nothing to update — name the fields to change' }, 400)
    }
    const linkError = await validateOrgLinks(store, {
      kind: fields.kind !== undefined
        ? (fields.kind as RegistryOrgKind | null)
        : (isRegistryOrgKind(org.kind) ? org.kind : null),
      designatedBy: fields.designatedBy !== undefined ? fields.designatedBy : org.designatedBy,
      proposedBy: fields.proposedBy !== undefined ? fields.proposedBy : org.proposedBy,
      csStatus: fields.csStatus !== undefined ? fields.csStatus : org.csStatus,
    })
    if (linkError) return c.json({ error: linkError }, 400)
    const updated = await store.updateOrgRegistryOrg(orgId, fields, gate.user!.email)
    await audit('organization.updated', orgId, { userId: gate.user!.id, userName: gate.user!.name }, {
      name: updated!.name,
      fields: Object.keys(fields),
    }, 'organization')
    return c.json(updated)
  })

  // POST /api/op/registry/orgs/:orgId/state — the lifecycle act:
  // { state: 'disabled' | 'active' }. DISABLE is the honest removal: the
  // org's ACTIVE memberships disable with it (the members' per-org roles
  // stop carrying at the next claims emission; the sessions' active-org
  // stamps clear inside the store's act), and the answer names the
  // cascade. The INVITED memberships wait — an invitation carries
  // nothing yet; the holder's accept refuses while the org is disabled.
  // RE-ENABLE reopens the row only: the memberships stay disabled (the
  // per-membership re-activation is the deliberate act, never an
  // automatic one).
  registry.post('/api/op/registry/orgs/:orgId/state', async (c) => {
    const gate = await requireAdmin(c)
    if (gate.error || !gate.user) return gate.error!
    const store = getStore()
    const orgId = c.req.param('orgId')
    const org = await store.getOrgRegistryOrg(orgId)
    if (!org) return c.json({ error: 'not found' }, 404)
    const body = await c.req.json<{ state?: string }>().catch(() => null)
    if (!body || (body.state !== 'active' && body.state !== 'disabled')) {
      return c.json({ error: 'state must be "active" or "disabled"' }, 400)
    }
    if (body.state === org.state) {
      return c.json({ error: `the organization is already ${org.state}` }, 409)
    }
    if (body.state === 'disabled') {
      const memberships = await store.listOrgMembers(orgId)
      let cascaded = 0
      for (const m of memberships) {
        if (m.state !== 'active') continue
        await store.setOrgMembershipState(m.userId, orgId, 'disabled', gate.user!.email)
        cascaded += 1
      }
      const waiting = memberships.filter(m => m.state === 'invited').length
      const updated = await store.setOrgRegistryOrgState(orgId, 'disabled', gate.user!.email)
      await audit('organization.disabled', orgId, { userId: gate.user!.id, userName: gate.user!.name }, {
        name: org.name,
        memberships_disabled: cascaded,
        invitations_waiting: waiting,
      }, 'organization')
      return c.json({ org: updated, membershipsDisabled: cascaded, invitationsWaiting: waiting })
    }
    const updated = await store.setOrgRegistryOrgState(orgId, 'active', gate.user!.email)
    const stillDisabled = (await store.listOrgMembers(orgId)).filter(m => m.state === 'disabled').length
    await audit('organization.reactivated', orgId, { userId: gate.user!.id, userName: gate.user!.name }, {
      name: org.name,
      memberships_still_disabled: stillDisabled,
    }, 'organization')
    return c.json({ org: updated, membershipsStillDisabled: stillDisabled })
  })

  // DELETE /api/op/registry/orgs/:orgId — the erasure-adjacent hard
  // delete, guarded honestly: only an org that NEVER held a membership
  // and has no join request referencing it (either history class keeps
  // the org: disable it instead — the audit trail is the history). The
  // audit row lands BEFORE the delete and carries the tombstone data.
  registry.delete('/api/op/registry/orgs/:orgId', async (c) => {
    const gate = await requireAdmin(c)
    if (gate.error || !gate.user) return gate.error!
    const store = getStore()
    const orgId = c.req.param('orgId')
    const org = await store.getOrgRegistryOrg(orgId)
    if (!org) return c.json({ error: 'not found' }, 404)
    const [memberships, requests] = await Promise.all([
      store.listOrgMembers(orgId),
      store.listOrgJoinRequests({ scope: 'org', orgId }),
    ])
    if (memberships.length || requests.length) {
      return c.json({
        error: `organization '${orgId}' holds history (${memberships.length} membership(s), ${requests.length} join request(s)) — removal is DISABLE honestly: the lifecycle act keeps the audit trail; the hard delete exists only for an org that never held either`,
        memberships: memberships.length,
        requests: requests.length,
      }, 409)
    }
    await audit('organization.removed', orgId, { userId: gate.user!.id, userName: gate.user!.name }, {
      name: org.name,
      kind: org.kind,
      participant_ref: org.participantRef,
    }, 'organization')
    await store.deleteOrgRegistryOrg(orgId)
    return c.json({ ok: true })
  })

  // GET /api/op/registry/orgs/:orgId — the per-ORG view (TODO.identity/11,
  // the multi-org model; TODO.identity-features/05 extends it to the
  // first-class org): the registry org's FULL row (the display data, the
  // contacts, the participant_ref annotation, the lifecycle stamps, the
  // per-kind STANDING — TODO.register/01), the DESIGNATION CHAIN both
  // directions (TODO.identity-features/10 — the row's own designated_by/
  // proposed_by resolved to display names, the orgs naming THIS org as
  // their designator/proposer, and the edit form's eligible link
  // targets), the designated bodies' CS STATUS facet, the manufacturer
  // standing's
  // ACTIVE endorsements (the endorsing IAs, names resolved), its
  // MEMBERSHIPS (the members with their per-org role sets + lifecycle
  // states — the org_admins among them marked by the role), its
  // join-request queue (every state, newest first), and the org's own
  // audit slice (the lifecycle acts + the membership + join-request acts
  // naming it, newest first, 50 deep). The membership mutations live in
  // routes/op-memberships.ts (the grant-checked surface); the org's own
  // acts are this router's (above); this aggregate is the read.
  registry.get('/api/op/registry/orgs/:orgId', async (c) => {
    const gate = await requireAdmin(c)
    if (gate.error) return gate.error
    const store = getStore()
    const orgId = c.req.param('orgId')
    const org = await resolveRegistryOrg(store, orgId)
    if (!org) {
      return c.json({ error: `organization '${orgId}' is not on the organization registry` }, 404)
    }
    const [memberships, users, requests, activity, orgTokens] = await Promise.all([
      store.listOrgMembers(orgId),
      store.listUsers(),
      store.listOrgJoinRequests({ scope: 'org', orgId }),
      // The org's own audit slice (TODO.identity-features/09 — the one
      // computation the org admin's grant-gated slice shares,
      // auth/op/org-audit.ts): the lifecycle acts + the membership
      // (roles, lifecycle, CONE) + join-request + org-invite acts naming
      // the org, newest first, 50 deep.
      orgAuditSlice(store, orgId),
      // TODO.identity-features/08: the org's token inventory (the org
      // detail page's section) — the members' developer tokens, the
      // METADATA only (never the plaintext, never the hash), EVERY
      // membership state (a disabled member's live token is exactly
      // what the oversight surface hunts).
      store.listOrgPersonalAccessTokens(orgId),
    ])
    const byId = new Map(users.map(u => [u.id, u]))
    // The manufacturer standing's endorsements (TODO.register/01): the
    // ACTIVE rows with the endorsing IA's display name resolved (the
    // revocations stay on the audit slice below — the history, honestly).
    const allOrgs = await listRegistryOrganizations(store)
    const orgNames = new Map(allOrgs.map(o => [o.id, o.name]))
    // The designation chain (TODO.identity-features/10), BOTH directions,
    // honestly: the row's own links RESOLVED (the designating/proposing
    // org's display name; a set link whose target left the registry
    // renders its raw id — the write path's validation keeps that from
    // landing, a disable after the fact stays honest), and the REVERSE
    // chain — the orgs naming THIS org as their designator/proposer
    // (the member's row reads "proposes: <IA>; designates: <Utilizer>",
    // the IA's "associated test laboratories: <TL>"). A legal body
    // holding several roles reads as its separate LINKED rows, never
    // merged.
    const resolveLink = (id: string | null) =>
      id ? { id, name: orgNames.get(id) ?? id } : null
    const linkedBy = allOrgs
      .filter(o => o.id !== org.id && (o.designatedBy === org.id || o.proposedBy === org.id))
      .map(o => ({
        id: o.id,
        name: o.name,
        kind: o.kind,
        via: (o.proposedBy === org.id ? 'proposed_by' : 'designated_by') as 'proposed_by' | 'designated_by',
      }))
    // The edit form's eligible link targets (the write path re-checks):
    // the ACTIVE orgs of each link-target kind.
    const activeOf = (kind: string) =>
      allOrgs.filter(o => o.kind === kind && o.state === 'active').map(o => ({ id: o.id, name: o.name }))
    const linkTargets = {
      memberStates: activeOf('member-state'),
      correspondingMembers: activeOf('corresponding-member'),
      issuingAuthorities: activeOf('issuing-authority'),
    }
    const endorsements = (await listOrgEndorsements(store, orgId))
      .filter(e => !e.revokedAt)
      .map(e => ({
        iaOrgId: e.iaOrgId,
        iaName: orgNames.get(e.iaOrgId) ?? e.iaOrgId,
        note: e.note,
        createdAt: e.createdAt,
        createdBy: e.createdBy,
      }))
    // The org's signing keys (TODO.trust-registry/01): the custody chain
    // WHOLE — active, rotated, revoked rows with their stamps and the
    // actor on each act (the administrator sees the chain honestly; the
    // PUBLIC endpoint /op/keys/<org-id>.json carries the dates only).
    const signingKeys = (await listOrgSigningKeys(store, orgId)).map(k => ({
      kid: k.kid,
      label: k.label,
      publicJwk: k.publicJwk,
      createdAt: k.createdAt,
      createdBy: k.createdBy,
      rotatedAt: k.rotatedAt,
      rotatedBy: k.rotatedBy,
      successorKid: k.successorKid,
      revokedAt: k.revokedAt,
      revokedBy: k.revokedBy,
    }))
    // The org's own audit slice (auth/op/org-audit.ts — computed in the
    // Promise.all above; the org administrator's grant-gated endpoint
    // answers the SAME slice, routes/op-memberships.ts).
    return c.json({
      org: {
        id: org.id,
        name: org.name,
        shortName: org.shortName,
        kind: org.kind,
        country: org.country,
        contacts: org.contacts,
        participantRef: org.participantRef,
        designatedBy: org.designatedBy,
        proposedBy: org.proposedBy,
        csStatus: org.csStatus,
        state: org.state,
        registered: org.registered,
        standing: org.standing,
        endorsedBy: org.endorsedBy,
        roles: org.roles,
        createdAt: org.createdAt,
        createdBy: org.createdBy,
        updatedAt: org.updatedAt,
        updatedBy: org.updatedBy,
        disabledAt: org.disabledAt,
        disabledBy: org.disabledBy,
      },
      links: {
        designatedBy: resolveLink(org.designatedBy),
        proposedBy: resolveLink(org.proposedBy),
      },
      linkedBy,
      linkTargets,
      endorsements,
      signingKeys,
      // The developer-token inventory (TODO.identity-features/08): the
      // holder resolved (an erased member reads honestly), the metadata
      // only.
      tokens: orgTokens.map(pat => {
        const holder = byId.get(pat.userId) ?? null
        return {
          ...patListRow(pat),
          holder: {
            userId: pat.userId,
            name: holder?.name ?? '(erased account)',
            email: holder?.email ?? null,
          },
        }
      }),
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
          cone: m.cone,
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
      activity,
    })
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
