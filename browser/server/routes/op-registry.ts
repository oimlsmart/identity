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
//                                                      profile, sign-in
//                                                      methods, links,
//                                                      sessions, the
//                                                      account's audit
//                                                      trail
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
import { resolveRegistryOrg } from '../auth/org-registry'
import { sessionUser } from '@oimlsmart/platform-server/session'

/** The audit actions the registry's activity feed surfaces: the identity
 *  registry's own journal rows (accounts, roles, links, sessions,
 *  sign-ins, clients, providers, join requests). Other workflow stores
 *  write auditEvents too; the feed keeps the identity slice. */
const REGISTRY_ENTITY_TYPES = new Set(['account', 'users', 'auth', 'client', 'provider'])
const REGISTRY_ACTION_PREFIXES = ['org_invite.', 'org_join.']

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
  // page renders: the profile, the sign-in methods, the linked
  // identities, the live sessions, and the account's own audit trail
  // (newest first, capped).
  registry.get('/api/op/registry/users/:id', async (c) => {
    const gate = await requireAdmin(c)
    if (gate.error) return gate.error
    const store = getStore()
    // The admin row (not getUserById): the detail carries active +
    // lastLogin, which the session payload does not.
    const user = (await store.listUsers()).find(u => u.id === c.req.param('id'))
    if (!user) return c.json({ error: 'not found' }, 404)
    const [methods, links, sessions, org, clientRoles] = await Promise.all([
      store.countSignInMethods(user.id),
      store.listIdentityLinks(user.id),
      store.listUserSessions(user.id),
      user.orgId ? resolveRegistryOrg(store, user.orgId) : Promise.resolve(null),
      store.listOpClientRoles(user.id),
    ])
    const activity = (await store.listEntities('auditEvents'))
      .map(row => parseAuditEvent(row.data))
      .filter((e): e is AuditEvent => !!e && e.entity_id === user.id && isRegistryEvent(e))
      .sort((a, b) => b.timestamp.localeCompare(a.timestamp))
      .slice(0, 50)
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
      },
      passwordSet: methods.password,
      links,
      sessions,
      // The per-client role assignments (TODO.identity/03's rows; the
      // editor lives on the user-registry console, this page reads them).
      clientRoles: clientRoles.map(a => ({ clientId: a.clientId, roles: a.roles, assignedBy: a.assignedBy, updatedAt: a.updatedAt })),
      activity,
    })
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
