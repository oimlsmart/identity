// ═══════════════════════════════════════════════════════════════════
// The SSO home's API (the post-login launcher, the spec: smart's
// TODO.identity-extract/02a "post-login landing") — the signed-in
// account's launcher feed and the request-access intake.
//
//   GET  /api/op/home             — the launcher feed: the account, the
//                                   admin flag, and the service cards
//                                   with the visibility computed
//                                   honestly (below);
//   POST /api/op/home/requests    — the request-access intake: the card
//                                   the account cannot enter (the
//                                   'request' visibility) files a
//                                   request on the audit chain, the
//                                   registry's activity feed carries it
//                                   (the approval-queue pattern's
//                                   honest minimum: recorded, never a
//                                   dead-end card).
//
// THE VISIBILITY COMPUTATION (per account × client): the client joins
// the feed only when it carries launch metadata (launch_url set) and is
// active. The card's state:
//
//   - 'launch'   the account may enter: the client's visibility is
//                'open', or the role claims the OP would emit for this
//                account on this client are NON-EMPTY — computed with
//                the ONE rule the token endpoint, userinfo and the
//                consent page share (auth/op/claims.ts's
//                roleClaimsForClient: the per-client assignment through
//                the claims policy's role allowlist). An empty set means
//                the instance receives no role for this account (its
//                first-seen path is the approval queue — a dead-end the
//                launcher never renders as a working card).
//   - 'request'  the account may NOT enter and the client's visibility
//                is 'request': the card renders without a working
//                launch, with the plain request-access state.
//   - (hidden)   otherwise (the 'roles' default): the card never
//                renders.
//
// Profile-gated like every OP route (a non-identity deployment answers
// 404). WORKER-SAFE: the store seam only, no node built-ins.
// ═══════════════════════════════════════════════════════════════════

import { Hono, type Context, type MiddlewareHandler } from 'hono'
import { getStore, type AuthUserPayload, type OidcClient } from '@oimlsmart/platform-server/store'
import { getInstanceProfile } from '@oimlsmart/platform-server/profile'
import { sessionUser } from '@oimlsmart/platform-server/session'
import { roleClaimsForClient } from '../auth/op/claims'

/** The feed's per-service card (the page renders exactly this). */
export interface HomeService {
  clientId: string
  name: string
  description: string | null
  icon: string | null
  /** The service's sign-in start — present ONLY on a launchable card
   *  (the request-access state never carries it: no dead-end links). */
  launchUrl?: string
  state: 'launch' | 'request'
  /** A request the account already filed rides the card (the "request
   *  access" state reads honestly across reloads). */
  requested: boolean
}

/** The role claims the OP would emit for this account on this client —
 *  the admission set (non-empty = the account enters with a role). The
 *  assignment arrives read: the LIST caller (the home feed) passes the
 *  once-per-request batch (the endpoint-scaling doctrine — a per-client
 *  getOpClientRoles was one store round trip per registered client);
 *  the single-client caller (the request act) passes its one read. */
async function emittedRoles(user: AuthUserPayload, client: OidcClient, assigned: string[] | null): Promise<string[]> {
  const claims = roleClaimsForClient(assigned, { role: user.role, roles: user.roles, orgId: user.orgId }, client.claimsPolicy)
  return (claims.roles as string[] | undefined) ?? []
}

/** The account's filed access requests (the audit journal's rows), as a
 *  client-id set. The scan mirrors the registry's activity feed (the
 *  same journal, the same parse discipline). */
async function requestedClientIds(userId: string): Promise<Set<string>> {
  const out = new Set<string>()
  for (const row of await getStore().listEntities('auditEvents')) {
    try {
      const event = JSON.parse(row.data) as { entity_id?: string; action?: string; metadata?: { clientId?: unknown } }
      if (event.entity_id === userId && event.action === 'account.access_request' && typeof event.metadata?.clientId === 'string') {
        out.add(event.metadata.clientId)
      }
    } catch { /* a malformed journal row never breaks the launcher */ }
  }
  return out
}

export function createOpHomeRouter(): Hono {
  const home = new Hono()

  // ── the profile gate (the same posture as routes/op.ts: the routes
  // exist in the ONE build, the identity module decides) ──────────────
  const profileGate: MiddlewareHandler = async (c, next) => {
    if (!getInstanceProfile().modules.includes('identity')) {
      return c.json({ error: 'not found' }, 404)
    }
    await next()
  }
  home.use('/api/op/home', profileGate)
  home.use('/api/op/home/*', profileGate)

  async function requireSession(c: Context): Promise<{ user: AuthUserPayload | null; error: Response | null }> {
    const user = await sessionUser(c)
    if (!user) return { user: null, error: c.json({ error: 'authentication required' }, 401) }
    return { user, error: null }
  }

  /** The request intake's audit record: the account's own row on the
   *  chain (entity_type 'account' — the registry's activity feed carries
   *  it), naming the client. The audit never blocks the path. */
  async function auditRequest(user: AuthUserPayload, client: OidcClient): Promise<void> {
    try {
      const id = crypto.randomUUID()
      await getStore().putEntity('auditEvents', id, null, JSON.stringify({
        id,
        timestamp: new Date().toISOString(),
        standard_id: '',
        entity_type: 'account',
        entity_id: user.id,
        action: 'account.access_request',
        user_id: user.id,
        user_name: user.name,
        metadata: { email: user.email, clientId: client.clientId, clientName: client.name },
      }))
    } catch (err) {
      console.error('[op] access-request audit event failed to persist:', (err as Error).message)
    }
  }

  // GET /api/op/home — the launcher feed.
  home.get('/api/op/home', async (c) => {
    const gate = await requireSession(c)
    if (gate.error || !gate.user) return gate.error!
    const user = gate.user!
    const store = getStore()
    // The account's per-client assignments load ONCE (grouped by client)
    // — the admission check below never re-enters the store per client.
    const [clients, requested, assignments] = await Promise.all([
      store.listOidcClients(),
      requestedClientIds(user.id),
      store.listOpClientRoles(user.id),
    ])
    const assignedByClient = new Map(assignments.map(a => [a.clientId, a.roles]))
    const services: HomeService[] = []
    for (const client of clients) {
      if (!client.launch || client.status !== 'active') continue
      const admitted = client.launch.visibility === 'open'
        || (await emittedRoles(user, client, assignedByClient.get(client.clientId) ?? null)).length > 0
      if (admitted) {
        services.push({
          clientId: client.clientId,
          name: client.name,
          description: client.launch.description,
          icon: client.launch.icon,
          launchUrl: client.launch.url,
          state: 'launch',
          requested: requested.has(client.clientId),
        })
      } else if (client.launch.visibility === 'request') {
        services.push({
          clientId: client.clientId,
          name: client.name,
          description: client.launch.description,
          icon: client.launch.icon,
          state: 'request',
          requested: requested.has(client.clientId),
        })
      } // 'roles': the card never renders.
    }
    services.sort((a, b) => a.name.localeCompare(b.name))
    return c.json({
      account: { id: user.id, name: user.name, email: user.email, avatarUrl: user.avatarUrl ?? null, role: user.role },
      admin: user.role === 'admin' || user.role === 'cs_admin',
      services,
    })
  })

  // POST /api/op/home/requests — the request-access intake. The honest
  // state machine: the client must exist, carry the card, be in the
  // 'request' posture, and the account must NOT already be admitted (a
  // request for a service the account can enter is refused, never
  // recorded). A repeat request answers idempotently (already: true).
  home.post('/api/op/home/requests', async (c) => {
    const gate = await requireSession(c)
    if (gate.error || !gate.user) return gate.error!
    const user = gate.user!
    const body = await c.req.json<{ client_id?: string }>().catch(() => null)
    if (!body || typeof body.client_id !== 'string' || !body.client_id.trim()) {
      return c.json({ error: 'client_id is required' }, 400)
    }
    const client = await getStore().getOidcClient(body.client_id.trim())
    if (!client || !client.launch || client.status !== 'active') {
      return c.json({ error: 'not found' }, 404)
    }
    if (client.launch.visibility !== 'request') {
      return c.json({ error: 'this service does not take access requests' }, 400)
    }
    if ((await emittedRoles(user, client, await getStore().getOpClientRoles(user.id, client.clientId))).length > 0) {
      return c.json({ error: 'your account already holds a role this service accepts — the card is launchable' }, 409)
    }
    const requested = await requestedClientIds(user.id)
    if (requested.has(client.clientId)) {
      return c.json({ ok: true, already: true })
    }
    await auditRequest(user, client)
    return c.json({ ok: true }, 201)
  })

  return home
}
