// ═══════════════════════════════════════════════════════════════════
// The remembered consent grants' console API (TODO.identity-features/12)
// — the account's OWN grants, every route session-gated (the developer
// tokens' posture, routes/op-tokens.ts):
//
//   GET    /api/op/account/grants        — the "apps they can access"
//                                          list: the account's LIVE
//                                          grants (the client's name,
//                                          the scope set, the
//                                          remembered-at stamp);
//   DELETE /api/op/account/grants/:id    — the "Revoke access" act (the
//                                          store's guard: the owner's
//                                          live row flips, once) — the
//                                          next sign-in to the client
//                                          re-prompts the consent page,
//                                          and the OFFLINE half dies with
//                                          it (the pair's refresh rows
//                                          delete — TODO.identity-sso,
//                                          the wave-C token surface).
//
// The acts land on the audit chain (entity_type 'account' — the
// account's own activity feed shows them).
//
// WORKER-SAFE: hono + the store seam only.
// ═══════════════════════════════════════════════════════════════════

import { Hono, type Context } from 'hono'
import { getStore } from '../store'
import { getInstanceProfile } from '../profile'
import { sessionUser } from '../session'
import { auditGrant, consentGrantRow } from '../auth/op/grants'

export function createOpGrantsRouter(): Hono {
  const grants = new Hono()

  // The profile gate (the op-accounts posture: one build, the identity
  // module decides).
  grants.use('/api/op/account/grants*', async (c, next) => {
    if (!getInstanceProfile().modules.includes('identity')) {
      return c.json({ error: 'not found' }, 404)
    }
    await next()
  })

  async function requireUser(c: Context) {
    const user = await sessionUser(c)
    if (!user) return { user: null, error: c.json({ error: 'authentication required' }, 401) }
    return { user, error: null }
  }

  // GET /api/op/account/grants — the account's live grants (the console's
  // "apps they can access").
  grants.get('/api/op/account/grants', async (c) => {
    const { user, error } = await requireUser(c)
    if (error || !user) return error!
    const store = getStore()
    // The client registry loads ONCE for the whole list — a per-grant
    // getOidcClient was one store round trip per grant (the
    // endpoint-scaling doctrine: prefetch once, group in memory).
    const [rows, clients] = await Promise.all([
      store.listConsentGrants(user.id),
      store.listOidcClients(),
    ])
    const clientsById = new Map(clients.map(cl => [cl.clientId, cl]))
    return c.json({ grants: await Promise.all(rows.map(row => consentGrantRow(store, row, clientsById))) })
  })

  // DELETE /api/op/account/grants/:id — the revoke (the store's guard:
  // the owner's live row flips, once; the row stays for the audit).
  grants.delete('/api/op/account/grants/:id', async (c) => {
    const { user, error } = await requireUser(c)
    if (error || !user) return error!
    const store = getStore()
    const rows = await store.listConsentGrants(user.id)
    const grant = rows.find(row => row.id === c.req.param('id'))
    if (!grant) return c.json({ error: 'no such grant' }, 404)
    const flipped = await store.revokeConsentGrant(grant.id, user.id)
    if (!flipped) return c.json({ error: 'this grant is already revoked' }, 409)
    // TODO.identity-sso (the wave-C token surface): the offline half dies
    // with the consent — every refresh row of the (account, client) pair
    // goes (the access tokens keep their ≤1 h life; the audit names the
    // count, never a token value).
    const refreshTokens = await store.deleteOidcRefreshTokensForUserClient(user.id, grant.clientId)
    await auditGrant('account.consent_revoked', user.id, { userId: user.id, userName: user.name }, {
      grant: grant.id,
      client: grant.clientId,
      name: (await store.getOidcClient(grant.clientId))?.name ?? grant.clientId,
      scope: grant.scope,
      refreshTokens,
    })
    return c.json({ ok: true })
  })

  return grants
}
