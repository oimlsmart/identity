// ═══════════════════════════════════════════════════════════════════
// The OIDC Provider's endpoints (TODO.identity/01) — the OP half of the
// Authorization Code + PKCE flow our instances (the RP side,
// TODO.federation/10) already consume. Hand-rolled on WebCrypto + the
// ServerStore seam, the same discipline as auth/oidc.ts: NO library
// dependency, every runtime (node ≥ 18, Cloudflare Workers) ships what
// this uses, and EVERY piece of state that must survive an isolate lives
// in the database (clients, pending authorizations, one-time codes,
// access tokens, the key history) — NOTHING in per-process Maps (the
// GitHub-flow lesson).
//
// The surface:
//   GET  /.well-known/openid-configuration — the discovery document;
//   GET  /jwks.json                        — the OP's public keys (ES256,
//                                            kid, rotation history);
//   GET  /op/authorize                     — the authorization endpoint:
//                                            client-registry validation,
//                                            the signed-in session (or a
//                                            redirect to the instance's
//                                            own login page), then the
//                                            consent page (/op/consent,
//                                            the Vue island) — SKIPPED
//                                            when a remembered grant
//                                            covers the scope set
//                                            (TODO.identity-features/12;
//                                            prompt=consent forces the
//                                            page);
//   GET  /api/op/consent/:id               — the consent page's context
//   POST /api/op/consent/:id/decide        — the consent decision → the
//                                            one-time code back to the RP;
//   POST /op/token                         — the code exchange: one-time
//                                            code + PKCE verify + the
//                                            client's secret → the signed
//                                            ES256 ID token + access token
//                                            (+ the FIRST refresh token of
//                                            a rotation family when the
//                                            grant carries offline_access —
//                                            TODO.identity-sso, the wave-C
//                                            token surface, kernel 0.2.6);
//                                            ALSO the refresh grant itself
//                                            (grant_type=refresh_token —
//                                            the one-time consume + the
//                                            rotation, a re-presented spent
//                                            token kills the family) AND
//                                            the machine cone
//                                            (grant_type=client_credentials,
//                                            the device + service classes
//                                            only → the self-contained
//                                            machine JWT — auth/op/
//                                            device-clients.ts +
//                                            service-clients.ts; the
//                                            RP-facing wire is unchanged —
//                                            the contract golden holds) AND
//                                            the person-bearing exchanges
//                                            (the RFC 8693 token exchange:
//                                            the developer cone's personal
//                                            access tokens, TODO.identity-
//                                            features/08; the session
//                                            delegation's access-token
//                                            subject, TODO.ai-platform/03 —
//                                            auth/op/tokens.ts; the same
//                                            register-internal posture, the
//                                            golden byte-identical);
//   GET  /op/userinfo                      — the access token's claims;
//   POST /op/revoke                        — RFC 7009 (the wave-C token
//                                            surface): the client-bound
//                                            revocation — a client revokes
//                                            only its OWN tokens, a refresh
//                                            token's revocation kills its
//                                            whole family, the answer is
//                                            200 whether the token existed
//                                            or not;
//   POST /op/introspect                    — RFC 7662 (identity#47/#42's
//                                            RS half): the authenticated
//                                            client reads a token's
//                                            standing — the opaque access
//                                            tokens from the table, the
//                                            machine classes' JWTs through
//                                            the signature + the named
//                                            client's standing (never a
//                                            table read);
//   GET  /op/avatar/<account id>           — the PUBLIC avatar serve (no
//                                            session — the `picture`
//                                            claim's target, the
//                                            GitHub-avatars convention);
//   GET/POST /api/op/clients[…]            — the client registry's admin
//                                            surface (admin/cs_admin).
//
// The routes mount on EVERY instance (app.ts) but answer 404 unless the
// deployment profile carries the identity module (roles: [identity]) —
// one build, the profile decides (the same posture as the module-gated
// client routes).
//
// WORKER-SAFE: WebCrypto + the store seam only, no node built-ins.
// ═══════════════════════════════════════════════════════════════════

import { Hono, type Context, type MiddlewareHandler } from 'hono'
import { env as runtimeEnv } from 'hono/adapter'
import { getStore } from '../store'
import { getInstanceProfile } from '../profile'
import { opRequestOrigin, resolveOpConfig, type OpConfig } from '../auth/op/config'
import { seedOidcClientsFromEnv } from '../auth/op/registry'

import { createOpAvatarServeRouter } from './op-avatar-serve'
import { createOpDiscoveryRouter } from './op-discovery'
import { createOpSessionManagementRouter } from './op-session-management'
import { createOpEndSessionRouter } from './op-end-session'
import { createOpClientsAdminRouter } from './op-clients-admin'
import { createOpProtocolRouter } from './op-protocol'
import { createOpTokenManagementRouter } from './op-token-management'
import { authenticateClient, createOpTokenRouter } from './op-token'
import { createOpCredentialsRouter } from './op-credentials'
import { createOpFederationRouter } from './op-federation'

type EnvLike = Record<string, string | undefined>

export function createOpRouter(): Hono {
  const op = new Hono()

  // ── the profile gate ─────────────────────────────────────────────
  // Only an identity-profile instance (roles: [identity] → the identity
  // module) serves the OP contract; every other deployment answers a
  // plain 404 — the routes exist in the ONE build, the profile decides.
  // (Scoped to the OP's own paths: this router mounts at the root, so a
  // bare '*' would gate the WHOLE app.)
  const profileGate: MiddlewareHandler = async (c, next) => {
    if (!getInstanceProfile().modules.includes('identity')) {
      return c.json({ error: 'not found' }, 404)
    }
    await next()
  }
  op.use('/.well-known/openid-configuration', profileGate)
  op.use('/.well-known/openid-credential-issuer', profileGate)
  op.use('/.well-known/openid-federation', profileGate)
  op.use('/jwks.json', profileGate)
  op.use('/op/*', profileGate)
  op.use('/api/op/*', profileGate)

  /** The request's effective OP config (env + this request's origin). */
  function configFor(c: Context): OpConfig {
    return resolveOpConfig(runtimeEnv<EnvLike>(c), opRequestOrigin(c.req.raw))
  }

  // The bootstrap client seed runs once per process/isolate (the
  // registry's known instances; idempotent upserts).
  let seeded: Promise<void> | null = null
  function ensureSeeded(c: Context): Promise<void> {
    if (!seeded) {
      seeded = (async () => {
        const ids = await seedOidcClientsFromEnv(runtimeEnv<EnvLike>(c), getStore())
        if (ids.length) console.log(`[op] client registry bootstrap seeded: ${ids.join(', ')}`)
      })()
      seeded.catch(() => { seeded = null }) // a failed seed retries next request
    }
    return seeded
  }

  // ── discovery + keys ─────────────────────────────────────────────
  // The metadata module (TODO.sota/07.4): routes/op-discovery.ts —
  // the discovery document + the JWKS (the RPs' first fetches).
  op.route('/', createOpDiscoveryRouter())

  // ── session management ────────────────────────────────────────────
  // The RP's session observation (TODO.modern/03): routes/
  // op-session-management.ts — the check iframe + the state read.
  op.route('/', createOpSessionManagementRouter())

  // ── the browser-facing protocol half (TODO.sota/07.4) ─────────────
  // routes/op-protocol.ts: authorize + PAR + the consent island's API
  // + the account chooser; the seed + audit seams ride in as
  // dependencies.
  op.route('/', createOpProtocolRouter({ ensureSeeded, audit, authenticateClient }))

  // ── token ────────────────────────────────────────────────────────
  // routes/op-token.ts (TODO.sota/07.4): the grant arms + the
  // client-authentication half (exported — the other modules' seam).
  op.route('/', createOpTokenRouter({ ensureSeeded, audit }))

  // ── the token surface's management half (TODO.identity-sso, wave C) ──
  // routes/op-token-management.ts (TODO.sota/07.4): userinfo + revoke +
  // introspect; the audit + client-auth seams ride in as dependencies.
  op.route('/', createOpTokenManagementRouter({ audit, authenticateClient }))


  /** The registry mutations' audit trail (the same discipline as
   *  routes/op-accounts.ts: the audit never blocks the path) — shared
   *  by the token grant arms and the clients-admin module (passed in
   *  as its dependency). */
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
        entity_type: 'client',
        entity_id: entityId,
        action,
        user_id: actor.userId,
        user_name: actor.userName,
        metadata,
      }))
    } catch (err) {
      console.error(`[op] client audit event ${action} failed to persist:`, (err as Error).message)
    }
  }

  // ── the end-session (TODO.identity-sso, the wave-A tail) ──────────
  // routes/op-end-session.ts (TODO.sota/07.4): the RP-initiated
  // logout + the backchannel fan-out; the router-instance seed seam
  // rides in as its dependency.
  op.route('/', createOpEndSessionRouter({ ensureSeeded }))

  // The avatar serve (TODO.sota/07.4's first extracted module):
  // routes/op-avatar-serve.ts.
  op.route('/', createOpAvatarServeRouter())

  // ── the federation (TODO.sota/09) ─────────────────────────────────
  // routes/op-federation.ts: the leaf entity configuration (the
  // OIDC Federation member's first document).
  op.route('/', createOpFederationRouter())

  // ── the credentials (TODO.sota/08) ────────────────────────────────
  // routes/op-credentials.ts: the OrgMembership SD-JWT VC's issuing
  // surface + the OIDC4VCI discovery document.
  op.route('/', createOpCredentialsRouter())

  // ── the client registry's admin surface ────────────────────────────
  // routes/op-clients-admin.ts (TODO.sota/07.4): the RP registry's
  // CRUD + status; the seed + audit seams ride in as dependencies.
  op.route('/', createOpClientsAdminRouter({ ensureSeeded, audit }))

  return op
}
