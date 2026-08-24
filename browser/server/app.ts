// ═══════════════════════════════════════════════════════════════════
// The API app factory, OP-ONLY (the extraction map, smart's
// PROGRESS/41 §3): the five OP routers, the session/demo seam
// (routes/auth-lean.ts — NOT the platform's RP router), /api/health, a
// lean /api/config (the identity projection + branding + the profile
// view), and the OP-surface rate limiter.
//
// Two composition roots:
//   - server/index.ts (node, self-hosted + the e2e stacks): the SQLite
//     store, the demo accounts auto-provisioned, dev-reset mounted in
//     dev;
//   - server/cloudflare.ts (the Worker): the D1 store from the env
//     binding, never auto-seeded.
//
// WORKER-SAFE: every module this pulls is portable TS (no node
// built-ins, no better-sqlite3) — the Worker bundle includes it whole.
// ═══════════════════════════════════════════════════════════════════

import { Hono, type MiddlewareHandler } from 'hono'
import { env as runtimeEnv } from 'hono/adapter'
import { createOpRouter } from './routes/op'
import { createOpUpstreamRouter } from './routes/op-upstream'
import { createOpAccountsRouter } from './routes/op-accounts'
import { createOpJoinRouter } from './routes/op-join'
import { createOpRegistryRouter } from './routes/op-registry'
import { createUsersRouter } from './routes/users'
import { createAuthLeanRouter, opDemoAccountsEnabled } from './routes/auth-lean'
import { createOpRateLimiter } from './rate-limit'
import { getBlobStore } from './blobs'
import { effectiveRbacMap } from '@oimlsmart/platform-server/rbac'
import { getInstanceProfile, projectModuleToggles, publicProfileView, type InstanceProfile } from '@oimlsmart/platform-server/profile'

export interface ApiAppOptions {
  /** Provision the demo accounts on first request (the node posture's
   *  zero-config boot). FALSE on the Worker. */
  autoSeedDemo: boolean
  /** Extra middleware applied before every route (the Worker installs
   *  the D1 store + the instance profile from the request's env this
   *  way). */
  middleware?: MiddlewareHandler[]
  /** The deployment profile this instance boots with — node passes the
   *  disk-loaded one explicitly; the Worker's middleware installs it per
   *  request, so /api/config falls back to the installed slot. */
  instanceProfile?: InstanceProfile
}

export function createApiApp(options: ApiAppOptions): Hono {
  const app = new Hono()

  for (const mw of options.middleware ?? []) app.use('*', mw)

  // The OP-surface rate limiter (server/rate-limit.ts — the extraction
  // map's risk-8 follow-through): a per-caller token bucket guards the
  // credential-bearing endpoints (authorize, token, the password
  // sign-in + reset) with honest 429s + an audit event on trips.
  // Generous defaults (the legitimate flows are human-paced);
  // OP_RATE_LIMIT_CAPACITY=0 disables it honestly.
  const rateLimit = createOpRateLimiter()
  app.use('/op/authorize', rateLimit)
  app.use('/op/token', rateLimit)
  app.use('/api/op/login', rateLimit)
  app.use('/api/op/login/reset', rateLimit)

  // The session + demo sign-in seam (routes/auth-lean.ts): the four
  // /api/auth endpoints the OP's own pages consume. The platform's RP
  // router (SSO/GitHub sign-in) is the monorepo's, never mounted here.
  app.route('/api/auth', createAuthLeanRouter({ autoSeedDemo: options.autoSeedDemo }))

  // The OIDC Provider: discovery, JWKS, authorize + consent, token,
  // userinfo, and the client registry's admin surface.
  app.route('/', createOpRouter())
  // The OP's upstream providers: the provider registry, the upstream
  // sign-in/link flows, and the account's link surface.
  app.route('/', createOpUpstreamRouter())
  // The OP's account model: the password sign-in, the invite-only
  // enrollment, and the account self-service.
  app.route('/', createOpAccountsRouter())
  // Delegated organization administration: the public "Request an
  // account" intake and the two decision queues.
  app.route('/', createOpJoinRouter())
  // The administrator's identity registry: the account search and
  // detail aggregate, link-on-behalf, session revocation, the activity
  // feed.
  app.route('/', createOpRegistryRouter())
  // The users surface (TODO.identity/10's org-scoped grant): the
  // org-admin consoles' data source. The router is the monorepo's
  // routes/users.ts moved byte-identical — its instance-wide half
  // (users.manage) serves the OP's administrators here; the platform's
  // own copy stays with the monorepo (wave 04 reconciles).
  app.route('/api/users', createUsersRouter())

  // Health check
  app.get('/api/health', (c) => c.json({ status: 'ok' }))

  // The deployment's public config, identity-service shape. The
  // identity projection is PUBLIC-SAFE and honest about this service:
  // the OP is never an RP of itself, so ssoEnabled/githubEnabled are
  // always false; demoAccountsEnabled drives the demo sign-in surface
  // (the preview posture). The brand projects the profile's declared
  // branding section over the service default; the profile view is the
  // kernel's public projection.
  app.get('/api/config', (c) => {
    const env = runtimeEnv<Record<string, string | undefined>>(c)
    const instanceProfile = options.instanceProfile ?? getInstanceProfile()
    return c.json({
      entityBackend: env.ENTITY_BACKEND === 'server' ? 'server' : 'indexeddb',
      // Whether a blob store is bound (the avatar uploads degrade to an
      // honest 503 when it is not). Availability only — public-safe.
      blobs: { available: getBlobStore() !== null },
      identity: {
        ssoEnabled: false,
        providerName: null,
        demoAccountsEnabled: opDemoAccountsEnabled(env),
        githubEnabled: false,
      },
      branding: {
        productName: instanceProfile.branding.name,
        shortName: instanceProfile.branding.name,
      },
      modules: projectModuleToggles(instanceProfile),
      rbac: { map: effectiveRbacMap(env) },
      instanceProfile: publicProfileView(instanceProfile),
    })
  })

  // Root — informational (in production the Astro shell's landing page
  // serves /)
  app.get('/', (c) => c.json({
    name: 'OIML SMART Identity',
    version: '1.0.0',
    endpoints: {
      health: '/api/health',
      discovery: '/.well-known/openid-configuration',
      jwks: '/jwks.json',
      session: '/api/auth/session',
      signIn: 'POST /api/op/login',
      signout: 'POST /api/auth/signout',
    },
  }))

  return app
}
