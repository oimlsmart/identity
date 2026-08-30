// ═══════════════════════════════════════════════════════════════════
// The API app factory, OP-ONLY (the extraction map, smart's
// PROGRESS/41 §3): the OP routers (routes/op*.ts — the protocol, the
// accounts, the upstream providers, the join intake, the memberships,
// the registry), the session/demo seam
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
import { createOpFactorsRouter } from './routes/op-factors'
import { createOpTokensRouter } from './routes/op-tokens'
import { createOpMfaRouter } from './routes/op-mfa'
import { createOpJoinRouter } from './routes/op-join'
import { createOpMembershipsRouter } from './routes/op-memberships'
import { createOpEndorsementsRouter } from './routes/op-endorsements'
import { createOpKeysRouter } from './routes/op-keys'
import { createOpRegistryRouter } from './routes/op-registry'
import { createOpDashboardRouter } from './routes/op-dashboard'
import { createOpHomeRouter } from './routes/op-home'
import { createOpWhoamiRouter } from './routes/op-whoami'
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
  // TODO.identity-sso/02+03 extends the same guard over the second-factor
  // + passkey ceremony endpoints (the six-digit window invites brute
  // force; the per-ACCOUNT backoff ladder rides the rows themselves,
  // routes/op-mfa.ts's throttleState).
  // Generous defaults (the legitimate flows are human-paced);
  // OP_RATE_LIMIT_CAPACITY=0 disables it honestly.
  const rateLimit = createOpRateLimiter()
  app.use('/op/authorize', rateLimit)
  app.use('/op/token', rateLimit)
  app.use('/api/op/login', rateLimit)
  app.use('/api/op/login/reset', rateLimit)
  app.use('/api/op/login/mfa/*', rateLimit)
  app.use('/api/op/login/passkey', rateLimit)
  app.use('/api/op/login/passkey/options', rateLimit)
  app.use('/api/op/account/factors/totp/*/verify', rateLimit)

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
  // The factor registry (TODO.identity-sso/02+03): the console's
  // passkey/TOTP/recovery-code surface.
  app.route('/', createOpFactorsRouter())
  // The developer tokens (TODO.identity-features/08): the console's
  // personal-access-token surface (list / mint / revoke); the exchange
  // grant itself lives on the OP router's /op/token.
  app.route('/', createOpTokensRouter())
  // The sign-in's second-factor + passwordless half (the same wave).
  app.route('/', createOpMfaRouter())
  // Delegated organization administration: the public "Request an
  // account" intake and the two decision queues.
  app.route('/', createOpJoinRouter())
  // The multi-org membership model (TODO.identity/11): the per-org
  // membership management API (the org admin's people slice + the
  // identity admin's per-org view).
  app.route('/', createOpMembershipsRouter())
  // The manufacturer standing's endorsement acts (TODO.register/01): an
  // issuing authority confirms / withdraws the manufacturer relationship
  // (declared → ia-endorsed, never the participant standing).
  app.route('/', createOpEndorsementsRouter())
  // The org signing keys (TODO.trust-registry/01): the management acts
  // (register/rotate/revoke, the org_admin-in-context or the estate
  // admin) + the PUBLIC key-resolution endpoint /op/keys/<org-id>.json
  // (the key set + the standing projection, anonymous + cacheable).
  app.route('/', createOpKeysRouter())
  // The administrator's identity registry: the account search and
  // detail aggregate, link-on-behalf, session revocation, the activity
  // feed.
  app.route('/', createOpRegistryRouter())
  // The administrator's dashboard (TODO.identity-sso/01): the overview
  // metrics, the aggregate live sessions + the revoke-all act, the
  // security signals, the queryable audit log, the live access review,
  // the per-client activity. A READ surface over the journal + the
  // store + the heartbeat's own history; the one write is the store's
  // own revocation half.
  app.route('/', createOpDashboardRouter())
  // The SSO home: the post-login launcher's feed (the per-account
  // visibility computed on the client registry's launch metadata) and
  // the request-access intake.
  app.route('/', createOpHomeRouter())
  // The whoami beacon (the estate's SSO-UX last mile): the static
  // properties' account chips read the OP session's minimal projection,
  // CORS-gated on the registered clients' declared origins.
  app.route('/', createOpWhoamiRouter())
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
        // The support affordance (the ISO-benchmark quick win, smart's
        // TODO.identity-features/11 item 6): the deployment's
        // SUPPORT_URL, rendered as a plain "Need help?" link — never a
        // third-party widget on the credential surface. Undeclared: no
        // link renders.
        ...(env.SUPPORT_URL?.trim() ? { supportUrl: env.SUPPORT_URL.trim() } : {}),
      },
      // The environment ribbon (item 5): the deployment declares
      // ENVIRONMENT_LABEL ("Preview", "Test" — the operator's own word)
      // and the shell renders it as a thin strip; production declares
      // nothing and the projection answers null. Public-safe by
      // construction: the label is the deployment's own name for
      // itself.
      environment: env.ENVIRONMENT_LABEL?.trim() ? { label: env.ENVIRONMENT_LABEL.trim() } : null,
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
