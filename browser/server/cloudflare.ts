// ═══════════════════════════════════════════════════════════════════
// The Worker composition root (the Cloudflare deployment of the
// identity service): the OP-only Hono API (server/app.ts) served inside
// the Astro worker, over the D1 binding. The account registry is the
// D1 database oiml-smart-platform-identity — it NEVER moves (the
// extraction's invariant).
//
// Posture differences from the node root, all deliberate:
//   - demo accounts are NEVER auto-seeded here (the production
//     posture); the preview's cast arrives through the declared
//     OP_ACCOUNT_SEED worker secret;
//   - the OP's own bootstrap seeds (the first administrator, the client
//     registry, the upstream providers) run lazily inside the OP
//     routers' env-driven seed seams, as in the monorepo.
//
// WORKER-SAFE: no node built-ins anywhere in this module's graph.
// ═══════════════════════════════════════════════════════════════════

import { Hono } from 'hono'
import type { D1Database, Fetcher, R2Bucket, SendEmail } from '@cloudflare/workers-types'
import { installStore } from '@oimlsmart/platform-server/store'
import { d1StoreFor } from '@oimlsmart/platform-server/store/d1'
import { createApiApp } from './app'
import { installInstanceProfile, resolveInstanceProfileFromEnv } from '@oimlsmart/platform-server/profile'
import { installBlobStore, r2BlobStore } from './blobs'

/** The worker's env (wrangler.toml [vars] + bindings + secrets). A type
 *  alias (not an interface) so it carries the implicit index signature
 *  hono/adapter's env() constraint asks for. */
export type CloudflareApiEnv = {
  DB: D1Database
  /** The account-avatar uploads (TODO.identity's account console): the
   *  R2 bucket binding from wrangler.toml's commented
   *  [[env.identity.r2_buckets]]. UNBOUND is a supported posture — the
   *  avatar routes answer 503 and the console shows the linked-provider
   *  picture or the initials. */
  BLOBS?: R2Bucket
  /** The worker's static-asset binding. */
  ASSETS?: Fetcher
  ENTITY_BACKEND?: string
  NODE_ENV?: string
  /** The deployment profile as an inline YAML binding (the Worker has
   *  no disk path). */
  INSTANCE_PROFILE_YAML?: string
  /** The OIDC Provider's bindings: the issuer URL, the ES256 signing
   *  key (a Worker secret, JWK JSON), and the bootstrap seeds (the
   *  client registry, the first administrator account, the upstream
   *  provider rows) — all env-driven, consumed lazily by the OP
   *  routers' seed seams. */
  OP_ISSUER?: string
  OP_SIGNING_KEY?: string
  OP_CLIENT_SEED?: string
  OP_ACCOUNT_SEED?: string
  OP_UPSTREAM_SEED?: string
  /** The demo sign-in override (the preview posture declares it). */
  DEMO_ACCOUNTS_ENABLED?: string
  /** The OP-surface rate limiter's tuning (server/rate-limit.ts). */
  OP_RATE_LIMIT_CAPACITY?: string
  OP_RATE_LIMIT_WINDOW_MS?: string
  /** The avatar upload cap override (server/auth/op/avatars.ts). */
  AVATAR_MAX_BYTES?: string
  /** Transactional email. EMAIL: the Cloudflare Email Service
   *  `send_email` binding (wrangler.toml's commented
   *  [[env.identity.send_email]] block). The HTTPS provider fallback is
   *  the two string envs (MAIL_PROVIDER_KEY a secret); EMAIL_FROM the
   *  sender. With neither configured the mailer is an honest no-op. */
  EMAIL?: SendEmail
  EMAIL_FROM?: string
  MAIL_PROVIDER_URL?: string
  MAIL_PROVIDER_KEY?: string
  MAIL_RATE_LIMIT_CAPACITY?: string
  MAIL_RATE_LIMIT_WINDOW_MS?: string
  MAIL_LOCALE?: string
}

function buildWorkerApp(): Hono {
  return createApiApp({
    autoSeedDemo: false,
    middleware: [
      // The store install: every request runs against the D1 binding —
      // or fails honestly when the binding is absent. The blob store
      // (the avatar uploads) installs alongside: the R2 binding when
      // present, the honest unavailable posture (null) otherwise. The
      // deployment profile resolves from the inline INSTANCE_PROFILE_YAML
      // binding (the identity default when undeclared).
      async (c, next) => {
        const db = (c.env as CloudflareApiEnv | undefined)?.DB
        if (!db) {
          return c.json({ error: 'the D1 binding (DB) is not configured on this worker' }, 500)
        }
        installStore(d1StoreFor(db))
        const bucket = (c.env as CloudflareApiEnv | undefined)?.BLOBS
        installBlobStore(bucket ? r2BlobStore(bucket) : null)
        installInstanceProfile(resolveInstanceProfileFromEnv(c.env as CloudflareApiEnv))
        await next()
      },
    ],
  })
}

let workerApp: Hono | null = null

/** The Astro catch-all endpoints' entry (src/pages/api/[...path].ts,
 *  src/pages/op/[...path].ts, the jwks/discovery shims): one Hono app
 *  per isolate, the env per request. */
export async function handleWorkerApi(request: Request, env: CloudflareApiEnv): Promise<Response> {
  workerApp ??= buildWorkerApp()
  return workerApp.fetch(request, env)
}
