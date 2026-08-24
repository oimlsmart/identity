// ═══════════════════════════════════════════════════════════════════
// The node composition root (the self-hosted posture + the e2e stacks):
// the OP-only API app (server/app.ts) over the SQLite store, plus the
// dev-reset seam (dev only). The Worker composition root is
// server/cloudflare.ts.
// ═══════════════════════════════════════════════════════════════════

import { installSqliteStore } from '@oimlsmart/platform-server/store/sqlite'
import { createApiApp } from './app'
import devReset from './routes/dev-reset'
import { installRbacMap } from '@oimlsmart/platform-server/rbac'
import { loadNodeRbacMap } from '@oimlsmart/platform-server/rbac/node'
import { loadNodeInstanceProfile } from '@oimlsmart/platform-server/profile/node'
import { installBlobStore } from './blobs'
import { diskBlobStore, nodeBlobsRoot } from './blobs-node'

// The store profile: SQLite (better-sqlite3) is THIS root's backend —
// installed before the first request lands (the routes resolve it
// lazily through the kernel's getStore).
installSqliteStore()

// The blob store (the account-avatar uploads): the local-disk adapter —
// dev and self-hosted node both store under BLOBS_DIR (default
// browser/data/blobs). BLOBS_DISABLED=true installs the honest
// unavailable posture (the avatar routes 503).
const blobsRoot = nodeBlobsRoot()
installBlobStore(blobsRoot ? diskBlobStore(blobsRoot) : null)

// The instance's RBAC map: INSTANCE_RBAC_JSON or the profile file's
// `rbac:` section; absent → the kernel's shipped default.
installRbacMap(loadNodeRbacMap())

// The deployment profile: the identity service's own (server/serve.ts
// defaults INSTANCE_PROFILE to server/instance.profile.dev.yaml when
// undeclared — the kernel's hub default would 404 every OP path).
// Loaded + installed BEFORE the app is built: /api/config answers it
// and the first request's seeds follow it.
const instanceProfile = loadNodeInstanceProfile()
const app = createApiApp({
  autoSeedDemo: true,
  instanceProfile,
})

// The e2e isolation seam — DEV ONLY, never mounted in production.
if (process.env.NODE_ENV !== 'production') {
  app.route('/api/dev-reset', devReset)
}

export default app
