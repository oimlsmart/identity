// ─────────────────────────────────────────────────────────────────────
// POST /api/dev-reset — the e2e isolation seam, identity-service shape.
//
// The identity e2e legs boot a fresh SQLite file per leg and call this
// once after boot to provision the pristine state: the demo cast (the
// store seam's seed) and the demonstration participants register (the
// vendored snapshot). The wipe clears the entity stores (the register)
// plus the OP's mutable flow state, so a re-run never inherits the
// previous leg's enrollments or join requests. Users and sessions
// persist — the demo logins keep working.
//
// MOUNTED ONLY IN DEV (see server/index.ts): production never serves
// this. There is no auth by design — it only exists on the developer's
// machine or the e2e runner, and anything it can destroy is
// seed-reproducible.
// ─────────────────────────────────────────────────────────────────────

import { Hono } from 'hono'
import { rm } from 'node:fs/promises'
import { getDb } from '@oimlsmart/platform-server/store/sqlite'
import { getStore } from '@oimlsmart/platform-server/store'
import { seedOrgRegisterSnapshot } from '../seed-org-register'
import { nodeBlobsRoot } from '../blobs-node'

const app = new Hono()

app.post('/', async (c) => {
  const db = getDb()
  // TODO.identity/11: the org memberships wipe with the OP's mutable
  // flow state (the join requests' sibling) — the seed below re-mirrors
  // the demo cast's primary memberships (the store's mirror, idempotent).
  db.exec(`
    DELETE FROM entity_changes; DELETE FROM evidence_records; DELETE FROM entities;
    DELETE FROM identity_approvals;
    DELETE FROM org_join_requests;
    DELETE FROM org_memberships;
    DELETE FROM enrollment_tokens;
  `)
  // The local blob store (the avatar uploads in dev) wipes with the
  // entities — the reseeded state carries no blob references, so the
  // bytes would be orphans.
  const blobsRoot = nodeBlobsRoot()
  if (blobsRoot) await rm(blobsRoot, { recursive: true, force: true })
  const store = getStore()
  await store.seedDemoAccounts()
  const registerCounts = await seedOrgRegisterSnapshot(store)
  const registerRows = Object.values(registerCounts).reduce((a, b) => a + b, 0)
  const count = (db.prepare('SELECT COUNT(*) AS n FROM entities').get() as { n: number }).n
  return c.json({ status: 'reset', entities: count, registerRows })
})

export default app
