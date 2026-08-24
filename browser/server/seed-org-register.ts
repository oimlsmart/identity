// ═══════════════════════════════════════════════════════════════════
// The org-register snapshot seed (the extraction map, smart's
// PROGRESS/41 §3): the identity service's dev/e2e posture reads the
// vendored demonstration register (browser/data/
// org-register.snapshot.yaml) into the entity store, so the join
// selector and the org-admin/registry consoles have real rows. The
// production feed from published content is a later wave (either
// repo), unchanged by the extraction — production degrades honestly
// (the "not listed" path routes to the scheme operator).
//
// NODE-ONLY (node:fs) — the dev-reset seam and the e2e stacks consume
// this; the Worker never imports it.
// ═══════════════════════════════════════════════════════════════════

import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { load as parseYaml } from 'js-yaml'
import type { ServerStore } from '@oimlsmart/platform-server/store'

const SNAPSHOT = join(dirname(fileURLToPath(import.meta.url)), '..', 'data', 'org-register.snapshot.yaml')

interface OrgRegisterSnapshot {
  organizations?: Array<Record<string, unknown>>
  utilizers?: Array<Record<string, unknown>>
  associates?: Array<Record<string, unknown>>
  participantDeclarations?: Array<Record<string, unknown>>
  participantApplications?: Array<Record<string, unknown>>
}

/** Upsert the snapshot into the entity store. Idempotent. Answers the
 *  per-collection counts for the caller's log line. */
export async function seedOrgRegisterSnapshot(store: ServerStore): Promise<Record<string, number>> {
  const snapshot = parseYaml(readFileSync(SNAPSHOT, 'utf-8')) as OrgRegisterSnapshot
  const counts: Record<string, number> = {}
  for (const [storeName, rows] of Object.entries(snapshot)) {
    if (!Array.isArray(rows)) continue
    let n = 0
    for (const row of rows) {
      const id = String(row.id ?? '')
      if (!id) continue
      await store.putEntity(storeName, id, null, JSON.stringify(row))
      n += 1
    }
    counts[storeName] = n
  }
  return counts
}
