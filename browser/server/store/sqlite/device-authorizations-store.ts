// ═══════════════════════════════════════════════════════════════════
// The device authorizations' SQLite half (TODO.ai-platform/10 — the
// RFC 8628 grant): the sync implementations behind the ServerStore
// device-authorization methods (sqlite-server-store.ts delegates here
// one-for-one, the pat-store.ts pattern). The D1 store implements the
// same surface in d1.ts.
//
// The doctrines carried:
//   - a plaintext code NEVER crosses the seam: the row holds the two
//     SHA-256 hashes (the UNIQUE lookup keys), no read projects a hash
//     onto a list surface;
//   - the decision + the consume are GUARDED updates (the pending row,
//   unexpired; the approved row, once) — a replay answers null, the row
//   stays for the audit;
//   - the erasure (op-accounts-store.ts's eraseOpAccount) removes the
//   rows outright — a dead account's ceremonies die with it.
//
// NODE-ONLY: better-sqlite3, received as the store instance's
// db parameter (TODO.restructure/28-D). The Worker bundle
// never sees this module.
// ═══════════════════════════════════════════════════════════════════

import type Database from 'better-sqlite3'
import { storeTimeToIso } from './factors-store'
import type { DeviceAuthorization } from '../../store'

/** The row → the seam's shape. The scopes cell parses defensively (a
 *  malformed cell reads as the empty set — never trusted, never breaking
 *  the read); the status narrows honestly (an unknown value reads as
 *  'pending'-dead: the decision + the consume guard on the literal). */
function toDeviceAuthorization(row: Record<string, unknown>): DeviceAuthorization {
  let scopes: string[] = []
  try {
    const parsed = JSON.parse((row.scopes as string | null) ?? '[]') as unknown
    if (Array.isArray(parsed)) scopes = parsed.filter((s): s is string => typeof s === 'string')
  } catch { /* a malformed scopes cell reads as none — the approval re-judges anyway */ }
  return {
    id: row.id as string,
    deviceCodeHash: row.device_code_hash as string,
    userCodeHash: row.user_code_hash as string,
    clientId: row.client_id as string,
    scopes,
    status: row.status as DeviceAuthorization['status'],
    userId: (row.user_id as string | null) ?? null,
    orgContext: (row.org_context as string | null) ?? null,
    intervalSeconds: (row.interval_seconds as number | null) ?? 5,
    lastPollAt: storeTimeToIso((row.last_poll_at as string | null) ?? null),
    createdAt: storeTimeToIso(row.created_at as string)!,
    expiresAt: storeTimeToIso(row.expires_at as string)!,
    decidedAt: storeTimeToIso((row.decided_at as string | null) ?? null),
  }
}

export function createDeviceAuthorization(db: Database.Database, input: {
  id: string
  deviceCodeHash: string
  userCodeHash: string
  clientId: string
  scopes: string[]
  intervalSeconds: number
  expiresAt: string
}): DeviceAuthorization {
  db.prepare(
    `INSERT INTO device_authorizations
       (id, device_code_hash, user_code_hash, client_id, scopes, interval_seconds, expires_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
  ).run(
    input.id, input.deviceCodeHash, input.userCodeHash, input.clientId,
    JSON.stringify(input.scopes), input.intervalSeconds, input.expiresAt,
  )
  return getDeviceAuthorization(db, input.id)!
}

export function getDeviceAuthorization(db: Database.Database, id: string): DeviceAuthorization | null {
  const row = db.prepare('SELECT * FROM device_authorizations WHERE id = ?').get(id) as Record<string, unknown> | undefined
  return row ? toDeviceAuthorization(row) : null
}

export function findDeviceAuthorizationByDeviceCodeHash(db: Database.Database, hash: string): DeviceAuthorization | null {
  const row = db.prepare('SELECT * FROM device_authorizations WHERE device_code_hash = ?').get(hash) as Record<string, unknown> | undefined
  return row ? toDeviceAuthorization(row) : null
}

export function findDeviceAuthorizationByUserCodeHash(db: Database.Database, hash: string): DeviceAuthorization | null {
  const row = db.prepare('SELECT * FROM device_authorizations WHERE user_code_hash = ?').get(hash) as Record<string, unknown> | undefined
  return row ? toDeviceAuthorization(row) : null
}

/** The guarded decision: the LIVE, unexpired, pending row flips once
 *  (the route's decidedAt is the expiry comparison's clock — ISO cells
 *  compare lexically). */
export function decideDeviceAuthorization(db: Database.Database,
  id: string,
  decision: { userId: string; orgContext: string | null; approve: boolean; decidedAt: string },
): DeviceAuthorization | null {
  const changes = db.prepare(
    `UPDATE device_authorizations
       SET status = ?, user_id = ?, org_context = ?, decided_at = ?
     WHERE id = ? AND status = 'pending' AND expires_at > ?`,
  ).run(decision.approve ? 'approved' : 'denied', decision.userId, decision.orgContext, decision.decidedAt, id, decision.decidedAt).changes
  return changes > 0 ? getDeviceAuthorization(db, id) : null
}

/** The poll stamp: lastPollAt always; the slow_down bump when the route
 *  judged one (RFC 8628 §3.5's interval growth). */
export function stampDeviceAuthorizationPoll(db: Database.Database, id: string, polledAt: string, intervalSeconds?: number): void {
  db.prepare('UPDATE device_authorizations SET last_poll_at = ? WHERE id = ?').run(polledAt, id)
  if (intervalSeconds !== undefined) {
    db.prepare('UPDATE device_authorizations SET interval_seconds = ? WHERE id = ?').run(intervalSeconds, id)
  }
}

/** The one-time consume: the approved row flips to consumed in the same
 *  breath the caller reads it (a second present answers null). */
export function consumeDeviceAuthorization(db: Database.Database, id: string): DeviceAuthorization | null {
  const changes = db.prepare(
    "UPDATE device_authorizations SET status = 'consumed' WHERE id = ? AND status = 'approved'",
  ).run(id).changes
  return changes > 0 ? getDeviceAuthorization(db, id) : null
}
