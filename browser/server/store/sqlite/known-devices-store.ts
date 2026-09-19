// ═══════════════════════════════════════════════════════════════════
// The known-devices' SQLite rows (TODO.modern/06's risk signals) —
// the webhook-store pattern: free functions over the shared handle.
// The D1 store implements the same surface in server/store/d1.ts;
// the schema arrives via schema.sql + 0030_known_devices.sql
// (the lockstep the migrations test pins).
// ═══════════════════════════════════════════════════════════════════

import type Database from 'better-sqlite3'
import type { KnownDeviceRow, KnownDeviceSighting } from '../../store'

interface DeviceRow {
  id: string
  account_id: string
  device_hash: string
  user_agent: string | null
  ip: string | null
  first_country: string | null
  last_country: string | null
  first_seen_at: string
  last_seen_at: string
}

function toDevice(row: DeviceRow): KnownDeviceRow {
  return {
    id: row.id,
    accountId: row.account_id,
    deviceHash: row.device_hash,
    userAgent: row.user_agent,
    ip: row.ip,
    firstCountry: row.first_country,
    lastCountry: row.last_country,
    firstSeenAt: row.first_seen_at,
    lastSeenAt: row.last_seen_at,
  }
}

export function recordKnownDevice(
  db: Database.Database,
  input: { id: string; accountId: string; deviceHash: string; userAgent: string | null; ip: string | null; country: string | null },
): KnownDeviceSighting {
  const prior = db.prepare(
    'SELECT last_country, last_seen_at FROM known_devices WHERE account_id = ? AND device_hash = ?',
  ).get(input.accountId, input.deviceHash) as { last_country: string | null; last_seen_at: string } | undefined
  db.prepare(
    `INSERT INTO known_devices (id, account_id, device_hash, user_agent, ip, first_country, last_country)
     VALUES (?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(account_id, device_hash) DO UPDATE SET
       user_agent = excluded.user_agent,
       ip = excluded.ip,
       last_country = excluded.last_country,
       last_seen_at = datetime('now')`,
  ).run(input.id, input.accountId, input.deviceHash, input.userAgent, input.ip, input.country, input.country)
  return {
    isNew: !prior,
    previousCountry: prior?.last_country ?? null,
    previousSeenAt: prior?.last_seen_at ?? null,
  }
}

export function listKnownDevices(db: Database.Database, accountId: string): KnownDeviceRow[] {
  const rows = db.prepare(
    'SELECT * FROM known_devices WHERE account_id = ? ORDER BY last_seen_at DESC, rowid DESC',
  ).all(accountId) as DeviceRow[]
  return rows.map(toDevice)
}
