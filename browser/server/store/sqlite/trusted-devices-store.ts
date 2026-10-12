// ═══════════════════════════════════════════════════════════════════
// The trusted-device MFA skip's rows (0042, the SOTA arc): the
// webhook-store pattern — free functions over the shared handle. The
// D1 store implements the same surface; the schema arrives via
// schema.sql + 0042 (the lockstep the migrations test pins).
// ═══════════════════════════════════════════════════════════════════

import type Database from 'better-sqlite3'
import type { TrustedDeviceRow } from '../../store'

interface Row {
  id: string
  account_id: string
  token_hash: string
  user_agent: string | null
  ip: string | null
  created_at: string
  last_used_at: string | null
  expires_at: string
}

function toRow(row: Row): TrustedDeviceRow {
  return {
    id: row.id,
    accountId: row.account_id,
    tokenHash: row.token_hash,
    userAgent: row.user_agent,
    ip: row.ip,
    createdAt: row.created_at,
    lastUsedAt: row.last_used_at,
    expiresAt: row.expires_at,
  }
}

export function createMfaTrustedDevice(db: Database.Database, input: { id: string; accountId: string; tokenHash: string; userAgent: string | null; ip: string | null; ttlMs: number }): void {
  db.prepare("DELETE FROM mfa_trusted_devices WHERE expires_at <= datetime('now')").run()
  db.prepare('INSERT INTO mfa_trusted_devices (id, account_id, token_hash, user_agent, ip, expires_at) VALUES (?, ?, ?, ?, ?, ?)')
    .run(input.id, input.accountId, input.tokenHash, input.userAgent, input.ip, new Date(Date.now() + input.ttlMs).toISOString())
}

/** The live row for a token hash (the cookie's proof) — null when
 *  absent or expired; a match stamps last_used_at (the list's honesty). */
export function findLiveMfaTrustedDevice(db: Database.Database, accountId: string, tokenHash: string): TrustedDeviceRow | null {
  const row = db.prepare('SELECT * FROM mfa_trusted_devices WHERE account_id = ? AND token_hash = ? AND expires_at > datetime(\'now\')')
    .get(accountId, tokenHash) as Row | undefined
  if (!row) return null
  db.prepare("UPDATE mfa_trusted_devices SET last_used_at = datetime('now') WHERE id = ?").run(row.id)
  return toRow(row)
}

export function listMfaTrustedDevices(db: Database.Database, accountId: string): TrustedDeviceRow[] {
  db.prepare("DELETE FROM mfa_trusted_devices WHERE expires_at <= datetime('now')").run()
  return (db.prepare('SELECT * FROM mfa_trusted_devices WHERE account_id = ? ORDER BY created_at DESC').all(accountId) as Row[]).map(toRow)
}

export function revokeMfaTrustedDevice(db: Database.Database, id: string, accountId: string): boolean {
  return db.prepare('DELETE FROM mfa_trusted_devices WHERE id = ? AND account_id = ?').run(id, accountId).changes > 0
}

export function revokeMfaTrustedDevicesForUser(db: Database.Database, accountId: string): number {
  return db.prepare('DELETE FROM mfa_trusted_devices WHERE account_id = ?').run(accountId).changes
}
