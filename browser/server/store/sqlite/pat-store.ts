// ═══════════════════════════════════════════════════════════════════
// The personal access tokens' SQLite half (TODO.identity-features/08) —
// the sync implementations behind the ServerStore PAT methods
// (sqlite-server-store.ts delegates here one-for-one, the
// factors-store.ts pattern). The D1 store implements the same surface
// in d1.ts.
//
// The doctrines carried:
//   - the plaintext NEVER crosses the seam: the row holds the SHA-256
//     (token_hash, the exchange's UNIQUE lookup key) + the display
//     prefix, and no read projects the hash onto a list surface;
//   - the revoke is a GUARDED update (the live row, the owner's) — a
//     replay or a foreign owner answers false, the row stays for the
//     audit + the org inventory;
//   - the erasure (op-accounts-store.ts's eraseOpAccount) removes the
//     rows outright — a dead account's tokens die with it.
//
// NODE-ONLY: better-sqlite3 through ./store's getDb. The Worker bundle
// never sees this module.
// ═══════════════════════════════════════════════════════════════════

import { getDb } from './store'
import { storeTimeToIso } from './factors-store'
import type { PersonalAccessToken } from '../../store'

/** The row → the seam's shape. The scopes cell parses defensively (a
 *  hand-edited row's malformed JSON reads as the empty set — never
 *  trusted, never breaking the read). */
function toPersonalAccessToken(row: Record<string, unknown>): PersonalAccessToken {
  let scopes: string[] = []
  try {
    const parsed = JSON.parse((row.scopes as string | null) ?? '[]') as unknown
    if (Array.isArray(parsed)) scopes = parsed.filter((s): s is string => typeof s === 'string')
  } catch { /* a malformed scopes cell reads as none — the token exchanges nothing */ }
  return {
    id: row.id as string,
    userId: row.user_id as string,
    name: row.name as string,
    tokenHash: row.token_hash as string,
    tokenPrefix: row.token_prefix as string,
    scopes,
    orgContext: (row.org_context as string | null) ?? null,
    createdAt: storeTimeToIso(row.created_at as string)!,
    expiresAt: storeTimeToIso(row.expires_at as string)!,
    lastUsedAt: storeTimeToIso((row.last_used_at as string | null) ?? null),
    lastExchangeAuditAt: storeTimeToIso((row.last_exchange_audit_at as string | null) ?? null),
    expiryNotifiedAt: storeTimeToIso((row.expiry_notified_at as string | null) ?? null),
    revokedAt: storeTimeToIso((row.revoked_at as string | null) ?? null),
    revokedBy: (row.revoked_by as string | null) ?? null,
  }
}

export function createPersonalAccessToken(input: {
  id: string
  userId: string
  name: string
  tokenHash: string
  tokenPrefix: string
  scopes: string[]
  orgContext: string | null
  expiresAt: string
}): PersonalAccessToken {
  getDb().prepare(
    `INSERT INTO personal_access_tokens
       (id, user_id, name, token_hash, token_prefix, scopes, org_context, expires_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
  ).run(
    input.id, input.userId, input.name, input.tokenHash, input.tokenPrefix,
    JSON.stringify(input.scopes), input.orgContext, input.expiresAt,
  )
  return getPersonalAccessToken(input.id)!
}

export function listPersonalAccessTokens(userId: string): PersonalAccessToken[] {
  // created_at is second-resolution (datetime('now')) — the rowid breaks
  // the tie so the newest mint leads even within one second.
  const rows = getDb().prepare(
    'SELECT * FROM personal_access_tokens WHERE user_id = ? ORDER BY created_at DESC, rowid DESC',
  ).all(userId) as Array<Record<string, unknown>>
  return rows.map(toPersonalAccessToken)
}

/** The org inventory: every token whose holder carries a membership row
 *  for the org (ANY state — the oversight surface hunts the disabled
 *  member's live token too), newest first. */
export function listOrgPersonalAccessTokens(orgId: string): PersonalAccessToken[] {
  const rows = getDb().prepare(
    `SELECT p.* FROM personal_access_tokens p
     JOIN org_memberships m ON m.user_id = p.user_id
     WHERE m.org_id = ?
     ORDER BY p.created_at DESC, p.id`,
  ).all(orgId) as Array<Record<string, unknown>>
  return rows.map(toPersonalAccessToken)
}

export function getPersonalAccessToken(id: string): PersonalAccessToken | null {
  const row = getDb().prepare('SELECT * FROM personal_access_tokens WHERE id = ?').get(id) as Record<string, unknown> | undefined
  return row ? toPersonalAccessToken(row) : null
}

export function findPersonalAccessTokenByHash(tokenHash: string): PersonalAccessToken | null {
  const row = getDb().prepare('SELECT * FROM personal_access_tokens WHERE token_hash = ?').get(tokenHash) as Record<string, unknown> | undefined
  return row ? toPersonalAccessToken(row) : null
}

/** The guarded revoke: the owner's LIVE row flips, once. */
export function revokePersonalAccessToken(id: string, userId: string, revokedBy: string): boolean {
  return getDb().prepare(
    "UPDATE personal_access_tokens SET revoked_at = datetime('now'), revoked_by = ? WHERE id = ? AND user_id = ? AND revoked_at IS NULL",
  ).run(revokedBy, id, userId).changes > 0
}

/** The exchange path's stamp (the throttled heartbeat + the expiry-soon
 *  mailer's one-shot mark — the route decides, the store writes). */
export function stampPersonalAccessTokenUse(
  id: string,
  stamps: { usedAt: string; auditAt?: string | null; expiryNotifiedAt?: string | null },
): void {
  const db = getDb()
  db.prepare('UPDATE personal_access_tokens SET last_used_at = ? WHERE id = ?').run(stamps.usedAt, id)
  if (stamps.auditAt) {
    db.prepare('UPDATE personal_access_tokens SET last_exchange_audit_at = ? WHERE id = ?').run(stamps.auditAt, id)
  }
  if (stamps.expiryNotifiedAt) {
    db.prepare('UPDATE personal_access_tokens SET expiry_notified_at = ? WHERE id = ?').run(stamps.expiryNotifiedAt, id)
  }
}
