// ═══════════════════════════════════════════════════════════════════
// The remembered consent grants' SQLite half (TODO.identity-features/12)
// — the sync implementations behind the ServerStore consent-grant
// methods (sqlite-server-store.ts delegates here one-for-one, the
// pat-store.ts pattern). The D1 store implements the same surface in
// d1.ts.
//
// The doctrines carried:
//   - ONE LIVE grant per (user, client, scope set): the partial unique
//     index (migration 0021) is the backstop; the record path's upsert
//     targets it, so a repeat allow refreshes the live row's stamp and a
//     REVOKED triple's re-allow lands a fresh row (the history survives);
//   - the scope cell is the CANONICAL spelling (normalizeOidcScopeSet) —
//     written normalized, read defensively (a hand-edited row still reads
//     as a set, never trusted as a string match);
//   - the revoke is a GUARDED update (the owner's live row flips, once);
//   - the erasure (op-accounts-store.ts's eraseOpAccount) removes the
//     rows outright — a dead account's grants die with it.
//
// NODE-ONLY: better-sqlite3, received as the store instance's
// db parameter (TODO.restructure/28-D). The Worker bundle
// never sees this module.
// ═══════════════════════════════════════════════════════════════════

import type Database from 'better-sqlite3'
import { randomUUID } from 'crypto'
import { storeTimeToIso } from './factors-store'
import { consentGrantCovers, normalizeOidcScopeSet, type OidcConsentGrant } from '../../store'

function toConsentGrant(row: Record<string, unknown>): OidcConsentGrant {
  return {
    id: row.id as string,
    userId: row.user_id as string,
    clientId: row.client_id as string,
    scope: row.scope as string,
    createdAt: storeTimeToIso(row.created_at as string)!,
    revokedAt: storeTimeToIso((row.revoked_at as string | null) ?? null),
  }
}

/** The authorize endpoint's remembered-consent read: the account's LIVE
 *  grant for this client whose scope set COVERS the requested set (the
 *  freshest first, when several cover). */
export function getConsentGrant(db: Database.Database, userId: string, clientId: string, scope: string): OidcConsentGrant | null {
  const rows = db.prepare(
    'SELECT * FROM oidc_consent_grants WHERE user_id = ? AND client_id = ? AND revoked_at IS NULL ORDER BY created_at DESC, rowid DESC',
  ).all(userId, clientId) as Array<Record<string, unknown>>
  for (const row of rows) {
    if (consentGrantCovers(row.scope as string, scope)) return toConsentGrant(row)
  }
  return null
}

/** The consent decision's remember (the allow): the upsert on the live
 *  triple refreshes the stamp; a revoked triple's re-allow inserts fresh
 *  (the partial unique index's predicate keeps the revoked row out of the
 *  collision). Answers the live row. */
export function recordConsentGrant(db: Database.Database, input: { userId: string; clientId: string; scope: string }): OidcConsentGrant {
  const scope = normalizeOidcScopeSet(input.scope)
  db.prepare(
    `INSERT INTO oidc_consent_grants (id, user_id, client_id, scope)
     VALUES (?, ?, ?, ?)
     ON CONFLICT (user_id, client_id, scope) WHERE revoked_at IS NULL
     DO UPDATE SET created_at = datetime('now')`,
  ).run(randomUUID(), input.userId, input.clientId, scope)
  const row = db.prepare(
    'SELECT * FROM oidc_consent_grants WHERE user_id = ? AND client_id = ? AND scope = ? AND revoked_at IS NULL',
  ).get(input.userId, input.clientId, scope) as Record<string, unknown> | undefined
  if (!row) throw new Error('recordConsentGrant: the upsert left no live row')
  return toConsentGrant(row)
}

/** The console's list: the account's LIVE grants, newest first. */
export function listConsentGrants(db: Database.Database, userId: string): OidcConsentGrant[] {
  const rows = db.prepare(
    'SELECT * FROM oidc_consent_grants WHERE user_id = ? AND revoked_at IS NULL ORDER BY created_at DESC, rowid DESC',
  ).all(userId) as Array<Record<string, unknown>>
  return rows.map(toConsentGrant)
}

/** The client-registry governance view's per-client read: EVERY grant row
 *  the client holds — live AND revoked, newest first. */
export function listOidcConsentGrantsForClient(db: Database.Database, clientId: string): OidcConsentGrant[] {
  const rows = db.prepare(
    'SELECT * FROM oidc_consent_grants WHERE client_id = ? ORDER BY created_at DESC, rowid DESC',
  ).all(clientId) as Array<Record<string, unknown>>
  return rows.map(toConsentGrant)
}

/** The guarded revoke: the owner's LIVE row flips, once. */
export function revokeConsentGrant(db: Database.Database, id: string, userId: string): boolean {
  return db.prepare(
    "UPDATE oidc_consent_grants SET revoked_at = datetime('now') WHERE id = ? AND user_id = ? AND revoked_at IS NULL",
  ).run(id, userId).changes > 0
}
