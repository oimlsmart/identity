// ═══════════════════════════════════════════════════════════════════
// The upstream providers' SQLite half (TODO.identity/08) — the sync
// implementations behind the ServerStore upstream methods
// (sqlite-server-store.ts delegates here one-for-one, mirroring
// op-store.ts's role for the OP domain).
//
// Two tables:
//   identity_providers — the upstream registry (GitHub + Google + Apple
//     + Entra + generic OIDC; the client secret is NEVER stored, only
//     the env reference);
//   identity_links — the linked identities (TODO.identity/02's shape,
//     landed additively here): THE match rule for an upstream sign-in
//     is (provider, provider_account_id) — NEVER email alone.
//
// NODE-ONLY: better-sqlite3, received as the store instance's
// db parameter (TODO.restructure/28-D). The Worker bundle
// never sees this module (the D1 store implements the same surface in
// d1-store.ts).
// ═══════════════════════════════════════════════════════════════════

import type Database from 'better-sqlite3'
import { randomUUID } from 'crypto'
import type { IdentityLink, IdentityProvider } from '../../store'

function toIdentityProvider(row: Record<string, unknown>): IdentityProvider {
  return {
    id: row.id as string,
    kind: row.kind as IdentityProvider['kind'],
    displayName: row.display_name as string,
    brandMark: (row.brand_mark as string | null) ?? null,
    issuer: (row.issuer as string | null) ?? null,
    clientId: row.client_id as string,
    clientSecretRef: (row.client_secret_ref as string | null) ?? null,
    scopes: (row.scopes as string | null) ?? null,
    enabled: row.enabled === 1,
    createdAt: row.created_at as string,
    createdBy: (row.created_by as string | null) ?? null,
    updatedAt: (row.updated_at as string | null) ?? null,
  }
}

export function listIdentityProviders(db: Database.Database): IdentityProvider[] {
  const rows = db.prepare('SELECT * FROM identity_providers ORDER BY created_at, id').all() as Array<Record<string, unknown>>
  return rows.map(toIdentityProvider)
}

export function getIdentityProvider(db: Database.Database, id: string): IdentityProvider | null {
  const row = db.prepare('SELECT * FROM identity_providers WHERE id = ?').get(id) as Record<string, unknown> | undefined
  return row ? toIdentityProvider(row) : null
}

export function upsertIdentityProvider(db: Database.Database, input: {
  id: string
  kind: IdentityProvider['kind']
  displayName: string
  brandMark?: string | null
  issuer?: string | null
  clientId: string
  clientSecretRef?: string | null
  scopes?: string | null
  enabled?: boolean
  createdBy?: string | null
}): IdentityProvider {
  db.prepare(`
    INSERT INTO identity_providers
      (id, kind, display_name, brand_mark, issuer, client_id, client_secret_ref, scopes, enabled, created_by)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT (id) DO UPDATE SET
      kind = excluded.kind,
      display_name = excluded.display_name,
      brand_mark = excluded.brand_mark,
      issuer = excluded.issuer,
      client_id = excluded.client_id,
      client_secret_ref = excluded.client_secret_ref,
      scopes = excluded.scopes,
      enabled = excluded.enabled,
      updated_at = datetime('now')
  `).run(
    input.id,
    input.kind,
    input.displayName,
    input.brandMark ?? null,
    input.issuer ?? null,
    input.clientId,
    input.clientSecretRef ?? null,
    input.scopes ?? null,
    // Disabled by default (the schema's DEFAULT 0): a provider becomes
    // visible to the login page only by a deliberate enable.
    input.enabled ? 1 : 0,
    input.createdBy ?? null,
  )
  return getIdentityProvider(db, input.id)!
}

export function setIdentityProviderEnabled(db: Database.Database, id: string, enabled: boolean): IdentityProvider | null {
  const res = db.prepare("UPDATE identity_providers SET enabled = ?, updated_at = datetime('now') WHERE id = ?")
    .run(enabled ? 1 : 0, id)
  return res.changes > 0 ? getIdentityProvider(db, id) : null
}

export function deleteIdentityProvider(db: Database.Database, id: string): boolean {
  const res = db.prepare('DELETE FROM identity_providers WHERE id = ?').run(id)
  return res.changes > 0
}

// ── the linked identities ────────────────────────────────────────────

function toIdentityLink(row: Record<string, unknown>): IdentityLink {
  return {
    id: row.id as string,
    userId: row.user_id as string,
    provider: row.provider as string,
    providerAccountId: row.provider_account_id as string,
    linkedAt: row.linked_at as string,
    linkedBy: (row.linked_by as string | null) ?? null,
  }
}

export function listIdentityLinks(db: Database.Database, userId: string): IdentityLink[] {
  const rows = db.prepare('SELECT * FROM identity_links WHERE user_id = ? ORDER BY linked_at, provider').all(userId) as Array<Record<string, unknown>>
  return rows.map(toIdentityLink)
}

/** The bulk list-endpoint variant (identity's TODO.restructure/06): the
 *  same rows for every id, ONE read for the whole set, grouped in
 *  memory. The single ORDER BY keeps each account's links in the
 *  per-id read's own (linked_at, provider) order. */
export function listIdentityLinksBulk(db: Database.Database, userIds: string[]): Map<string, IdentityLink[]> {
  const answer = new Map<string, IdentityLink[]>(userIds.map(id => [id, []]))
  if (userIds.length === 0) return answer
  const placeholders = userIds.map(() => '?').join(',')
  const rows = db
    .prepare(`SELECT * FROM identity_links WHERE user_id IN (${placeholders}) ORDER BY linked_at, provider`)
    .all(...userIds) as Array<Record<string, unknown>>
  for (const row of rows) {
    const link = toIdentityLink(row)
    answer.get(link.userId)?.push(link)
  }
  return answer
}

export function findIdentityLink(db: Database.Database, provider: string, providerAccountId: string): IdentityLink | null {
  const row = db.prepare('SELECT * FROM identity_links WHERE provider = ? AND provider_account_id = ?')
    .get(provider, providerAccountId) as Record<string, unknown> | undefined
  return row ? toIdentityLink(row) : null
}

/** Create the link; NULL on the UNIQUE(provider, provider_account_id)
 *  conflict — the pair is already linked (to any account). */
export function createIdentityLink(db: Database.Database, input: {
  userId: string
  provider: string
  providerAccountId: string
  linkedBy?: string | null
}): IdentityLink | null {
  const id = randomUUID()
  const res = db.prepare(
    'INSERT OR IGNORE INTO identity_links (id, user_id, provider, provider_account_id, linked_by) VALUES (?, ?, ?, ?, ?)',
  ).run(id, input.userId, input.provider, input.providerAccountId, input.linkedBy ?? null)
  if (res.changes === 0) return null
  return findIdentityLink(db, input.provider, input.providerAccountId)
}

export function deleteIdentityLink(db: Database.Database, userId: string, provider: string): boolean {
  const res = db.prepare('DELETE FROM identity_links WHERE user_id = ? AND provider = ?').run(userId, provider)
  return res.changes > 0
}
