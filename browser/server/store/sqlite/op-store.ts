// ═══════════════════════════════════════════════════════════════════
// The OIDC Provider's SQLite half (TODO.identity/01) — the sync
// implementations behind the ServerStore OP methods
// (sqlite-server-store.ts delegates here one-for-one, mirroring
// store.ts's role for the auth domain).
//
// NODE-ONLY: better-sqlite3 through ./store's getDb. The Worker bundle
// never sees this module (the D1 store implements the same surface in
// d1-store.ts).
// ═══════════════════════════════════════════════════════════════════

import { getDb } from './store'
import type {
  ConsumeOidcRefreshTokenResult,
  OidcAccessToken,
  OidcAuthorization,
  OidcClient,
  OidcClientLaunch,
  OidcCode,
  OidcKeyRow,
  OidcRefreshToken,
} from '../../store'

function toOidcClient(row: Record<string, unknown>): OidcClient {
  return {
    clientId: row.client_id as string,
    name: row.name as string,
    secretHash: (row.secret_hash as string | null) ?? null,
    redirectUris: JSON.parse(row.redirect_uris as string) as string[],
    claimsPolicy: row.claims_policy ? JSON.parse(row.claims_policy as string) as OidcClient['claimsPolicy'] : null,
    // The SSO-home launch metadata (migration 0011): no launch_url = the
    // client never appears on the launcher. A pre-0011 database reads
    // the columns as absent — launch stays null, the honest default.
    launch: row.launch_url
      ? {
          url: row.launch_url as string,
          icon: (row.launch_icon as string | null) ?? null,
          description: (row.launch_description as string | null) ?? null,
          visibility: ((row.launch_visibility as string | null) ?? 'roles') as OidcClientLaunch['visibility'],
        }
      : null,
    status: row.status as OidcClient['status'],
    createdAt: row.created_at as string,
    createdBy: (row.created_by as string | null) ?? null,
  }
}

function toOidcAuthorization(row: Record<string, unknown>): OidcAuthorization {
  return {
    id: row.id as string,
    clientId: row.client_id as string,
    redirectUri: row.redirect_uri as string,
    scope: row.scope as string,
    state: row.state as string,
    nonce: (row.nonce as string | null) ?? null,
    codeChallenge: row.code_challenge as string,
    userId: (row.user_id as string | null) ?? null,
    decision: (row.decision as OidcAuthorization['decision']) ?? null,
    createdAt: row.created_at as string,
    expiresAt: row.expires_at as string,
  }
}

export function getOidcClient(clientId: string): OidcClient | null {
  const row = getDb().prepare('SELECT * FROM oidc_clients WHERE client_id = ?').get(clientId) as Record<string, unknown> | undefined
  return row ? toOidcClient(row) : null
}

export function listOidcClients(): OidcClient[] {
  const rows = getDb().prepare('SELECT * FROM oidc_clients ORDER BY created_at, client_id').all() as Array<Record<string, unknown>>
  return rows.map(toOidcClient)
}

export function upsertOidcClient(input: {
  clientId: string
  name: string
  secretHash: string | null
  redirectUris: string[]
  claimsPolicy: { claims: string[] } | null
  createdBy?: string | null
}): OidcClient {
  getDb().prepare(`
    INSERT INTO oidc_clients (client_id, name, secret_hash, redirect_uris, claims_policy, created_by)
    VALUES (?, ?, ?, ?, ?, ?)
    ON CONFLICT (client_id) DO UPDATE SET
      name = excluded.name,
      secret_hash = excluded.secret_hash,
      redirect_uris = excluded.redirect_uris,
      claims_policy = excluded.claims_policy
  `).run(
    input.clientId,
    input.name,
    input.secretHash,
    JSON.stringify(input.redirectUris),
    input.claimsPolicy ? JSON.stringify(input.claimsPolicy) : null,
    input.createdBy ?? null,
  )
  return getOidcClient(input.clientId)!
}

export function setOidcClientStatus(clientId: string, status: OidcClient['status']): OidcClient | null {
  const res = getDb().prepare('UPDATE oidc_clients SET status = ? WHERE client_id = ?').run(status, clientId)
  return res.changes > 0 ? getOidcClient(clientId) : null
}

/** The SSO-home launch metadata write (migration 0011): the launcher's
 *  card, or null to take the client off it. The registry upsert above
 *  never touches these columns, so a re-seed keeps the admin's edits. */
export function setOidcClientLaunch(clientId: string, launch: OidcClientLaunch | null): OidcClient | null {
  const res = getDb().prepare(`
    UPDATE oidc_clients SET launch_url = ?, launch_icon = ?, launch_description = ?, launch_visibility = ?
    WHERE client_id = ?
  `).run(
    launch?.url ?? null,
    launch?.icon ?? null,
    launch?.description ?? null,
    launch?.visibility ?? 'roles',
    clientId,
  )
  return res.changes > 0 ? getOidcClient(clientId) : null
}

export function createOidcAuthorization(input: {
  id: string
  clientId: string
  redirectUri: string
  scope: string
  state: string
  nonce: string | null
  codeChallenge: string
  userId: string | null
  ttlMs: number
}): OidcAuthorization {
  const expiresAt = new Date(Date.now() + input.ttlMs).toISOString()
  getDb().prepare(`
    INSERT INTO oidc_authorizations
      (id, client_id, redirect_uri, scope, state, nonce, code_challenge, user_id, expires_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    input.id, input.clientId, input.redirectUri, input.scope, input.state,
    input.nonce, input.codeChallenge, input.userId, expiresAt,
  )
  return getOidcAuthorization(input.id)!
}

export function getOidcAuthorization(id: string): OidcAuthorization | null {
  const row = getDb().prepare('SELECT * FROM oidc_authorizations WHERE id = ?').get(id) as Record<string, unknown> | undefined
  return row ? toOidcAuthorization(row) : null
}

export function decideOidcAuthorization(
  id: string,
  decision: { userId: string; decision: 'allow' | 'deny' },
): OidcAuthorization | null {
  // The decision binds to the row's OWN account (userId must equal the
  // row's stamped user) and flips atomically — a decided or
  // cross-account row loses the race.
  const res = getDb().prepare(
    'UPDATE oidc_authorizations SET decision = ? WHERE id = ? AND decision IS NULL AND user_id = ?',
  ).run(decision.decision, id, decision.userId)
  return res.changes > 0 ? getOidcAuthorization(id) : null
}

export function createOidcCode(input: {
  code: string
  clientId: string
  redirectUri: string
  scope: string
  nonce: string | null
  codeChallenge: string
  userId: string
  /** TODO.identity/11: the session's stamped active-org context at the
   *  consent decision (NULL = the primary context). */
  contextOrg?: string | null
  /** TODO.identity-sso/02+03: the consenting session's amr provenance
   *  (stored as JSON; the token endpoint emits it as the ID token's
   *  amr). Absent = no provenance recorded. */
  amr?: string[] | null
  /** TODO.identity-sso (the wave-A tail): the consenting session's
   *  authentication instant (verbatim; absent = none recorded) — the
   *  token endpoint emits it as the ID token's auth_time. */
  authTime?: string | null
  ttlMs: number
}): void {
  const expiresAt = new Date(Date.now() + input.ttlMs).toISOString()
  getDb().prepare(`
    INSERT INTO oidc_codes (code, client_id, redirect_uri, scope, nonce, code_challenge, user_id, context_org, amr, auth_time, expires_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(input.code, input.clientId, input.redirectUri, input.scope, input.nonce, input.codeChallenge, input.userId,
    input.contextOrg ?? null, input.amr?.length ? JSON.stringify(input.amr) : null, input.authTime ?? null, expiresAt)
}

/** Atomically consume the code: the UPDATE flips consumed_at exactly
 *  once — a replay loses the race and answers null (→ invalid_grant).
 *  An expired code is consumed too (never a second chance). */
export function consumeOidcCode(code: string): OidcCode | null {
  const db = getDb()
  const res = db.prepare("UPDATE oidc_codes SET consumed_at = datetime('now') WHERE code = ? AND consumed_at IS NULL").run(code)
  if (res.changes === 0) return null
  const row = db.prepare('SELECT * FROM oidc_codes WHERE code = ?').get(code) as Record<string, unknown> | undefined
  if (!row) return null
  if (new Date(row.expires_at as string).getTime() <= Date.now()) return null
  return {
    code: row.code as string,
    clientId: row.client_id as string,
    redirectUri: row.redirect_uri as string,
    scope: row.scope as string,
    nonce: (row.nonce as string | null) ?? null,
    codeChallenge: row.code_challenge as string,
    userId: row.user_id as string,
    contextOrg: (row.context_org as string | null) ?? null,
    amr: parseJsonStringList(row.amr),
    authTime: (row.auth_time as string | null) ?? null,
    expiresAt: row.expires_at as string,
  }
}

export function createOidcAccessToken(input: {
  token: string
  userId: string
  clientId: string
  scope: string
  /** The granting code's context (userinfo answers the ID token's
   *  claims). */
  contextOrg?: string | null
  /** TODO.identity-sso/02+03: the authorizing authentication's amr —
   *  userinfo answers the same truth the ID token carried. */
  amr?: string[] | null
  ttlMs: number
}): void {
  const expiresAt = new Date(Date.now() + input.ttlMs).toISOString()
  getDb().prepare(
    'INSERT INTO oidc_access_tokens (token, user_id, client_id, scope, context_org, amr, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
  ).run(input.token, input.userId, input.clientId, input.scope, input.contextOrg ?? null,
    input.amr?.length ? JSON.stringify(input.amr) : null, expiresAt)
}

export function getOidcAccessToken(token: string): OidcAccessToken | null {
  const row = getDb().prepare(
    "SELECT * FROM oidc_access_tokens WHERE token = ? AND datetime(expires_at) > datetime('now')",
  ).get(token) as Record<string, unknown> | undefined
  if (!row) return null
  return {
    token: row.token as string,
    userId: row.user_id as string,
    clientId: row.client_id as string,
    scope: row.scope as string,
    contextOrg: (row.context_org as string | null) ?? null,
    amr: parseJsonStringList(row.amr),
    expiresAt: row.expires_at as string,
  }
}

/** The account console's per-app read + the governance view's per-user
 *  slice: the account's LIVE access tokens, newest first — created_at is
 *  second-resolution, the rowid breaks the tie. */
export function listOidcAccessTokens(userId: string): OidcAccessToken[] {
  const rows = getDb().prepare(
    "SELECT * FROM oidc_access_tokens WHERE user_id = ? AND datetime(expires_at) > datetime('now') ORDER BY created_at DESC, rowid DESC",
  ).all(userId) as Array<Record<string, unknown>>
  return rows.map(row => ({
    token: row.token as string,
    userId: row.user_id as string,
    clientId: row.client_id as string,
    scope: row.scope as string,
    contextOrg: (row.context_org as string | null) ?? null,
    amr: parseJsonStringList(row.amr),
    expiresAt: row.expires_at as string,
  }))
}

/** The RFC 7009 access-token revocation: the row goes, client-bound. */
export function deleteOidcAccessToken(token: string, clientId: string): boolean {
  const res = getDb().prepare('DELETE FROM oidc_access_tokens WHERE token = ? AND client_id = ?').run(token, clientId)
  return res.changes > 0
}

/** The governance view's population read: the client's LIVE access-token
 *  count (unexpired — the row's absence IS the revocation). */
export function countOidcAccessTokensForClient(clientId: string): number {
  const row = getDb().prepare(
    "SELECT COUNT(*) AS n FROM oidc_access_tokens WHERE client_id = ? AND datetime(expires_at) > datetime('now')",
  ).get(clientId) as { n: number }
  return row.n
}

function toOidcRefreshToken(row: Record<string, unknown>): OidcRefreshToken {
  return {
    token: row.token as string,
    userId: row.user_id as string,
    clientId: row.client_id as string,
    scope: row.scope as string,
    contextOrg: (row.context_org as string | null) ?? null,
    amr: parseJsonStringList(row.amr),
    authTime: (row.auth_time as string | null) ?? null,
    familyId: row.family_id as string,
    createdAt: row.created_at as string,
    expiresAt: row.expires_at as string,
    consumedAt: (row.consumed_at as string | null) ?? null,
  }
}

/** The refresh mint (migration 0025): the row carries the granting code's
 *  provenance verbatim — a rotation re-mints the SAME truth, auth_time
 *  never advances. */
export function createOidcRefreshToken(input: {
  token: string
  userId: string
  clientId: string
  scope: string
  contextOrg?: string | null
  amr?: string[] | null
  authTime?: string | null
  familyId: string
  ttlMs: number
}): OidcRefreshToken {
  const expiresAt = new Date(Date.now() + input.ttlMs).toISOString()
  getDb().prepare(`
    INSERT INTO oidc_refresh_tokens (token, user_id, client_id, scope, context_org, amr, auth_time, family_id, expires_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(input.token, input.userId, input.clientId, input.scope, input.contextOrg ?? null,
    input.amr?.length ? JSON.stringify(input.amr) : null, input.authTime ?? null, input.familyId, expiresAt)
  return toOidcRefreshToken(
    getDb().prepare('SELECT * FROM oidc_refresh_tokens WHERE token = ?').get(input.token) as Record<string, unknown>,
  )
}

/** The refresh exchange's consume: the UPDATE flips consumed_at exactly
 *  once — a replay loses the race, reads the consumed row back, and the
 *  WHOLE FAMILY dies (the theft signal, RFC 6819 §5.2.2.3; a concurrent
 *  double-present lands the same verdict — fail toward invalidation). An
 *  expired live row is consumed anyway (never a second chance) and
 *  answers 'invalid'. */
export function consumeOidcRefreshToken(token: string): ConsumeOidcRefreshTokenResult {
  const db = getDb()
  const res = db.prepare("UPDATE oidc_refresh_tokens SET consumed_at = datetime('now') WHERE token = ? AND consumed_at IS NULL").run(token)
  if (res.changes > 0) {
    const row = db.prepare('SELECT * FROM oidc_refresh_tokens WHERE token = ?').get(token) as Record<string, unknown>
    if (new Date(row.expires_at as string).getTime() <= Date.now()) return { kind: 'invalid' }
    return { kind: 'ok', token: toOidcRefreshToken(row) }
  }
  const row = db.prepare('SELECT * FROM oidc_refresh_tokens WHERE token = ?').get(token) as Record<string, unknown> | undefined
  if (!row) return { kind: 'invalid' }
  // The reuse signal: the consumed row's family dies outright.
  const familyId = row.family_id as string
  db.prepare('DELETE FROM oidc_refresh_tokens WHERE family_id = ?').run(familyId)
  return { kind: 'reuse', familyId, userId: row.user_id as string, clientId: row.client_id as string }
}

/** The RFC 7009 refresh revocation, client-bound: the presented token's
 *  family goes (never another client's rows). */
export function revokeOidcRefreshToken(token: string, clientId: string): boolean {
  const db = getDb()
  const row = db.prepare('SELECT family_id FROM oidc_refresh_tokens WHERE token = ? AND client_id = ?').get(token, clientId) as { family_id: string } | undefined
  if (!row) return false
  db.prepare('DELETE FROM oidc_refresh_tokens WHERE family_id = ?').run(row.family_id)
  return true
}

/** The consent revocation's companion: the (account, client) pair's
 *  refresh rows all go. */
export function deleteOidcRefreshTokensForUserClient(userId: string, clientId: string): number {
  return getDb().prepare('DELETE FROM oidc_refresh_tokens WHERE user_id = ? AND client_id = ?').run(userId, clientId).changes
}

/** The governance view's population read: the client's LIVE refresh-token
 *  count (unconsumed AND unexpired — a revoked family is deleted wholesale,
 *  so a live row's presence is the offline grant's standing). */
export function countOidcRefreshTokensForClient(clientId: string): number {
  const row = getDb().prepare(
    "SELECT COUNT(*) AS n FROM oidc_refresh_tokens WHERE client_id = ? AND consumed_at IS NULL AND datetime(expires_at) > datetime('now')",
  ).get(clientId) as { n: number }
  return row.n
}

/** The amr column's honest parse (a JSON array of strings, else null —
 *  the provenance is absent on rows that predate the wave). */
function parseJsonStringList(raw: unknown): string[] | null {
  if (typeof raw !== 'string' || !raw) return null
  try {
    const parsed = JSON.parse(raw) as unknown
    if (!Array.isArray(parsed)) return null
    const list = parsed.filter((v): v is string => typeof v === 'string')
    return list.length ? list : null
  } catch {
    return null
  }
}

export function listOidcKeys(): OidcKeyRow[] {
  const rows = getDb().prepare('SELECT * FROM oidc_keys ORDER BY created_at, kid').all() as Array<Record<string, unknown>>
  return rows.map(row => ({
    kid: row.kid as string,
    publicJwk: row.public_jwk as string,
    status: row.status as OidcKeyRow['status'],
    createdAt: row.created_at as string,
    retiredAt: (row.retired_at as string | null) ?? null,
  }))
}

export function upsertOidcKey(input: { kid: string; publicJwk: string }): void {
  getDb().prepare(
    'INSERT OR IGNORE INTO oidc_keys (kid, public_jwk) VALUES (?, ?)',
  ).run(input.kid, input.publicJwk)
}

export function retireOidcKey(kid: string): void {
  getDb().prepare("UPDATE oidc_keys SET status = 'retired', retired_at = datetime('now') WHERE kid = ? AND status = 'active'").run(kid)
}
