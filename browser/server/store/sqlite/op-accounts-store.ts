// ═══════════════════════════════════════════════════════════════════
// The OP account model's SQLite half (TODO.identity/02) — the sync
// implementations behind the ServerStore account/enrollment/session
// methods (sqlite-server-store.ts delegates here one-for-one, mirroring
// op-store.ts's role for the OIDC state and upstream-store.ts's for the
// linked identities, TODO.identity/08).
//
// NODE-ONLY: better-sqlite3 through ./store's getDb. The Worker bundle
// never sees this module (the D1 store implements the same surface in
// d1-store.ts).
// ═══════════════════════════════════════════════════════════════════

import { randomUUID } from 'crypto'
import { getDb } from './store'
import type {
  AccountEmail,
  AddAccountEmailResult,
  AuthUserPayload,
  CompleteEmailChangeResult,
  CompleteEnrollmentResult,
  EmailChangeToken,
  EnrollmentToken,
  OpClientRoleAssignment,
  OpLiveSession,
  SessionView,
  UserAdminRow,
} from '../../store'

/** The AuthUserPayload projection of a users row (the sqlite/store.ts
 *  userPayload shape — the full assigned role set rides along). */
function accountPayload(row: Record<string, unknown>): AuthUserPayload {
  let roles: string[] | undefined
  try {
    const parsed = JSON.parse((row.roles as string | null) ?? 'null') as unknown
    roles = Array.isArray(parsed) && parsed.length ? parsed.filter((v): v is string => typeof v === 'string') : undefined
  } catch { roles = undefined }
  return {
    id: row.id as string,
    email: row.email as string,
    name: row.name as string,
    role: row.role as string,
    ...(roles?.length ? { roles } : {}),
    orgId: (row.org_id as string | null) ?? null,
    avatarUrl: (row.avatar_url as string | null) ?? undefined,
    provider: row.provider as string,
    emailVerifiedAt: (row.email_verified_at as string | null) ?? null,
  }
}

function toEnrollmentToken(row: Record<string, unknown>): EnrollmentToken {
  return {
    token: row.token as string,
    userId: row.user_id as string,
    createdBy: (row.created_by as string | null) ?? null,
    createdAt: row.created_at as string,
    expiresAt: row.expires_at as string,
    consumedAt: (row.consumed_at as string | null) ?? null,
  }
}

/** Create the OP password account. Answers null when the email is taken
 *  (the invite route's 409; the UNIQUE constraint is the race backstop).
 *  TODO.identity-features/01: the taken read spans BOTH address tables —
 *  an additional on another account blocks the address as a primary. */
export function createOpAccount(input: {
  email: string
  name: string
  role: string
  createdBy?: string | null
}): UserAdminRow | null {
  const db = getDb()
  const id = randomUUID()
  const additional = db.prepare('SELECT user_id FROM account_emails WHERE email = ?').get(input.email.trim().toLowerCase())
  if (additional) return null
  try {
    db.prepare(
      "INSERT INTO users (id, email, name, provider, role) VALUES (?, ?, ?, 'password', ?)",
    ).run(id, input.email.trim().toLowerCase(), input.name.trim(), input.role)
  } catch (e) {
    if (String((e as Error).message).includes('UNIQUE')) return null
    throw e
  }
  const row = db.prepare('SELECT * FROM users WHERE id = ?').get(id) as Record<string, unknown>
  return {
    id: row.id as string,
    email: row.email as string,
    name: row.name as string,
    role: row.role as string,
    roles: [row.role as string],
    orgId: (row.org_id as string | null) ?? null,
    active: row.active !== 0,
    provider: row.provider as string,
    lastLogin: (row.last_login as string | null) ?? null,
  }
}

/** The password sign-in's lookup: the credential + the active flag, by
 *  (normalized) email. The credential's EXISTENCE is the qualifier — an
 *  account that holds a password may sign in with it.
 *  TODO.identity-features/01: the address resolves by ANY of the
 *  account's VERIFIED addresses — the primary first (the primary owner
 *  always wins, the deterministic rule), then a proven account_emails
 *  row; an unverified additional never resolves. */
export function getPasswordLogin(email: string): { userId: string; hash: string; active: boolean } | null {
  const db = getDb()
  const normalized = email.trim().toLowerCase()
  let row = db.prepare(
    `SELECT u.id AS user_id, u.active AS active, p.hash AS hash
     FROM users u JOIN passwords p ON p.user_id = u.id
     WHERE u.email = ?`,
  ).get(normalized) as Record<string, unknown> | undefined
  if (!row) {
    row = db.prepare(
      `SELECT u.id AS user_id, u.active AS active, p.hash AS hash
       FROM users u JOIN passwords p ON p.user_id = u.id
       WHERE u.id = (SELECT user_id FROM account_emails WHERE email = ? AND verified_at IS NOT NULL)`,
    ).get(normalized) as Record<string, unknown> | undefined
  }
  if (!row) return null
  return { userId: row.user_id as string, hash: row.hash as string, active: row.active !== 0 }
}

export function setPasswordHash(userId: string, hash: string, setBy?: string | null): void {
  getDb().prepare(
    `INSERT INTO passwords (user_id, hash, set_by) VALUES (?, ?, ?)
     ON CONFLICT (user_id) DO UPDATE SET hash = excluded.hash, set_at = datetime('now'), set_by = excluded.set_by`,
  ).run(userId, hash, setBy ?? null)
}

/** The sign-in methods the account holds (the account page's
 *  password-set state + the admin list's posture). TODO.identity-sso/02:
 *  the passkeys count — a passkey is a PRIMARY sign-in method
 *  (passwordless), so the at-least-one-way-in guard reads it. */
export function countSignInMethods(userId: string): { password: boolean; links: number; passkeys: number } {
  const db = getDb()
  const pw = db.prepare('SELECT COUNT(*) AS n FROM passwords WHERE user_id = ?').get(userId) as { n: number }
  const links = db.prepare('SELECT COUNT(*) AS n FROM identity_links WHERE user_id = ?').get(userId) as { n: number }
  const passkeys = db.prepare('SELECT COUNT(*) AS n FROM webauthn_credentials WHERE user_id = ?').get(userId) as { n: number }
  return { password: pw.n > 0, links: links.n, passkeys: passkeys.n }
}

/** The bulk list-endpoint variant (identity's TODO.restructure/06): one
 *  grouped read per underlying table — three statements for the whole
 *  set, never three per account. Every requested id answers; an absent
 *  row reads as zero (the per-id read's posture). */
export function countSignInMethodsBulk(userIds: string[]): Map<string, { password: boolean; links: number; passkeys: number }> {
  const answer = new Map<string, { password: boolean; links: number; passkeys: number }>(
    userIds.map(id => [id, { password: false, links: 0, passkeys: 0 }]),
  )
  if (userIds.length === 0) return answer
  const db = getDb()
  const placeholders = userIds.map(() => '?').join(',')
  const counts = (table: string): Map<string, number> => {
    const m = new Map<string, number>()
    const rows = db
      .prepare(`SELECT user_id, COUNT(*) AS n FROM ${table} WHERE user_id IN (${placeholders}) GROUP BY user_id`)
      .all(...userIds) as Array<{ user_id: string; n: number }>
    for (const row of rows) m.set(row.user_id, row.n)
    return m
  }
  const pw = counts('passwords')
  const links = counts('identity_links')
  const passkeys = counts('webauthn_credentials')
  for (const id of userIds) {
    answer.set(id, {
      password: (pw.get(id) ?? 0) > 0,
      links: links.get(id) ?? 0,
      passkeys: passkeys.get(id) ?? 0,
    })
  }
  return answer
}

export function createEnrollmentToken(input: {
  token: string
  userId: string
  createdBy?: string | null
  ttlMs: number
}): EnrollmentToken {
  const expiresAt = new Date(Date.now() + input.ttlMs).toISOString()
  getDb().prepare(
    'INSERT INTO enrollment_tokens (token, user_id, created_by, expires_at) VALUES (?, ?, ?, ?)',
  ).run(input.token, input.userId, input.createdBy ?? null, expiresAt)
  return getEnrollmentToken(input.token)!
}

export function getEnrollmentToken(token: string): EnrollmentToken | null {
  const row = getDb().prepare('SELECT * FROM enrollment_tokens WHERE token = ?').get(token) as Record<string, unknown> | undefined
  return row ? toEnrollmentToken(row) : null
}

/** Complete the enrollment: the token is consumed ATOMICALLY first (a
 *  presented link works exactly once — a concurrent double-submit loses
 *  the race), then the expiry is judged (an expired link is burned, never
 *  redeemed later), then the password lands. */
export function completeEnrollment(token: string, passwordHash: string, setBy?: string | null): CompleteEnrollmentResult {
  const db = getDb()
  const res = db.prepare(
    "UPDATE enrollment_tokens SET consumed_at = datetime('now') WHERE token = ? AND consumed_at IS NULL",
  ).run(token)
  if (res.changes === 0) return { kind: 'unknown' }
  const row = getEnrollmentToken(token)!
  if (new Date(row.expiresAt).getTime() <= Date.now()) return { kind: 'expired' }
  setPasswordHash(row.userId, passwordHash, setBy)
  // TODO.identity/06: the invite ceremony doubles as the address's
  // verification (the administrator delivered the one-time link to that
  // mailbox out-of-band; completing it proves the pair).
  db.prepare("UPDATE users SET email_verified_at = datetime('now') WHERE id = ?").run(row.userId)
  return { kind: 'ok', userId: row.userId }
}

/** The account's live sessions, `current` computed in SQL against the
 *  presenting token — the token value itself never leaves the store. */
export function listUserSessions(userId: string, currentToken?: string): SessionView[] {
  const rows = getDb().prepare(
    `SELECT id, created_at, expires_at, last_seen_at, user_agent, ip, (token = ?) AS is_current
     FROM sessions
     WHERE user_id = ? AND expires_at > datetime('now')
     ORDER BY created_at DESC`,
  ).all(currentToken ?? '', userId) as Array<Record<string, unknown>>
  return rows.map(row => ({
    id: row.id as string,
    createdAt: row.created_at as string,
    expiresAt: row.expires_at as string,
    lastSeenAt: (row.last_seen_at as string | null) ?? null,
    userAgent: (row.user_agent as string | null) ?? null,
    ip: (row.ip as string | null) ?? null,
    current: Number(row.is_current) === 1,
  }))
}

/** Revoke ONE of the account's own sessions (the user_id clause makes
 *  another account's session id a no-op). */
export function deleteSessionById(userId: string, sessionId: string): boolean {
  const res = getDb().prepare('DELETE FROM sessions WHERE id = ? AND user_id = ?').run(sessionId, userId)
  return res.changes > 0
}

/** Every live session across accounts (expired excluded), `current`
 *  computed in SQL against the presenting token — the aggregate admin
 *  read (TODO.identity-sso/01); the token never leaves the store. */
export function listOpLiveSessions(currentToken?: string): OpLiveSession[] {
  const rows = getDb().prepare(
    `SELECT id, user_id, created_at, expires_at, last_seen_at, user_agent, ip, (token = ?) AS is_current
     FROM sessions
     WHERE expires_at > datetime('now')
     ORDER BY created_at DESC`,
  ).all(currentToken ?? '') as Array<Record<string, unknown>>
  return rows.map(row => ({
    id: row.id as string,
    userId: row.user_id as string,
    createdAt: row.created_at as string,
    expiresAt: row.expires_at as string,
    lastSeenAt: (row.last_seen_at as string | null) ?? null,
    userAgent: (row.user_agent as string | null) ?? null,
    ip: (row.ip as string | null) ?? null,
    current: Number(row.is_current) === 1,
  }))
}

/** The administrator's revoke-all (TODO.identity-sso/01's light act):
 *  every session of the account, none kept; answers the count. */
export function deleteAllUserSessions(userId: string): number {
  return getDb().prepare('DELETE FROM sessions WHERE user_id = ?').run(userId).changes
}

// ── the central user registry (TODO.identity/03) ─────────────────────
// The per-client role assignments + the deactivation's revocation half
// + the audit-chain sign-in read.

interface OpClientRoleRow {
  user_id: string
  client_id: string
  roles: string
  assigned_by: string | null
  created_at: string
  updated_at: string | null
}

function toClientRoleAssignment(row: OpClientRoleRow): OpClientRoleAssignment {
  return {
    userId: row.user_id,
    clientId: row.client_id,
    roles: JSON.parse(row.roles) as string[],
    assignedBy: row.assigned_by ?? null,
    createdAt: row.created_at,
    updatedAt: row.updated_at ?? null,
  }
}

export function listOpClientRoles(userId: string): OpClientRoleAssignment[] {
  const rows = getDb().prepare(
    'SELECT * FROM op_client_roles WHERE user_id = ? ORDER BY client_id',
  ).all(userId) as unknown as OpClientRoleRow[]
  return rows.map(toClientRoleAssignment)
}

/** EVERY per-client assignment across accounts (TODO.identity-sso/01's
 *  live access review). */
export function listAllOpClientRoles(): OpClientRoleAssignment[] {
  const rows = getDb().prepare(
    'SELECT * FROM op_client_roles ORDER BY user_id, client_id',
  ).all() as unknown as OpClientRoleRow[]
  return rows.map(toClientRoleAssignment)
}

/** The assignment for ONE client: NULL = no row (the account's OP-side
 *  role set is that client's default); an EMPTY array = the explicit
 *  "no roles on this client". */
export function getOpClientRoles(userId: string, clientId: string): string[] | null {
  const row = getDb().prepare(
    'SELECT roles FROM op_client_roles WHERE user_id = ? AND client_id = ?',
  ).get(userId, clientId) as { roles: string } | undefined
  return row ? (JSON.parse(row.roles) as string[]) : null
}

export function setOpClientRoles(userId: string, clientId: string, roles: string[], assignedBy: string | null): void {
  getDb().prepare(`
    INSERT INTO op_client_roles (user_id, client_id, roles, assigned_by)
    VALUES (?, ?, ?, ?)
    ON CONFLICT (user_id, client_id) DO UPDATE SET
      roles = excluded.roles,
      assigned_by = excluded.assigned_by,
      updated_at = datetime('now')
  `).run(userId, clientId, JSON.stringify(roles), assignedBy)
}

export function deleteOpClientRoles(userId: string, clientId: string): boolean {
  const res = getDb().prepare('DELETE FROM op_client_roles WHERE user_id = ? AND client_id = ?').run(userId, clientId)
  return res.changes > 0
}

/** The deactivation's revocation half: every live session, every issued
 *  access token, every refresh token (migration 0025 — consumed or not;
 *  the reuse detector has no more verdicts to give), every unconsumed
 *  code and pending authorization goes. The user row STAYS (the
 *  history). */
export function revokeOpUserCredentials(userId: string): { sessions: number; accessTokens: number; refreshTokens: number; codes: number; authorizations: number } {
  const db = getDb()
  const sessions = db.prepare('DELETE FROM sessions WHERE user_id = ?').run(userId).changes
  const accessTokens = db.prepare('DELETE FROM oidc_access_tokens WHERE user_id = ?').run(userId).changes
  const refreshTokens = db.prepare('DELETE FROM oidc_refresh_tokens WHERE user_id = ?').run(userId).changes
  const codes = db.prepare('DELETE FROM oidc_codes WHERE user_id = ? AND consumed_at IS NULL').run(userId).changes
  const authorizations = db.prepare('DELETE FROM oidc_authorizations WHERE user_id = ? AND decision IS NULL').run(userId).changes
  return { sessions, accessTokens, refreshTokens, codes, authorizations }
}

/** The registry's edit act (name/email). The email UNIQUE conflict
 *  throws 'unique' (the route maps it to a 409, never a silent take).
 *  TODO.identity/06: an admin-set address never went through the
 *  verify-new-email ceremony, so the verification state resets.
 *  TODO.identity-features/01: the conflict read spans BOTH address
 *  tables — an additional row (on any account, this one included) holds
 *  the address too. */
export function updateOpAccount(id: string, input: { name?: string; email?: string }): boolean {
  const db = getDb()
  if (input.email !== undefined) {
    const additional = db.prepare('SELECT user_id FROM account_emails WHERE email = ?').get(input.email.trim().toLowerCase())
    if (additional) throw new Error(`unique: ${input.email}`)
    try {
      db.prepare('UPDATE users SET email = ?, email_verified_at = NULL WHERE id = ?').run(input.email.trim().toLowerCase(), id)
    } catch (e) {
      if (String((e as Error).message).includes('UNIQUE')) throw new Error(`unique: ${input.email}`)
      throw e
    }
  }
  if (input.name !== undefined) {
    db.prepare('UPDATE users SET name = ? WHERE id = ?').run(input.name.trim(), id)
  }
  const res = db.prepare('SELECT 1 AS ok FROM users WHERE id = ?').get(id)
  return !!res
}

/** The registry's ERASURE act (the offboarding runbook's delete path —
 *  docs/deployment/identity-operations.md): everything the account held
 *  is removed (the password credential, the enrollment + email-change
 *  tokens, the linked identities, the per-client role assignments, every
 *  live credential) and the user row is ANONYMIZED in place: the row
 *  survives as a tombstone (the audit chain's entity_id still resolves,
 *  foreign keys never dangle) but carries no person — name, email,
 *  organization, roles, avatar and the verification stamp all go, and
 *  provider becomes 'erased' so the row drops out of every account
 *  surface (the registry list, the sign-in joins, the admin acts).
 *  Answers the removal counts (the audit event's metadata), or null when
 *  the account does not exist. */
export function eraseOpAccount(userId: string): {
  sessions: number
  accessTokens: number
  refreshTokens: number
  codes: number
  authorizations: number
  links: number
  clientRoles: number
  memberships: number
  tokens: number
  factors: number
  personalAccessTokens: number
  consentGrants: number
  emails: number
} | null {
  const db = getDb()
  const row = db.prepare('SELECT 1 AS ok FROM users WHERE id = ?').get(userId)
  if (!row) return null
  const revoked = revokeOpUserCredentials(userId)
  const links = db.prepare('DELETE FROM identity_links WHERE user_id = ?').run(userId).changes
  const clientRoles = db.prepare('DELETE FROM op_client_roles WHERE user_id = ?').run(userId).changes
  // TODO.identity/11: the memberships go too (every org's row — the
  // tombstone acts for no organization).
  const memberships = db.prepare('DELETE FROM org_memberships WHERE user_id = ?').run(userId).changes
  const tokens =
    db.prepare('DELETE FROM passwords WHERE user_id = ?').run(userId).changes +
    db.prepare('DELETE FROM enrollment_tokens WHERE user_id = ?').run(userId).changes +
    db.prepare('DELETE FROM email_change_tokens WHERE user_id = ?').run(userId).changes
  // TODO.identity-sso/02+03: the factor registry follows the account
  // into erasure — passkeys, TOTP secrets, recovery codes, and the
  // pending ceremony state (challenges, pending-MFA rows).
  const factors =
    db.prepare('DELETE FROM webauthn_credentials WHERE user_id = ?').run(userId).changes +
    db.prepare('DELETE FROM totp_secrets WHERE user_id = ?').run(userId).changes +
    db.prepare('DELETE FROM recovery_codes WHERE user_id = ?').run(userId).changes +
    db.prepare('DELETE FROM webauthn_challenges WHERE user_id = ?').run(userId).changes +
    db.prepare('DELETE FROM mfa_pending WHERE user_id = ?').run(userId).changes
  // TODO.identity-features/08: the developer tokens die with the account
  // (the hashed rows go — a tombstone's tokens never exchange again).
  const personalAccessTokens = db.prepare('DELETE FROM personal_access_tokens WHERE user_id = ?').run(userId).changes
  // TODO.identity-features/12: the remembered consent grants die with the
  // account (a tombstone never skips a consent page again).
  const consentGrants = db.prepare('DELETE FROM oidc_consent_grants WHERE user_id = ?').run(userId).changes
  // TODO.identity-features/01: the additional addresses die with the
  // account (a tombstone's addresses never resolve a sign-in again).
  const emails = db.prepare('DELETE FROM account_emails WHERE user_id = ?').run(userId).changes
  db.prepare(
    `UPDATE users SET
       email = ?, name = 'Deleted account', provider = 'erased',
       role = 'viewer', roles = NULL, org_id = NULL,
       avatar_url = NULL, email_verified_at = NULL, active = 0
     WHERE id = ?`,
  ).run(`deleted-${userId}@erased.invalid`, userId)
  return { ...revoked, links, clientRoles, memberships, tokens, factors, personalAccessTokens, consentGrants, emails }
}

/** The last OP-side sign-in per account, FROM THE AUDIT CHAIN: the
 *  newest auditEvents row whose action is a sign-in ('account.sign_in'
 *  — the password login; 'upstream_sign_in' — a linked-provider
 *  sign-in) per entity_id (the account id). The typed read (the
 *  2026-09-06 audit): json_extract against idx_entities_store_action —
 *  an index walk over the sign-in slice, never the O(journal)
 *  data-LIKE scan; the json_valid guard spells the index's expression
 *  exactly (a corrupt entities row answers NULL legs, never a raised
 *  'malformed JSON'). The action match stays exact (the retired LIKE's
 *  closing quote made it so too) — and now spelling-proof: the legs
 *  parse the JSON, so a serialized-with-spaces row answers and an
 *  embedded lookalike substring never does. */
export function lastAccountSignIns(): Record<string, string> {
  const rows = getDb().prepare(
    `SELECT json_extract(CASE WHEN json_valid(data) THEN data ELSE '{}' END, '$.entity_id') AS entity_id,
            MAX(json_extract(CASE WHEN json_valid(data) THEN data ELSE '{}' END, '$.timestamp')) AS ts
     FROM entities
     WHERE store = 'auditEvents'
       AND json_extract(CASE WHEN json_valid(data) THEN data ELSE '{}' END, '$.action') IN ('account.sign_in', 'upstream_sign_in')
     GROUP BY json_extract(CASE WHEN json_valid(data) THEN data ELSE '{}' END, '$.entity_id')`,
  ).all() as Array<{ entity_id: string | null; ts: string | null }>
  const out: Record<string, string> = {}
  for (const { entity_id, ts } of rows) {
    if (typeof entity_id === 'string' && typeof ts === 'string') out[entity_id] = ts
  }
  return out
}

// ── the account console (TODO.identity/06) ───────────────────────────

/** The profile edit's write (the display name). */
export function updateUserName(userId: string, name: string): boolean {
  const res = getDb().prepare('UPDATE users SET name = ? WHERE id = ?').run(name.trim(), userId)
  return res.changes > 0
}

/** The avatar write (the account console's upload/remove): users.avatar_url
 *  carries the serving URL (the OP's own avatar route for an upload, the
 *  linked provider's picture URL for an OAuth-provisioned row), NULL when
 *  the account shows its initials. Answers false when the account is gone. */
export function setUserAvatar(userId: string, avatarUrl: string | null): boolean {
  const res = getDb().prepare('UPDATE users SET avatar_url = ? WHERE id = ?').run(avatarUrl, userId)
  return res.changes > 0
}

/** Remove the account's password credential (the route holds the
 *  at-least-one-method guard). */
export function deletePasswordHash(userId: string): boolean {
  const res = getDb().prepare('DELETE FROM passwords WHERE user_id = ?').run(userId)
  return res.changes > 0
}

/** Revoke every session of the account EXCEPT the presenting one.
 *  Answers the revoked count. */
export function deleteOtherSessions(userId: string, keepToken: string): number {
  const res = getDb().prepare('DELETE FROM sessions WHERE user_id = ? AND token != ?').run(userId, keepToken)
  return res.changes
}

function toEmailChangeToken(row: Record<string, unknown>): EmailChangeToken {
  return {
    token: row.token as string,
    userId: row.user_id as string,
    newEmail: row.new_email as string,
    deliveredBy: row.delivered_by === 'mailer' ? 'mailer' : 'shown',
    // TODO.identity-features/01: rows predating the kind column read as
    // the legacy ceremony; the 0.2.4 'verify' kind reads by its name.
    kind: row.kind === 'add' ? 'add' : row.kind === 'verify' ? 'verify' : 'change',
    createdAt: row.created_at as string,
    expiresAt: row.expires_at as string,
    consumedAt: (row.consumed_at as string | null) ?? null,
  }
}

/** Mint the ceremony's token. The void rule keeps ONE live link per
 *  ceremony target: a 'change' request voids the account's earlier
 *  pending 'change' rows (only the newest change link works — the
 *  pre-01 doctrine); an 'add' request voids the account's earlier
 *  pending 'add' rows FOR THE SAME address (other addresses' links
 *  stand); a 'verify' request voids the account's earlier pending
 *  'verify' rows (the target is the current primary — one per account,
 *  the change doctrine's scoping). */
export function createEmailChangeToken(input: {
  token: string
  userId: string
  newEmail: string
  deliveredBy: 'mailer' | 'shown'
  kind?: 'change' | 'add' | 'verify'
  ttlMs: number
}): EmailChangeToken {
  const db = getDb()
  const kind = input.kind ?? 'change'
  if (kind === 'change') {
    db.prepare(
      "UPDATE email_change_tokens SET consumed_at = datetime('now') WHERE user_id = ? AND kind = 'change' AND consumed_at IS NULL",
    ).run(input.userId)
  } else if (kind === 'verify') {
    db.prepare(
      "UPDATE email_change_tokens SET consumed_at = datetime('now') WHERE user_id = ? AND kind = 'verify' AND consumed_at IS NULL",
    ).run(input.userId)
  } else {
    db.prepare(
      "UPDATE email_change_tokens SET consumed_at = datetime('now') WHERE user_id = ? AND kind = 'add' AND new_email = ? AND consumed_at IS NULL",
    ).run(input.userId, input.newEmail.trim().toLowerCase())
  }
  const expiresAt = new Date(Date.now() + input.ttlMs).toISOString()
  db.prepare(
    'INSERT INTO email_change_tokens (token, user_id, new_email, delivered_by, kind, expires_at) VALUES (?, ?, ?, ?, ?, ?)',
  ).run(input.token, input.userId, input.newEmail.trim().toLowerCase(), input.deliveredBy, kind, expiresAt)
  return getEmailChangeToken(input.token)!
}

export function getEmailChangeToken(token: string): EmailChangeToken | null {
  const row = getDb().prepare('SELECT * FROM email_change_tokens WHERE token = ?').get(token) as Record<string, unknown> | undefined
  return row ? toEmailChangeToken(row) : null
}

/** The account's pending PRIMARY change (the newest live 'change' row),
 *  so the console can show it. The per-address verifications are the
 *  account_emails rows' own state (verified_at NULL = waiting), never a
 *  pending read here. */
export function getPendingEmailChange(userId: string): EmailChangeToken | null {
  const row = getDb().prepare(
    `SELECT * FROM email_change_tokens
     WHERE user_id = ? AND kind = 'change' AND consumed_at IS NULL AND expires_at > datetime('now')
     ORDER BY created_at DESC LIMIT 1`,
  ).get(userId) as Record<string, unknown> | undefined
  return row ? toEmailChangeToken(row) : null
}

/** Complete the ceremony: consume ATOMICALLY (a presented link works
 *  exactly once, expired or not), judge the expiry, then act on the
 *  kind. 'change' (the pre-01 primary replacement): re-check the
 *  address's uniqueness across BOTH address tables (a conflict burns the
 *  token honestly — an additional row anywhere holds the address too,
 *  this account's included), then move users.email. 'add' (the
 *  per-address verification): the account_emails row landed unverified
 *  at the request; the completion stamps it (a row removed meanwhile
 *  burns the link as 'unknown'). 'verify' (the 0.2.4 kind): the
 *  re-verification of the address the account ALREADY holds as its
 *  primary — the completion stamps users.email_verified_at when the
 *  token's new_email IS STILL the primary (a primary moved meanwhile —
 *  a completed 'change', an admin re-address — burns the link as
 *  'unknown', the vanished-target doctrine; the erasure's token sweep
 *  burns it earlier). A 'mailer'-delivered token verifies the address;
 *  a shown one never does. */
export function completeEmailChange(token: string): CompleteEmailChangeResult {
  const db = getDb()
  const res = db.prepare(
    "UPDATE email_change_tokens SET consumed_at = datetime('now') WHERE token = ? AND consumed_at IS NULL",
  ).run(token)
  if (res.changes === 0) return { kind: 'unknown' }
  const row = getEmailChangeToken(token)!
  if (new Date(row.expiresAt).getTime() <= Date.now()) return { kind: 'expired' }
  const verified = row.deliveredBy === 'mailer'
  if (row.kind === 'add') {
    const standing = db.prepare('SELECT 1 AS ok FROM account_emails WHERE user_id = ? AND email = ?').get(row.userId, row.newEmail)
    if (!standing) return { kind: 'unknown' }
    if (verified) markAccountEmailVerified(row.userId, row.newEmail)
    return { kind: 'ok', userId: row.userId, newEmail: row.newEmail, verified }
  }
  if (row.kind === 'verify') {
    // The address NEVER changes hands in this ceremony — 'conflict' does
    // not exist here; the honest burns are the moved primary and the
    // gone account, both read from the users row.
    const current = db.prepare('SELECT email FROM users WHERE id = ?').get(row.userId) as { email: string } | undefined
    if (!current || current.email !== row.newEmail) return { kind: 'unknown' }
    if (verified) db.prepare("UPDATE users SET email_verified_at = datetime('now') WHERE id = ?").run(row.userId)
    return { kind: 'ok', userId: row.userId, newEmail: row.newEmail, verified }
  }
  const taken = db.prepare('SELECT id FROM users WHERE email = ?').get(row.newEmail) as { id: string } | undefined
  if (taken) return { kind: 'conflict' }
  const takenAdditional = db.prepare('SELECT user_id FROM account_emails WHERE email = ?').get(row.newEmail) as { user_id: string } | undefined
  if (takenAdditional) return { kind: 'conflict' }
  db.prepare(
    `UPDATE users SET email = ?, email_verified_at = ${verified ? "datetime('now')" : 'NULL'} WHERE id = ?`,
  ).run(row.newEmail, row.userId)
  return { kind: 'ok', userId: row.userId, newEmail: row.newEmail, verified }
}

// ── multiple emails per account (TODO.identity-features/01) ──────────

function toAccountEmail(row: Record<string, unknown>, isPrimary: boolean): AccountEmail {
  return {
    userId: row.user_id as string,
    email: row.email as string,
    verifiedAt: (row.verified_at as string | null) ?? null,
    isPrimary,
    addedBy: (row.added_by as string | null) ?? null,
    createdAt: row.created_at as string,
  }
}

/** The account's addresses: the PRIMARY first (the users row's email +
 *  its verification stamp), then the additional account_emails rows
 *  (oldest first). */
export function listAccountEmails(userId: string): AccountEmail[] {
  const db = getDb()
  const primary = db.prepare(
    'SELECT id AS user_id, email, email_verified_at AS verified_at, created_at FROM users WHERE id = ?',
  ).get(userId) as Record<string, unknown> | undefined
  const rows = db.prepare(
    'SELECT * FROM account_emails WHERE user_id = ? ORDER BY created_at, email',
  ).all(userId) as Array<Record<string, unknown>>
  const out: AccountEmail[] = []
  if (primary) out.push(toAccountEmail(primary, true))
  out.push(...rows.map(r => toAccountEmail(r, false)))
  return out
}

/** Resolve the account by ANY of its addresses (normalized): the primary
 *  always names it (and the primary owner always wins — the
 *  deterministic rule); an additional ONLY when verified. */
export function findUserByAnyEmail(email: string): AuthUserPayload | null {
  const db = getDb()
  const normalized = email.trim().toLowerCase()
  const primary = db.prepare('SELECT * FROM users WHERE email = ?').get(normalized) as Record<string, unknown> | undefined
  if (primary) return accountPayload(primary)
  const owner = db.prepare(
    'SELECT user_id FROM account_emails WHERE email = ? AND verified_at IS NOT NULL',
  ).get(normalized) as { user_id: string } | undefined
  if (!owner) return null
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(owner.user_id) as Record<string, unknown> | undefined
  return user ? accountPayload(user) : null
}

/** Add an ADDITIONAL address (normalized lowercase; the row lands
 *  UNVERIFIED). The account's own existing row answers 'present' (the
 *  idempotent re-add); any other hold of the address — a primary
 *  anywhere (this account's included) or another account's additional —
 *  answers 'conflict'. The unique index is the race backstop. */
export function addAccountEmail(userId: string, email: string, addedBy?: string | null): AddAccountEmailResult {
  const db = getDb()
  const normalized = email.trim().toLowerCase()
  const takenPrimary = db.prepare('SELECT id FROM users WHERE email = ?').get(normalized)
  if (takenPrimary) return 'conflict'
  const existing = db.prepare('SELECT user_id FROM account_emails WHERE email = ?').get(normalized) as { user_id: string } | undefined
  if (existing) return existing.user_id === userId ? 'present' : 'conflict'
  try {
    db.prepare('INSERT INTO account_emails (user_id, email, added_by) VALUES (?, ?, ?)').run(userId, normalized, addedBy ?? null)
  } catch (e) {
    if (String((e as Error).message).includes('UNIQUE')) return 'conflict'
    throw e
  }
  return 'added'
}

/** The verification ceremony's stamp on the account's OWN row: the
 *  guarded UPDATE flips verified_at, once. */
export function markAccountEmailVerified(userId: string, email: string): boolean {
  return getDb().prepare(
    "UPDATE account_emails SET verified_at = datetime('now') WHERE user_id = ? AND email = ? AND verified_at IS NULL",
  ).run(userId, email.trim().toLowerCase()).changes > 0
}

/** Promote a VERIFIED additional to primary: the promoted address
 *  becomes users.email with its verification stamp; the outgoing
 *  primary takes the row's place in account_emails with ITS stamp (it
 *  stays a verified additional — sign-in by it keeps working). */
export function setPrimaryAccountEmail(userId: string, email: string): 'ok' | 'unknown' | 'unverified' {
  const db = getDb()
  const normalized = email.trim().toLowerCase()
  const row = db.prepare('SELECT * FROM account_emails WHERE user_id = ? AND email = ?').get(userId, normalized) as Record<string, unknown> | undefined
  if (!row) return 'unknown'
  if (!row.verified_at) return 'unverified'
  const current = db.prepare('SELECT email, email_verified_at FROM users WHERE id = ?').get(userId) as { email: string; email_verified_at: string | null } | undefined
  if (!current) return 'unknown'
  db.prepare('UPDATE users SET email = ?, email_verified_at = ? WHERE id = ?').run(normalized, row.verified_at as string, userId)
  db.prepare('DELETE FROM account_emails WHERE user_id = ? AND email = ?').run(userId, normalized)
  db.prepare('INSERT INTO account_emails (user_id, email, verified_at) VALUES (?, ?, ?)').run(userId, current.email, current.email_verified_at)
  return 'ok'
}

/** Remove an ADDITIONAL address. The primary refuses honestly
 *  ('primary' — promote another address first). */
export function removeAccountEmail(userId: string, email: string): 'ok' | 'primary' | 'unknown' {
  const db = getDb()
  const normalized = email.trim().toLowerCase()
  const current = db.prepare('SELECT email FROM users WHERE id = ?').get(userId) as { email: string } | undefined
  if (current?.email === normalized) return 'primary'
  const res = db.prepare('DELETE FROM account_emails WHERE user_id = ? AND email = ?').run(userId, normalized)
  return res.changes > 0 ? 'ok' : 'unknown'
}
