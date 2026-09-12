import Database from 'better-sqlite3'
import bcrypt from 'bcryptjs'
import { randomUUID } from 'crypto'
import { readFileSync, existsSync, mkdirSync } from 'fs'
import { join, dirname } from 'path'
import { fileURLToPath } from 'url'

// The payload type's home is the worker-safe backend seam
// (TODO.cs-e2e/14); re-exported here so existing importers are
// undisturbed.
import type { AuthUserPayload } from '../../store'
export type { AuthUserPayload } from '../../store'

const __dirname = dirname(fileURLToPath(import.meta.url))

// The default database path is anchored one level above the process's
// working directory: every boot that relies on the default (the dev
// scripts, tsx watch, the seed legs) runs with cwd = the consumer app's
// directory (browser/ in the smart monorepo), so the effective default
// is unchanged from the store's pre-extraction home
// (<repo>/data/oiml-smart.db, gitignored by name). DATABASE_PATH always
// wins; the deploy postures (Docker, the e2e stacks, the tests) declare
// it explicitly.
const DB_PATH = process.env.DATABASE_PATH || join(process.cwd(), '..', 'data', 'oiml-smart.db')

// The module-global, post-TODO.restructure/28-D, is exactly ONE named
// thing: the DEFAULT instance's handle (getDb below — the composition
// root's named default, what dev-reset and the dev scripts address).
// Everything else about a store is INSTANCE state: createSqliteStore
// (../sqlite.ts) opens its own database through openSqliteDatabase and
// answers a ServerStore bound to it — two instances in one process,
// each with its own file, is the federation spec's standing proof.
let _db: Database.Database | null = null

/** Open + bring up a database at the path: the directory, the WAL
 *  posture, the shipped schema, the idempotent column adds. The
 *  instance's open act — one handle per open database, never shared. */
export function openSqliteDatabase(path: string): Database.Database {
  const dir = dirname(path)
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true })
  const db = new Database(path)
  db.pragma('journal_mode = WAL')
  db.exec(readFileSync(join(__dirname, 'schema.sql'), 'utf-8'))
  migrateAuthTables(db)
  return db
}

/** The DEFAULT instance's handle (memoized): the composition root's
 *  named default at DATABASE_PATH (or the pre-extraction home). The
 *  verbs above no longer read it — they receive their instance's db. */
export function getDb(): Database.Database {
  if (_db) return _db
  _db = openSqliteDatabase(DB_PATH)
  return _db
}

/** Migration-safe column adds for DBs created before a schema change. */
function migrateAuthTables(db: Database.Database): void {
  const cols = db.prepare('PRAGMA table_info(users)').all() as Array<{ name: string }>
  if (!cols.some(c => c.name === 'org_id')) {
    db.exec('ALTER TABLE users ADD COLUMN org_id TEXT')
  }
  // TODO.federation/10 — the SSO logout hint (id_token for RP-initiated
  // logout); identity_approvals itself arrives via schema.sql's
  // CREATE IF NOT EXISTS on every boot.
  const sessionCols = db.prepare('PRAGMA table_info(sessions)').all() as Array<{ name: string }>
  if (!sessionCols.some(c => c.name === 'id_token_hint')) {
    db.exec('ALTER TABLE sessions ADD COLUMN id_token_hint TEXT')
  }
  // TODO.identity/06 (the account console): the session sign-in context
  // (user agent / IP at creation, last-active on resolution) and the
  // email verification state on the users row.
  if (!sessionCols.some(c => c.name === 'user_agent')) {
    db.exec('ALTER TABLE sessions ADD COLUMN user_agent TEXT')
  }
  if (!sessionCols.some(c => c.name === 'ip')) {
    db.exec('ALTER TABLE sessions ADD COLUMN ip TEXT')
  }
  if (!sessionCols.some(c => c.name === 'last_seen_at')) {
    db.exec('ALTER TABLE sessions ADD COLUMN last_seen_at TEXT')
  }
  if (!cols.some(c => c.name === 'email_verified_at')) {
    db.exec('ALTER TABLE users ADD COLUMN email_verified_at TEXT')
  }
  // TODO.federation/12 (RBAC): the assigned role set + the active flag.
  if (!cols.some(c => c.name === 'roles')) {
    db.exec('ALTER TABLE users ADD COLUMN roles TEXT')
  }
  if (!cols.some(c => c.name === 'active')) {
    db.exec('ALTER TABLE users ADD COLUMN active INTEGER NOT NULL DEFAULT 1')
  }
  // The SSO home (migration 0011): the client registry's launch
  // metadata. The launcher's reads degrade honestly without the columns
  // (launch stays null); a pre-0011 SQLite file grows them here.
  const clientCols = db.prepare('PRAGMA table_info(oidc_clients)').all() as Array<{ name: string }>
  if (clientCols.length && !clientCols.some(c => c.name === 'launch_url')) {
    db.exec(`ALTER TABLE oidc_clients ADD COLUMN launch_url TEXT`)
    db.exec(`ALTER TABLE oidc_clients ADD COLUMN launch_icon TEXT`)
    db.exec(`ALTER TABLE oidc_clients ADD COLUMN launch_description TEXT`)
    db.exec(`ALTER TABLE oidc_clients ADD COLUMN launch_visibility TEXT NOT NULL DEFAULT 'roles'`)
  }
  // TODO.identity/11 (the multi-org membership model): the session's
  // active-org stamp + the token-flow context columns (the code carries
  // the consent's context; the access token inherits it for userinfo).
  if (!sessionCols.some(c => c.name === 'active_org')) {
    db.exec('ALTER TABLE sessions ADD COLUMN active_org TEXT')
  }
  const codeCols = db.prepare('PRAGMA table_info(oidc_codes)').all() as Array<{ name: string }>
  if (!codeCols.some(c => c.name === 'context_org')) {
    db.exec('ALTER TABLE oidc_codes ADD COLUMN context_org TEXT')
  }
  const accessCols = db.prepare('PRAGMA table_info(oidc_access_tokens)').all() as Array<{ name: string }>
  if (!accessCols.some(c => c.name === 'context_org')) {
    db.exec('ALTER TABLE oidc_access_tokens ADD COLUMN context_org TEXT')
  }
  // The backfill (migration 0012's twin, IDEMPOTENT — it rides every
  // boot): every org-bound account's PRIMARY membership, mirrored from
  // the legacy columns (the dual-read doctrine's foundation). The
  // deterministic id keeps re-runs no-ops; the roles column is the
  // account's full legacy set (or the primary role when NULL).
  db.exec(`
    INSERT OR IGNORE INTO org_memberships (id, user_id, org_id, roles, state, is_primary, activated_at)
    SELECT 'mbr-' || id, id, org_id,
           CASE WHEN roles IS NOT NULL AND roles != '' THEN roles ELSE json_array(role) END,
           'active', 1, COALESCE(last_login, created_at)
    FROM users WHERE org_id IS NOT NULL
  `)
  // TODO.identity-features/09 (the org-member data cone): the
  // membership's cone column arrives with migration 0017 — a dev file
  // predating it grows the column here. NULL = org-wide: existing
  // memberships keep their posture silently.
  const membershipCols = db.prepare('PRAGMA table_info(org_memberships)').all() as Array<{ name: string }>
  if (membershipCols.length && !membershipCols.some(c => c.name === 'cone')) {
    db.exec('ALTER TABLE org_memberships ADD COLUMN cone TEXT')
  }
  // TODO.identity-features/10 (the OIML Member category): the
  // designation links + the CS status facet arrive with migration 0019 —
  // a dev file predating it grows the columns here. NULL = not recorded:
  // existing rows keep their posture silently.
  const registryCols = db.prepare('PRAGMA table_info(org_registry)').all() as Array<{ name: string }>
  if (registryCols.length) {
    if (!registryCols.some(c => c.name === 'designated_by')) {
      db.exec('ALTER TABLE org_registry ADD COLUMN designated_by TEXT')
    }
    if (!registryCols.some(c => c.name === 'proposed_by')) {
      db.exec('ALTER TABLE org_registry ADD COLUMN proposed_by TEXT')
    }
    if (!registryCols.some(c => c.name === 'cs_status')) {
      db.exec('ALTER TABLE org_registry ADD COLUMN cs_status TEXT')
    }
  }
  // TODO.identity-sso/02+03 (the strong-authentication wave): the amr
  // provenance columns on sessions → codes → access tokens.
  if (!sessionCols.some(c => c.name === 'amr')) {
    db.exec('ALTER TABLE sessions ADD COLUMN amr TEXT')
  }
  const amrCodeCols = db.prepare('PRAGMA table_info(oidc_codes)').all() as Array<{ name: string }>
  if (!amrCodeCols.some(c => c.name === 'amr')) {
    db.exec('ALTER TABLE oidc_codes ADD COLUMN amr TEXT')
  }
  const amrTokenCols = db.prepare('PRAGMA table_info(oidc_access_tokens)').all() as Array<{ name: string }>
  if (!amrTokenCols.some(c => c.name === 'amr')) {
    db.exec('ALTER TABLE oidc_access_tokens ADD COLUMN amr TEXT')
  }
  // TODO.identity-features/01 (multiple emails per account): the
  // ceremony token's kind column arrives with migration 0022 — a dev
  // file predating it grows the column here ('change' — every existing
  // row is the legacy primary-replacement ceremony). The account_emails
  // table itself arrives via schema.sql's CREATE IF NOT EXISTS on every
  // boot.
  const emailChangeCols = db.prepare('PRAGMA table_info(email_change_tokens)').all() as Array<{ name: string }>
  if (emailChangeCols.length && !emailChangeCols.some(c => c.name === 'kind')) {
    db.exec("ALTER TABLE email_change_tokens ADD COLUMN kind TEXT NOT NULL DEFAULT 'change'")
  }
  // TODO.notify/05's remainders (migration 0027): the event row's
  // mentions column + the inbox marker's saved_at stamp — a dev file
  // predating it grows the columns here. NULL = none / unsaved: existing
  // rows keep their posture silently.
  const eventCols = db.prepare('PRAGMA table_info(events)').all() as Array<{ name: string }>
  if (eventCols.length && !eventCols.some(c => c.name === 'mentions')) {
    db.exec('ALTER TABLE events ADD COLUMN mentions TEXT')
  }
  const inboxCols = db.prepare('PRAGMA table_info(notify_inbox_state)').all() as Array<{ name: string }>
  if (inboxCols.length && !inboxCols.some(c => c.name === 'saved_at')) {
    db.exec('ALTER TABLE notify_inbox_state ADD COLUMN saved_at TEXT')
  }
}

// AuthUserPayload lives in ./backend (see the re-export above).

// The demo cast's home is the worker-safe backend seam (TODO.cs-e2e/14 —
// the D1 store seeds the same accounts); the password constant is imported,
// the account list now flows through the profile-aware plan below.
import { DEMO_PASSWORD } from '../../store'
// TODO.federation/01 — the account plan follows the deployment profile:
// the hub seeds DEMO_ACCOUNTS (the historical cast); an ia/tl instance
// seeds its own staff (+ the cast when the profile carries the
// demo-personas flag). The installed slot defaults to the hub profile,
// so a boot with no profile declaration behaves exactly as before.
import { getInstanceProfile, seedAccountsForProfile } from '../../profile'

export function seedDemoAccounts(db: Database.Database): void {
  const insert = db.prepare(`
    INSERT OR IGNORE INTO users (id, email, name, provider, provider_account_id, role, org_id, roles)
    VALUES (?, ?, ?, 'demo', ?, ?, ?, ?)
  `)
  // Align existing demo rows (created by older seeds) with the current
  // role/org assignments — INSERT OR IGNORE alone would leave them stale.
  // The roles column aligns too (NULL when the seed declares no full set
  // — a stale set from an older cast never survives the align).
  const align = db.prepare(`
    UPDATE users SET name = ?, role = ?, org_id = ?, roles = ? WHERE email = ? AND provider = 'demo'
  `)

  for (const account of seedAccountsForProfile(getInstanceProfile())) {
    const roles = account.roles?.length ? JSON.stringify(account.roles) : null
    insert.run(randomUUID(), account.email, account.name, account.email, account.role, account.orgId, roles)
    align.run(account.name, account.role, account.orgId, roles, account.email)
    // TODO.identity/11: the org-bound seed accounts' primary memberships
    // ride the mirror (idempotent — the seed runs at every boot).
    if (account.orgId) {
      const row = db.prepare('SELECT id FROM users WHERE email = ?').get(account.email) as { id: string } | undefined
      if (row) syncPrimaryMembership(db, row.id)
    }
  }
}

/** Parse the users.roles JSON column (the assigned role set; NULL →
 *  the primary role only). */
function parseRoles(raw: unknown): string[] | undefined {
  if (typeof raw !== 'string' || !raw) return undefined
  try {
    const parsed = JSON.parse(raw) as unknown
    return Array.isArray(parsed) ? parsed.filter((v): v is string => typeof v === 'string') : undefined
  } catch {
    return undefined
  }
}

/** The users-row → session payload projection (RBAC: roles + the
 *  active flag are part of the row; a deactivated account never
 *  produces a payload). */
function toAuthPayload(user: any, avatarUrl?: string): AuthUserPayload {
  const roles = parseRoles(user.roles)
  // TODO.identity-sso/02+03: the session row's amr (a JSON array) — only
  // the session-backed read carries it; a plain user row answers absent.
  const amr = parseRoles(user.amr) ?? undefined
  return {
    id: user.id,
    email: user.email,
    name: user.name,
    role: user.role,
    ...(roles?.length ? { roles } : {}),
    orgId: user.org_id ?? null,
    avatarUrl: avatarUrl ?? user.avatar_url,
    provider: user.provider,
    // TODO.identity/06: the primary address's verification state (NULL on
    // rows that predate the console; the account page shows it honestly).
    emailVerifiedAt: user.email_verified_at ?? null,
    ...(amr?.length ? { amr } : {}),
  }
}

export function authenticateDemo(db: Database.Database, email: string, password: string): AuthUserPayload | null {
  const user = db.prepare("SELECT * FROM users WHERE email = ? AND provider = 'demo'").get(email) as any
  if (!user) return null
  // A deactivated account refuses sign-in (TODO.federation/12).
  if (user.active === 0) return null

  if (password === DEMO_PASSWORD) {
    db.prepare("UPDATE users SET last_login = datetime('now') WHERE id = ?").run(user.id)
    return toAuthPayload(user)
  }
  return null
}

export function createSession(db: Database.Database,
  userId: string,
  opts?: { idTokenHint?: string | null; userAgent?: string | null; ip?: string | null; amr?: string[] | null },
): string {
  const token = randomUUID()
  const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString()
  db.prepare('INSERT INTO sessions (id, user_id, token, expires_at, id_token_hint, user_agent, ip, last_seen_at, amr) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)')
    .run(randomUUID(), userId, token, expiresAt, opts?.idTokenHint ?? null, opts?.userAgent ?? null, opts?.ip ?? null, null,
      opts?.amr?.length ? JSON.stringify(opts.amr) : null)
  return token
}

/** Stamp the account's last sign-in (TODO.identity/07 — the OP's own
 *  sign-in paths call this; the demo/OAuth paths bump it inline). */
export function touchLastLogin(db: Database.Database, userId: string): void {
  db.prepare("UPDATE users SET last_login = datetime('now') WHERE id = ?").run(userId)
}

export function getSessionUser(db: Database.Database, token: string): AuthUserPayload | null {
  // The session joins the LIVE user row: a role reassignment takes
  // effect on the next request, and a deactivated account's sessions
  // stop resolving at once (TODO.federation/12).
  const session = db.prepare(`
    SELECT s.*, u.email, u.name, u.role, u.roles, u.org_id, u.avatar_url, u.provider, u.email_verified_at
    FROM sessions s JOIN users u ON s.user_id = u.id
    WHERE s.token = ? AND s.expires_at > datetime('now') AND u.active = 1
  `).get(token) as any
  if (!session) return null
  // TODO.identity/06: the last-active stamp, throttled to one write per
  // minute per session (the account console's sessions section shows it).
  db.prepare(
    "UPDATE sessions SET last_seen_at = datetime('now') WHERE token = ? AND (last_seen_at IS NULL OR last_seen_at < datetime('now', '-60 seconds'))",
  ).run(token)
  // s.* carries the SESSION's id — the payload's id is the USER's.
  const payload = toAuthPayload({ ...session, id: session.user_id })
  // TODO.identity-sso (the wave-A tail): the session's authentication
  // instant (sessions.created_at, verbatim) — the ID token's auth_time
  // derives from it (the consumer converts to the OIDC NumericDate).
  payload.sessionCreatedAt = session.created_at as string
  // TODO.identity/11: the active-org context (the membership model) —
  // the payload's org/roles follow the session's stamped context.
  return applySessionOrgContext(db, session.active_org ?? null, payload)
}

export function deleteSession(db: Database.Database, token: string): void {
  db.prepare('DELETE FROM sessions WHERE token = ?').run(token)
}

export function cleanExpiredSessions(db: Database.Database): void {
  db.prepare("DELETE FROM sessions WHERE expires_at <= datetime('now')").run()
}

// ── identity federation (TODO.federation/10) ──────────────────────────

import type { IdentityApproval } from '../../store'

interface UserRow {
  id: string
  email: string
  name: string
  role: string
  /** The full assigned role set as a JSON array (fed-12); NULL = the
   *  primary role only. */
  roles: string | null
  org_id: string | null
  avatar_url: string | null
  provider: string
  email_verified_at?: string | null
}

function userPayload(row: UserRow): AuthUserPayload {
  // The FULL assigned role set rides along (the OP's claim emission reads
  // it — the ID token's roles claim must reflect an assignment, not just
  // the primary role); absent = the primary role only.
  const roles = parseRoles(row.roles)
  return {
    id: row.id,
    email: row.email,
    name: row.name,
    role: row.role,
    ...(roles?.length ? { roles } : {}),
    orgId: row.org_id ?? null,
    avatarUrl: row.avatar_url ?? undefined,
    provider: row.provider,
    emailVerifiedAt: row.email_verified_at ?? null,
  }
}

export function findUserByEmail(db: Database.Database, email: string): AuthUserPayload | null {
  const row = db.prepare('SELECT * FROM users WHERE email = ?').get(email) as UserRow | undefined
  return row ? userPayload(row) : null
}

/** The account by its id (TODO.identity/01 — the OP's token endpoint
 *  resolves the code's user_id). */
export function getUserById(db: Database.Database, id: string): AuthUserPayload | null {
  const row = db.prepare('SELECT * FROM users WHERE id = ?').get(id) as UserRow | undefined
  return row ? userPayload(row) : null
}

export function findUserByProvider(db: Database.Database, provider: string, providerAccountId: string): AuthUserPayload | null {
  const row = db.prepare(
    'SELECT * FROM users WHERE provider = ? AND provider_account_id = ?',
  ).get(provider, providerAccountId) as UserRow | undefined
  return row ? userPayload(row) : null
}

export function provisionSsoUser(db: Database.Database, input: {
  email: string
  name: string
  provider: string
  providerAccountId: string
  role: string
  orgId: string | null
}): AuthUserPayload {
  const id = randomUUID()
  db.prepare(
    'INSERT INTO users (id, email, name, provider, provider_account_id, role, org_id, last_login) VALUES (?, ?, ?, ?, ?, ?, ?, datetime(\'now\'))',
  ).run(id, input.email, input.name, input.provider, input.providerAccountId, input.role, input.orgId)
  if (input.orgId) syncPrimaryMembership(db, id) // TODO.identity/11 — the mirror
  return { id, email: input.email, name: input.name, role: input.role, orgId: input.orgId }
}

export function updateUserRoleOrg(db: Database.Database, userId: string, role: string, orgId: string | null): void {
  db.prepare('UPDATE users SET role = ?, org_id = ? WHERE id = ?').run(role, orgId, userId)
  if (orgId) syncPrimaryMembership(db, userId) // TODO.identity/11 — the mirror
}

interface IdentityApprovalRow {
  id: string
  email: string
  name: string
  issuer: string
  sub: string
  claims_json: string | null
  status: 'pending' | 'approved' | 'rejected'
  decided_role: string | null
  decided_org: string | null
  decided_by: string | null
  created_at: string
  last_seen: string | null
  decided_at: string | null
}

function approvalPayload(row: IdentityApprovalRow): IdentityApproval {
  return {
    id: row.id,
    email: row.email,
    name: row.name,
    issuer: row.issuer,
    sub: row.sub,
    claimsJson: row.claims_json,
    status: row.status,
    decidedRole: row.decided_role,
    decidedOrg: row.decided_org,
    decidedBy: row.decided_by,
    createdAt: row.created_at,
    lastSeen: row.last_seen ?? row.created_at,
    decidedAt: row.decided_at,
  }
}

// ── the SSO sign-in state jar (TODO.identity/04) ────────────────────

import type { SsoSignInState } from '../../store'

interface SsoStateRow {
  state: string
  nonce: string
  verifier: string
  expires_at: string
}

// ── federation peers (TODO.federation/04) ────────────────────────────

import type { FederationPeer } from '../../store'

interface FederationPeerRow {
  id: string
  name: string
  roles: string
  descriptor_url: string | null
  descriptor_json: string
  pinned_via: 'url' | 'manual' | 'directory'
  connectivity: 'verified' | 'unverified'
  status: 'active' | 'revoked'
  added_at: string
  added_by: string | null
  refreshed_at: string | null
  revoked_at: string | null
  revoked_by: string | null
}

function peerPayload(row: FederationPeerRow): FederationPeer {
  return {
    id: row.id,
    name: row.name,
    roles: row.roles,
    descriptorUrl: row.descriptor_url,
    descriptorJson: row.descriptor_json,
    pinnedVia: row.pinned_via,
    connectivity: row.connectivity,
    status: row.status,
    addedAt: row.added_at,
    addedBy: row.added_by,
    refreshedAt: row.refreshed_at,
    revokedAt: row.revoked_at,
    revokedBy: row.revoked_by,
  }
}

// ── User administration (TODO.federation/12 — multi-user instances) ──
// The instance's users are listed, created (the local/demo-provider
// path), reassigned and deactivated through the users API
// (server/routes/users.ts, gated by the users.manage permission).

import type { UserAdminRow } from '../../store'

function toAdminRow(user: any): UserAdminRow {
  return {
    id: user.id,
    email: user.email,
    name: user.name,
    role: user.role,
    roles: parseRoles(user.roles) ?? [user.role],
    orgId: user.org_id ?? null,
    active: user.active !== 0,
    provider: user.provider,
    lastLogin: user.last_login ?? null,
    emailVerifiedAt: user.email_verified_at ?? null,
  }
}

export function listUsers(db: Database.Database): UserAdminRow[] {
  return (db.prepare('SELECT * FROM users ORDER BY name').all() as any[]).map(toAdminRow)
}

/** Create a LOCAL user (the demo provider — the self-hosted instance's
 *  account path; OIDC-linked users arrive through item 10's linking and
 *  get roles assigned here the same way). Signs in with the instance's
 *  local password (DEMO_PASSWORD) — documented in docs/deployment/
 *  rbac.md. */
export function createLocalUser(db: Database.Database, input: {
  email: string
  name: string
  role: string
  roles?: string[]
  orgId?: string | null
}): UserAdminRow {
  const id = randomUUID()
  const roles = input.roles?.length ? input.roles : [input.role]
  db.prepare(
    `INSERT INTO users (id, email, name, provider, provider_account_id, role, roles, org_id)
     VALUES (?, ?, ?, 'demo', ?, ?, ?, ?)`,
  ).run(id, input.email, input.name, input.email, input.role, JSON.stringify(roles), input.orgId ?? null)
  if (input.orgId) syncPrimaryMembership(db, id) // TODO.identity/11 — the mirror
  return toAdminRow(db.prepare('SELECT * FROM users WHERE id = ?').get(id))
}

/** Reassign a user's roles: `role` becomes the section-gating primary,
 *  `roles` the full permission set (validated against the instance's
 *  role map by the route — the store trusts its caller). */
export function setUserRoles(db: Database.Database, id: string, role: string, roles: string[]): boolean {
  const res = db.prepare('UPDATE users SET role = ?, roles = ? WHERE id = ?')
    .run(role, JSON.stringify(roles.length ? roles : [role]), id)
  if (res.changes > 0) syncPrimaryMembership(db, id) // TODO.identity/11 — the mirror (a no-op for org-free accounts)
  return res.changes > 0
}

/** Deactivate/reactivate: sessions stop resolving immediately (the
 *  getSessionUser join) and demo sign-in refuses. */
export function setUserActive(db: Database.Database, id: string, active: boolean): boolean {
  const res = db.prepare('UPDATE users SET active = ? WHERE id = ?').run(active ? 1 : 0, id)
  return res.changes > 0
}

// ── organization administration (TODO.identity/10) ───────────────────
// The self-service join requests: org-bound rows land with the org's
// admin; org_id NULL rows (the "not listed" path) land with BIML. The
// decision is atomic on status='pending'.

import type { OrgJoinRequest } from '../../store'

interface OrgJoinRequestRow {
  id: string
  name: string
  email: string
  org_id: string | null
  org_name_text: string | null
  requested_role: string
  note: string | null
  status: 'pending' | 'approved' | 'refused'
  decided_by: string | null
  decided_at: string | null
  refusal_reason: string | null
  invited_user_id: string | null
  created_at: string
}

function joinRequestPayload(row: OrgJoinRequestRow): OrgJoinRequest {
  return {
    id: row.id,
    name: row.name,
    email: row.email,
    orgId: row.org_id,
    orgNameText: row.org_name_text,
    requestedRole: row.requested_role,
    note: row.note,
    status: row.status,
    decidedBy: row.decided_by,
    decidedAt: row.decided_at,
    refusalReason: row.refusal_reason,
    invitedUserId: row.invited_user_id,
    createdAt: row.created_at,
  }
}

export function createOrgJoinRequest(db: Database.Database, input: {
  name: string
  email: string
  orgId: string | null
  orgNameText: string | null
  requestedRole: string
  note?: string | null
}): OrgJoinRequest {
  const id = randomUUID()
  db.prepare(
    `INSERT INTO org_join_requests (id, name, email, org_id, org_name_text, requested_role, note)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
  ).run(id, input.name, input.email, input.orgId, input.orgNameText, input.requestedRole, input.note ?? null)
  return joinRequestPayload(db.prepare('SELECT * FROM org_join_requests WHERE id = ?').get(id) as OrgJoinRequestRow)
}

export function getOrgJoinRequest(db: Database.Database, id: string): OrgJoinRequest | null {
  const row = db.prepare('SELECT * FROM org_join_requests WHERE id = ?').get(id) as OrgJoinRequestRow | undefined
  return row ? joinRequestPayload(row) : null
}

export function listOrgJoinRequests(db: Database.Database, filter?: {
  scope?: 'org' | 'unregistered' | 'all'
  orgId?: string
  status?: OrgJoinRequest['status']
}): OrgJoinRequest[] {
  const scope = filter?.scope ?? 'all'
  const where: string[] = []
  const args: unknown[] = []
  if (scope === 'org') { where.push('org_id = ?'); args.push(filter?.orgId ?? '') }
  if (scope === 'unregistered') where.push('org_id IS NULL')
  if (filter?.status) { where.push('status = ?'); args.push(filter.status) }
  const sql = `SELECT * FROM org_join_requests${where.length ? ` WHERE ${where.join(' AND ')}` : ''} ORDER BY created_at`
  const rows = db.prepare(sql).all(...args) as OrgJoinRequestRow[]
  return rows.map(joinRequestPayload)
}

export function decideOrgJoinRequest(db: Database.Database,
  id: string,
  decision: {
    status: 'approved' | 'refused'
    decidedBy: string
    refusalReason?: string | null
    invitedUserId?: string | null
  },
): OrgJoinRequest | null {
  // Atomic on 'pending' — a double decide (two admins, a resubmit) loses.
  const res = db.prepare(
    `UPDATE org_join_requests
     SET status = ?, decided_by = ?, decided_at = datetime('now'), refusal_reason = ?, invited_user_id = ?
     WHERE id = ? AND status = 'pending'`,
  ).run(decision.status, decision.decidedBy, decision.refusalReason ?? null, decision.invitedUserId ?? null, id)
  if (res.changes === 0) return null
  return getOrgJoinRequest(db, id)
}

export function findPendingOrgJoinRequestByEmail(db: Database.Database, email: string): OrgJoinRequest | null {
  const row = db.prepare(
    `SELECT * FROM org_join_requests WHERE email = ? AND status = 'pending' ORDER BY created_at`,
  ).get(email) as OrgJoinRequestRow | undefined
  return row ? joinRequestPayload(row) : null
}

// ── organization memberships (TODO.identity/11 — the multi-org model) ──
// One row per (account, org): the per-org role set + the lifecycle
// state. THE DUAL-READ DOCTRINE: users.org_id/roles stay the
// backward-compatible read — the PRIMARY membership's mirror — until
// every consumer reads the memberships. syncPrimaryMembership (the
// mirror) rides every legacy writer above; setOrgMembershipRoles on a
// primary row writes the columns back. resolveOrgContext (the shared
// pure rule, ../../store) decides what a session/token actually acts
// AS; the columns' last writer never resurrects a disabled membership.

import type { OrgMembership, OrgMembershipState } from '../../store'
import { resolveOrgContext, parseOrgMemberCone } from '../../store'

interface OrgMembershipRow {
  id: string
  user_id: string
  org_id: string
  roles: string
  /** TODO.identity-features/09 — the membership's data cone (the nullable
   *  column; absent on a pre-migration row read). */
  cone?: string | null
  state: OrgMembershipState
  is_primary: number
  invited_by: string | null
  created_at: string
  activated_at: string | null
  disabled_at: string | null
  disabled_by: string | null
}

function membershipPayload(row: OrgMembershipRow): OrgMembership {
  return {
    id: row.id,
    userId: row.user_id,
    orgId: row.org_id,
    roles: parseRoles(row.roles) ?? [],
    // The cone (TODO.identity-features/09): NULL parses to the org-wide
    // default — a pre-existing membership keeps its posture silently.
    cone: parseOrgMemberCone(row.cone),
    state: row.state,
    isPrimary: row.is_primary === 1,
    invitedBy: row.invited_by,
    createdAt: row.created_at,
    activatedAt: row.activated_at,
    disabledAt: row.disabled_at,
    disabledBy: row.disabled_by,
  }
}

/** THE MIRROR (the dual-read doctrine's write half): re-project the
 *  PRIMARY membership from the users row's legacy columns. Every legacy
 *  writer calls it after its update; an org-free account holds no
 *  primary membership. A DISABLED row keeps its state (the mirror never
 *  resurrects it — only roles + the primary mark move). Idempotent. */
export function syncPrimaryMembership(db: Database.Database, userId: string): void {
  const user = db.prepare('SELECT id, role, roles, org_id FROM users WHERE id = ?').get(userId) as
    { id: string; role: string; roles: string | null; org_id: string | null } | undefined
  if (!user || !user.org_id) return
  const roles = parseRoles(user.roles) ?? [user.role]
  db.prepare('UPDATE org_memberships SET is_primary = 0 WHERE user_id = ? AND org_id != ? AND is_primary = 1')
    .run(userId, user.org_id)
  db.prepare(
    `INSERT INTO org_memberships (id, user_id, org_id, roles, state, is_primary, activated_at)
     VALUES (?, ?, ?, ?, 'active', 1, datetime('now'))
     ON CONFLICT (user_id, org_id) DO UPDATE SET roles = excluded.roles, is_primary = 1`,
  ).run(randomUUID(), userId, user.org_id, JSON.stringify(roles))
}

/** The session payload under the org context (getSessionUser's hook):
 *  the shared rule resolves the effective org + roles; a stale stamp
 *  (the membership was disabled or removed mid-session) is cleared on
 *  the read that notices it. */
function applySessionOrgContext(db: Database.Database, activeOrg: string | null, payload: AuthUserPayload): AuthUserPayload {
  const active = activeOrg ? getOrgMembership(db, payload.id, activeOrg) : null
  const primary = payload.orgId ? getOrgMembership(db, payload.id, payload.orgId) : null
  const resolved = resolveOrgContext(payload, { activeOrg, active, primary })
  if (activeOrg && !(active && active.state === 'active')) {
    db.prepare('UPDATE sessions SET active_org = NULL WHERE user_id = ? AND active_org = ?').run(payload.id, activeOrg)
  }
  // TODO.identity-features/09: the context membership's cone rides the
  // payload — the entity gates enforce it without a store round-trip.
  return { ...payload, orgId: resolved.orgId, roles: resolved.roles, cone: resolved.cone }
}

export function listOrgMemberships(db: Database.Database, userId: string): OrgMembership[] {
  const rows = db.prepare(
    'SELECT * FROM org_memberships WHERE user_id = ? ORDER BY is_primary DESC, created_at',
  ).all(userId) as OrgMembershipRow[]
  return rows.map(membershipPayload)
}

export function listOrgMembers(db: Database.Database, orgId: string): OrgMembership[] {
  const rows = db.prepare(
    'SELECT * FROM org_memberships WHERE org_id = ? ORDER BY created_at',
  ).all(orgId) as OrgMembershipRow[]
  return rows.map(membershipPayload)
}

export function listAllOrgMemberships(db: Database.Database): OrgMembership[] {
  const rows = db.prepare(
    'SELECT * FROM org_memberships ORDER BY org_id, created_at',
  ).all() as OrgMembershipRow[]
  return rows.map(membershipPayload)
}

export function getOrgMembership(db: Database.Database, userId: string, orgId: string): OrgMembership | null {
  const row = db.prepare('SELECT * FROM org_memberships WHERE user_id = ? AND org_id = ?')
    .get(userId, orgId) as OrgMembershipRow | undefined
  return row ? membershipPayload(row) : null
}

/** Create the membership. NULL on the (user, org) conflict — the honest
 *  "already a member" (the route's 409). 'active' stamps activated_at;
 *  'invited' waits for the holder's accept. */
export function createOrgMembership(db: Database.Database, input: {
  userId: string
  orgId: string
  roles: string[]
  state: OrgMembershipState
  invitedBy?: string | null
}): OrgMembership | null {
  const res = db.prepare(
    `INSERT OR IGNORE INTO org_memberships (id, user_id, org_id, roles, state, invited_by, activated_at)
     VALUES (?, ?, ?, ?, ?, ?, CASE WHEN ? = 'active' THEN datetime('now') ELSE NULL END)`,
  ).run(
    randomUUID(), input.userId, input.orgId, JSON.stringify(input.roles), input.state,
    input.invitedBy ?? null, input.state,
  )
  if (res.changes === 0) return null
  return getOrgMembership(db, input.userId, input.orgId)
}

/** Replace the per-org role set. The PRIMARY membership's write mirrors
 *  into the users row's roles (the dual-write; the section-gating
 *  primary role moves only when it fell out of the set). The route
 *  refuses an EMPTY set on the primary (the legacy columns carry no
 *  empty-set concept); the store's mirror writes the primary role in
 *  that case, keeping the columns honest. */
export function setOrgMembershipRoles(db: Database.Database, userId: string, orgId: string, roles: string[]): boolean {
  const res = db.prepare('UPDATE org_memberships SET roles = ? WHERE user_id = ? AND org_id = ?')
    .run(JSON.stringify(roles), userId, orgId)
  if (res.changes === 0) return false
  const membership = getOrgMembership(db, userId, orgId)
  if (membership?.isPrimary) {
    const user = db.prepare('SELECT role FROM users WHERE id = ?').get(userId) as { role: string } | undefined
    if (user) {
      const primaryRole = roles.includes(user.role) ? user.role : (roles[0] ?? user.role)
      db.prepare('UPDATE users SET role = ?, roles = ? WHERE id = ?')
        .run(primaryRole, JSON.stringify(roles.length ? roles : [primaryRole]), userId)
    }
  }
  return true
}

/** The lifecycle act. Disabling also ends the live context: every
 *  session stamped with the org falls back to the primary context (the
 *  stamp is cleared here, and any in-flight OIDC code's context is
 *  re-judged against the live membership at the exchange). */
export function setOrgMembershipState(db: Database.Database,
  userId: string,
  orgId: string,
  state: OrgMembershipState,
  actor?: string | null,
): OrgMembership | null {
  const existing = getOrgMembership(db, userId, orgId)
  if (!existing) return null
  if (state === 'active') {
    // Re-activation clears the disable stamps (the row reads honestly).
    db.prepare("UPDATE org_memberships SET state = 'active', activated_at = datetime('now'), disabled_at = NULL, disabled_by = NULL WHERE user_id = ? AND org_id = ?")
      .run(userId, orgId)
  } else if (state === 'disabled') {
    db.prepare("UPDATE org_memberships SET state = 'disabled', disabled_at = datetime('now'), disabled_by = ? WHERE user_id = ? AND org_id = ?")
      .run(actor ?? null, userId, orgId)
    db.prepare('UPDATE sessions SET active_org = NULL WHERE user_id = ? AND active_org = ?').run(userId, orgId)
  } else {
    db.prepare("UPDATE org_memberships SET state = 'invited' WHERE user_id = ? AND org_id = ?").run(userId, orgId)
  }
  return getOrgMembership(db, userId, orgId)
}

/** Set the membership's data cone (TODO.identity-features/09): the
 *  canonical column spelling, or NULL for the org-wide default. Answers
 *  null when no membership exists. */
export function setOrgMembershipCone(db: Database.Database, userId: string, orgId: string, cone: string | null): OrgMembership | null {
  const existing = getOrgMembership(db, userId, orgId)
  if (!existing) return null
  db.prepare('UPDATE org_memberships SET cone = ? WHERE user_id = ? AND org_id = ?').run(cone, userId, orgId)
  return getOrgMembership(db, userId, orgId)
}

/** Remove the row (the holder declining an invitation; the erasure's
 *  cleanup). The route refuses the PRIMARY membership. */
export function deleteOrgMembership(db: Database.Database, userId: string, orgId: string): boolean {
  const res = db.prepare('DELETE FROM org_memberships WHERE user_id = ? AND org_id = ?').run(userId, orgId)
  if (res.changes > 0) {
    db.prepare('UPDATE sessions SET active_org = NULL WHERE user_id = ? AND active_org = ?').run(userId, orgId)
  }
  return res.changes > 0
}

/** The session's stamped active-org context (NULL = the primary
 *  context; also NULL for an unknown/expired token). */
export function getSessionActiveOrg(db: Database.Database, token: string): string | null {
  const row = db.prepare("SELECT active_org FROM sessions WHERE token = ? AND expires_at > datetime('now')")
    .get(token) as { active_org: string | null } | undefined
  return row?.active_org ?? null
}

/** Stamp the session's active-org context (the route validated the
 *  membership first); NULL clears to the primary context. */
export function setSessionActiveOrg(db: Database.Database, token: string, orgId: string | null): boolean {
  const res = db.prepare("UPDATE sessions SET active_org = ? WHERE token = ? AND expires_at > datetime('now')")
    .run(orgId, token)
  return res.changes > 0
}

// ── the organization registry (TODO.identity-features/05) ────────────
// The identity service's OWN org registry: the first-class organizations
// the membership graph references by id. The lifecycle acts are the
// routes' (the disable cascade loops setOrgMembershipState); these are
// the row reads/writes.

import type { OrgRegistryContact, OrgRegistryOrg, OrgRegistryState } from '../../store'

interface OrgRegistryRow {
  id: string
  name: string
  short_name: string | null
  kind: string | null
  country: string | null
  contacts: string
  participant_ref: string | null
  designated_by: string | null
  proposed_by: string | null
  cs_status: string | null
  state: OrgRegistryState
  created_at: string
  created_by: string | null
  updated_at: string | null
  updated_by: string | null
  disabled_at: string | null
  disabled_by: string | null
}

/** The contacts column's defensive parse: a malformed row entry is
 *  skipped, never trusted (an entry is a contact only with its email). */
export function parseOrgContacts(json: string | null): OrgRegistryContact[] {
  if (!json) return []
  try {
    const parsed = JSON.parse(json) as unknown
    if (!Array.isArray(parsed)) return []
    return parsed
      .filter((e): e is Record<string, unknown> => !!e && typeof e === 'object')
      .map(e => ({ name: typeof e.name === 'string' && e.name.trim() ? e.name.trim() : null, email: typeof e.email === 'string' ? e.email.trim() : '' }))
      .filter(e => e.email.includes('@'))
  } catch {
    return []
  }
}

function orgRegistryPayload(row: OrgRegistryRow): OrgRegistryOrg {
  return {
    id: row.id,
    name: row.name,
    shortName: row.short_name,
    kind: row.kind,
    country: row.country,
    contacts: parseOrgContacts(row.contacts),
    participantRef: row.participant_ref,
    designatedBy: row.designated_by ?? null,
    proposedBy: row.proposed_by ?? null,
    csStatus: row.cs_status ?? null,
    state: row.state,
    createdAt: row.created_at,
    createdBy: row.created_by,
    updatedAt: row.updated_at,
    updatedBy: row.updated_by,
    disabledAt: row.disabled_at,
    disabledBy: row.disabled_by,
  }
}

export function listOrgRegistryOrgs(db: Database.Database): OrgRegistryOrg[] {
  const rows = db.prepare('SELECT * FROM org_registry').all() as OrgRegistryRow[]
  return rows.map(orgRegistryPayload).sort((a, b) => a.name.localeCompare(b.name))
}

export function getOrgRegistryOrg(db: Database.Database, id: string): OrgRegistryOrg | null {
  const row = db.prepare('SELECT * FROM org_registry WHERE id = ?').get(id) as OrgRegistryRow | undefined
  return row ? orgRegistryPayload(row) : null
}

/** Add the organization; NULL on the id conflict (the slug is taken). */
export function createOrgRegistryOrg(db: Database.Database, input: {
  id: string
  name: string
  shortName?: string | null
  kind?: string | null
  country?: string | null
  contacts?: OrgRegistryContact[]
  participantRef?: string | null
  designatedBy?: string | null
  proposedBy?: string | null
  csStatus?: string | null
  createdBy?: string | null
}): OrgRegistryOrg | null {
  const res = db.prepare(
    `INSERT OR IGNORE INTO org_registry (id, name, short_name, kind, country, contacts, participant_ref, designated_by, proposed_by, cs_status, created_by)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  ).run(
    input.id, input.name, input.shortName ?? null, input.kind ?? null, input.country ?? null,
    JSON.stringify(input.contacts ?? []), input.participantRef ?? null,
    input.designatedBy ?? null, input.proposedBy ?? null, input.csStatus ?? null, input.createdBy ?? null,
  )
  if (res.changes === 0) return null
  return getOrgRegistryOrg(db, input.id)
}

/** Edit the display data (the id never moves); stamps updated_at/by.
 *  NULL when the registry does not carry the org. */
export function updateOrgRegistryOrg(db: Database.Database,
  id: string,
  patch: {
    name?: string
    shortName?: string | null
    kind?: string | null
    country?: string | null
    contacts?: OrgRegistryContact[]
    participantRef?: string | null
    designatedBy?: string | null
    proposedBy?: string | null
    csStatus?: string | null
  },
  actor?: string | null,
): OrgRegistryOrg | null {
  const sets: string[] = []
  const params: unknown[] = []
  if (patch.name !== undefined) { sets.push('name = ?'); params.push(patch.name) }
  if (patch.shortName !== undefined) { sets.push('short_name = ?'); params.push(patch.shortName) }
  if (patch.kind !== undefined) { sets.push('kind = ?'); params.push(patch.kind) }
  if (patch.country !== undefined) { sets.push('country = ?'); params.push(patch.country) }
  if (patch.contacts !== undefined) { sets.push('contacts = ?'); params.push(JSON.stringify(patch.contacts)) }
  if (patch.participantRef !== undefined) { sets.push('participant_ref = ?'); params.push(patch.participantRef) }
  if (patch.designatedBy !== undefined) { sets.push('designated_by = ?'); params.push(patch.designatedBy) }
  if (patch.proposedBy !== undefined) { sets.push('proposed_by = ?'); params.push(patch.proposedBy) }
  if (patch.csStatus !== undefined) { sets.push('cs_status = ?'); params.push(patch.csStatus) }
  sets.push("updated_at = datetime('now')", 'updated_by = ?')
  params.push(actor ?? null)
  const res = db.prepare(`UPDATE org_registry SET ${sets.join(', ')} WHERE id = ?`).run(...params, id)
  if (res.changes === 0) return null
  return getOrgRegistryOrg(db, id)
}

/** The lifecycle act: disable stamps disabled_at/by; re-enable clears
 *  them (the memberships stay as they are — re-activation is the
 *  per-membership deliberate act). NULL when the org is unknown. */
export function setOrgRegistryOrgState(db: Database.Database, id: string, state: OrgRegistryState, actor?: string | null): OrgRegistryOrg | null {
  const existing = getOrgRegistryOrg(db, id)
  if (!existing) return null
  if (state === 'disabled') {
    db.prepare("UPDATE org_registry SET state = 'disabled', disabled_at = datetime('now'), disabled_by = ? WHERE id = ?")
      .run(actor ?? null, id)
  } else {
    db.prepare("UPDATE org_registry SET state = 'active', disabled_at = NULL, disabled_by = NULL WHERE id = ?")
      .run(id)
  }
  return getOrgRegistryOrg(db, id)
}

/** The erasure-adjacent hard delete (the route guards it: an org that
 *  ever held a membership, or that a join request references, disables
 *  instead). */
export function deleteOrgRegistryOrg(db: Database.Database, id: string): boolean {
  const res = db.prepare('DELETE FROM org_registry WHERE id = ?').run(id)
  return res.changes > 0
}

// ── the register's holder-org attribution (TODO.register/02) ─────────
// The certificate_holder_orgs / certificate_holder_claims tables (the
// 0015 migration): which OP org a registered certificate belongs to (the
// hub's own record), and the legacy-row claim act's state machine.

import type { CertificateHolderClaim, CertificateHolderOrg } from '../../store'

interface HolderOrgRow {
  certificate_id: string
  org_id: string
  org_name: string
  source: string
  attributed_at: string
  attributed_by: string | null
  claim_id: string | null
}

function holderOrgPayload(row: HolderOrgRow): CertificateHolderOrg {
  return {
    certificateId: row.certificate_id,
    orgId: row.org_id,
    orgName: row.org_name,
    source: row.source as CertificateHolderOrg['source'],
    attributedAt: row.attributed_at,
    attributedBy: row.attributed_by,
    claimId: row.claim_id,
  }
}

interface HolderClaimRow {
  id: string
  certificate_id: string
  claimant_org_id: string
  claimant_org_name: string
  matched_holder_name: string
  claimed_by: string
  state: string
  decided_by: string | null
  decided_at: string | null
  refusal_reason: string | null
  created_at: string
}

function holderClaimPayload(row: HolderClaimRow): CertificateHolderClaim {
  return {
    id: row.id,
    certificateId: row.certificate_id,
    claimantOrgId: row.claimant_org_id,
    claimantOrgName: row.claimant_org_name,
    matchedHolderName: row.matched_holder_name,
    claimedBy: row.claimed_by,
    state: row.state as CertificateHolderClaim['state'],
    decidedBy: row.decided_by,
    decidedAt: row.decided_at,
    refusalReason: row.refusal_reason,
    createdAt: row.created_at,
  }
}

// ── the instrument register (TODO.register/03) ─────────────────────────
// The platform-side serial register: one row per instrument registered
// under a type certificate's scope. The scope check + the cones are the
// route's (browser/server/routes/registrations.ts); these are the row
// reads/writes. Every row returned is a registration that STOOD — the
// refused (out-of-scope) declaration never lands.

import type {
  InstrumentRegistration,
  InstrumentRegistrationLifecycle,
  InstrumentRegistrationScopeStatus,
  InstrumentRegistrationWriteInput,
} from '../../store'
import { INSTRUMENT_REGISTRATIONS_CHUNK } from '../../store'

interface InstrumentRegistrationRow {
  id: string
  certificate_id: string
  holder_org_id: string
  standard_id: string
  serial_number: string
  manufacture_date: string | null
  designations: string
  scope_status: InstrumentRegistrationScopeStatus
  scope_detail: string | null
  lifecycle: InstrumentRegistrationLifecycle
  registered_at: string
  registered_by: string | null
  updated_at: string | null
  updated_by: string | null
}

/** The designations column's defensive parse: a malformed cell reads as
 *  the empty object, never trusted (the parseOrgContacts posture). */
function parseDesignations(json: string | null): Record<string, unknown> {
  if (!json) return {}
  try {
    const parsed = JSON.parse(json) as unknown
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed as Record<string, unknown> : {}
  } catch {
    return {}
  }
}

function instrumentRegistrationPayload(row: InstrumentRegistrationRow): InstrumentRegistration {
  return {
    id: row.id,
    certificateId: row.certificate_id,
    holderOrgId: row.holder_org_id,
    standardId: row.standard_id,
    serialNumber: row.serial_number,
    manufactureDate: row.manufacture_date,
    designations: parseDesignations(row.designations),
    scopeStatus: row.scope_status,
    scopeDetail: row.scope_detail,
    lifecycle: row.lifecycle,
    registeredAt: row.registered_at,
    registeredBy: row.registered_by,
    updatedAt: row.updated_at,
    updatedBy: row.updated_by,
  }
}
