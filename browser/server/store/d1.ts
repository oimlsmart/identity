// ═══════════════════════════════════════════════════════════════════
// The D1 ServerStore (TODO.cs-e2e/14 — the Cloudflare deployment):
// the SAME surface as the SQLite store (server/db/store.ts +
// entities.ts) against a Cloudflare D1 binding — D1 IS SQLite, so the
// schema (schema.sql, and the canonical migration set under
// migrations/) and every statement port directly; only the driver
// calls change (prepare/bind/run, async).
//
// WORKER-SAFE: the only import is the D1 TYPE (erased at build) — no
// node built-ins, no better-sqlite3. The binding arrives from the
// Worker entry (server/cloudflare.ts), which installs this store when
// env.DB is present — the binding-presence profile switch, the same
// pattern ENTITY_BACKEND uses client-side.
//
// Local proof: the smart monorepo's browser/src/__tests__/
// d1-store.test.ts runs this class against a better-sqlite3-backed D1
// facade (the binding contract with real semantics) plus the real
// workerd binding through scripts/cloudflare-smoke.ts there.
//
// THE BOUNDED-WRITE DISCIPLINE (the 2026-09-01 outage's lesson): every
// write/batch/DDL statement races a confirmation budget (the default
// DEFAULT_STORE_WRITE_BUDGET_MS, tunable per deployment through the
// consumer's STORE_WRITE_BUDGET_MS env binding) — a slow/hung store
// write answers StoreUnavailable in seconds, never spins the request
// forever. READS stay unbounded here: the read-path latency story is
// read replication, not this bound. The constructor wraps the binding
// in the bounded facade ONCE (boundedD1Writes below); the ensure memos
// key on the RAW binding (a rejected chain still evicts itself).
// ═══════════════════════════════════════════════════════════════════

import type { D1Database, D1PreparedStatement, D1Result } from '@cloudflare/workers-types'
import {
  APPEND_EVENTS_CHUNK,
  DEMO_PASSWORD,
  EVENTS_BULK_KEY_CHUNK,
  EVENTS_ID_CHUNK,
  INSTRUMENT_REGISTRATIONS_CHUNK,
  PUT_ENTITIES_CHUNK,
  StoreUnavailable,
  type AccountEmail,
  type AddAccountEmailResult,
  type AdvanceCounterResult,
  type AuthUserPayload,
  type CompleteEmailChangeResult,
  type CompleteEnrollmentResult,
  type ConsumeOidcRefreshTokenResult,
  type EmailChangeToken,
  type EnrollmentToken,
  type EntityChange,
  type EntityListOptions,
  type EntityRow,
  type EntityWriteInput,
  type EventEntityKey,
  type EventKeyFilter,
  type EventWriteInput,
  type FederationPeer,
  type IdentityApproval,
  type IdentityLink,
  type IdentityProvider,
  type MfaPending,
  type NotifyDelivery,
  type NotifyDeliveryStatus,
  type NotifyEntityMute,
  type NotifyInboxState,
  type NotifyPreferences,
  type NotifyRule,
  type OAuthInitialAssignment,
  type OidcAccessToken,
  type OidcAuthorization,
  type OidcClient,
  type OidcClientLaunch,
  type OidcCode,
  type OidcConsentGrant,
  type OidcKeyRow,
  type OidcRefreshToken,
  consentGrantCovers,
  normalizeOidcScopeSet,
  type OpAccountErasure,
  type OpClientRoleAssignment,
  type OpLiveSession,
  type OrgJoinRequest,
  type OrgMembership,
  type OrgMembershipState,
  type CertificateHolderClaim,
  type CertificateHolderOrg,
  type OrgRegistryContact,
  type OrgRegistryOrg,
  type OrgRegistryState,
  type InstrumentRegistration,
  type InstrumentRegistrationLifecycle,
  type InstrumentRegistrationScopeStatus,
  type InstrumentRegistrationWriteInput,
  type JournalAppend,
  type PersonalAccessToken,
  type PlatformEvent,
  resolveOrgContext,
  parseOrgMemberCone,
  type RecoveryCodeState,
  type ServerStore,
  type SessionView,
  type SsoSignInState,
  type TotpSecret,
  type UserAdminRow,
  type WebauthnChallenge,
  type WebauthnCredential,
} from '../store'
// TODO.federation/01 — the account plan follows the deployment profile
// (the Worker's seed route installs it from the env binding first; the
// slot defaults to the hub profile, which is exactly DEMO_ACCOUNTS).
import { getInstanceProfile, seedAccountsForProfile } from '../profile'

interface UserRecord {
  id: string
  email: string
  name: string
  role: string
  org_id: string | null
  avatar_url: string | null
  roles: string | null
  active: number
  provider: string
  email_verified_at?: string | null
}

function parseRoles(raw: string | null): string[] | undefined {
  if (!raw) return undefined
  try {
    const parsed = JSON.parse(raw) as unknown
    return Array.isArray(parsed) && parsed.length ? parsed.filter((v): v is string => typeof v === 'string') : undefined
  } catch {
    return undefined
  }
}

function toPayload(user: UserRecord, avatarUrl?: string): AuthUserPayload {
  const roles = parseRoles(user.roles)
  return {
    id: user.id,
    email: user.email,
    name: user.name,
    role: user.role,
    ...(roles?.length ? { roles } : {}),
    orgId: user.org_id ?? null,
    avatarUrl: avatarUrl ?? user.avatar_url ?? undefined,
    provider: user.provider,
    // TODO.identity/06: the primary address's verification state.
    emailVerifiedAt: user.email_verified_at ?? null,
  }
}

/** The identity_approvals row → the seam's camelCase shape. */
function toIdentityApproval(row: Record<string, unknown>): IdentityApproval {
  return {
    id: row.id as string,
    email: row.email as string,
    name: row.name as string,
    issuer: row.issuer as string,
    sub: row.sub as string,
    claimsJson: (row.claims_json as string | null) ?? null,
    status: row.status as IdentityApproval['status'],
    decidedRole: (row.decided_role as string | null) ?? null,
    decidedOrg: (row.decided_org as string | null) ?? null,
    decidedBy: (row.decided_by as string | null) ?? null,
    createdAt: row.created_at as string,
    lastSeen: (row.last_seen as string | null) ?? (row.created_at as string),
    decidedAt: (row.decided_at as string | null) ?? null,
  }
}

/** The federation_peers row → the seam's camelCase shape
 *  (TODO.federation/04). */
function toFederationPeer(row: Record<string, unknown>): FederationPeer {
  return {
    id: row.id as string,
    name: row.name as string,
    roles: row.roles as string,
    descriptorUrl: (row.descriptor_url as string | null) ?? null,
    descriptorJson: row.descriptor_json as string,
    pinnedVia: row.pinned_via as FederationPeer['pinnedVia'],
    connectivity: row.connectivity as FederationPeer['connectivity'],
    status: row.status as FederationPeer['status'],
    addedAt: row.added_at as string,
    addedBy: (row.added_by as string | null) ?? null,
    refreshedAt: (row.refreshed_at as string | null) ?? null,
    revokedAt: (row.revoked_at as string | null) ?? null,
    revokedBy: (row.revoked_by as string | null) ?? null,
  }
}

function toAdminRow(user: UserRecord & { last_login?: string | null; provider?: string }): UserAdminRow {
  return {
    id: user.id,
    email: user.email,
    name: user.name,
    role: user.role,
    roles: parseRoles(user.roles) ?? [user.role],
    orgId: user.org_id ?? null,
    active: user.active !== 0,
    provider: user.provider ?? 'demo',
    lastLogin: user.last_login ?? null,
    emailVerifiedAt: user.email_verified_at ?? null,
  }
}

/** The workflow tables the reset wipe covers, in a fixed order. Ranged
 *  rounds address rows by rowid (stable under deletion, so a resumed
 *  round never re-scans); every table here is an ordinary rowid table
 *  (none WITHOUT ROWID — schema.sql). The TODO.notify/01 event store
 *  wipes with them — its rows reference the workflow entities a reset
 *  removes (the feed's read-time visibility gate would drop the orphans
 *  anyway; wiping keeps the demo honest). TODO.notify/04: the delivery
 *  store wipes alongside (its rows reference the wiped events). */
const WIPE_TABLES = ['entity_changes', 'evidence_records', 'entities', 'events', 'instrument_registrations', 'notify_deliveries'] as const

// ── The ensure chains' memo scope (the 2026-09 portal-load audit, R2) ──
// Every defensive ensure below (a dev-database heal: the PRAGMA probes,
// the CREATE … IF NOT EXISTS, the idempotent membership backfill) was
// memoized on the store INSTANCE — but the Worker consumers install a
// store per request (the binding factory memoizes per binding OBJECT and
// the Workers runtime hands each request its own env, so the binding's
// identity is not guaranteed to recur), and the audit measured the
// ~13-statement chain on every authenticated request (~0.6–0.9 s on the
// demo hub's D1). The ensures are idempotent by construction, so the
// honest scope is the (binding, chain) pair held at MODULE scope: the
// Worker's isolate persists across requests and the consumer pins the
// binding (the smart repo's server/cloudflare.ts), so the same
// D1Database object recurs and the chain runs once per isolate. A
// consumer whose runtime rotates binding objects degrades to the old
// per-request posture — correct, just unmemoized. A REJECTED ensure
// evicts itself: the next call retries the heal.
interface EnsureMemos {
  usersColumns: Promise<void> | null
  sessionColumns: Promise<void> | null
  membershipSupport: Promise<void> | null
  orgRegistrySupport: Promise<void> | null
  holderAttributionSupport: Promise<void> | null
  instrumentRegistrationSupport: Promise<void> | null
  oidcColumns: Promise<void> | null
  personalAccessTokenSupport: Promise<void> | null
  consentGrantSupport: Promise<void> | null
  oidcRefreshTokenSupport: Promise<void> | null
  accountEmailSupport: Promise<void> | null
  notifyDeliverySupport: Promise<void> | null
}

const ensureMemosByBinding = new WeakMap<D1Database, EnsureMemos>()

/** Run the chain once per (binding, slot); a rejection evicts itself so
 *  the next caller retries. */
function ensured(binding: D1Database, slot: keyof EnsureMemos, run: () => Promise<void>): Promise<void> {
  let memos = ensureMemosByBinding.get(binding)
  if (!memos) {
    memos = {
      usersColumns: null, sessionColumns: null, membershipSupport: null,
      orgRegistrySupport: null, holderAttributionSupport: null,
      instrumentRegistrationSupport: null, oidcColumns: null,
      personalAccessTokenSupport: null, consentGrantSupport: null,
      oidcRefreshTokenSupport: null,
      accountEmailSupport: null, notifyDeliverySupport: null,
    }
    ensureMemosByBinding.set(binding, memos)
  }
  let pending = memos[slot]
  if (!pending) {
    pending = run()
    memos[slot] = pending
    pending.catch(() => { if (memos[slot] === pending) memos[slot] = null })
  }
  return pending
}

// TODO.identity/06's last-active stamp (getSessionUser's write): the
// DB-side 60 s WHERE clause stays the source of truth (a second
// isolate's write still lands through it); the in-isolate cache below
// simply never ISSUES the write the row would refuse — the audit's R2
// measured that write on every authenticated request. Keyed on the
// session token (per-isolate), capped so a long-lived isolate's map
// stays bounded (a cap reset only re-issues a write the DB clause then
// throttles — never a correctness change).
const lastSeenWrites = new Map<string, number>()
const LAST_SEEN_THROTTLE_MS = 60_000
const LAST_SEEN_CACHE_CAP = 4096

// ── The bounded-write discipline (the 2026-09-01 outage's lesson) ────
// Yesterday's outage: a cross-region path flap hung the identity
// service's D1 WRITES indefinitely and the login page spun for minutes.
// The discipline: every write/batch/DDL statement races a confirmation
// budget and a timeout answers StoreUnavailable — an honest error in
// seconds, never an infinite spin. READS (SELECT/PRAGMA/…) pass through
// untouched: the read-path latency story is read replication, a
// separate fix. The bound wraps the BINDING once at construction (the
// store's every write path — the 180+ .run() sites, the batches, the
// ensure chains' DDL — flows through it), so no call site changes.

/** The default write-confirmation budget: D1's healthy write latency is
 *  tens of ms; 5 s is two orders of magnitude past any honest p99 yet
 *  still "seconds" to a waiting human — the 503 reaches the login page
 *  before the browser's own patience ends. Tunable per deployment (the
 *  consumer's STORE_WRITE_BUDGET_MS env binding). */
export const DEFAULT_STORE_WRITE_BUDGET_MS = 5_000

export interface D1WriteBudgetOptions {
  /** The write/batch/DDL confirmation budget in ms. Absent:
   *  DEFAULT_STORE_WRITE_BUDGET_MS. */
  writeBudgetMs?: number
}

// ── D1 replica reads (TODO.restructure/28-E) ────────────────────────
// Cloudflare's Sessions API (the current docs, verified 2026-09-12):
// `withSession(constraint)` answers a session whose queries carry a
// bookmark — sequential consistency, the docs' own list including
// read-my-own-writes ("all writes done through the session will be
// visible in subsequent reads" — the workers-types contract on
// withSession). Replicas are read-only, so a write through the session
// lands on the primary anyway and ADVANCES the session's bookmark: the
// read-after-write sequence needs no special casing, it rides the same
// session and observes its own write. 'first-primary' pins only the
// FIRST query to the primary ("Use this option if you need to start
// the Session with the most up-to-date data") — an identity service's
// first read is the auth gate, so it starts fresh; every query after
// it may serve from a replica causally after that bookmark.
//
// THE SESSION'S SCOPE: one per store INSTANCE — instance state, never
// a module global. d1StoreFor memoizes one store per binding, so the
// session spans the isolate's request population: every query the
// isolate issues rides one sequentially-consistent thread, and the
// per-request installStore flip stays harmless (the memo answers the
// same object every request). Per-REQUEST sessions would need a
// request-scoped store install — the store-instance refactor's
// (TODO.restructure/28-D) territory, a named follow-up, never smuggled
// in here: with today's module-global install, per-request stores
// would bleed a sibling request's session across a mid-request await
// and a write-then-read pair could straddle the flip.
//
// The flag ships OFF (D1_REPLICA_READS unset): local suites prove the
// ROUTING on SQLite facades only — actual replica serving is the D1
// runtime's, proven in the preview cycle first (the ops runbook's
// preview-first rollout).
export interface D1ReplicaReadOptions {
  /** Route the store's statements through one withSession('first-primary')
   *  session per store instance (the discipline note above). Absent:
   *  off — statements ride the raw binding's bounded facade exactly as
   *  before. */
  replicaReads?: boolean
}

export type D1StoreOptions = D1WriteBudgetOptions & D1ReplicaReadOptions

/** The consumer-side env resolution (the resolveStoreWriteBudgetMs
 *  posture): D1_REPLICA_READS=1 — exactly '1', whitespace-trimmed —
 *  enables the replica-reads posture. Unset, empty, or any other
 *  value: OFF, the shipping default. */
export function d1ReplicaReadsEnabled(env?: { D1_REPLICA_READS?: string }): boolean {
  return env?.D1_REPLICA_READS?.trim() === '1'
}

/** The consumer-side env resolution (the resolveInstanceProfileFromEnv
 *  posture — the kernel never reads process.env; the Worker-safe
 *  modules take the env binding as an argument). Unset/garbage resolves
 *  undefined — the store's default stands, never a silent 0. */
export function resolveStoreWriteBudgetMs(env?: { STORE_WRITE_BUDGET_MS?: string }): number | undefined {
  const raw = env?.STORE_WRITE_BUDGET_MS?.trim()
  if (!raw) return undefined
  const parsed = Number.parseInt(raw, 10)
  return Number.isFinite(parsed) && parsed > 0 ? parsed : undefined
}

/** The write-classified leading verbs (DDL included). Everything else —
 *  SELECT, the PRAGMA probes, EXPLAIN — is a read and stays unbounded. */
const WRITE_STATEMENT = /^\s*(?:insert|update|delete|replace|create|alter|drop|vacuum|reindex)\b/i

/** The statement's idempotency posture for StoreUnavailable.retrySafe:
 *  the shapes whose replay converges after a write that may have
 *  landed — keyed UPDATE/DELETE/REPLACE, INSERT OR IGNORE/REPLACE, the
 *  ON CONFLICT upserts, the IF NOT EXISTS heals. A plain INSERT is NOT
 *  claimed safe (a retry could double-land). */
function writeRetrySafe(sql: string): boolean {
  if (/^\s*(?:update|delete|replace)\b/i.test(sql)) return true
  if (/^\s*insert\s+or\s+(?:ignore|replace)\b/i.test(sql)) return true
  if (/^\s*insert\b/i.test(sql) && /\bon\s+conflict\b/i.test(sql)) return true
  if (/^\s*create\b/i.test(sql) && /\bif\s+not\s+exists\b/i.test(sql)) return true
  return false
}

/** The error/log label for a write: the verb phrase + the target object
 *  ('UPDATE sessions', 'CREATE TABLE IF NOT EXISTS org_memberships').
 *  Never the bound values — the label is all an error may carry. */
function sqlWriteLabel(sql: string): string {
  const flat = sql.trim().replace(/\s+/g, ' ')
  const m = /^((?:insert(?:\s+or\s+(?:ignore|replace))?\s+into|update|delete\s+from|replace\s+into|create\s+(?:unique\s+)?(?:table|index)(?:\s+if\s+not\s+exists)?|alter\s+table|drop\s+(?:table|index)(?:\s+if\s+exists)?))\s+("?\w+"?)/i.exec(flat)
  if (m) return `${m[1].toUpperCase()} ${m[2]}`
  return flat.slice(0, 60)
}

/** Race a write against its confirmation budget. The in-flight write is
 *  never cancelled (D1 has no abort) — the race's handlers stay attached
 *  past the timeout, so a late settling (success OR failure) never
 *  surfaces as an unhandled rejection. */
function raceWriteBudget<T>(operation: string, budgetMs: number, retrySafe: boolean, pending: Promise<T>): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(new StoreUnavailable(operation, budgetMs, retrySafe)), budgetMs)
    pending.then(
      value => { clearTimeout(timer); resolve(value) },
      (error: unknown) => { clearTimeout(timer); reject(error) },
    )
  })
}

/** The wrapper → the underlying statement (+ its idempotency posture).
 *  batch() hands the REAL statements back to the binding: the runtime
 *  reads the SQL off the statement object itself, so a wrapper is not a
 *  statement to it. WeakMap-keyed — the entries die with the wrappers. */
const unwrappedStatements = new WeakMap<D1PreparedStatement, { stmt: D1PreparedStatement; retrySafe: boolean }>()

/** The write-bounded statement facade: read-classified SQL returns the
 *  raw statement untouched; write-classified SQL gets every terminal
 *  (run/first/all/raw — INSERT … RETURNING reads back through a write)
 *  raced against the budget. bind() stays chainable on the wrapper. */
function boundedStatement(stmt: D1PreparedStatement, sql: string, budgetMs: number): D1PreparedStatement {
  if (!WRITE_STATEMENT.test(sql)) return stmt
  const operation = sqlWriteLabel(sql)
  const retrySafe = writeRetrySafe(sql)
  const wrap = (s: D1PreparedStatement): D1PreparedStatement => {
    const wrapped = {
      bind: (...values: unknown[]): D1PreparedStatement => wrap(s.bind(...values)),
      first: (<T = unknown>(colName?: string) =>
        raceWriteBudget(operation, budgetMs, retrySafe, (colName === undefined ? s.first<T>() : s.first<T>(colName)) as Promise<T | null>)
      ) as D1PreparedStatement['first'],
      run: (<T = Record<string, unknown>>() =>
        raceWriteBudget(operation, budgetMs, retrySafe, s.run<T>())
      ) as D1PreparedStatement['run'],
      all: (<T = Record<string, unknown>>() =>
        raceWriteBudget(operation, budgetMs, retrySafe, s.all<T>())
      ) as D1PreparedStatement['all'],
      raw: (<T = unknown[]>(options?: { columnNames?: boolean }) =>
        options?.columnNames
          ? raceWriteBudget(operation, budgetMs, retrySafe, s.raw<T>({ columnNames: true }))
          : raceWriteBudget(operation, budgetMs, retrySafe, s.raw<T>(options as { columnNames?: false } | undefined))
      ) as D1PreparedStatement['raw'],
    }
    unwrappedStatements.set(wrapped as D1PreparedStatement, { stmt: s, retrySafe })
    return wrapped as D1PreparedStatement
  }
  return wrap(stmt)
}

/** The binding facade the store holds: prepare() bounds write-classified
 *  statements, batch()/exec() race their own budget (a D1 batch is ONE
 *  round-trip — one budget, retry-safe exactly when every member is),
 *  dump()/the reads pass through, withSession()'s session gets the same
 *  discipline. One budget per round-trip, never per row. */
function boundedD1Writes(binding: D1Database, budgetMs: number): D1Database {
  const boundedBatch = <T>(run: (real: D1PreparedStatement[]) => Promise<T>, statements: D1PreparedStatement[],): Promise<T> => {
    const real = statements.map(s => unwrappedStatements.get(s)?.stmt ?? s)
    const retrySafe = statements.length > 0 && statements.every(s => unwrappedStatements.get(s)?.retrySafe === true)
    return raceWriteBudget(`batch (${statements.length} statements)`, budgetMs, retrySafe, run(real))
  }
  return {
    prepare: (sql: string) => boundedStatement(binding.prepare(sql), sql, budgetMs),
    batch: <T = unknown>(statements: D1PreparedStatement[]) => boundedBatch(r => binding.batch<T>(r), statements),
    exec: (sql: string) => raceWriteBudget('exec (DDL script)', budgetMs, false, binding.exec(sql)),
    dump: () => binding.dump(),
    withSession: (constraintOrBookmark?: string) => {
      const session = binding.withSession(constraintOrBookmark)
      return {
        prepare: (sql: string) => boundedStatement(session.prepare(sql), sql, budgetMs),
        batch: <T = unknown>(statements: D1PreparedStatement[]) => boundedBatch(r => session.batch<T>(r), statements),
        getBookmark: () => session.getBookmark(),
      }
    },
  }
}

/** The entity write's two statements, ONE textual source for putEntity
 *  and putEntities alike (the multi-row write must land each row
 *  byte-identically to the single-row verb — the upsert, then its
 *  journal entry). */
const ENTITY_UPSERT_SQL = `INSERT INTO entities (store, id, org_id, data, updated_at) VALUES (?, ?, ?, ?, datetime('now'))
         ON CONFLICT (store, id) DO UPDATE SET org_id = excluded.org_id, data = excluded.data, updated_at = datetime('now')`
const ENTITY_CHANGE_SQL = 'INSERT INTO entity_changes (store, type, id) VALUES (?, ?, ?)'

/** The journal fan-out's ISOLATE-scope registry (the seam's
 *  onJournalAppend): one module-scope set — a registration through ANY
 *  D1ServerStore instance hears every journal append landing in this
 *  isolate, whichever instance wrote it. Cross-isolate writes never
 *  fire it (the database is the source of truth; the consumer's poll
 *  stays the fallback). */
const journalListeners = new Set<(appends: readonly JournalAppend[]) => void>()

/** Fires the registry with one write's appended triples, AFTER the
 *  write stands (the batch resolved / the row gone). Synchronous, in
 *  the write's continuation; a listener's throw is swallowed per
 *  listener — the write path never breaks for a listener. The snapshot
 *  keeps an unregistering listener's removal honest mid-emit. */
function emitJournalAppends(appends: readonly JournalAppend[]): void {
  if (appends.length === 0 || journalListeners.size === 0) return
  for (const listener of [...journalListeners]) {
    try {
      listener(appends)
    } catch { /* a listener never breaks the write path */ }
  }
}

/** The register's number lookup (findCertificatesByNumber): the keyed
 *  read against idx_entities_store_certificate_number (migration 0028)
 *  — the json_valid-guarded extract's exact spelling, COLLATE NOCASE
 *  for the register's case-insensitive number match. INDEXED BY pins
 *  the walk: without it the planner prefers idx_entities_store_org for
 *  the ORDER BY (org_id, rowid) — the seam's list order, kept so the
 *  first match IS the retiring listEntities scan's first match — and
 *  the "index" would walk the whole store; with it a database behind
 *  migration 0028 errors honestly, never scans silently. */
const CERTIFICATE_NUMBER_SQL = `SELECT store, id, org_id, data, updated_at
       FROM entities INDEXED BY idx_entities_store_certificate_number
       WHERE store = 'certificates'
         AND json_extract(CASE WHEN json_valid(data) THEN data ELSE '{}' END, '$.certificate_number') COLLATE NOCASE = ?
       ORDER BY org_id, rowid`

/** The register write's INSERT — ONE textual source for
 *  createInstrumentRegistration and createInstrumentRegistrations alike
 *  (the batch verb appends RETURNING * so the stored row answers off
 *  the write itself; the single verb keeps its .run() + by-id
 *  read-back pair). */
const INSTRUMENT_REGISTRATION_INSERT_SQL = `INSERT OR IGNORE INTO instrument_registrations
       (id, certificate_id, holder_org_id, standard_id, serial_number, manufacture_date, designations, scope_status, scope_detail, registered_by)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

/** The event append's INSERT … RETURNING * — ONE textual source for
 *  appendEvent and appendEvents alike (the stored row — seq + the
 *  default at — answers off the write itself). The mentions column
 *  (migration 0027) lands from the input, NULL when absent. */
const EVENT_INSERT_SQL = 'INSERT INTO events (id, domain, entity_id, action, payload, mentions) VALUES (?, ?, ?, ?, ?, ?) RETURNING *'

export class D1ServerStore implements ServerStore {
  /** The RAW binding — the ensure memos (and d1StoreFor's map) key on
   *  it: the facade below is per-instance and would never hit. */
  private readonly binding: D1Database
  /** The bounded statement surface the store issues against — the
   *  binding's facade, or (D1_REPLICA_READS=1) the bounded session
   *  over it. Only prepare/batch are the store's verbs; the type keeps
   *  exec/dump out (a session has neither — they are not the store's). */
  private readonly db: Pick<D1Database, 'prepare' | 'batch'>

  constructor(binding: D1Database, opts?: D1StoreOptions) {
    this.binding = binding
    const bounded = boundedD1Writes(binding, opts?.writeBudgetMs ?? DEFAULT_STORE_WRITE_BUDGET_MS)
    // TODO.restructure/28-E: the replica-reads posture resolves the
    // session ONCE, at construction — one session per store instance,
    // instance state, never a global (the discipline note above). The
    // bounded facade's own withSession wrapper keeps the write-budget
    // discipline on session-routed writes. Off: the facade itself,
    // byte-identical routing to before.
    this.db = opts?.replicaReads ? bounded.withSession('first-primary') : bounded
  }

  private stmt(sql: string, ...params: unknown[]): D1PreparedStatement {
    return this.db.prepare(sql).bind(...params)
  }

  // TODO.federation/12: the roles/active columns arrive with migration
  // 0002 — a dev D1 migrated from the pre-RBAC 0001 lacks them, so the
  //  user methods ensure them defensively (PRAGMA probe + ALTER),
  //  memoized per (binding, chain) at module scope (the header note).
  private ensureUserColumns(): Promise<void> {
    return ensured(this.binding, 'usersColumns', async () => {
      const cols = await this.db.prepare('PRAGMA table_info(users)').all<{ name: string }>()
      const names = new Set(cols.results.map(c => c.name))
      if (!names.has('roles')) await this.db.prepare('ALTER TABLE users ADD COLUMN roles TEXT').run()
      if (!names.has('active')) await this.db.prepare('ALTER TABLE users ADD COLUMN active INTEGER NOT NULL DEFAULT 1').run()
      // TODO.identity/06 (the account console): the address's
      // verification state.
      if (!names.has('email_verified_at')) await this.db.prepare('ALTER TABLE users ADD COLUMN email_verified_at TEXT').run()
    })
  }

  // TODO.identity/06 (the account console's sessions section): the
  // sign-in context columns arrive with migration 0009 — a dev D1
  // migrated from before it lacks them, so the session methods ensure
  // them defensively (the ensureUserColumns posture, memoized per
  // (binding, chain) at module scope).
  private ensureSessionColumns(): Promise<void> {
    return ensured(this.binding, 'sessionColumns', async () => {
      const cols = await this.db.prepare('PRAGMA table_info(sessions)').all<{ name: string }>()
      const names = new Set(cols.results.map(c => c.name))
      if (!names.has('user_agent')) await this.db.prepare('ALTER TABLE sessions ADD COLUMN user_agent TEXT').run()
      if (!names.has('ip')) await this.db.prepare('ALTER TABLE sessions ADD COLUMN ip TEXT').run()
      if (!names.has('last_seen_at')) await this.db.prepare('ALTER TABLE sessions ADD COLUMN last_seen_at TEXT').run()
      // TODO.identity-sso/02+03: the sign-in provenance.
      if (!names.has('amr')) await this.db.prepare('ALTER TABLE sessions ADD COLUMN amr TEXT').run()
    })
  }

  // TODO.identity/11 (the multi-org membership model): the
  // org_memberships table, the session's active-org stamp and the
  // token-flow context columns arrive with migration 0011 — a dev D1
  // migrated from before it lacks them, so the membership/session/token
  // methods ensure them defensively (the ensureUserColumns posture,
  // memoized per (binding, chain) at module scope). The backfill (the
  // migration's twin) is IDEMPOTENT and rides the ensure: every
  // org-bound account's primary membership mirrors the legacy columns.
  private ensureMembershipSupport(): Promise<void> {
    return ensured(this.binding, 'membershipSupport', async () => {
      await this.db.prepare(
        `CREATE TABLE IF NOT EXISTS org_memberships (
           id TEXT PRIMARY KEY,
           user_id TEXT NOT NULL REFERENCES users(id),
           org_id TEXT NOT NULL,
           roles TEXT NOT NULL DEFAULT '[]',
           state TEXT NOT NULL DEFAULT 'active',
           is_primary INTEGER NOT NULL DEFAULT 0,
           invited_by TEXT,
           created_at TEXT NOT NULL DEFAULT (datetime('now')),
           activated_at TEXT,
           disabled_at TEXT,
           disabled_by TEXT,
           UNIQUE (user_id, org_id)
         )`,
      ).run()
      await this.db.prepare('CREATE INDEX IF NOT EXISTS idx_org_memberships_org ON org_memberships (org_id, state)').run()
      await this.db.prepare('CREATE INDEX IF NOT EXISTS idx_org_memberships_user ON org_memberships (user_id, state)').run()
      // TODO.identity-features/09 (the org-member data cone): the cone
      // column arrives with migration 0017 — a dev D1 predating it
      // grows the column here. NULL = org-wide: existing memberships
      // keep their posture silently.
      const membershipCols = await this.db.prepare('PRAGMA table_info(org_memberships)').all<{ name: string }>()
      if (!membershipCols.results.some(c => c.name === 'cone')) {
        await this.db.prepare('ALTER TABLE org_memberships ADD COLUMN cone TEXT').run()
      }
      const sessionCols = await this.db.prepare('PRAGMA table_info(sessions)').all<{ name: string }>()
      if (!sessionCols.results.some(c => c.name === 'active_org')) {
        await this.db.prepare('ALTER TABLE sessions ADD COLUMN active_org TEXT').run()
      }
      const codeCols = await this.db.prepare('PRAGMA table_info(oidc_codes)').all<{ name: string }>()
      if (!codeCols.results.some(c => c.name === 'context_org')) {
        await this.db.prepare('ALTER TABLE oidc_codes ADD COLUMN context_org TEXT').run()
      }
      const accessCols = await this.db.prepare('PRAGMA table_info(oidc_access_tokens)').all<{ name: string }>()
      if (!accessCols.results.some(c => c.name === 'context_org')) {
        await this.db.prepare('ALTER TABLE oidc_access_tokens ADD COLUMN context_org TEXT').run()
      }
      await this.db.prepare(
        `INSERT OR IGNORE INTO org_memberships (id, user_id, org_id, roles, state, is_primary, activated_at)
         SELECT 'mbr-' || id, id, org_id,
                CASE WHEN roles IS NOT NULL AND roles != '' THEN roles ELSE json_array(role) END,
                'active', 1, COALESCE(last_login, created_at)
         FROM users WHERE org_id IS NOT NULL`,
      ).run()
    })
  }

  // TODO.identity-features/05 (the organization registry): the
  // org_registry table arrives with migration 0013 — a dev D1 migrated
  // from before it lacks the table, so the registry methods ensure it
  // defensively (the ensureMembershipSupport posture, memoized per
  // (binding, chain) at module scope).
  private ensureOrgRegistrySupport(): Promise<void> {
    return ensured(this.binding, 'orgRegistrySupport', async () => {
      await this.db.prepare(
        `CREATE TABLE IF NOT EXISTS org_registry (
           id TEXT PRIMARY KEY,
           name TEXT NOT NULL,
           short_name TEXT,
           kind TEXT,
           country TEXT,
           contacts TEXT NOT NULL DEFAULT '[]',
           participant_ref TEXT,
           state TEXT NOT NULL DEFAULT 'active',
           created_at TEXT NOT NULL DEFAULT (datetime('now')),
           created_by TEXT,
           updated_at TEXT,
           updated_by TEXT,
           disabled_at TEXT,
           disabled_by TEXT
         )`,
      ).run()
      await this.db.prepare('CREATE INDEX IF NOT EXISTS idx_org_registry_state ON org_registry (state)').run()
      // TODO.identity-features/10 (the OIML Member category): the
      // designation links + the CS status facet arrive with migration
      // 0019 — a dev D1 predating it grows the columns here (the
      // PRAGMA probe + ALTER posture of ensureUserColumns). NULL = not
      // recorded: existing rows keep their posture silently.
      const cols = await this.db.prepare('PRAGMA table_info(org_registry)').all<{ name: string }>()
      const names = new Set(cols.results.map(c => c.name))
      if (!names.has('designated_by')) await this.db.prepare('ALTER TABLE org_registry ADD COLUMN designated_by TEXT').run()
      if (!names.has('proposed_by')) await this.db.prepare('ALTER TABLE org_registry ADD COLUMN proposed_by TEXT').run()
      if (!names.has('cs_status')) await this.db.prepare('ALTER TABLE org_registry ADD COLUMN cs_status TEXT').run()
    })
  }

  // TODO.register/02 (the register's holder-org attribution): the
  // certificate_holder_orgs / certificate_holder_claims tables arrive with
  // migration 0015 — a dev D1 migrated from before it lacks them, so the
  // attribution/claim methods ensure them defensively (the
  // ensureOrgRegistrySupport posture, memoized per (binding, chain) at
  // module scope).
  private ensureHolderAttributionSupport(): Promise<void> {
    return ensured(this.binding, 'holderAttributionSupport', async () => {
      await this.db.prepare(
        `CREATE TABLE IF NOT EXISTS certificate_holder_orgs (
           certificate_id TEXT PRIMARY KEY,
           org_id TEXT NOT NULL,
           org_name TEXT NOT NULL,
           source TEXT NOT NULL,
           attributed_at TEXT NOT NULL,
           attributed_by TEXT,
           claim_id TEXT
         )`,
      ).run()
      await this.db.prepare('CREATE INDEX IF NOT EXISTS idx_certificate_holder_orgs_org ON certificate_holder_orgs (org_id)').run()
      await this.db.prepare(
        `CREATE TABLE IF NOT EXISTS certificate_holder_claims (
           id TEXT PRIMARY KEY,
           certificate_id TEXT NOT NULL,
           claimant_org_id TEXT NOT NULL,
           claimant_org_name TEXT NOT NULL,
           matched_holder_name TEXT NOT NULL,
           claimed_by TEXT NOT NULL,
           state TEXT NOT NULL DEFAULT 'pending',
           decided_by TEXT,
           decided_at TEXT,
           refusal_reason TEXT,
           created_at TEXT NOT NULL DEFAULT (datetime('now'))
         )`,
      ).run()
      await this.db.prepare('CREATE INDEX IF NOT EXISTS idx_certificate_holder_claims_cert ON certificate_holder_claims (certificate_id)').run()
      await this.db.prepare('CREATE INDEX IF NOT EXISTS idx_certificate_holder_claims_state ON certificate_holder_claims (state)').run()
      await this.db.prepare('CREATE INDEX IF NOT EXISTS idx_certificate_holder_claims_org ON certificate_holder_claims (claimant_org_id)').run()
    })
  }

  // TODO.register/03 (the instrument register): the
  // instrument_registrations table arrives with migration 0016 — a dev
  // D1 migrated from before it lacks the table, so the register methods
  // ensure it defensively (the ensureOrgRegistrySupport posture,
  // memoized per (binding, chain) at module scope).
  private ensureInstrumentRegistrationSupport(): Promise<void> {
    return ensured(this.binding, 'instrumentRegistrationSupport', async () => {
      await this.db.prepare(
        `CREATE TABLE IF NOT EXISTS instrument_registrations (
           id TEXT PRIMARY KEY,
           certificate_id TEXT NOT NULL,
           holder_org_id TEXT NOT NULL,
           standard_id TEXT NOT NULL,
           serial_number TEXT NOT NULL,
           manufacture_date TEXT,
           designations TEXT NOT NULL DEFAULT '{}',
           scope_status TEXT NOT NULL,
           scope_detail TEXT,
           lifecycle TEXT NOT NULL DEFAULT 'registered',
           registered_at TEXT NOT NULL DEFAULT (datetime('now')),
           registered_by TEXT,
           updated_at TEXT,
           updated_by TEXT,
           UNIQUE (certificate_id, serial_number)
         )`,
      ).run()
      await this.db.prepare('CREATE INDEX IF NOT EXISTS idx_instrument_registrations_certificate ON instrument_registrations (certificate_id)').run()
      await this.db.prepare('CREATE INDEX IF NOT EXISTS idx_instrument_registrations_holder ON instrument_registrations (holder_org_id)').run()
      await this.db.prepare('CREATE INDEX IF NOT EXISTS idx_instrument_registrations_lifecycle ON instrument_registrations (lifecycle)').run()
    })
  }

  // TODO.identity-sso/02+03: the amr provenance columns on the OIDC
  // flow rows arrive with migration 0012 — the OIDC methods ensure them
  // defensively (the same memoized posture as the session/user columns,
  // per (binding, chain) at module scope), so a dev D1 migrated from
  // before the wave never 500s the core flow.
  private ensureOidcColumns(): Promise<void> {
    return ensured(this.binding, 'oidcColumns', async () => {
      const codeCols = await this.db.prepare('PRAGMA table_info(oidc_codes)').all<{ name: string }>()
      if (!codeCols.results.some(c => c.name === 'amr')) {
        await this.db.prepare('ALTER TABLE oidc_codes ADD COLUMN amr TEXT').run()
      }
      // TODO.identity-sso (the wave-A tail): the code carries the
      // consenting session's authentication instant (migration 0024).
      if (!codeCols.results.some(c => c.name === 'auth_time')) {
        await this.db.prepare('ALTER TABLE oidc_codes ADD COLUMN auth_time TEXT').run()
      }
      const tokenCols = await this.db.prepare('PRAGMA table_info(oidc_access_tokens)').all<{ name: string }>()
      if (!tokenCols.results.some(c => c.name === 'amr')) {
        await this.db.prepare('ALTER TABLE oidc_access_tokens ADD COLUMN amr TEXT').run()
      }
    })
  }

  // TODO.identity-features/08 (the personal access tokens): the
  // personal_access_tokens table arrives with migration 0020 — a dev D1
  // migrated from before it lacks the table, so the PAT methods ensure
  // it defensively (the ensureOrgRegistrySupport posture, memoized per
  // (binding, chain) at module scope).
  private ensurePersonalAccessTokenSupport(): Promise<void> {
    return ensured(this.binding, 'personalAccessTokenSupport', async () => {
      await this.db.prepare(
        `CREATE TABLE IF NOT EXISTS personal_access_tokens (
           id TEXT PRIMARY KEY,
           user_id TEXT NOT NULL REFERENCES users(id),
           name TEXT NOT NULL,
           token_hash TEXT NOT NULL,
           token_prefix TEXT NOT NULL,
           scopes TEXT NOT NULL DEFAULT '[]',
           org_context TEXT,
           created_at TEXT NOT NULL DEFAULT (datetime('now')),
           expires_at TEXT NOT NULL,
           last_used_at TEXT,
           last_exchange_audit_at TEXT,
           expiry_notified_at TEXT,
           revoked_at TEXT,
           revoked_by TEXT,
           UNIQUE (token_hash)
         )`,
      ).run()
      await this.db.prepare('CREATE INDEX IF NOT EXISTS idx_personal_access_tokens_user ON personal_access_tokens (user_id)').run()
    })
  }

  // TODO.identity-features/12 (the remembered consent grants): the
  // oidc_consent_grants table arrives with migration 0021 — a dev D1
  // migrated from before it lacks the table, so the grant methods ensure
  // it defensively (the ensurePersonalAccessTokenSupport posture,
  // memoized per (binding, chain) at module scope).
  private ensureConsentGrantSupport(): Promise<void> {
    return ensured(this.binding, 'consentGrantSupport', async () => {
      await this.db.prepare(
        `CREATE TABLE IF NOT EXISTS oidc_consent_grants (
           id TEXT PRIMARY KEY,
           user_id TEXT NOT NULL REFERENCES users(id),
           client_id TEXT NOT NULL,
           scope TEXT NOT NULL,
           created_at TEXT NOT NULL DEFAULT (datetime('now')),
           revoked_at TEXT
         )`,
      ).run()
      await this.db.prepare(
        'CREATE UNIQUE INDEX IF NOT EXISTS idx_oidc_consent_grants_live ON oidc_consent_grants (user_id, client_id, scope) WHERE revoked_at IS NULL',
      ).run()
      await this.db.prepare('CREATE INDEX IF NOT EXISTS idx_oidc_consent_grants_user ON oidc_consent_grants (user_id)').run()
    })
  }

  // TODO.identity-sso (the wave-C token surface): the oidc_refresh_tokens
  // table arrives with migration 0025 — a dev D1 migrated from before it
  // lacks the table, so the refresh methods (and the deactivation sweep)
  // ensure it defensively (the ensureConsentGrantSupport posture,
  // memoized per (binding, chain) at module scope).
  private ensureOidcRefreshTokenSupport(): Promise<void> {
    return ensured(this.binding, 'oidcRefreshTokenSupport', async () => {
      await this.db.prepare(
        `CREATE TABLE IF NOT EXISTS oidc_refresh_tokens (
           token TEXT PRIMARY KEY,
           user_id TEXT NOT NULL REFERENCES users(id),
           client_id TEXT NOT NULL,
           scope TEXT NOT NULL,
           context_org TEXT,
           amr TEXT,
           auth_time TEXT,
           family_id TEXT NOT NULL,
           created_at TEXT NOT NULL DEFAULT (datetime('now')),
           expires_at TEXT NOT NULL,
           consumed_at TEXT
         )`,
      ).run()
      await this.db.prepare('CREATE INDEX IF NOT EXISTS idx_oidc_refresh_tokens_user ON oidc_refresh_tokens (user_id)').run()
      await this.db.prepare('CREATE INDEX IF NOT EXISTS idx_oidc_refresh_tokens_family ON oidc_refresh_tokens (family_id)').run()
    })
  }

  // TODO.identity-features/01 (multiple emails per account): the
  // account_emails table + the email_change_tokens.kind column arrive
  // with migration 0022 — a dev D1 migrated from before it lacks both,
  // so the address methods ensure them defensively (the
  // ensureConsentGrantSupport posture, memoized per (binding, chain) at
  // module scope).
  private ensureAccountEmailSupport(): Promise<void> {
    return ensured(this.binding, 'accountEmailSupport', async () => {
      await this.db.prepare(
        `CREATE TABLE IF NOT EXISTS account_emails (
           user_id TEXT NOT NULL REFERENCES users(id),
           email TEXT NOT NULL,
           verified_at TEXT,
           added_by TEXT,
           created_at TEXT NOT NULL DEFAULT (datetime('now')),
           PRIMARY KEY (user_id, email)
         )`,
      ).run()
      await this.db.prepare('CREATE UNIQUE INDEX IF NOT EXISTS idx_account_emails_email ON account_emails (email)').run()
      const tokenCols = await this.db.prepare('PRAGMA table_info(email_change_tokens)').all<{ name: string }>()
      if (!tokenCols.results.some(c => c.name === 'kind')) {
        await this.db.prepare("ALTER TABLE email_change_tokens ADD COLUMN kind TEXT NOT NULL DEFAULT 'change'").run()
      }
    })
  }

  // ── users / sessions ─────────────────────────────────────────────

  async seedDemoAccounts(): Promise<void> {
    const statements: D1PreparedStatement[] = []
    for (const account of seedAccountsForProfile(getInstanceProfile())) {
      // The roles column carries the account's declared FULL set (NULL =
      // the primary role only); the align clears a stale set honestly
      // (the SQLite seed's rule).
      const roles = account.roles?.length ? JSON.stringify(account.roles) : null
      statements.push(this.stmt(
        `INSERT OR IGNORE INTO users (id, email, name, provider, provider_account_id, role, org_id, roles)
         VALUES (?, ?, ?, 'demo', ?, ?, ?, ?)`,
        crypto.randomUUID(), account.email, account.name, account.email, account.role, account.orgId, roles,
      ))
      // Align existing demo rows with the current role/org assignments —
      // INSERT OR IGNORE alone would leave them stale (same rule as the
      // SQLite seed).
      statements.push(this.stmt(
        `UPDATE users SET name = ?, role = ?, org_id = ?, roles = ? WHERE email = ? AND provider = 'demo'`,
        account.name, account.role, account.orgId, roles, account.email,
      ))
    }
    // A profile with no demo cast (the production posture) is an honest
    // no-op, never an error — D1's batch rejects an empty statement
    // list ("No SQL statements detected").
    if (statements.length === 0) return
    await this.db.batch(statements)
    // TODO.identity/11: the org-bound seed accounts' primary memberships
    // ride the mirror (idempotent — the seed runs at every boot).
    for (const account of seedAccountsForProfile(getInstanceProfile())) {
      if (!account.orgId) continue
      const row = await this.stmt('SELECT id FROM users WHERE email = ?', account.email).first<{ id: string }>()
      if (row) await this.syncPrimaryMembership(row.id)
    }
  }

  async authenticateDemo(email: string, password: string): Promise<AuthUserPayload | null> {
    await this.ensureUserColumns()
    const user = await this.stmt("SELECT * FROM users WHERE email = ? AND provider = 'demo'", email)
      .first<UserRecord>()
    if (!user) return null
    // A deactivated account refuses sign-in (TODO.federation/12).
    if (user.active === 0) return null
    if (password !== DEMO_PASSWORD) return null
    await this.stmt("UPDATE users SET last_login = datetime('now') WHERE id = ?", user.id).run()
    return toPayload(user)
  }

  async createSession(
    userId: string,
    opts?: { idTokenHint?: string | null; userAgent?: string | null; ip?: string | null; amr?: string[] | null },
  ): Promise<string> {
    await this.ensureSessionColumns()
    const token = crypto.randomUUID()
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString()
    await this.stmt(
      'INSERT INTO sessions (id, user_id, token, expires_at, id_token_hint, user_agent, ip, last_seen_at, amr) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
      crypto.randomUUID(), userId, token, expiresAt, opts?.idTokenHint ?? null, opts?.userAgent ?? null, opts?.ip ?? null, null,
      opts?.amr?.length ? JSON.stringify(opts.amr) : null,
    ).run()
    return token
  }

  async touchLastLogin(userId: string): Promise<void> {
    await this.stmt("UPDATE users SET last_login = datetime('now') WHERE id = ?", userId).run()
  }

  /** TODO.identity/06's last-active stamp, throttled to one ISSUED write
   *  per minute per session per isolate — the DB-side 60 s WHERE clause
   *  stays the source of truth across isolates (the module-scope note);
   *  the in-isolate cache only skips issuing a write the row would
   *  refuse. A failed write is never cached (the cache set follows the
   *  await), so the next request retries. */
  private async stampSessionLastSeen(token: string): Promise<void> {
    const now = Date.now()
    if (now - (lastSeenWrites.get(token) ?? 0) < LAST_SEEN_THROTTLE_MS) return
    await this.stmt(
      "UPDATE sessions SET last_seen_at = datetime('now') WHERE token = ? AND (last_seen_at IS NULL OR last_seen_at < datetime('now', '-60 seconds'))",
      token,
    ).run()
    if (lastSeenWrites.size >= LAST_SEEN_CACHE_CAP) lastSeenWrites.clear()
    lastSeenWrites.set(token, now)
  }

  async getSessionUser(token: string): Promise<AuthUserPayload | null> {
    // The ensure chains are memoized per (binding, chain) at module scope
    // (the header note) — past the isolate's first request these three
    // awaits are memo hits, and the per-request work that remains is the
    // session read itself.
    await this.ensureUserColumns()
    await this.ensureSessionColumns()
    await this.ensureMembershipSupport()
    // The session joins the LIVE user row (TODO.federation/12): a role
    // reassignment takes effect on the next request; deactivation ends
    // the session at once.
    const session = await this.stmt(
      `SELECT s.user_id, s.active_org, s.amr, s.created_at, u.email, u.name, u.role, u.roles, u.org_id, u.avatar_url, u.provider, u.email_verified_at
       FROM sessions s JOIN users u ON s.user_id = u.id
       WHERE s.token = ? AND s.expires_at > datetime('now') AND u.active = 1`,
      token,
    ).first<{ user_id: string; active_org: string | null; amr: string | null; created_at: string; email: string; name: string; role: string; roles: string | null; org_id: string | null; avatar_url: string | null; provider: string; email_verified_at: string | null }>()
    if (!session) return null
    const amr = parseRoles(session.amr)
    const payload: AuthUserPayload = {
      id: session.user_id,
      email: session.email,
      name: session.name,
      role: session.role,
      ...(parseRoles(session.roles)?.length ? { roles: parseRoles(session.roles) } : {}),
      orgId: session.org_id ?? null,
      avatarUrl: session.avatar_url ?? undefined,
      provider: session.provider,
      emailVerifiedAt: session.email_verified_at ?? null,
      ...(amr?.length ? { amr } : {}),
      // TODO.identity-sso (the wave-A tail): the authentication instant —
      // the ID token's auth_time derives from it (the consumer converts).
      sessionCreatedAt: session.created_at,
    }
    // TODO.identity/11: the active-org context (the membership model) —
    // the payload's org/roles follow the session's stamped context. The
    // three post-JOIN statements (the throttled last-active stamp, the
    // two membership reads) are independent, so they round-trip together
    // (the audit's R2: sequential statements are the latency).
    const activeOrg = session.active_org ?? null
    const [, active, primary] = await Promise.all([
      this.stampSessionLastSeen(token),
      activeOrg ? this.getOrgMembership(payload.id, activeOrg) : null,
      payload.orgId ? this.getOrgMembership(payload.id, payload.orgId) : null,
    ])
    const resolved = resolveOrgContext(payload, { activeOrg, active, primary })
    if (activeOrg && !(active && active.state === 'active')) {
      // The stale stamp never lingers (the membership ended mid-session).
      await this.stmt('UPDATE sessions SET active_org = NULL WHERE user_id = ? AND active_org = ?', payload.id, activeOrg).run()
    }
    // TODO.identity-features/09: the context membership's cone rides the
    // payload — the entity gates enforce it without a store round-trip.
    return { ...payload, orgId: resolved.orgId, roles: resolved.roles, cone: resolved.cone }
  }

  async deleteSession(token: string): Promise<void> {
    await this.stmt('DELETE FROM sessions WHERE token = ?', token).run()
  }

  async cleanExpiredSessions(): Promise<void> {
    await this.stmt("DELETE FROM sessions WHERE expires_at <= datetime('now')").run()
  }

  async listDemoAccounts(): Promise<Array<{ email: string; name: string; role: string }>> {
    const res = await this.stmt(
      "SELECT email, name, role FROM users WHERE provider = 'demo' ORDER BY role, name",
    ).all<{ email: string; name: string; role: string }>()
    return res.results
  }

  // ── identity federation (TODO.federation/10) ───────────────────────

  async findUserByEmail(email: string): Promise<AuthUserPayload | null> {
    const user = await this.stmt('SELECT * FROM users WHERE email = ?', email).first<UserRecord>()
    return user ? toPayload(user) : null
  }

  /** TODO.identity/01 — the OP's token endpoint resolves the code's
   *  user_id through this. */
  async getUserById(id: string): Promise<AuthUserPayload | null> {
    const user = await this.stmt('SELECT * FROM users WHERE id = ?', id).first<UserRecord>()
    return user ? toPayload(user) : null
  }

  async findUserByProvider(provider: string, providerAccountId: string): Promise<AuthUserPayload | null> {
    const user = await this.stmt(
      'SELECT * FROM users WHERE provider = ? AND provider_account_id = ?', provider, providerAccountId,
    ).first<UserRecord>()
    return user ? toPayload(user) : null
  }

  async provisionSsoUser(input: {
    email: string
    name: string
    provider: string
    providerAccountId: string
    role: string
    orgId: string | null
  }): Promise<AuthUserPayload> {
    const id = crypto.randomUUID()
    await this.stmt(
      "INSERT INTO users (id, email, name, provider, provider_account_id, role, org_id, last_login) VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))",
      id, input.email, input.name, input.provider, input.providerAccountId, input.role, input.orgId,
    ).run()
    if (input.orgId) await this.syncPrimaryMembership(id) // TODO.identity/11 — the mirror
    return { id, email: input.email, name: input.name, role: input.role, orgId: input.orgId }
  }

  async updateUserRoleOrg(userId: string, role: string, orgId: string | null): Promise<void> {
    await this.stmt('UPDATE users SET role = ?, org_id = ? WHERE id = ?', role, orgId, userId).run()
    if (orgId) await this.syncPrimaryMembership(userId) // TODO.identity/11 — the mirror
  }

  // The approval queue rows port directly (D1 is SQLite).

  private async approvalRow(where: string, ...params: unknown[]) {
    const row = await this.stmt(`SELECT * FROM identity_approvals WHERE ${where}`, ...params)
      .first<Record<string, unknown>>()
    return row ? toIdentityApproval(row) : null
  }

  // ── the SSO sign-in state jar (TODO.identity/04) ───────────────────
  // The rows port directly (D1 is SQLite); the consume's UPDATE flip is
  // the atomic single-use guarantee across isolates.

  // ── federation peers (TODO.federation/04) ───────────────────────────
  // The peer rows port directly (D1 is SQLite).

  // ── user administration (TODO.federation/12) ─────────────────────

  async listUsers(): Promise<UserAdminRow[]> {
    await this.ensureUserColumns()
    const res = await this.stmt('SELECT * FROM users ORDER BY name')
      .all<UserRecord & { last_login?: string | null; provider?: string }>()
    return res.results.map(toAdminRow)
  }

  async createLocalUser(input: {
    email: string
    name: string
    role: string
    roles?: string[]
    orgId?: string | null
  }): Promise<UserAdminRow> {
    await this.ensureUserColumns()
    const id = crypto.randomUUID()
    const roles = input.roles?.length ? input.roles : [input.role]
    await this.stmt(
      `INSERT INTO users (id, email, name, provider, provider_account_id, role, roles, org_id)
       VALUES (?, ?, ?, 'demo', ?, ?, ?, ?)`,
      id, input.email, input.name, input.email, input.role, JSON.stringify(roles), input.orgId ?? null,
    ).run()
    if (input.orgId) await this.syncPrimaryMembership(id) // TODO.identity/11 — the mirror
    const row = await this.stmt('SELECT * FROM users WHERE id = ?', id).first<UserRecord>()
    return toAdminRow(row!)
  }

  async setUserRoles(id: string, role: string, roles: string[]): Promise<boolean> {
    await this.ensureUserColumns()
    const res = await this.stmt(
      'UPDATE users SET role = ?, roles = ? WHERE id = ?',
      role, JSON.stringify(roles.length ? roles : [role]), id,
    ).run()
    // TODO.identity/11 — the mirror (a no-op for org-free accounts).
    if ((res.meta.changes ?? 0) > 0) await this.syncPrimaryMembership(id)
    return (res.meta.changes ?? 0) > 0
  }

  async setUserActive(id: string, active: boolean): Promise<boolean> {
    await this.ensureUserColumns()
    const res = await this.stmt('UPDATE users SET active = ? WHERE id = ?', active ? 1 : 0, id).run()
    return (res.meta.changes ?? 0) > 0
  }

  // ── the OIDC Provider (TODO.identity/01) ───────────────────────────
  // The OP rows port directly (D1 is SQLite) — the same statements as
  // op-store.ts's sync half.

  private static toOidcClient(row: Record<string, unknown>): OidcClient {
    return {
      clientId: row.client_id as string,
      name: row.name as string,
      secretHash: (row.secret_hash as string | null) ?? null,
      redirectUris: JSON.parse(row.redirect_uris as string) as string[],
      claimsPolicy: row.claims_policy ? JSON.parse(row.claims_policy as string) as OidcClient['claimsPolicy'] : null,
      // The SSO-home launch metadata (migration 0011): no launch_url =
      // the client never appears on the launcher. A pre-0011 database
      // reads the columns as absent — launch stays null, the honest
      // default.
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

  private static toOidcAuthorization(row: Record<string, unknown>): OidcAuthorization {
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

  async getOidcClient(clientId: string): Promise<OidcClient | null> {
    const row = await this.stmt('SELECT * FROM oidc_clients WHERE client_id = ?', clientId).first<Record<string, unknown>>()
    return row ? D1ServerStore.toOidcClient(row) : null
  }

  async listOidcClients(): Promise<OidcClient[]> {
    const res = await this.stmt('SELECT * FROM oidc_clients ORDER BY created_at, client_id').all<Record<string, unknown>>()
    return res.results.map(D1ServerStore.toOidcClient)
  }

  async upsertOidcClient(input: {
    clientId: string
    name: string
    secretHash: string | null
    redirectUris: string[]
    claimsPolicy: { claims: string[] } | null
    createdBy?: string | null
  }): Promise<OidcClient> {
    await this.stmt(
      `INSERT INTO oidc_clients (client_id, name, secret_hash, redirect_uris, claims_policy, created_by)
       VALUES (?, ?, ?, ?, ?, ?)
       ON CONFLICT (client_id) DO UPDATE SET
         name = excluded.name,
         secret_hash = excluded.secret_hash,
         redirect_uris = excluded.redirect_uris,
         claims_policy = excluded.claims_policy`,
      input.clientId, input.name, input.secretHash,
      JSON.stringify(input.redirectUris),
      input.claimsPolicy ? JSON.stringify(input.claimsPolicy) : null,
      input.createdBy ?? null,
    ).run()
    return (await this.getOidcClient(input.clientId))!
  }

  async setOidcClientStatus(clientId: string, status: OidcClient['status']): Promise<OidcClient | null> {
    const res = await this.stmt('UPDATE oidc_clients SET status = ? WHERE client_id = ?', status, clientId).run()
    return (res.meta.changes ?? 0) > 0 ? this.getOidcClient(clientId) : null
  }

  async setOidcClientLaunch(clientId: string, launch: OidcClientLaunch | null): Promise<OidcClient | null> {
    const res = await this.stmt(
      `UPDATE oidc_clients SET launch_url = ?, launch_icon = ?, launch_description = ?, launch_visibility = ?
       WHERE client_id = ?`,
      launch?.url ?? null,
      launch?.icon ?? null,
      launch?.description ?? null,
      launch?.visibility ?? 'roles',
      clientId,
    ).run()
    return (res.meta.changes ?? 0) > 0 ? this.getOidcClient(clientId) : null
  }

  async createOidcAuthorization(input: {
    id: string
    clientId: string
    redirectUri: string
    scope: string
    state: string
    nonce: string | null
    codeChallenge: string
    userId: string | null
    ttlMs: number
  }): Promise<OidcAuthorization> {
    const expiresAt = new Date(Date.now() + input.ttlMs).toISOString()
    await this.stmt(
      `INSERT INTO oidc_authorizations
         (id, client_id, redirect_uri, scope, state, nonce, code_challenge, user_id, expires_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      input.id, input.clientId, input.redirectUri, input.scope, input.state,
      input.nonce, input.codeChallenge, input.userId, expiresAt,
    ).run()
    return (await this.getOidcAuthorization(input.id))!
  }

  async getOidcAuthorization(id: string): Promise<OidcAuthorization | null> {
    const row = await this.stmt('SELECT * FROM oidc_authorizations WHERE id = ?', id).first<Record<string, unknown>>()
    return row ? D1ServerStore.toOidcAuthorization(row) : null
  }

  async decideOidcAuthorization(
    id: string,
    decision: { userId: string; decision: 'allow' | 'deny' },
  ): Promise<OidcAuthorization | null> {
    // The decision binds to the row's OWN account and flips atomically.
    const res = await this.stmt(
      'UPDATE oidc_authorizations SET decision = ? WHERE id = ? AND decision IS NULL AND user_id = ?',
      decision.decision, id, decision.userId,
    ).run()
    return (res.meta.changes ?? 0) > 0 ? this.getOidcAuthorization(id) : null
  }

  async createOidcCode(input: {
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
  }): Promise<void> {
    await this.ensureMembershipSupport()
    const expiresAt = new Date(Date.now() + input.ttlMs).toISOString()
    await this.ensureOidcColumns()
    await this.stmt(
      `INSERT INTO oidc_codes (code, client_id, redirect_uri, scope, nonce, code_challenge, user_id, context_org, amr, auth_time, expires_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      input.code, input.clientId, input.redirectUri, input.scope, input.nonce, input.codeChallenge, input.userId, input.contextOrg ?? null,
      input.amr?.length ? JSON.stringify(input.amr) : null, input.authTime ?? null, expiresAt,
    ).run()
  }

  /** Atomically consume the code: the UPDATE flips consumed_at exactly
   *  once — a replay loses the race and answers null (→ invalid_grant).
   *  An expired code is consumed too (never a second chance). */
  async consumeOidcCode(code: string): Promise<OidcCode | null> {
    await this.ensureMembershipSupport()
    const res = await this.stmt(
      "UPDATE oidc_codes SET consumed_at = datetime('now') WHERE code = ? AND consumed_at IS NULL", code,
    ).run()
    if ((res.meta.changes ?? 0) === 0) return null
    const row = await this.stmt('SELECT * FROM oidc_codes WHERE code = ?', code).first<Record<string, unknown>>()
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
      amr: parseRoles((row.amr as string | null) ?? null) ?? null,
      authTime: (row.auth_time as string | null) ?? null,
      expiresAt: row.expires_at as string,
    }
  }

  async createOidcAccessToken(input: {
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
  }): Promise<void> {
    await this.ensureMembershipSupport()
    const expiresAt = new Date(Date.now() + input.ttlMs).toISOString()
    await this.ensureOidcColumns()
    await this.stmt(
      'INSERT INTO oidc_access_tokens (token, user_id, client_id, scope, context_org, amr, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
      input.token, input.userId, input.clientId, input.scope, input.contextOrg ?? null,
      input.amr?.length ? JSON.stringify(input.amr) : null, expiresAt,
    ).run()
  }

  async getOidcAccessToken(token: string): Promise<OidcAccessToken | null> {
    await this.ensureMembershipSupport()
    const row = await this.stmt(
      "SELECT * FROM oidc_access_tokens WHERE token = ? AND datetime(expires_at) > datetime('now')", token,
    ).first<Record<string, unknown>>()
    if (!row) return null
    return {
      token: row.token as string,
      userId: row.user_id as string,
      clientId: row.client_id as string,
      scope: row.scope as string,
      contextOrg: (row.context_org as string | null) ?? null,
      amr: parseRoles((row.amr as string | null) ?? null) ?? null,
      expiresAt: row.expires_at as string,
    }
  }

  /** The RFC 7009 access-token revocation: the row goes, client-bound. */
  async deleteOidcAccessToken(token: string, clientId: string): Promise<boolean> {
    await this.ensureMembershipSupport()
    const res = await this.stmt(
      'DELETE FROM oidc_access_tokens WHERE token = ? AND client_id = ?', token, clientId,
    ).run()
    return (res.meta.changes ?? 0) > 0
  }

  /** The governance view's population read: the client's LIVE access-token
   *  count (unexpired — the row's absence IS the revocation). */
  async countOidcAccessTokensForClient(clientId: string): Promise<number> {
    await this.ensureMembershipSupport()
    const row = await this.stmt(
      "SELECT COUNT(*) AS n FROM oidc_access_tokens WHERE client_id = ? AND datetime(expires_at) > datetime('now')", clientId,
    ).first<{ n: number }>()
    return row?.n ?? 0
  }

  private static toRefreshToken(row: Record<string, unknown>): OidcRefreshToken {
    return {
      token: row.token as string,
      userId: row.user_id as string,
      clientId: row.client_id as string,
      scope: row.scope as string,
      contextOrg: (row.context_org as string | null) ?? null,
      amr: parseRoles((row.amr as string | null) ?? null) ?? null,
      authTime: (row.auth_time as string | null) ?? null,
      familyId: row.family_id as string,
      createdAt: row.created_at as string,
      expiresAt: row.expires_at as string,
      consumedAt: (row.consumed_at as string | null) ?? null,
    }
  }

  async createOidcRefreshToken(input: {
    token: string
    userId: string
    clientId: string
    scope: string
    contextOrg?: string | null
    amr?: string[] | null
    authTime?: string | null
    familyId: string
    ttlMs: number
  }): Promise<OidcRefreshToken> {
    await this.ensureMembershipSupport()
    await this.ensureOidcRefreshTokenSupport()
    const expiresAt = new Date(Date.now() + input.ttlMs).toISOString()
    await this.stmt(
      `INSERT INTO oidc_refresh_tokens (token, user_id, client_id, scope, context_org, amr, auth_time, family_id, expires_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      input.token, input.userId, input.clientId, input.scope, input.contextOrg ?? null,
      input.amr?.length ? JSON.stringify(input.amr) : null, input.authTime ?? null, input.familyId, expiresAt,
    ).run()
    const row = await this.stmt('SELECT * FROM oidc_refresh_tokens WHERE token = ?', input.token).first<Record<string, unknown>>()
    return D1ServerStore.toRefreshToken(row as Record<string, unknown>)
  }

  /** The refresh exchange's consume: the UPDATE flips consumed_at exactly
   *  once — a replay loses the race, reads the consumed row back, and the
   *  WHOLE FAMILY dies (the theft signal, RFC 6819 §5.2.2.3; a concurrent
   *  double-present lands the same verdict — fail toward invalidation).
   *  An expired live row is consumed anyway (never a second chance) and
   *  answers 'invalid'. */
  async consumeOidcRefreshToken(token: string): Promise<ConsumeOidcRefreshTokenResult> {
    await this.ensureMembershipSupport()
    await this.ensureOidcRefreshTokenSupport()
    const res = await this.stmt(
      "UPDATE oidc_refresh_tokens SET consumed_at = datetime('now') WHERE token = ? AND consumed_at IS NULL", token,
    ).run()
    if ((res.meta.changes ?? 0) > 0) {
      const row = await this.stmt('SELECT * FROM oidc_refresh_tokens WHERE token = ?', token).first<Record<string, unknown>>()
      if (!row) return { kind: 'invalid' }
      if (new Date(row.expires_at as string).getTime() <= Date.now()) return { kind: 'invalid' }
      return { kind: 'ok', token: D1ServerStore.toRefreshToken(row) }
    }
    const row = await this.stmt('SELECT * FROM oidc_refresh_tokens WHERE token = ?', token).first<Record<string, unknown>>()
    if (!row) return { kind: 'invalid' }
    // The reuse signal: the consumed row's family dies outright.
    const familyId = row.family_id as string
    await this.stmt('DELETE FROM oidc_refresh_tokens WHERE family_id = ?', familyId).run()
    return { kind: 'reuse', familyId, userId: row.user_id as string, clientId: row.client_id as string }
  }

  /** The RFC 7009 refresh revocation, client-bound: the presented token's
   *  family goes (never another client's rows). */
  async revokeOidcRefreshToken(token: string, clientId: string): Promise<boolean> {
    await this.ensureMembershipSupport()
    await this.ensureOidcRefreshTokenSupport()
    const row = await this.stmt(
      'SELECT family_id FROM oidc_refresh_tokens WHERE token = ? AND client_id = ?', token, clientId,
    ).first<{ family_id: string }>()
    if (!row) return false
    await this.stmt('DELETE FROM oidc_refresh_tokens WHERE family_id = ?', row.family_id).run()
    return true
  }

  /** The consent revocation's companion: the (account, client) pair's
   *  refresh rows all go. */
  async deleteOidcRefreshTokensForUserClient(userId: string, clientId: string): Promise<number> {
    await this.ensureMembershipSupport()
    await this.ensureOidcRefreshTokenSupport()
    const res = await this.stmt(
      'DELETE FROM oidc_refresh_tokens WHERE user_id = ? AND client_id = ?', userId, clientId,
    ).run()
    return res.meta.changes ?? 0
  }

  /** The governance view's population read: the client's LIVE refresh-token
   *  count (unconsumed AND unexpired — a revoked family is deleted
   *  wholesale, so a live row's presence is the offline grant's standing). */
  async countOidcRefreshTokensForClient(clientId: string): Promise<number> {
    await this.ensureMembershipSupport()
    await this.ensureOidcRefreshTokenSupport()
    const row = await this.stmt(
      "SELECT COUNT(*) AS n FROM oidc_refresh_tokens WHERE client_id = ? AND consumed_at IS NULL AND datetime(expires_at) > datetime('now')", clientId,
    ).first<{ n: number }>()
    return row?.n ?? 0
  }

  async listOidcKeys(): Promise<OidcKeyRow[]> {
    const res = await this.stmt('SELECT * FROM oidc_keys ORDER BY created_at, kid').all<Record<string, unknown>>()
    return res.results.map(row => ({
      kid: row.kid as string,
      publicJwk: row.public_jwk as string,
      status: row.status as OidcKeyRow['status'],
      createdAt: row.created_at as string,
      retiredAt: (row.retired_at as string | null) ?? null,
    }))
  }

  async upsertOidcKey(input: { kid: string; publicJwk: string }): Promise<void> {
    await this.stmt('INSERT OR IGNORE INTO oidc_keys (kid, public_jwk) VALUES (?, ?)', input.kid, input.publicJwk).run()
  }

  // ── the remembered consent grants (TODO.identity-features/12) ─────

  private static toConsentGrant(row: Record<string, unknown>): OidcConsentGrant {
    return {
      id: row.id as string,
      userId: row.user_id as string,
      clientId: row.client_id as string,
      scope: row.scope as string,
      createdAt: D1ServerStore.storeTimeToIso(row.created_at as string)!,
      revokedAt: D1ServerStore.storeTimeToIso((row.revoked_at as string | null) ?? null),
    }
  }

  async getConsentGrant(userId: string, clientId: string, scope: string): Promise<OidcConsentGrant | null> {
    await this.ensureConsentGrantSupport()
    // The skip check's coverage math is the store.ts helper's, never a
    // LIKE scan: the account's live rows for the client, the freshest
    // covering grant wins.
    const res = await this.stmt(
      'SELECT * FROM oidc_consent_grants WHERE user_id = ? AND client_id = ? AND revoked_at IS NULL ORDER BY created_at DESC, rowid DESC',
      userId, clientId,
    ).all<Record<string, unknown>>()
    for (const row of res.results) {
      if (consentGrantCovers(row.scope as string, scope)) return D1ServerStore.toConsentGrant(row)
    }
    return null
  }

  async recordConsentGrant(input: { userId: string; clientId: string; scope: string }): Promise<OidcConsentGrant> {
    await this.ensureConsentGrantSupport()
    const scope = normalizeOidcScopeSet(input.scope)
    // The upsert targets the partial unique index: a live triple's row
    // refreshes its stamp (the re-affirmed consent); a REVOKED triple's
    // re-allow falls out of the index's predicate and inserts FRESH —
    // the history survives.
    await this.stmt(
      `INSERT INTO oidc_consent_grants (id, user_id, client_id, scope)
       VALUES (?, ?, ?, ?)
       ON CONFLICT (user_id, client_id, scope) WHERE revoked_at IS NULL
       DO UPDATE SET created_at = datetime('now')`,
      crypto.randomUUID(), input.userId, input.clientId, scope,
    ).run()
    const row = await this.stmt(
      'SELECT * FROM oidc_consent_grants WHERE user_id = ? AND client_id = ? AND scope = ? AND revoked_at IS NULL',
      input.userId, input.clientId, scope,
    ).first<Record<string, unknown>>()
    if (!row) throw new Error('recordConsentGrant: the upsert left no live row')
    return D1ServerStore.toConsentGrant(row)
  }

  async listConsentGrants(userId: string): Promise<OidcConsentGrant[]> {
    await this.ensureConsentGrantSupport()
    // The console's list: the LIVE grants only (the revoked rows ride the
    // audit chain), newest first — created_at is second-resolution, the
    // rowid breaks the tie.
    const res = await this.stmt(
      'SELECT * FROM oidc_consent_grants WHERE user_id = ? AND revoked_at IS NULL ORDER BY created_at DESC, rowid DESC',
      userId,
    ).all<Record<string, unknown>>()
    return res.results.map(D1ServerStore.toConsentGrant)
  }

  /** The guarded revoke: the owner's LIVE row flips, once. */
  async revokeConsentGrant(id: string, userId: string): Promise<boolean> {
    await this.ensureConsentGrantSupport()
    const res = await this.stmt(
      "UPDATE oidc_consent_grants SET revoked_at = datetime('now') WHERE id = ? AND user_id = ? AND revoked_at IS NULL",
      id, userId,
    ).run()
    return (res.meta.changes ?? 0) > 0
  }

  /** The client-registry governance view's per-client read: EVERY grant row
   *  the client holds — live AND revoked, newest first. */
  async listOidcConsentGrantsForClient(clientId: string): Promise<OidcConsentGrant[]> {
    await this.ensureConsentGrantSupport()
    const res = await this.stmt(
      'SELECT * FROM oidc_consent_grants WHERE client_id = ? ORDER BY created_at DESC, rowid DESC',
      clientId,
    ).all<Record<string, unknown>>()
    return res.results.map(D1ServerStore.toConsentGrant)
  }

  // ── the upstream providers (TODO.identity/08) ─────────────────────
  // The provider + link rows port directly (D1 is SQLite).

  private static toIdentityProvider(row: Record<string, unknown>): IdentityProvider {
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

  async listIdentityProviders(): Promise<IdentityProvider[]> {
    const res = await this.stmt('SELECT * FROM identity_providers ORDER BY created_at, id').all<Record<string, unknown>>()
    return res.results.map(D1ServerStore.toIdentityProvider)
  }

  async getIdentityProvider(id: string): Promise<IdentityProvider | null> {
    const row = await this.stmt('SELECT * FROM identity_providers WHERE id = ?', id).first<Record<string, unknown>>()
    return row ? D1ServerStore.toIdentityProvider(row) : null
  }

  async upsertIdentityProvider(input: {
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
  }): Promise<IdentityProvider> {
    await this.stmt(
      `INSERT INTO identity_providers
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
         updated_at = datetime('now')`,
      input.id, input.kind, input.displayName, input.brandMark ?? null, input.issuer ?? null,
      input.clientId, input.clientSecretRef ?? null, input.scopes ?? null,
      // Disabled by default (the schema's DEFAULT 0): a deliberate
      // enable makes the provider visible.
      input.enabled ? 1 : 0, input.createdBy ?? null,
    ).run()
    return (await this.getIdentityProvider(input.id))!
  }

  async setIdentityProviderEnabled(id: string, enabled: boolean): Promise<IdentityProvider | null> {
    const res = await this.stmt(
      "UPDATE identity_providers SET enabled = ?, updated_at = datetime('now') WHERE id = ?",
      enabled ? 1 : 0, id,
    ).run()
    return (res.meta.changes ?? 0) > 0 ? this.getIdentityProvider(id) : null
  }

  async deleteIdentityProvider(id: string): Promise<boolean> {
    const res = await this.stmt('DELETE FROM identity_providers WHERE id = ?', id).run()
    return (res.meta.changes ?? 0) > 0
  }

  // ── the linked identities (TODO.identity/02's shape, 08's flows) ────
  // ── the OP's account model (TODO.identity/02) ──────────────────────
  // The account rows port directly (D1 is SQLite) — the same statements
  // as op-accounts-store.ts's sync half.

  private static toIdentityLink(row: Record<string, unknown>): IdentityLink {
    return {
      id: row.id as string,
      userId: row.user_id as string,
      provider: row.provider as string,
      providerAccountId: row.provider_account_id as string,
      linkedAt: row.linked_at as string,
      linkedBy: (row.linked_by as string | null) ?? null,
    }
  }

  async listIdentityLinks(userId: string): Promise<IdentityLink[]> {
    const res = await this.stmt('SELECT * FROM identity_links WHERE user_id = ? ORDER BY linked_at, provider', userId)
      .all<Record<string, unknown>>()
    return res.results.map(D1ServerStore.toIdentityLink)
  }

  /** The bulk list-endpoint variant (identity's TODO.restructure/06):
   *  ONE read for the whole set (the per-row loop's O(rows) D1 round
   *  trips collapsed); every requested id answers, an unknown id as the
   *  empty array; each account's links keep the per-id read's own
   *  (linked_at, provider) order. */
  async listIdentityLinksBulk(userIds: string[]): Promise<Map<string, IdentityLink[]>> {
    const answer = new Map<string, IdentityLink[]>(userIds.map(id => [id, []]))
    if (userIds.length === 0) return answer
    const placeholders = userIds.map(() => '?').join(',')
    const res = await this.stmt(`SELECT * FROM identity_links WHERE user_id IN (${placeholders}) ORDER BY linked_at, provider`, ...userIds)
      .all<Record<string, unknown>>()
    for (const row of res.results) {
      const link = D1ServerStore.toIdentityLink(row)
      answer.get(link.userId)?.push(link)
    }
    return answer
  }

  async findIdentityLink(provider: string, providerAccountId: string): Promise<IdentityLink | null> {
    const row = await this.stmt('SELECT * FROM identity_links WHERE provider = ? AND provider_account_id = ?', provider, providerAccountId)
      .first<Record<string, unknown>>()
    return row ? D1ServerStore.toIdentityLink(row) : null
  }

  /** Create the link; NULL on the UNIQUE(provider, provider_account_id)
   *  conflict — the pair is already linked (to any account). */
  async createIdentityLink(input: {
    userId: string
    provider: string
    providerAccountId: string
    linkedBy?: string | null
  }): Promise<IdentityLink | null> {
    const res = await this.stmt(
      'INSERT OR IGNORE INTO identity_links (id, user_id, provider, provider_account_id, linked_by) VALUES (?, ?, ?, ?, ?)',
      crypto.randomUUID(), input.userId, input.provider, input.providerAccountId, input.linkedBy ?? null,
    ).run()
    if ((res.meta.changes ?? 0) === 0) return null
    return this.findIdentityLink(input.provider, input.providerAccountId)
  }

  async deleteIdentityLink(userId: string, provider: string): Promise<boolean> {
    const res = await this.stmt('DELETE FROM identity_links WHERE user_id = ? AND provider = ?', userId, provider).run()
    return (res.meta.changes ?? 0) > 0
  }

  private static toEnrollmentToken(row: Record<string, unknown>): EnrollmentToken {
    return {
      token: row.token as string,
      userId: row.user_id as string,
      createdBy: (row.created_by as string | null) ?? null,
      createdAt: row.created_at as string,
      expiresAt: row.expires_at as string,
      consumedAt: (row.consumed_at as string | null) ?? null,
    }
  }

  async createOpAccount(input: {
    email: string
    name: string
    role: string
    createdBy?: string | null
  }): Promise<UserAdminRow | null> {
    const id = crypto.randomUUID()
    // TODO.identity-features/01: the address must be free across BOTH
    // address tables — an additional on another account blocks the
    // address as a new account's primary (an address names at most one
    // account; the users.email UNIQUE remains the race backstop).
    await this.ensureAccountEmailSupport()
    const additional = await this.stmt('SELECT user_id FROM account_emails WHERE email = ?', input.email.trim().toLowerCase()).first<{ user_id: string }>()
    if (additional) return null
    try {
      await this.stmt(
        "INSERT INTO users (id, email, name, provider, role) VALUES (?, ?, ?, 'password', ?)",
        id, input.email.trim().toLowerCase(), input.name.trim(), input.role,
      ).run()
    } catch (e) {
      if (String((e as Error).message).includes('UNIQUE')) return null
      throw e
    }
    const row = await this.stmt('SELECT * FROM users WHERE id = ?', id).first<UserRecord & { last_login?: string | null; provider?: string }>()
    return toAdminRow(row!)
  }

  /** The password sign-in's lookup: the credential + the active flag, by
   *  (normalized) email. The credential's EXISTENCE is the qualifier.
   *  TODO.identity-features/01: the address resolves by ANY of the
   *  account's VERIFIED addresses — the primary first (the primary owner
   *  always wins, the deterministic rule), then a proven account_emails
   *  row; an unverified additional never resolves. */
  async getPasswordLogin(email: string): Promise<{ userId: string; hash: string; active: boolean } | null> {
    await this.ensureAccountEmailSupport()
    const normalized = email.trim().toLowerCase()
    let row = await this.stmt(
      `SELECT u.id AS user_id, u.active AS active, p.hash AS hash
       FROM users u JOIN passwords p ON p.user_id = u.id
       WHERE u.email = ?`,
      normalized,
    ).first<{ user_id: string; active: number; hash: string }>()
    if (!row) {
      row = await this.stmt(
        `SELECT u.id AS user_id, u.active AS active, p.hash AS hash
         FROM users u JOIN passwords p ON p.user_id = u.id
         WHERE u.id = (SELECT user_id FROM account_emails WHERE email = ? AND verified_at IS NOT NULL)`,
        normalized,
      ).first<{ user_id: string; active: number; hash: string }>()
    }
    if (!row) return null
    return { userId: row.user_id, hash: row.hash, active: row.active !== 0 }
  }

  async setPasswordHash(userId: string, hash: string, setBy?: string | null): Promise<void> {
    await this.stmt(
      `INSERT INTO passwords (user_id, hash, set_by) VALUES (?, ?, ?)
       ON CONFLICT (user_id) DO UPDATE SET hash = excluded.hash, set_at = datetime('now'), set_by = excluded.set_by`,
      userId, hash, setBy ?? null,
    ).run()
  }

  /** The sign-in methods the account holds (the account page's
   *  password-set state + the admin list's posture). TODO.identity-sso/02:
   *  the passkeys count — a passkey is a PRIMARY sign-in method. */
  async countSignInMethods(userId: string): Promise<{ password: boolean; links: number; passkeys: number }> {
    const pw = await this.stmt('SELECT COUNT(*) AS n FROM passwords WHERE user_id = ?', userId).first<{ n: number }>()
    const links = await this.stmt('SELECT COUNT(*) AS n FROM identity_links WHERE user_id = ?', userId).first<{ n: number }>()
    const passkeys = await this.stmt('SELECT COUNT(*) AS n FROM webauthn_credentials WHERE user_id = ?', userId).first<{ n: number }>()
    return { password: (pw?.n ?? 0) > 0, links: links?.n ?? 0, passkeys: passkeys?.n ?? 0 }
  }

  /** The bulk list-endpoint variant (identity's TODO.restructure/06): the
   *  three grouped counts ride ONE batch — a single D1 round trip for
   *  the whole set, never three per account. Every requested id answers;
   *  an absent row reads as zero (the per-id read's posture). */
  async countSignInMethodsBulk(userIds: string[]): Promise<Map<string, { password: boolean; links: number; passkeys: number }>> {
    const answer = new Map<string, { password: boolean; links: number; passkeys: number }>(
      userIds.map(id => [id, { password: false, links: 0, passkeys: 0 }]),
    )
    if (userIds.length === 0) return answer
    const placeholders = userIds.map(() => '?').join(',')
    const grouped = (table: string) =>
      `SELECT user_id, COUNT(*) AS n FROM ${table} WHERE user_id IN (${placeholders}) GROUP BY user_id`
    const [pw, links, passkeys] = await this.db.batch<Record<string, unknown>>([
      this.stmt(grouped('passwords'), ...userIds),
      this.stmt(grouped('identity_links'), ...userIds),
      this.stmt(grouped('webauthn_credentials'), ...userIds),
    ])
    const tally = (res: D1Result<Record<string, unknown>>): Map<string, number> => {
      const m = new Map<string, number>()
      for (const row of res.results) m.set(String(row.user_id), Number(row.n))
      return m
    }
    const pwBy = tally(pw)
    const linksBy = tally(links)
    const passkeysBy = tally(passkeys)
    for (const id of userIds) {
      answer.set(id, {
        password: (pwBy.get(id) ?? 0) > 0,
        links: linksBy.get(id) ?? 0,
        passkeys: passkeysBy.get(id) ?? 0,
      })
    }
    return answer
  }

  async createEnrollmentToken(input: {
    token: string
    userId: string
    createdBy?: string | null
    ttlMs: number
  }): Promise<EnrollmentToken> {
    const expiresAt = new Date(Date.now() + input.ttlMs).toISOString()
    await this.stmt(
      'INSERT INTO enrollment_tokens (token, user_id, created_by, expires_at) VALUES (?, ?, ?, ?)',
      input.token, input.userId, input.createdBy ?? null, expiresAt,
    ).run()
    return (await this.getEnrollmentToken(input.token))!
  }

  async getEnrollmentToken(token: string): Promise<EnrollmentToken | null> {
    const row = await this.stmt('SELECT * FROM enrollment_tokens WHERE token = ?', token).first<Record<string, unknown>>()
    return row ? D1ServerStore.toEnrollmentToken(row) : null
  }

  /** Complete the enrollment: consume the token ATOMICALLY (a concurrent
   *  double-submit loses the consumed_at race), judge the expiry (an
   *  expired link is burned, never redeemed), then set the password. */
  async completeEnrollment(token: string, passwordHash: string, setBy?: string | null): Promise<CompleteEnrollmentResult> {
    const res = await this.stmt(
      "UPDATE enrollment_tokens SET consumed_at = datetime('now') WHERE token = ? AND consumed_at IS NULL", token,
    ).run()
    if ((res.meta.changes ?? 0) === 0) return { kind: 'unknown' }
    const row = (await this.getEnrollmentToken(token))!
    if (new Date(row.expiresAt).getTime() <= Date.now()) return { kind: 'expired' }
    await this.setPasswordHash(row.userId, passwordHash, setBy)
    // TODO.identity/06: the invite ceremony doubles as the address's
    // verification (the administrator-delivered one-time link).
    await this.stmt("UPDATE users SET email_verified_at = datetime('now') WHERE id = ?", row.userId).run()
    return { kind: 'ok', userId: row.userId }
  }

  /** The account's live sessions, `current` computed in SQL against the
   *  presenting token — the token value itself never leaves the store. */
  async listUserSessions(userId: string, currentToken?: string): Promise<SessionView[]> {
    await this.ensureSessionColumns()
    const res = await this.stmt(
      `SELECT id, created_at, expires_at, last_seen_at, user_agent, ip, (token = ?) AS is_current
       FROM sessions
       WHERE user_id = ? AND expires_at > datetime('now')
       ORDER BY created_at DESC`,
      currentToken ?? '', userId,
    ).all<Record<string, unknown>>()
    return res.results.map(row => ({
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
  async deleteSessionById(userId: string, sessionId: string): Promise<boolean> {
    const res = await this.stmt('DELETE FROM sessions WHERE id = ? AND user_id = ?', sessionId, userId).run()
    return (res.meta.changes ?? 0) > 0
  }

  /** Every live session across accounts (expired excluded), `current`
   *  computed in SQL against the presenting token — the aggregate admin
   *  read (TODO.identity-sso/01); the token never leaves the store. */
  async listOpLiveSessions(currentToken?: string): Promise<OpLiveSession[]> {
    await this.ensureSessionColumns()
    const res = await this.stmt(
      `SELECT id, user_id, created_at, expires_at, last_seen_at, user_agent, ip, (token = ?) AS is_current
       FROM sessions
       WHERE expires_at > datetime('now')
       ORDER BY created_at DESC`,
      currentToken ?? '',
    ).all<Record<string, unknown>>()
    return res.results.map(row => ({
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
  async deleteAllUserSessions(userId: string): Promise<number> {
    const res = await this.stmt('DELETE FROM sessions WHERE user_id = ?', userId).run()
    return res.meta.changes ?? 0
  }

  // ── the central user registry (TODO.identity/03) ──────────────────

  private static toClientRoleAssignment(row: Record<string, unknown>): OpClientRoleAssignment {
    return {
      userId: row.user_id as string,
      clientId: row.client_id as string,
      roles: JSON.parse(row.roles as string) as string[],
      assignedBy: (row.assigned_by as string | null) ?? null,
      createdAt: row.created_at as string,
      updatedAt: (row.updated_at as string | null) ?? null,
    }
  }

  async listOpClientRoles(userId: string): Promise<OpClientRoleAssignment[]> {
    const res = await this.stmt(
      'SELECT * FROM op_client_roles WHERE user_id = ? ORDER BY client_id', userId,
    ).all<Record<string, unknown>>()
    return res.results.map(D1ServerStore.toClientRoleAssignment)
  }

  /** EVERY per-client assignment across accounts (TODO.identity-sso/01's
   *  live access review). */
  async listAllOpClientRoles(): Promise<OpClientRoleAssignment[]> {
    const res = await this.stmt(
      'SELECT * FROM op_client_roles ORDER BY user_id, client_id',
    ).all<Record<string, unknown>>()
    return res.results.map(D1ServerStore.toClientRoleAssignment)
  }

  /** The assignment for ONE client: NULL = no row (the account default);
   *  an EMPTY array = the explicit "no roles on this client". */
  async getOpClientRoles(userId: string, clientId: string): Promise<string[] | null> {
    const row = await this.stmt(
      'SELECT roles FROM op_client_roles WHERE user_id = ? AND client_id = ?', userId, clientId,
    ).first<{ roles: string }>()
    return row ? (JSON.parse(row.roles) as string[]) : null
  }

  async setOpClientRoles(userId: string, clientId: string, roles: string[], assignedBy: string | null): Promise<void> {
    await this.stmt(
      `INSERT INTO op_client_roles (user_id, client_id, roles, assigned_by)
       VALUES (?, ?, ?, ?)
       ON CONFLICT (user_id, client_id) DO UPDATE SET
         roles = excluded.roles,
         assigned_by = excluded.assigned_by,
         updated_at = datetime('now')`,
      userId, clientId, JSON.stringify(roles), assignedBy,
    ).run()
  }

  async deleteOpClientRoles(userId: string, clientId: string): Promise<boolean> {
    const res = await this.stmt('DELETE FROM op_client_roles WHERE user_id = ? AND client_id = ?', userId, clientId).run()
    return (res.meta.changes ?? 0) > 0
  }

  /** The deactivation's revocation half: every live session, every issued
   *  access token, every refresh token (migration 0025 — the ensure runs
   *  first: a dev D1 from before it lacks the table), every unconsumed
   *  code and pending authorization goes. The user row STAYS (the
   *  history). */
  async revokeOpUserCredentials(userId: string): Promise<{ sessions: number; accessTokens: number; refreshTokens: number; codes: number; authorizations: number }> {
    await this.ensureOidcRefreshTokenSupport()
    const sessions = await this.stmt('DELETE FROM sessions WHERE user_id = ?', userId).run()
    const accessTokens = await this.stmt('DELETE FROM oidc_access_tokens WHERE user_id = ?', userId).run()
    const refreshTokens = await this.stmt('DELETE FROM oidc_refresh_tokens WHERE user_id = ?', userId).run()
    const codes = await this.stmt('DELETE FROM oidc_codes WHERE user_id = ? AND consumed_at IS NULL', userId).run()
    const authorizations = await this.stmt('DELETE FROM oidc_authorizations WHERE user_id = ? AND decision IS NULL', userId).run()
    return {
      sessions: sessions.meta.changes ?? 0,
      accessTokens: accessTokens.meta.changes ?? 0,
      refreshTokens: refreshTokens.meta.changes ?? 0,
      codes: codes.meta.changes ?? 0,
      authorizations: authorizations.meta.changes ?? 0,
    }
  }

  /** The registry's ERASURE act (the offboarding runbook's delete path):
   *  every credential, token, link and per-client assignment removed; the
   *  user row anonymized in place (provider 'erased' — it drops out of
   *  every account surface; the tombstone keeps the audit chain's
   *  entity_id resolvable). Answers the counts, null when absent. */
  async eraseOpAccount(userId: string): Promise<OpAccountErasure | null> {
    await this.ensureMembershipSupport()
    const row = await this.stmt('SELECT 1 AS ok FROM users WHERE id = ?', userId).first<{ ok: number }>()
    if (!row) return null
    const revoked = await this.revokeOpUserCredentials(userId)
    const links = await this.stmt('DELETE FROM identity_links WHERE user_id = ?', userId).run()
    const clientRoles = await this.stmt('DELETE FROM op_client_roles WHERE user_id = ?', userId).run()
    // TODO.identity/11: the memberships go too (the tombstone acts for
    // no organization).
    const memberships = await this.stmt('DELETE FROM org_memberships WHERE user_id = ?', userId).run()
    const passwords = await this.stmt('DELETE FROM passwords WHERE user_id = ?', userId).run()
    const enrollments = await this.stmt('DELETE FROM enrollment_tokens WHERE user_id = ?', userId).run()
    const emailChanges = await this.stmt('DELETE FROM email_change_tokens WHERE user_id = ?', userId).run()
    // TODO.identity-sso/02+03: the factor registry follows the account
    // into erasure (passkeys, TOTP secrets, recovery codes, pending
    // ceremony state).
    const passkeys = await this.stmt('DELETE FROM webauthn_credentials WHERE user_id = ?', userId).run()
    const totp = await this.stmt('DELETE FROM totp_secrets WHERE user_id = ?', userId).run()
    const recovery = await this.stmt('DELETE FROM recovery_codes WHERE user_id = ?', userId).run()
    const challenges = await this.stmt('DELETE FROM webauthn_challenges WHERE user_id = ?', userId).run()
    const mfa = await this.stmt('DELETE FROM mfa_pending WHERE user_id = ?', userId).run()
    // TODO.identity-features/08: the developer tokens die with the
    // account (the hashed rows go — a tombstone's tokens never exchange
    // again).
    await this.ensurePersonalAccessTokenSupport()
    const personalAccessTokens = await this.stmt('DELETE FROM personal_access_tokens WHERE user_id = ?', userId).run()
    // TODO.identity-features/12: the remembered consent grants die with
    // the account (a tombstone never skips a consent page again).
    await this.ensureConsentGrantSupport()
    const consentGrants = await this.stmt('DELETE FROM oidc_consent_grants WHERE user_id = ?', userId).run()
    // TODO.identity-features/01: the additional addresses die with the
    // account (a tombstone's addresses never resolve a sign-in again).
    await this.ensureAccountEmailSupport()
    const emails = await this.stmt('DELETE FROM account_emails WHERE user_id = ?', userId).run()
    await this.stmt(
      `UPDATE users SET
         email = ?, name = 'Deleted account', provider = 'erased',
         role = 'viewer', roles = NULL, org_id = NULL,
         avatar_url = NULL, email_verified_at = NULL, active = 0
       WHERE id = ?`,
      `deleted-${userId}@erased.invalid`, userId,
    ).run()
    return {
      ...revoked,
      links: links.meta.changes ?? 0,
      clientRoles: clientRoles.meta.changes ?? 0,
      memberships: memberships.meta.changes ?? 0,
      tokens: (passwords.meta.changes ?? 0) + (enrollments.meta.changes ?? 0) + (emailChanges.meta.changes ?? 0),
      factors: (passkeys.meta.changes ?? 0) + (totp.meta.changes ?? 0) + (recovery.meta.changes ?? 0)
        + (challenges.meta.changes ?? 0) + (mfa.meta.changes ?? 0),
      personalAccessTokens: personalAccessTokens.meta.changes ?? 0,
      consentGrants: consentGrants.meta.changes ?? 0,
      emails: emails.meta.changes ?? 0,
    }
  }

  /** The registry's edit act (name/email). The email UNIQUE conflict
   *  throws 'unique' (the route maps it to a 409, never a silent take).
   *  TODO.identity-features/01: the conflict read spans BOTH address
   *  tables — an additional row (on any account, this one included)
   *  holds the address too. */
  async updateOpAccount(id: string, input: { name?: string; email?: string }): Promise<boolean> {
    if (input.email !== undefined) {
      await this.ensureAccountEmailSupport()
      const additional = await this.stmt('SELECT user_id FROM account_emails WHERE email = ?', input.email.trim().toLowerCase()).first<{ user_id: string }>()
      if (additional) throw new Error(`unique: ${input.email}`)
      try {
        // TODO.identity/06: an admin-set address never went through the
        // verify-new-email ceremony, so the verification state resets.
        await this.stmt('UPDATE users SET email = ?, email_verified_at = NULL WHERE id = ?', input.email.trim().toLowerCase(), id).run()
      } catch (e) {
        if (String((e as Error).message).includes('UNIQUE')) throw new Error(`unique: ${input.email}`)
        throw e
      }
    }
    if (input.name !== undefined) {
      await this.stmt('UPDATE users SET name = ? WHERE id = ?', input.name.trim(), id).run()
    }
    const row = await this.stmt('SELECT 1 AS ok FROM users WHERE id = ?', id).first<{ ok: number }>()
    return !!row
  }

  /** The last OP-side sign-in per account, FROM THE AUDIT CHAIN: the
   *  newest auditEvents row whose action is a sign-in
   *  ('account.sign_in' / 'upstream_sign_in') per entity_id. The typed
   *  read (the 2026-09-06 audit): the legs come out of the data JSON by
   *  json_extract against idx_entities_store_action (migration 0023) —
   *  the sign-in slice is an index walk, never the O(journal) data-LIKE
   *  scan. The json_valid guard spells the index's expression exactly
   *  (a corrupt entities row answers NULL legs, never a raised
   *  'malformed JSON'). The action match stays exact (the retired
   *  LIKE's closing quote made it so too) — and now spelling-proof:
   *  the legs parse the JSON, so a serialized-with-spaces row answers
   *  and an embedded lookalike substring never does. */
  async lastAccountSignIns(): Promise<Record<string, string>> {
    const res = await this.stmt(
      `SELECT json_extract(CASE WHEN json_valid(data) THEN data ELSE '{}' END, '$.entity_id') AS entity_id,
              MAX(json_extract(CASE WHEN json_valid(data) THEN data ELSE '{}' END, '$.timestamp')) AS ts
       FROM entities
       WHERE store = 'auditEvents'
         AND json_extract(CASE WHEN json_valid(data) THEN data ELSE '{}' END, '$.action') IN ('account.sign_in', 'upstream_sign_in')
       GROUP BY json_extract(CASE WHEN json_valid(data) THEN data ELSE '{}' END, '$.entity_id')`,
    ).all<{ entity_id: string | null; ts: string | null }>()
    const out: Record<string, string> = {}
    for (const { entity_id, ts } of res.results) {
      // A row missing either leg (the malformed audit row) is skipped,
      // never trusted — the same posture the JSON fold held.
      if (typeof entity_id === 'string' && typeof ts === 'string') out[entity_id] = ts
    }
    return out
  }

  // ── the account console (TODO.identity/06) ─────────────────────────

  /** The profile edit's write (the display name). */
  async updateUserName(userId: string, name: string): Promise<boolean> {
    const res = await this.stmt('UPDATE users SET name = ? WHERE id = ?', name.trim(), userId).run()
    return (res.meta.changes ?? 0) > 0
  }

  /** The avatar write (the account console's upload/remove; NULL = the
   *  initials). */
  async setUserAvatar(userId: string, avatarUrl: string | null): Promise<boolean> {
    const res = await this.stmt('UPDATE users SET avatar_url = ? WHERE id = ?', avatarUrl, userId).run()
    return (res.meta.changes ?? 0) > 0
  }

  /** Remove the account's password credential (the route holds the
   *  at-least-one-method guard). */
  async deletePasswordHash(userId: string): Promise<boolean> {
    const res = await this.stmt('DELETE FROM passwords WHERE user_id = ?', userId).run()
    return (res.meta.changes ?? 0) > 0
  }

  /** Revoke every session of the account EXCEPT the presenting one. */
  async deleteOtherSessions(userId: string, keepToken: string): Promise<number> {
    const res = await this.stmt('DELETE FROM sessions WHERE user_id = ? AND token != ?', userId, keepToken).run()
    return res.meta.changes ?? 0
  }

  private static toEmailChangeToken(row: Record<string, unknown>): EmailChangeToken {
    return {
      token: row.token as string,
      userId: row.user_id as string,
      newEmail: row.new_email as string,
      deliveredBy: row.delivered_by === 'mailer' ? 'mailer' : 'shown',
      // TODO.identity-features/01: rows predating the kind column (or a
      // store over a pre-0022 database) read as the legacy ceremony; the
      // 0.2.4 'verify' kind reads by its name.
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
   *  'verify' rows (the target is the current primary — one per
   *  account, the change doctrine's scoping). */
  async createEmailChangeToken(input: {
    token: string
    userId: string
    newEmail: string
    deliveredBy: 'mailer' | 'shown'
    kind?: 'change' | 'add' | 'verify'
    ttlMs: number
  }): Promise<EmailChangeToken> {
    await this.ensureAccountEmailSupport()
    const kind = input.kind ?? 'change'
    if (kind === 'change') {
      await this.stmt(
        "UPDATE email_change_tokens SET consumed_at = datetime('now') WHERE user_id = ? AND kind = 'change' AND consumed_at IS NULL",
        input.userId,
      ).run()
    } else if (kind === 'verify') {
      await this.stmt(
        "UPDATE email_change_tokens SET consumed_at = datetime('now') WHERE user_id = ? AND kind = 'verify' AND consumed_at IS NULL",
        input.userId,
      ).run()
    } else {
      await this.stmt(
        "UPDATE email_change_tokens SET consumed_at = datetime('now') WHERE user_id = ? AND kind = 'add' AND new_email = ? AND consumed_at IS NULL",
        input.userId, input.newEmail.trim().toLowerCase(),
      ).run()
    }
    const expiresAt = new Date(Date.now() + input.ttlMs).toISOString()
    await this.stmt(
      'INSERT INTO email_change_tokens (token, user_id, new_email, delivered_by, kind, expires_at) VALUES (?, ?, ?, ?, ?, ?)',
      input.token, input.userId, input.newEmail.trim().toLowerCase(), input.deliveredBy, kind, expiresAt,
    ).run()
    return (await this.getEmailChangeToken(input.token))!
  }

  async getEmailChangeToken(token: string): Promise<EmailChangeToken | null> {
    const row = await this.stmt('SELECT * FROM email_change_tokens WHERE token = ?', token).first<Record<string, unknown>>()
    return row ? D1ServerStore.toEmailChangeToken(row) : null
  }

  /** The account's pending PRIMARY change (the newest live 'change'
   *  row), so the console can show it. The per-address verifications are
   *  the account_emails rows' own state (verified_at NULL = waiting),
   *  never a pending read here. */
  async getPendingEmailChange(userId: string): Promise<EmailChangeToken | null> {
    await this.ensureAccountEmailSupport()
    const row = await this.stmt(
      `SELECT * FROM email_change_tokens
       WHERE user_id = ? AND kind = 'change' AND consumed_at IS NULL AND expires_at > datetime('now')
       ORDER BY created_at DESC LIMIT 1`,
      userId,
    ).first<Record<string, unknown>>()
    return row ? D1ServerStore.toEmailChangeToken(row) : null
  }

  /** Complete the ceremony: consume ATOMICALLY (a presented link works
   *  exactly once, expired or not), judge the expiry, then act on the
   *  kind. 'change' (the pre-01 primary replacement): re-check the
   *  address's uniqueness across BOTH address tables (a conflict burns
   *  the token honestly — an additional row anywhere holds the address
   *  too, this account's included), then move users.email. 'add' (the
   *  per-address verification): the account_emails row landed unverified
   *  at the request; the completion stamps it (a row removed meanwhile
   *  burns the link as 'unknown'). 'verify' (the 0.2.4 kind): the
   *  re-verification of the address the account ALREADY holds as its
   *  primary — the completion stamps users.email_verified_at when the
   *  token's new_email IS STILL the primary (a primary moved meanwhile
   *  burns the link as 'unknown', the vanished-target doctrine).
   *  A 'mailer'-delivered token verifies the address; a shown one never
   *  does. */
  async completeEmailChange(token: string): Promise<CompleteEmailChangeResult> {
    await this.ensureAccountEmailSupport()
    const res = await this.stmt(
      "UPDATE email_change_tokens SET consumed_at = datetime('now') WHERE token = ? AND consumed_at IS NULL", token,
    ).run()
    if ((res.meta.changes ?? 0) === 0) return { kind: 'unknown' }
    const row = (await this.getEmailChangeToken(token))!
    if (new Date(row.expiresAt).getTime() <= Date.now()) return { kind: 'expired' }
    const verified = row.deliveredBy === 'mailer'
    if (row.kind === 'add') {
      const standing = await this.stmt('SELECT 1 AS ok FROM account_emails WHERE user_id = ? AND email = ?', row.userId, row.newEmail).first<{ ok: number }>()
      if (!standing) return { kind: 'unknown' }
      if (verified) await this.markAccountEmailVerified(row.userId, row.newEmail)
      return { kind: 'ok', userId: row.userId, newEmail: row.newEmail, verified }
    }
    if (row.kind === 'verify') {
      // The address never changes hands in this ceremony — 'conflict'
      // does not exist here; the honest burns are the moved primary and
      // the gone account, both read from the users row.
      const current = await this.stmt('SELECT email FROM users WHERE id = ?', row.userId).first<{ email: string }>()
      if (!current || current.email !== row.newEmail) return { kind: 'unknown' }
      if (verified) await this.stmt("UPDATE users SET email_verified_at = datetime('now') WHERE id = ?", row.userId).run()
      return { kind: 'ok', userId: row.userId, newEmail: row.newEmail, verified }
    }
    const taken = await this.stmt('SELECT id FROM users WHERE email = ?', row.newEmail).first<{ id: string }>()
    if (taken) return { kind: 'conflict' }
    const takenAdditional = await this.stmt('SELECT user_id FROM account_emails WHERE email = ?', row.newEmail).first<{ user_id: string }>()
    if (takenAdditional) return { kind: 'conflict' }
    await this.stmt(
      `UPDATE users SET email = ?, email_verified_at = ${verified ? "datetime('now')" : 'NULL'} WHERE id = ?`,
      row.newEmail, row.userId,
    ).run()
    return { kind: 'ok', userId: row.userId, newEmail: row.newEmail, verified }
  }

  // ── multiple emails per account (TODO.identity-features/01) ────────

  private static toAccountEmail(row: Record<string, unknown>, isPrimary: boolean): AccountEmail {
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
  async listAccountEmails(userId: string): Promise<AccountEmail[]> {
    await this.ensureAccountEmailSupport()
    const primary = await this.stmt(
      'SELECT id AS user_id, email, email_verified_at AS verified_at, created_at FROM users WHERE id = ?', userId,
    ).first<Record<string, unknown>>()
    const res = await this.stmt(
      'SELECT * FROM account_emails WHERE user_id = ? ORDER BY created_at, email', userId,
    ).all<Record<string, unknown>>()
    const out: AccountEmail[] = []
    if (primary) out.push(D1ServerStore.toAccountEmail(primary, true))
    out.push(...res.results.map(r => D1ServerStore.toAccountEmail(r, false)))
    return out
  }

  /** Resolve the account by ANY of its addresses: the primary always
   *  names it (and the primary owner always wins — the deterministic
   *  rule); an additional ONLY when verified. */
  async findUserByAnyEmail(email: string): Promise<AuthUserPayload | null> {
    await this.ensureAccountEmailSupport()
    const normalized = email.trim().toLowerCase()
    const primary = await this.stmt('SELECT * FROM users WHERE email = ?', normalized).first<UserRecord>()
    if (primary) return toPayload(primary)
    const owner = await this.stmt(
      'SELECT user_id FROM account_emails WHERE email = ? AND verified_at IS NOT NULL', normalized,
    ).first<{ user_id: string }>()
    if (!owner) return null
    const user = await this.stmt('SELECT * FROM users WHERE id = ?', owner.user_id).first<UserRecord>()
    return user ? toPayload(user) : null
  }

  /** Add an ADDITIONAL address (normalized lowercase; the row lands
   *  UNVERIFIED). The account's own existing row answers 'present' (the
   *  idempotent re-add); any other hold of the address — a primary
   *  anywhere (this account's included) or another account's additional
   *  — answers 'conflict'. The unique index is the race backstop. */
  async addAccountEmail(userId: string, email: string, addedBy?: string | null): Promise<AddAccountEmailResult> {
    await this.ensureAccountEmailSupport()
    const normalized = email.trim().toLowerCase()
    const takenPrimary = await this.stmt('SELECT id FROM users WHERE email = ?', normalized).first<{ id: string }>()
    if (takenPrimary) return 'conflict'
    const existing = await this.stmt('SELECT user_id FROM account_emails WHERE email = ?', normalized).first<{ user_id: string }>()
    if (existing) return existing.user_id === userId ? 'present' : 'conflict'
    try {
      await this.stmt(
        'INSERT INTO account_emails (user_id, email, added_by) VALUES (?, ?, ?)',
        userId, normalized, addedBy ?? null,
      ).run()
    } catch (e) {
      if (String((e as Error).message).includes('UNIQUE')) return 'conflict'
      throw e
    }
    return 'added'
  }

  /** The verification ceremony's stamp on the account's OWN row: the
   *  guarded UPDATE flips verified_at, once. */
  async markAccountEmailVerified(userId: string, email: string): Promise<boolean> {
    await this.ensureAccountEmailSupport()
    const res = await this.stmt(
      "UPDATE account_emails SET verified_at = datetime('now') WHERE user_id = ? AND email = ? AND verified_at IS NULL",
      userId, email.trim().toLowerCase(),
    ).run()
    return (res.meta.changes ?? 0) > 0
  }

  /** Promote a VERIFIED additional to primary: the promoted address
   *  becomes users.email with its verification stamp; the outgoing
   *  primary takes the row's place in account_emails with ITS stamp
   *  (it stays a verified additional — sign-in by it keeps working). */
  async setPrimaryAccountEmail(userId: string, email: string): Promise<'ok' | 'unknown' | 'unverified'> {
    await this.ensureAccountEmailSupport()
    const normalized = email.trim().toLowerCase()
    const row = await this.stmt('SELECT * FROM account_emails WHERE user_id = ? AND email = ?', userId, normalized).first<Record<string, unknown>>()
    if (!row) return 'unknown'
    if (!row.verified_at) return 'unverified'
    const current = await this.stmt('SELECT email, email_verified_at FROM users WHERE id = ?', userId).first<{ email: string; email_verified_at: string | null }>()
    if (!current) return 'unknown'
    await this.stmt('UPDATE users SET email = ?, email_verified_at = ? WHERE id = ?', normalized, row.verified_at as string, userId).run()
    await this.stmt('DELETE FROM account_emails WHERE user_id = ? AND email = ?', userId, normalized).run()
    await this.stmt('INSERT INTO account_emails (user_id, email, verified_at) VALUES (?, ?, ?)', userId, current.email, current.email_verified_at).run()
    return 'ok'
  }

  /** Remove an ADDITIONAL address. The primary refuses honestly
   *  ('primary' — promote another address first). */
  async removeAccountEmail(userId: string, email: string): Promise<'ok' | 'primary' | 'unknown'> {
    await this.ensureAccountEmailSupport()
    const normalized = email.trim().toLowerCase()
    const current = await this.stmt('SELECT email FROM users WHERE id = ?', userId).first<{ email: string }>()
    if (current?.email === normalized) return 'primary'
    const res = await this.stmt('DELETE FROM account_emails WHERE user_id = ? AND email = ?', userId, normalized).run()
    return (res.meta.changes ?? 0) > 0 ? 'ok' : 'unknown'
  }

  // ── strong authentication: the factor registry (TODO.identity-sso/02 + /03) ──
  // The same SQL as the SQLite half (store/sqlite/factors-store.ts): the
  // one-time consumes are guarded UPDATEs, the counter advance is the
  // clone-guarded UPDATE, the throttles ride the rows — the database is
  // the proof, never a per-isolate Map.

  async createWebauthnChallenge(input: {
    challenge: string
    userId: string | null
    kind: WebauthnChallenge['kind']
    ttlMs: number
  }): Promise<void> {
    const expiresAt = new Date(Date.now() + input.ttlMs).toISOString()
    // The sweep rides the write (the putSsoState pattern).
    await this.stmt("DELETE FROM webauthn_challenges WHERE expires_at <= datetime('now')").run()
    await this.stmt(
      'INSERT INTO webauthn_challenges (challenge, user_id, kind, expires_at) VALUES (?, ?, ?, ?)',
      input.challenge, input.userId, input.kind, expiresAt,
    ).run()
  }

  async consumeWebauthnChallenge(challenge: string): Promise<WebauthnChallenge | null> {
    const res = await this.stmt(
      "UPDATE webauthn_challenges SET consumed_at = datetime('now') WHERE challenge = ? AND consumed_at IS NULL", challenge,
    ).run()
    if ((res.meta.changes ?? 0) === 0) return null
    const row = await this.stmt('SELECT * FROM webauthn_challenges WHERE challenge = ?', challenge).first<Record<string, unknown>>()
    if (!row) return null
    if (new Date(row.expires_at as string).getTime() <= Date.now()) return null
    return D1ServerStore.toWebauthnChallenge(row)
  }

  async createWebauthnCredential(input: {
    credentialId: string
    userId: string
    name: string
    publicKeyCose: string
    signCount: number
    aaguid: string | null
    transports: string[]
    ip?: string | null
  }): Promise<WebauthnCredential | null> {
    try {
      await this.stmt(
        `INSERT INTO webauthn_credentials
           (credential_id, user_id, name, public_key, sign_count, aaguid, transports, last_ip)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        input.credentialId, input.userId, input.name, input.publicKeyCose,
        Math.max(0, Math.floor(input.signCount)), input.aaguid, JSON.stringify(input.transports),
        input.ip ?? null,
      ).run()
    } catch (e) {
      if (String((e as Error).message).includes('UNIQUE')) return null
      throw e
    }
    return this.getWebauthnCredential(input.credentialId)
  }

  async listWebauthnCredentials(userId: string): Promise<WebauthnCredential[]> {
    const res = await this.stmt(
      'SELECT * FROM webauthn_credentials WHERE user_id = ? ORDER BY created_at, credential_id', userId,
    ).all<Record<string, unknown>>()
    return res.results.map(D1ServerStore.toWebauthnCredential)
  }

  async getWebauthnCredential(credentialId: string): Promise<WebauthnCredential | null> {
    const row = await this.stmt(
      'SELECT * FROM webauthn_credentials WHERE credential_id = ?', credentialId,
    ).first<Record<string, unknown>>()
    return row ? D1ServerStore.toWebauthnCredential(row) : null
  }

  async deleteWebauthnCredential(userId: string, credentialId: string): Promise<boolean> {
    const res = await this.stmt(
      'DELETE FROM webauthn_credentials WHERE credential_id = ? AND user_id = ?', credentialId, userId,
    ).run()
    return (res.meta.changes ?? 0) > 0
  }

  async advanceWebauthnCounter(credentialId: string, newCount: number, opts?: { ip?: string | null }): Promise<AdvanceCounterResult> {
    const count = Math.max(0, Math.floor(newCount))
    const res = await this.stmt(
      `UPDATE webauthn_credentials
       SET sign_count = ?, last_used_at = datetime('now'), last_ip = ?
       WHERE credential_id = ? AND ((sign_count = 0 AND ? = 0) OR sign_count < ?)`,
      count, opts?.ip ?? null, credentialId, count, count,
    ).run()
    if ((res.meta.changes ?? 0) > 0) return 'ok'
    return (await this.getWebauthnCredential(credentialId)) ? 'regressed' : 'unknown'
  }

  async createTotpSecret(input: { id: string; userId: string; name: string; secret: string }): Promise<TotpSecret> {
    await this.stmt(
      'INSERT INTO totp_secrets (id, user_id, name, secret) VALUES (?, ?, ?, ?)',
      input.id, input.userId, input.name, input.secret,
    ).run()
    return (await this.getTotpSecret(input.id))!
  }

  async listTotpSecrets(userId: string): Promise<TotpSecret[]> {
    const res = await this.stmt(
      'SELECT * FROM totp_secrets WHERE user_id = ? ORDER BY created_at, id', userId,
    ).all<Record<string, unknown>>()
    return res.results.map(D1ServerStore.toTotpSecret)
  }

  async getTotpSecret(id: string): Promise<TotpSecret | null> {
    const row = await this.stmt('SELECT * FROM totp_secrets WHERE id = ?', id).first<Record<string, unknown>>()
    return row ? D1ServerStore.toTotpSecret(row) : null
  }

  async markTotpSecretVerified(id: string, userId: string, name: string): Promise<boolean> {
    const res = await this.stmt(
      "UPDATE totp_secrets SET verified_at = datetime('now'), name = ? WHERE id = ? AND user_id = ? AND verified_at IS NULL",
      name, id, userId,
    ).run()
    return (res.meta.changes ?? 0) > 0
  }

  async recordTotpEnrollFailure(id: string, userId: string): Promise<number> {
    const res = await this.stmt(
      "UPDATE totp_secrets SET fail_count = fail_count + 1, last_failure_at = datetime('now') WHERE id = ? AND user_id = ? AND verified_at IS NULL",
      id, userId,
    ).run()
    if ((res.meta.changes ?? 0) === 0) return 0
    const row = await this.stmt('SELECT fail_count AS n FROM totp_secrets WHERE id = ?', id).first<{ n: number }>()
    return row?.n ?? 0
  }

  async markTotpSecretUsed(id: string, opts?: { ip?: string | null }): Promise<void> {
    await this.stmt(
      "UPDATE totp_secrets SET last_used_at = datetime('now'), last_ip = ? WHERE id = ?",
      opts?.ip ?? null, id,
    ).run()
  }

  async deleteTotpSecret(userId: string, id: string): Promise<boolean> {
    const res = await this.stmt('DELETE FROM totp_secrets WHERE id = ? AND user_id = ?', id, userId).run()
    return (res.meta.changes ?? 0) > 0
  }

  /** The regenerate: the old batch goes, the new hashes land — D1's
   *  batch is all-or-nothing (the sqlite half's transaction). */
  async replaceRecoveryCodes(userId: string, batch: string, codeHashes: string[]): Promise<void> {
    const statements: D1PreparedStatement[] = [
      this.stmt('DELETE FROM recovery_codes WHERE user_id = ?', userId),
      ...codeHashes.map(hash => this.stmt(
        'INSERT INTO recovery_codes (id, user_id, batch, code_hash) VALUES (?, ?, ?, ?)',
        crypto.randomUUID(), userId, batch, hash,
      )),
    ]
    await this.db.batch(statements)
  }

  async recoveryCodeState(userId: string): Promise<RecoveryCodeState> {
    const row = await this.stmt(
      `SELECT COUNT(*) AS total,
              SUM(CASE WHEN consumed_at IS NULL THEN 1 ELSE 0 END) AS remaining,
              MAX(created_at) AS created_at
       FROM recovery_codes WHERE user_id = ?`, userId,
    ).first<{ total: number; remaining: number | null; created_at: string | null }>()
    return {
      total: row?.total ?? 0,
      remaining: row?.remaining ?? 0,
      createdAt: (row?.total ?? 0) > 0 ? (row?.created_at ?? null) : null,
    }
  }

  async consumeRecoveryCode(userId: string, codeHash: string): Promise<boolean> {
    const res = await this.stmt(
      "UPDATE recovery_codes SET consumed_at = datetime('now') WHERE user_id = ? AND code_hash = ? AND consumed_at IS NULL",
      userId, codeHash,
    ).run()
    return (res.meta.changes ?? 0) > 0
  }

  async createMfaPending(input: { token: string; userId: string; amr: string[]; ttlMs: number }): Promise<void> {
    const expiresAt = new Date(Date.now() + input.ttlMs).toISOString()
    await this.stmt("DELETE FROM mfa_pending WHERE expires_at <= datetime('now')").run()
    await this.stmt(
      'INSERT INTO mfa_pending (token, user_id, amr, expires_at) VALUES (?, ?, ?, ?)',
      input.token, input.userId, JSON.stringify(input.amr), expiresAt,
    ).run()
  }

  async getMfaPending(token: string): Promise<MfaPending | null> {
    const row = await this.stmt('SELECT * FROM mfa_pending WHERE token = ?', token).first<Record<string, unknown>>()
    return row ? D1ServerStore.toMfaPending(row) : null
  }

  async consumeMfaPending(token: string): Promise<MfaPending | null> {
    const res = await this.stmt(
      "UPDATE mfa_pending SET consumed_at = datetime('now') WHERE token = ? AND consumed_at IS NULL", token,
    ).run()
    if ((res.meta.changes ?? 0) === 0) return null
    const row = await this.stmt('SELECT * FROM mfa_pending WHERE token = ?', token).first<Record<string, unknown>>()
    if (!row) return null
    if (new Date(row.expires_at as string).getTime() <= Date.now()) return null
    return D1ServerStore.toMfaPending(row)
  }

  async recordMfaPendingFailure(token: string): Promise<MfaPending | null> {
    const res = await this.stmt(
      "UPDATE mfa_pending SET fail_count = fail_count + 1, last_failure_at = datetime('now') WHERE token = ? AND consumed_at IS NULL",
      token,
    ).run()
    if ((res.meta.changes ?? 0) === 0) return null
    const row = await this.stmt('SELECT * FROM mfa_pending WHERE token = ?', token).first<Record<string, unknown>>()
    return row ? D1ServerStore.toMfaPending(row) : null
  }

  // ── the personal access tokens (TODO.identity-features/08) ─────────

  async createPersonalAccessToken(input: {
    id: string
    userId: string
    name: string
    tokenHash: string
    tokenPrefix: string
    scopes: string[]
    orgContext: string | null
    expiresAt: string
  }): Promise<PersonalAccessToken> {
    await this.ensurePersonalAccessTokenSupport()
    await this.stmt(
      `INSERT INTO personal_access_tokens
         (id, user_id, name, token_hash, token_prefix, scopes, org_context, expires_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      input.id, input.userId, input.name, input.tokenHash, input.tokenPrefix,
      JSON.stringify(input.scopes), input.orgContext, input.expiresAt,
    ).run()
    return (await this.getPersonalAccessToken(input.id))!
  }

  async listPersonalAccessTokens(userId: string): Promise<PersonalAccessToken[]> {
    await this.ensurePersonalAccessTokenSupport()
    // created_at is second-resolution (datetime('now')) — the rowid
    // breaks the tie so the newest mint leads even within one second.
    const res = await this.stmt(
      'SELECT * FROM personal_access_tokens WHERE user_id = ? ORDER BY created_at DESC, rowid DESC', userId,
    ).all<Record<string, unknown>>()
    return res.results.map(D1ServerStore.toPersonalAccessToken)
  }

  async listOrgPersonalAccessTokens(orgId: string): Promise<PersonalAccessToken[]> {
    await this.ensurePersonalAccessTokenSupport()
    // The org inventory: every token whose holder carries a membership
    // row for the org (ANY state — a disabled member's live token is
    // exactly what the oversight surface hunts). org_memberships arrived
    // with 0011, long before the PAT table — the join needs no ensure of
    // its own beyond the membership support's.
    await this.ensureMembershipSupport()
    const res = await this.stmt(
      `SELECT p.* FROM personal_access_tokens p
       JOIN org_memberships m ON m.user_id = p.user_id
       WHERE m.org_id = ?
       ORDER BY p.created_at DESC, p.id`,
      orgId,
    ).all<Record<string, unknown>>()
    return res.results.map(D1ServerStore.toPersonalAccessToken)
  }

  async getPersonalAccessToken(id: string): Promise<PersonalAccessToken | null> {
    await this.ensurePersonalAccessTokenSupport()
    const row = await this.stmt('SELECT * FROM personal_access_tokens WHERE id = ?', id).first<Record<string, unknown>>()
    return row ? D1ServerStore.toPersonalAccessToken(row) : null
  }

  async findPersonalAccessTokenByHash(tokenHash: string): Promise<PersonalAccessToken | null> {
    await this.ensurePersonalAccessTokenSupport()
    const row = await this.stmt('SELECT * FROM personal_access_tokens WHERE token_hash = ?', tokenHash).first<Record<string, unknown>>()
    return row ? D1ServerStore.toPersonalAccessToken(row) : null
  }

  async revokePersonalAccessToken(id: string, userId: string, revokedBy: string): Promise<boolean> {
    await this.ensurePersonalAccessTokenSupport()
    const res = await this.stmt(
      "UPDATE personal_access_tokens SET revoked_at = datetime('now'), revoked_by = ? WHERE id = ? AND user_id = ? AND revoked_at IS NULL",
      revokedBy, id, userId,
    ).run()
    return (res.meta.changes ?? 0) > 0
  }

  async stampPersonalAccessTokenUse(
    id: string,
    stamps: { usedAt: string; auditAt?: string | null; expiryNotifiedAt?: string | null },
  ): Promise<void> {
    await this.ensurePersonalAccessTokenSupport()
    await this.stmt('UPDATE personal_access_tokens SET last_used_at = ? WHERE id = ?', stamps.usedAt, id).run()
    if (stamps.auditAt) {
      await this.stmt('UPDATE personal_access_tokens SET last_exchange_audit_at = ? WHERE id = ?', stamps.auditAt, id).run()
    }
    if (stamps.expiryNotifiedAt) {
      await this.stmt('UPDATE personal_access_tokens SET expiry_notified_at = ? WHERE id = ?', stamps.expiryNotifiedAt, id).run()
    }
  }

  // ── organization administration (TODO.identity/10) ────────────────

  /** The store's time columns arrive in two shapes (datetime('now')'s
   *  naive UTC 'YYYY-MM-DD HH:MM:SS' from the DEFAULT writes, and the ISO
   *  strings the code paths write); the API answers ISO always —
   *  Date.parse would read the naive shape as LOCAL time and the routes'
   *  age math would misfire off-UTC. */
  private static storeTimeToIso(value: string | null): string | null {
    if (value === null) return null
    if (value.includes('T')) return value
    return value.replace(' ', 'T') + 'Z'
  }

  private static toWebauthnCredential(row: Record<string, unknown>): WebauthnCredential {
    return {
      credentialId: row.credential_id as string,
      userId: row.user_id as string,
      name: row.name as string,
      publicKeyCose: row.public_key as string,
      signCount: Number(row.sign_count ?? 0),
      aaguid: (row.aaguid as string | null) ?? null,
      transports: parseRoles((row.transports as string | null) ?? null) ?? [],
      createdAt: D1ServerStore.storeTimeToIso(row.created_at as string)!,
      lastUsedAt: D1ServerStore.storeTimeToIso((row.last_used_at as string | null) ?? null),
      lastIp: (row.last_ip as string | null) ?? null,
    }
  }

  private static toTotpSecret(row: Record<string, unknown>): TotpSecret {
    return {
      id: row.id as string,
      userId: row.user_id as string,
      name: row.name as string,
      secret: row.secret as string,
      failCount: Number(row.fail_count ?? 0),
      lastFailureAt: D1ServerStore.storeTimeToIso((row.last_failure_at as string | null) ?? null),
      createdAt: D1ServerStore.storeTimeToIso(row.created_at as string)!,
      verifiedAt: D1ServerStore.storeTimeToIso((row.verified_at as string | null) ?? null),
      lastUsedAt: D1ServerStore.storeTimeToIso((row.last_used_at as string | null) ?? null),
      lastIp: (row.last_ip as string | null) ?? null,
    }
  }

  private static toWebauthnChallenge(row: Record<string, unknown>): WebauthnChallenge {
    return {
      challenge: row.challenge as string,
      userId: (row.user_id as string | null) ?? null,
      kind: row.kind as WebauthnChallenge['kind'],
      createdAt: D1ServerStore.storeTimeToIso(row.created_at as string)!,
      expiresAt: D1ServerStore.storeTimeToIso(row.expires_at as string)!,
      consumedAt: D1ServerStore.storeTimeToIso((row.consumed_at as string | null) ?? null),
    }
  }

  private static toMfaPending(row: Record<string, unknown>): MfaPending {
    return {
      token: row.token as string,
      userId: row.user_id as string,
      amr: parseRoles((row.amr as string | null) ?? null) ?? [],
      failCount: Number(row.fail_count ?? 0),
      lastFailureAt: D1ServerStore.storeTimeToIso((row.last_failure_at as string | null) ?? null),
      createdAt: D1ServerStore.storeTimeToIso(row.created_at as string)!,
      expiresAt: D1ServerStore.storeTimeToIso(row.expires_at as string)!,
      consumedAt: D1ServerStore.storeTimeToIso((row.consumed_at as string | null) ?? null),
    }
  }

  /** The personal_access_tokens row → the seam's shape (TODO.identity-
   *  features/08). The scopes cell parses defensively — a hand-edited
   *  row's malformed JSON reads as the empty set, never trusted. */
  private static toPersonalAccessToken(row: Record<string, unknown>): PersonalAccessToken {
    return {
      id: row.id as string,
      userId: row.user_id as string,
      name: row.name as string,
      tokenHash: row.token_hash as string,
      tokenPrefix: row.token_prefix as string,
      scopes: parseRoles((row.scopes as string | null) ?? null) ?? [],
      orgContext: (row.org_context as string | null) ?? null,
      createdAt: D1ServerStore.storeTimeToIso(row.created_at as string)!,
      expiresAt: D1ServerStore.storeTimeToIso(row.expires_at as string)!,
      lastUsedAt: D1ServerStore.storeTimeToIso((row.last_used_at as string | null) ?? null),
      lastExchangeAuditAt: D1ServerStore.storeTimeToIso((row.last_exchange_audit_at as string | null) ?? null),
      expiryNotifiedAt: D1ServerStore.storeTimeToIso((row.expiry_notified_at as string | null) ?? null),
      revokedAt: D1ServerStore.storeTimeToIso((row.revoked_at as string | null) ?? null),
      revokedBy: (row.revoked_by as string | null) ?? null,
    }
  }

  private static toOrgJoinRequest(row: Record<string, unknown>): OrgJoinRequest {
    return {
      id: row.id as string,
      name: row.name as string,
      email: row.email as string,
      orgId: (row.org_id as string | null) ?? null,
      orgNameText: (row.org_name_text as string | null) ?? null,
      requestedRole: row.requested_role as string,
      note: (row.note as string | null) ?? null,
      status: row.status as OrgJoinRequest['status'],
      decidedBy: (row.decided_by as string | null) ?? null,
      decidedAt: (row.decided_at as string | null) ?? null,
      refusalReason: (row.refusal_reason as string | null) ?? null,
      invitedUserId: (row.invited_user_id as string | null) ?? null,
      createdAt: row.created_at as string,
    }
  }

  async createOrgJoinRequest(input: {
    name: string
    email: string
    orgId: string | null
    orgNameText: string | null
    requestedRole: string
    note?: string | null
  }): Promise<OrgJoinRequest> {
    const id = crypto.randomUUID()
    await this.stmt(
      `INSERT INTO org_join_requests (id, name, email, org_id, org_name_text, requested_role, note)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      id, input.name, input.email, input.orgId, input.orgNameText, input.requestedRole, input.note ?? null,
    ).run()
    return (await this.getOrgJoinRequest(id))!
  }

  async getOrgJoinRequest(id: string): Promise<OrgJoinRequest | null> {
    const row = await this.stmt('SELECT * FROM org_join_requests WHERE id = ?', id).first<Record<string, unknown>>()
    return row ? D1ServerStore.toOrgJoinRequest(row) : null
  }

  async listOrgJoinRequests(filter?: {
    scope?: 'org' | 'unregistered' | 'all'
    orgId?: string
    status?: OrgJoinRequest['status']
  }): Promise<OrgJoinRequest[]> {
    const scope = filter?.scope ?? 'all'
    const where: string[] = []
    const args: unknown[] = []
    if (scope === 'org') { where.push('org_id = ?'); args.push(filter?.orgId ?? '') }
    if (scope === 'unregistered') where.push('org_id IS NULL')
    if (filter?.status) { where.push('status = ?'); args.push(filter.status) }
    const sql = `SELECT * FROM org_join_requests${where.length ? ` WHERE ${where.join(' AND ')}` : ''} ORDER BY created_at`
    const res = await this.stmt(sql, ...args).all<Record<string, unknown>>()
    return res.results.map(D1ServerStore.toOrgJoinRequest)
  }

  /** The decision — atomic on 'pending' (a double decide loses honestly). */
  async decideOrgJoinRequest(
    id: string,
    decision: {
      status: 'approved' | 'refused'
      decidedBy: string
      refusalReason?: string | null
      invitedUserId?: string | null
    },
  ): Promise<OrgJoinRequest | null> {
    const res = await this.stmt(
      `UPDATE org_join_requests
       SET status = ?, decided_by = ?, decided_at = datetime('now'), refusal_reason = ?, invited_user_id = ?
       WHERE id = ? AND status = 'pending'`,
      decision.status, decision.decidedBy, decision.refusalReason ?? null, decision.invitedUserId ?? null, id,
    ).run()
    if ((res.meta.changes ?? 0) === 0) return null
    return this.getOrgJoinRequest(id)
  }

  async findPendingOrgJoinRequestByEmail(email: string): Promise<OrgJoinRequest | null> {
    const row = await this.stmt(
      "SELECT * FROM org_join_requests WHERE email = ? AND status = 'pending' ORDER BY created_at", email,
    ).first<Record<string, unknown>>()
    return row ? D1ServerStore.toOrgJoinRequest(row) : null
  }

  // ── organization memberships (TODO.identity/11 — the multi-org model) ──
  // The rows port directly (D1 is SQLite) — the same statements as the
  // SQLite store's membership section. THE DUAL-READ DOCTRINE: the users
  // row's org_id/roles columns stay the backward-compatible read (the
  // PRIMARY membership's mirror); the mirror rides every legacy writer.

  private static toOrgMembership(row: Record<string, unknown>): OrgMembership {
    let roles: string[] = []
    try {
      const parsed = JSON.parse(row.roles as string) as unknown
      if (Array.isArray(parsed)) roles = parsed.filter((v): v is string => typeof v === 'string')
    } catch { /* a malformed roles cell reads as the empty set */ }
    return {
      id: row.id as string,
      userId: row.user_id as string,
      orgId: row.org_id as string,
      roles,
      // The cone (TODO.identity-features/09): NULL parses to the
      // org-wide default — a pre-existing membership keeps its posture.
      cone: parseOrgMemberCone((row.cone as string | null) ?? null),
      state: row.state as OrgMembershipState,
      isPrimary: row.is_primary === 1,
      invitedBy: (row.invited_by as string | null) ?? null,
      createdAt: row.created_at as string,
      activatedAt: (row.activated_at as string | null) ?? null,
      disabledAt: (row.disabled_at as string | null) ?? null,
      disabledBy: (row.disabled_by as string | null) ?? null,
    }
  }

  /** THE MIRROR (the dual-read doctrine's write half): re-project the
   *  PRIMARY membership from the users row's legacy columns. A DISABLED
   *  row keeps its state (only roles + the primary mark move). */
  private async syncPrimaryMembership(userId: string): Promise<void> {
    await this.ensureMembershipSupport()
    const user = await this.stmt('SELECT id, role, roles, org_id FROM users WHERE id = ?', userId)
      .first<{ id: string; role: string; roles: string | null; org_id: string | null }>()
    if (!user || !user.org_id) return
    const roles = parseRoles(user.roles) ?? [user.role]
    await this.db.batch([
      this.stmt('UPDATE org_memberships SET is_primary = 0 WHERE user_id = ? AND org_id != ? AND is_primary = 1', userId, user.org_id),
      this.stmt(
        `INSERT INTO org_memberships (id, user_id, org_id, roles, state, is_primary, activated_at)
         VALUES (?, ?, ?, ?, 'active', 1, datetime('now'))
         ON CONFLICT (user_id, org_id) DO UPDATE SET roles = excluded.roles, is_primary = 1`,
        crypto.randomUUID(), userId, user.org_id, JSON.stringify(roles),
      ),
    ])
  }

  async listOrgMemberships(userId: string): Promise<OrgMembership[]> {
    await this.ensureMembershipSupport()
    const res = await this.stmt(
      'SELECT * FROM org_memberships WHERE user_id = ? ORDER BY is_primary DESC, created_at', userId,
    ).all<Record<string, unknown>>()
    return res.results.map(D1ServerStore.toOrgMembership)
  }

  async listOrgMembers(orgId: string): Promise<OrgMembership[]> {
    await this.ensureMembershipSupport()
    const res = await this.stmt(
      'SELECT * FROM org_memberships WHERE org_id = ? ORDER BY created_at', orgId,
    ).all<Record<string, unknown>>()
    return res.results.map(D1ServerStore.toOrgMembership)
  }

  async listAllOrgMemberships(): Promise<OrgMembership[]> {
    await this.ensureMembershipSupport()
    const res = await this.stmt(
      'SELECT * FROM org_memberships ORDER BY org_id, created_at',
    ).all<Record<string, unknown>>()
    return res.results.map(D1ServerStore.toOrgMembership)
  }

  async getOrgMembership(userId: string, orgId: string): Promise<OrgMembership | null> {
    await this.ensureMembershipSupport()
    const row = await this.stmt('SELECT * FROM org_memberships WHERE user_id = ? AND org_id = ?', userId, orgId)
      .first<Record<string, unknown>>()
    return row ? D1ServerStore.toOrgMembership(row) : null
  }

  /** Create the membership; NULL on the (user, org) conflict — the
   *  honest "already a member". */
  async createOrgMembership(input: {
    userId: string
    orgId: string
    roles: string[]
    state: OrgMembershipState
    invitedBy?: string | null
  }): Promise<OrgMembership | null> {
    await this.ensureMembershipSupport()
    const res = await this.stmt(
      `INSERT OR IGNORE INTO org_memberships (id, user_id, org_id, roles, state, invited_by, activated_at)
       VALUES (?, ?, ?, ?, ?, ?, CASE WHEN ? = 'active' THEN datetime('now') ELSE NULL END)`,
      crypto.randomUUID(), input.userId, input.orgId, JSON.stringify(input.roles), input.state,
      input.invitedBy ?? null, input.state,
    ).run()
    if ((res.meta.changes ?? 0) === 0) return null
    return this.getOrgMembership(input.userId, input.orgId)
  }

  /** Replace the per-org role set; the PRIMARY membership's write mirrors
   *  into the users row (the dual-write — the legacy read stays
   *  identical). */
  async setOrgMembershipRoles(userId: string, orgId: string, roles: string[]): Promise<boolean> {
    await this.ensureMembershipSupport()
    const res = await this.stmt('UPDATE org_memberships SET roles = ? WHERE user_id = ? AND org_id = ?',
      JSON.stringify(roles), userId, orgId).run()
    if ((res.meta.changes ?? 0) === 0) return false
    const membership = await this.getOrgMembership(userId, orgId)
    if (membership?.isPrimary) {
      const user = await this.stmt('SELECT role FROM users WHERE id = ?', userId).first<{ role: string }>()
      if (user) {
        const primaryRole = roles.includes(user.role) ? user.role : (roles[0] ?? user.role)
        await this.stmt('UPDATE users SET role = ?, roles = ? WHERE id = ?',
          primaryRole, JSON.stringify(roles.length ? roles : [primaryRole]), userId).run()
      }
    }
    return true
  }

  /** The lifecycle act (stamps; disabling also clears the account's
   *  sessions' active-org stamps pointing at the org). */
  async setOrgMembershipState(
    userId: string,
    orgId: string,
    state: OrgMembershipState,
    actor?: string | null,
  ): Promise<OrgMembership | null> {
    await this.ensureMembershipSupport()
    const existing = await this.getOrgMembership(userId, orgId)
    if (!existing) return null
    if (state === 'active') {
      await this.stmt(
        "UPDATE org_memberships SET state = 'active', activated_at = datetime('now'), disabled_at = NULL, disabled_by = NULL WHERE user_id = ? AND org_id = ?",
        userId, orgId,
      ).run()
    } else if (state === 'disabled') {
      await this.db.batch([
        this.stmt(
          "UPDATE org_memberships SET state = 'disabled', disabled_at = datetime('now'), disabled_by = ? WHERE user_id = ? AND org_id = ?",
          actor ?? null, userId, orgId,
        ),
        this.stmt('UPDATE sessions SET active_org = NULL WHERE user_id = ? AND active_org = ?', userId, orgId),
      ])
    } else {
      await this.stmt("UPDATE org_memberships SET state = 'invited' WHERE user_id = ? AND org_id = ?", userId, orgId).run()
    }
    return this.getOrgMembership(userId, orgId)
  }

  /** Set the membership's data cone (TODO.identity-features/09): the
   *  canonical spelling, or NULL for the org-wide default. */
  async setOrgMembershipCone(userId: string, orgId: string, cone: string | null): Promise<OrgMembership | null> {
    await this.ensureMembershipSupport()
    const existing = await this.getOrgMembership(userId, orgId)
    if (!existing) return null
    await this.stmt('UPDATE org_memberships SET cone = ? WHERE user_id = ? AND org_id = ?', cone, userId, orgId).run()
    return this.getOrgMembership(userId, orgId)
  }

  /** Remove the row (the declined invitation; the erasure's cleanup). */
  async deleteOrgMembership(userId: string, orgId: string): Promise<boolean> {
    await this.ensureMembershipSupport()
    const res = await this.stmt('DELETE FROM org_memberships WHERE user_id = ? AND org_id = ?', userId, orgId).run()
    if ((res.meta.changes ?? 0) > 0) {
      await this.stmt('UPDATE sessions SET active_org = NULL WHERE user_id = ? AND active_org = ?', userId, orgId).run()
    }
    return (res.meta.changes ?? 0) > 0
  }

  /** The session's stamped active-org context (NULL = the primary
   *  context; also NULL for an unknown/expired token). */
  async getSessionActiveOrg(token: string): Promise<string | null> {
    await this.ensureMembershipSupport()
    const row = await this.stmt("SELECT active_org FROM sessions WHERE token = ? AND expires_at > datetime('now')", token)
      .first<{ active_org: string | null }>()
    return row?.active_org ?? null
  }

  /** Stamp the session's active-org context; NULL clears to the primary
   *  context. */
  async setSessionActiveOrg(token: string, orgId: string | null): Promise<boolean> {
    await this.ensureMembershipSupport()
    const res = await this.stmt("UPDATE sessions SET active_org = ? WHERE token = ? AND expires_at > datetime('now')",
      orgId, token).run()
    return (res.meta.changes ?? 0) > 0
  }

  // ── the organization registry (TODO.identity-features/05) ──────────
  // The identity service's OWN org registry — the rows the membership
  // graph references by id. The lifecycle acts are the routes'; these
  // mirror the SQLite store's registry section one-for-one.

  private static toOrgRegistryOrg(row: Record<string, unknown>): OrgRegistryOrg {
    let contacts: OrgRegistryContact[] = []
    try {
      const parsed = JSON.parse((row.contacts as string) ?? '[]') as unknown
      if (Array.isArray(parsed)) {
        contacts = parsed
          .filter((e): e is Record<string, unknown> => !!e && typeof e === 'object')
          .map(e => ({ name: typeof e.name === 'string' && e.name.trim() ? e.name.trim() : null, email: typeof e.email === 'string' ? e.email.trim() : '' }))
          .filter(e => e.email.includes('@'))
      }
    } catch { /* a malformed contacts cell reads as the empty list */ }
    return {
      id: row.id as string,
      name: row.name as string,
      shortName: (row.short_name as string | null) ?? null,
      kind: (row.kind as string | null) ?? null,
      country: (row.country as string | null) ?? null,
      contacts,
      participantRef: (row.participant_ref as string | null) ?? null,
      designatedBy: (row.designated_by as string | null) ?? null,
      proposedBy: (row.proposed_by as string | null) ?? null,
      csStatus: (row.cs_status as string | null) ?? null,
      state: row.state as OrgRegistryState,
      createdAt: row.created_at as string,
      createdBy: (row.created_by as string | null) ?? null,
      updatedAt: (row.updated_at as string | null) ?? null,
      updatedBy: (row.updated_by as string | null) ?? null,
      disabledAt: (row.disabled_at as string | null) ?? null,
      disabledBy: (row.disabled_by as string | null) ?? null,
    }
  }

  async listOrgRegistryOrgs(): Promise<OrgRegistryOrg[]> {
    await this.ensureOrgRegistrySupport()
    const res = await this.stmt('SELECT * FROM org_registry').all<Record<string, unknown>>()
    return res.results.map(D1ServerStore.toOrgRegistryOrg).sort((a, b) => a.name.localeCompare(b.name))
  }

  async getOrgRegistryOrg(id: string): Promise<OrgRegistryOrg | null> {
    await this.ensureOrgRegistrySupport()
    const row = await this.stmt('SELECT * FROM org_registry WHERE id = ?', id).first<Record<string, unknown>>()
    return row ? D1ServerStore.toOrgRegistryOrg(row) : null
  }

  /** Add the organization; NULL on the id conflict (the slug is taken). */
  async createOrgRegistryOrg(input: {
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
  }): Promise<OrgRegistryOrg | null> {
    await this.ensureOrgRegistrySupport()
    const res = await this.stmt(
      `INSERT OR IGNORE INTO org_registry (id, name, short_name, kind, country, contacts, participant_ref, designated_by, proposed_by, cs_status, created_by)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      input.id, input.name, input.shortName ?? null, input.kind ?? null, input.country ?? null,
      JSON.stringify(input.contacts ?? []), input.participantRef ?? null,
      input.designatedBy ?? null, input.proposedBy ?? null, input.csStatus ?? null, input.createdBy ?? null,
    ).run()
    if ((res.meta.changes ?? 0) === 0) return null
    return this.getOrgRegistryOrg(input.id)
  }

  /** Edit the display data (the id never moves); stamps updated_at/by. */
  async updateOrgRegistryOrg(
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
  ): Promise<OrgRegistryOrg | null> {
    await this.ensureOrgRegistrySupport()
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
    const res = await this.stmt(`UPDATE org_registry SET ${sets.join(', ')} WHERE id = ?`, ...params, id).run()
    if ((res.meta.changes ?? 0) === 0) return null
    return this.getOrgRegistryOrg(id)
  }

  /** The lifecycle act (stamps; re-enable clears the disable stamps —
   *  the memberships stay as they are). */
  async setOrgRegistryOrgState(id: string, state: OrgRegistryState, actor?: string | null): Promise<OrgRegistryOrg | null> {
    await this.ensureOrgRegistrySupport()
    const existing = await this.getOrgRegistryOrg(id)
    if (!existing) return null
    if (state === 'disabled') {
      await this.stmt("UPDATE org_registry SET state = 'disabled', disabled_at = datetime('now'), disabled_by = ? WHERE id = ?",
        actor ?? null, id).run()
    } else {
      await this.stmt("UPDATE org_registry SET state = 'active', disabled_at = NULL, disabled_by = NULL WHERE id = ?",
        id).run()
    }
    return this.getOrgRegistryOrg(id)
  }

  /** The erasure-adjacent hard delete (the route guards it). */
  async deleteOrgRegistryOrg(id: string): Promise<boolean> {
    await this.ensureOrgRegistrySupport()
    const res = await this.stmt('DELETE FROM org_registry WHERE id = ?', id).run()
    return (res.meta.changes ?? 0) > 0
  }

  // ── the register's holder-org attribution (TODO.register/02) ────────

  private static toCertificateHolderOrg(row: Record<string, unknown>): CertificateHolderOrg {
    return {
      certificateId: row.certificate_id as string,
      orgId: row.org_id as string,
      orgName: row.org_name as string,
      source: row.source as CertificateHolderOrg['source'],
      attributedAt: row.attributed_at as string,
      attributedBy: (row.attributed_by as string | null) ?? null,
      claimId: (row.claim_id as string | null) ?? null,
    }
  }

  private static toCertificateHolderClaim(row: Record<string, unknown>): CertificateHolderClaim {
    return {
      id: row.id as string,
      certificateId: row.certificate_id as string,
      claimantOrgId: row.claimant_org_id as string,
      claimantOrgName: row.claimant_org_name as string,
      matchedHolderName: row.matched_holder_name as string,
      claimedBy: row.claimed_by as string,
      state: row.state as CertificateHolderClaim['state'],
      decidedBy: (row.decided_by as string | null) ?? null,
      decidedAt: (row.decided_at as string | null) ?? null,
      refusalReason: (row.refusal_reason as string | null) ?? null,
      createdAt: row.created_at as string,
    }
  }

  // ── the instrument register (TODO.register/03) ─────────────────────
  // The platform-side serial register — the rows the registration
  // interface's cones read (the route's; browser/server/routes/
  // registrations.ts). These mirror the SQLite store's register section
  // one-for-one.

  private static toInstrumentRegistration(row: Record<string, unknown>): InstrumentRegistration {
    let designations: Record<string, unknown> = {}
    try {
      const parsed = JSON.parse((row.designations as string) ?? '{}') as unknown
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) designations = parsed as Record<string, unknown>
    } catch { /* a malformed designations cell reads as the empty object, never trusted */ }
    return {
      id: row.id as string,
      certificateId: row.certificate_id as string,
      holderOrgId: row.holder_org_id as string,
      standardId: row.standard_id as string,
      serialNumber: row.serial_number as string,
      manufactureDate: (row.manufacture_date as string | null) ?? null,
      designations,
      scopeStatus: row.scope_status as InstrumentRegistrationScopeStatus,
      scopeDetail: (row.scope_detail as string | null) ?? null,
      lifecycle: row.lifecycle as InstrumentRegistrationLifecycle,
      registeredAt: row.registered_at as string,
      registeredBy: (row.registered_by as string | null) ?? null,
      updatedAt: (row.updated_at as string | null) ?? null,
      updatedBy: (row.updated_by as string | null) ?? null,
    }
  }

  // ── the workflow entity store + change journal ───────────────────

  async listEntities(store: string, options?: EntityListOptions): Promise<EntityRow[]> {
    // The ORDER BY is the seam's contract (the 0.2.3 pin): the answer
    // arrives in (org_id, rowid) order — the read's observable order
    // since migration 0001, when the planner walked
    // idx_entities_store_org. Migration 0023's expression index offered
    // a second store-prefixed walk and the unnamed order flipped to
    // insertion (the smart app's render-baseline red, oimlsmart/smart
    // PR #264) — a list read's order is a consumer-visible contract,
    // never the planner's pick.
    // options.orgId narrows the candidate set (the seam's EntityListOptions
    // — the portal-load audit's R3-fix3): the kept groups (NULL stamps,
    // then the named org) are the two lowest org_id buckets, so the
    // filtered ORDER BY is the unfiltered order's restriction to the
    // candidates — a gate-driven projection of either answer is
    // byte-identical.
    if (options?.orgId) {
      const res = await this.stmt(
        'SELECT store, id, org_id, data, updated_at FROM entities WHERE store = ? AND (org_id = ? OR org_id IS NULL) ORDER BY org_id, rowid',
        store, options.orgId,
      ).all<EntityRow>()
      return res.results
    }
    const res = await this.stmt(
      'SELECT store, id, org_id, data, updated_at FROM entities WHERE store = ? ORDER BY org_id, rowid', store,
    ).all<EntityRow>()
    return res.results
  }

  async getEntity(store: string, id: string): Promise<EntityRow | undefined> {
    const row = await this.stmt(
      'SELECT store, id, org_id, data, updated_at FROM entities WHERE store = ? AND id = ?', store, id,
    ).first<EntityRow>()
    return row ?? undefined
  }

  async putEntity(store: string, id: string, orgId: string | null, data: string): Promise<void> {
    // The upsert + its journal entry ride ONE batch — D1 batches are
    // all-or-nothing, the same atomicity the SQLite path gets from its
    // transaction.
    await this.db.batch([
      this.stmt(ENTITY_UPSERT_SQL, store, id, orgId, data),
      this.stmt(ENTITY_CHANGE_SQL, store, 'persist', id),
    ])
    emitJournalAppends([{ store, type: 'persist', id }])
  }

  async deleteEntity(store: string, id: string): Promise<boolean> {
    const res = await this.stmt('DELETE FROM entities WHERE store = ? AND id = ?', store, id).run()
    const gone = (res.meta.changes ?? 0) > 0
    if (gone) {
      await this.stmt('INSERT INTO entity_changes (store, type, id) VALUES (?, ?, ?)', store, 'remove', id).run()
      emitJournalAppends([{ store, type: 'remove', id }])
    }
    return gone
  }

  // ── the platform event store (TODO.notify/01) ─────────────────────
  // The event rows port directly (D1 is SQLite) — the same statements
  // as sqlite/events.ts's sync half.

  private static toPlatformEvent(row: Record<string, unknown>): PlatformEvent {
    return {
      seq: row.seq as number,
      id: row.id as string,
      domain: row.domain as string,
      entityId: row.entity_id as string,
      action: row.action as string,
      payload: row.payload as string,
      mentions: (row.mentions as string | null) ?? null,
      at: row.at as string,
    }
  }

  // ── the notification subscriptions store (TODO.notify/02) ─────────
  // The SAME statements as sqlite/notify.ts's sync half (D1 is SQLite).

  private static toNotifyRule(row: Record<string, unknown>): NotifyRule {
    return {
      id: row.id as string,
      userId: row.user_id as string,
      pattern: row.pattern as string,
      domain: row.domain as string,
      entityId: (row.entity_id as string | null) ?? null,
      action: (row.action as string | null) ?? null,
      mode: row.mode as NotifyRule['mode'],
      channelOverrides: (row.channel_overrides as string | null) ?? null,
      createdAt: row.created_at as string,
    }
  }

  private static toNotifyEntityMute(row: Record<string, unknown>): NotifyEntityMute {
    return {
      id: row.id as string,
      userId: row.user_id as string,
      domain: row.domain as string,
      entityId: row.entity_id as string,
      createdAt: row.created_at as string,
    }
  }

  private static toNotifyPreferences(row: Record<string, unknown>): NotifyPreferences {
    return {
      userId: row.user_id as string,
      channels: row.channels as string,
      updatedAt: row.updated_at as string,
    }
  }

  // ── the inbox state (TODO.notify/03) ──────────────────────────────
  // The SAME statements as sqlite/notify.ts's sync half (D1 is SQLite).

  private static toNotifyInboxState(row: Record<string, unknown>): NotifyInboxState {
    return {
      userId: row.user_id as string,
      eventId: row.event_id as string,
      readAt: (row.read_at as string | null) ?? null,
      doneAt: (row.done_at as string | null) ?? null,
      savedAt: (row.saved_at as string | null) ?? null,
      createdAt: row.created_at as string,
    }
  }

  // ── the email channel's delivery store (TODO.notify/04) ───────────
  // The SAME statements as sqlite/notify.ts's sync half (D1 is SQLite).
  // The defensive ensure mirrors the instrument_registrations posture:
  // a dev D1 migrated from before migration 0018 lacks the table.
  // (Memoized per (binding, chain) at module scope — the header note.)

  private ensureNotifyDeliverySupport(): Promise<void> {
    return ensured(this.binding, 'notifyDeliverySupport', async () => {
      await this.db.prepare(
        `CREATE TABLE IF NOT EXISTS notify_deliveries (
           id TEXT PRIMARY KEY,
           event_id TEXT NOT NULL,
           user_id TEXT NOT NULL,
           reason TEXT NOT NULL,
           email TEXT NOT NULL,
           email_status TEXT,
           email_at TEXT,
           created_at TEXT NOT NULL DEFAULT (datetime('now')),
           UNIQUE (event_id, user_id)
         )`,
      ).run()
      await this.db.prepare('CREATE INDEX IF NOT EXISTS idx_notify_deliveries_event ON notify_deliveries (event_id)').run()
      await this.db.prepare('CREATE INDEX IF NOT EXISTS idx_notify_deliveries_user ON notify_deliveries (user_id)').run()
      await this.db.prepare('CREATE INDEX IF NOT EXISTS idx_notify_deliveries_status ON notify_deliveries (email_status)').run()
    })
  }

  private static toNotifyDelivery(row: Record<string, unknown>): NotifyDelivery {
    return {
      id: row.id as string,
      eventId: row.event_id as string,
      userId: row.user_id as string,
      reason: row.reason as string,
      email: row.email as NotifyDelivery['email'],
      emailStatus: (row.email_status as NotifyDelivery['emailStatus']) ?? null,
      emailAt: (row.email_at as string | null) ?? null,
      createdAt: row.created_at as string,
    }
  }

  // ── provisioning / dev support ───────────────────────────────────

}

/** The worker entry's install: one store per binding, memoized (the
 *  store is a stateless facade over the binding — safe to share across
 *  the isolate's concurrent requests; under D1_REPLICA_READS the
 *  shared store carries the isolate's ONE session, the TODO.restructure/
 *  28-E discipline note). The opts — the write budget, the
 *  replica-reads flag — come from the FIRST resolution: the memoized
 *  store keeps them (the deployment's env is constant, so every
 *  request passes the same values; a changed posture needs a fresh
 *  binding/isolate). */
const byBinding = new WeakMap<D1Database, D1ServerStore>()

export function d1StoreFor(binding: D1Database, opts?: D1StoreOptions): D1ServerStore {
  let store = byBinding.get(binding)
  if (!store) {
    store = new D1ServerStore(binding, opts)
    byBinding.set(binding, store)
  }
  return store
}

// The seam's honest-unavailable error, re-exported where the consumer's
// route surface already imports the D1 half from.
export { StoreUnavailable }
