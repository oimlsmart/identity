// ─────────────────────────────────────────────────────────────────────
// The D1 store's proof, restored. The unit suites run the SQLite half
// only (server/store/sqlite/) — the D1 half (server/store/d1.ts) rode
// with NO executed coverage since the extraction, which dropped the
// smart monorepo's d1-store.test.ts. The 2026-09-23 /op/authorize
// production outage is the proof this mattered: the JARM wave
// (migration 0032) added response_mode to the
// INSERT and dropped one bind argument on the D1 half only — every
// SQLite test stayed green while every consent-less sign-in 500'd with
// D1_ERROR: Wrong number of parameter bindings.
//
// Two honest layers, after the id-store-unavailable + id-d1-replica-
// reads precedent (the REAL D1ServerStore over a better-sqlite3-backed
// D1 binding facade — the binding CONTRACT prepare/bind/run/all/first/
// batch/exec with real statement semantics, the store's own SQL
// unmodified, the canonical migration set applied):
//
//   1. The runtime legs: the authorization/code/consent/token path —
//      the exact /op/authorize trace that failed in production — plus
//      the entity batch, every statement executed with its real bind
//      arity (better-sqlite3 refuses a mismatch; the facade's own
//      check names the SQL).
//
//   2. The static arity gate over d1.ts itself: EVERY this.stmt( call
//      site must carry placeholders == bind arguments. A site whose
//      SQL is built dynamically is admitted only through the declared
//      exception list below — a NEW dynamic site fails the gate until
//      it is declared with its reason (the endpoint-scaling budget
//      posture). This is the layer that catches the class without
//      executing anything: it would have failed on the outage's INSERT
//      the moment it was written.
// ─────────────────────────────────────────────────────────────────────

import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import { mkdtempSync, readFileSync, readdirSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import Database from 'better-sqlite3'
import type { D1Database, D1PreparedStatement, D1Result } from '@cloudflare/workers-types'
import { D1ServerStore } from '../../server/store/d1'

const TMP = mkdtempSync(join(tmpdir(), 'oiml-id-d1-store-'))
const MIGRATIONS_DIR = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'migrations')
const D1_SOURCE_PATH = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'server', 'store', 'd1.ts')

// ── The D1 binding facade over better-sqlite3 (test-only) ───────────
// The arity check is the facade's own contract: SQLite refuses a bind
// mismatch at execution, but the message names nothing — the facade
// fails FIRST, with the SQL and both counts (the production error was
// opaque; the regression must not be).

function countPlaceholders(sql: string): number {
  let n = 0
  let inSingle = false
  for (let i = 0; i < sql.length; i++) {
    const c = sql[i]
    if (inSingle) {
      if (c === `'`) inSingle = sql[i + 1] === `'` ? (i++, false) : false
      continue
    }
    if (c === `'`) inSingle = true
    else if (c === '?') n++
  }
  return n
}

class SqliteD1Statement {
  constructor(
    private readonly db: Database.Database,
    readonly sql: string,
    private readonly params: unknown[],
  ) {}

  private assertArity(): void {
    const expected = countPlaceholders(this.sql)
    if (this.params.length !== expected) {
      throw new Error(
        `D1 bind arity: ${expected} placeholder(s) vs ${this.params.length} bind argument(s) — ${this.sql.replace(/\s+/g, ' ').slice(0, 120)}`,
      )
    }
  }

  bind(...values: unknown[]): SqliteD1Statement {
    const bound = new SqliteD1Statement(this.db, this.sql, values)
    bound.assertArity()
    return bound
  }

  runSync(): D1Result {
    this.assertArity()
    const res = this.db.prepare(this.sql).run(...(this.params as never[]))
    return { results: [], success: true, meta: { changes: res.changes } } as unknown as D1Result
  }

  async run(): Promise<D1Result> {
    return this.runSync()
  }

  async all<T>(): Promise<D1Result<T>> {
    const rows = this.db.prepare(this.sql).all(...(this.params as never[])) as T[]
    return { results: rows, success: true, meta: { changes: 0 } } as unknown as D1Result<T>
  }

  async first<T>(colName?: string): Promise<T | null> {
    const row = this.db.prepare(this.sql).get(...(this.params as never[])) as Record<string, unknown> | undefined
    if (!row) return null
    return (colName ? row[colName] : row) as T
  }

  async raw<T>(): Promise<T[]> {
    return this.db.prepare(this.sql).raw().all(...(this.params as never[])) as T[]
  }
}

class SqliteD1 {
  private readonly db: Database.Database

  constructor(path: string) {
    this.db = new Database(path)
  }

  prepare(sql: string): D1PreparedStatement {
    return new SqliteD1Statement(this.db, sql, []) as unknown as D1PreparedStatement
  }

  async batch<T>(statements: D1PreparedStatement[]): Promise<D1Result<T>[]> {
    // D1 batches are all-or-nothing — the facade's transaction.
    const stmts = statements as unknown as SqliteD1Statement[]
    return this.db.transaction(() => stmts.map(s => s.runSync()))() as unknown as D1Result<T>[]
  }

  async exec(sql: string): Promise<{ count: number; duration: number }> {
    const start = Date.now()
    this.db.exec(sql)
    return { count: 0, duration: Date.now() - start }
  }

  withSession(): this {
    return this
  }

  close(): void {
    this.db.close()
  }
}

// ── The static arity gate (layer 2) ──────────────────────────────────
// A tolerant scanner over d1.ts: every this.stmt( call site, its SQL
// argument's placeholder count vs its bind-argument count. Dynamic SQL
// (template interpolation, a bare identifier, a spread bind list) is
// admitted ONLY through DECLARED_D1_DYNAMISM below — each entry names
// its reason, and a stale entry (the SQL text moved on) fails the gate
// like an undeclared one.

interface StmtSite {
  line: number
  placeholders: number
  bindArgs: number
  dynamic: boolean
  sqlHead: string
}

/** The declared dynamic-SQL sites (sqlHead prefix → the reason). The
 *  audit of 2026-09-23 walked all 246 sites; these were the dynamic
 *  shapes, each verified paired at its construction site. */
const DECLARED_D1_DYNAMISM: Record<string, string> = {
  'SELECT * FROM identity_approvals WHERE ${where}':
    'the approvalRow helper: the where string and its params arrive paired from the caller (no live callers; SQLite-half parity)',
  'SELECT * FROM identity_links WHERE user_id IN (${placeholders})':
    'the bulk IN-list: placeholders = userIds.length, bind args = ...userIds — built paired',
  'grouped(': 'the bulk sign-in-method count batch: the same generated IN list rides each member, built paired',
  'UPDATE users SET email = ?, email_verified_at =':
    "the interpolation is a literal ('datetime(now)' vs NULL), never a ? — the two ?s carry the two args",
  'sql': 'the org_join_requests filter builder: one ? per arg, pushed adjacently in the same block',
  'DELETE FROM ${table} WHERE rowid IN':
    'the TTL sweep: the table is the seam TTL_TABLES constant (never caller input); the two ?s carry the two args',
  "UPDATE org_registry SET ${sets.join(":
    'the registry patch builder: each set clause ? is pushed with its param, adjacently',
  'ENTITY_UPSERT_SQL':
    'the module const (putEntity/putEntities share it); its four ?s carry the four args — executed by the runtime legs',
  'ENTITY_CHANGE_SQL':
    'the module const (the journal entry); its three ?s carry the three args — executed by the runtime legs',
}

/** The placeholder count over a SOURCE expression: the ?s inside its
 *  JS string/template literal segments (never the code between them —
 *  a ternary ? inside a ${...} substitution is code, not a bind
 *  placeholder). */
function countPlaceholdersInJsLiteral(expr: string): number {
  let n = 0
  let i = 0
  while (i < expr.length) {
    const c = expr[i]
    if (c !== `'` && c !== '"' && c !== '`') { i++; continue }
    const q = c
    i++
    while (i < expr.length) {
      if (expr[i] === '\\') { i += 2; continue }
      if (expr[i] === q) { i++; break }
      if (q === '`' && expr[i] === '$' && expr[i + 1] === '{') {
        i += 2
        let d = 1
        while (i < expr.length && d > 0) {
          const s = expr[i]
          if (s === `'` || s === '"' || s === '`') { i = skipJsString(expr, i); continue }
          if (s === '{') d++
          else if (s === '}') d--
          i++
        }
        continue
      }
      if (expr[i] === '?') n++
      i++
    }
  }
  return n
}

function skipJsString(s: string, start: number): number {
  const q = s[start]
  let j = start + 1
  while (j < s.length) {
    if (s[j] === '\\') { j += 2; continue }
    if (s[j] === q) return j + 1
    j++
  }
  return j
}

function scanStmtSites(src: string): StmtSite[] {
  const sites: StmtSite[] = []
  const needle = 'this.stmt('
  let idx = 0
  while ((idx = src.indexOf(needle, idx)) !== -1) {
    const line = src.slice(0, idx).split('\n').length
    const open = idx + needle.length - 1
    const call = parseCallArgs(src, open)
    if (call) {
      const nonEmpty = call.filter(p => p.trim() !== '')
      const sqlExpr = nonEmpty[0]
      const dynamic = /\$\{/.test(sqlExpr) || !/['"`]/.test(sqlExpr)
      const placeholders = dynamic ? 0 : countPlaceholdersInJsLiteral(sqlExpr)
      sites.push({
        line,
        placeholders,
        bindArgs: nonEmpty.length - 1,
        dynamic,
        // The head for exception matching: the source expression with
        // its JS string delimiters stripped (the keys name the SQL, not
        // the syntax).
        sqlHead: sqlExpr.replace(/\s+/g, ' ').trim().replace(/^[`'"]+|[`'"]+$/g, '').slice(0, 80),
      })
    }
    idx += needle.length
  }
  return sites
}

/** The balanced argument list of a call: top-level comma splits,
 *  tracking nesting, string/template literals and comments. */
function parseCallArgs(src: string, openIdx: number): string[] | null {
  let i = openIdx + 1
  const stack: string[] = []
  const parts: string[] = []
  let partStart = i
  while (i < src.length) {
    const c = src[i]
    if (c === `'` || c === '"' || c === '`') { i = skipString(src, i); continue }
    if (c === '/' && (src[i + 1] === '/' || src[i + 1] === '*')) { i = skipComment(src, i); continue }
    if (c === '(' || c === '[' || c === '{') { stack.push(c); i++; continue }
    if (c === ')' && stack.length === 0) {
      parts.push(src.slice(partStart, i))
      return parts
    }
    if (c === ']' || c === '}') { stack.pop(); i++; continue }
    if (c === ',' && stack.length === 0) {
      parts.push(src.slice(partStart, i))
      partStart = i + 1
      i++
      continue
    }
    i++
  }
  return null

  function skipString(s: string, start: number): number {
    const q = s[start]
    let j = start + 1
    while (j < s.length) {
      if (s[j] === '\\') { j += 2; continue }
      if (s[j] === q) return j + 1
      if (q === '`' && s[j] === '$' && s[j + 1] === '{') {
        j += 2
        let d = 1
        while (j < s.length && d > 0) {
          if (s[j] === `'` || s[j] === '"' || s[j] === '`') { j = skipString(s, j); continue }
          if (s[j] === '{') d++
          else if (s[j] === '}') d--
          j++
        }
        continue
      }
      j++
    }
    return j
  }

  function skipComment(s: string, start: number): number {
    if (s[start + 1] === '/') {
      while (start < s.length && s[start] !== '\n') start++
      return start
    }
    start += 2
    while (start < s.length && !(s[start] === '*' && s[start + 1] === '/')) start++
    return start + 2
  }
}

// ── The shared fixture: the REAL D1ServerStore over the facade ──────

let d1: SqliteD1
let store: D1ServerStore
let user1Id: string

beforeAll(() => {
  d1 = new SqliteD1(join(TMP, 'identity.db'))
  for (const file of readdirSync(MIGRATIONS_DIR).filter(f => f.endsWith('.sql')).sort()) {
    d1.exec(readFileSync(join(MIGRATIONS_DIR, file), 'utf-8'))
  }
  store = new D1ServerStore(d1 as unknown as D1Database)
})

afterAll(() => {
  d1?.close()
  rmSync(TMP, { recursive: true, force: true })
})

describe('the D1 half — the /op/authorize incident regression (2026-09-23)', () => {
  it('the authorization row lands with every column it declares — the JARM response_mode round-trips (the outage leg)', async () => {
    await store.upsertOidcClient({
      clientId: 'oiml-smart-demo',
      name: 'the OIML SMART demo instance',
      secretHash: 'test-hash',
      redirectUris: ['https://demo.oimlsmart.org/callback'],
      claimsPolicy: null,
      createdBy: null,
    })
    // The authorizing account (the FKs on the consent/refresh rows are
    // real — the trace signs a real user in).
    const user = await store.provisionSsoUser({
      email: 'resident-1@example.org', name: 'the resident',
      provider: 'demo', providerAccountId: 'resident-1', role: 'viewer', orgId: null,
    })
    user1Id = user.id
    const auth = await store.createOidcAuthorization({
      id: 'auth-jarm-1',
      clientId: 'oiml-smart-demo',
      redirectUri: 'https://demo.oimlsmart.org/callback',
      scope: 'openid profile',
      state: 'st-1',
      nonce: 'n-1',
      codeChallenge: 'cc-1',
      userId: user1Id,
      responseMode: 'jwt',
      ttlMs: 600_000,
    })
    expect(auth.responseMode).toBe('jwt')
    const read = await store.getOidcAuthorization('auth-jarm-1')
    expect(read).not.toBeNull()
    expect(read!.responseMode).toBe('jwt')
    expect(read!.clientId).toBe('oiml-smart-demo')
    expect(read!.redirectUri).toBe('https://demo.oimlsmart.org/callback')
    expect(read!.scope).toBe('openid profile')
    expect(read!.state).toBe('st-1')
    expect(read!.nonce).toBe('n-1')
    expect(read!.codeChallenge).toBe('cc-1')
    expect(read!.userId).toBe(user1Id)
  })

  it('the pre-JARM shape: an absent responseMode stores NULL and the row still lands', async () => {
    const auth = await store.createOidcAuthorization({
      id: 'auth-plain-1',
      clientId: 'oiml-smart-demo',
      redirectUri: 'https://demo.oimlsmart.org/callback',
      scope: 'openid',
      state: 'st-2',
      nonce: null,
      codeChallenge: 'cc-2',
      userId: null,
      ttlMs: 600_000,
    })
    expect(auth.responseMode).toBeNull()
    expect((await store.getOidcAuthorization('auth-plain-1'))!.responseMode).toBeNull()
  })

  it('the consent-less sign-in trace end to end: authorize → decide → code → consume → access token', async () => {
    const decided = await store.decideOidcAuthorization('auth-jarm-1', { userId: user1Id, decision: 'allow' })
    expect(decided?.decision).toBe('allow')
    await store.createOidcCode({
      code: 'code-1',
      clientId: 'oiml-smart-demo',
      redirectUri: 'https://demo.oimlsmart.org/callback',
      scope: 'openid profile',
      nonce: 'n-1',
      codeChallenge: 'cc-1',
      userId: user1Id,
      ttlMs: 60_000,
    })
    const consumed = await store.consumeOidcCode('code-1')
    expect(consumed?.userId).toBe(user1Id)
    expect(consumed?.clientId).toBe('oiml-smart-demo')
    // The replay loses: consumed_at is set exactly once.
    expect(await store.consumeOidcCode('code-1')).toBeNull()
    await store.createOidcAccessToken({
      token: 'at-1',
      userId: user1Id,
      clientId: 'oiml-smart-demo',
      scope: 'openid profile',
      ttlMs: 3_600_000,
    })
    const at = await store.getOidcAccessToken('at-1')
    expect(at?.userId).toBe(user1Id)
    expect(at?.clientId).toBe('oiml-smart-demo')
  })

  it('the remembered consent grant: absent → recorded → covering → revoked (its INSERT rides the same proof)', async () => {
    expect(await store.getConsentGrant(user1Id, 'oiml-smart-demo', 'openid profile')).toBeNull()
    const grant = await store.recordConsentGrant({ userId: user1Id, clientId: 'oiml-smart-demo', scope: 'openid profile' })
    expect(await store.getConsentGrant(user1Id, 'oiml-smart-demo', 'openid profile')).not.toBeNull()
    expect(await store.revokeConsentGrant(grant.id, user1Id)).toBe(true)
    expect(await store.getConsentGrant(user1Id, 'oiml-smart-demo', 'openid profile')).toBeNull()
  })

  it('the refresh rotation: one-time consume, the replay answers reuse and kills the family', async () => {
    await store.createOidcRefreshToken({
      token: 'rt-1',
      userId: user1Id,
      clientId: 'oiml-smart-demo',
      scope: 'openid offline_access',
      familyId: 'fam-1',
      ttlMs: 86_400_000,
    })
    const first = await store.consumeOidcRefreshToken('rt-1')
    expect(first.kind).toBe('ok')
    const replay = await store.consumeOidcRefreshToken('rt-1')
    expect(replay.kind).toBe('reuse')
    expect(replay.kind === 'reuse' && replay.familyId).toBe('fam-1')
  })

  it('the entity batch (the module-const SQL): the upsert and its journal entry ride ONE batch', async () => {
    await store.putEntity('incident', 'ent-1', null, JSON.stringify({ hello: 'd1' }))
    const row = await store.getEntity('incident', 'ent-1')
    expect(JSON.parse(row!.data)).toEqual({ hello: 'd1' })
  })
})

describe('the D1 bind-arity gate — every this.stmt( site in d1.ts (static)', () => {
  it('placeholder count equals bind-argument count at every call site; every dynamic site is declared', () => {
    const src = readFileSync(D1_SOURCE_PATH, 'utf-8')
    const sites = scanStmtSites(src)
    expect(sites.length).toBeGreaterThan(200) // the scanner found the file, not a stub

    const failures: string[] = []
    const matchedExceptions = new Set<string>()
    for (const site of sites) {
      const declared = Object.entries(DECLARED_D1_DYNAMISM).find(([prefix]) => site.sqlHead.startsWith(prefix))
      if (declared) {
        matchedExceptions.add(declared[0])
        continue
      }
      if (site.dynamic) {
        failures.push(
          `line ${site.line}: UNDECLARED dynamic SQL — ${site.sqlHead} (declare it in DECLARED_D1_DYNAMISM with its reason)`,
        )
        continue
      }
      if (site.placeholders !== site.bindArgs) {
        failures.push(
          `line ${site.line}: ${site.placeholders} placeholder(s) vs ${site.bindArgs} bind argument(s) — ${site.sqlHead}`,
        )
      }
    }
    for (const prefix of Object.keys(DECLARED_D1_DYNAMISM)) {
      if (!matchedExceptions.has(prefix)) {
        failures.push(`the declared exception "${prefix}" matches no call site any more — retire or re-pin it`)
      }
    }
    expect(failures, failures.join('\n')).toEqual([])
  })
}
)
