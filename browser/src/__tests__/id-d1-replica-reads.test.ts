// ─────────────────────────────────────────────────────────────────────
// TODO.restructure/28-E's routing decisions, proven in-process: the
// D1 replica-reads posture (D1_REPLICA_READS=1) resolves ONE
// withSession('first-primary') session per store instance and rides
// every statement through it; the shipping default (unset) routes
// byte-identically through the raw binding. The local suites run
// SQLite only — what is HONESTLY provable here is the ROUTING (which
// surface served each statement) and the bookmark bookkeeping (a
// write through the session advances it; the read-after-write pair
// rides the same thread); actual replica serving is the D1 runtime's,
// which is exactly why the flag ships OFF and turns on preview-first
// (docs/deployment/identity-operations.md).
//
// The harness (the id-store-unavailable precedent): the REAL
// D1ServerStore over a better-sqlite3-backed D1 binding facade (the
// migration set applied, real statement semantics) whose
// withSession() answers REAL session objects — each a recording
// surface with an honest bookmark model (the docs' definition: the
// latest database version seen by the session's last query; writes
// bump the shared version, every query makes its session observe it).
// ─────────────────────────────────────────────────────────────────────

import { mkdtempSync, rmSync, readFileSync, readdirSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import Database from 'better-sqlite3'
import type { D1Database, D1PreparedStatement, D1Result } from '@cloudflare/workers-types'
import { D1ServerStore, d1ReplicaReadsEnabled, d1StoreFor } from '../../server/store/d1'
import { StoreUnavailable } from '../../server/store'

const TMP = mkdtempSync(join(tmpdir(), 'oiml-id-d1-replica-'))
const MIGRATIONS_DIR = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'migrations')

/** The test budget for the bounded-write leg (the unavailable suite's
 * posture: past any in-process write's honest latency, far under the
 * production 5 s). */
const BUDGET_MS = 60

const SQL_WRITE = /^\s*(?:INSERT|UPDATE|DELETE|REPLACE|CREATE|ALTER|DROP)/i

/** The shared version model: every executed write bumps it (the
 * primary's replication version); a session's bookmark is the version
 * its last query observed — the docs' bookmark definition, honestly
 * modeled on one SQLite file. */
interface StatementSurface {
  record(sql: string): void
}

class RecordingStatement {
  constructor(
    private readonly surface: StatementSurface,
    private readonly version: { n: number },
    private readonly hangWrites: () => boolean,
    private readonly db: Database.Database,
    readonly sql: string,
    private readonly params: unknown[],
  ) {}

  bind(...values: unknown[]): RecordingStatement {
    return new RecordingStatement(this.surface, this.version, this.hangWrites, this.db, this.sql, values)
  }

  private terminal<T>(kind: 'run' | 'all' | 'first'): Promise<T> {
    this.surface.record(this.sql)
    if (this.hangWrites() && SQL_WRITE.test(this.sql)) {
      return new Promise<T>(() => {}) // the path flap: no answer, ever
    }
    if (SQL_WRITE.test(this.sql)) this.version.n += 1
    if (kind === 'run') {
      const res = this.db.prepare(this.sql).run(...(this.params as never[]))
      return Promise.resolve({ results: [], success: true, meta: { changes: res.changes } } as T)
    }
    if (kind === 'all') {
      return Promise.resolve({ results: this.db.prepare(this.sql).all(...(this.params as never[])), success: true, meta: { changes: 0 } } as T)
    }
    return Promise.resolve((this.db.prepare(this.sql).get(...(this.params as never[])) ?? null) as T)
  }

  run(): Promise<D1Result> { return this.terminal<D1Result>('run') }
  all<T>(): Promise<D1Result<T>> { return this.terminal<D1Result<T>>('all') }
  first<T>(): Promise<T | null> { return this.terminal<T | null>('first') }
}

/** A REAL session surface over the same database: its statements
 * execute for real, its bookmark advances with the version its
 * queries observe. */
class RecordingSession implements StatementSurface {
  readonly statements: string[] = []
  readonly batchSizes: number[] = []
  private lastVersion: number | null = null

  constructor(
    private readonly owner: RecordingBinding,
    readonly constraint: string | undefined,
  ) {}

  record(sql: string): void {
    this.statements.push(sql)
    this.lastVersion = this.owner.version.n
  }

  prepare(sql: string): D1PreparedStatement {
    return new RecordingStatement(this, this.owner.version, () => this.owner.hangWrites, this.owner.db, sql, []) as unknown as D1PreparedStatement
  }

  async batch(statements: D1PreparedStatement[]): Promise<D1Result[]> {
    const results: D1Result[] = []
    for (const s of statements) results.push(await s.run())
    this.batchSizes.push(statements.length)
    return results
  }

  getBookmark(): string | null {
    return this.lastVersion === null ? null : String(this.lastVersion)
  }
}

class RecordingBinding implements StatementSurface {
  readonly statements: string[] = []
  readonly sessions: RecordingSession[] = []
  readonly version = { n: 0 }
  hangWrites = false

  constructor(readonly db: Database.Database) {}

  record(sql: string): void {
    this.statements.push(sql)
  }

  prepare(sql: string): D1PreparedStatement {
    return new RecordingStatement(this, this.version, () => this.hangWrites, this.db, sql, []) as unknown as D1PreparedStatement
  }

  async batch(statements: D1PreparedStatement[]): Promise<D1Result[]> {
    const results: D1Result[] = []
    for (const s of statements) results.push(await s.run())
    return results
  }

  withSession(constraint?: string): RecordingSession {
    const session = new RecordingSession(this, constraint)
    this.sessions.push(session)
    return session
  }
}

let db: Database.Database

beforeAll(() => {
  db = new Database(join(TMP, 'identity.db'))
  for (const file of readdirSync(MIGRATIONS_DIR).filter(f => f.endsWith('.sql')).sort()) {
    db.exec(readFileSync(join(MIGRATIONS_DIR, file), 'utf-8'))
  }
})

afterAll(() => {
  rmSync(TMP, { recursive: true, force: true })
})

describe('the D1 replica-reads routing (TODO.restructure/28-E)', () => {
  it('the shipping default is OFF: statements ride the raw binding, withSession never enters, the memo answers one store per binding', async () => {
    const binding = new RecordingBinding(db)
    const first = d1StoreFor(binding as unknown as D1Database)
    expect(d1StoreFor(binding as unknown as D1Database)).toBe(first)

    await first.listUsers()

    expect(binding.sessions).toHaveLength(0)
    expect(binding.statements.length).toBeGreaterThan(0)
  })

  it('the flag on: ONE first-primary session per store instance carries every statement — the ensure chains included, nothing binding-direct', async () => {
    const binding = new RecordingBinding(db)
    const store = d1StoreFor(binding as unknown as D1Database, { replicaReads: true })

    await store.listUsers()

    expect(binding.sessions).toHaveLength(1)
    expect(binding.sessions[0].constraint).toBe('first-primary')
    expect(binding.sessions[0].statements.length).toBeGreaterThan(0)
    expect(binding.statements).toHaveLength(0)
    // The memo posture is unchanged under the flag: the per-request
    // installs answer the same store, so the session is the isolate's one.
    expect(d1StoreFor(binding as unknown as D1Database, { replicaReads: true })).toBe(store)
    // A second INSTANCE over the same binding answers its own session —
    // the session is instance state, never a global.
    const other = new D1ServerStore(binding as unknown as D1Database, { replicaReads: true })
    await other.listDemoAccounts()
    expect(binding.sessions).toHaveLength(2)
  })

  it('a write through the session advances its bookmark; the read-after-write pair rides the same session and observes the write', async () => {
    const binding = new RecordingBinding(db)
    const store = d1StoreFor(binding as unknown as D1Database, { replicaReads: true })

    const created = await store.createOpAccount({ email: 'replica-rider@example.org', name: 'Replica Rider', role: 'viewer' })
    expect(created).not.toBeNull()
    const readBack = await store.findUserByEmail('replica-rider@example.org')
    expect(readBack?.id).toBe(created!.id)

    const session = binding.sessions[0]
    // The session's bookmark is the latest version — the INSERT rode the
    // session and the read-back observed it (read-my-own-writes).
    expect(session.getBookmark()).toBe(String(binding.version.n))

    // The bulk reads ride the session's BATCH, not the binding's.
    const counts = await store.countSignInMethodsBulk([created!.id])
    expect(counts.get(created!.id)).toEqual({ password: false, links: 0, passkeys: 0 })
    expect(session.batchSizes).toEqual([3])
    expect(binding.statements).toHaveLength(0)
  })

  it('the bounded-write discipline carries over session-routed writes (the outage posture is session-proof)', async () => {
    const binding = new RecordingBinding(db)
    const store = new D1ServerStore(binding as unknown as D1Database, { replicaReads: true, writeBudgetMs: BUDGET_MS })
    // Warm the memoized ensure chains with a healthy pass so the armed
    // leg's first write is the UPDATE itself.
    await store.listUsers()

    binding.hangWrites = true
    const started = Date.now()
    await expect(store.touchLastLogin('any-user')).rejects.toBeInstanceOf(StoreUnavailable)
    const elapsed = Date.now() - started
    binding.hangWrites = false

    expect(elapsed).toBeLessThan(5_000)
    // The hung write rode the SESSION (routing and bounding together).
    expect(binding.sessions[0].statements.some(sql => /^\s*UPDATE\s+users/i.test(sql))).toBe(true)
  })

  it('the env resolver: exactly D1_REPLICA_READS=1 enables; unset, empty, or any other value never does', () => {
    expect(d1ReplicaReadsEnabled({ D1_REPLICA_READS: '1' })).toBe(true)
    expect(d1ReplicaReadsEnabled({ D1_REPLICA_READS: ' 1 ' })).toBe(true)
    expect(d1ReplicaReadsEnabled()).toBe(false)
    expect(d1ReplicaReadsEnabled({})).toBe(false)
    expect(d1ReplicaReadsEnabled({ D1_REPLICA_READS: '' })).toBe(false)
    expect(d1ReplicaReadsEnabled({ D1_REPLICA_READS: '  ' })).toBe(false)
    expect(d1ReplicaReadsEnabled({ D1_REPLICA_READS: '0' })).toBe(false)
    expect(d1ReplicaReadsEnabled({ D1_REPLICA_READS: 'true' })).toBe(false)
    expect(d1ReplicaReadsEnabled({ D1_REPLICA_READS: 'yes' })).toBe(false)
  })
})
