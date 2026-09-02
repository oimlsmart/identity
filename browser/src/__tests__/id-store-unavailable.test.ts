// ─────────────────────────────────────────────────────────────────────
// The 2026-09-01 outage's consumer half, proven in-process: the kernel's
// bounded-write discipline (0.2.0 — a hung D1 write answers the typed
// StoreUnavailable in ~budget ms) reaches THIS service's route surface
// as the honest 503 — the store's temporary unavailability + the
// retryability named, never the bare 500, never the login page's
// infinite spinner of that night.
//
// The harness: the REAL createApiApp (the onError mapping lives there)
// over the REAL kernel D1ServerStore, whose binding is a
// better-sqlite3-backed D1 facade (the kernel's own migrations applied)
// with a hangWrites switch — an armed write's promise never settles
// (the cross-region path flap's exact shape: not an error, an absence
// of answer). The e2e stacks boot node + SQLite (the bound is D1-only),
// so this in-process leg — the real store, the real binding contract,
// the real route — is the honest harness for the hang; the browser
// legs never see a hang SQLite cannot produce.
// ─────────────────────────────────────────────────────────────────────

import { mkdtempSync, rmSync, readFileSync, readdirSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import Database from 'better-sqlite3'
import type { D1Database, D1PreparedStatement, D1Result } from '@cloudflare/workers-types'
import { hashPassword } from '../../server/auth/passwords'

const TMP = mkdtempSync(join(tmpdir(), 'oiml-id-store-unavailable-'))
const MIGRATIONS_DIR = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'node_modules', '@oimlsmart', 'platform-server', 'migrations')

/** The test budget: past any in-process write's honest latency, far
 *  under the production 5 s default. */
const BUDGET_MS = 60

// ── the hanging binding (the facade's OWN write classification) ──────

const FAKE_WRITE = /^\s*(?:INSERT|UPDATE|DELETE|REPLACE|CREATE|ALTER|DROP)/i

class HangableStatement {
  constructor(
    readonly facade: { hangWrites: boolean },
    readonly db: Database.Database,
    readonly sql: string,
    readonly params: unknown[],
  ) {}

  bind(...values: unknown[]): HangableStatement {
    return new HangableStatement(this.facade, this.db, this.sql, values)
  }

  private terminal<T>(kind: 'run' | 'all' | 'first'): Promise<T> {
    if (this.facade.hangWrites && FAKE_WRITE.test(this.sql)) {
      return new Promise<T>(() => {}) // the path flap: no answer, ever
    }
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

const facade = { hangWrites: false }
let app: import('hono').Hono

beforeAll(async () => {
  const db = new Database(join(TMP, 'identity.db'))
  for (const file of readdirSync(MIGRATIONS_DIR).filter(f => f.endsWith('.sql')).sort()) {
    db.exec(readFileSync(join(MIGRATIONS_DIR, file), 'utf-8'))
  }
  const binding = {
    prepare: (sql: string) => new HangableStatement(facade, db, sql, []) as unknown as D1PreparedStatement,
    batch: async (statements: D1PreparedStatement[]) => {
      const results: D1Result[] = []
      for (const s of statements) results.push(await s.run())
      return results
    },
  } as unknown as D1Database

  const { D1ServerStore } = await import('@oimlsmart/platform-server/store/d1')
  const { installStore } = await import('@oimlsmart/platform-server/store')
  const store = new D1ServerStore(binding, { writeBudgetMs: BUDGET_MS })
  installStore(store)
  const profileMod = await import('@oimlsmart/platform-server/profile')
  profileMod.installInstanceProfile(profileMod.parseInstanceProfile(`
identity:
  org_id: oimlsmart-id
  org_name: OIML SMART Identity
  role_codes: [identity]
roles: [identity]
branding: { name: OIML SMART Identity }
`))

  const { createApiApp } = await import('../../server/app')
  app = createApiApp({ autoSeedDemo: false })

  // The account (unarmed): the invite-free direct store seed.
  const account = await store.createOpAccount({ email: 'holder@example.org', name: 'The Holder', role: 'viewer' })
  await store.setPasswordHash(account!.id, await hashPassword('a correct horse battery staple'))
}, 60_000)

afterAll(() => {
  rmSync(TMP, { recursive: true, force: true })
})

function login(email = 'holder@example.org', password = 'a correct horse battery staple') {
  return app.request('/api/op/login', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password }),
  })
}

describe('the bounded-write outage posture (the 2026-09-01 lesson)', () => {
  it('a hung store write on the sign-in path answers the honest 503 in ~budget ms — never the spin', async () => {
    // Warm the memoized ensure chains with one healthy sign-in, so the
    // armed leg's first write is the sign-in's own (touchLastLogin).
    const warm = await login()
    expect(warm.status).toBe(200)

    facade.hangWrites = true
    const started = Date.now()
    const res = await login()
    const elapsed = Date.now() - started
    facade.hangWrites = false

    expect(res.status).toBe(503)
    expect(res.headers.get('retry-after')).toBe('5')
    const body = await res.json() as Record<string, unknown>
    expect(body.code).toBe('store_unavailable')
    expect(body.retryable).toBe(true)
    expect(body.error).toContain('briefly unavailable')
    expect(body.operation).toBe('UPDATE users')
    expect(body.budgetMs).toBe(BUDGET_MS)
    expect(body.writeMayHaveLanded).toBe(true)
    // A keyed UPDATE replays convergently — the surface says so.
    expect(body.retrySafe).toBe(true)
    // The honest answer arrived in ~the budget — seconds, never minutes.
    expect(elapsed).toBeLessThan(5_000)
  }, 30_000)

  it('the recovered store signs in again (the bound is a timeout, not a wedge)', async () => {
    const res = await login()
    expect(res.status).toBe(200)
    expect(res.headers.get('set-cookie')).toContain('oiml-session=')
  }, 30_000)

  it('a READ route sails through under the armed write hang (reads stay unbounded)', async () => {
    // Warm the provider registry's own chains first (a cold binding's
    // idempotent heals are writes — they honestly bound too).
    const warm = await app.request('/api/op/providers/public')
    expect(warm.status).toBe(200)
    facade.hangWrites = true
    const res = await app.request('/api/op/providers/public')
    facade.hangWrites = false
    expect(res.status).toBe(200)
  }, 30_000)

  it('the FAILURE path stays prompt + honest under the hang (the audit write is bounded and never blocks)', async () => {
    // The unknown account's refusal writes only the audit event — and
    // the audit is caught by design ("the audit never blocks the path").
    // The bounded timeout turns the hang into a logged line, and the
    // caller still gets the uniform 401 in ~the budget, not the spin.
    facade.hangWrites = true
    const started = Date.now()
    const res = await app.request('/api/op/login', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: 'nobody@example.org', password: 'wrong-password' }),
    })
    const elapsed = Date.now() - started
    facade.hangWrites = false
    expect(res.status).toBe(401)
    const body = await res.json() as { error?: string }
    expect(body.error).toBe('Invalid email or password')
    expect(elapsed).toBeLessThan(5_000)
  }, 30_000)
})
