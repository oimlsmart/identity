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
const MIGRATIONS_DIR = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'migrations')

/** The test budget: past any in-process write's honest latency, far
 *  under the production 5 s default. */
const BUDGET_MS = 60

// ── the hanging binding (the facade's OWN write classification) ──────

const FAKE_WRITE = /^\s*(?:INSERT|UPDATE|DELETE|REPLACE|CREATE|ALTER|DROP)/i

class HangableStatement {
  constructor(
    readonly facade: { hangWrites: boolean; hangSql: RegExp | null },
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
    if (this.facade.hangSql?.test(this.sql)) {
      return new Promise<T>(() => {}) // the selective flap (the seed arbiter's shape: ONE statement hangs, the rest run)
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

const facade = { hangWrites: false, hangSql: null as RegExp | null }
let d1Binding: import('@cloudflare/workers-types').D1Database | null = null
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
  d1Binding = binding

  const { D1ServerStore } = await import('../../server/store/d1')
  const { installStore } = await import('../../server/store')
  const store = new D1ServerStore(binding, { writeBudgetMs: BUDGET_MS })
  installStore(store)
  const profileMod = await import('../../server/profile')
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

describe("the bootstrap seed's read-back arbiter (the 2026-09-23 lesson)", () => {
  // The production trace: the bootstrap seed's `INSERT INTO oidc_clients`
  // rode a hung write-confirm; the seed wrapper re-ran the whole seed on
  // the next credential request and the login answered 503 — even though
  // the timed-out write may well have LANDED. The arbiter (routes/
  // op-seed-guard.ts): on a timed-out confirm, read the declared content
  // back and PROCEED when it is complete; rethrow only a genuinely
  // incomplete seed.
  const SEED_ACCOUNT = { email: 'seeded-admin@example.org', name: 'The Seeded Admin', role: 'admin' }
  const SEED_CLIENT = {
    client_id: 'seeded-rp',
    name: 'The Seeded RP',
    secret: 'seeded-secret',
    redirect_uris: ['https://rp.example.org/callback'],
    claims_policy: { claims: ['email'] },
  }
  let seedApp: import('hono').Hono

  beforeAll(async () => {
    process.env.OP_ACCOUNT_SEED = JSON.stringify([SEED_ACCOUNT])
    process.env.OP_CLIENT_SEED = JSON.stringify([SEED_CLIENT])
    // The content ALREADY LANDED (the timed-out confirm's premise): the
    // declared rows planted directly, the account with its password set
    // (so the seed's account step is reads only — no enrollment mint).
    const { installedStore } = await import('../../server/store')
    const store = installedStore()!
    const account = await store.createOpAccount({ email: SEED_ACCOUNT.email, name: SEED_ACCOUNT.name, role: SEED_ACCOUNT.role })
    await store.setPasswordHash(account!.id, await hashPassword('a correct horse battery staple'))
    await store.upsertOidcClient({
      clientId: SEED_CLIENT.client_id,
      name: SEED_CLIENT.name,
      secretHash: 'seeded',
      redirectUris: SEED_CLIENT.redirect_uris,
      claimsPolicy: null,
      createdBy: 'test',
    })
    // A FRESH app: the seed memo is per-app (the per-isolate posture) —
    // the shared app above already ran its seed on the earlier logins.
    const { createApiApp } = await import('../../server/app')
    seedApp = createApiApp({ autoSeedDemo: false })
  })

  afterAll(() => {
    delete process.env.OP_ACCOUNT_SEED
    delete process.env.OP_CLIENT_SEED
    facade.hangSql = null
  })

  function seedLogin() {
    return seedApp.request('/api/op/login', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: SEED_ACCOUNT.email, password: 'a correct horse battery staple' }),
    })
  }

  it('a LANDED registry never reaches the seed path — the login proceeds without the arbiter\'s stall (the #78 check-first posture)', async () => {
    // The content ALREADY LANDED (pre-planted above): since #78's fix
    // the fresh isolate's read-back check runs BEFORE the seed — the
    // declaration proves complete and the convergence is never started
    // inline, so the hanging upsert is never reached and the answer
    // pays no budget stall (the pre-fix posture paid BUDGET_MS here
    // for the arbiter; the check-first posture removed the inline seed
    // from this scenario entirely).
    facade.hangSql = /INSERT INTO oidc_clients/
    // The deterministic discriminator (a wall-clock ceiling against the
    // 60ms budget flaked on CI — the login's honest work can exceed it
    // on a loaded runner with no stall at all): re-install the SAME
    // binding under a 10-SECOND confirm budget. Pre-fix, the login
    // awaited the seed's hung upsert through that budget (the arbiter
    // ran at 10s); post-fix, the check proves the registry complete and
    // the answer never touches the seed path.
    const { D1ServerStore } = await import('../../server/store/d1')
    const { installStore, installedStore } = await import('../../server/store')
    const original = installedStore()!
    installStore(new D1ServerStore(d1Binding!, { writeBudgetMs: 10_000 }))
    const started = Date.now()
    const res = await seedLogin()
    const elapsed = Date.now() - started
    installStore(original)
    facade.hangSql = null
    expect(res.status).toBe(200)
    expect(res.headers.get('set-cookie')).toContain('oiml-session=')
    expect(elapsed, 'the check-first posture answers without the seed path (a 10s confirm budget would have surfaced any inline seed)').toBeLessThan(2_000)
  }, 30_000)

  it('the arbiter itself: a timed-out confirm PROCEEDS on a complete read-back, rethrows on an incomplete one', async () => {
    // The route can no longer reach the rescue arm with the hang
    // facade (check-first means a landed registry never seeds inline),
    // but the production condition it guards is real: a D1 write whose
    // CONFIRMATION times out after the statement was ACCEPTED (the
    // 2026-09-23 login-503 incident). The arbiter's own contract,
    // unit-covered directly.
    const { StoreUnavailable } = await import('../../server/store')
    const { seedWithReadBack } = await import('../../server/routes/op-seed-guard')
    const landed = seedWithReadBack(
      'unit rescue',
      async () => { throw new StoreUnavailable('UPDATE oidc_clients', 2000, true) },
      async () => true,
    )
    await expect(landed).resolves.toEqual([])
    const incomplete = seedWithReadBack(
      'unit rethrow',
      async () => { throw new StoreUnavailable('UPDATE oidc_clients', 2000, true) },
      async () => false,
    )
    await expect(incomplete).rejects.toBeInstanceOf(StoreUnavailable)
  })

  it('a genuinely incomplete seed keeps the honest 503 + the retry posture', async () => {
    // The declared account does NOT exist and its write hangs: the
    // read-back answers incomplete, the StoreUnavailable rethrows, the
    // route surface's 503 mapping stands (the wrapper clears its memo —
    // the next credential request retries).
    process.env.OP_ACCOUNT_SEED = JSON.stringify([{ email: 'missing@example.org', name: 'The Missing', role: 'admin' }])
    const { createApiApp } = await import('../../server/app')
    const freshApp = createApiApp({ autoSeedDemo: false })
    facade.hangSql = /INSERT INTO users/
    const started = Date.now()
    const res = await freshApp.request('/api/op/login', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: 'missing@example.org', password: 'whatever' }),
    })
    const elapsed = Date.now() - started
    facade.hangSql = null
    expect(res.status).toBe(503)
    const body = await res.json() as Record<string, unknown>
    expect(body.code).toBe('store_unavailable')
    expect(body.retryable).toBe(true)
    expect(elapsed).toBeGreaterThanOrEqual(BUDGET_MS)
  }, 30_000)
})
