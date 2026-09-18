// ─────────────────────────────────────────────────────────────────────
// The TTL tables' expired-row sweep (the 2026-09-18 improvement wave,
// item 2 — retention part 2), proven in-process over the REAL SQLite
// store: the audit journal got its policy-driven purge (TODO 28-A);
// these tables carry TTL semantics of their own — an expired session,
// code, token, or one-time challenge is DEAD BY DEFINITION, and one
// that is never presented again (the common case: abandoned flows)
// otherwise lingers FOREVER. The sweep keeps every row count flat so
// every surface stays fast permanently.
//
// The set (schema-audited): sessions, oidc_authorizations, oidc_codes,
// oidc_access_tokens, oidc_refresh_tokens, enrollment_tokens,
// email_change_tokens, sso_states, webauthn_challenges, mfa_pending,
// personal_access_tokens. EXCLUDED deliberately: instrument_
// registrations — its expires_at is the CERTIFICATE's validity (a
// domain fact and history, never garbage), and oidc_keys (the
// rotation's at-the-time honesty keeps retired rows by design).
//
// The verb pages (rowid IN (SELECT ... LIMIT n)) — one bounded DELETE
// per table per call, the bounded-write budget's friend; the script
// loops to zero. instrument: direct better-sqlite3 on the same temp
// file (WAL) to age rows past/present — no doubles, real tables.
// ─────────────────────────────────────────────────────────────────────

import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import Database from 'better-sqlite3'

const TMP = mkdtempSync(join(tmpdir(), 'oiml-id-ttl-sweep-'))
const DB_PATH = join(TMP, 'test.db')
process.env.DATABASE_PATH = DB_PATH

let store: import('../../server/store').ServerStore
let db: Database.Database

beforeAll(async () => {
  const { installSqliteStore } = await import('../../server/store/sqlite')
  store = installSqliteStore()
  const profileMod = await import('../../server/profile')
  profileMod.installInstanceProfile(profileMod.parseInstanceProfile(`
identity:
  org_id: oimlsmart-id
  org_name: OIML SMART Identity
  role_codes: [identity]
roles: [identity]
branding: { name: OIML SMART Identity }
`))
  // A second real connection for aging rows (WAL): the store's install
  // already built the schema's end state (migrations.test.ts proves the
  // two DDL sources equivalent — re-applying the migrations' ALTERs
  // here would collide).
  db = new Database(DB_PATH)
}, 30_000)

afterAll(() => {
  db?.close()
  rmSync(TMP, { recursive: true, force: true })
  delete process.env.DATABASE_PATH
})

describe('purgeExpiredTtlRows — the TTL sweep verb', () => {
  it('deletes ONLY the expired rows, paged, across the TTL set', async () => {
    const holder = await store.createOpAccount({ email: 'ttl-holder@example.org', name: 'TTL Holder', role: 'viewer' })
    const past = '2020-01-01T00:00:00.000Z'
    const future = '2099-01-01T00:00:00.000Z'
    // Representative pairs across the set: a flow table, a one-time
    // table, and a PAT row (the mandatory-expiry class).
    const insert = db.prepare(
      'INSERT INTO sessions (id, user_id, token, created_at, expires_at) VALUES (?, ?, ?, ?, ?)')
    for (const [id, tok] of [['s-e1', 'tok-e1'], ['s-e2', 'tok-e2'], ['s-e3', 'tok-e3']] as const) {
      insert.run(id, holder!.id, tok, past, past)
    }
    insert.run('s-live', holder!.id, 'tok-l', past, future)
    db.prepare('INSERT INTO oidc_codes (code, client_id, user_id, redirect_uri, scope, nonce, code_challenge, auth_time, created_at, expires_at, consumed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)')
      .run('c-expired', 'cli', holder!.id, 'https://r', 'openid', 'n', 'ch', past, past, past)
    db.prepare('INSERT INTO oidc_codes (code, client_id, user_id, redirect_uri, scope, nonce, code_challenge, auth_time, created_at, expires_at, consumed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)')
      .run('c-live', 'cli', holder!.id, 'https://r', 'openid', 'n', 'ch', past, future, future)
    db.prepare('INSERT INTO personal_access_tokens (id, user_id, name, token_hash, token_prefix, created_at, expires_at, last_used_at) VALUES (?, ?, ?, ?, ?, ?, ?, NULL)')
      .run('p-expired', holder!.id, 'probe', 'h', 'pre', past, past)
    db.prepare('INSERT INTO personal_access_tokens (id, user_id, name, token_hash, token_prefix, created_at, expires_at, last_used_at) VALUES (?, ?, ?, ?, ?, ?, ?, NULL)')
      .run('p-live', holder!.id, 'probe', 'h2', 'pre', past, future)

    // The page bound is PER TABLE (one bounded DELETE each): with
    // three expired sessions and limit 2, sessions stops at 2 on the
    // first call — the rowid-IN paging proving itself.
    const first = await store.purgeExpiredTtlRows('2026-09-18T00:00:00.000Z', 2)
    expect(first.sessions).toBe(2)
    let sweep: Record<string, number>
    do {
      sweep = await store.purgeExpiredTtlRows('2026-09-18T00:00:00.000Z', 500)
    } while (Object.values(sweep).some(n => n > 0))

    expect(db.prepare('SELECT id FROM sessions').all()).toEqual([{ id: 's-live' }])
    expect(db.prepare('SELECT code FROM oidc_codes').all()).toEqual([{ code: 'c-live' }])
    expect(db.prepare('SELECT id FROM personal_access_tokens').all()).toEqual([{ id: 'p-live' }])
  })
})
