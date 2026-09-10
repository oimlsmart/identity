// ─────────────────────────────────────────────────────────────────────
// The public join intake's rate bound (the 2026-09-07 security cone
// audit's F10.5, smart#297): POST /api/op/join-requests is ANONYMOUS
// and mints rows (join requests; manufacturer-registry orgs on the
// self-registration path), so it rides the OP rate limiter like the
// credential-bearing endpoints. Proven in-process over the REAL app
// factory (createApiApp) with a tiny declared capacity:
//   - the burst trips the honest 429 (Retry-After + retryAfterMs) and
//     audits the trip;
//   - inside the budget the request reaches the route (the 400 of the
//     empty submit, never a 429).
// ─────────────────────────────────────────────────────────────────────

import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

// The store's DB path is read at module evaluation — set it before any
// import below touches @oimlsmart/platform-server/store/sqlite (the imports are dynamic).
const TMP = mkdtempSync(join(tmpdir(), 'oiml-join-rate-'))
process.env.DATABASE_PATH = join(TMP, 'test.db')
process.env.OP_ISSUER = 'http://op.test'
process.env.OP_RATE_LIMIT_CAPACITY = '4'

let app: import('hono').Hono
let store: ReturnType<typeof import('../../server/store').getStore>

beforeAll(async () => {
  const { installSqliteStore } = await import('../../server/store/sqlite')
  store = installSqliteStore()
  const { parseInstanceProfile, installInstanceProfile } = await import('../../server/profile')
  const profile = parseInstanceProfile(`
identity:
  org_id: oimlsmart-id
  org_name: OIML SMART Identity
  role_codes: [identity]
roles: [identity]
branding: { name: OIML SMART Identity }
demo_personas: false
`)
  installInstanceProfile(profile)
  const { createApiApp } = await import('../../server/app')
  app = createApiApp({ autoSeedDemo: false, instanceProfile: profile })
})

afterAll(() => {
  rmSync(TMP, { recursive: true, force: true })
})

describe('the join intake rides the OP rate limiter (F10.5)', () => {
  it('the burst trips the honest 429 with the audit row; inside the budget the route answers', async () => {
    const submit = () => app.request('http://op.test/api/op/join-requests', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({}),
    })
    // Inside the budget: the limiter lets the request through and the
    // ROUTE answers (the empty submit's honest 400). (The app mounts the
    // base path AND its wildcard — Hono's `path/*` matches the base too,
    // the smart monorepo's own mounts practice the same pair — so each
    // request spends two tokens: 4 in the bucket, two submits through,
    // the third trips.)
    for (let i = 0; i < 2; i++) {
      const res = await submit()
      expect(res.status).toBe(400)
    }
    // The next submit crosses the declared bucket: 429 + Retry-After.
    const tripped = await submit()
    expect(tripped.status).toBe(429)
    expect(tripped.headers.get('retry-after')).toBeTruthy()
    const body = await tripped.json() as { retryAfterMs?: number }
    expect(typeof body.retryAfterMs).toBe('number')
    const trips = (await store.listEntities('auditEvents'))
      .map(row => JSON.parse(row.data) as { action: string; metadata?: { path?: string } })
      .filter(row => row.action === 'rate_limited' && row.metadata?.path === '/api/op/join-requests')
    expect(trips.length).toBe(1)
  })
})
