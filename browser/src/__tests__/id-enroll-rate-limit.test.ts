// ─────────────────────────────────────────────────────────────────────
// The public setup endpoint's rate bound (2026-10-10): POST
// /api/op/enroll/:token is ANONYMOUS, judges a password policy, calls
// the HIBP corpus (an outbound HTTPS round trip per attempt), and
// writes credential rows — so it rides the OP rate limiter like every
// other credential-bearing surface. The token is 256-bit random (a
// brute force is hopeless) — the bound exists for the AMPLIFIER (the
// HIBP call) and the store's sake, not the guess. Proven in-process
// over the REAL app factory with a tiny declared capacity.
// ─────────────────────────────────────────────────────────────────────

import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

const TMP = mkdtempSync(join(tmpdir(), 'oiml-enroll-rate-'))
process.env.DATABASE_PATH = join(TMP, 'test.db')
process.env.OP_ISSUER = 'http://op.test'
process.env.OP_RATE_LIMIT_CAPACITY = '4'

let app: import('hono').Hono

beforeAll(async () => {
  const { installSqliteStore } = await import('../../server/store/sqlite')
  installSqliteStore()
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

describe('the setup endpoint rides the OP rate limiter', () => {
  it('the burst trips the honest 429; inside the budget the route answers', async () => {
    const probe = () => app.request('http://op.test/api/op/enroll/not-a-real-token', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ password: 'a probe, not a password' }),
    })
    // Inside the budget the limiter lets the request through and the
    // ROUTE answers (the unknown token's honest 410); the bucket drains
    // (one or two tokens per request, per the mount pair's match) and
    // the burst trips the honest 429.
    let tripped = false
    for (let i = 0; i < 12 && !tripped; i++) {
      const res = await probe()
      if (res.status === 429) {
        tripped = true
        expect(res.headers.get('retry-after')).toBeTruthy()
        const body = await res.json() as { retryAfterMs?: number }
        expect(typeof body.retryAfterMs).toBe('number')
      } else {
        expect(res.status).toBe(410)
      }
    }
    expect(tripped, 'the burst trips within the sweep').toBe(true)
  })
})
