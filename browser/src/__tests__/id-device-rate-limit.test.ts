// ─────────────────────────────────────────────────────────────────────
// The device-grant surface rides the OP rate limiter (the 2026-09-25
// security pass): POST /op/device/authorization is ANONYMOUS and mints
// a ceremony row per call (a D1 write per answer — the join-intake
// F10.5 shape exactly), and the page API's user_code lookups are the
// brute-force window (40 bits of Crockford base32 — the limiter is the
// second layer, the repo's own doctrine for code-shaped surfaces).
// Proven in-process over the REAL app factory with a tiny declared
// capacity, the join-intake leg's shape.
// ─────────────────────────────────────────────────────────────────────

import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

const TMP = mkdtempSync(join(tmpdir(), 'oiml-device-rate-'))
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

describe('the device-grant surface rides the OP rate limiter', () => {
  it('the ceremony-create burst trips the honest 429; inside the budget the route answers', async () => {
    const ask = () => app.request('http://op.test/op/device/authorization', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ client_id: 'no-such-cli', scope: 'svc:read' }).toString(),
    })
    const codes: number[] = []
    for (let i = 0; i < 6; i++) codes.push((await ask()).status)
    // Inside the budget the ROUTE answers (the unknown client's 401);
    // past it, the honest 429.
    expect(codes.slice(0, 4).every(c => c === 401), `the first four answered ${codes.join(',')}`).toBe(true)
    expect(codes.slice(4).some(c => c === 429), `the burst tripped: ${codes.join(',')}`).toBe(true)
  })

  it('the page API\'s code lookups trip the 429 past the budget', async () => {
    const peek = () => app.request('http://op.test/api/op/device?user_code=AAAA-BBBB')
    const codes: number[] = []
    for (let i = 0; i < 6; i++) codes.push((await peek()).status)
    expect(codes.slice(4).some(c => c === 429), `the burst tripped: ${codes.join(',')}`).toBe(true)
  })
})
