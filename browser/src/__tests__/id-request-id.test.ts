// ─────────────────────────────────────────────────────────────────────
// TODO.modern/09 — the request-id seam, in-process against the REAL
// app factory: every answer carries X-Request-Id (generated, or an
// inbound well-formed one honored); a malformed inbound never echoes;
// the typed store-outage answer names the id (support conversations
// reference it). The REAL app, the REAL onError.
// ─────────────────────────────────────────────────────────────────────

import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

const TMP = mkdtempSync(join(tmpdir(), 'oiml-request-id-'))
process.env.DATABASE_PATH = join(TMP, 'test.db')
const ISSUER = 'http://op.test'
process.env.OP_ISSUER = ISSUER

let app: import('hono').Hono

beforeAll(async () => {
  const { installSqliteStore } = await import('../../server/store/sqlite')
  installSqliteStore()
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
  app = createApiApp({ autoSeedDemo: false, instanceProfile: profileMod.getInstanceProfile() })

  // The outage simulator: a real typed StoreUnavailable thrown INSIDE
  // the real stack (the middleware runs before the 404 fallthrough).
  const { StoreUnavailable } = await import('../../server/store')
  app.use('/__outage', async () => {
    throw new StoreUnavailable('test.outage', 2_000, false)
  })
})

afterAll(() => {
  rmSync(TMP, { recursive: true, force: true })
  delete process.env.DATABASE_PATH
  delete process.env.OP_ISSUER
})

describe('the X-Request-Id seam', () => {
  it('every answer carries a generated id (32 hex)', async () => {
    const res = await app.request(`${ISSUER}/api/health`)
    expect(res.status).toBe(200)
    const id = res.headers.get('x-request-id')
    expect(id).toMatch(/^[0-9a-f]{32}$/)
  })

  it('honors a well-formed inbound id; answers differ per request', async () => {
    const first = await app.request(`${ISSUER}/api/health`, { headers: { 'x-request-id': 'trace-abc-123' } })
    expect(first.headers.get('x-request-id')).toBe('trace-abc-123')
    const second = await app.request(`${ISSUER}/api/health`)
    expect(second.headers.get('x-request-id')).not.toBe(first.headers.get('x-request-id'))
  })

  it('a malformed inbound id never echoes (sanitized away)', async () => {
    for (const evil of ['<script>alert(1)</script>', 'x'.repeat(200), 'id with spaces']) {
      const res = await app.request(`${ISSUER}/api/health`, { headers: { 'x-request-id': evil } })
      const echoed = res.headers.get('x-request-id')
      expect(echoed, `never echoes ${evil}`).not.toBe(evil)
      expect(echoed).toMatch(/^[0-9a-f]{32}$/)
    }
  })

  it('the outage answer names the id in the body AND the header', async () => {
    const res = await app.request(`${ISSUER}/__outage`, { headers: { 'x-request-id': 'support-ref-42' } })
    expect(res.status).toBe(503)
    expect(res.headers.get('x-request-id')).toBe('support-ref-42')
    const body = await res.json() as { request_id?: string; code?: string }
    expect(body.code).toBe('store_unavailable')
    expect(body.request_id).toBe('support-ref-42')
  })
})
