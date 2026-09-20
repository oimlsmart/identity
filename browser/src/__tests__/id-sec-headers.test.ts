// ─────────────────────────────────────────────────────────────────────
// TODO.modern/13 — the transport/document hardening baseline: nosniff
// on every answer; HSTS + no-referrer + frame-ancestors 'none' on the
// HTML answers; the check_session_iframe's own frame-ancestors * wins
// by design (the RPs frame it — the RFC's protocol); the middleware
// NEVER overrides an existing header.
// ─────────────────────────────────────────────────────────────────────

import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

const TMP = mkdtempSync(join(tmpdir(), 'oiml-sec-headers-'))
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
})

afterAll(() => {
  rmSync(TMP, { recursive: true, force: true })
  delete process.env.DATABASE_PATH
  delete process.env.OP_ISSUER
})

describe('the API answers', () => {
  it('carry nosniff (and no frame policy — JSON is not framed)', async () => {
    const res = await app.request(`${ISSUER}/api/health`)
    expect(res.status).toBe(200)
    expect(res.headers.get('x-content-type-options')).toBe('nosniff')
    expect(res.headers.get('content-security-policy')).toBeNull()
  })
})

describe('the HTML answers', () => {
  it('carry HSTS + nosniff + no-referrer + frame-ancestors none', async () => {
    // The authorize refusal page — a plain HTML answer.
    const res = await app.request(`${ISSUER}/op/authorize?client_id=unknown`)
    expect(res.status).toBe(400)
    expect(res.headers.get('content-type')).toContain('text/html')
    expect(res.headers.get('strict-transport-security')).toBe('max-age=31536000')
    expect(res.headers.get('x-content-type-options')).toBe('nosniff')
    expect(res.headers.get('referrer-policy')).toBe('no-referrer')
    expect(res.headers.get('content-security-policy')).toBe("frame-ancestors 'none'; object-src 'none'; base-uri 'self'; form-action 'self'")
    expect(res.headers.get('cross-origin-opener-policy')).toBe('same-origin')
  })

  it("the session iframe own frame-ancestors * WINS (the RPs frame it by design)", async () => {
    const res = await app.request(`${ISSUER}/op/session/check?client_id=hub`)
    expect(res.status).toBe(200)
    expect(res.headers.get('content-security-policy')).toBe('frame-ancestors *')
  })
})
