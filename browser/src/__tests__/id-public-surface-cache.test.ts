// ─────────────────────────────────────────────────────────────────────
// The public OIDC surface's cache posture (the 2026-09-18 improvement
// wave, item 3), proven in-process over the REAL app factory: the
// discovery document and the JWKS answer are PUBLIC, deploy-stable,
// and fetched by every RP on every flow — Cache-Control lets
// Cloudflare's edge carry the repeat load instead of the Worker.
//
// The budget, honestly derived:
//   - discovery changes only on DEPLOYS — minutes of freshness are
//     nothing (max-age=300);
//   - JWKS changes only on the quarterly rotation, whose ceremony
//     keeps the predecessor key resolvable for the 24 h retirement
//     margin (access tokens 1 h + RP JWKS caches 1 h) — a 5-minute
//     max-age sits two orders of magnitude inside the safety margin;
//   - the org register feed is pinned in id-manufacturer-kind.test.ts
//     (public, max-age=300 — the same wave).
// The contract golden captures BODIES, not headers — this posture is
// additive to it.
// ─────────────────────────────────────────────────────────────────────

import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

const TMP = mkdtempSync(join(tmpdir(), 'oiml-id-surface-cache-'))
process.env.DATABASE_PATH = join(TMP, 'test.db')
const ISSUER = 'http://op.test'
process.env.OP_ISSUER = ISSUER

let app: import('hono').Hono

beforeAll(async () => {
  const { generateSuccessorPair } = await import('../../scripts/op-key-rotate')
  process.env.OP_SIGNING_KEY = (await generateSuccessorPair()).privateJwkJson

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
demo_personas: true
`))

  const { createApiApp } = await import('../../server/app')
  app = createApiApp({ autoSeedDemo: true, instanceProfile: profileMod.getInstanceProfile() })
}, 30_000)

afterAll(() => {
  rmSync(TMP, { recursive: true, force: true })
  delete process.env.OP_ISSUER
  delete process.env.OP_SIGNING_KEY
  delete process.env.DATABASE_PATH
})

describe('the public OIDC surface answers edge-cacheable', () => {
  it('the discovery document carries Cache-Control: public, max-age=300', async () => {
    const res = await app.request(`${ISSUER}/.well-known/openid-configuration`)
    expect(res.status).toBe(200)
    expect(res.headers.get('cache-control')).toBe('public, max-age=300')
  })

  it('the JWKS answer carries Cache-Control: public, max-age=300 (two orders inside the rotation margin)', async () => {
    const res = await app.request(`${ISSUER}/jwks.json`)
    expect(res.status).toBe(200)
    expect(res.headers.get('cache-control')).toBe('public, max-age=300')
  })

  it('the WebFinger JRD carries Cache-Control: public, max-age=300 (the federation front door — the answer is public scheme data keyed per resource URL)', async () => {
    const res = await app.request(`${ISSUER}/.well-known/webfinger?resource=${encodeURIComponent('acct:anyone@op.test')}`)
    expect(res.status).toBe(200)
    expect(res.headers.get('cache-control')).toBe('public, max-age=300')
    // The 404 half caches too — a foreign domain's refusal is as
    // deterministic as the answer (never a proxy, never an open
    // resolver; the domain decides).
    const miss = await app.request(`${ISSUER}/.well-known/webfinger?resource=${encodeURIComponent('acct:x@other.example')}`)
    expect(miss.status).toBe(404)
    expect(miss.headers.get('cache-control')).toBe('public, max-age=300')
  })

  it('the security.txt record carries Cache-Control: public, max-age=300 (static text, deploy-stable)', async () => {
    const res = await app.request(`${ISSUER}/.well-known/security.txt`)
    expect(res.status).toBe(200)
    expect(res.headers.get('cache-control')).toBe('public, max-age=300')
  })
})
