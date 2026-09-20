// ─────────────────────────────────────────────────────────────────────
// TODO.modern/14 — the RFC 9116 pointer: the disclosure contact, the
// yearly expiry, the languages — served at the well-known path.
// ─────────────────────────────────────────────────────────────────────

import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, beforeAll, expect, it } from 'vitest'

const TMP = mkdtempSync(join(tmpdir(), 'oiml-sectxt-'))
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

it('answers the RFC 9116 shape at the well-known path', async () => {
  const res = await app.request(`${ISSUER}/.well-known/security.txt`)
  expect(res.status).toBe(200)
  expect(res.headers.get('content-type')).toContain('text/plain')
  const body = await res.text()
  expect(body).toMatch(/^Contact: https:\/\/github\.com\/oimlsmart\/identity\/security\/advisories\/new$/m)
  expect(body).toMatch(/^Expires: \d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/m)
  expect(body).toMatch(/^Preferred-Languages: en, fr$/m)
  expect(body).toMatch(/^Canonical: /m)
})
