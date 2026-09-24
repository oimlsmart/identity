// ─────────────────────────────────────────────────────────────────────
// The owner directive (no OIML SMART property is indexed): /robots.txt
// keeps the crawl OPEN — the noindex rides the meta tag on every page
// (and X-Robots-Tag on every answer), so a Disallow here would trap the
// stale index entries: a crawler that cannot fetch never sees the
// noindex. Allow everything, de-index by tag.
// ─────────────────────────────────────────────────────────────────────

import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, beforeAll, expect, it } from 'vitest'

const TMP = mkdtempSync(join(tmpdir(), 'oiml-robotstxt-'))
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

it('answers the crawl-open shape at /robots.txt', async () => {
  const res = await app.request(`${ISSUER}/robots.txt`)
  expect(res.status).toBe(200)
  expect(res.headers.get('content-type')).toContain('text/plain')
  const body = await res.text()
  expect(body).toMatch(/^# noindex rides the meta tag on every page — crawl stays open so the de-index propagates$/m)
  expect(body).toMatch(/^User-agent: \*$/m)
  expect(body).toMatch(/^Allow: \/$/m)
  expect(body).not.toMatch(/^Disallow:/m)
})
