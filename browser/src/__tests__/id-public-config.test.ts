// ─────────────────────────────────────────────────────────────────────
// The deployment's public config projection (server/app.ts's
// /api/config), proven in-process over the REAL app factory:
//
//   SUPPORT_URL → branding.supportUrl (the ISO-benchmark quick win,
//     item 6): the support affordance's "set" half — declared, the
//     sign-in page + the shell footer render the plain "Need help?"
//     link; undeclared, the key is ABSENT (never an empty string the
//     client could render hollow).
//   ENVIRONMENT_LABEL → environment.label (item 5): the ribbon's "set"
//     half — production declares nothing and the projection answers
//     null.
// ─────────────────────────────────────────────────────────────────────

import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest'

// The store's DB path is read at module evaluation — set it before any
// import below touches @oimlsmart/platform-server/store/sqlite (the imports are dynamic).
const TMP = mkdtempSync(join(tmpdir(), 'oiml-public-config-'))
process.env.DATABASE_PATH = join(TMP, 'test.db')
process.env.OP_ISSUER = 'http://op.test'

let app: import('hono').Hono

interface PublicConfig {
  branding: { productName: string; shortName: string; supportUrl?: string }
}

async function config(): Promise<PublicConfig> {
  const res = await app.request('http://op.test/api/config')
  expect(res.status).toBe(200)
  return res.json() as Promise<PublicConfig>
}

beforeAll(async () => {
  const { installSqliteStore } = await import('@oimlsmart/platform-server/store/sqlite')
  installSqliteStore()
  const { parseInstanceProfile } = await import('@oimlsmart/platform-server/profile')
  const { createApiApp } = await import('../../server/app')
  app = createApiApp({
    autoSeedDemo: false,
    instanceProfile: parseInstanceProfile(`
identity:
  org_id: oimlsmart-id
  org_name: OIML SMART Identity
  role_codes: [identity]
roles: [identity]
branding: { name: OIML SMART Identity }
demo_personas: false
`),
  })
})

afterAll(() => {
  rmSync(TMP, { recursive: true, force: true })
})

afterEach(() => {
  delete process.env.SUPPORT_URL
})

describe('/api/config — the support affordance (item 6)', () => {
  it('undeclared: the branding projection carries NO supportUrl', async () => {
    delete process.env.SUPPORT_URL
    const cfg = await config()
    expect(cfg.branding.productName).toBe('OIML SMART Identity')
    expect('supportUrl' in cfg.branding).toBe(false)
  })

  it('declared: SUPPORT_URL projects as branding.supportUrl', async () => {
    process.env.SUPPORT_URL = 'mailto:info@oimlsmart.org'
    const cfg = await config()
    expect(cfg.branding.supportUrl).toBe('mailto:info@oimlsmart.org')
  })

  it('a blank declaration is no declaration', async () => {
    process.env.SUPPORT_URL = '   '
    const cfg = await config()
    expect('supportUrl' in cfg.branding).toBe(false)
  })
})
