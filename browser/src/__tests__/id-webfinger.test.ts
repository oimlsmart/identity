// ─────────────────────────────────────────────────────────────────────
// TODO.modern/18 — WebFinger (RFC 7033), the federation's discovery
// front door: an RP holding an email address discovers the issuer
// with zero configuration. The DOMAIN decides (never the mailbox —
// enumeration-safe by construction); a foreign domain's resource
// answers 404 (never a proxy, never an open resolver).
// ─────────────────────────────────────────────────────────────────────

import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

const TMP = mkdtempSync(join(tmpdir(), 'oiml-webfinger-'))
process.env.DATABASE_PATH = join(TMP, 'test.db')
const ISSUER = 'http://op.test'
process.env.OP_ISSUER = ISSUER

let app: import('hono').Hono

const wf = (resource: string) => app.request(`${ISSUER}/.well-known/webfinger?resource=${encodeURIComponent(resource)}`)

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

describe('the webfinger discovery', () => {
  it('answers the acct form with the issuer JRD (the domain decides — any local part)', async () => {
    const res = await wf('acct:anyone@op.test')
    expect(res.status).toBe(200)
    expect(res.headers.get('content-type')).toContain('application/jrd+json')
    const jrd = await res.json() as { subject: string; links: Array<{ rel: string; href: string }> }
    expect(jrd.subject).toBe('acct:anyone@op.test')
    expect(jrd.links).toContainEqual({ rel: 'http://openid.net/specs/connect/1.0/issuer', href: ISSUER })
  })

  it('the mailto form answers the same JRD', async () => {
    const res = await wf('mailto:someone@op.test')
    expect(res.status).toBe(200)
    const jrd = await res.json() as { subject: string }
    expect(jrd.subject).toBe('mailto:someone@op.test')
  })

  it('a FOREIGN domain answers 404 (never a proxy, never an open resolver)', async () => {
    const res = await wf('acct:someone@other.example')
    expect(res.status).toBe(404)
  })

  it('a malformed or absent resource answers 400/404 honestly', async () => {
    const absent = await app.request(`${ISSUER}/.well-known/webfinger`)
    expect(absent.status).toBe(400)
    const malformed = await wf('not-a-resource')
    expect(malformed.status).toBe(404)
  })
})
