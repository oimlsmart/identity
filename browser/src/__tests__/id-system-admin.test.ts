// ─────────────────────────────────────────────────────────────────────
// The SYSTEM-ADMIN role (the 2026-09-29 owner ruling): a named,
// grantable role whose holders hold FULL access to every organization
// and the operator consoles — the org-console refusal copy never
// appears for them, and they may grant the role onward through the
// identity system.
//
// Proven in-process over the REAL app factory + routers + a REAL temp
// SQLite store (the id-registry posture):
//   VOCAB      the role is in the assignable vocabulary; the
//              system-authority predicate admits it (and the plain
//              org_admin stays OUT);
//   CONSOLE    an operator-gated registry route answers 200 (never the
//              'administrator role required' 403);
//   WIDE       the org-admin console's own join-queue endpoint answers
//              the WIDE grant — the consoleGrant refusal cannot fire;
//   GRANT      the roles editor accepts the system-admin's assignment
//              of the role to another account (grantability).
// ─────────────────────────────────────────────────────────────────────
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

const TMP = mkdtempSync(join(tmpdir(), 'oiml-system-admin-'))
process.env.DATABASE_PATH = join(TMP, 'test.db')

const ISSUER = 'http://op.test'
process.env.OP_ISSUER = ISSUER

// The seeded cast: the system-admin holder + a plain target account.
process.env.OP_ACCOUNT_SEED = JSON.stringify([
  { email: 'sysadmin@oimlsmart.org', name: 'System Admin', role: 'system_admin', password: 'the system admin passphrase', emailVerified: true },
  { email: 'target@oimlsmart.org', name: 'Target Account', role: 'viewer', password: 'the target passphrase', emailVerified: true },
])

let app: import('hono').Hono
let cookie: string

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

  const res = await app.request(`${ISSUER}/api/op/login`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email: 'sysadmin@oimlsmart.org', password: 'the system admin passphrase' }),
  })
  expect(res.status).toBe(200)
  cookie = res.headers.get('set-cookie')!.split(';')[0]!
})

afterAll(() => {
  rmSync(TMP, { recursive: true, force: true })
  for (const key of ['DATABASE_PATH', 'OP_ISSUER', 'OP_ACCOUNT_SEED']) delete process.env[key]
})

describe('TODO.sota/02 — the org administrators\' console', () => {
  it('roleHome seats the org admin at THEIR console; the route exists in the OP route table', async () => {
    const { roleHome } = await import('../../server/vocab/roles')
    expect(roleHome('org_admin')).toBe('/op/admin/organization')
    const entrypoint = await import('../../src/astro/app-entrypoint')
    void entrypoint
    const { readFileSync } = await import('node:fs')
    const source = readFileSync(new URL('../../src/astro/app-entrypoint.ts', import.meta.url), 'utf8')
    expect(source).toContain("path: '/op/admin/organization'")
  })
})

describe('the SYSTEM-ADMIN role (the 2026-09-29 ruling)', () => {
  it('VOCAB: the role is assignable; the system-authority predicate admits it and keeps the org admin out', async () => {
    const { APP_ROLES, isSystemAuthority } = await import('../../server/vocab/roles')
    expect(APP_ROLES).toContain('system_admin')
    expect(isSystemAuthority('system_admin')).toBe(true)
    expect(isSystemAuthority('admin')).toBe(true)
    expect(isSystemAuthority('org_admin')).toBe(false)
    expect(isSystemAuthority('viewer')).toBe(false)
  })

  it('CONSOLE: the operator-gated registry route answers 200 for the system-admin (never the 403)', async () => {
    const res = await app.request(`${ISSUER}/api/op/registry/orgs`, { headers: { cookie } })
    expect(res.status).toBe(200)
  })

  it('WIDE: the org-admin console\'s join queue answers the WIDE grant (the consoleGrant refusal cannot fire)', async () => {
    const res = await app.request(`${ISSUER}/api/op/join-requests`, { headers: { cookie } })
    expect(res.status).toBe(200)
    const envelope = await res.json() as { grant: 'wide' | 'org' }
    expect(envelope.grant).toBe('wide')
  })

  it('GRANT: the system-admin assigns the role onward through the roles editor', async () => {
    const { getStore } = await import('../../server/store')
    const target = await getStore().findUserByEmail('target@oimlsmart.org')
    expect(target).toBeTruthy()
    const res = await app.request(`${ISSUER}/api/users/${target!.id}/roles`, {
      method: 'PUT', headers: { cookie, 'content-type': 'application/json' },
      body: JSON.stringify({ role: 'system_admin', roles: ['system_admin', 'viewer'] }),
    })
    expect(res.status, await res.text()).toBe(200)
  })
})
