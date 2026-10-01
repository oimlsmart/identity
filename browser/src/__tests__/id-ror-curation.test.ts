// ─────────────────────────────────────────────────────────────────────
// TODO.sota/05 — the ROR curation loop: the registry rows' ROR ids are
// WRITABLE (the seam patch, the registry API's ror_id field) and the
// vendored artifact's enrichment can be swept onto the EXISTING rows
// (the backfill planner — the domain-id join first, the iso+name join
// second; the operator's plan is printed, never applied blind).
// ─────────────────────────────────────────────────────────────────────
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

const TMP = mkdtempSync(join(tmpdir(), 'oiml-ror-'))
process.env.DATABASE_PATH = join(TMP, 'test.db')
const ISSUER = 'http://op.test'
process.env.OP_ISSUER = ISSUER
const PROFILE = join(TMP, 'profile.yaml')
writeFileSync(PROFILE, `name: ror-curation
roles: [identity]
branding: { name: ROR Curation }
demo_personas: true
`)
process.env.INSTANCE_PROFILE = PROFILE

let store: ReturnType<typeof import('../../server/store').getStore>
let app: import('hono').Hono

async function demoLogin(email: string): Promise<string> {
  const res = await app.request('/api/auth/demo', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password: 'demo2026' }),
  })
  expect(res.ok, `demo login ${email}`).toBe(true)
  return res.headers.get('set-cookie')!.split(';')[0]!
}

beforeAll(async () => {
  const { installSqliteStore } = await import('../../server/store/sqlite')
  store = installSqliteStore()
  const profileMod = await import('../../server/profile')
  profileMod.installInstanceProfile(profileMod.parseInstanceProfile(`
identity:
  org_id: oimlsmart-id
  org_name: ROR Curation
  role_codes: [identity]
roles: [identity]
branding: { name: ROR Curation }
demo_personas: true
`))
  const { Hono } = await import('hono')
  const { createAuthLeanRouter } = await import('../../server/routes/auth-lean')
  const { createOpRegistryRouter } = await import('../../server/routes/op-registry')
  const root = new Hono()
  root.route('/api/auth', createAuthLeanRouter({ autoSeedDemo: true }))
  root.route('/', createOpRegistryRouter())
  app = root
  await demoLogin('admin@oimlsmart.org')
}, 30_000)

afterAll(async () => {
  rmSync(TMP, { recursive: true, force: true })
  delete process.env.OP_ISSUER
  delete process.env.DATABASE_PATH
  delete process.env.INSTANCE_PROFILE
  const profileMod = await import('../../server/profile')
  profileMod.resetInstanceProfileForTest()
})

describe('the seam — the registry row\'s rorId is writable', () => {
  it('create carries it; update sets it; null clears it; the read back is honest', async () => {
    const created = await store.createOrgRegistryOrg({
      id: 'nist.gov', name: 'National Institute of Standards and Technology (NIST)',
      country: 'United States', rorId: 'https://ror.org/05xpvk416', createdBy: 'test',
    })
    expect(created?.rorId).toBe('https://ror.org/05xpvk416')

    const corrected = await store.updateOrgRegistryOrg('nist.gov', { rorId: 'https://ror.org/05xpvk416x' }, 'test')
    expect(corrected?.rorId).toBe('https://ror.org/05xpvk416x')

    const cleared = await store.updateOrgRegistryOrg('nist.gov', { rorId: null }, 'test')
    expect(cleared?.rorId).toBeNull()

    const set = await store.updateOrgRegistryOrg('nist.gov', { rorId: 'https://ror.org/05xpvk416' }, 'test')
    expect(set?.rorId).toBe('https://ror.org/05xpvk416')
  })
})

describe('the registry API — the org edit act carries ror_id', () => {
  it('a valid id sets it; a malformed id refuses loudly; null clears', async () => {
    await store.createOrgRegistryOrg({ id: 'abnorm.bf', name: 'ABNORM', country: 'Burkina Faso', createdBy: 'test' })
    const admin = await demoLogin('admin@oimlsmart.org')

    const set = await app.request('/api/op/registry/orgs/abnorm.bf', {
      method: 'PUT',
      headers: { 'content-type': 'application/json', cookie: admin },
      body: JSON.stringify({ ror_id: 'https://ror.org/01akz7g58' }),
    })
    expect(set.status).toBe(200)
    expect(((await set.json()) as { rorId: string | null }).rorId).toBe('https://ror.org/01akz7g58')

    const malformed = await app.request('/api/op/registry/orgs/abnorm.bf', {
      method: 'PUT',
      headers: { 'content-type': 'application/json', cookie: admin },
      body: JSON.stringify({ ror_id: '05xpvk416' }),
    })
    expect(malformed.status).toBe(400)

    const cleared = await app.request('/api/op/registry/orgs/abnorm.bf', {
      method: 'PUT',
      headers: { 'content-type': 'application/json', cookie: admin },
      body: JSON.stringify({ ror_id: null }),
    })
    expect(cleared.status).toBe(200)
    expect(((await cleared.json()) as { rorId: string | null }).rorId).toBeNull()
  })
})

describe('the backfill planner — the artifact\'s enrichment reaches the EXISTING rows', () => {
  const catalog = {
    version: 2,
    matchingRule: 'test',
    generatedAt: '2026-09-30T00:00:00Z',
    domains: new Map([
      ['nist.gov', { country: 'United States', country_fr: 'États-Unis', iso: 'US', status: 'member-state', org: 'National Institute of Standards and Technology (NIST)', roles: ['ciml-member'], verification: 'inferred', evidence: '' }],
    ]),
    countries: [
      {
        country: 'Burkina Faso', country_fr: 'Burkina Faso', iso: 'BF', status: 'corresponding-member',
        orgs: [{ name: 'ABNORM', roles: ['representative'], domains: [], website_domains: [], web_domains: [], ror_id: 'https://ror.org/01abnorm22', verification: 'inferred', admin_queue: false }],
      },
      {
        country: 'United States', country_fr: 'États-Unis', iso: 'US', status: 'member-state',
        orgs: [{ name: 'National Institute of Standards and Technology (NIST)', roles: ['ciml-member'], domains: [], website_domains: [], web_domains: [], ror_id: 'https://ror.org/05xpvk416', verification: 'inferred', admin_queue: false }],
      },
    ],
    rorByOrg: new Map([
      ['BF|ABNORM', 'https://ror.org/01abnorm22'],
      ['US|National Institute of Standards and Technology (NIST)', 'https://ror.org/05xpvk416'],
    ]),
  } as unknown as import('../../server/auth/op/member-domains').DomainsCatalog

  it('the domain-id join plans the update; a matched equal row is unchanged; unmatched rows are reported', async () => {
    const { planRorBackfill } = await import('../../server/ror-backfill')
    const plan = planRorBackfill([
      { id: 'nist.gov', name: 'National Institute of Standards and Technology (NIST)', country: 'United States', rorId: null },
      { id: 'some-slug', name: 'ABNORM', country: 'Burkina Faso', rorId: null },
      { id: 'nist.gov2', name: 'National Institute of Standards and Technology (NIST)', country: 'United States', rorId: 'https://ror.org/05xpvk416' },
      { id: 'unknown.example', name: 'No Such Org', country: 'Nowhere', rorId: null },
    ], catalog)
    expect(plan.actions).toEqual([
      { id: 'nist.gov', name: 'National Institute of Standards and Technology (NIST)', from: null, to: 'https://ror.org/05xpvk416', basis: 'domain-id' },
      { id: 'some-slug', name: 'ABNORM', from: null, to: 'https://ror.org/01abnorm22', basis: 'iso-name' },
    ])
    expect(plan.unchanged).toBe(1)
    expect(plan.unmatched).toEqual(['unknown.example'])
  })

  it('a drifted id is corrected (the artifact is the source of truth)', async () => {
    const { planRorBackfill } = await import('../../server/ror-backfill')
    const plan = planRorBackfill([
      { id: 'nist.gov', name: 'National Institute of Standards and Technology (NIST)', country: 'United States', rorId: 'https://ror.org/old-wrong1' },
    ], catalog)
    expect(plan.actions).toEqual([
      { id: 'nist.gov', name: 'National Institute of Standards and Technology (NIST)', from: 'https://ror.org/old-wrong1', to: 'https://ror.org/05xpvk416', basis: 'domain-id' },
    ])
    expect(plan.unchanged).toBe(0)
    expect(plan.unmatched).toEqual([])
  })
})
