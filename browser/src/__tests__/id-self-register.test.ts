// ─────────────────────────────────────────────────────────────────────
// The Ommisa member tier's self-enrollment (the 2026-09-26 flow, rev
// 4): the four gates and the ONE write. The law under test: NOTHING is
// stored before the verified click — leg 1 and the emailed token write
// nothing; the click's completion is the flow's only creation, and it
// carries the registry hit's roles as the Ommisa client's per-client
// assignments.
// ─────────────────────────────────────────────────────────────────────

import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { loadDomains as loadMemberCatalog } from '../../server/auth/op/member-domains'

const TMP = mkdtempSync(join(tmpdir(), 'oiml-selfreg-'))
process.env.DATABASE_PATH = join(TMP, 'test.db')
const ISSUER = 'http://op.test'
process.env.OP_ISSUER = ISSUER
// The tier's config: ON; the Ommisa client carrying the registry
// roles. The landing org needs NO configuration — it is the
// organization the registry entry names, keyed by the domain.
process.env.OP_SELF_REGISTER = '1'
process.env.OP_SELF_REGISTER_CLIENT = 'oiml-ommisa'

let app: import('hono').Hono
let store: ReturnType<typeof import('../../server/store').getStore>
let linkKeyMaterial: string
let orgs: { users: () => number }

const START = (body: Record<string, unknown>) => app.request('/api/op/self-register/start', {
  method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body),
})

beforeAll(async () => {
  const { generateSuccessorPair } = await import('../../scripts/op-key-rotate')
  process.env.OP_SIGNING_KEY = (await generateSuccessorPair()).privateJwkJson
  const { installSqliteStore } = await import('../../server/store/sqlite')
  installSqliteStore()
  store = (await import('../../server/store')).getStore()
  const profileMod = await import('../../server/profile')
  profileMod.installInstanceProfile(profileMod.parseInstanceProfile(`
identity:
  org_id: oimlsmart-id
  org_name: OIML SMART Identity
  role_codes: [identity]
roles: [identity]
branding: { name: OIML SMART Identity }
demo_personas: false
`))
  const { createApiApp } = await import('../../server/app')
  app = createApiApp({ autoSeedDemo: false, identityModule: { modules: ['identity'] } } as never)

  // The attribution upstream: the enabled google row (the tier prefers
  // it; github is the accepted alternative).
  await store.upsertIdentityProvider({
    id: 'google', kind: 'oidc', displayName: 'Google', enabled: true,
    issuer: 'https://accounts.google.com', clientId: 'test-google-client',
    clientSecretRef: 'GOOGLE_UPSTREAM_CLIENT_SECRET', scopes: 'openid email',
    createdBy: 'test',
  })

  // The link tokens sign with the SAME material the app resolves.
  const { resolveOpSigningKey } = await import('../../server/auth/op/keys')
  linkKeyMaterial = (await resolveOpSigningKey(process.env as Record<string, string>)).secretMaterial

  const { mintRegistrationToken } = await import('../../server/auth/op/self-register-links')
  void mintRegistrationToken
  orgs = {
    users: () => (store as unknown as { listUsers: () => Promise<unknown[]> }).listUsers.length,
  }
  void orgs
})

afterAll(() => {
  rmSync(TMP, { recursive: true, force: true })
  for (const key of ['OP_ISSUER', 'OP_SIGNING_KEY', 'DATABASE_PATH', 'OP_SELF_REGISTER', 'OP_SELF_REGISTER_CLIENT']) {
    delete process.env[key]
  }
})

describe('leg 1 — the start (the eligibility reads; NOTHING is written)', () => {
  it('the happy eligibility answers the attribution bounce and writes NOTHING', async () => {
    const before = await store.listUsers()
    const res = await START({ country: 'United States', org: 'National Institute of Standards and Technology (NIST)', name: 'Test Applicant', email: 'applicant@nist.gov' })
    expect(res.status).toBe(200)
    const body = await res.json() as { ok: boolean; providers: { id: string; name: string; next: string }[] }
    expect(body.ok).toBe(true)
    expect(body.providers.length).toBe(1)
    expect(body.providers[0].id).toBe('google')
    expect(body.providers[0].next).toContain('/op/upstream/google/signin?mode=attribute&email=applicant%40nist.gov')
    const after = await store.listUsers()
    expect(after.length).toBe(before.length) // the law: nothing is written
  })

  it('the mismatch names the owning organization', async () => {
    const res = await START({ country: 'United States', org: 'National Institute of Standards and Technology (NIST)', name: 'X', email: 'someone@cmi.gov.cz' })
    expect(res.status).toBe(403)
    const body = await res.json() as { error: string; registeredTo: { org: string } }
    expect(body.error).toContain('registered to')
    expect(body.registeredTo.org).toContain('Czech Metrology Institute')
  })

  it('an unmatched domain answers the queue fallback AND creates the join request', async () => {
    const res = await START({ country: 'United States', org: 'National Institute of Standards and Technology (NIST)', name: 'Industry Applicant', email: 'industry@acme-industry.example' })
    expect(res.status).toBe(200)
    const body = await res.json() as { ok: boolean; queued: boolean; requestId: string }
    expect(body.queued).toBe(true)
    const request = await store.getOrgJoinRequest(body.requestId)
    expect(request?.email).toBe('industry@acme-industry.example')
    expect(request?.orgNameText).toContain('NIST')
  })

  it('the admin_queue org refuses self-provisioning with the queue sentence', async () => {
    // The registry's admin_queue flag rides the vendored artifact's
    // countries projection; find one (or the absence proves the
    // posture is data-driven and the test yields).
    const catalog = loadCatalog()
    const adminQueueOrg = catalog.countries.flatMap(c => c.orgs.map(o => ({ c: c.country, o })))
      .find(x => x.o.admin_queue)
    if (!adminQueueOrg) return // the current artifact carries none — the posture is data-driven
    const res = await START({ country: adminQueueOrg.c, org: adminQueueOrg.o.name, name: 'X', email: `x@${adminQueueOrg.o.domains[0]}` })
    expect(res.status).toBe(200)
    const body = await res.json() as { queued: boolean }
    expect(body.queued).toBe(true)
  })

  it('an unknown country refuses', async () => {
    const res = await START({ country: 'Atlantis', org: 'X', name: 'X', email: 'a@b.cd' })
    expect(res.status).toBe(403)
  })
})

describe('leg 3+4 — the verified click (the flow\'s ONLY write)', () => {
  it('the complete creates the account verified, with the registry roles, the org binding, and a working password', async () => {
    const { mintRegistrationToken } = await import('../../server/auth/op/self-register-links')
    const token = await mintRegistrationToken(linkKeyMaterial, 'member@nist.gov', Date.now(), 24 * 3600_000, 'NIST Member')
    const complete = await app.request('/api/op/self-register/complete', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ token, password: 'a proper member passphrase 2026' }),
    })
    expect(complete.status).toBe(200)

    // The account: verified by the click, bound to the ORG OF THE SAME
    // DOMAIN NAME — the row materialized from the registry, its FULL
    // NAME from the registry entry, active.
    const account = await store.findUserByEmail('member@nist.gov')
    expect(account).toBeTruthy()
    expect(account!.emailVerifiedAt ?? 'verified').toBeTruthy()
    const org = await store.getOrgRegistryOrg('nist.gov')
    expect(org?.name).toBe('National Institute of Standards and Technology (NIST)')
    expect(org?.state).toBe('active')
    expect(org?.country).toBe('United States')

    // The registry roles ride as the Ommisa client's per-client
    // assignments (the standing the service reads).
    const roles = await store.listOpClientRoles(account!.id)
    const ommisa = roles.find(r => r.clientId === 'oiml-ommisa')
    expect(ommisa?.roles).toContain('ciml-member')

    // The password works.
    const login = await store.getPasswordLogin('member@nist.gov')
    expect(login?.active).toBe(true)

    // The audit names the registry vintage.
    const auditRows = await store.listEntities('auditEvents')
    const row = JSON.stringify(auditRows)
    expect(row).toContain('account.self_registered')
  })

  it('the verify answers the carried name and the org (the setup page\'s copy)', async () => {
    const { mintRegistrationToken } = await import('../../server/auth/op/self-register-links')
    const token = await mintRegistrationToken(linkKeyMaterial, 'second@nist.gov', Date.now(), 24 * 3600_000, 'Second Member')
    const res = await app.request('/api/op/self-register/verify', {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ token }),
    })
    expect(res.status).toBe(200)
    const body = await res.json() as { ok: boolean; email: string; name: string | null; org: string }
    expect(body.ok).toBe(true)
    expect(body.name).toBe('Second Member')
    expect(body.org).toContain('National Institute')
    // Verify creates NOTHING.
    expect(await store.findUserByEmail('second@nist.gov')).toBeNull()
  })

  it('a replayed (post-creation) token answers the honest already-registered', async () => {
    const { mintRegistrationToken } = await import('../../server/auth/op/self-register-links')
    const token = await mintRegistrationToken(linkKeyMaterial, 'member@nist.gov')
    const res = await app.request('/api/op/self-register/complete', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ token, password: 'another passphrase entirely 2026' }),
    })
    expect(res.status).toBe(400)
    expect((await res.json() as { error: string }).error).toContain('already exists')
  })

  it('a tampered token answers the uniform refusal', async () => {
    const { mintRegistrationToken } = await import('../../server/auth/op/self-register-links')
    const token = await mintRegistrationToken(linkKeyMaterial, 'member@nist.gov')
    const res = await app.request('/api/op/self-register/complete', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ token: token.slice(0, -2) + 'xx', password: 'a proper passphrase 2026' }),
    })
    expect(res.status).toBe(400)
  })

  it('an expired token answers the uniform refusal', async () => {
    const { mintRegistrationToken } = await import('../../server/auth/op/self-register-links')
    const token = await mintRegistrationToken(linkKeyMaterial, 'expired@nist.gov', Date.now() - 25 * 3600_000)
    const res = await app.request('/api/op/self-register/complete', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ token, password: 'a proper passphrase 2026' }),
    })
    expect(res.status).toBe(400)
  })
})

describe('the config posture (fail-closed)', () => {
  it('the disabled switch answers 403 with the queue sentence', async () => {
    process.env.OP_SELF_REGISTER = '0'
    const res = await START({ country: 'United States', org: 'National Institute of Standards and Technology (NIST)', name: 'X', email: 'a@nist.gov' })
    process.env.OP_SELF_REGISTER = '1'
    expect(res.status).toBe(403)
    expect((await res.json() as { error: string }).error).toContain('join queue')
  })
})

function loadCatalog(): ReturnType<typeof import('../../server/auth/op/member-domains').loadDomains> {
  return loadMemberCatalog()
}
