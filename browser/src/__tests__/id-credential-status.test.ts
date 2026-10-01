// ─────────────────────────────────────────────────────────────────────
// TODO.sota/08 slice 2 — the STATUS LIST (RFC 9157): the credential's
// revocation story. The mint stamps status.status_list.{uri, idx}
// (structural, never disclosable); the list endpoint answers the
// statuslist+jwt whose compressed bitstring carries one bit per
// issued credential; the revocation act flips the bit. The keys are
// REAL, the store is REAL, the compression is the platform's own
// CompressionStream.
// ─────────────────────────────────────────────────────────────────────
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

const TMP = mkdtempSync(join(tmpdir(), 'oiml-sl-'))
process.env.DATABASE_PATH = join(TMP, 'test.db')
const ISSUER = 'http://op.test'
process.env.OP_ISSUER = ISSUER
const PROFILE = join(TMP, 'profile.yaml')
writeFileSync(PROFILE, `name: statuslist
roles: [identity]
branding: { name: Status List }
demo_personas: true
`)
process.env.INSTANCE_PROFILE = PROFILE

let store: ReturnType<typeof import('../../server/store').getStore>
let app: import('hono').Hono
let key: import('../../server/auth/op/keys').OpSigningKey
let adminCookie: string

beforeAll(async () => {
  process.env.OP_SIGNING_KEY = await (await import('../../e2e/fixtures/op-signing-key')).fixtureOpSigningKey()
  const { installSqliteStore } = await import('../../server/store/sqlite')
  store = installSqliteStore()
  const profileMod = await import('../../server/profile')
  profileMod.installInstanceProfile(profileMod.parseInstanceProfile(`
identity:
  org_id: oimlsmart-id
  org_name: Status List
  role_codes: [identity]
roles: [identity]
branding: { name: Status List }
demo_personas: true
`))
  const { resolveOpSigningKey, ensureOpKeyRegistered } = await import('../../server/auth/op/keys')
  key = await resolveOpSigningKey(process.env as Record<string, string | undefined>)
  await ensureOpKeyRegistered(store, key)

  const { Hono } = await import('hono')
  const { createAuthLeanRouter } = await import('../../server/routes/auth-lean')
  const { createOpCredentialsRouter } = await import('../../server/routes/op-credentials')
  const root = new Hono()
  root.route('/api/auth', createAuthLeanRouter({ autoSeedDemo: true }))
  root.route('/', createOpCredentialsRouter())
  app = root
  const res = await app.request('/api/auth/demo', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email: 'admin@oimlsmart.org', password: 'demo2026' }),
  })
  expect(res.ok).toBe(true)
  adminCookie = res.headers.get('set-cookie')!.split(';')[0]!
}, 30_000)

afterAll(async () => {
  rmSync(TMP, { recursive: true, force: true })
  delete process.env.OP_ISSUER
  delete process.env.OP_SIGNING_KEY
  delete process.env.DATABASE_PATH
  delete process.env.INSTANCE_PROFILE
  const profileMod = await import('../../server/profile')
  profileMod.resetInstanceProfileForTest()
})

describe('the status-list seam (migration 0040)', () => {
  it('allocates unique indices; the revocation flips the read', async () => {
    const a = await store.allocateCredentialStatusIdx()
    const b = await store.allocateCredentialStatusIdx()
    expect(a).not.toBe(b)
    expect(await store.setCredentialStatusRevoked(a, new Date().toISOString())).toBe(true)
    expect(await store.setCredentialStatusRevoked(999999, new Date().toISOString())).toBe(false)
    const read = await store.readCredentialStatus()
    expect(read.maxIdx).toBeGreaterThanOrEqual(b)
    expect(read.revoked).toContain(a)
  })
})

describe('the mint stamps the status; the list answers; the revocation flips the bit', () => {
  it('a credential carries status.status_list.{uri, idx}; the list verifies and reads the bit', async () => {
    const { mintSdJwt, verifySdJwtPresentation, credentialRevoked } = await import('../../server/auth/op/sd-jwt')
    const minted = await mintSdJwt(key, {
      issuer: ISSUER, subject: 'acct-1', ttlSec: 3600,
      plain: { vct: 'org-membership' }, disclosable: { name: 'Ada' },
      statusListUri: `${ISSUER}/op/credentials/statuslist`, statusListIdx: await store.allocateCredentialStatusIdx(),
    })
    const verified = await verifySdJwtPresentation(store, minted.sdJwt, { issuer: ISSUER })
    expect('claims' in verified).toBe(true)
    const status = (verified as { claims: Record<string, unknown> }).claims.status as { status_list: { uri: string; idx: number } }
    expect(status.status_list.uri).toBe(`${ISSUER}/op/credentials/statuslist`)
    expect(typeof status.status_list.idx).toBe('number')

    const listRes = await app.request('/op/credentials/statuslist')
    expect(listRes.status).toBe(200)
    const listJwt = await listRes.text()
    expect(await credentialRevoked(store, listJwt, status.status_list.idx, ISSUER)).toBe(false)
  })

  it('the revocation act flips the bit at the index; the list JWT verifies as the issuer\'s own', async () => {
    const { mintSdJwt, credentialRevoked } = await import('../../server/auth/op/sd-jwt')
    const minted = await mintSdJwt(key, {
      issuer: ISSUER, subject: 'acct-2', ttlSec: 3600,
      plain: {}, disclosable: {},
      statusListUri: `${ISSUER}/op/credentials/statuslist`, statusListIdx: await store.allocateCredentialStatusIdx(),
    })
    const payload = JSON.parse(atob(minted.sdJwt.split('.')[1]!.replace(/-/g, '+').replace(/_/g, '/'))) as { status: { status_list: { idx: number } } }
    const idx = payload.status.status_list.idx

    // The act is admin-gated: no session refuses.
    const refused = await app.request(`/api/op/credentials/statuslist/${idx}/revoke`, { method: 'POST' })
    expect(refused.status).toBe(401)

    const revoked = await app.request(`/api/op/credentials/statuslist/${idx}/revoke`, {
      method: 'POST',
      headers: { cookie: adminCookie },
    })
    expect(revoked.status).toBe(200)
    const listJwt = await (await app.request('/op/credentials/statuslist')).text()
    expect(await credentialRevoked(store, listJwt, idx, ISSUER)).toBe(true)
  })
})
