// ─────────────────────────────────────────────────────────────────────
// The OP_ACCOUNT_SEED's declared entries — the demonstration cast's
// provisioning. A plain entry creates-if-absent and hands off (the
// registry seed's posture); a declared entry (orgId / roles /
// emailVerified / password / clientRoles) converges EXACTLY its
// declared fields on every boot, so the cast cannot drift out from
// under the demo — and never reaches further than its declared
// per-client assignments.
// ─────────────────────────────────────────────────────────────────────

import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

const TMP = mkdtempSync(join(tmpdir(), 'oiml-acct-seed-'))
process.env.DATABASE_PATH = join(TMP, 'test.db')
process.env.OP_ISSUER = 'http://op.test'

let store: ReturnType<typeof import('../../server/store').getStore>
let seedOpAccountsFromEnv: typeof import('../../server/auth/op/accounts').seedOpAccountsFromEnv
let parseOpAccountSeed: typeof import('../../server/auth/op/accounts').parseOpAccountSeed
let verifyPassword: typeof import('../../server/auth/passwords').verifyPassword

const PERSONA = {
  email: 'ia@oimlsmart.org',
  name: 'IA Officer (Demonstration)',
  role: 'user',
  orgId: 'EX1',
  emailVerified: true,
  password: 'demo2026',
  clientRoles: { 'oiml-smart-demo': ['ia_officer'] },
}

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
demo_personas: false
`))
  store = (await import('../../server/store')).getStore()
  const accounts = await import('../../server/auth/op/accounts')
  seedOpAccountsFromEnv = accounts.seedOpAccountsFromEnv
  parseOpAccountSeed = accounts.parseOpAccountSeed
  verifyPassword = (await import('../../server/auth/passwords')).verifyPassword
})

afterAll(() => {
  rmSync(TMP, { recursive: true, force: true })
  delete process.env.DATABASE_PATH
  delete process.env.OP_ISSUER
})

describe('parseOpAccountSeed (the declaration validator)', () => {
  it('accepts a full persona declaration', () => {
    const parsed = parseOpAccountSeed(JSON.stringify([PERSONA]))
    expect(parsed).toHaveLength(1)
    expect(parsed[0]!.orgId).toBe('EX1')
    expect(parsed[0]!.clientRoles).toEqual({ 'oiml-smart-demo': ['ia_officer'] })
  })

  it('refuses a malformed field honestly (the boot fails, never guesses)', () => {
    for (const bad of [
      '[{"email":"a@b.c","name":"A","orgId":""}]',
      '[{"email":"a@b.c","name":"A","roles":"admin"}]',
      '[{"email":"a@b.c","name":"A","emailVerified":"yes"}]',
      '[{"email":"a@b.c","name":"A","password":""}]',
      '[{"email":"a@b.c","name":"A","clientRoles":{"c":"admin"}}]',
      '[{"email":"a@b.c","name":"A","clientRoles":{"c":[""]}}]',
      'not-json',
      '{"email":"a@b.c"}',
    ]) {
      expect(() => parseOpAccountSeed(bad), bad).toThrow()
    }
  })
})

describe('the declared entry (the demonstration persona)', () => {
  it('creates the account with every declared field', async () => {
    const seeded = await seedOpAccountsFromEnv({ OP_ACCOUNT_SEED: JSON.stringify([PERSONA]) }, store, 'http://op.test')
    expect(seeded).toEqual(['ia@oimlsmart.org'])

    const account = (await store.findUserByEmail('ia@oimlsmart.org'))!
    expect(account).toBeTruthy()
    expect(account.role).toBe('user')
    expect(account.orgId).toBe('EX1')
    expect(account.emailVerifiedAt).toBeTruthy()

    // The credential verifies (hashed on the seed — the plaintext never
    // lands anywhere).
    const cred = await store.getPasswordLogin('ia@oimlsmart.org')
    expect(cred).toBeTruthy()
    expect(await verifyPassword('demo2026', cred!.hash)).toBe(true)

    // The per-client assignment is the reach the declaration names.
    expect(await store.getOpClientRoles(account.id, 'oiml-smart-demo')).toEqual(['ia_officer'])

    // The primary membership mirror is active (the org claim's basis).
    const membership = await store.getOrgMembership(account.id, 'EX1')
    expect(membership?.state).toBe('active')
    expect(membership?.isPrimary).toBe(true)
  })

  it('converges a drifted account back to the declaration on the next boot', async () => {
    const account = (await store.findUserByEmail('ia@oimlsmart.org'))!
    // The drift: an administrator's edits to every declared field.
    await store.updateUserRoleOrg(account.id, 'admin', null)
    await store.deleteOpClientRoles(account.id, 'oiml-smart-demo')
    await store.setOrgMembershipState(account.id, 'EX1', 'disabled', 'test')

    await seedOpAccountsFromEnv({ OP_ACCOUNT_SEED: JSON.stringify([PERSONA]) }, store, 'http://op.test')

    const after = (await store.getUserById(account.id))!
    expect(after.role).toBe('user')
    expect(after.orgId).toBe('EX1')
    expect(await store.getOpClientRoles(account.id, 'oiml-smart-demo')).toEqual(['ia_officer'])
    expect((await store.getOrgMembership(account.id, 'EX1'))?.state).toBe('active')
  })

  it('never clobbers an existing password credential', async () => {
    const account = (await store.findUserByEmail('ia@oimlsmart.org'))!
    await store.setPasswordHash(account.id, 'unused-hash-value', 'test')
    await seedOpAccountsFromEnv({ OP_ACCOUNT_SEED: JSON.stringify([PERSONA]) }, store, 'http://op.test')
    const cred = await store.getPasswordLogin('ia@oimlsmart.org')
    expect(cred?.hash).toBe('unused-hash-value')
  })

  it('the second boot is idempotent (one account, one assignment, one membership)', async () => {
    const seed = { OP_ACCOUNT_SEED: JSON.stringify([PERSONA]) }
    await seedOpAccountsFromEnv(seed, store, 'http://op.test')
    await seedOpAccountsFromEnv(seed, store, 'http://op.test')
    const account = (await store.findUserByEmail('ia@oimlsmart.org'))!
    expect(await store.listOpClientRoles(account.id)).toHaveLength(1)
    expect(await store.getOrgMembership(account.id, 'EX1')).toBeTruthy()
  })
})

describe('the plain entry (the bootstrap administrator)', () => {
  it('creates-if-absent, then hands off — a declared sibling never bleeds into it', async () => {
    const admin = { email: 'root@oimlsmart.org', name: 'The Administrator', role: 'admin' }
    await seedOpAccountsFromEnv({ OP_ACCOUNT_SEED: JSON.stringify([admin]) }, store, 'http://op.test')
    const account = (await store.findUserByEmail('root@oimlsmart.org'))!

    // The drift an administrator makes afterwards STAYS (the hands-off
    // doctrine — no persona fields declared, nothing converges).
    await store.updateUserRoleOrg(account.id, 'viewer', null)
    await seedOpAccountsFromEnv({ OP_ACCOUNT_SEED: JSON.stringify([admin]) }, store, 'http://op.test')
    expect((await store.getUserById(account.id))!.role).toBe('viewer')

    // A password-less plain entry still earns its enrollment link (the
    // first administrator's way in): the methods count says no password.
    const methods = await store.countSignInMethods(account.id)
    expect(methods.password).toBe(false)
  })

  it('a plain entry created before the declared extension keeps its role (role absent from the entry)', async () => {
    const legacy = { email: 'elder@oimlsmart.org', name: 'Elder Admin' } // no role: the 'admin' default
    await seedOpAccountsFromEnv({ OP_ACCOUNT_SEED: JSON.stringify([legacy]) }, store, 'http://op.test')
    const account = (await store.findUserByEmail('elder@oimlsmart.org'))!
    expect(account.role).toBe('admin')
  })
})
