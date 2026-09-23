// ─────────────────────────────────────────────────────────────────────
// TODO.modern/06's last half — the risk signals, in-process: the
// known-device record (the UA+IP hash per account), the new-device
// and country-change advisories riding the sign-in audit, and the
// account's own devices view. The REAL app factory + the REAL store;
// the route leg drives a REAL password sign-in (an account created
// through the SCIM surface, its hash set directly).
// ─────────────────────────────────────────────────────────────────────

import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

const TMP = mkdtempSync(join(tmpdir(), 'oiml-risk-'))
process.env.DATABASE_PATH = join(TMP, 'test.db')
const ISSUER = 'http://op.test'
process.env.OP_ISSUER = ISSUER
process.env.SCIM_BEARER_TOKEN = 'risk-suite-bearer'

let app: import('hono').Hono
let store: ReturnType<typeof import('../../server/store').getStore>

async function provisionAccount(email: string, password: string): Promise<string> {
  const created = await (await app.request(`${ISSUER}/scim/v2/Users`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: 'Bearer risk-suite-bearer' },
    body: JSON.stringify({ userName: email, active: true }),
  })).json() as { id: string }
  const { hashPassword } = await import('../../server/auth/passwords')
  await store.setPasswordHash(created.id, await hashPassword(password))
  return created.id
}

async function passwordLogin(email: string, password: string, headers: Record<string, string> = {}) {
  return app.request(`${ISSUER}/api/op/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...headers },
    body: JSON.stringify({ email, password }),
  })
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
demo_personas: true
`))
  const { createApiApp } = await import('../../server/app')
  app = createApiApp({ autoSeedDemo: true, instanceProfile: profileMod.getInstanceProfile() })
  store = (await import('../../server/store')).getStore()
})

afterAll(() => {
  rmSync(TMP, { recursive: true, force: true })
  delete process.env.DATABASE_PATH
  delete process.env.OP_ISSUER
  delete process.env.SCIM_BEARER_TOKEN
})

describe('the risk module (the pure seams)', () => {
  it('the device hash binds UA + IP deterministically', async () => {
    const { deviceHashOf } = await import('../../server/auth/op/risk')
    const a = await deviceHashOf('Mozilla/5.0 TestAgent', '203.0.113.9')
    expect(a).toMatch(/^[0-9a-f]{64}$/)
    expect(await deviceHashOf('Mozilla/5.0 TestAgent', '203.0.113.9')).toBe(a)
    expect(await deviceHashOf('Mozilla/5.0 OtherAgent', '203.0.113.9')).not.toBe(a)
    expect(await deviceHashOf('Mozilla/5.0 TestAgent', '198.51.100.4')).not.toBe(a)
  })

  it('the country reads the Worker\'s cf field, then the header, else null', async () => {
    const { countryOf } = await import('../../server/auth/op/risk')
    const req = new Request('http://op.test/api/health', { headers: { 'cf-ipcountry': 'CH' } })
    expect(countryOf({ req })).toBe('CH')
    expect(countryOf({ req: new Request('http://op.test/api/health') })).toBeNull()
  })
})

describe('the known-device record (the store seam)', () => {
  it('the first sighting is NEW; the repeat is known, with the prior country', async () => {
    // Real accounts (the FK) — the demo cast seeds on the warm-up login.
    const warm = await app.request('/api/auth/demo', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: 'ia@oimlsmart.org', password: 'demo2026' }),
    })
    expect(warm.ok).toBe(true)
    const oneId = (await store.findUserByEmail('biml@oimlsmart.org'))!.id
    const first = await store.recordKnownDevice({
      id: crypto.randomUUID(), accountId: oneId, deviceHash: 'dev-hash-1',
      userAgent: 'TestAgent/1.0', ip: '203.0.113.9', country: 'FR',
    })
    expect(first.isNew).toBe(true)
    expect(first.previousCountry).toBeNull()

    const again = await store.recordKnownDevice({
      id: crypto.randomUUID(), accountId: oneId, deviceHash: 'dev-hash-1',
      userAgent: 'TestAgent/1.0', ip: '203.0.113.9', country: 'CH',
    })
    expect(again.isNew).toBe(false)
    expect(again.previousCountry).toBe('FR')

    const list = await store.listKnownDevices(oneId)
    expect(list).toHaveLength(1)
    expect(list[0]!.lastCountry).toBe('CH')
  })

  it('the account sees only its own devices', async () => {
    const twoId = (await store.findUserByEmail('cs@oimlsmart.org'))!.id
    await store.recordKnownDevice({
      id: crypto.randomUUID(), accountId: twoId, deviceHash: 'dev-hash-2',
      userAgent: 'Other/2.0', ip: '198.51.100.4', country: null,
    })
    expect(await store.listKnownDevices(twoId)).toHaveLength(1)
    expect(await store.listKnownDevices((await store.findUserByEmail('mc@oimlsmart.org'))!.id)).toHaveLength(0)
  })
})

describe('the sign-in integration (the real password login)', () => {
  it('a NEW device flags the audit + lands in the devices view; the repeat does not', async () => {
    const id = await provisionAccount('risk.person@example.org', 'a-risk-probe-passphrase-2026')

    const first = await passwordLogin('risk.person@example.org', 'a-risk-probe-passphrase-2026', {
      'user-agent': 'RiskProbe/1.0 (first device)',
      'x-forwarded-for': '203.0.113.9',
    })
    expect(first.status).toBe(200)
    const cookie = first.headers.get('set-cookie')!.split(';')[0]!

    const devices = await (await app.request(`${ISSUER}/api/op/account/devices`, { headers: { cookie } })).json() as {
      devices: Array<{ userAgent: string | null; ipMasked: string | null; firstSeenAt: string; lastSeenAt: string }>
    }
    expect(devices.devices).toHaveLength(1)
    expect(devices.devices[0]!.userAgent).toContain('RiskProbe/1.0')
    expect(devices.devices[0]!.ipMasked).toBe('203.0.113.*')

    // The audit carries the advisory (the journal is the risk truth).
    const rows = await store.listEntities('auditEvents')
    const signIns = rows.filter(r => {
      const row = JSON.parse(r.data) as { action: string; user_id: string; metadata: { newDevice?: boolean } }
      return row.action === 'account.sign_in' && row.user_id === id
    })
    expect(signIns.length).toBeGreaterThanOrEqual(1)
    const firstMeta = JSON.parse(signIns.at(-1)!.data) as { metadata: { newDevice?: boolean } }
    expect(firstMeta.metadata.newDevice).toBe(true)

    // The SAME device again: known, no new flag.
    await passwordLogin('risk.person@example.org', 'a-risk-probe-passphrase-2026', {
      'user-agent': 'RiskProbe/1.0 (first device)',
      'x-forwarded-for': '203.0.113.9',
    })
    const rowsAfter = await store.listEntities('auditEvents')
    const second = rowsAfter.map(r => JSON.parse(r.data) as { action: string; user_id: string; metadata: { newDevice?: boolean } })
      .filter(row => row.action === 'account.sign_in' && row.user_id === id)
    expect(second.at(-1)!.metadata.newDevice).toBe(false)
  })

  it('the devices view requires the session', async () => {
    const res = await app.request(`${ISSUER}/api/op/account/devices`)
    expect(res.status).toBe(401)
  })
})
