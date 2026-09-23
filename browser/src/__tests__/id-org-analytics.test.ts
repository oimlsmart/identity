// ─────────────────────────────────────────────────────────────────────
// TODO.modern/09's last half — the per-org analytics, in-process: the
// dashboard's tenant view over the journal (sign-ins, failed sign-ins,
// exchanges per org, the per-day series), membership-joined in memory
// (bulk reads, call-count invariant — the scaling doctrine). The REAL
// app factory + the REAL store; the journal seeded through its OWN
// writer (putEntity — the truth's own shape).
// ─────────────────────────────────────────────────────────────────────

import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

const TMP = mkdtempSync(join(tmpdir(), 'oiml-org-analytics-'))
process.env.DATABASE_PATH = join(TMP, 'test.db')
const ISSUER = 'http://op.test'
process.env.OP_ISSUER = ISSUER

let app: import('hono').Hono
let store: ReturnType<typeof import('../../server/store').getStore>

const ORG = 'anly-test-org'

async function seedAudit(action: string, entityId: string, extra: Record<string, unknown> = {}): Promise<void> {
  await store.putEntity('auditEvents', crypto.randomUUID(), null, JSON.stringify({
    id: crypto.randomUUID(),
    timestamp: new Date().toISOString(),
    standard_id: '',
    entity_type: 'account',
    entity_id: entityId,
    action,
    user_id: entityId,
    metadata: extra,
  }))
}

async function memberOf(orgId: string): Promise<string> {
  const account = await store.createOpAccount({
    email: `anly-${orgId}-${crypto.randomUUID().slice(0, 8)}@example.org`,
    name: 'Analytics Member',
    role: 'viewer',
    createdBy: 'test',
  })
  await store.createOrgMembership({ userId: account!.id, orgId, roles: ['org_member'], state: 'active' })
  return account!.id
}

async function adminCookie(): Promise<string> {
  const res = await app.request('/api/auth/demo', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email: 'admin@oimlsmart.org', password: 'demo2026' }),
  })
  expect(res.ok, 'the admin demo login').toBe(true)
  return res.headers.get('set-cookie')!.split(';')[0]!
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
  await adminCookie() // the cast seeds

  // Two members; the journal carries their acts (the truth's own shape).
  const memberOne = await memberOf(ORG)
  const memberTwo = await memberOf(ORG)
  const outsider = await memberOf('anly-other-org')
  await seedAudit('account.sign_in', memberOne)
  await seedAudit('account.sign_in', memberTwo)
  await seedAudit('account.sign_in_failed', memberTwo)
  await seedAudit('client.token_issued', 'some-client', { account: memberOne })
  await seedAudit('account.sign_in', outsider) // another org's row — excluded
})

afterAll(() => {
  rmSync(TMP, { recursive: true, force: true })
  delete process.env.DATABASE_PATH
  delete process.env.OP_ISSUER
})

describe('the per-org analytics (the tenant view)', () => {
  it('aggregates the org\'s acts, membership-joined, per-day', async () => {
    const cookie = await adminCookie()
    const res = await app.request(`${ISSUER}/api/op/dashboard/org-activity?org=${ORG}&days=7`, { headers: { cookie } })
    expect(res.status).toBe(200)
    const body = await res.json() as {
      org: string
      days: number
      totals: { signIns: number; failedSignIns: number; exchanges: number }
      byDay: Array<{ date: string; signIns: number; failedSignIns: number; exchanges: number }>
    }
    expect(body.org).toBe(ORG)
    expect(body.days).toBe(7)
    expect(body.totals).toEqual({ signIns: 2, failedSignIns: 1, exchanges: 1 })
    expect(body.byDay).toHaveLength(7)
    const today = body.byDay.at(-1)!
    expect(today.signIns).toBe(2)
    expect(today.failedSignIns).toBe(1)
    expect(today.exchanges).toBe(1)
  })

  it('the outsider org sees only its own row', async () => {
    const cookie = await adminCookie()
    const res = await app.request(`${ISSUER}/api/op/dashboard/org-activity?org=anly-other-org&days=7`, { headers: { cookie } })
    const body = await res.json() as { totals: { signIns: number } }
    expect(body.totals.signIns).toBe(1)
  })

  it('requires the admin', async () => {
    const anon = await app.request(`${ISSUER}/api/op/dashboard/org-activity?org=${ORG}`)
    expect(anon.status).toBe(401)
    const member = await app.request('/api/auth/demo', {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: 'tl@oimlsmart.org', password: 'demo2026' }),
    })
    const cookie = member.headers.get('set-cookie')!.split(';')[0]!
    const refused = await app.request(`${ISSUER}/api/op/dashboard/org-activity?org=${ORG}`, { headers: { cookie } })
    expect(refused.status).toBe(403)
  })

  it('the window is bounded (1–90 days)', async () => {
    const cookie = await adminCookie()
    const tooWide = await app.request(`${ISSUER}/api/op/dashboard/org-activity?org=${ORG}&days=400`, { headers: { cookie } })
    expect(tooWide.status).toBe(400)
  })
})
