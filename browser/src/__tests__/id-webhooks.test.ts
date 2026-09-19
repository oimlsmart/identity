// ─────────────────────────────────────────────────────────────────────
// TODO.modern/08 — the outbound webhooks, in-process: the HMAC
// signature (the Stripe posture), the subscription surface
// (account-owned, https-only, the secret shown ONCE), the delivery
// ladder (bounded retries, the dead-letter record), and the fan-out at
// a real act (the PAT mint). The REAL app factory + the REAL store.
// ─────────────────────────────────────────────────────────────────────

import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest'

const TMP = mkdtempSync(join(tmpdir(), 'oiml-webhooks-'))
process.env.DATABASE_PATH = join(TMP, 'test.db')
const ISSUER = 'http://op.test'
process.env.OP_ISSUER = ISSUER
process.env.WEBHOOK_RETRY_DELAYS_MS = '0,0,0'

let app: import('hono').Hono
const realFetch = globalThis.fetch

async function demoLogin(email: string): Promise<string> {
  const res = await app.request('/api/auth/demo', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password: 'demo2026' }),
  })
  expect(res.ok, `demo login ${email}`).toBe(true)
  return res.headers.get('set-cookie')!.split(';')[0]!
}

interface SubscriptionAnswer {
  id: string
  url: string
  events: string[]
  secret: string
}

async function createSubscription(cookie: string, url: string, events: string[]): Promise<Response> {
  return app.request(`${ISSUER}/api/op/account/webhooks`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', cookie },
    body: JSON.stringify({ url, events }),
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
})

afterEach(() => {
  globalThis.fetch = realFetch
})

afterAll(() => {
  rmSync(TMP, { recursive: true, force: true })
  delete process.env.DATABASE_PATH
  delete process.env.OP_ISSUER
  delete process.env.WEBHOOK_RETRY_DELAYS_MS
})

describe('the signature (the Stripe posture)', () => {
  it('signs and verifies over timestamp + body', async () => {
    const { signWebhookPayload, verifyWebhookSignature } = await import('../../server/webhooks/signature')
    const body = JSON.stringify({ event: 'account.pat_minted' })
    const header = await signWebhookPayload('oswh_secret', 1_700_000_000_000, body)
    expect(header).toMatch(/^t=1700000000000,v1=[0-9a-f]{64}$/)
    expect(await verifyWebhookSignature({ secret: 'oswh_secret', header, body, nowMs: 1_700_000_000_000 + 10_000, toleranceSec: 300 })).toBe(true)
  })

  it('a tampered body or wrong secret never verifies', async () => {
    const { signWebhookPayload, verifyWebhookSignature } = await import('../../server/webhooks/signature')
    const header = await signWebhookPayload('oswh_secret', 1_700_000_000_000, '{"a":1}')
    expect(await verifyWebhookSignature({ secret: 'oswh_other', header, body: '{"a":1}', nowMs: 1_700_000_000_000, toleranceSec: 300 })).toBe(false)
    expect(await verifyWebhookSignature({ secret: 'oswh_secret', header, body: '{"a":2}', nowMs: 1_700_000_000_000, toleranceSec: 300 })).toBe(false)
    expect(await verifyWebhookSignature({ secret: 'oswh_secret', header: 'garbage', body: '{"a":1}', nowMs: 1_700_000_000_000, toleranceSec: 300 })).toBe(false)
  })

  it('a stale timestamp refuses (the replay bound)', async () => {
    const { signWebhookPayload, verifyWebhookSignature } = await import('../../server/webhooks/signature')
    const header = await signWebhookPayload('oswh_secret', 1_700_000_000_000, '{"a":1}')
    expect(await verifyWebhookSignature({ secret: 'oswh_secret', header, body: '{"a":1}', nowMs: 1_700_000_000_000 + 301_000, toleranceSec: 300 })).toBe(false)
  })
})

describe('the event vocabulary (the SSOT whitelist)', () => {
  it('admits the declared acts, refuses everything else', async () => {
    const { isWebhookEvent } = await import('../../server/webhooks/events')
    for (const name of [
      'account.password', 'account.session_revoked',
      'account.pat_minted', 'account.pat_revoked',
      'factor.totp_enrolled', 'factor.passkey_enrolled',
    ]) {
      expect(isWebhookEvent(name), name).toBe(true)
    }
    // Requests are not state changes: the reset REQUEST never carries
    // delivery (only the performed change does).
    expect(isWebhookEvent('account.password_reset')).toBe(false)
    expect(isWebhookEvent('account.sign_in')).toBe(false)
    expect(isWebhookEvent('')).toBe(false)
  })
})

describe('the subscription surface (session-gated, account-owned)', () => {
  it('creates with the secret shown ONCE; lists without it', async () => {
    const cookie = await demoLogin('ia@oiml.org')
    const res = await createSubscription(cookie, 'https://rp.example/hooks', ['account.pat_minted', 'account.session_revoked'])
    expect(res.status).toBe(201)
    const created = await res.json() as SubscriptionAnswer
    expect(created.url).toBe('https://rp.example/hooks')
    expect(created.events).toEqual(['account.pat_minted', 'account.session_revoked'])
    expect(created.secret).toMatch(/^oswh_[A-Za-z0-9_-]{40,}$/)

    const list = await app.request(`${ISSUER}/api/op/account/webhooks`, { headers: { cookie } })
    expect(list.status).toBe(200)
    const body = await list.json() as { subscriptions: Array<Record<string, unknown>> }
    expect(body.subscriptions).toHaveLength(1)
    expect(body.subscriptions[0]!.secret).toBeUndefined()
    expect(body.subscriptions[0]!.active).toBe(true)
  })

  it('refuses http, private hosts, empty and unknown event sets', async () => {
    const cookie = await demoLogin('ia@oiml.org')
    expect((await createSubscription(cookie, 'http://rp.example/hooks', ['account.pat_minted'])).status).toBe(400)
    expect((await createSubscription(cookie, 'https://localhost/hooks', ['account.pat_minted'])).status).toBe(400)
    expect((await createSubscription(cookie, 'https://192.168.1.5/hooks', ['account.pat_minted'])).status).toBe(400)
    expect((await createSubscription(cookie, 'https://rp.example/hooks', [])).status).toBe(400)
    expect((await createSubscription(cookie, 'https://rp.example/hooks', ['account.sign_in'])).status).toBe(400)
    expect((await createSubscription(cookie, 'not a url', ['account.pat_minted'])).status).toBe(400)
  })

  it('requires the session', async () => {
    const res = await app.request(`${ISSUER}/api/op/account/webhooks`)
    expect(res.status).toBe(401)
  })

  it('revokes only the owner\'s subscription', async () => {
    const owner = await demoLogin('ia@oiml.org')
    const other = await demoLogin('tl@oiml.org')
    const created = await (await createSubscription(owner, 'https://rp.example/hooks', ['account.pat_minted'])).json() as SubscriptionAnswer

    const foreign = await app.request(`${ISSUER}/api/op/account/webhooks/${created.id}`, { method: 'DELETE', headers: { cookie: other } })
    expect(foreign.status).toBe(404)

    const own = await app.request(`${ISSUER}/api/op/account/webhooks/${created.id}`, { method: 'DELETE', headers: { cookie: owner } })
    expect(own.status).toBe(200)

    const list = await app.request(`${ISSUER}/api/op/account/webhooks`, { headers: { cookie: owner } })
    const body = await list.json() as { subscriptions: Array<{ id: string; active: boolean }> }
    expect(body.subscriptions.find(s => s.id === created.id)).toBeUndefined()
  })
})

describe('the delivery ladder (bounded retries + the dead letter)', () => {
  it('delivers a subscribed event: signed, envelope-shaped, recorded', async () => {
    const { verifyWebhookSignature } = await import('../../server/webhooks/signature')
    const store = (await import('../../server/store')).getStore()
    const ia2Id = (await store.findUserByEmail('ia2@oiml.org'))!.id
    const secret = 'oswh_test_secret_one'
    await store.createWebhookSubscription({
      id: crypto.randomUUID(),
      accountId: ia2Id,
      url: 'https://rp.example/hooks',
      events: ['account.pat_minted'],
      secret,
    })

    const seen: Array<{ url: string; headers: Headers; body: string }> = []
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      seen.push({
        url: String(input),
        headers: new Headers(init?.headers),
        body: String(init?.body),
      })
      return new Response('ok', { status: 200 })
    }) as typeof fetch

    const { deliverWebhookEvent } = await import('../../server/webhooks/deliver')
    const delivered = await deliverWebhookEvent({ WEBHOOK_RETRY_DELAYS_MS: '0,0,0' }, {
      event: 'account.pat_minted',
      accountId: ia2Id,
      data: { name: 'ci-hook', scopes: ['identity:read'] },
    })
    expect(delivered).toBe(1)
    expect(seen).toHaveLength(1)
    expect(seen[0]!.url).toBe('https://rp.example/hooks')

    const envelope = JSON.parse(seen[0]!.body) as { id: string; event: string; account: string; created: string; data: Record<string, unknown> }
    expect(envelope.event).toBe('account.pat_minted')
    expect(envelope.account).toBe(ia2Id)
    expect(envelope.data.name).toBe('ci-hook')
    expect(typeof envelope.created).toBe('string')

    const signature = seen[0]!.headers.get('webhook-signature')!
    expect(await verifyWebhookSignature({ secret, header: signature, body: seen[0]!.body, nowMs: Date.now(), toleranceSec: 300 })).toBe(true)
  })

  it('a non-subscribed account or event delivers nothing', async () => {
    const store = (await import('../../server/store')).getStore()
    const iaId = (await store.findUserByEmail('ia@oiml.org'))!.id
    let calls = 0
    globalThis.fetch = (async (): Promise<Response> => { calls++; return new Response('ok', { status: 200 }) }) as typeof fetch

    const { deliverWebhookEvent } = await import('../../server/webhooks/deliver')
    expect(await deliverWebhookEvent({ WEBHOOK_RETRY_DELAYS_MS: '0,0,0' }, { event: 'factor.totp_enrolled', accountId: iaId, data: {} })).toBe(0)
    expect(await deliverWebhookEvent({ WEBHOOK_RETRY_DELAYS_MS: '0,0,0' }, { event: 'account.sign_in', accountId: iaId, data: {} })).toBe(0)
    expect(calls).toBe(0)
  })

  it('the exhausted ladder records the dead letter (attempts + last status)', async () => {
    const store = (await import('../../server/store')).getStore()
    const bimlId = (await store.findUserByEmail('biml@oiml.org'))!.id
    await store.createWebhookSubscription({
      id: crypto.randomUUID(),
      accountId: bimlId,
      url: 'https://down.example/hooks',
      events: ['account.pat_revoked'],
      secret: 'oswh_test_secret_three',
    })
    let attempts = 0
    globalThis.fetch = (async (): Promise<Response> => { attempts++; return new Response('nope', { status: 500 }) }) as typeof fetch

    const { deliverWebhookEvent } = await import('../../server/webhooks/deliver')
    expect(await deliverWebhookEvent({ WEBHOOK_RETRY_DELAYS_MS: '0,0,0' }, { event: 'account.pat_revoked', accountId: bimlId, data: {} })).toBe(0)
    expect(attempts).toBe(3)

    const dead = await store.listWebhookDeliveries(bimlId)
    expect(dead).toHaveLength(1)
    expect(dead[0]!.delivered).toBe(false)
    expect(dead[0]!.attempts).toBe(3)
    expect(dead[0]!.lastStatus).toBe(500)
    expect(dead[0]!.event).toBe('account.pat_revoked')
    expect(dead[0]!.bodyDigest).toMatch(/^[0-9a-f]{64}$/)
  })
})

describe('the fan-out at a real act (the PAT mint)', () => {
  it('a minted PAT reaches the subscribed endpoint, signed', async () => {
    const { verifyWebhookSignature } = await import('../../server/webhooks/signature')
    const cookie = await demoLogin('cs@oiml.org')
    const created = await (await createSubscription(cookie, 'https://rp.example/hooks', ['account.password'])).json() as SubscriptionAnswer

    const deliveries: Array<{ headers: Headers; body: string }> = []
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      if (String(input).includes('rp.example')) {
        deliveries.push({ headers: new Headers(init?.headers), body: String(init?.body) })
      }
      return new Response('ok', { status: 200 })
    }) as typeof fetch

    // The act: the password change (demo accounts carry no password,
    // so {next} alone authenticates the change).
    const change = await app.request(`${ISSUER}/api/op/account/password`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ next: 'a-fresh-webhook-probe-2026' }),
    })
    expect(change.status, 'the password change answers').toBe(200)

    // The fan-out is fire-and-forget — poll for the delivery.
    const deadline = Date.now() + 5_000
    while (deliveries.length === 0 && Date.now() < deadline) await new Promise(r => setTimeout(r, 50))
    expect(deliveries).toHaveLength(1)

    const envelope = JSON.parse(deliveries[0]!.body) as { event: string; data: Record<string, unknown> }
    expect(envelope.event).toBe('account.password')
    expect(typeof envelope.data.otherSessionsRevoked).toBe('number')
    expect(await verifyWebhookSignature({
      secret: created.secret,
      header: deliveries[0]!.headers.get('webhook-signature')!,
      body: deliveries[0]!.body,
      nowMs: Date.now(),
      toleranceSec: 300,
    })).toBe(true)
  })
})
