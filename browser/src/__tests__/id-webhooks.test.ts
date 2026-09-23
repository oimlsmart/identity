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
    const cookie = await demoLogin('ia@oimlsmart.org')
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
    const cookie = await demoLogin('ia@oimlsmart.org')
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
    const owner = await demoLogin('ia@oimlsmart.org')
    const other = await demoLogin('tl@oimlsmart.org')
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
    const ia2Id = (await store.findUserByEmail('ia2@oimlsmart.org'))!.id
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
    const iaId = (await store.findUserByEmail('ia@oimlsmart.org'))!.id
    let calls = 0
    globalThis.fetch = (async (): Promise<Response> => { calls++; return new Response('ok', { status: 200 }) }) as typeof fetch

    const { deliverWebhookEvent } = await import('../../server/webhooks/deliver')
    expect(await deliverWebhookEvent({ WEBHOOK_RETRY_DELAYS_MS: '0,0,0' }, { event: 'factor.totp_enrolled', accountId: iaId, data: {} })).toBe(0)
    expect(await deliverWebhookEvent({ WEBHOOK_RETRY_DELAYS_MS: '0,0,0' }, { event: 'account.sign_in', accountId: iaId, data: {} })).toBe(0)
    expect(calls).toBe(0)
  })

  it('the exhausted ladder records the dead letter (attempts + last status)', async () => {
    const store = (await import('../../server/store')).getStore()
    const bimlId = (await store.findUserByEmail('biml@oimlsmart.org'))!.id
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
    const cookie = await demoLogin('cs@oimlsmart.org')
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

describe('the dead-letter redelivery (edition 2: the cron pass)', () => {
  // The system boundary again: the pass's own POST is the network.
  const pass = async (handler: (url: string, init: RequestInit | undefined) => Promise<Response>) => {
    const calls: Array<{ url: string; init: RequestInit | undefined }> = []
    globalThis.fetch = (async (url: unknown, init?: RequestInit) => {
      calls.push({ url: String(url), init })
      return handler(String(url), init)
    }) as typeof fetch
    return calls
  }

  it('UNSET: the redelivery endpoint does not exist (the house 404 pattern)', async () => {
    const res = await app.request(`${ISSUER}/api/op/webhooks/redeliver`, { method: 'POST' })
    expect(res.status).toBe(404)
  })

  it('SET: the wrong bearer refuses; the right bearer answers the pass tally', async () => {
    process.env.WEBHOOK_REDELIVERY_TOKEN = 'the-redelivery-bearer'
    try {
      const wrong = await app.request(`${ISSUER}/api/op/webhooks/redeliver`, {
        method: 'POST', headers: { authorization: 'Bearer not-it' },
      })
      expect(wrong.status).toBe(401)
      const right = await app.request(`${ISSUER}/api/op/webhooks/redeliver`, {
        method: 'POST', headers: { authorization: 'Bearer the-redelivery-bearer' },
      })
      expect(right.status).toBe(200)
      expect(await right.json() as { attempted: number; delivered: number; retired: number }).toEqual({ attempted: 0, delivered: 0, retired: 0 })
    } finally {
      delete process.env.WEBHOOK_REDELIVERY_TOKEN
    }
  })

  it('a dead letter with its envelope body: ONE pass re-signs and re-POSTs it verbatim; the letter retires; the log gains the outcome', async () => {
    const { getStore } = await import('../../server/store')
    const store = getStore()
    const cookie = await demoLogin('biml@oimlsmart.org')
    const created = ((await (await createSubscription(cookie, 'https://redeliver.example/hooks', ['account.password'])).json()) as SubscriptionAnswer)
    const { getStore: gs0 } = await import('../../server/store')
    const ownerId = (await gs0().findUserByEmail('biml@oimlsmart.org'))!.id
    const envelope = JSON.stringify({ id: 'the-envelope-id', event: 'account.password', account: ownerId, created: new Date().toISOString(), data: { otherSessionsRevoked: 0 } })
    await store.recordWebhookDelivery({
      subscriptionId: created.id, accountId: ownerId, event: 'account.password',
      url: 'https://redeliver.example/hooks', attempts: 3, lastStatus: 500, delivered: false,
      bodyDigest: 'the-digest', recordedAt: new Date(Date.now() - 3_600_000).toISOString(), body: envelope,
    })
    process.env.WEBHOOK_REDELIVERY_TOKEN = 'the-redelivery-bearer'
    try {
      const calls = await pass(async () => new Response('ok', { status: 200 }))
      const res = await app.request(`${ISSUER}/api/op/webhooks/redeliver`, {
        method: 'POST', headers: { authorization: 'Bearer the-redelivery-bearer' },
      })
      expect(res.status).toBe(200)
      expect(await res.json() as { attempted: number; delivered: number; retired: number }).toEqual({ attempted: 1, delivered: 1, retired: 0 })
      expect(calls).toHaveLength(1)
      expect(calls[0]!.url).toBe('https://redeliver.example/hooks')
      expect(calls[0]!.init!.body).toBe(envelope)
      // The fresh signature verifies against the subscription's secret.
      const { verifyWebhookSignature } = await import('../../server/webhooks/signature')
      expect(await verifyWebhookSignature({
        secret: created.secret, header: (calls[0]!.init!.headers as Record<string, string>)['webhook-signature'],
        body: envelope, nowMs: Date.now(), toleranceSec: 300,
      })).toBe(true)
      // The letter retired (no re-entry) and the log carries the outcome.
      const store2 = getStore()
      expect(await store2.listDeadWebhookDeliveries({ olderThan: new Date(Date.now() - 60_000).toISOString(), limit: 100 })).toHaveLength(0)
      const log = await store2.listWebhookDeliveries(ownerId)
      expect(log.some(d => d.delivered === true && d.attempts === 1)).toBe(true)
    } finally {
      delete process.env.WEBHOOK_REDELIVERY_TOKEN
      globalThis.fetch = realFetch
    }
  })

  it('the receiver still down: the pass attempts ONCE and the letter retires regardless (bounded — no storm)', async () => {
    const { getStore } = await import('../../server/store')
    const store = getStore()
    const cookie = await demoLogin('biml@oimlsmart.org')
    const created = ((await (await createSubscription(cookie, 'https://still-down.example/hooks', ['account.password'])).json()) as SubscriptionAnswer)
    const { getStore: gs1 } = await import('../../server/store')
    const ownerId2 = (await gs1().findUserByEmail('biml@oimlsmart.org'))!.id
    await store.recordWebhookDelivery({
      subscriptionId: created.id, accountId: ownerId2, event: 'account.password',
      url: 'https://still-down.example/hooks', attempts: 3, lastStatus: 500, delivered: false,
      bodyDigest: 'digest-2', recordedAt: new Date(Date.now() - 3_600_000).toISOString(), body: '{"id":"e2"}',
    })
    process.env.WEBHOOK_REDELIVERY_TOKEN = 'the-redelivery-bearer'
    try {
      await pass(async () => new Response('nope', { status: 500 }))
      const first = await app.request(`${ISSUER}/api/op/webhooks/redeliver`, {
        method: 'POST', headers: { authorization: 'Bearer the-redelivery-bearer' },
      })
      expect(await first.json() as { attempted: number }).toEqual({ attempted: 1, delivered: 0, retired: 0 })
      globalThis.fetch = (async () => { throw new Error('the pass must not call again') }) as typeof fetch
      const second = await app.request(`${ISSUER}/api/op/webhooks/redeliver`, {
        method: 'POST', headers: { authorization: 'Bearer the-redelivery-bearer' },
      })
      expect(await second.json() as { attempted: number }).toEqual({ attempted: 0, delivered: 0, retired: 0 })
    } finally {
      delete process.env.WEBHOOK_REDELIVERY_TOKEN
      globalThis.fetch = realFetch
    }
  })

  it('a revoked subscription or a body-less legacy letter retires WITHOUT a fetch', async () => {
    const { getStore } = await import('../../server/store')
    const store = getStore()
    const cookie = await demoLogin('biml@oimlsmart.org')
    const created = ((await (await createSubscription(cookie, 'https://revoked.example/hooks', ['account.password'])).json()) as SubscriptionAnswer)
    const { getStore: gs2 } = await import('../../server/store')
    const ownerId3 = (await gs2().findUserByEmail('biml@oimlsmart.org'))!.id
    const revoked = await store.revokeWebhookSubscription(created.id, ownerId3)
    expect(revoked, 'the owner-guarded revoke lands (the test owns the account)').toBe(true)
      await store.recordWebhookDelivery({
        subscriptionId: created.id, accountId: ownerId3, event: 'account.password',
        url: 'https://revoked.example/hooks', attempts: 3, lastStatus: 500, delivered: false,
        bodyDigest: 'digest-3', recordedAt: new Date(Date.now() - 3_600_000).toISOString(), body: '{"id":"e3"}',
      })
      await store.recordWebhookDelivery({
        subscriptionId: created.id, accountId: ownerId3, event: 'account.password',
        url: 'https://legacy.example/hooks', attempts: 3, lastStatus: 500, delivered: false,
        bodyDigest: 'digest-4', recordedAt: new Date(Date.now() - 3_600_000).toISOString(),
      })
    process.env.WEBHOOK_REDELIVERY_TOKEN = 'the-redelivery-bearer'
    try {
      const calls = await pass(async () => new Response('ok', { status: 200 }))
      const res = await app.request(`${ISSUER}/api/op/webhooks/redeliver`, {
        method: 'POST', headers: { authorization: 'Bearer the-redelivery-bearer' },
      })
      expect(await res.json() as { attempted: number; retired: number }).toEqual({ attempted: 0, delivered: 0, retired: 2 })
      expect(calls).toHaveLength(0)
    } finally {
      delete process.env.WEBHOOK_REDELIVERY_TOKEN
      globalThis.fetch = realFetch
    }
  })
})
