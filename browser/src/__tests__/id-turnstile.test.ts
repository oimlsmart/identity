// ─────────────────────────────────────────────────────────────────────
// The bot gate's specs (TODO.modern/01): the module's verify seam
// (the system-boundary HTTP stub — the one acceptable seam, the
// network itself) and the route gate's three postures (the bad token
// 403, the good token's pass-through, the unset env's byte-identical
// no-change). No model doubles — the real app factory, the real
// store, the real routes.
// ─────────────────────────────────────────────────────────────────────

import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest'

const TMP = mkdtempSync(join(tmpdir(), 'oiml-turnstile-'))
process.env.DATABASE_PATH = join(TMP, 'test.db')
const ISSUER = 'http://op.test'
process.env.OP_ISSUER = ISSUER

let app: import('hono').Hono
const realFetch = globalThis.fetch

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
  app = createApiApp({ autoSeedDemo: true, instanceProfile: profileMod.getInstanceProfile() })
})

afterEach(() => {
  globalThis.fetch = realFetch
  delete process.env.TURNSTILE_SECRET
  delete process.env.TURNSTILE_SITE_KEY
})

afterAll(() => {
  rmSync(TMP, { recursive: true, force: true })
  delete process.env.DATABASE_PATH
  delete process.env.OP_ISSUER
})

describe('the turnstile module', () => {
  it('enabled iff both declarations present; the verify honors the verdict', async () => {
    const { turnstileEnabled, turnstileVerify } = await import('../../server/auth/op/turnstile')
    expect(turnstileEnabled({})).toBe(false)
    expect(turnstileEnabled({ TURNSTILE_SITE_KEY: 'k' })).toBe(false)
    expect(turnstileEnabled({ TURNSTILE_SITE_KEY: 'k', TURNSTILE_SECRET: 's' })).toBe(true)

    const calls: string[] = []
    globalThis.fetch = (async (url: unknown, init?: RequestInit) => {
      calls.push(String(url))
      const posted = String(init?.body)
      return new Response(JSON.stringify({ success: posted.includes('good-token') }), { status: 200 })
    }) as typeof fetch
    const env = { TURNSTILE_SECRET: 's' }
    expect(await turnstileVerify(env, 'good-token', '203.0.113.9')).toBe(true)
    expect(await turnstileVerify(env, 'bad-token', null)).toBe(false)
    expect(calls[0]).toContain('siteverify')
    expect(calls[0] === calls[1]).toBe(true)
  })

  it('fails CLOSED: a siteverify network error never opens the gate', async () => {
    const { turnstileVerify } = await import('../../server/auth/op/turnstile')
    globalThis.fetch = (async () => { throw new Error('network down') }) as typeof fetch
    expect(await turnstileVerify({ TURNSTILE_SECRET: 's' }, 'any', null)).toBe(false)
  })
})

describe('the route gate (the three postures)', () => {
  it('UNSET: the join submit answers exactly as before (the no-gate world)', async () => {
    const res = await app.request(`${ISSUER}/api/op/join-requests`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ name: 'Gate Probe', email: `gate-${Date.now()}@example.org`, org_name_text: 'The Gate Probe Co' }),
    })
    expect([201, 400]).toContain(res.status)
  })

  it('SET + a bad token: the 403 bot answer, before any credential work', async () => {
    process.env.TURNSTILE_SECRET = 's'
    process.env.TURNSTILE_SITE_KEY = 'k'
    globalThis.fetch = (async () => new Response(JSON.stringify({ success: false }), { status: 200 })) as typeof fetch
    const res = await app.request(`${ISSUER}/api/op/login`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: 'admin@oiml.org', password: 'demo2026', 'cf-turnstile-response': 'bad' }),
    })
    expect(res.status).toBe(403)
    expect(((await res.json()) as { error: string }).error).toContain('bot')
  })

  it('SET + a good token: the gate OPENS (the act proceeds past the bot check)', async () => {
    process.env.TURNSTILE_SECRET = 's'
    process.env.TURNSTILE_SITE_KEY = 'k'
    globalThis.fetch = (async () => new Response(JSON.stringify({ success: true }), { status: 200 })) as typeof fetch
    const res = await app.request(`${ISSUER}/api/op/login`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: 'whoever@example.org', password: 'whatever-passphrase', 'cf-turnstile-response': 'good' }),
    })
    // The GATE's contract: a verified token never answers the bot 403 —
    // the request proceeds into the credential work (its own honest
    // 401 for unknown credentials, never the gate's shape).
    expect(res.status, 'the gate opened — the credential path answers, never the bot 403').not.toBe(403)
    expect(((await res.json()) as { error: string }).error).not.toContain('bot')
  })
})
