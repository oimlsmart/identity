// ─────────────────────────────────────────────────────────────────────
// TODO.modern/06's open half — the per-route freshness gate (the
// "confirm it's you"): the bank-grade acts (the token-scope WIDEN, the
// org-key rotation) demand a recently-authenticated session; a stale
// one refuses with the DISTINCT fresh_auth_required shape (the console
// routes the holder through sign-in again — prompt=login's own path).
// The REAL app factory + the REAL store; staleness is injected by
// backdating the session row itself.
// ─────────────────────────────────────────────────────────────────────

import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import Database from 'better-sqlite3'

const TMP = mkdtempSync(join(tmpdir(), 'oiml-freshauth-'))
process.env.DATABASE_PATH = join(TMP, 'test.db')
const ISSUER = 'http://op.test'
process.env.OP_ISSUER = ISSUER

const HUB = {
  client_id: 'hub-instance',
  name: 'OIML SMART platform hub',
  secret: 'hub-secret-123',
  redirect_uris: ['https://hub.example/api/auth/callback/oidc'],
  claims_policy: { claims: ['roles', 'groups', 'org'] },
}
process.env.OP_CLIENT_SEED = JSON.stringify([HUB])

let app: import('hono').Hono
let backdate: (token: string, secondsAgo: number) => void

async function demoLogin(email: string): Promise<string> {
  const res = await app.request('/api/auth/demo', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password: 'demo2026' }),
  })
  expect(res.ok, `demo login ${email}`).toBe(true)
  return res.headers.get('set-cookie')!.split(';')[0]!
}

/** Mint a PAT for the signed-in account (the read scope — the
 *  widening PATCH will push past it). */
async function mintReadToken(cookie: string): Promise<string> {
  const res = await app.request(`${ISSUER}/api/op/account/tokens`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', cookie },
    body: JSON.stringify({ name: 'the freshness probe', scopes: [`${HUB.client_id}:read`] }),
  })
  expect(res.status, 'the mint answers 201').toBe(201)
  const { token } = await res.json() as { token: { id: string } }
  return token.id
}

async function patchScopes(cookie: string, id: string, scopes: string[]): Promise<{ status: number; body: { code?: string } }> {
  const res = await app.request(`${ISSUER}/api/op/account/tokens/${id}`, {
    method: 'PATCH',
    headers: { 'content-type': 'application/json', cookie },
    body: JSON.stringify({ scopes }),
  })
  return { status: res.status, body: await res.json().catch(() => ({})) }
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

  const raw = new Database(process.env.DATABASE_PATH!)
  backdate = (token: string, secondsAgo: number) => {
    raw.prepare(
      "UPDATE sessions SET created_at = datetime('now', ?) WHERE token = ?",
    ).run(`-${secondsAgo} seconds`, token)
  }
}, 30_000)

afterAll(() => {
  rmSync(TMP, { recursive: true, force: true })
  delete process.env.DATABASE_PATH
  delete process.env.OP_ISSUER
  delete process.env.OP_CLIENT_SEED
})

describe('the widening PATCH demands fresh proof', () => {
  it('a FRESH session widens (the act proceeds)', async () => {
    const cookie = await demoLogin('ia@oimlsmart.org')
    const id = await mintReadToken(cookie)
    const widened = await patchScopes(cookie, id, [`${HUB.client_id}:read`, `${HUB.client_id}:write`])
    expect(widened.status).toBe(200)
  })

  it('a STALE session refuses the widening with the distinct shape', async () => {
    const cookie = await demoLogin('ia@oimlsmart.org')
    const id = await mintReadToken(cookie)
    backdate(cookie.split('=')[1]!, 2 * 60 * 60)
    const refused = await patchScopes(cookie, id, [`${HUB.client_id}:read`, `${HUB.client_id}:write`])
    expect(refused.status).toBe(403)
    expect(refused.body.code).toBe('fresh_auth_required')
    expect(JSON.stringify(refused.body)).toContain('sign in again')
  })

  it('a NARROWING edit is never gated (friction only where the risk is)', async () => {
    const cookie = await demoLogin('ia@oimlsmart.org')
    const id = await mintReadToken(cookie)
    backdate(cookie.split('=')[1]!, 2 * 60 * 60)
    const narrowed = await patchScopes(cookie, id, [`${HUB.client_id}:read`])
    expect(narrowed.status).not.toBe(403)
  })

  it('the rename alone is never gated', async () => {
    const cookie = await demoLogin('ia@oimlsmart.org')
    const id = await mintReadToken(cookie)
    backdate(cookie.split('=')[1]!, 2 * 60 * 60)
    const res = await app.request(`${ISSUER}/api/op/account/tokens/${id}`, {
      method: 'PATCH',
      headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ name: 'a new label' }),
    })
    expect(res.status).not.toBe(403)
  })
})

describe('the org-key rotation demands fresh proof', () => {
  const rotate = (cookie: string) =>
    app.request(`${ISSUER}/api/op/org-keys/some-org/kid-x/rotate`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie },
    })

  it('a STALE session refuses before anything else', async () => {
    const cookie = await demoLogin('ia@oimlsmart.org')
    backdate(cookie.split('=')[1]!, 2 * 60 * 60)
    const res = await rotate(cookie)
    expect(res.status).toBe(403)
    const body = await res.json() as { code?: string }
    expect(body.code).toBe('fresh_auth_required')
  })

  it('a FRESH session proceeds past the freshness gate (its own honest refusal for the unknown key)', async () => {
    const cookie = await demoLogin('ia@oimlsmart.org')
    const res = await rotate(cookie)
    const body = await res.json().catch(() => ({})) as { code?: string }
    expect(body.code).not.toBe('fresh_auth_required')
  })
})
