// ─────────────────────────────────────────────────────────────────────
// TODO.modern/07 — the typed SDK's consumer proof: the generated
// client (sdk/gen, regenerated from the drift-gated spec — never
// hand-edited) drives REAL documented operations through the
// in-process app; the posture layer (sdk/identity-client.ts) proves
// both auth postures (the PAT exchange; the bearer rider). The
// compile is part of the proof: a mistyped operation or claim fails
// vue-tsc, not production.
// ─────────────────────────────────────────────────────────────────────

import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest'

const TMP = mkdtempSync(join(tmpdir(), 'oiml-sdk-'))
process.env.DATABASE_PATH = join(TMP, 'test.db')
const ISSUER = 'http://op.test'
process.env.OP_ISSUER = ISSUER

let app: import('hono').Hono
const realFetch = globalThis.fetch

const routeIntoApp = (async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
  return app.request(new Request(input, init))
}) as typeof fetch

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
  app = createApiApp({ autoSeedDemo: false, instanceProfile: profileMod.getInstanceProfile() })
  // The generated client rides the same origin — route its fetch into
  // the in-process app (the system-boundary stub: the network itself).
  // new Request normalizes the hey-api client's Request-object form.
  globalThis.fetch = routeIntoApp
})

afterEach(() => {
  globalThis.fetch = routeIntoApp
})

afterAll(() => {
  globalThis.fetch = realFetch
  rmSync(TMP, { recursive: true, force: true })
  delete process.env.DATABASE_PATH
  delete process.env.OP_ISSUER
})

describe('the generated SDK (sdk/gen — regenerate, never hand-edit)', () => {
  it('drives a real documented GET with the spec\'s types', async () => {
    const { getDiscovery } = await import('../../sdk/gen/sdk.gen')
    const { data, response } = await getDiscovery()
    expect(response!.status).toBe(200)
    // `data` is TYPED from the spec — the discovery document's shape.
    expect(data!.issuer).toBe(ISSUER)
    expect(data!.token_endpoint).toContain('/op/token')
  })

  it('the PAT exchange helper speaks the token exchange exactly', async () => {
    const calls: Array<{ url: string; init?: RequestInit }> = []
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url
      calls.push({ url, init })
      return new Response(JSON.stringify({ access_token: 'jwt-x', token_type: 'N_A', expires_in: 3600, scope: 'openid profile' }), { status: 200 })
    }) as typeof fetch

    const { patAccessToken } = await import('../../sdk/identity-client')
    const granted = await patAccessToken({ baseUrl: ISSUER, pat: 'ospt_test', scope: 'openid profile' })
    expect(granted).toEqual({ accessToken: 'jwt-x', tokenType: 'N_A', expiresInSeconds: 3600 })

    expect(calls[0]!.url).toBe(`${ISSUER}/op/token`)
    const body = String(calls[0]!.init!.body)
    expect(body).toContain('grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange')
    expect(body).toContain('subject_token_type=urn%3Aoimlsmart%3Aparams%3Aoauth%3Atoken-type%3Apat')
    expect(body).toContain('subject_token=ospt_test')
    expect(body).toContain('scope=openid+profile')
  })

  it('the PAT exchange refuses honestly (no token minted)', async () => {
    globalThis.fetch = (async () => new Response(JSON.stringify({ error: 'invalid_grant' }), { status: 400 })) as typeof fetch
    const { patAccessToken } = await import('../../sdk/identity-client')
    await expect(patAccessToken({ baseUrl: ISSUER, pat: 'ospt_dead' })).rejects.toThrow(/400/)
  })

  it('the bearer rider attaches the exchanged token to every call', async () => {
    const seen: string[] = []
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      seen.push(new Request(input, init).headers.get('authorization') ?? '')
      return new Response(JSON.stringify({ error: 'no token' }), { status: 401 })
    }) as typeof fetch

    const { createBearerClient } = await import('../../sdk/identity-client')
    const bearer = createBearerClient({ baseUrl: ISSUER, accessToken: 'jwt-x' })
    await bearer.get({ url: '/op/userinfo' })
    expect(seen[0]).toBe('Bearer jwt-x')
  })
})
