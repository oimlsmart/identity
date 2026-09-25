// ─────────────────────────────────────────────────────────────────────
// The RFC 8628 device authorization grant (TODO.ai-platform/10 — the
// CLI cone's user-attended bootstrap), proven in-process: the REAL op +
// op-device routers over a REAL temp SQLite store, the demo cast for
// the accounts, and the OP's own JWKS verifying the round trip's end
// (no stub anywhere).
//
// Covered:
//   THE ASK          — POST /op/device/authorization: the §3.2 answer's
//     (the           shape (the codes, the URIs, the bounds); the store
//      authorization row holds ONLY the hashes; the client lattice —
//      endpoint)     unknown (invalid_client), confidential
//                      (unauthorized_client — the code flow is theirs),
//                      the machine classes (unauthorized_client —
//                      client_credentials is theirs); the scope lattice —
//                      absent/malformed/unknown-service/machine-service
//                      all invalid_scope.
//   THE APPROVAL     — the page API: the context read (the honest ask,
//     (the browser   the account, the sign-in bounce), the code lattice
//      leg)          (malformed/unknown/expired/decided), the guarded
//                      decision (a double decides once), the STANDING
//                      judgment (an ask the account cannot hold refuses
//                      403 WITHOUT deciding — the ceremony stays
//                      pending), the audit events on the account's feed.
//   THE POLL         — /op/token's device_code leg: the §3.5 error set
//     (the token     verbatim (authorization_pending, slow_down with the
//      leg)          bumped interval, access_denied, expired_token), the
//                      one-time consume (a replay answers invalid_grant),
//                      the wrong-client invalid_grant, and THE ROUND
//                      TRIP: the approved poll's answer IS the freshly
//                      minted personal access token (the audit names the
//                      device grant + the client), which exchanges at
//                      the RFC 8693 grant for the scoped OP JWT
//                      verified against the OP's own JWKS.
// ─────────────────────────────────────────────────────────────────────

import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

// The store's DB path is read at module evaluation — set it before any
// import below touches the store (the imports are dynamic).
const TMP = mkdtempSync(join(tmpdir(), 'oiml-op-device-'))
process.env.DATABASE_PATH = join(TMP, 'test.db')

const ISSUER = 'http://op.test'
process.env.OP_ISSUER = ISSUER

// The register: the hub (the service the CLI's token scopes to), the
// CLI itself (the PUBLIC client), a confidential application (the code
// flow is theirs), a service-class row + a device-class row (the machine
// classes), and a device-class SERVICE (never a person's scope).
const HUB = { clientId: 'hub-instance', name: 'OIML SMART platform hub', claims: ['roles', 'org'] }
const CLI = { clientId: 'smart-cli', name: 'The OIML SMART CLI', claims: [] }

let app: import('hono').Hono
let store: ReturnType<typeof import('../../server/store').getStore>

async function demoLogin(email: string): Promise<string> {
  const res = await app.request('/api/auth/demo', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password: 'demo2026' }),
  })
  expect(res.ok, `demo login ${email}`).toBe(true)
  return res.headers.get('set-cookie')!.split(';')[0]!
}

/** The §3.1 ask. */
async function ask(body: Record<string, string>): Promise<Response> {
  return app.request(`${ISSUER}/op/device/authorization`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(body),
  })
}

/** The §3.5 poll. */
async function poll(body: Record<string, string>): Promise<Response> {
  return app.request(`${ISSUER}/op/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
      client_id: CLI.clientId,
      ...body,
    }),
  })
}

/** The page API's context read + decision. */
async function context(cookie: string | null, userCode: string): Promise<Response> {
  return app.request(`${ISSUER}/api/op/device?user_code=${encodeURIComponent(userCode)}`, {
    headers: cookie ? { cookie } : {},
  })
}
async function decide(cookie: string, userCode: string, decision: 'approve' | 'deny'): Promise<Response> {
  return app.request(`${ISSUER}/api/op/device/decide`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', cookie },
    body: JSON.stringify({ user_code: userCode, decision }),
  })
}

function base64urlDecode(s: string): Uint8Array {
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice(0, (4 - (s.length % 4)) % 4)
  const bin = atob(b64)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}
function decodePart(s: string): Record<string, unknown> {
  return JSON.parse(new TextDecoder().decode(base64urlDecode(s))) as Record<string, unknown>
}

/** Verify an OP JWT against the OP's OWN JWKS (the RP's posture). */
async function verifyOpJwt(token: string): Promise<Record<string, unknown>> {
  const [h, p, s] = token.split('.')
  expect(s, 'a 3-part JWT').toBeTruthy()
  const header = decodePart(h!)
  const jwks = await (await app.request(`${ISSUER}/jwks.json`)).json() as { keys: Array<{ kid?: string; x: string; y: string }> }
  const jwk = jwks.keys.find(k => k.kid === header.kid)
  expect(jwk, 'the signing key is on the JWKS').toBeTruthy()
  const key = await crypto.subtle.importKey(
    'jwk',
    { kty: 'EC', crv: 'P-256', x: jwk!.x, y: jwk!.y },
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['verify'],
  )
  const ok = await crypto.subtle.verify(
    { name: 'ECDSA', hash: 'SHA-256' },
    key,
    base64urlDecode(s!) as BufferSource,
    new TextEncoder().encode(`${h}.${p}`),
  )
  expect(ok, 'the token verifies against the OP’s JWKS').toBe(true)
  return decodePart(p!)
}

/** The audit journal (the store directly). */
async function journal(): Promise<Array<{ action: string; entity_type: string; entity_id: string; metadata?: Record<string, unknown> }>> {
  return (await store.listEntities('auditEvents')).map(row => JSON.parse(row.data) as never)
}

beforeAll(async () => {
  // The simulated deployment declares its signing key (identity#7's
  // gate: the round trips verify against the JWKS — the production
  // posture).
  const { generateSuccessorPair } = await import('../../scripts/op-key-rotate')
  process.env.OP_SIGNING_KEY = (await generateSuccessorPair()).privateJwkJson

  const { installSqliteStore } = await import('../../server/store/sqlite')
  store = installSqliteStore()
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

  const { Hono } = await import('hono')
  const { createAuthLeanRouter } = await import('../../server/routes/auth-lean')
  const { createOpRouter } = await import('../../server/routes/op')
  const { createOpDeviceRouter } = await import('../../server/routes/op-device')
  const root = new Hono()
  root.route('/api/auth', createAuthLeanRouter({ autoSeedDemo: true }))
  root.route('/', createOpRouter())
  root.route('/', createOpDeviceRouter())
  app = root

  // The register's clients.
  await store.upsertOidcClient({
    clientId: HUB.clientId,
    name: HUB.name,
    secretHash: null,
    redirectUris: [`https://${HUB.clientId}.example/callback`],
    claimsPolicy: { claims: HUB.claims },
    createdBy: 'the test seed',
  })
  await store.upsertOidcClient({
    clientId: CLI.clientId,
    name: CLI.name,
    secretHash: null,
    redirectUris: [],
    claimsPolicy: { claims: CLI.claims },
    createdBy: 'the test seed',
  })
  await store.upsertOidcClient({
    clientId: 'server-app',
    name: 'A server-side application',
    secretHash: 'pbkdf2:1:x:x',
    redirectUris: ['https://server-app.example/callback'],
    claimsPolicy: { claims: [] },
    createdBy: 'the test seed',
  })
  await store.upsertOidcClient({
    clientId: 'svc-exporter',
    name: 'The export machine',
    secretHash: 'pbkdf2:1:x:x',
    redirectUris: [],
    claimsPolicy: { claims: [], class: 'service', service: { id: 'exporter', org: 'oimlsmart', audience: 'exchange', scopes: ['exchange:write'] } } as never,
    createdBy: 'the test seed',
  })
  await store.upsertOidcClient({
    clientId: 'device-acme-lc500-0001',
    name: 'ACME LC-500 (the twin)',
    secretHash: 'pbkdf2:1:x:x',
    redirectUris: [],
    claimsPolicy: { claims: [], class: 'device', device: { id: 'acme-lc500-sn-0001', org: 'mfr-acme', instrument_model: 'acme-lc500@2021' } } as never,
    createdBy: 'the test seed',
  })

  await demoLogin('admin@oimlsmart.org') // the demo cast lands
})

afterAll(() => {
  rmSync(TMP, { recursive: true, force: true })
  delete process.env.OP_ISSUER
  delete process.env.OP_SIGNING_KEY
  delete process.env.DATABASE_PATH
})

// ── the ask (the authorization endpoint) ─────────────────────────────

describe('the ask (POST /op/device/authorization)', () => {
  it('answers §3.2 for the public CLI client — and the store holds ONLY the hashes', async () => {
    const res = await ask({ client_id: CLI.clientId, scope: `${HUB.clientId}:read` })
    expect(res.status).toBe(200)
    const body = await res.json() as {
      device_code: string; user_code: string
      verification_uri: string; verification_uri_complete: string
      expires_in: number; interval: number
    }
    expect(body.user_code).toMatch(/^[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}$/)
    expect(body.verification_uri).toBe(`${ISSUER}/op/device`)
    expect(body.verification_uri_complete).toBe(`${ISSUER}/op/device?code=${encodeURIComponent(body.user_code)}`)
    expect(body.expires_in).toBe(600)
    expect(body.interval).toBe(5)

    // The row: hashes ONLY — never a plaintext code anywhere in it.
    const { hashUserCode } = await import('../../server/auth/op/device-grant')
    const row = await store.findDeviceAuthorizationByUserCodeHash(await hashUserCode(body.user_code))!
    expect(row, 'the user_code resolves its ceremony').toBeTruthy()
    expect(row!.clientId).toBe(CLI.clientId)
    expect(row!.scopes).toEqual([`${HUB.clientId}:read`])
    expect(row!.status).toBe('pending')
    expect(JSON.stringify(row)).not.toContain(body.device_code)
    expect(JSON.stringify(row)).not.toContain(body.user_code)
  })

  it('refuses the client lattice honestly', async () => {
    expect((await ask({ client_id: 'nope', scope: `${HUB.clientId}:read` })).status).toBe(401)
    const confidential = await ask({ client_id: 'server-app', scope: `${HUB.clientId}:read` })
    expect(confidential.status).toBe(400)
    expect(((await confidential.json()) as { error: string }).error).toBe('unauthorized_client')
    for (const machine of ['svc-exporter', 'device-acme-lc500-0001']) {
      const res = await ask({ client_id: machine, scope: `${HUB.clientId}:read` })
      expect(res.status, `${machine} is the machine cone`).toBe(400)
      expect(((await res.json()) as { error: string }).error).toBe('unauthorized_client')
    }
  })

  it('refuses the scope lattice honestly', async () => {
    expect(((await (await ask({ client_id: CLI.clientId, scope: '' })).json()) as { error: string }).error).toBe('invalid_scope')
    expect(((await (await ask({ client_id: CLI.clientId, scope: 'openid profile' })).json()) as { error: string }).error).toBe('invalid_scope')
    expect(((await (await ask({ client_id: CLI.clientId, scope: 'no-such-service:read' })).json()) as { error: string }).error).toBe('invalid_scope')
    expect(((await (await ask({ client_id: CLI.clientId, scope: 'device-acme-lc500-0001:read' })).json()) as { error: string }).error).toBe('invalid_scope')
  })
})

// ── the approval (the browser leg) ───────────────────────────────────

describe('the approval (the page API)', () => {
  it('reads the honest context, bounces the session-less, and refuses the code lattice', async () => {
    const cookie = await demoLogin('ia@oimlsmart.org')
    const asked = await (await ask({ client_id: CLI.clientId, scope: `${HUB.clientId}:read ${HUB.clientId}:write` })).json() as { user_code: string }

    const noSession = await context(null, asked.user_code)
    expect(noSession.status).toBe(401)
    const bounce = await noSession.json() as { login?: string }
    expect(bounce.login).toContain(encodeURIComponent(`/op/device?code=${asked.user_code}`))

    expect((await context(cookie, 'xx')).status, 'a malformed entry reads 400').toBe(400)
    expect((await context(cookie, 'WDJB-MJHT')).status).toBe(404)

    const ok = await context(cookie, asked.user_code)
    expect(ok.status).toBe(200)
    const body = await ok.json() as {
      client: { id: string; name: string }
      scopes: Array<{ service: string; name: string; action: string }>
      account: { email: string }
    }
    expect(body.client.name).toBe(CLI.name)
    // The PAT grammar's ordinal fold: read + write on the ONE service
    // collapses to the widest class (write ⊃ read — patScopeCovers' own
    // rule), so the ask shows a single honest row.
    expect(body.scopes).toEqual([
      { service: HUB.clientId, name: HUB.name, action: 'write' },
    ])
    expect(body.account.email).toBe('ia@oimlsmart.org')
    // The Crockford aliases fold (the holder's keyboard reality).
    const aliased = asked.user_code.toLowerCase().replace(/1/g, 'l')
    expect((await context(cookie, aliased)).status, 'the entered aliases resolve').toBe(200)
  })

  it('approves once: the guarded flip binds the account, the audit lands, a double decision 409s', async () => {
    const cookie = await demoLogin('ia@oimlsmart.org')
    const asked = await (await ask({ client_id: CLI.clientId, scope: `${HUB.clientId}:read` })).json() as { user_code: string }
    const approved = await decide(cookie, asked.user_code, 'approve')
    expect(approved.status).toBe(200)
    expect((await decide(cookie, asked.user_code, 'approve')).status).toBe(409)
    expect((await context(cookie, asked.user_code)).status).toBe(409)

    const { hashUserCode } = await import('../../server/auth/op/device-grant')
    const row = await store.findDeviceAuthorizationByUserCodeHash(await hashUserCode(asked.user_code))
    expect(row!.status).toBe('approved')
    expect(row!.userId, 'the approval bound the account').toBeTruthy()
    const events = (await journal()).filter(e => e.action === 'account.device_grant_approved')
    expect(events.length).toBe(1)
    expect(events[0]!.metadata!.client).toBe(CLI.clientId)
  })

  it('denies: the poll answers access_denied', async () => {
    const cookie = await demoLogin('ia@oimlsmart.org')
    const asked = await (await ask({ client_id: CLI.clientId, scope: `${HUB.clientId}:read` })).json() as { device_code: string; user_code: string }
    expect((await decide(cookie, asked.user_code, 'deny')).status).toBe(200)
    const res = await poll({ device_code: asked.device_code })
    expect(res.status).toBe(400)
    expect(((await res.json()) as { error: string }).error).toBe('access_denied')
    const events = (await journal()).filter(e => e.action === 'account.device_grant_denied')
    expect(events.length).toBe(1)
  })

  it('refuses the ask the account cannot hold WITHOUT deciding — the ceremony stays pending', async () => {
    const viewer = await demoLogin('viewer@oimlsmart.org')
    const officer = await demoLogin('ia@oimlsmart.org')
    const asked = await (await ask({ client_id: CLI.clientId, scope: `${HUB.clientId}:write` })).json() as { device_code: string; user_code: string }
    const refused = await decide(viewer, asked.user_code, 'approve')
    expect(refused.status).toBe(403)
    expect(((await refused.json()) as { error: string }).error).toBe('scope_standing')
    // Still pending — the officer's approval (same code, while it lives) lands.
    expect((await decide(officer, asked.user_code, 'approve')).status).toBe(200)
    const res = await poll({ device_code: asked.device_code })
    expect(res.status).toBe(200)
  })
})

// ── the poll (the token leg) ─────────────────────────────────────────

describe('the poll (POST /op/token, the device_code leg)', () => {
  it('speaks §3.5: pending, then the slow_down with the bumped interval', async () => {
    const asked = await (await ask({ client_id: CLI.clientId, scope: `${HUB.clientId}:read` })).json() as { device_code: string }
    const first = await poll({ device_code: asked.device_code })
    expect(((await first.json()) as { error: string }).error).toBe('authorization_pending')
    const fast = await poll({ device_code: asked.device_code })
    expect(((await fast.json()) as { error: string }).error).toBe('slow_down')
    const { hashDeviceCode } = await import('../../server/auth/op/device-grant')
    const row = await store.findDeviceAuthorizationByDeviceCodeHash(await hashDeviceCode(asked.device_code))
    expect(row!.intervalSeconds, 'the interval grew by the increment').toBe(10)
  })

  it('refuses a foreign client + an unknown code with invalid_grant', async () => {
    const asked = await (await ask({ client_id: CLI.clientId, scope: `${HUB.clientId}:read` })).json() as { device_code: string }
    expect(((await (await poll({ device_code: 'never-issued' })).json()) as { error: string }).error).toBe('invalid_grant')
    const foreign = await app.request(`${ISSUER}/op/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
        client_id: HUB.clientId, // a real client, but not the ceremony's
        device_code: asked.device_code,
      }),
    })
    expect(((await foreign.json()) as { error: string }).error).toBe('invalid_grant')
  })

  it('answers an expired ceremony with expired_token (the context reads 410)', async () => {
    // The ceremony minted straight into the past (the store seam).
    const { mintDeviceCode, mintUserCode, hashDeviceCode, hashUserCode } = await import('../../server/auth/op/device-grant')
    const deviceCode = mintDeviceCode()
    const userCode = mintUserCode()
    await store.createDeviceAuthorization({
      id: crypto.randomUUID(),
      deviceCodeHash: await hashDeviceCode(deviceCode),
      userCodeHash: await hashUserCode(userCode),
      clientId: CLI.clientId,
      scopes: [`${HUB.clientId}:read`],
      intervalSeconds: 5,
      expiresAt: new Date(Date.now() - 1000).toISOString(),
    })
    expect(((await (await poll({ device_code: deviceCode })).json()) as { error: string }).error).toBe('expired_token')
    const cookie = await demoLogin('ia@oimlsmart.org')
    expect((await context(cookie, userCode)).status).toBe(410)
  })

  it('THE ROUND TRIP: the approved poll delivers the PAT, the audit names the grant, the PAT exchanges against the JWKS — once', async () => {
    const cookie = await demoLogin('ia@oimlsmart.org')
    const asked = await (await ask({ client_id: CLI.clientId, scope: `${HUB.clientId}:read ${HUB.clientId}:write` })).json() as { device_code: string; user_code: string }
    expect((await decide(cookie, asked.user_code, 'approve')).status).toBe(200)

    const res = await poll({ device_code: asked.device_code })
    expect(res.status).toBe(200)
    const body = await res.json() as { access_token: string; token_type: string; expires_in: number; scope: string }
    expect(body.access_token.startsWith('ospt_'), 'the delivered credential IS the personal access token').toBe(true)
    // The ordinal fold (read + write on the one service → write).
    expect(body.scope).toBe(`${HUB.clientId}:write`)
    expect(body.expires_in).toBeGreaterThan(80 * 86_400) // ~90 days

    // The row: the PAT cone's own shape — the name names the client, the
    // permissions cone is empty (a console act), the audit names the
    // device grant + the client.
    const pats = await store.listPersonalAccessTokens((await store.findDeviceAuthorizationByUserCodeHash(
      await (await import('../../server/auth/op/device-grant')).hashUserCode(asked.user_code),
    ))!.userId!)
    const pat = pats.find(p => p.name.includes(CLI.name))!
    expect(pat.name).toContain('device grant')
    expect(pat.permissions).toEqual([])
    expect(JSON.stringify(pat)).not.toContain(body.access_token)
    const mints = (await journal()).filter(e => e.action === 'account.pat_minted' && e.metadata!.via === 'device_grant' && e.metadata!.pat === pat.id)
    expect(mints.length).toBe(1)
    expect(mints[0]!.metadata!.client).toBe(CLI.clientId)

    // The replay: consumed ONCE.
    expect(((await (await poll({ device_code: asked.device_code })).json()) as { error: string }).error).toBe('invalid_grant')

    // The delivered PAT exchanges at the RFC 8693 grant — the scoped OP
    // JWT verified against the OP's own JWKS (the full wire truth).
    const exchanged = await app.request(`${ISSUER}/op/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
        subject_token_type: 'urn:oimlsmart:params:oauth:token-type:pat',
        subject_token: body.access_token,
      }),
    })
    expect(exchanged.status).toBe(200)
    const exchangedBody = await exchanged.json() as { access_token: string }
    const claims = await verifyOpJwt(exchangedBody.access_token)
    expect(claims.scope).toBe(`${HUB.clientId}:write`)
    expect(claims.pat).toBe(pat.id)
    expect(claims.aud).toEqual([HUB.clientId])
  })
})
