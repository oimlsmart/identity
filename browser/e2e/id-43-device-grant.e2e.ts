// ═══════════════════════════════════════════════════════════════════
// id-43 — the RFC 8628 device authorization grant, booted-stack
// (TODO.ai-platform/10). The in-process lattice lives in
// src/__tests__/id-device-grant.test.ts; THIS leg proves the WIRING on
// a real spawned stack (the app.ts mounts, the astro page build, the
// discovery document) and the full round trip over real HTTP:
//
//   leg 1  the discovery document advertises the device authorization
//          endpoint + the device_code grant (the deliberate golden
//          addition);
//   leg 2  the op-device router is MOUNTED (the app.ts wiring): the
//          page API's context read answers the sign-in bounce (401 +
//          the login URL carrying the page's re-entry), never a 404;
//   leg 3  THE ROUND TRIP over real HTTP: the seeded PUBLIC CLI client's
//          §3.1 ask → the holder's demo sign-in → the page API's
//          context read → the approval → the §3.5 poll delivering the
//          freshly minted personal access token → the RFC 8693 exchange
//          → the scoped OP JWT verified against the stack's own JWKS.
//
// API-only (the op-surface-contract pattern): every OP endpoint this
// drives is served by the Hono app, so no browser — real HTTP on every
// hop. The approval PAGE's own proof is the astro production build
// (the .astro route compiles — the repo's build gate); the island's
// behavior is the API's, proven in-process.
//
// Port-isolated: API 10493 — clear of every live leg (id-16's 10393..
// 10395, the contract gate's 9693/9694, the shared dev stack).
// ═══════════════════════════════════════════════════════════════════

import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import { spawn, type ChildProcess } from 'node:child_process'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { mkdirSync, rmSync } from 'node:fs'
import { delay } from './helpers'
import { fixtureOpSigningKey } from './fixtures/op-signing-key'

const BROWSER_DIR = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const DB_DIR = join(BROWSER_DIR, '.cache', 'id-43-device-grant')

const ID_API = 10493
const ISSUER = `http://localhost:${ID_API}` // the API serves the OP surface directly (app.ts mounts the OP router at the root)

const CLI = { clientId: 'smart-cli', name: 'The OIML SMART CLI' }
const HUB = { clientId: 'hub-instance', name: 'OIML SMART platform hub' }

let api: ChildProcess | undefined
const logs: string[] = []

function killTreeHard(proc: ChildProcess | undefined): void {
  if (!proc || proc.exitCode !== null || proc.pid === undefined) return
  try { process.kill(-proc.pid, 'SIGKILL') } catch { /* group already gone */ }
  try { proc.kill('SIGKILL') } catch { /* already gone */ }
}

async function waitForHttp(url: string, timeoutMs: number): Promise<void> {
  const deadline = Date.now() + timeoutMs
  let lastError = ''
  while (Date.now() < deadline) {
    try {
      const res = await fetch(url)
      if (res.status < 500) return
      lastError = `HTTP ${res.status}`
    } catch (e) {
      lastError = String(e)
    }
    await delay(1_000)
  }
  throw new Error(`timed out waiting for ${url} (${lastError})\n--- stack logs ---\n${logs.join('').slice(-4000)}`)
}

beforeAll(async () => {
  mkdirSync(DB_DIR, { recursive: true })
  const dbPath = join(DB_DIR, 'identity.db')
  for (const suffix of ['', '-wal', '-shm']) rmSync(dbPath + suffix, { force: true })

  try {
    const probe = await fetch(`${ISSUER}/api/health`).catch(() => null)
    if (probe && probe.status < 500) throw new Error(`port ${ID_API} is already serving — a leftover stack? (kill it: lsof -ti tcp:${ID_API} | xargs kill)`)
  } catch (e) {
    if (e instanceof Error && e.message.includes('already serving')) throw e
  }

  // The tsx CLI directly (never npx — the wrapper orphans the server);
  // detached so the process group dies together; the env scrubs the
  // vitest markers and the suite's SSO posture (the id-01 lesson).
  const inherited = Object.fromEntries(
    Object.entries(process.env).filter(([k]) => k !== 'NODE_ENV' && k !== 'VITEST' && !k.startsWith('VITEST_')),
  ) as NodeJS.ProcessEnv
  api = spawn(join(BROWSER_DIR, 'node_modules', '.bin', 'tsx'), ['server/serve.ts'], {
    cwd: BROWSER_DIR,
    env: {
      ...inherited,
      PORT: String(ID_API),
      DATABASE_PATH: dbPath,
      ENTITY_BACKEND: 'server',
      INSTANCE_PROFILE: join(BROWSER_DIR, 'e2e', 'fixtures', 'instance.profile.identity.yaml'),
      OIDC_ISSUER: '',
      OIDC_CLIENT_ID: '',
      DEMO_ACCOUNTS_ENABLED: 'true',
      OP_ISSUER: ISSUER,
      // identity#7: a declared-issuer stack declares its signing key too.
      OP_SIGNING_KEY: await fixtureOpSigningKey(),
      // The registry's bootstrap seed: the PUBLIC CLI client (secretless —
      // the device flow's cone) + the hub (the service the token scopes
      // to).
      OP_CLIENT_SEED: JSON.stringify([
        {
          client_id: CLI.clientId,
          name: CLI.name,
          redirect_uris: [],
          claims_policy: { claims: [] },
        },
        {
          client_id: HUB.clientId,
          name: HUB.name,
          redirect_uris: [`https://${HUB.clientId}.example/callback`],
          claims_policy: { claims: ['roles', 'org'] },
        },
      ]),
    },
    stdio: ['ignore', 'pipe', 'pipe'],
    detached: true,
  })
  api.stdout?.on('data', d => logs.push(String(d)))
  api.stderr?.on('data', d => logs.push(String(d)))

  try {
    await waitForHttp(`${ISSUER}/api/health`, 120_000)
    // Provision the profile's seed (the demo cast + the instance admin).
    const reset = await fetch(`${ISSUER}/api/dev-reset`, { method: 'POST' })
    if (!reset.ok) throw new Error(`dev-reset answered ${reset.status}\n${logs.join('').slice(-2000)}`)
  } catch (e) {
    killTreeHard(api)
    throw e
  }
}, 180_000)

afterAll(() => {
  killTreeHard(api)
})

describe('id-43 — the device authorization grant (RFC 8628), booted-stack', () => {
  it('leg 1: the discovery document advertises the endpoint + the grant', async () => {
    const discovery = await (await fetch(`${ISSUER}/.well-known/openid-configuration`)).json() as {
      device_authorization_endpoint?: string
      grant_types_supported: string[]
    }
    expect(discovery.device_authorization_endpoint).toBe(`${ISSUER}/op/device/authorization`)
    expect(discovery.grant_types_supported).toContain('urn:ietf:params:oauth:grant-type:device_code')
  })

  it('leg 2: the page API is mounted — the session-less read answers the sign-in bounce', async () => {
    // A live ceremony (so the 401 is the SESSION's absence, never the
    // code's): the ask precedes the read.
    const askedRes = await fetch(`${ISSUER}/op/device/authorization`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ client_id: CLI.clientId, scope: `${HUB.clientId}:read` }),
    })
    expect(askedRes.status).toBe(200)
    const asked = await askedRes.json() as { user_code: string }
    const res = await fetch(`${ISSUER}/api/op/device?user_code=${encodeURIComponent(asked.user_code)}`)
    expect(res.status).toBe(401)
    const body = await res.json() as { error: string; login?: string }
    expect(body.error).toBe('authentication_required')
    expect(body.login).toContain(encodeURIComponent(`/op/device?code=${asked.user_code}`))
  })

  it('leg 3: THE ROUND TRIP over real HTTP — ask → approve → poll → PAT → exchange → JWKS-verified JWT', { timeout: 120_000 }, async () => {
    // §3.1 — the CLI's ask.
    const askedRes = await fetch(`${ISSUER}/op/device/authorization`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ client_id: CLI.clientId, scope: `${HUB.clientId}:read ${HUB.clientId}:write` }),
    })
    expect(askedRes.status).toBe(200)
    const asked = await askedRes.json() as {
      device_code: string; user_code: string
      verification_uri: string; verification_uri_complete: string
      expires_in: number; interval: number
    }
    expect(asked.user_code).toMatch(/^[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}$/)
    expect(asked.verification_uri).toBe(`${ISSUER}/op/device`)

    // The holder signs in (the demo cast's IA officer).
    const login = await fetch(`${ISSUER}/api/auth/demo`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: 'ia@oimlsmart.org', password: 'demo2026' }),
    })
    expect(login.ok).toBe(true)
    const cookie = login.headers.get('set-cookie')!.split(';')[0]!

    // The page API's context read + the approval.
    const context = await fetch(`${ISSUER}/api/op/device?user_code=${encodeURIComponent(asked.user_code)}`, { headers: { cookie } })
    expect(context.status).toBe(200)
    const contextBody = await context.json() as { client: { name: string }; scopes: Array<{ action: string }> }
    expect(contextBody.client.name).toBe(CLI.name)
    const approved = await fetch(`${ISSUER}/api/op/device/decide`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ user_code: asked.user_code, decision: 'approve' }),
    })
    expect(approved.status).toBe(200)

    // §3.5 — the poll delivers the freshly minted personal access token.
    const polled = await fetch(`${ISSUER}/op/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
        client_id: CLI.clientId,
        device_code: asked.device_code,
      }),
    })
    expect(polled.status).toBe(200)
    const granted = await polled.json() as { access_token: string; scope: string }
    expect(granted.access_token.startsWith('ospt_'), 'the delivered credential IS the PAT').toBe(true)

    // The PAT exchanges at the RFC 8693 grant — the scoped OP JWT,
    // verified against the stack's own JWKS (the RP's posture).
    const exchanged = await fetch(`${ISSUER}/op/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
        subject_token_type: 'urn:oimlsmart:params:oauth:token-type:pat',
        subject_token: granted.access_token,
      }),
    })
    expect(exchanged.status).toBe(200)
    const { access_token: jwt } = await exchanged.json() as { access_token: string }
    const [h, p, s] = jwt.split('.')
    const decode = (part: string): Record<string, unknown> => {
      const b64 = part.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice(0, (4 - (part.length % 4)) % 4)
      return JSON.parse(Buffer.from(b64, 'base64').toString('utf-8')) as Record<string, unknown>
    }
    const header = decode(h!)
    const jwks = await (await fetch(`${ISSUER}/jwks.json`)).json() as { keys: Array<{ kid?: string; x: string; y: string }> }
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
      Buffer.from(s!.replace(/-/g, '+').replace(/_/g, '/'), 'base64'),
      new TextEncoder().encode(`${h}.${p}`),
    )
    expect(ok, 'the exchanged token verifies against the stack’s JWKS').toBe(true)
    expect(decode(p!).scope).toBe(`${HUB.clientId}:write`) // the ordinal fold (write ⊃ read)
  })
})
