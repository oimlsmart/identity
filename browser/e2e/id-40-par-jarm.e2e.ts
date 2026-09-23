// ═══════════════════════════════════════════════════════════════════
// The PAR + JARM leg (TODO.modern/15) — the FAPI-class authorization
// posture over the REAL booted stack (the id-39 posture: API-only, no
// astro, no browser — real HTTP):
//
//   leg 1  the PUSH (RFC 9126): POST /op/par with the confidential
//          client's Basic auth + the full authorize set (response_mode
//          = jwt among them) answers the request_uri; the browser
//          redirect carries NOTHING else;
//   leg 2  the SIGNED response (RFC 9150): authorize?request_uri=…
//          (the demo session) → the consent allow → the redirect is
//          redirect_uri?response=<JWT> — NO plain code in the query —
//          decoding carries code/state/iss/aud;
//   leg 3  the DECODED code exchanges (PKCE verifier) for the ID
//          token; and the request_uri is single-use (the replay
//          refuses).
//
// SELF-CONTAINED: own port (API 10659 — above id-39's 10655/10657),
// own SQLite file.
// ═══════════════════════════════════════════════════════════════════

import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import { spawn, type ChildProcess } from 'node:child_process'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { mkdirSync, rmSync } from 'node:fs'
import { delay } from './helpers'
import { fixtureOpSigningKey } from './fixtures/op-signing-key'
import { generatePkce } from '../server/oidc'

const BROWSER_DIR = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const FIXTURES = join(BROWSER_DIR, 'e2e', 'fixtures')
const DB_DIR = join(BROWSER_DIR, '.cache', 'id-40')

// Port-isolated: above id-39's 10655/10657.
const ID_API = 10659
const ISSUER = `http://127.0.0.1:${ID_API}`
const API_BASE = ISSUER

const RP = {
  client_id: 'fapi-rp',
  name: 'The FAPI fixture RP',
  secret: 'fapi-rp-secret',
  redirect_uris: ['http://127.0.0.1:10661/callback'],
}
const REDIRECT = RP.redirect_uris[0]!
const BASIC = `Basic ${btoa(`${encodeURIComponent(RP.client_id)}:${encodeURIComponent(RP.secret)}`)}`

let api: ChildProcess | undefined
const logs: string[] = []

function killTreeHard(proc: ChildProcess | undefined): void {
  if (!proc || proc.exitCode !== null || proc.pid === undefined) return
  try { process.kill(-proc.pid, 'SIGKILL') } catch { /* already gone */ }
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

async function apiSignIn(email: string): Promise<string> {
  const login = await fetch(`${API_BASE}/api/auth/demo`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password: 'demo2026' }),
  })
  expect(login.ok, `demo sign-in ${email}`).toBe(true)
  return (login.headers.get('set-cookie') ?? '').split(';')[0]!
}

interface JarmClaims { code?: string; state?: string; iss?: string; aud?: string }

function decodeJarm(response: string): JarmClaims {
  const [, payload] = response.split('.')
  expect(payload, 'the response parameter is a JWT').toBeTruthy()
  return JSON.parse(atob(payload!.replace(/-/g, '+').replace(/_/g, '/'))) as JarmClaims
}

describe('the PAR + JARM leg (TODO.modern/15 — the FAPI posture over the booted stack)', () => {
  beforeAll(async () => {
    mkdirSync(DB_DIR, { recursive: true })
    const dbPath = join(DB_DIR, 'identity.db')
    for (const suffix of ['', '-wal', '-shm']) rmSync(dbPath + suffix, { force: true })

    api = spawn(join(BROWSER_DIR, 'node_modules', '.bin', 'tsx'), ['server/serve.ts'], {
      cwd: BROWSER_DIR,
      env: {
        ...Object.fromEntries(Object.entries(process.env).filter(([k]) => k !== 'NODE_ENV' && k !== 'VITEST' && !k.startsWith('VITEST_'))),
        PORT: String(ID_API),
        DATABASE_PATH: dbPath,
        ENTITY_BACKEND: 'server',
        INSTANCE_PROFILE: join(FIXTURES, 'instance.profile.identity.yaml'),
        OIDC_ISSUER: '',
        OIDC_CLIENT_ID: '',
        DEMO_ACCOUNTS_ENABLED: 'true',
        OP_ISSUER: ISSUER,
        OP_SIGNING_KEY: await fixtureOpSigningKey(),
        OP_CLIENT_SEED: JSON.stringify([RP]),
      } as NodeJS.ProcessEnv,
      stdio: ['ignore', 'pipe', 'pipe'],
      detached: true,
    })
    api.stdout?.on('data', d => logs.push(String(d)))
    api.stderr?.on('data', d => logs.push(String(d)))
    await waitForHttp(`${API_BASE}/api/health`, 120_000)
    const reset = await fetch(`${API_BASE}/api/dev-reset`, { method: 'POST' })
    if (!reset.ok) throw new Error(`dev-reset answered ${reset.status}\n${logs.join('').slice(-2000)}`)
  }, 300_000)

  afterAll(() => {
    killTreeHard(api)
    rmSync(DB_DIR, { recursive: true, force: true })
  })

  it('the push → the signed response → the decoded code exchanges; the request_uri is single-use', async () => {
    const cookie = await apiSignIn('ia@oimlsmart.org')
    const pkce = await generatePkce()

    // Leg 1 — the PUSH (RFC 9126): the whole request on the back channel.
    const push = await fetch(`${API_BASE}/op/par`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', authorization: BASIC },
      body: new URLSearchParams({
        response_type: 'code', redirect_uri: REDIRECT,
        scope: 'openid profile', state: 'st-fapi-e2e', nonce: 'nn-fapi-e2e',
        code_challenge: pkce.challenge, code_challenge_method: 'S256',
        response_mode: 'jwt', prompt: 'consent',
      }),
    })
    expect(push.status, 'the push answers 201').toBe(201)
    const pushed = await push.json() as { request_uri: string; expires_in: number }
    expect(pushed.request_uri).toMatch(/^urn:ietf:params:oauth:request_uri:/)

    // Leg 2 — the authorize carrying ONLY the request_uri.
    const authorize = await fetch(`${API_BASE}/op/authorize?request_uri=${encodeURIComponent(pushed.request_uri)}`, {
      headers: { cookie }, redirect: 'manual',
    })
    expect(authorize.status).toBe(302)
    const consentUrl = new URL(authorize.headers.get('location')!, ISSUER)
    expect(consentUrl.pathname).toBe('/op/consent')
    const authId = consentUrl.searchParams.get('auth')!

    const decide = await fetch(`${API_BASE}/api/op/consent/${authId}/decide`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ decision: 'allow' }),
    })
    expect(decide.ok).toBe(true)
    const { redirect } = await decide.json() as { redirect: string }
    const back = new URL(redirect)
    expect(`${back.origin}${back.pathname}`).toBe(REDIRECT)
    expect(back.searchParams.get('code'), 'NO plain code in the front channel').toBeNull()
    const claims = decodeJarm(back.searchParams.get('response')!)
    expect(claims.state).toBe('st-fapi-e2e')
    expect(claims.iss).toBe(ISSUER)
    expect(claims.aud).toBe(RP.client_id)
    expect(claims.code).toBeTruthy()

    // Leg 3 — the DECODED code exchanges for the ID token.
    const token = await fetch(`${API_BASE}/op/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', authorization: BASIC },
      body: new URLSearchParams({
        grant_type: 'authorization_code', code: claims.code!,
        redirect_uri: REDIRECT, client_id: RP.client_id,
        code_verifier: pkce.verifier,
      }),
    })
    expect(token.status, 'the exchange answers 200').toBe(200)
    const payload = await token.json() as { id_token: string }
    expect(payload.id_token).toBeTruthy()

    // And the request_uri never answers twice (RFC 9126 §5).
    const replay = await fetch(`${API_BASE}/op/authorize?request_uri=${encodeURIComponent(pushed.request_uri)}`, {
      headers: { cookie }, redirect: 'manual',
    })
    expect(replay.status).toBe(400)
  })
})
