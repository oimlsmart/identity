// ═══════════════════════════════════════════════════════════════════
// The machine cone's GENERAL half — the service class (TODO.identity-
// ops/07), the e2e (the identity-profile stack, the id-19 spawned-stack
// pattern — its own API + its own astro, its own SQLite file):
//
//   leg 1  the SEEDED service client stands (the bootstrap seed accepts
//          the class): the admin API's view carries the class + the
//          service block, never the human-cone fields;
//   leg 2  the admin registers a SECOND service client through the
//          CONSOLE (the form's service mode renders honestly: the class
//          picker, the binding fieldset — the id, the org select
//          carrying the registry's mfr-acme, the audience, the scope
//          allowlist —, the confidential note; no redirect-URI/claims/
//          SSO-home fieldsets), the generated secret shown once, the row
//          rendering the service badge + the service line (no launch
//          line, no URIs list);
//   leg 3  the GRANT for real: both service clients mint the self-
//          contained service JWT at /op/token (client_credentials), the
//          claims verified against the OP's own JWKS (sub = the service
//          id, aud = the DECLARED audience — the audience binding the
//          device class does not have —, client_id, org, scope; never
//          an ID token, never a user claim) — and the scope NARROWING
//          (a subset mints the narrowed token; a scope beyond the
//          allowlist refuses invalid_scope);
//   leg 4  the refusals: the application class never speaks
//          client_credentials (the pre-machine answer), the bare probe
//          keeps the golden's shape, refresh_token refuses, the
//          authorization-code flow refuses the service at /op/authorize
//          IN PLACE;
//   leg 5  the ROTATION through the console (the re-key: the old secret
//          refuses, the new mints), the REVOCATION (the disable: the
//          grant 401s), and the audit chain carrying the arc naming the
//          service + the audience.
//
// SELF-CONTAINED: the suite's shared stack (E2E_BASE_URL) is untouched —
// the identity instance boots on its own ports (API 10601 / astro
// 10602) with its own SQLite file.
// ═══════════════════════════════════════════════════════════════════

import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import puppeteer, { type Browser, type Page } from 'puppeteer'
import { spawn, type ChildProcess } from 'node:child_process'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { existsSync, mkdirSync, rmSync, cpSync } from 'node:fs'
import { closeBrowser, delay } from './helpers'
import { fixtureOpSigningKey } from './fixtures/op-signing-key'

const BROWSER_DIR = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const FIXTURES = join(BROWSER_DIR, 'e2e', 'fixtures')
const DB_DIR = join(BROWSER_DIR, '.cache', 'id-22')

// Port-isolated: above every declared e2e stack (…10600 is id-21's) and
// the local dev loops.
const ID_API = 10601
const ID_WEB = 10602

const ADMIN_EMAIL = 'admin@oiml.org'

// The service binding's org: the demonstration manufacturer on the
// profile's org registry seed (the same org id-19's device binds).
const SERVICE_ORG = 'mfr-acme'
// The reference caller (TODO.identity-ops/07's): the RAG's MCP ingest
// pipeline — a confidential client, no redirect URIs, an audience-bound
// token, a scoped claim set.
const SERVICE_AUDIENCE = 'oiml-rag-mcp'
const SERVICE_SCOPES = ['documents:read', 'ingest:write']

// The bootstrap seed's service client (leg 1) — the seed accepts the
// class — plus the hub (the application class: the grant-refusal legs'
// confidential RP).
const SEEDED_SERVICE = {
  client_id: 'svc-rag-mcp-ingest',
  name: 'The RAG’s MCP ingest pipeline (the seed)',
  class: 'service',
  service: { id: 'rag-mcp-ingest', org: SERVICE_ORG, audience: SERVICE_AUDIENCE, scopes: SERVICE_SCOPES },
  secret: 'the-seeded-service-secret-demo',
}
const HUB = {
  client_id: 'hub-instance',
  name: 'OIML SMART platform hub',
  secret: 'hub-secret-123',
  redirect_uris: ['https://hub.example/api/auth/callback/oidc'],
  claims_policy: { claims: ['roles', 'groups', 'org'] },
  launch: { url: 'https://hub.example/api/auth/signin/oidc', icon: 'grid', description: 'The certification hub.', visibility: 'open' },
}
// The console-registered service client (leg 2).
const CONSOLE_SERVICE = {
  clientId: 'svc-nightly-reconcile',
  name: 'The nightly reconciliation job',
  service: { id: 'nightly-reconcile', org: SERVICE_ORG, audience: 'oiml-smart-platform', scopes: ['reconcile:run', 'reports:read'] },
}

interface Stack {
  api: ChildProcess
  astro: ChildProcess
  base: string
  apiBase: string
  logs: string[]
}

function spawnLogged(cmd: string, args: string[], env: NodeJS.ProcessEnv, logs: string[]): ChildProcess {
  // detached (the process group dies together — the tsx CLI wrapper
  // lesson); the env SCRUBS the vitest markers (NODE_ENV=test would
  // poison the spawned astro's vite cache hash).
  const inherited = Object.fromEntries(
    Object.entries(process.env).filter(([k]) => k !== 'NODE_ENV' && k !== 'VITEST' && !k.startsWith('VITEST_')),
  ) as NodeJS.ProcessEnv
  const proc = spawn(cmd, args, {
    cwd: BROWSER_DIR,
    env: { ...inherited, ...env },
    stdio: ['ignore', 'pipe', 'pipe'],
    detached: true,
  })
  proc.stdout?.on('data', d => logs.push(String(d)))
  proc.stderr?.on('data', d => logs.push(String(d)))
  return proc
}

function killTree(proc: ChildProcess | undefined): void {
  if (!proc || proc.exitCode !== null || proc.pid === undefined) return
  try { process.kill(-proc.pid, 'SIGTERM') } catch { /* group already gone */ }
  try { proc.kill('SIGTERM') } catch { /* already gone */ }
}

function killTreeHard(proc: ChildProcess | undefined): void {
  if (!proc || proc.exitCode === null || proc.pid === undefined) return
  try { process.kill(-proc.pid, 'SIGKILL') } catch { /* group already gone */ }
  try { proc.kill('SIGKILL') } catch { /* already gone */ }
}

async function waitForHttp(url: string, timeoutMs: number, logs: string[], exact200 = false): Promise<void> {
  const deadline = Date.now() + timeoutMs
  let lastError = ''
  while (Date.now() < deadline) {
    try {
      const res = await fetch(url)
      if (exact200 ? res.status === 200 : res.status < 500) return
      lastError = `HTTP ${res.status}`
    } catch (e) {
      lastError = String(e)
    }
    await delay(1_000)
  }
  throw new Error(`timed out waiting for ${url} (${lastError})\n--- stack logs ---\n${logs.join('').slice(-4000)}`)
}

/** Boot the identity-profile stack (the id-19 posture), the client
 *  registry's bootstrap seed carrying the hub + the service-class entry. */
async function bootIdentityStack(): Promise<Stack> {
  const logs: string[] = []
  mkdirSync(DB_DIR, { recursive: true })
  const dbPath = join(DB_DIR, 'identity.db')
  for (const suffix of ['', '-wal', '-shm']) rmSync(dbPath + suffix, { force: true })

  let api: ChildProcess | undefined
  let astro: ChildProcess | undefined
  const reap = () => {
    for (const proc of [astro, api]) killTreeHard(proc)
  }

  try {
    for (const probe of [`http://localhost:${ID_API}/api/health`, `http://localhost:${ID_WEB}/`]) {
      try {
        const res = await fetch(probe)
        if (res.status < 500) throw new Error(`port for ${probe} is already serving — a leftover stack? (kill it: lsof -ti tcp:${new URL(probe).port} | xargs kill)`)
      } catch (e) {
        if (e instanceof Error && e.message.includes('already serving')) throw e
      }
    }

    api = spawnLogged(join(BROWSER_DIR, 'node_modules', '.bin', 'tsx'), ['server/serve.ts'], {
      PORT: String(ID_API),
      DATABASE_PATH: dbPath,
      ENTITY_BACKEND: 'server',
      INSTANCE_PROFILE: join(FIXTURES, 'instance.profile.identity.yaml'),
      OIDC_ISSUER: '',
      OIDC_CLIENT_ID: '',
      DEMO_ACCOUNTS_ENABLED: 'true',
      OP_ISSUER: `http://localhost:${ID_WEB}`,
      OP_SIGNING_KEY: await fixtureOpSigningKey(),
      OP_CLIENT_SEED: JSON.stringify([HUB, SEEDED_SERVICE]),
    }, logs)
    const apiBase = `http://localhost:${ID_API}`
    await waitForHttp(`${apiBase}/api/health`, 120_000, logs)

    // Provision the profile's seed (the demo cast + the org registry —
    // mfr-acme among it). The client seed rides the OP router's own
    // bootstrap latch (dev-reset never touches oidc_clients).
    const reset = await fetch(`${apiBase}/api/dev-reset`, { method: 'POST' })
    if (!reset.ok) throw new Error(`dev-reset on ${apiBase} answered ${reset.status}\n${logs.join('').slice(-2000)}`)

    const stackViteCache = join(DB_DIR, `vite-${ID_WEB}`)
    const sharedViteCache = join(BROWSER_DIR, 'node_modules', '.vite')
    if (existsSync(sharedViteCache)) {
      rmSync(stackViteCache, { recursive: true, force: true })
      cpSync(sharedViteCache, stackViteCache, { recursive: true })
    }
    astro = spawnLogged(join(BROWSER_DIR, 'node_modules', '.bin', 'astro'), ['dev', '--port', String(ID_WEB), '--ignore-lock'], {
      API_ORIGIN: apiBase,
      VITE_CACHE_DIR: stackViteCache,
      DEV_PUBLIC_HOST: `localhost:${ID_WEB}`,
    }, logs)
    const base = `http://localhost:${ID_WEB}`
    await waitForHttp(`${base}/`, 240_000, logs)
    await waitForHttp(`${base}/op/join`, 240_000, logs, true)
    return { api, astro, base, apiBase, logs }
  } catch (e) {
    reap()
    throw e
  }
}

async function stopStack(stack: Stack | undefined): Promise<void> {
  if (!stack) return
  for (const proc of [stack.astro, stack.api]) killTree(proc)
  await delay(1_500)
  for (const proc of [stack.astro, stack.api]) killTreeHard(proc)
}

const SETTLE = 240_000 // spawned astro compiles page chunks cold on first hit

/** Sign in through the demo cast (DEMO_ACCOUNTS_ENABLED=true). */
async function opSignIn(page: Page, email: string): Promise<void> {
  await page.waitForSelector('[data-testid="login-email"]', { timeout: SETTLE, polling: 500 })
  await page.evaluate(() => {
    (document.querySelector('[data-testid="login-email"]') as HTMLInputElement).value = ''
  })
  await page.type('[data-testid="login-email"]', email)
  await page.type('[data-testid="login-password"]', 'demo2026')
  await page.evaluate(() => (document.querySelector('[data-testid="login-submit"]') as HTMLElement).click())
}

/** A fetch-level demo sign-in against the stack (the acts that never
 *  need a browser). */
async function apiSignIn(apiBase: string, email: string): Promise<string> {
  const login = await fetch(`${apiBase}/api/auth/demo`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password: 'demo2026' }),
  })
  expect(login.ok, `demo sign-in ${email}`).toBe(true)
  return (login.headers.get('set-cookie') ?? '').split(';')[0]!
}

/** The service grant (client_credentials, client_secret_basic), with the
 *  optional RFC 6749 §4.4 scope narrowing. */
async function mintServiceToken(apiBase: string, clientId: string, secret: string, scope?: string): Promise<Response> {
  return fetch(`${apiBase}/op/token`, {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      authorization: `Basic ${btoa(`${encodeURIComponent(clientId)}:${encodeURIComponent(secret)}`)}`,
    },
    body: scope === undefined ? 'grant_type=client_credentials' : `grant_type=client_credentials&scope=${encodeURIComponent(scope)}`,
  })
}

function base64urlDecode(s: string): Uint8Array {
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice(0, (4 - (s.length % 4)) % 4)
  const bin = atob(b64)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

/** Verify the service JWT against the stack's OWN JWKS (the called
 *  service's posture) and answer its claims. */
async function verifyServiceJwt(apiBase: string, token: string): Promise<Record<string, unknown>> {
  const [h, p, s] = token.split('.')
  expect(s, 'a 3-part JWT').toBeTruthy()
  const header = JSON.parse(new TextDecoder().decode(base64urlDecode(h!))) as { kid: string }
  const jwks = await (await fetch(`${apiBase}/jwks.json`)).json() as { keys: Array<{ kid?: string; x: string; y: string }> }
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
  expect(ok, 'the service token verifies against the OP’s JWKS').toBe(true)
  return JSON.parse(new TextDecoder().decode(base64urlDecode(p!))) as Record<string, unknown>
}

describe('the machine cone’s service class (the identity profile)', () => {
  let stack: Stack
  let browser: Browser
  let page: Page
  let consoleSecret = ''

  beforeAll(async () => {
    stack = await bootIdentityStack()
    browser = await puppeteer.launch({ headless: 'shell', protocolTimeout: 480_000, args: ['--no-sandbox', '--disable-setuid-sandbox'] })
    page = await browser.newPage()
    await page.setViewport({ width: 1440, height: 900 })
    page.on('pageerror', e => console.log('[pageerror]', String(e).slice(0, 300)))
    page.on('requestfailed', r => console.log('[requestfailed]', r.url().slice(0, 140), r.failure()?.errorText ?? ''))
  }, 600_000)

  afterAll(async () => {
    await closeBrowser(browser)
    await stopStack(stack)
  })

  it('leg 1 — the bootstrap seed accepts the class: the seeded service client stands, honestly shaped', { timeout: 900_000 }, async () => {
    const admin = await apiSignIn(stack.apiBase, ADMIN_EMAIL)
    const list = await (await fetch(`${stack.apiBase}/api/op/clients`, { headers: { cookie: admin } })).json() as Array<Record<string, any>>
    const seeded = list.find(r => r.clientId === SEEDED_SERVICE.client_id)
    expect(seeded, 'the seeded service client is on the registry').toBeTruthy()
    expect(seeded.class).toBe('service')
    expect(seeded.service).toEqual(SEEDED_SERVICE.service)
    expect(seeded.device, 'never the device block').toBeNull()
    expect(seeded.confidential).toBe(true)
    expect(seeded.redirectUris).toEqual([])
    expect(seeded.launch).toBeNull()
    expect(seeded.claimsPolicy.claims).toEqual([])
    // The hub seeds as the APPLICATION class, its launch card intact.
    const hub = list.find(r => r.clientId === HUB.client_id)
    expect(hub.class).toBe('application')
    expect(hub.launch?.url).toBe(HUB.launch.url)
  })

  it('leg 2 — the console registers the second service client, the form’s service mode honest throughout', { timeout: 900_000 }, async () => {
    await page.goto(`${stack.base}/`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await opSignIn(page, ADMIN_EMAIL)
    await page.waitForFunction(() => window.location.pathname !== '/', { timeout: SETTLE, polling: 500 })
    await page.goto(`${stack.base}/op/admin/clients`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await page.waitForSelector('[data-testid="op-client-form"]', { timeout: SETTLE, polling: 500 })

    // The service mode: the class picker swaps the fieldsets honestly.
    await page.select('[data-testid="op-client-field-class"]', 'service')
    await page.waitForSelector('[data-testid="op-client-field-service"]', { timeout: SETTLE, polling: 500 })
    // The human-cone fieldsets never render in the service mode (and the
    // device binding stays the device class's own).
    expect(await page.$('[data-testid="op-client-field-uris"]')).toBeNull()
    expect(await page.$('[data-testid="op-client-field-claims"]')).toBeNull()
    expect(await page.$('[data-testid="op-client-field-launch-on"]')).toBeNull()
    expect(await page.$('[data-testid="op-client-field-confidential"]')).toBeNull()
    expect(await page.$('[data-testid="op-client-field-device"]')).toBeNull()
    await page.waitForSelector('[data-testid="op-client-field-service-confidential"]', { timeout: SETTLE, polling: 500 })
    // The org select rides the organization registry (mfr-acme among it).
    await page.waitForSelector(`[data-testid="op-client-service-org-${SERVICE_ORG}"]`, { timeout: SETTLE, polling: 500 })

    await page.type('[data-testid="op-client-field-id"]', CONSOLE_SERVICE.clientId)
    await page.type('[data-testid="op-client-field-name"]', CONSOLE_SERVICE.name)
    await page.type('[data-testid="op-client-field-service-id"]', CONSOLE_SERVICE.service.id)
    await page.select('[data-testid="op-client-field-service-org"]', SERVICE_ORG)
    await page.type('[data-testid="op-client-field-service-audience"]', CONSOLE_SERVICE.service.audience)
    await page.type('[data-testid="op-client-field-service-scopes"]', CONSOLE_SERVICE.service.scopes.join(' '))
    await page.evaluate(() => (document.querySelector('[data-testid="op-client-save"]') as HTMLElement).click())

    // The generated secret shows exactly ONCE.
    await page.waitForSelector('[data-testid="op-client-secret"]', { timeout: SETTLE, polling: 500 })
    consoleSecret = await page.$eval('[data-testid="op-client-secret"]', el => el.textContent ?? '')
    expect(consoleSecret.length).toBeGreaterThan(20)

    // The row renders the class honestly: the service badge + the service
    // line — no launch line, no URIs list.
    await page.waitForSelector(`[data-testid="op-client-class-${CONSOLE_SERVICE.clientId}"]`, { timeout: SETTLE, polling: 500 })
    const serviceLine = await page.$eval(`[data-testid="op-client-service-${CONSOLE_SERVICE.clientId}"]`, el => el.textContent ?? '')
    expect(serviceLine).toContain(CONSOLE_SERVICE.service.id)
    expect(serviceLine).toContain(SERVICE_ORG)
    expect(serviceLine).toContain(CONSOLE_SERVICE.service.audience)
    expect(serviceLine).toContain(CONSOLE_SERVICE.service.scopes.join(' '))
    expect(await page.$(`[data-testid="op-client-launch-${CONSOLE_SERVICE.clientId}"]`)).toBeNull()
    expect(await page.$(`[data-testid="op-client-uris-${CONSOLE_SERVICE.clientId}"]`)).toBeNull()
  })

  it('leg 3 — the grant for real: both service clients mint the JWKS-verifiable service JWT (the declared audience, the scoped claims, never a user claim) + the narrowing', { timeout: 900_000 }, async () => {
    for (const [clientId, secret, service] of [
      [SEEDED_SERVICE.client_id, SEEDED_SERVICE.secret, SEEDED_SERVICE.service],
      [CONSOLE_SERVICE.clientId, consoleSecret, CONSOLE_SERVICE.service],
    ] as const) {
      const res = await mintServiceToken(stack.apiBase, clientId, secret)
      expect(res.status, `${clientId} mints`).toBe(200)
      const body = await res.json() as { access_token: string; token_type: string; expires_in: number; scope?: string; id_token?: string; refresh_token?: string }
      expect(body.token_type).toBe('Bearer')
      expect(body.scope, 'the effective scopes ride the answer').toBe(service.scopes.join(' '))
      expect(body.id_token, 'no ID token — there is no user').toBeUndefined()
      expect(body.refresh_token, 'no refresh — the service re-authenticates').toBeUndefined()
      const claims = await verifyServiceJwt(stack.apiBase, body.access_token)
      expect(claims.iss).toBe(`http://localhost:${ID_WEB}`)
      expect(claims.sub, 'the subject is the SERVICE').toBe(service.id)
      expect(claims.aud, 'the audience is the DECLARED one, not the client id').toBe(service.audience)
      expect(claims.client_id).toBe(clientId)
      expect(claims.org).toBe(SERVICE_ORG)
      expect(claims.scope).toBe(service.scopes.join(' '))
      for (const userClaim of ['name', 'email', 'email_verified', 'roles', 'groups', 'picture', 'amr', 'nonce', 'instrument_model']) {
        expect(claims[userClaim], `no ${userClaim} on a service token`).toBeUndefined()
      }
    }

    // The narrowing: a subset mints the narrowed token; a scope beyond
    // the allowlist refuses invalid_scope (never a silent drop, never a
    // mint beyond the registered set).
    const narrowed = await mintServiceToken(stack.apiBase, SEEDED_SERVICE.client_id, SEEDED_SERVICE.secret, 'documents:read')
    expect(narrowed.status).toBe(200)
    const narrowedBody = await narrowed.json() as { access_token: string; scope: string }
    expect(narrowedBody.scope).toBe('documents:read')
    expect((await verifyServiceJwt(stack.apiBase, narrowedBody.access_token)).scope).toBe('documents:read')
    const beyond = await mintServiceToken(stack.apiBase, SEEDED_SERVICE.client_id, SEEDED_SERVICE.secret, 'documents:read admin:write')
    expect(beyond.status).toBe(400)
    expect(((await beyond.json()) as { error: string }).error).toBe('invalid_scope')
  })

  it('leg 4 — the refusals: the application class never speaks the grant, the golden’s probe shape stands, no refresh, no auth-code', { timeout: 900_000 }, async () => {
    // The bare probe (no client authentication): the pre-machine answer —
    // the contract golden's token_wrong_grant shape, byte-identical.
    const bare = await fetch(`${stack.apiBase}/op/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: 'grant_type=client_credentials',
    })
    expect(bare.status).toBe(400)
    expect(((await bare.json()) as { error: string }).error).toBe('unsupported_grant_type')

    // The hub (the application class, a valid secret) never speaks it.
    const hub = await mintServiceToken(stack.apiBase, HUB.client_id, HUB.secret)
    expect(hub.status).toBe(400)
    expect(((await hub.json()) as { error: string }).error).toBe('unsupported_grant_type')

    // No refresh grant for anyone.
    const refresh = await fetch(`${stack.apiBase}/op/token`, {
      method: 'POST',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        authorization: `Basic ${btoa(`${SEEDED_SERVICE.client_id}:${SEEDED_SERVICE.secret}`)}`,
      },
      body: 'grant_type=refresh_token&refresh_token=whatever',
    })
    expect(refresh.status).toBe(400)
    expect(((await refresh.json()) as { error: string }).error).toBe('unsupported_grant_type')

    // The authorization-code flow refuses the service client IN PLACE
    // (never a redirect — a service has no registered redirect URI).
    const authorize = await fetch(`${stack.apiBase}/op/authorize?${new URLSearchParams({
      response_type: 'code', client_id: SEEDED_SERVICE.client_id,
      redirect_uri: 'https://svc.example/callback', scope: 'openid',
      state: 's', code_challenge: 'whatever', code_challenge_method: 'S256',
    })}`, { redirect: 'manual' })
    expect(authorize.status).toBe(400)
    expect(authorize.headers.get('location')).toBeNull()
    expect(await authorize.text()).toContain('op-authorize-error')
  })

  it('leg 5 — the rotation through the console, the revocation, and the audit chain naming the service', { timeout: 900_000 }, async () => {
    // The re-key through the console (the edit mode: the class picker
    // locked, the binding pre-filled, the re-key the only secret act).
    await page.goto(`${stack.base}/op/admin/clients`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await page.waitForSelector('[data-testid="op-client-form"]', { timeout: SETTLE, polling: 500 })
    await page.evaluate((id) => (document.querySelector(`[data-testid="op-client-edit-${id}"]`) as HTMLElement).click(), CONSOLE_SERVICE.clientId)
    await page.waitForSelector('[data-testid="op-client-field-rekey"]', { timeout: SETTLE, polling: 500 })
    // The class picker locks in edit mode (the class is fixed).
    expect(await page.$eval('[data-testid="op-client-field-class"]', el => (el as HTMLSelectElement).disabled)).toBe(true)
    expect(await page.$eval('[data-testid="op-client-field-service-id"]', el => (el as HTMLInputElement).value)).toBe(CONSOLE_SERVICE.service.id)
    expect(await page.$eval('[data-testid="op-client-field-service-scopes"]', el => (el as HTMLInputElement).value)).toBe(CONSOLE_SERVICE.service.scopes.join(' '))
    await page.evaluate(() => (document.querySelector('[data-testid="op-client-field-rekey"]') as HTMLElement).click())
    await page.evaluate(() => (document.querySelector('[data-testid="op-client-save"]') as HTMLElement).click())
    await page.waitForSelector('[data-testid="op-client-secret"]', { timeout: SETTLE, polling: 500 })
    const rotated = await page.$eval('[data-testid="op-client-secret"]', el => el.textContent ?? '')
    expect(rotated.length).toBeGreaterThan(20)
    expect(rotated).not.toBe(consoleSecret)

    // The old secret stops working at once; the fresh one mints.
    expect((await mintServiceToken(stack.apiBase, CONSOLE_SERVICE.clientId, consoleSecret)).status).toBe(401)
    expect((await mintServiceToken(stack.apiBase, CONSOLE_SERVICE.clientId, rotated)).status).toBe(200)
    consoleSecret = rotated

    // The revocation (the disable toggle through the console).
    await page.goto(`${stack.base}/op/admin/clients`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await page.waitForSelector(`[data-testid="op-client-toggle-${CONSOLE_SERVICE.clientId}"]`, { timeout: SETTLE, polling: 500 })
    await page.evaluate((id) => (document.querySelector(`[data-testid="op-client-toggle-${id}"]`) as HTMLElement).click(), CONSOLE_SERVICE.clientId)
    await page.waitForFunction((id) => {
      const btn = document.querySelector(`[data-testid="op-client-toggle-${id}"]`)
      return btn?.textContent?.trim() === 'disabled'
    }, { timeout: SETTLE, polling: 500 }, CONSOLE_SERVICE.clientId)
    expect((await mintServiceToken(stack.apiBase, CONSOLE_SERVICE.clientId, consoleSecret)).status).toBe(401)

    // The audit chain carries the arc, naming the service per act.
    const admin = await apiSignIn(stack.apiBase, ADMIN_EMAIL)
    const feed = await (await fetch(`${stack.apiBase}/api/op/registry/activity?limit=200`, { headers: { cookie: admin } })).json() as Array<{
      action: string; entity_id: string; metadata?: Record<string, unknown>
    }>
    const arc = feed.filter(e => e.entity_id === CONSOLE_SERVICE.clientId)
    const registered = arc.find(e => e.action === 'client.registered')
    expect(registered?.metadata).toMatchObject({ class: 'service', service: CONSOLE_SERVICE.service })
    const rekeyed = arc.find(e => e.action === 'client.updated' && e.metadata?.rekeyed === true)
    expect(rekeyed?.metadata).toMatchObject({ class: 'service' })
    const issued = arc.find(e => e.action === 'client.token_issued')
    expect(issued?.metadata).toMatchObject({ class: 'service', service: CONSOLE_SERVICE.service.id, org: SERVICE_ORG, audience: CONSOLE_SERVICE.service.audience, scopes: CONSOLE_SERVICE.service.scopes })
    const revoked = arc.find(e => e.action === 'client.status')
    expect(revoked?.metadata).toMatchObject({ status: 'disabled', class: 'service', service: CONSOLE_SERVICE.service.id })
  })
})
