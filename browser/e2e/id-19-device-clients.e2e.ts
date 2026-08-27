// ═══════════════════════════════════════════════════════════════════
// The machine cone + the whoami beacon, the e2e (the identity-profile
// stack, the id-17/id-18 spawned-stack pattern — its own API + its own
// astro, its own SQLite file):
//
//   leg 1  the SEEDED device client stands (the bootstrap seed accepts
//          the class): the admin API's view carries the class + the
//          device block, never the human-cone fields;
//   leg 2  the admin registers the demo cast's SECOND device client
//          through the CONSOLE (the form's device mode renders honestly:
//          the class picker, the binding fieldset, the org select
//          carrying the registry's mfr-acme, the confidential note — no
//          redirect-URI/claims/SSO-home fieldsets), the generated secret
//          shown once, the row rendering the device badge + the device
//          line (no launch line, no URIs list);
//   leg 3  the GRANT for real: both device clients mint the self-
//          contained device JWT at /op/token (client_credentials), the
//          claims verified against the OP's own JWKS (sub = the device
//          id, org, instrument_model; never an ID token, never a user
//          claim);
//   leg 4  the refusals: the application class never speaks
//          client_credentials (the pre-device answer), the bare probe
//          keeps the golden's shape, refresh_token refuses, the
//          authorization-code flow refuses the device at /op/authorize
//          IN PLACE;
//   leg 5  the ROTATION through the console (the re-key: the old secret
//          refuses, the new mints), the REVOCATION (the disable: the
//          grant 401s), and the audit chain carrying the arc naming the
//          device;
//   leg 6  the whoami beacon: signed-out → the cheap cacheable shape
//          with the hub's origin reflected (and the foreign origin
//          getting NO CORS header); the admin's session → the minimal
//          projection (name, picture, the admin flag — never the
//          dossier), no-store; the astro-proxy path answering the same.
//
// SELF-CONTAINED: the suite's shared stack (E2E_BASE_URL) is untouched —
// the identity instance boots on its own ports (API 10595 / astro
// 10596) with its own SQLite file.
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
const DB_DIR = join(BROWSER_DIR, '.cache', 'id-19')

// Port-isolated: above every declared e2e stack (…10594 is id-18's) and
// the local dev loops.
const ID_API = 10595
const ID_WEB = 10596

const ADMIN_EMAIL = 'admin@oiml.org'

// The demo cast's instrument: ACME's LC-500 (the model supply chain's
// product-reference spelling) on the demonstration manufacturer's org —
// the SMI twin the machine cone vouches for.
const DEVICE_ORG = 'mfr-acme'
const DEVICE_MODEL = 'acme-lc500@2021'

// The bootstrap seed's device client (leg 1) — the seed accepts the
// class — plus the hub (the application class: the launch card feeds the
// whoami allowlist, the secret the grant-refusal legs).
const SEEDED_DEVICE = {
  client_id: 'device-acme-lc500-demo',
  name: 'ACME LC-500 demonstration twin (the seed)',
  class: 'device',
  device: { id: 'acme-lc500-demo-01', org: DEVICE_ORG, instrument_model: DEVICE_MODEL },
  secret: 'the-seeded-device-secret-demo',
}
const HUB = {
  client_id: 'hub-instance',
  name: 'OIML SMART platform hub',
  secret: 'hub-secret-123',
  redirect_uris: ['https://hub.example/api/auth/callback/oidc'],
  claims_policy: { claims: ['roles', 'groups', 'org'] },
  launch: { url: 'https://hub.example/api/auth/signin/oidc', icon: 'grid', description: 'The certification hub.', visibility: 'open' },
}
// The console-registered device client (leg 2).
const CONSOLE_DEVICE = {
  clientId: 'device-acme-lc500-sn0199',
  name: 'ACME LC-500 sn 0199 (the twin)',
  device: { id: 'acme-lc500-sn-0199', org: DEVICE_ORG, instrument_model: DEVICE_MODEL },
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

/** Boot the identity-profile stack (the id-18 posture), the client
 *  registry's bootstrap seed carrying the hub + the device-class entry. */
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
      OP_CLIENT_SEED: JSON.stringify([HUB, SEEDED_DEVICE]),
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

/** The device grant (client_credentials, client_secret_basic). */
async function mintDeviceToken(apiBase: string, clientId: string, secret: string): Promise<Response> {
  return fetch(`${apiBase}/op/token`, {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      authorization: `Basic ${btoa(`${encodeURIComponent(clientId)}:${encodeURIComponent(secret)}`)}`,
    },
    body: 'grant_type=client_credentials',
  })
}

function base64urlDecode(s: string): Uint8Array {
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice(0, (4 - (s.length % 4)) % 4)
  const bin = atob(b64)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

/** Verify the device JWT against the stack's OWN JWKS (the twin
 *  endpoints' posture) and answer its claims. */
async function verifyDeviceJwt(apiBase: string, token: string): Promise<Record<string, unknown>> {
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
  expect(ok, 'the device token verifies against the OP’s JWKS').toBe(true)
  return JSON.parse(new TextDecoder().decode(base64urlDecode(p!))) as Record<string, unknown>
}

describe('the machine cone + the whoami beacon (the identity profile)', () => {
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

  it('leg 1 — the bootstrap seed accepts the class: the seeded device client stands, honestly shaped', { timeout: 900_000 }, async () => {
    const admin = await apiSignIn(stack.apiBase, ADMIN_EMAIL)
    const list = await (await fetch(`${stack.apiBase}/api/op/clients`, { headers: { cookie: admin } })).json() as Array<Record<string, any>>
    const seeded = list.find(r => r.clientId === SEEDED_DEVICE.client_id)
    expect(seeded, 'the seeded device client is on the registry').toBeTruthy()
    expect(seeded.class).toBe('device')
    expect(seeded.device).toEqual(SEEDED_DEVICE.device)
    expect(seeded.confidential).toBe(true)
    expect(seeded.redirectUris).toEqual([])
    expect(seeded.launch).toBeNull()
    expect(seeded.claimsPolicy.claims).toEqual([])
    // The hub seeds as the APPLICATION class, its launch card intact.
    const hub = list.find(r => r.clientId === HUB.client_id)
    expect(hub.class).toBe('application')
    expect(hub.launch?.url).toBe(HUB.launch.url)
  })

  it('leg 2 — the console registers the demo cast’s second device client, the form’s device mode honest throughout', { timeout: 900_000 }, async () => {
    await page.goto(`${stack.base}/`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await opSignIn(page, ADMIN_EMAIL)
    await page.waitForFunction(() => window.location.pathname !== '/', { timeout: SETTLE, polling: 500 })
    await page.goto(`${stack.base}/op/admin/clients`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await page.waitForSelector('[data-testid="op-client-form"]', { timeout: SETTLE, polling: 500 })

    // The device mode: the class picker swaps the fieldsets honestly.
    await page.select('[data-testid="op-client-field-class"]', 'device')
    await page.waitForSelector('[data-testid="op-client-field-device"]', { timeout: SETTLE, polling: 500 })
    // The human-cone fieldsets never render in the device mode.
    expect(await page.$('[data-testid="op-client-field-uris"]')).toBeNull()
    expect(await page.$('[data-testid="op-client-field-claims"]')).toBeNull()
    expect(await page.$('[data-testid="op-client-field-launch-on"]')).toBeNull()
    expect(await page.$('[data-testid="op-client-field-confidential"]')).toBeNull()
    await page.waitForSelector('[data-testid="op-client-field-device-confidential"]', { timeout: SETTLE, polling: 500 })
    // The org select rides the organization registry (mfr-acme among it).
    await page.waitForSelector(`[data-testid="op-client-device-org-${DEVICE_ORG}"]`, { timeout: SETTLE, polling: 500 })

    await page.type('[data-testid="op-client-field-id"]', CONSOLE_DEVICE.clientId)
    await page.type('[data-testid="op-client-field-name"]', CONSOLE_DEVICE.name)
    await page.type('[data-testid="op-client-field-device-id"]', CONSOLE_DEVICE.device.id)
    await page.select('[data-testid="op-client-field-device-org"]', DEVICE_ORG)
    await page.type('[data-testid="op-client-field-device-model"]', CONSOLE_DEVICE.device.instrument_model)
    await page.evaluate(() => (document.querySelector('[data-testid="op-client-save"]') as HTMLElement).click())

    // The generated secret shows exactly ONCE.
    await page.waitForSelector('[data-testid="op-client-secret"]', { timeout: SETTLE, polling: 500 })
    consoleSecret = await page.$eval('[data-testid="op-client-secret"]', el => el.textContent ?? '')
    expect(consoleSecret.length).toBeGreaterThan(20)

    // The row renders the class honestly: the device badge + the device
    // line — no launch line, no URIs list.
    await page.waitForSelector(`[data-testid="op-client-class-${CONSOLE_DEVICE.clientId}"]`, { timeout: SETTLE, polling: 500 })
    const deviceLine = await page.$eval(`[data-testid="op-client-device-${CONSOLE_DEVICE.clientId}"]`, el => el.textContent ?? '')
    expect(deviceLine).toContain(CONSOLE_DEVICE.device.id)
    expect(deviceLine).toContain(DEVICE_ORG)
    expect(deviceLine).toContain(DEVICE_MODEL)
    expect(await page.$(`[data-testid="op-client-launch-${CONSOLE_DEVICE.clientId}"]`)).toBeNull()
    expect(await page.$(`[data-testid="op-client-uris-${CONSOLE_DEVICE.clientId}"]`)).toBeNull()
  })

  it('leg 3 — the grant for real: both device clients mint the JWKS-verifiable device JWT (the device claims, never a user claim)', { timeout: 900_000 }, async () => {
    for (const [clientId, secret, device] of [
      [SEEDED_DEVICE.client_id, SEEDED_DEVICE.secret, SEEDED_DEVICE.device],
      [CONSOLE_DEVICE.clientId, consoleSecret, CONSOLE_DEVICE.device],
    ] as const) {
      const res = await mintDeviceToken(stack.apiBase, clientId, secret)
      expect(res.status, `${clientId} mints`).toBe(200)
      const body = await res.json() as { access_token: string; token_type: string; expires_in: number; id_token?: string; refresh_token?: string }
      expect(body.token_type).toBe('Bearer')
      expect(body.id_token, 'no ID token — there is no user').toBeUndefined()
      expect(body.refresh_token, 'no refresh — the device re-authenticates').toBeUndefined()
      const claims = await verifyDeviceJwt(stack.apiBase, body.access_token)
      expect(claims.iss).toBe(`http://localhost:${ID_WEB}`)
      expect(claims.sub, 'the subject is the DEVICE').toBe(device.id)
      expect(claims.aud).toBe(clientId)
      expect(claims.org).toBe(DEVICE_ORG)
      expect(claims.instrument_model).toBe(DEVICE_MODEL)
      for (const userClaim of ['name', 'email', 'email_verified', 'roles', 'groups', 'picture', 'amr', 'nonce']) {
        expect(claims[userClaim], `no ${userClaim} on a device token`).toBeUndefined()
      }
    }
  })

  it('leg 4 — the refusals: the application class never speaks the grant, the golden’s probe shape stands, no refresh, no auth-code', { timeout: 900_000 }, async () => {
    // The bare probe (no client authentication): the pre-device answer —
    // the contract golden's token_wrong_grant shape, byte-identical.
    const bare = await fetch(`${stack.apiBase}/op/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: 'grant_type=client_credentials',
    })
    expect(bare.status).toBe(400)
    expect(((await bare.json()) as { error: string }).error).toBe('unsupported_grant_type')

    // The hub (the application class, a valid secret) never speaks it.
    const hub = await mintDeviceToken(stack.apiBase, HUB.client_id, HUB.secret)
    expect(hub.status).toBe(400)
    expect(((await hub.json()) as { error: string }).error).toBe('unsupported_grant_type')

    // No refresh grant for anyone.
    const refresh = await fetch(`${stack.apiBase}/op/token`, {
      method: 'POST',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        authorization: `Basic ${btoa(`${SEEDED_DEVICE.client_id}:${SEEDED_DEVICE.secret}`)}`,
      },
      body: 'grant_type=refresh_token&refresh_token=whatever',
    })
    expect(refresh.status).toBe(400)
    expect(((await refresh.json()) as { error: string }).error).toBe('unsupported_grant_type')

    // The authorization-code flow refuses the device client IN PLACE
    // (never a redirect — a device has no registered redirect URI).
    const authorize = await fetch(`${stack.apiBase}/op/authorize?${new URLSearchParams({
      response_type: 'code', client_id: SEEDED_DEVICE.client_id,
      redirect_uri: 'https://device.example/callback', scope: 'openid',
      state: 's', code_challenge: 'whatever', code_challenge_method: 'S256',
    })}`, { redirect: 'manual' })
    expect(authorize.status).toBe(400)
    expect(authorize.headers.get('location')).toBeNull()
    expect(await authorize.text()).toContain('op-authorize-error')
  })

  it('leg 5 — the rotation through the console, the revocation, and the audit chain naming the device', { timeout: 900_000 }, async () => {
    // The re-key through the console (the edit mode: the class picker
    // locked, the binding pre-filled, the re-key the only secret act).
    await page.goto(`${stack.base}/op/admin/clients`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await page.waitForSelector('[data-testid="op-client-form"]', { timeout: SETTLE, polling: 500 })
    await page.evaluate((id) => (document.querySelector(`[data-testid="op-client-edit-${id}"]`) as HTMLElement).click(), CONSOLE_DEVICE.clientId)
    await page.waitForSelector('[data-testid="op-client-field-rekey"]', { timeout: SETTLE, polling: 500 })
    // The class picker locks in edit mode (the class is fixed).
    expect(await page.$eval('[data-testid="op-client-field-class"]', el => (el as HTMLSelectElement).disabled)).toBe(true)
    expect(await page.$eval('[data-testid="op-client-field-device-id"]', el => (el as HTMLInputElement).value)).toBe(CONSOLE_DEVICE.device.id)
    await page.evaluate(() => (document.querySelector('[data-testid="op-client-field-rekey"]') as HTMLElement).click())
    await page.evaluate(() => (document.querySelector('[data-testid="op-client-save"]') as HTMLElement).click())
    await page.waitForSelector('[data-testid="op-client-secret"]', { timeout: SETTLE, polling: 500 })
    const rotated = await page.$eval('[data-testid="op-client-secret"]', el => el.textContent ?? '')
    expect(rotated.length).toBeGreaterThan(20)
    expect(rotated).not.toBe(consoleSecret)

    // The old secret stops working at once; the fresh one mints.
    expect((await mintDeviceToken(stack.apiBase, CONSOLE_DEVICE.clientId, consoleSecret)).status).toBe(401)
    expect((await mintDeviceToken(stack.apiBase, CONSOLE_DEVICE.clientId, rotated)).status).toBe(200)
    consoleSecret = rotated

    // The revocation (the disable toggle through the console).
    await page.goto(`${stack.base}/op/admin/clients`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await page.waitForSelector(`[data-testid="op-client-toggle-${CONSOLE_DEVICE.clientId}"]`, { timeout: SETTLE, polling: 500 })
    await page.evaluate((id) => (document.querySelector(`[data-testid="op-client-toggle-${id}"]`) as HTMLElement).click(), CONSOLE_DEVICE.clientId)
    await page.waitForFunction((id) => {
      const btn = document.querySelector(`[data-testid="op-client-toggle-${id}"]`)
      return btn?.textContent?.trim() === 'disabled'
    }, { timeout: SETTLE, polling: 500 }, CONSOLE_DEVICE.clientId)
    expect((await mintDeviceToken(stack.apiBase, CONSOLE_DEVICE.clientId, consoleSecret)).status).toBe(401)

    // The audit chain carries the arc, naming the device per act.
    const admin = await apiSignIn(stack.apiBase, ADMIN_EMAIL)
    const feed = await (await fetch(`${stack.apiBase}/api/op/registry/activity?limit=200`, { headers: { cookie: admin } })).json() as Array<{
      action: string; entity_id: string; metadata?: Record<string, unknown>
    }>
    const arc = feed.filter(e => e.entity_id === CONSOLE_DEVICE.clientId)
    const registered = arc.find(e => e.action === 'client.registered')
    expect(registered?.metadata).toMatchObject({ class: 'device', device: CONSOLE_DEVICE.device })
    const rekeyed = arc.find(e => e.action === 'client.updated' && e.metadata?.rekeyed === true)
    expect(rekeyed?.metadata).toMatchObject({ class: 'device' })
    const issued = arc.find(e => e.action === 'client.token_issued')
    expect(issued?.metadata).toMatchObject({ class: 'device', device: CONSOLE_DEVICE.device.id, org: DEVICE_ORG, instrument_model: DEVICE_MODEL })
    const revoked = arc.find(e => e.action === 'client.status')
    expect(revoked?.metadata).toMatchObject({ status: 'disabled', class: 'device', device: CONSOLE_DEVICE.device.id })
  })

  it('leg 6 — the whoami beacon: the signed-out shape cacheable + CORS-gated, the session’s minimal projection, the proxy path', { timeout: 900_000 }, async () => {
    // Signed out, the allowlisted origin reflected (the hub's launch
    // origin) — cheap and cacheable.
    const anon = await fetch(`${stack.apiBase}/op/whoami`, { headers: { origin: 'https://hub.example' } })
    expect(anon.status).toBe(200)
    expect(await anon.json()).toEqual({ signedIn: false })
    expect(anon.headers.get('access-control-allow-origin')).toBe('https://hub.example')
    expect(anon.headers.get('access-control-allow-credentials')).toBe('true')
    expect(anon.headers.get('cache-control')).toBe('public, max-age=60')

    // The foreign origin: the answer stands, the CORS header never does.
    const foreign = await fetch(`${stack.apiBase}/op/whoami`, { headers: { origin: 'https://evil.example' } })
    expect(foreign.status).toBe(200)
    expect(foreign.headers.get('access-control-allow-origin')).toBeNull()

    // The admin's session: the minimal projection (a face, not a
    // dossier), never cached.
    const admin = await apiSignIn(stack.apiBase, ADMIN_EMAIL)
    const signed = await fetch(`${stack.apiBase}/op/whoami`, { headers: { cookie: admin, origin: 'https://hub.example' } })
    expect(signed.status).toBe(200)
    const projection = await signed.json() as Record<string, unknown>
    expect(projection.signedIn).toBe(true)
    expect(projection.name).toBeTruthy()
    expect(projection.picture).toBeNull() // no upload → the chip's initials fallback
    expect(projection.admin).toBe(true)
    for (const never of ['email', 'role', 'roles', 'groups', 'org', 'orgId', 'id']) {
      expect(projection[never], `the projection never carries ${never}`).toBeUndefined()
    }
    expect(signed.headers.get('cache-control')).toBe('no-store')

    // The same beacon through the astro proxy (the static properties'
    // posture: cross-origin to the OP host, credentials included).
    const viaProxy = await fetch(`${stack.base}/op/whoami`, { headers: { cookie: admin, origin: 'https://hub.example' } })
    expect(viaProxy.status).toBe(200)
    expect(((await viaProxy.json()) as { signedIn: boolean }).signedIn).toBe(true)
    expect(viaProxy.headers.get('access-control-allow-origin')).toBe('https://hub.example')
  })
})
