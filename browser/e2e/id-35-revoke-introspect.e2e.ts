// ═══════════════════════════════════════════════════════════════════
// TODO.identity-sso (the wave-C token surface) — the REVOCATION (RFC
// 7009) + INTROSPECTION (RFC 7662 — identity#47/#42's RS half) e2e: the
// identity-profile stack (the id-34 spawned-stack pattern) and the
// fixture Relying Party sign in with the offline grant; the acts then
// run as PURE HTTP from the test process (the revocation/introspection
// endpoints are server-to-server — no browser on those legs):
//
//   leg 1  THE OPAQUE HALF: the browser sign-in's access token
//          introspects ACTIVE with the claim set (the table read); the
//          refresh token introspects inactive (the rows serve rotation
//          only — the surface's named scope); the access revocation
//          kills userinfo and flips the introspection; the refresh
//          revocation under the WRONG token_type_hint still kills the
//          family (the RFC's search extension — the grant then reads
//          invalid_grant); the unknown token answers the
//          indistinguishable 200, the missing token the honest 400, the
//          unauthenticated call 401;
//   leg 2  THE CLIENT BINDING: a FOREIGN (device-class) client's revoke
//          of the RP's refresh token answers 200 and kills NOTHING —
//          the grant still rotates (a client revokes only its own);
//   leg 3  THE MACHINE HALF: the device client's self-contained JWT
//          introspects active through the SIGNATURE + the named
//          client's LIVE standing (never a table read); the admin
//          console's disable flips the in-flight token inactive — the
//          revocation story the rows never had — and the re-enable
//          stands it again; a garbage token answers the honest
//          inactive.
//
// SELF-CONTAINED: the suite's shared stack (E2E_BASE_URL) is untouched —
// own ports (API 10641 / astro 10642 / fixture RP 10643 — above id-34's
// 10638-10640), own SQLite file.
//
// THE BROWSER IS PER-LEG (the id-02 lesson); cross-leg state rides the
// DATABASE + the fixture RP's capture.
// ═══════════════════════════════════════════════════════════════════

import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import puppeteer, { type Browser, type Page } from 'puppeteer'
import { spawn, type ChildProcess } from 'node:child_process'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { existsSync, mkdirSync, rmSync, cpSync, appendFileSync } from 'node:fs'
import { closeBrowser, delay } from './helpers'
import { fixtureOpSigningKey } from './fixtures/op-signing-key'
import { startStubRp, type StubRp } from './fixtures/stub-rp'

const BROWSER_DIR = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const FIXTURES = join(BROWSER_DIR, 'e2e', 'fixtures')
const DB_DIR = join(BROWSER_DIR, '.cache', 'id-35')

// Port-isolated: above id-34's 10638-10640.
const ID_API = 10641
const ID_WEB = 10642
const RP_PORT = 10643

const ISSUER = `http://localhost:${ID_WEB}` // the astro origin (the browser's OP)
const RP_CLIENT_ID = 'fixture-rp'
const RP_CLIENT_SECRET = 'fixture-rp-secret'
const DEVICE_ID = 'device-grant'
const DEVICE_SECRET = 'device-secret-e2e'
const DEVICE_MACHINE_ID = 'acme-lc500-sn-0001'
const ACCOUNT = 'ia@oiml.org' // the demo cast (dev-reset seeds it; the form takes demo2026)

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
  // poison the spawned astro's vite cache hash — the 2026-08-14 stall).
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
  if (!proc || proc.exitCode !== null || proc.pid === undefined) return
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

/** Boot the identity-profile stack — the wave-C seed: the fixture RP
 *  (the application class) + a DEVICE-class client (the machine cone's
 *  fixture: the introspection JWT half + the foreign-revoke actor). */
async function bootIdentityStack(): Promise<Stack> {
  const logs: string[] = []
  mkdirSync(DB_DIR, { recursive: true })
  const dbPath = join(DB_DIR, 'identity.db')
  for (const suffix of ['', '-wal', '-shm']) rmSync(dbPath + suffix, { force: true })
  rmSync(PROGRESS_LOG, { force: true })

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

    // The tsx CLI directly (never npx — the wrapper orphans the server).
    // OIDC_* scrubbed + the demo override ON (the id-01 doctrine: a CI
    // e2e job's SUITE-stack SSO posture must not leak into this stack).
    api = spawnLogged(join(BROWSER_DIR, 'node_modules', '.bin', 'tsx'), ['server/serve.ts'], {
      PORT: String(ID_API),
      DATABASE_PATH: dbPath,
      ENTITY_BACKEND: 'server',
      INSTANCE_PROFILE: join(FIXTURES, 'instance.profile.identity.yaml'),
      OIDC_ISSUER: '',
      OIDC_CLIENT_ID: '',
      DEMO_ACCOUNTS_ENABLED: 'true',
      OP_ISSUER: ISSUER,
      // identity#7: a declared-issuer stack declares its signing key too
      // (the generated dev key never registers off the dev posture).
      OP_SIGNING_KEY: await fixtureOpSigningKey(),
      OP_CLIENT_SEED: JSON.stringify([
        {
          client_id: RP_CLIENT_ID,
          name: 'The e2e fixture RP',
          secret: RP_CLIENT_SECRET,
          redirect_uris: [`http://127.0.0.1:${RP_PORT}/callback`],
          claims_policy: { claims: ['roles', 'groups', 'org'] },
        },
        {
          client_id: DEVICE_ID,
          name: 'The LC-500 twin',
          class: 'device',
          secret: DEVICE_SECRET,
          device: { id: DEVICE_MACHINE_ID, org: 'mfr-acme', instrument_model: 'acme-lc500@2021' },
        },
      ]),
    }, logs)
    const apiBase = `http://localhost:${ID_API}`
    await waitForHttp(`${apiBase}/api/health`, 120_000, logs)

    // Provision the profile's seed (the demo cast + the instance admin).
    const reset = await fetch(`${apiBase}/api/dev-reset`, { method: 'POST' })
    if (!reset.ok) throw new Error(`dev-reset on ${apiBase} answered ${reset.status}\n${logs.join('').slice(-2000)}`)

    // The spawned vite gets a PRIVATE cache seeded from the worktree's
    // warm one (the fed-01 lesson: a cold optimizer outlives the boot
    // budget on a loaded host).
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
    // Gate on a routed page (astro answers `/` before its route table
    // finishes — the fed-01 stall class; /op/join is the table-bound one
    // here: the root IS the sign-in page and answers early).
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

/** Progress outside vitest's per-test console capture (a stalled browser
 *  makes the suite silent until the file ends — this log is live). */
const PROGRESS_LOG = join(DB_DIR, 'progress.log')
function flog(page: Page | null, msg: string): void {
  const url = page && !page.isClosed() ? page.url() : '(no page)'
  const line = `${new Date().toISOString()} ${msg} @ ${url}\n`
  try { appendFileSync(PROGRESS_LOG, line) } catch { /* the log never breaks the leg */ }
}

/** A fresh browser per leg (the header note): the page comes with the
 *  viewport + the error taps, the browser closes at the leg's end. */
async function withPage(fn: (page: Page) => Promise<void>): Promise<void> {
  const browser: Browser = await puppeteer.launch({
    headless: 'shell',
    protocolTimeout: 480_000,
    args: ['--no-sandbox', '--disable-setuid-sandbox'],
  })
  try {
    const page = await browser.newPage()
    await page.setViewport({ width: 1440, height: 900 })
    page.on('pageerror', e => flog(page, `[pageerror] ${String(e).slice(0, 300)}`))
    page.on('requestfailed', r => flog(page, `[requestfailed] ${r.url().slice(0, 140)} ${r.failure()?.errorText ?? ''}`))
    await fn(page)
  } finally {
    await closeBrowser(browser)
  }
}

/** Sign in at the OP through the form (the demo cast's password). */
async function opSignIn(page: Page, email: string): Promise<void> {
  await page.waitForSelector('[data-testid="login-email"]', { timeout: SETTLE, polling: 500 })
  await page.evaluate(() => {
    (document.querySelector('[data-testid="login-email"]') as HTMLInputElement).value = ''
  })
  await page.type('[data-testid="login-email"]', email)
  await page.type('[data-testid="login-password"]', 'demo2026')
  await page.evaluate(() => (document.querySelector('[data-testid="login-submit"]') as HTMLElement).click())
}

/** The RP round trip through the REAL browser (the id-33 driver). */
async function rpRoundTrip(page: Page, rp: StubRp, signInAs?: string): Promise<void> {
  await page.goto(`${rp.baseUrl}/signin`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
  const consentSel = '[data-testid="op-consent-allow"]'
  const loginSel = '[data-testid="login-email"]'
  const doneSel = '[data-testid="rp-signed-in"]'
  await page.waitForFunction(
    (a: string, b: string, c: string) => Boolean(document.querySelector(a) || document.querySelector(b) || document.querySelector(c)),
    { timeout: SETTLE, polling: 500 },
    consentSel, loginSel, doneSel,
  )
  if (signInAs && await page.$(loginSel)) {
    await opSignIn(page, signInAs)
  }
  await page.waitForFunction(
    (a: string, b: string) => Boolean(document.querySelector(a) || document.querySelector(b)),
    { timeout: SETTLE, polling: 500 },
    consentSel, doneSel,
  )
  if (await page.$(consentSel)) {
    await page.evaluate((sel) => (document.querySelector(sel) as HTMLElement).click(), consentSel)
  }
  await page.waitForSelector(doneSel, { timeout: SETTLE, polling: 500 })
}

/** The fixture RP's assertion surface. */
async function rpWhoami(rp: StubRp): Promise<{
  claims: (Record<string, unknown> & { sub: string; auth_time?: number }) | null
  lastAccessToken: string | null
  lastRefreshToken: string | null
  lastRefreshResult: { ok: true } | { ok: false; status: number; error: string } | null
}> {
  return (await (await fetch(`${rp.baseUrl}/whoami`)).json()) as never
}

function clientBasic(clientId: string, secret: string): string {
  return `Basic ${btoa(`${encodeURIComponent(clientId)}:${encodeURIComponent(secret)}`)}`
}

/** RFC 7009 over the wire (the API origin — the OP router mounts at the
 *  root there exactly as behind the astro proxy). */
async function revoke(apiBase: string, params: { token: string; clientId: string; secret: string; hint?: string }): Promise<Response> {
  const body = new URLSearchParams({ token: params.token, client_id: params.clientId })
  if (params.hint) body.set('token_type_hint', params.hint)
  return fetch(`${apiBase}/op/revoke`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', authorization: clientBasic(params.clientId, params.secret) },
    body,
  })
}

/** RFC 7662 over the wire. */
async function introspect(apiBase: string, params: { token: string; clientId: string; secret: string }): Promise<Record<string, unknown>> {
  const res = await fetch(`${apiBase}/op/introspect`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', authorization: clientBasic(params.clientId, params.secret) },
    body: new URLSearchParams({ token: params.token, client_id: params.clientId }),
  })
  expect(res.status, 'the introspection answers 200 for an authenticated client').toBe(200)
  return res.json() as Promise<Record<string, unknown>>
}

describe('TODO.identity-sso (the wave-C token surface) — revocation + introspection (the identity profile)', () => {
  let stack: Stack
  let rp: StubRp

  beforeAll(async () => {
    stack = await bootIdentityStack()
    rp = await startStubRp({
      port: RP_PORT,
      issuer: ISSUER,
      clientId: RP_CLIENT_ID,
      clientSecret: RP_CLIENT_SECRET,
      scopes: 'openid profile email offline_access', // the offline ask
    })
  }, 600_000)

  afterAll(async () => {
    await rp?.close()
    await stopStack(stack)
  })

  it('leg 1 — the opaque half: live active + claims, the refresh token inactive, the revocations land (the wrong hint included), the indistinguishable 200s', { timeout: 900_000 }, async () => {
    await withPage(async (page) => {
      flog(page, 'leg1: the offline sign-in round trip')
      await rpRoundTrip(page, rp, ACCOUNT)
      const who = await rpWhoami(rp)
      expect(who.claims?.email, 'the RP-validated sign-in landed').toBe(ACCOUNT)
      expect(who.lastAccessToken).toBeTruthy()
      expect(who.lastRefreshToken, 'the offline grant carried the refresh token').toBeTruthy()
      const access = who.lastAccessToken!
      const refreshToken = who.lastRefreshToken!
      flog(page, 'leg1: signed in; the introspection + revocation arc')

      // The LIVE access token introspects active with the claim set.
      const live = await introspect(stack.apiBase, { token: access, clientId: RP_CLIENT_ID, secret: RP_CLIENT_SECRET })
      expect(live.active).toBe(true)
      expect(live.iss).toBe(ISSUER)
      expect(live.sub).toBe(who.claims!.sub)
      expect(live.aud).toBe(RP_CLIENT_ID)
      expect(live.client_id).toBe(RP_CLIENT_ID)
      expect(live.token_type).toBe('Bearer')
      expect(typeof live.exp, 'the epoch expiry').toBe('number')
      expect(String(live.scope).split(' ').sort(), 'the granted set').toEqual(['email', 'offline_access', 'openid', 'profile'])

      // The REFRESH token introspects inactive (the named scope: the
      // refresh rows serve the token endpoint's rotation only).
      const refreshProbe = await introspect(stack.apiBase, { token: refreshToken, clientId: RP_CLIENT_ID, secret: RP_CLIENT_SECRET })
      expect(refreshProbe.active).toBe(false)

      // The ACCESS revocation: userinfo 401s, the introspection flips.
      expect((await revoke(stack.apiBase, { token: access, clientId: RP_CLIENT_ID, secret: RP_CLIENT_SECRET, hint: 'access_token' })).status).toBe(200)
      const userinfo = await fetch(`${stack.base}/op/userinfo`, { headers: { authorization: `Bearer ${access}` } })
      expect(userinfo.status, 'the revoked access token never resolves userinfo').toBe(401)
      expect((await introspect(stack.apiBase, { token: access, clientId: RP_CLIENT_ID, secret: RP_CLIENT_SECRET })).active).toBe(false)

      // The REFRESH revocation under the WRONG hint (the RFC's search
      // extension): still revokes — the family dies (the grant reads
      // invalid_grant through the fixture's /refresh leg).
      expect((await revoke(stack.apiBase, { token: refreshToken, clientId: RP_CLIENT_ID, secret: RP_CLIENT_SECRET, hint: 'access_token' })).status).toBe(200)
      const dead = await fetch(`${rp.baseUrl}/refresh`)
      expect(await dead.text()).toContain('rp-refresh-refused')
      expect((await rpWhoami(rp)).lastRefreshResult, 'the revoked family never rotates again').toEqual({ ok: false, status: 400, error: 'invalid_grant' })

      // The indistinguishability + the honest refusals.
      expect((await revoke(stack.apiBase, { token: 'never-minted', clientId: RP_CLIENT_ID, secret: RP_CLIENT_SECRET })).status, 'the unknown token answers the same 200').toBe(200)
      const noToken = await fetch(`${stack.apiBase}/op/revoke`, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded', authorization: clientBasic(RP_CLIENT_ID, RP_CLIENT_SECRET) },
        body: `client_id=${RP_CLIENT_ID}`,
      })
      expect(noToken.status, 'the missing token is the honest 400').toBe(400)
      const noAuth = await fetch(`${stack.apiBase}/op/revoke`, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: 'token=whatever',
      })
      expect(noAuth.status, 'the unauthenticated call refuses').toBe(401)
      const noAuthIntrospect = await fetch(`${stack.apiBase}/op/introspect`, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: 'token=whatever',
      })
      expect(noAuthIntrospect.status).toBe(401)
      flog(page, 'leg1: done')
    })
  })

  it('leg 2 — the client binding: a FOREIGN client’s revoke answers 200 and kills nothing (the grant still rotates)', { timeout: 900_000 }, async () => {
    await withPage(async (page) => {
      flog(page, 'leg2: a fresh offline sign-in')
      await rpRoundTrip(page, rp, ACCOUNT)
      const who = await rpWhoami(rp)
      expect(who.lastRefreshToken).toBeTruthy()
      flog(page, 'leg2: the device client revokes the RP’s token')

      // The device client (a FOREIGN, machine-class client — registered,
      // active, secret-bearing) revokes the RP's refresh token: the
      // answer is the indistinguishable 200, and the family STANDS.
      expect((await revoke(stack.apiBase, { token: who.lastRefreshToken!, clientId: DEVICE_ID, secret: DEVICE_SECRET, hint: 'refresh_token' })).status).toBe(200)
      const alive = await fetch(`${rp.baseUrl}/refresh`)
      expect(await alive.text()).toContain('rp-refreshed')
      expect((await rpWhoami(rp)).lastRefreshResult, 'the foreign revoke killed nothing').toEqual({ ok: true })
      flog(page, 'leg2: done')
    })
  })

  it('leg 3 — the machine half: the device JWT introspects through the signature + the named client’s LIVE standing (the disable/enable flip)', { timeout: 600_000 }, async () => {
    // Mint the device JWT (the machine cone's own grant, over the wire).
    const minted = await fetch(`${stack.apiBase}/op/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', authorization: clientBasic(DEVICE_ID, DEVICE_SECRET) },
      body: 'grant_type=client_credentials',
    })
    expect(minted.status).toBe(200)
    const { access_token: machineToken } = await minted.json() as { access_token: string }

    // Active through the SIGNATURE — never a table read (there are no
    // rows for the machine tokens); ANY active registered client may ask
    // (the fixture RP asks here).
    const live = await introspect(stack.apiBase, { token: machineToken, clientId: RP_CLIENT_ID, secret: RP_CLIENT_SECRET })
    expect(live.active, 'the device JWT introspects active').toBe(true)
    expect(live.sub).toBe(DEVICE_MACHINE_ID)
    expect(live.aud).toBe(DEVICE_ID)
    expect(live.token_type).toBe('Bearer')

    // The standing re-judgment through the ADMIN console's status act
    // (the demo cast's admin, the session-cookie posture): DISABLE the
    // client and the in-flight token goes inactive; re-enable and it
    // stands again.
    const adminLogin = await fetch(`${stack.apiBase}/api/auth/demo`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: 'admin@oiml.org', password: 'demo2026' }),
    })
    expect(adminLogin.ok, 'the admin demo sign-in').toBe(true)
    const adminCookie = adminLogin.headers.get('set-cookie')!.split(';')[0]!
    const setStatus = (status: 'active' | 'disabled') => fetch(`${stack.apiBase}/api/op/clients/${DEVICE_ID}/status`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: adminCookie },
      body: JSON.stringify({ status }),
    })
    expect((await setStatus('disabled')).status).toBe(200)
    try {
      const disabled = await introspect(stack.apiBase, { token: machineToken, clientId: RP_CLIENT_ID, secret: RP_CLIENT_SECRET })
      expect(disabled.active, 'the disabled client’s in-flight token is inactive').toBe(false)
    } finally {
      expect((await setStatus('active')).status).toBe(200)
    }
    const restored = await introspect(stack.apiBase, { token: machineToken, clientId: RP_CLIENT_ID, secret: RP_CLIENT_SECRET })
    expect(restored.active, 'the re-enabled client’s token stands again').toBe(true)

    // The honest inactive: garbage, and a refresh-shaped unknown.
    expect((await introspect(stack.apiBase, { token: 'not-a-token', clientId: RP_CLIENT_ID, secret: RP_CLIENT_SECRET })).active).toBe(false)
    const forged = `${btoa('{"alg":"ES256","kid":"nobody"}')}.${btoa('{"iss":"x","sub":"x","exp":9999999999}')}.${btoa('forged')}`
    expect((await introspect(stack.apiBase, { token: forged, clientId: RP_CLIENT_ID, secret: RP_CLIENT_SECRET })).active, 'a foreign-signed JWT reads inactive').toBe(false)
  })
})
