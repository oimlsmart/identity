// ═══════════════════════════════════════════════════════════════════
// TODO.identity-sso (the wave-A tail) — the OP's LOGOUT cone + the OIDC
// forced re-authentication, the e2e: the identity-profile stack (its own
// API + its own astro, the fed-01 spawned-stack pattern) and the fixture
// Relying Party (e2e/fixtures/stub-rp.ts — the kernel's REAL RP code)
// drive the full arc over real HTTP and the real UI, no stubs on the OP
// side:
//
//   leg 1  RP-INITIATED LOGOUT (the end-session endpoint): the browser
//          signs in through the RP (the ID token carries auth_time), the
//          RP's /signout bounces to the OP's /op/endsession, and the
//          REGISTERED post_logout_redirect_uri takes the browser back to
//          the RP's /signed-out (the state round-trips) — and the OP
//          session is DEAD (the sign-in page renders its form again,
//          never the signed-in bounce);
//   leg 2  OP-INITIATED BACKCHANNEL LOGOUT: the same end-session act
//          fanned a logout_token to the RP's registered receiver — the
//          RP validates it through the kernel's REAL token validation
//          (the signature against the OP's served JWKS, iss/aud/exp):
//          the spec's claim set (the backchannel-logout event, jti, the
//          120 s life), NO sid (the named gap — no sid tracking exists),
//          NO nonce;
//   leg 3  prompt=login (the forced re-authentication): WITH a live OP
//          session, the RP's prompt=login ask renders the sign-in FORM
//          (the existing-session bounce is refused — the flow's own
//          prompt flag), the re-authentication completes WITHOUT looping
//          (the authorize redirect consumed the 'login' value), and the
//          fresh ID token's auth_time is STRICTLY later than the
//          previous one's — the freshness proof the RP asked for.
//
// SELF-CONTAINED: the suite's shared stack (E2E_BASE_URL) is untouched —
// own ports (API 10634 / astro 10635 / fixture RP 10636 — above id-32's
// 10631-10633), own SQLite file.
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
const DB_DIR = join(BROWSER_DIR, '.cache', 'id-33')

// Port-isolated: above id-32's 10631-10633.
const ID_API = 10634
const ID_WEB = 10635
const RP_PORT = 10636

const ISSUER = `http://localhost:${ID_WEB}` // the astro origin (the browser's OP)
const RP_CLIENT_ID = 'fixture-rp'
const RP_CLIENT_SECRET = 'fixture-rp-secret'
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

/** Boot the identity-profile stack with the client registry's fixture RP
 *  seed — the wave-A tail's shape: the RP carries its LOGOUT surface (the
 *  exact post-logout landing + the backchannel receiver). */
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
      // The registry's bootstrap seed: the fixture RP (a confidential
      // client) WITH the wave-A tail's logout block — the exact
      // post-logout landing (the end-session redirect's allowlist) and
      // the backchannel receiver (the fan-out's target).
      OP_CLIENT_SEED: JSON.stringify([{
        client_id: RP_CLIENT_ID,
        name: 'The e2e fixture RP',
        secret: RP_CLIENT_SECRET,
        redirect_uris: [`http://127.0.0.1:${RP_PORT}/callback`],
        claims_policy: { claims: ['roles', 'groups', 'org'] },
        logout: {
          post_logout_redirect_uris: [`http://127.0.0.1:${RP_PORT}/signed-out`],
          backchannel_logout_uri: `http://127.0.0.1:${RP_PORT}/backchannel-logout`,
        },
      }]),
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

/** The RP round trip through the REAL browser (the id-29 driver): the
 *  OP session exists, so the authorize lands on the consent page for the
 *  first grant (a REMEMBERED grant skips it — the driver tolerates
 *  both); a missing session lands on the sign-in form first. */
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
  lastError: unknown
  logoutState: string | null
  logoutTokens: string[]
}> {
  return (await (await fetch(`${rp.baseUrl}/whoami`)).json()) as never
}

describe('TODO.identity-sso (the wave-A tail) — the logout cone + prompt=login (the identity profile)', () => {
  let stack: Stack
  let rp: StubRp

  beforeAll(async () => {
    stack = await bootIdentityStack()
    rp = await startStubRp({
      port: RP_PORT,
      issuer: ISSUER,
      clientId: RP_CLIENT_ID,
      clientSecret: RP_CLIENT_SECRET,
    })
  }, 600_000)

  afterAll(async () => {
    await rp?.close()
    await stopStack(stack)
  })

  it('leg 1 — RP-initiated logout: the end-session redirect lands on the REGISTERED post-logout URI (the state round-trips), and the OP session is dead', { timeout: 900_000 }, async () => {
    await withPage(async (page) => {
      flog(page, 'leg1: the sign-in round trip')
      await rpRoundTrip(page, rp, ACCOUNT)
      const who = await rpWhoami(rp)
      expect(who.claims?.email, 'the RP-validated sign-in landed').toBe(ACCOUNT)
      expect(typeof who.claims?.auth_time, 'the ID token carries the authentication instant').toBe('number')
      expect(Math.abs(Date.now() / 1000 - who.claims!.auth_time!), 'the instant is THIS sign-in').toBeLessThan(300)
      flog(page, 'leg1: signed in; the RP initiates the logout')

      await page.goto(`${rp.baseUrl}/signout`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
      // The OP's end-session answered the 302 to the REGISTERED landing.
      await page.waitForSelector('[data-testid="rp-signed-out"]', { timeout: SETTLE, polling: 500 })
      expect(new URL(page.url()).origin + new URL(page.url()).pathname).toBe(`${rp.baseUrl}/signed-out`)
      const echoed = await page.$eval('[data-testid="rp-signed-out-state"]', el => el.textContent?.trim())
      const after = await rpWhoami(rp)
      expect(after.logoutState, 'the RP sent a state').toBeTruthy()
      expect(echoed, 'the state round-tripped through the OP').toBe(after.logoutState)
      flog(page, 'leg1: the landing + the state stand; the OP session must be dead')

      // The session's death, proven at the OP's own surface: the sign-in
      // page renders its FORM (a live session would have bounced past it).
      await page.goto(`${stack.base}/`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
      await page.waitForSelector('[data-testid="login-email"]', { timeout: SETTLE, polling: 500 })
      expect(new URL(page.url()).pathname, 'no bounce — the form stands').toBe('/')
      flog(page, 'leg1: done')
    })
  })

  it('leg 2 — the end-session act fanned a logout_token to the RP’s backchannel receiver, and it validates through the RP’s real path', { timeout: 600_000 }, async () => {
    // The fan-out floats (the act never waits on an RP) — poll the
    // receiver's capture.
    const deadline = Date.now() + 60_000
    while (rp.logoutTokens.length < 1 && Date.now() < deadline) await delay(250)
    expect(rp.logoutTokens.length, 'the backchannel receiver saw the logout_token').toBeGreaterThanOrEqual(1)
    const token = rp.logoutTokens[rp.logoutTokens.length - 1]!

    // THE RP'S REAL VALIDATION PATH (the kernel's oidc.ts — the module
    // the platform's instances run): the signature against the OP's
    // served JWKS, the issuer, the audience, the expiry. The logout
    // token carries NO nonce — the strict nonce compare passes on
    // undefined===undefined (the builder's type names a string; the
    // logout token is not an ID token).
    const { discoverIssuer, validateIdToken } = await import('../server/oidc')
    const metadata = await discoverIssuer(ISSUER)
    const claims = await validateIdToken(token, {
      issuer: ISSUER,
      clientId: RP_CLIENT_ID,
      nonce: undefined as unknown as string,
      jwksUri: metadata.jwks_uri,
    })
    expect(claims.iss).toBe(ISSUER)
    expect(claims.aud).toBe(RP_CLIENT_ID)
    expect(claims.sub, 'the account the session belonged to').toBeTruthy()
    // The spec's claim set: the backchannel-logout event, the jti, the
    // 120 s life.
    const events = (claims as unknown as Record<string, unknown>).events as Record<string, unknown>
    expect(Object.keys(events ?? {})).toEqual(['http://schemas.openid.net/event/backchannel-logout'])
    expect(typeof (claims as unknown as Record<string, unknown>).jti).toBe('string')
    const raw = claims as unknown as Record<string, unknown>
    expect((raw.exp as number) - (raw.iat as number)).toBe(120)
    // NO sid (no sid tracking exists — the wave's named gap), NO nonce.
    expect(raw.sid).toBeUndefined()
    expect(raw.nonce).toBeUndefined()
  })

  it('leg 3 — prompt=login: a live session does NOT skip the form; the re-authentication completes without looping and the fresh auth_time is strictly later', { timeout: 900_000 }, async () => {
    await withPage(async (page) => {
      // The session from leg 1 is dead — sign in again (the remembered
      // grant from leg 1 skips the consent page).
      flog(page, 'leg3: the baseline sign-in')
      await rpRoundTrip(page, rp, ACCOUNT)
      const baseline = (await rpWhoami(rp)).claims!.auth_time!
      flog(page, `leg3: the baseline auth_time ${baseline}; the prompt=login ask`)

      // Cross a second boundary (auth_time is seconds-precision) — the
      // flow's own navigation time dwarfs this.
      await delay(1_100)

      // The RP asks for the forced re-authentication WITH the session live.
      await page.goto(`${rp.baseUrl}/signin?prompt=login`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
      // THE assertion: the sign-in FORM renders despite the live session
      // (the authorize redirect's prompt flag holds the existing-session
      // bounce off — without it the flow would have sailed straight
      // through to the RP's callback).
      await page.waitForSelector('[data-testid="login-email"]', { timeout: SETTLE, polling: 500 })
      expect(new URL(page.url()).pathname).toBe('/')
      expect(new URL(page.url()).searchParams.get('prompt'), 'the flow’s own prompt flag').toBe('login')
      flog(page, 'leg3: the form stands with the live session; re-authenticating')

      await opSignIn(page, ACCOUNT)
      // The re-entry: the authorize consumed the 'login' value (the
      // stateless loop guard) — the flow completes, never loops back to
      // the form.
      await page.waitForSelector('[data-testid="rp-signed-in"]', { timeout: SETTLE, polling: 500 })
      const after = await rpWhoami(rp)
      expect(after.claims?.email).toBe(ACCOUNT)
      expect(after.claims!.auth_time!, 'the freshness proof: the re-authentication’s instant is STRICTLY later')
        .toBeGreaterThan(baseline)
      flog(page, 'leg3: done')
    })
  })
})
