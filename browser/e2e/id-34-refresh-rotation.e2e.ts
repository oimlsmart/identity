// ═══════════════════════════════════════════════════════════════════
// TODO.identity-sso (the wave-C token surface) — the REFRESH GRANT's
// e2e: the identity-profile stack (its own API + its own astro, the
// id-33 spawned-stack pattern) and the fixture Relying Party
// (e2e/fixtures/stub-rp.ts — the kernel's REAL RP code, the /refresh leg
// driving the real token endpoint) prove the offline half over real
// HTTP and the real UI, no stubs on the OP side:
//
//   leg 1  THE OFFLINE SIGN-IN + THE ROTATION: the browser signs in
//          through the RP with `openid profile email offline_access` —
//          the code exchange answers the FIRST refresh token of a
//          rotation family; the RP's /refresh rotates it (the presented
//          token consumes, the successor differs), and the refreshed ID
//          token — validated through the RP's REAL path (the signature
//          against the OP's served JWKS) — proves the ORIGINAL
//          auth_time (never the refresh's moment, OIDC Core §12.2)
//          while its iat advances;
//   leg 2  THE REUSE VERDICT over the wire (RFC 6819 §5.2.2.3): the
//          SPENT token presented again reads invalid_grant — and the
//          family's LIVE successor is dead with it (the legitimate
//          chain and the attacker's copy both end, proven over HTTP
//          through the fixture's capture).
//
// SELF-CONTAINED: the suite's shared stack (E2E_BASE_URL) is untouched —
// own ports (API 10638 / astro 10639 / fixture RP 10640 — above id-33's
// 10634-10636), own SQLite file.
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
const DB_DIR = join(BROWSER_DIR, '.cache', 'id-34')

// Port-isolated: above id-33's 10634-10636.
const ID_API = 10638
const ID_WEB = 10639
const RP_PORT = 10640

const ISSUER = `http://localhost:${ID_WEB}` // the astro origin (the browser's OP)
const RP_CLIENT_ID = 'fixture-rp'
const RP_CLIENT_SECRET = 'fixture-rp-secret'
const ACCOUNT = 'tl@oiml.org' // the demo cast (dev-reset seeds it; the form takes demo2026)

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
 *  seed — the wave-C shape: a plain confidential application client (the
 *  offline grant's home). */
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
      // application client — the refresh grant's universal application
      // admission).
      OP_CLIENT_SEED: JSON.stringify([{
        client_id: RP_CLIENT_ID,
        name: 'The e2e fixture RP',
        secret: RP_CLIENT_SECRET,
        redirect_uris: [`http://127.0.0.1:${RP_PORT}/callback`],
        claims_policy: { claims: ['roles', 'groups', 'org'] },
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

/** The RP round trip through the REAL browser (the id-33 driver): the
 *  consent page shows for the first grant (a REMEMBERED grant skips it —
 *  the driver tolerates both); a missing session lands on the sign-in
 *  form first. */
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
  claims: (Record<string, unknown> & { sub: string; auth_time?: number; iat?: number }) | null
  lastAccessToken: string | null
  lastRefreshToken: string | null
  lastRefreshResult: { ok: true } | { ok: false; status: number; error: string } | null
}> {
  return (await (await fetch(`${rp.baseUrl}/whoami`)).json()) as never
}

describe('TODO.identity-sso (the wave-C token surface) — the refresh grant with rotation (the identity profile)', () => {
  let stack: Stack
  let rp: StubRp
  // The cross-leg capture: leg 1's ORIGINAL (spent) token + the original
  // authentication instant — leg 2's reuse probe presents the spent one.
  let originalRefreshToken: string
  let originalAuthTime: number

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

  it('leg 1 — the offline sign-in mints the family’s first refresh token; the rotation consumes the present and the refreshed ID token proves the ORIGINAL auth_time', { timeout: 900_000 }, async () => {
    await withPage(async (page) => {
      flog(page, 'leg1: the offline sign-in round trip')
      await rpRoundTrip(page, rp, ACCOUNT)
      const who = await rpWhoami(rp)
      expect(who.claims?.email, 'the RP-validated sign-in landed').toBe(ACCOUNT)
      expect(who.lastRefreshToken, 'the offline grant carried the refresh token').toBeTruthy()
      expect(typeof who.claims?.auth_time, 'the ID token carries the authentication instant').toBe('number')
      originalRefreshToken = who.lastRefreshToken!
      originalAuthTime = who.claims!.auth_time!
      flog(page, 'leg1: signed in with the offline half; rotating')

      // Cross a second boundary (auth_time is seconds-precision).
      await delay(1_100)

      // The refresh grant over the real wire (the fixture's /refresh leg
      // POSTs the grant and re-validates the fresh ID token through the
      // RP's real path).
      const refreshed = await fetch(`${rp.baseUrl}/refresh`)
      expect(refreshed.status, 'the rotation answered').toBe(200)
      const after = await rpWhoami(rp)
      expect(after.lastRefreshResult, 'the rotation succeeded').toEqual({ ok: true })
      expect(after.lastRefreshToken, 'the successor differs from the presented token').not.toBe(originalRefreshToken)
      expect(after.lastRefreshToken).toBeTruthy()
      expect(after.lastAccessToken, 'a fresh access token').toBeTruthy()
      expect(after.lastAccessToken).not.toBe(who.lastAccessToken)
      // THE freshness-vs-authentication proof (OIDC Core §12.2): the
      // refreshed ID token's auth_time is the ORIGINAL authentication
      // instant — never the refresh's moment — while its iat advances.
      expect(after.claims!.auth_time, 'the ORIGINAL authentication instant').toBe(originalAuthTime)
      expect(after.claims!.iat!, 'the issuance is the refresh’s own moment').toBeGreaterThan(originalAuthTime)
      expect(after.claims!.email).toBe(ACCOUNT)
      flog(page, 'leg1: done')
    })
  })

  it('leg 2 — the reuse verdict over the wire: the SPENT token’s re-present is invalid_grant and the family’s live successor dies with it', { timeout: 600_000 }, async () => {
    // The theft signal: leg 1's consumed token presented again (the
    // fixture's ?token= override — the capture holds the successor).
    const replay = await fetch(`${rp.baseUrl}/refresh?token=${encodeURIComponent(originalRefreshToken)}`)
    expect(replay.status).toBe(200) // the fixture answers its refusal page
    const replayText = await replay.text()
    expect(replayText).toContain('rp-refresh-refused')
    const afterReplay = await rpWhoami(rp)
    expect(afterReplay.lastRefreshResult, 'the reuse reads invalid_grant').toEqual({ ok: false, status: 400, error: 'invalid_grant' })

    // The blast radius (RFC 6819 §5.2.2.3): the family's LIVE successor —
    // the legitimate chain's next token — refuses too.
    const successor = await fetch(`${rp.baseUrl}/refresh`)
    const successorText = await successor.text()
    expect(successorText).toContain('rp-refresh-refused')
    const afterSuccessor = await rpWhoami(rp)
    expect(afterSuccessor.lastRefreshResult, 'the reuse killed the whole family').toEqual({ ok: false, status: 400, error: 'invalid_grant' })
  })
})
