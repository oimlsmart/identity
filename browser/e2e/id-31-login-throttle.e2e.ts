// ═══════════════════════════════════════════════════════════════════
// TODO.identity-sso/04 (the account lifecycle discipline, slice C) —
// the password leg's per-account backoff ladder over the real booted
// stack (the id-30 pattern; no browser ceremony is the subject — the
// ladder lives in the route, so the legs ride real HTTP against the
// astro front door):
//
//   leg 1  the BURST slows: four wrong passwords on one address all
//          answer the uniform 401 byte-for-byte (never a 429, never a
//          Retry-After) while the owed wait grows rung by rung — and
//          every failure lands on the holder's activity feed (the
//          burst signal's raw material, unchanged);
//   leg 2  the RIGHT password is never locked out: it signs in THROUGH
//          the owed wait, and the success clears the ladder (the next
//          sign-in is fast again);
//   leg 3  the UI tolerates the delayed 401: the login page renders
//          the same invalid-credentials error after the wait (no
//          throttle semantics leak into the page).
//
// The stack declares OP_LOGIN_BACKOFF_BASE_MS=150 (the honest test
// value: the rungs owe 300/600/1200/2400 ms — measurable, never slept
// through) and HIBP_RANGE_URL=off (slice B's check is not this arc's
// subject).
//
// SELF-CONTAINED: own ports (API 10627 / astro 10628 — above id-30's
// 10623-10626), own SQLite file.
// ═══════════════════════════════════════════════════════════════════

import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import puppeteer, { type Browser, type Page } from 'puppeteer'
import { spawn, type ChildProcess } from 'node:child_process'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { existsSync, mkdirSync, rmSync, cpSync, appendFileSync } from 'node:fs'
import { closeBrowser, delay } from './helpers'
import { fixtureOpSigningKey } from './fixtures/op-signing-key'

const BROWSER_DIR = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const FIXTURES = join(BROWSER_DIR, 'e2e', 'fixtures')
const DB_DIR = join(BROWSER_DIR, '.cache', 'id-31')

// Port-isolated: above id-30's 10623-10626.
const ID_API = 10627
const ID_WEB = 10628

const ISSUER = `http://localhost:${ID_WEB}` // the astro origin (the browser's OP)

const ROOT = { email: 'root@oimlsmart.org', name: 'Root Operator', password: 'the root operator passphrase' }
const FINN = { email: 'finn@example.org', name: 'Finn Example', password: 'finn has a proper passphrase' }

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

/** Boot the identity-profile stack with the ladder's test base declared. */
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
    // OIDC_* scrubbed + the demo override ON: a CI e2e job declares the
    // SUITE stack's SSO posture in the shared env — the identity stack
    // must not inherit it.
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
      // The first administrator arrives by DECLARATION (invite-only means
      // nobody else can mint the first link) — the setup link lands in
      // the boot log.
      OP_ACCOUNT_SEED: JSON.stringify([{ email: ROOT.email, name: ROOT.name, role: 'admin' }]),
      // TODO.identity-sso/04 slice C's test value: the rungs owe
      // 300/600/1200/2400 ms — the ladder is exercised and measurable,
      // never slept through.
      OP_LOGIN_BACKOFF_BASE_MS: '150',
      // Slice B's breach corpus is not this arc's subject (the suite-wide
      // posture, declared honestly per stack).
      HIBP_RANGE_URL: 'off',
    }, logs)
    const apiBase = `http://localhost:${ID_API}`
    await waitForHttp(`${apiBase}/api/health`, 120_000, logs)

    // Provision the profile's seed (the demo cast + the instance admin).
    const reset = await fetch(`${apiBase}/api/dev-reset`, { method: 'POST' })
    if (!reset.ok) throw new Error(`dev-reset on ${apiBase} answered ${reset.status}\n${logs.join('').slice(-2000)}`)

    // The account bootstrap seed runs on the first OP account request.
    const seedProbe = await fetch(`${apiBase}/api/op/login`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: 'nobody@example.org', password: 'a probe, not a password' }),
    })
    if (seedProbe.status !== 401) throw new Error(`the OP login probe answered ${seedProbe.status} (401 expected)\n${logs.join('').slice(-2000)}`)

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

/** A fresh browser per leg needing one (the id-02 lesson). */
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

describe('TODO.identity-sso/04 slice C — the password leg’s backoff ladder (the identity profile)', () => {
  let stack: Stack
  let rootCookie: string

  beforeAll(async () => {
    stack = await bootIdentityStack()

    // ── the setup (over real HTTP, never the subject): the root admin's
    //    password through the boot-logged setup link, then Finn's invite
    //    + enrollment through the admin API. ──
    const deadline = Date.now() + 60_000
    let setupUrl = ''
    while (Date.now() < deadline) {
      const m = /bootstrap: account root@oimlsmart\.org has no password[^\n]*\n\s*(\S+\/op\/setup\?token=\S+)/.exec(stack.logs.join(''))
      if (m) { setupUrl = m[1]!; break }
      await delay(500)
    }
    expect(setupUrl, 'the bootstrap setup link in the boot log').toContain('/op/setup?token=')
    const rootEnroll = await fetch(`${stack.apiBase}/api/op/enroll/${new URL(setupUrl).searchParams.get('token')}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ password: ROOT.password }),
    })
    expect(rootEnroll.status).toBe(200)
    const rootLogin = await fetch(`${stack.base}/api/op/login`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: ROOT.email, password: ROOT.password }),
    })
    expect(rootLogin.ok, 'the root admin signs in').toBe(true)
    rootCookie = rootLogin.headers.get('set-cookie')!.split(';')[0]!

    const invite = await fetch(`${stack.base}/api/op/accounts`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: rootCookie },
      body: JSON.stringify({ email: FINN.email, name: FINN.name }),
    })
    expect(invite.status).toBe(201)
    const { setupUrl: finnSetup } = await invite.json() as { setupUrl: string }
    const finnEnroll = await fetch(`${stack.apiBase}/api/op/enroll/${new URL(finnSetup).searchParams.get('token')}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ password: FINN.password }),
    })
    expect(finnEnroll.status).toBe(200)
  }, 600_000)

  afterAll(async () => {
    await stopStack(stack)
  })

  /** A timed password login through the astro front door (the browser's
   *  own path — never the API port directly). */
  async function timedLogin(email: string, password: string): Promise<{ status: number; body: unknown; elapsedMs: number }> {
    const started = Date.now()
    const res = await fetch(`${stack.base}/api/op/login`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email, password }),
    })
    const body = await res.json().catch(() => null)
    return { status: res.status, body, elapsedMs: Date.now() - started }
  }

  it('leg 1 — the burst slows rung by rung; the answer stays the uniform 401; every failure lands on the feed', { timeout: 900_000 }, async () => {
    const attempts: Array<{ status: number; body: unknown; elapsedMs: number }> = []
    for (let i = 0; i < 4; i++) {
      attempts.push(await timedLogin(FINN.email, 'finn has a WRONG passphrase'))
      flog(null, `leg1: attempt ${i + 1} answered ${attempts[i]!.status} in ${attempts[i]!.elapsedMs} ms`)
    }
    for (const [i, a] of attempts.entries()) {
      expect(a.status, `attempt ${i + 1}`).toBe(401)
      // The silent posture: byte-identical body, no throttle semantics.
      expect(a.body, `attempt ${i + 1}'s body`).toEqual({ error: 'Invalid email or password' })
    }
    // The ladder's growth, measured: the fourth attempt pays 2^3 × 150 ms
    // = 1200 ms owed (the first pays nothing) — a loose floor against a
    // loaded CI host.
    expect(
      attempts[3]!.elapsedMs - attempts[0]!.elapsedMs,
      `the ladder grew (first ${attempts[0]!.elapsedMs} ms, fourth ${attempts[3]!.elapsedMs} ms)`,
    ).toBeGreaterThanOrEqual(900)

    // The holder is never locked out: the right password signs in THROUGH
    // the owed wait (2^4 × 150 = 2400 ms — and leg 2 asserts the clear
    // this success performs + the feed's four failure rows).
    const signin = await timedLogin(FINN.email, FINN.password)
    expect(signin.status, 'the right password is never locked out').toBe(200)
    flog(null, `leg1: the success answered in ${signin.elapsedMs} ms (the owed wait paid)`)
  })

  it('leg 2 — the success clears the ladder: the next sign-in is fast again', { timeout: 900_000 }, async () => {
    // The ladder was cleared by leg 1's trailing success: this sign-in
    // owes nothing.
    const fast = await timedLogin(FINN.email, FINN.password)
    expect(fast.status).toBe(200)
    expect(fast.elapsedMs, 'the cleared ladder owes nothing').toBeLessThan(1_500)

    // And the feed (Finn's own session, the real route) carries exactly
    // the four wrong-password failures — the audit chain unchanged.
    const setCookie = await fetch(`${stack.base}/api/op/login`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: FINN.email, password: FINN.password }),
    })
    const finnCookie = setCookie.headers.get('set-cookie')!.split(';')[0]!
    const activity = await fetch(`${stack.base}/api/op/account/activity`, { headers: { cookie: finnCookie } })
    expect(activity.status).toBe(200)
    const events = await activity.json() as Array<{ action: string; metadata?: { reason?: string } }>
    const failures = events.filter(e => e.action === 'account.sign_in_failed')
    expect(failures, 'the four burst failures, no more and no less').toHaveLength(4)
    for (const f of failures) expect(f.metadata?.reason).toBe('invalid_credentials')
  })

  it('leg 3 — the login page renders the same error after the wait (no throttle semantics leak)', { timeout: 900_000 }, async () => {
    // One API-level failure arms a rung; the page's own attempt pays the
    // wait and shows the UNCHANGED invalid-credentials copy.
    await timedLogin(FINN.email, 'finn has a WRONG passphrase')
    await withPage(async (page) => {
      flog(page, 'leg3: the throttled wrong password through the login page')
      await page.goto(`${stack.base}/`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
      await page.waitForSelector('[data-testid="login-email"]', { timeout: SETTLE, polling: 500 })
      await page.type('[data-testid="login-email"]', FINN.email)
      await page.type('[data-testid="login-password"]', 'finn has a WRONG passphrase')
      await page.evaluate(() => (document.querySelector('[data-testid="login-submit"]') as HTMLElement).click())
      await page.waitForSelector('[data-testid="login-error"]', { timeout: SETTLE, polling: 500 })
      expect(await page.$eval('[data-testid="login-error"]', el => el.textContent ?? ''))
        .toContain('Invalid email or password')
      flog(page, 'leg3: done')
    })
    // The ladder's state is per-address — leave it cleared for the suite
    // hygiene (the dev-reset would do it; the honest success does too).
    await timedLogin(FINN.email, FINN.password)
  })
})
