// ═══════════════════════════════════════════════════════════════════
// TODO.identity-sso/04 (the account lifecycle discipline, slice B) —
// the breached-password discipline over real HTTP and the real UI (the
// identity-profile stack + the HIBP range stub, the id-29 boot
// pattern):
//
//   leg 1  the REFUSAL through the setup page: a breached candidate is
//          refused with the plain-language error and the one-time link
//          STANDS — the same link then completes with a clean password;
//   leg 2  the ACCEPT + RE-CHECK arc: an unreachable corpus accepts the
//          enrollment (the audit notes it, the marker arms); the
//          revived corpus's BREACHED verdict rides the next password
//          sign-in — which completes anyway (the holder is never
//          stranded) — and the holder's own activity feed carries the
//          re-check row.
//
// SELF-CONTAINED: the suite's shared stack (E2E_BASE_URL) is untouched —
// own ports (API 10623 / astro 10624 / HIBP stub 10625 — above id-29's
// 10619-10622), own SQLite file.
//
// THE BROWSER IS PER-LEG (the id-02 lesson); cross-leg state rides the
// DATABASE + the stub's live corpus.
// ═══════════════════════════════════════════════════════════════════

import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import puppeteer, { type Browser, type Page } from 'puppeteer'
import { spawn, type ChildProcess } from 'node:child_process'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { existsSync, mkdirSync, rmSync, cpSync, appendFileSync } from 'node:fs'
import { closeBrowser, delay } from './helpers'
import { fixtureOpSigningKey } from './fixtures/op-signing-key'
import { startStubHibp, type StubHibp } from './fixtures/stub-hibp'

const BROWSER_DIR = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const FIXTURES = join(BROWSER_DIR, 'e2e', 'fixtures')
const DB_DIR = join(BROWSER_DIR, '.cache', 'id-30')

// Port-isolated: above id-29's 10619-10622.
const ID_API = 10623
const ID_WEB = 10624
const HIBP_PORT = 10625

const ISSUER = `http://localhost:${ID_WEB}` // the astro origin (the browser's OP)

const ROOT = { email: 'root@oimlsmart.org', name: 'Root Operator', password: 'the root operator passphrase' }
const UNA = { email: 'una@example.org', name: 'Una Example', breached: 'una breached passphrase', clean: 'una clean passphrase' }
const BEA = { email: 'bea@example.org', name: 'Bea Example', password: 'bea has a proper passphrase' }

interface Stack {
  api: ChildProcess
  astro: ChildProcess
  base: string
  apiBase: string
  logs: string[]
}

/** The candidate's range suffix (the check's own math, run by the test). */
async function sha1Suffix(password: string): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-1', new TextEncoder().encode(password)))
  return [...digest].map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase().slice(5)
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

/** Boot the identity-profile stack with the breach corpus bound to the
 *  stub (the HIBP_RANGE_URL seam — never the live service). */
async function bootIdentityStack(hibp: StubHibp): Promise<Stack> {
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
      // TODO.identity-sso/04 slice B's seam: the breach corpus is the
      // in-process stub, never the live service.
      HIBP_RANGE_URL: hibp.baseUrl,
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
// The FIRST /app/* navigation of a run compiles the whole app-shell
// island; on a contended host that cold compile outlives SETTLE (the
// id-02 lesson). The first account-page wait carries this budget.
const APP_COLD = 840_000

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

describe('TODO.identity-sso/04 slice B — the breached-password discipline (the identity profile)', () => {
  let stack: Stack
  let hibp: StubHibp
  let rootCookie: string

  beforeAll(async () => {
    hibp = await startStubHibp({ port: HIBP_PORT })
    stack = await bootIdentityStack(hibp)

    // ── the setup (over real HTTP, never the subject): the root admin's
    //    password through the boot-logged setup link. ──
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
  }, 600_000)

  afterAll(async () => {
    await hibp?.close()
    await stopStack(stack)
  })

  /** The admin invite over the real API (never the arc's subject). */
  async function invite(email: string, name: string): Promise<string> {
    const res = await fetch(`${stack.base}/api/op/accounts`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: rootCookie },
      body: JSON.stringify({ email, name }),
    })
    expect(res.status, `invite ${email}`).toBe(201)
    const { setupUrl } = await res.json() as { setupUrl: string }
    return setupUrl
  }

  it('leg 1 — the setup page refuses a breached password; the SAME link completes with a clean one', { timeout: 900_000 }, async () => {
    const setupUrl = await invite(UNA.email, UNA.name)
    hibp.corpus = new Set([await sha1Suffix(UNA.breached)])

    await withPage(async (page) => {
      flog(page, 'leg1: opening the setup link')
      await page.goto(setupUrl, { waitUntil: 'domcontentloaded', timeout: SETTLE })
      await page.waitForSelector('[data-testid="op-setup-password"]', { timeout: SETTLE, polling: 500 })

      await page.type('[data-testid="op-setup-password"]', UNA.breached)
      await page.type('[data-testid="op-setup-confirm"]', UNA.breached)
      await page.evaluate(() => (document.querySelector('[data-testid="op-setup-submit"]') as HTMLElement).click())
      await page.waitForSelector('[data-testid="op-setup-error"]', { timeout: SETTLE, polling: 500 })
      expect(await page.$eval('[data-testid="op-setup-error"]', el => el.textContent ?? ''))
        .toContain('known data breach')
      flog(page, 'leg1: the refusal rendered; the link stands (the form stayed)')

      // The link was never burned: the same page completes with a clean
      // password (the fields re-fill in place).
      hibp.corpus = new Set()
      for (const sel of ['[data-testid="op-setup-password"]', '[data-testid="op-setup-confirm"]']) {
        await page.click(sel, { count: 3 })
        await page.type(sel, UNA.clean)
      }
      await page.evaluate(() => (document.querySelector('[data-testid="op-setup-submit"]') as HTMLElement).click())
      // The successful setup signs the account in and lands on /op/account.
      await page.waitForFunction(() => window.location.pathname === '/op/account', { timeout: APP_COLD, polling: 500 })
      await page.waitForSelector('[data-testid="account-email"]', { timeout: SETTLE, polling: 500 })
      expect(await page.$eval('[data-testid="account-email"]', el => el.textContent ?? '')).toContain(UNA.email)
      flog(page, 'leg1: done')
    })
  })

  it('leg 2 — the unreachable corpus accepts; the revived corpus’s BREACHED verdict rides the next sign-in (never strands)', { timeout: 900_000 }, async () => {
    // The corpus is DOWN for the ceremony: the password lands anyway.
    hibp.down = true
    const setupUrl = await invite(BEA.email, BEA.name)
    const enroll = await fetch(`${stack.apiBase}/api/op/enroll/${new URL(setupUrl).searchParams.get('token')}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ password: BEA.password }),
    })
    expect(enroll.status, 'the unreachable corpus never strands the ceremony').toBe(200)
    flog(null, 'leg2: enrolled under the unreachable corpus; reviving it with the password in the corpus')

    // The corpus returns, now carrying the password: the sign-in re-runs
    // the check on the presented password — and STILL completes.
    hibp.down = false
    hibp.corpus = new Set([await sha1Suffix(BEA.password)])

    await withPage(async (page) => {
      flog(page, 'leg2: signing in through the login page')
      await page.goto(`${stack.base}/`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
      await page.waitForSelector('[data-testid="login-email"]', { timeout: SETTLE, polling: 500 })
      await page.type('[data-testid="login-email"]', BEA.email)
      await page.type('[data-testid="login-password"]', BEA.password)
      await page.evaluate(() => (document.querySelector('[data-testid="login-submit"]') as HTMLElement).click())
      await page.waitForFunction(() => window.location.pathname !== '/', { timeout: SETTLE, polling: 500 })

      // Never stranded: the console loads signed in…
      flog(page, 'leg2: signed in; the console’s activity feed carries the re-check')
      await page.goto(`${stack.base}/op/account`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
      await page.waitForSelector('[data-testid="account-email"]', { timeout: APP_COLD, polling: 500 })
      expect(await page.$eval('[data-testid="account-email"]', el => el.textContent ?? '')).toContain(BEA.email)

      // …and the holder's own activity feed names the re-check + its
      // breached verdict (the account-activity-<action> row convention).
      await page.waitForSelector('[data-testid="account-activity-account-password_breach_recheck"]', { timeout: SETTLE, polling: 500 })
      expect(await page.$eval('[data-testid="account-activity-account-password_breach_recheck"]', el => el.textContent ?? ''))
        .toContain('breached')
      flog(page, 'leg2: done')
    })
  })
})
