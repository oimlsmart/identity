// ═══════════════════════════════════════════════════════════════════
// TODO.identity/06 — the account-holder console e2e: the
// identity-profile stack (the id-02 spawned-stack pattern: own API +
// own astro + the stub GitHub) proves the console's five sections
// against the REAL pages and routes:
//
//   leg 1  the bootstrap: the seeded admin's logged setup link sets the
//          password; the admin invites Casey; her setup link lands on
//          the console — the five sections render, the address carries
//          its verified badge (the invite ceremony verified it);
//   leg 2  the profile: the inline rename (the empty name refuses
//          inline), then the verify-new-email ceremony: the request
//          shows the link HONESTLY (no mailer is configured), the link
//          page confirms, the address moves, the badge honestly drops
//          to "not verified", and the sign-in follows the new address;
//   leg 3  the sign-in methods: link GitHub (the real button, the stub
//          round trip), remove the password (allowed: a link remains),
//          THE GUARD: the last remaining method refuses with the
//          explanation (the button disabled, the server's 409 too),
//          then a fresh password re-enables the unlink;
//   leg 4  the password + the sessions: the honest meter, the wrong
//          current refused, the change revoking the OTHER session (the
//          notice names the count; the old cookie dies), the rows
//          carrying the user agent, and sign-out-everywhere-else;
//   leg 5  the activity feed: the account's own events, newest first;
//          the guide screenshots are captured here (the documentation
//          rule: real 1440x900 captures from the running app).
//
// SELF-CONTAINED: own ports (API 9493 / astro 9393; clear of id-01's
// 8693/8393, id-02's 8793/8593, id-08's 8993/8893 and id-10's
// 9193/9093), own SQLite file, the stub GitHub on a kernel-assigned
// port. THE BROWSER IS PER-LEG (the id-02 header note: a long-lived
// headless-shell wedges silently under load; cross-leg state rides the
// DATABASE).
// ═══════════════════════════════════════════════════════════════════

import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import puppeteer, { type Browser, type Page } from 'puppeteer'
import { spawn, type ChildProcess } from 'node:child_process'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { existsSync, mkdirSync, rmSync, cpSync, appendFileSync, writeFileSync } from 'node:fs'
import { closeBrowser, delay } from './helpers'
import { startStubGitHub, type StubGitHub } from './fixtures/stub-github'

const BROWSER_DIR = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const FIXTURES = join(BROWSER_DIR, 'e2e', 'fixtures')
const DB_DIR = join(BROWSER_DIR, '.cache', 'id-06')
const DOCS_IMG = join(BROWSER_DIR, '..', 'docs', 'guides', 'img')

const ID_API = 9493
const ID_WEB = 9393

const ISSUER = `http://localhost:${ID_WEB}` // the astro origin (the browser's OP)

const ROOT = { email: 'root@oimlsmart.org', name: 'Root Operator', password: 'the root operator passphrase' }
const CASEY = { email: 'casey@example.org', name: 'Casey Console', password: 'casey has a proper passphrase' }
const CASEY_EMAIL_2 = 'casey.renamed@example.org'
const CASEY_PASSWORD_2 = 'casey has an interim passphrase'
const CASEY_PASSWORD_3 = 'casey has the final passphrase 2026'
const GH_CASEY = { login: 'octocat-casey', id: 306, name: 'Octo Casey', email: 'casey-gh@example.org' }

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

/** Boot the identity-profile stack (the id-02 recipe, minus the fixture
 *  RP: this suite never drives the consent leg). */
async function bootIdentityStack(github: StubGitHub): Promise<Stack> {
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
      OP_ACCOUNT_SEED: JSON.stringify([{ email: ROOT.email, name: ROOT.name, role: 'admin' }]),
      // The linked login's upstream: the stub GitHub as a REGISTRY ROW
      // (TODO.identity/08 — a provider is a row, never a code fork).
      OP_UPSTREAM_SEED: JSON.stringify([{
        id: 'github',
        kind: 'github',
        display_name: 'GitHub',
        brand_mark: 'github',
        client_id: 'op-e2e',
        client_secret_ref: 'env:OP_E2E_GH_SECRET',
        enabled: true,
      }]),
      OP_E2E_GH_SECRET: 'op-e2e-secret',
      GITHUB_OAUTH_BASE_URL: github.baseUrl,
      GITHUB_API_BASE_URL: github.baseUrl,
    }, logs)
    const apiBase = `http://localhost:${ID_API}`
    await waitForHttp(`${apiBase}/api/health`, 120_000, logs)

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
// island cold; on a contended host that outlives SETTLE (the id-02
// lesson). The first console wait of each flow carries this budget.
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

/** The OP's password sign-in over fetch: the session cookie value. */
async function passwordCookie(base: string, email: string, password: string, userAgent?: string): Promise<string> {
  const res = await fetch(`${base}/api/op/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...(userAgent ? { 'user-agent': userAgent } : {}) },
    body: JSON.stringify({ email, password }),
  })
  expect(res.ok, `password sign-in ${email}`).toBe(true)
  return res.headers.get('set-cookie')!.split(';')[0]!.split('=')[1]!
}

/** Install a session cookie on the page (the fetch-level sign-in's
 *  continuity — the console then loads signed in). */
async function signInViaCookie(page: Page, base: string, cookieValue: string): Promise<void> {
  await page.setCookie({ name: 'oiml-session', value: cookieValue, url: base })
}

/** The OP's password sign-in through the login page form. */
async function opPasswordSignIn(page: Page, email: string, password: string): Promise<void> {
  await page.waitForSelector('[data-testid="login-email"]', { timeout: SETTLE, polling: 500 })
  await page.type('[data-testid="login-email"]', email)
  await page.type('[data-testid="login-password"]', password)
  await page.evaluate(() => (document.querySelector('[data-testid="login-submit"]') as HTMLElement).click())
}

/** Type into a field AFTER clearing it with input events (a bare .value
 *  assignment desyncs the v-model — the id-02 lesson). */
async function retype(page: Page, testid: string, value: string): Promise<void> {
  await page.evaluate((tid) => {
    const el = document.querySelector(`[data-testid="${tid}"]`) as HTMLInputElement
    el.value = ''
    el.dispatchEvent(new Event('input', { bubbles: true }))
  }, testid)
  if (value) await page.type(`[data-testid="${testid}"]`, value)
}

let stubGithub: StubGitHub

/** The stub GitHub's consent shortcut (the id-02 pattern): the browser
 *  drives the REAL button/redirect, the interception appends the fixture
 *  `login` param GitHub has no equivalent of. */
async function interceptStubGitHub(page: Page, login: string): Promise<void> {
  await page.setRequestInterception(true)
  page.on('request', (req) => {
    const url = req.url()
    const p = url.startsWith(`${stubGithub.baseUrl}/login/oauth/authorize`)
      ? req.continue({ url: `${url}&login=${login}` })
      : req.continue()
    // Teardown races in-flight deliveries: a continue() landing after
    // stopIntercepting disabled interception throws "Request Interception
    // is not enabled!" — and an event-handler throw fails the suite.
    void p.catch(() => {})
  })
}

async function stopIntercepting(page: Page): Promise<void> {
  page.removeAllListeners('request')
  await page.setRequestInterception(false)
}

/** The console, loaded signed in: navigate + wait for the profile card. */
async function openConsole(page: Page, base: string, cookie: string): Promise<void> {
  await signInViaCookie(page, base, cookie)
  await page.goto(`${base}/op/account`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
  await page.waitForSelector('[data-testid="account-name"]', { timeout: APP_COLD, polling: 500 })
}

describe('TODO.identity/06 — the account-holder console (the identity profile)', () => {
  let stack: Stack

  beforeAll(async () => {
    stubGithub = await startStubGitHub({ clientSecret: 'op-e2e-secret', users: [GH_CASEY] })
    stack = await bootIdentityStack(stubGithub)
  }, 600_000)

  afterAll(async () => {
    await stubGithub?.close()
    await stopStack(stack)
  })

  it('leg 1 — the bootstrap, the invite, the enrollment: the console’s five sections stand', { timeout: 900_000 }, async () => {
    // The seed logged the first admin's one-time link (the operator's way
    // in on a fresh OP) — read it from the API's log stream.
    const deadline = Date.now() + 60_000
    let setupUrl = ''
    while (Date.now() < deadline) {
      const m = /bootstrap: account root@oimlsmart\.org has no password[^\n]*\n\s*(\S+\/op\/setup\?token=\S+)/.exec(stack.logs.join(''))
      if (m) { setupUrl = m[1]!; break }
      await delay(500)
    }
    expect(setupUrl, 'the bootstrap setup link in the boot log').toContain('/op/setup?token=')

    await withPage(async (page) => {
      flog(page, 'leg1: the root setup')
      await page.goto(setupUrl, { waitUntil: 'domcontentloaded', timeout: SETTLE })
      await page.waitForSelector('[data-testid="op-setup-password"]', { timeout: SETTLE, polling: 500 })
      await page.type('[data-testid="op-setup-password"]', ROOT.password)
      await page.type('[data-testid="op-setup-confirm"]', ROOT.password)
      await page.evaluate(() => (document.querySelector('[data-testid="op-setup-submit"]') as HTMLElement).click())
      await page.waitForSelector('[data-testid="account-name"]', { timeout: APP_COLD, polling: 500 })
      flog(page, 'leg1: root enrolled')
    })

    // The admin invites Casey over the API (the registry console UI is
    // TODO.identity/03/07's).
    const rootCookie = await passwordCookie(stack.base, ROOT.email, ROOT.password)
    const invite = await fetch(`${stack.base}/api/op/accounts`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: `oiml-session=${rootCookie}` },
      body: JSON.stringify({ email: CASEY.email, name: CASEY.name }),
    })
    expect(invite.status).toBe(201)
    const { setupUrl: caseySetup } = await invite.json() as { setupUrl: string }
    flog(null, 'leg1: Casey invited')

    await withPage(async (page) => {
      // Casey's browser is a FRESH one (no cookies).
      await page.goto(caseySetup, { waitUntil: 'domcontentloaded', timeout: SETTLE })
      await page.waitForSelector('[data-testid="op-setup-account"]', { timeout: SETTLE, polling: 500 })
      expect(await page.$eval('[data-testid="op-setup-account"]', el => el.textContent ?? '')).toContain(CASEY.email)
      await page.type('[data-testid="op-setup-password"]', CASEY.password)
      await page.type('[data-testid="op-setup-confirm"]', CASEY.password)
      await page.evaluate(() => (document.querySelector('[data-testid="op-setup-submit"]') as HTMLElement).click())
      await page.waitForSelector('[data-testid="account-name"]', { timeout: APP_COLD, polling: 500 })
      expect(await page.$eval('[data-testid="account-name"]', el => el.textContent?.trim())).toBe(CASEY.name)

      // The five sections stand: profile, sign-in methods, password,
      // sessions, activity — each deep-linkable by its anchor id.
      for (const testid of ['account-profile', 'account-links', 'account-password', 'account-sessions', 'account-activity']) {
        await page.waitForSelector(`[data-testid="${testid}"]`, { timeout: SETTLE, polling: 500 })
      }
      // The invite ceremony verified the address on file.
      await page.waitForSelector('[data-testid="account-email-verified"]', { timeout: SETTLE, polling: 500 })
      // The password method row + the no-links empty state.
      await page.waitForSelector('[data-testid="account-method-password"]', { timeout: SETTLE, polling: 500 })
      await page.waitForSelector('[data-testid="op-account-no-links"]', { timeout: SETTLE, polling: 500 })
      // The activity feed already carries the enrollment.
      await page.waitForSelector('[data-testid="account-activity-account-enrolled"]', { timeout: SETTLE, polling: 500 })
      flog(page, 'leg1: the console stands')
    })
  })

  it('leg 2 — the profile: the inline rename and the honestly-shown email change', { timeout: 900_000 }, async () => {
    const cookie = await passwordCookie(stack.base, CASEY.email, CASEY.password)
    await withPage(async (page) => {
      await openConsole(page, stack.base, cookie)

      // The inline rename: an empty name refuses inline (persistent
      // validation), the real one saves and the header name follows.
      await page.evaluate(() => (document.querySelector('[data-testid="account-profile-edit"]') as HTMLElement).click())
      await page.waitForSelector('[data-testid="account-profile-name-input"]', { timeout: 30_000, polling: 200 })
      await retype(page, 'account-profile-name-input', '   ')
      await page.evaluate(() => (document.querySelector('[data-testid="account-profile-save"]') as HTMLElement).click())
      await page.waitForSelector('[data-testid="account-profile-name-error"]', { timeout: 30_000, polling: 200 })
      await retype(page, 'account-profile-name-input', 'Casey Console-Renamed')
      await page.evaluate(() => (document.querySelector('[data-testid="account-profile-save"]') as HTMLElement).click())
      await page.waitForFunction(
        () => document.querySelector('[data-testid="account-name"]')?.textContent?.trim() === 'Casey Console-Renamed',
        { timeout: 60_000, polling: 500 },
      )
      flog(page, 'leg2: renamed')

      // The email change: the request shows the link HONESTLY (no mailer
      // is configured), with the explanation.
      await page.type('[data-testid="account-email-input"]', CASEY_EMAIL_2)
      await page.evaluate(() => (document.querySelector('[data-testid="account-email-submit"]') as HTMLElement).click())
      await page.waitForSelector('[data-testid="account-email-delivery"]', { timeout: 60_000, polling: 500 })
      const delivery = await page.$eval('[data-testid="account-email-delivery"]', el => el.textContent ?? '')
      expect(delivery).toContain('No mailer is configured')
      // The pending change rides the console.
      await page.waitForSelector('[data-testid="account-email-pending"]', { timeout: 60_000, polling: 500 })
      // The documentation rule: the honest-link state is a guide capture.
      const box = await page.$('[data-testid="account-email-delivery"]')
      await box!.screenshot({ path: join(DOCS_IMG, 'oimlsmart-account-email-change.png') })
      const href = await page.$eval('[data-testid="account-email-link"]', el => el.getAttribute('href') ?? '')
      expect(href).toContain('/op/email-change?token=')
      flog(page, 'leg2: the link is shown honestly')

      // Open the link (same tab — the ceremony's page), confirm, and the
      // result card says plainly that nothing proved the mailbox.
      await page.goto(new URL(href).toString(), { waitUntil: 'domcontentloaded', timeout: SETTLE })
      await page.waitForSelector('[data-testid="op-email-change-context"]', { timeout: SETTLE, polling: 500 })
      const contextText = await page.$eval('[data-testid="op-email-change-context"]', el => el.textContent ?? '')
      expect(contextText).toContain(CASEY.email)
      expect(contextText).toContain(CASEY_EMAIL_2)
      await page.evaluate(() => (document.querySelector('[data-testid="op-email-change-confirm"]') as HTMLElement).click())
      await page.waitForSelector('[data-testid="op-email-change-done"]', { timeout: 60_000, polling: 500 })
      await page.waitForSelector('[data-testid="op-email-change-unverified"]', { timeout: 30_000, polling: 200 })
      flog(page, 'leg2: the change confirmed')

      // Back at the console: the new address, the honest unverified badge.
      await page.goto(`${stack.base}/op/account`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
      await page.waitForSelector('[data-testid="account-email"]', { timeout: SETTLE, polling: 500 })
      expect(await page.$eval('[data-testid="account-email"]', el => el.textContent?.trim())).toBe(CASEY_EMAIL_2)
      await page.waitForSelector('[data-testid="account-email-unverified"]', { timeout: SETTLE, polling: 500 })
      flog(page, 'leg2: done')
    })

    // The sign-in follows the new address; the old one refuses.
    await passwordCookie(stack.base, CASEY_EMAIL_2, CASEY.password)
    const oldRefused = await fetch(`${stack.base}/api/op/login`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: CASEY.email, password: CASEY.password }),
    })
    expect(oldRefused.status).toBe(401)
  })

  it('leg 3 — the sign-in methods: link, password removal, the last-method guard, unlink', { timeout: 900_000 }, async () => {
    const cookie = await passwordCookie(stack.base, CASEY_EMAIL_2, CASEY.password)
    await withPage(async (page) => {
      await openConsole(page, stack.base, cookie)

      // Link GitHub: the real button, the signed state, the stub round trip.
      await page.waitForSelector('[data-testid="op-account-link-github-action"]', { timeout: SETTLE, polling: 500 })
      await interceptStubGitHub(page, GH_CASEY.login)
      try {
        await page.evaluate(() => (document.querySelector('[data-testid="op-account-link-github-action"]') as HTMLElement).click())
        await page.waitForFunction(
          () => window.location.pathname === '/op/account' && window.location.search.includes('linked=github'),
          { timeout: SETTLE, polling: 500 },
        )
        // The URL matches at navigation START — the page's load still
        // streams through the listener; tear interception down once the
        // page STANDS (the id-02 teardown lesson).
        await page.waitForSelector('[data-testid="account-name"]', { timeout: SETTLE, polling: 500 })
      } finally {
        await stopIntercepting(page)
      }
      await page.waitForSelector('[data-testid="op-account-link-github"]', { timeout: SETTLE, polling: 500 })
      // The row names the provider and the linked account id (never an email).
      expect(await page.$eval('[data-testid="op-account-link-github"]', el => el.textContent ?? '')).toContain(String(GH_CASEY.id))
      flog(page, 'leg3: GitHub linked')

      // Remove the password: allowed, a link remains.
      await page.waitForSelector('[data-testid="account-method-password-remove"]', { timeout: SETTLE, polling: 500 })
      await page.evaluate(() => (document.querySelector('[data-testid="account-method-password-remove"]') as HTMLElement).click())
      await page.waitForFunction(
        () => document.querySelector('[data-testid="account-method-password-state"]')?.textContent?.includes('No password set'),
        { timeout: 60_000, polling: 500 },
      )
      flog(page, 'leg3: the password removed')

      // THE GUARD: the GitHub link is now the ONLY way in — the unlink
      // button is disabled and explains itself…
      const disabled = await page.$eval('[data-testid="op-account-unlink-github"]', el => (el as HTMLButtonElement).disabled)
      expect(disabled, 'the unlink disabled on the last method').toBe(true)
      await page.waitForSelector('[data-testid="account-link-guard"]', { timeout: 30_000, polling: 200 })
      expect(await page.$eval('[data-testid="account-link-guard"]', el => el.textContent ?? '')).toContain('only way to sign in')
      // …and the server holds the same rule (the UI is never the gate).
      const refused = await fetch(`${stack.base}/api/op/account/links/github`, {
        method: 'DELETE',
        headers: { cookie: `oiml-session=${cookie}` },
      })
      expect(refused.status).toBe(409)
      expect(await refused.json()).toMatchObject({ error: expect.stringContaining('only way to sign in') })
      flog(page, 'leg3: the guard holds')

      // Set a fresh password (no current field when none is set)…
      await page.type('[data-testid="account-password-next"]', CASEY_PASSWORD_2)
      await page.type('[data-testid="account-password-confirm"]', CASEY_PASSWORD_2)
      await page.evaluate(() => (document.querySelector('[data-testid="account-password-submit"]') as HTMLElement).click())
      await page.waitForFunction(
        () => document.querySelector('[data-testid="account-method-password-state"]')?.textContent?.includes('A password is set'),
        { timeout: 60_000, polling: 500 },
      )
      // …and the unlink is enabled again — and works.
      await page.waitForFunction(
        () => !(document.querySelector('[data-testid="op-account-unlink-github"]') as HTMLButtonElement | null)?.disabled,
        { timeout: 60_000, polling: 500 },
      )
      await page.evaluate(() => (document.querySelector('[data-testid="op-account-unlink-github"]') as HTMLElement).click())
      await page.waitForSelector('[data-testid="op-account-no-links"]', { timeout: 60_000, polling: 500 })
      flog(page, 'leg3: unlinked, the console honest throughout')
    })
  })

  it('leg 4 — the password change revokes the other session; the sessions section shows context', { timeout: 900_000 }, async () => {
    // A second live session, stamped with its own user agent.
    const otherCookie = await passwordCookie(stack.base, CASEY_EMAIL_2, CASEY_PASSWORD_2, 'e2e-second-browser/1.0')
    const cookie = await passwordCookie(stack.base, CASEY_EMAIL_2, CASEY_PASSWORD_2)
    await withPage(async (page) => {
      await openConsole(page, stack.base, cookie)

      // The sessions section lists both, the other's user agent named.
      await page.waitForFunction(
        () => document.querySelectorAll('[data-testid="account-session-list"] > li').length >= 2,
        { timeout: 60_000, polling: 500 },
      )
      const agents = await page.$$eval('[data-testid="account-session-list"] > li', rows => rows.map(r => r.textContent ?? ''))
      expect(agents.some(text => text.includes('e2e-second-browser/1.0')), 'the other session’s user agent named').toBe(true)
      await page.waitForSelector('[data-testid="account-session-current"]', { timeout: 30_000, polling: 200 })
      flog(page, 'leg4: the sessions carry their context')

      // The honest meter advises while typing…
      await page.type('[data-testid="account-password-next"]', 'short')
      await page.waitForSelector('[data-testid="account-password-meter-label"]', { timeout: 30_000, polling: 200 })
      expect(await page.$eval('[data-testid="account-password-meter-label"]', el => el.textContent?.trim())).toBe('Too short')
      // …the wrong current refuses…
      await retype(page, 'account-password-next', CASEY_PASSWORD_3)
      await page.type('[data-testid="account-password-current"]', 'not casey password at all')
      await page.type('[data-testid="account-password-confirm"]', CASEY_PASSWORD_3)
      await page.evaluate(() => (document.querySelector('[data-testid="account-password-submit"]') as HTMLElement).click())
      await page.waitForSelector('[data-testid="op-account-error"]', { timeout: 60_000, polling: 500 })
      expect(await page.$eval('[data-testid="op-account-error"]', el => el.textContent ?? '')).toContain('current password')
      flog(page, 'leg4: the wrong current refused')

      // …and the real change names the revocation of the other session.
      await retype(page, 'account-password-current', CASEY_PASSWORD_2)
      await retype(page, 'account-password-next', CASEY_PASSWORD_3)
      await retype(page, 'account-password-confirm', CASEY_PASSWORD_3)
      await page.evaluate(() => (document.querySelector('[data-testid="account-password-submit"]') as HTMLElement).click())
      await page.waitForSelector('[data-testid="op-account-notice"]', { timeout: 60_000, polling: 500 })
      const notice = await page.$eval('[data-testid="op-account-notice"]', el => el.textContent ?? '')
      expect(notice).toContain('password was changed')
      expect(notice).toContain('other session')
      flog(page, 'leg4: changed; the other session revoked')
    })

    // The other session's cookie is dead; a fresh sign-in needs the NEW password.
    const dead = await fetch(`${stack.base}/api/auth/session`, { headers: { cookie: `oiml-session=${otherCookie}` } })
    expect(dead.status).toBe(401)
    await passwordCookie(stack.base, CASEY_EMAIL_2, CASEY_PASSWORD_3)

    // Sign-out-everywhere-else: two fresh sessions, the console's button,
    // only the current one remains.
    await passwordCookie(stack.base, CASEY_EMAIL_2, CASEY_PASSWORD_3)
    const cookie3 = await passwordCookie(stack.base, CASEY_EMAIL_2, CASEY_PASSWORD_3)
    await withPage(async (page) => {
      await openConsole(page, stack.base, cookie3)
      await page.waitForFunction(
        () => document.querySelectorAll('[data-testid="account-session-list"] > li').length >= 2,
        { timeout: 60_000, polling: 500 },
      )
      await page.evaluate(() => (document.querySelector('[data-testid="account-sessions-revoke-others"]') as HTMLElement).click())
      await page.waitForFunction(
        () => document.querySelectorAll('[data-testid="account-session-list"] > li').length === 1,
        { timeout: 60_000, polling: 500 },
      )
      await page.waitForSelector('[data-testid="account-sessions-only-current"]', { timeout: 60_000, polling: 500 })
      flog(page, 'leg4: everywhere else signed out')
    })
  })

  it('leg 5 — the activity feed is the account’s own, newest first; the guide captures', { timeout: 900_000 }, async () => {
    const cookie = await passwordCookie(stack.base, CASEY_EMAIL_2, CASEY_PASSWORD_3)
    await withPage(async (page) => {
      await openConsole(page, stack.base, cookie)

      // The feed carries the account's own journey: the enrollment, the
      // sign-ins, the rename, the email change, the password acts, the
      // link and the unlink.
      await page.waitForSelector('[data-testid="account-activity-list"]', { timeout: SETTLE, polling: 500 })
      for (const testid of [
        'account-activity-account-enrolled',
        'account-activity-account-sign_in',
        'account-activity-account-profile',
        'account-activity-account-email_changed',
        'account-activity-account-password',
        'account-activity-account-password_removed',
        'account-activity-upstream_link',
        'account-activity-upstream_unlink',
        'account-activity-account-sessions_revoked',
      ]) {
        await page.waitForSelector(`[data-testid="${testid}"]`, { timeout: 60_000, polling: 500 })
      }
      // Newest first: this leg's sign-in tops the list.
      const firstRow = await page.$eval('[data-testid="account-activity-list"] > li:first-child', el => el.textContent ?? '')
      expect(firstRow).toContain('Signed in')
      // Never another account's events: the root admin's own sign-ins and
      // her other acts never appear (Casey's invite DOES: it is an act on
      // her account, and the feed says so in her own terms).
      const feedText = await page.$eval('[data-testid="account-activity-list"]', el => el.textContent ?? '')
      expect(feedText).toContain('The administrator created this account')
      expect(feedText).not.toContain(ROOT.email)
      flog(page, 'leg5: the feed is honest')

      // The documentation rule: the console's guide capture, 1440x900.
      // The astro dev toolbar is a fixed overlay that paints over the
      // page in fullPage captures; hide it for the shots (the captured
      // sections are untouched).
      await page.addStyleTag({ content: 'astro-dev-toolbar { display: none !important }' })
      await page.evaluate(() => window.scrollTo(0, 0))
      await page.screenshot({ path: join(DOCS_IMG, 'oimlsmart-account.png'), fullPage: true })
      // The activity feed's own capture for the guide's activity section.
      // The sticky app header is also a fixed overlay: an element capture
      // scrolls the section under it, so hide it for the shot.
      await page.addStyleTag({ content: 'header.sticky { display: none !important }' })
      const feed = await page.$('[data-testid="account-activity"]')
      await feed!.screenshot({ path: join(DOCS_IMG, 'oimlsmart-account-activity.png') })
      flog(page, 'leg5: the guide captures landed')
    })
  })

  it('leg 6 — the avatar: the upload (capped + type-allowlisted), the renders, the removal', { timeout: 900_000 }, async () => {
    const cookie = await passwordCookie(stack.base, CASEY_EMAIL_2, CASEY_PASSWORD_3)
    // The fixtures: a real 1x1 PNG, an SVG (never an avatar type), and a
    // 2 MiB + 1 payload with a real PNG header (the oversize leg).
    const PNG_1PX = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==', 'base64')
    const pngPath = join(DB_DIR, 'casey-avatar.png')
    const svgPath = join(DB_DIR, 'not-an-avatar.svg')
    const bigPath = join(DB_DIR, 'too-big.png')
    writeFileSync(pngPath, PNG_1PX)
    writeFileSync(svgPath, '<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>')
    const big = Buffer.alloc(2 * 1024 * 1024 + 1)
    PNG_1PX.copy(big)
    writeFileSync(bigPath, big)

    await withPage(async (page) => {
      await openConsole(page, stack.base, cookie)
      flog(page, 'leg6: the console, no avatar yet — the initials stand in')

      // The initials state + the upload affordance (the disk blob store
      // is bound on the node stack, so the feature shows, with its limit
      // named in the note).
      await page.waitForSelector('[data-testid="account-avatar-initials"]', { timeout: SETTLE, polling: 500 })
      await page.waitForSelector('[data-testid="account-avatar-change"]', { timeout: SETTLE, polling: 500 })
      expect(await page.$eval('[data-testid="account-avatar-note"]', el => el.textContent ?? '')).toContain('2 MB')

      // The client-side refusals (the honest fast paths; the server
      // re-judges both — proven below).
      const input = await page.$('[data-testid="account-avatar-input"]')
      await input!.uploadFile(svgPath)
      await page.waitForSelector('[data-testid="account-avatar-error"]', { timeout: 30_000, polling: 250 })
      expect(await page.$eval('[data-testid="account-avatar-error"]', el => el.textContent ?? '')).toContain('PNG, JPEG, WebP or GIF')
      await input!.uploadFile(bigPath)
      await page.waitForFunction(
        () => (document.querySelector('[data-testid="account-avatar-error"]')?.textContent ?? '').includes('2 MB'),
        { timeout: 30_000, polling: 250 },
      )
      flog(page, 'leg6: the client-side refusals named the rules')

      // The server-side gates (the page is never the only gate): the SVG
      // 415s, the 2 MiB + 1 body 413s.
      const refused = await page.evaluate(async (pngB64) => {
        const png = Uint8Array.from(atob(pngB64), ch => ch.charCodeAt(0))
        const svg = new TextEncoder().encode('<svg xmlns="http://www.w3.org/2000/svg"/>')
        const bigBody = new Uint8Array(2 * 1024 * 1024 + 1)
        bigBody.set(png, 0)
        const results: Record<string, number> = {}
        results.svg = (await fetch('/api/op/account/avatar', { method: 'PUT', headers: { 'content-type': 'image/svg+xml' }, credentials: 'include', body: svg })).status
        results.big = (await fetch('/api/op/account/avatar', { method: 'PUT', headers: { 'content-type': 'image/png' }, credentials: 'include', body: bigBody })).status
        return results
      }, PNG_1PX.toString('base64'))
      expect(refused).toEqual({ svg: 415, big: 413 })
      flog(page, 'leg6: the server gates held (415 + 413)')

      // The upload: the real PNG through the console's own input.
      await input!.uploadFile(pngPath)
      await page.waitForSelector('[data-testid="account-avatar"]', { timeout: SETTLE, polling: 500 })
      flog(page, 'leg6: uploaded — the picture renders on the console')

      // The serving route answers the bytes with the image type.
      const served = await page.evaluate(async () => {
        const res = await fetch('/api/op/account/avatar', { credentials: 'include' })
        return { status: res.status, type: res.headers.get('content-type'), bytes: (await res.arrayBuffer()).byteLength }
      })
      expect(served).toMatchObject({ status: 200, type: 'image/png', bytes: PNG_1PX.byteLength })

      // The header's session payload loads at bootstrap, so the user
      // menu's picture shows from the next navigation — reload, then the
      // menu button renders it (and the console re-reads its context).
      await page.reload({ waitUntil: 'domcontentloaded', timeout: SETTLE })
      await page.waitForSelector('[data-testid="account-name"]', { timeout: APP_COLD, polling: 500 })
      await page.waitForSelector('[data-testid="header-avatar"]', { timeout: SETTLE, polling: 500 })
      const headerSrc = await page.$eval('[data-testid="header-avatar"]', el => (el as HTMLImageElement).src)
      expect(headerSrc).toContain('/api/op/account/avatar')
      await page.waitForSelector('[data-testid="account-avatar"]', { timeout: SETTLE, polling: 500 })
      flog(page, 'leg6: the header’s user menu renders the picture')

      // The guide capture: the profile card with the uploaded picture.
      await page.addStyleTag({ content: 'astro-dev-toolbar { display: none !important }' })
      const card = await page.$('[data-testid="account-profile"]')
      await card!.screenshot({ path: join(DOCS_IMG, 'oimlsmart-account-avatar.png') })

      // The removal: the initials stand in again, the serve 404s.
      await page.evaluate(() => (document.querySelector('[data-testid="account-avatar-remove"]') as HTMLElement).click())
      await page.waitForSelector('[data-testid="account-avatar-initials"]', { timeout: SETTLE, polling: 500 })
      const gone = await page.evaluate(async () => (await fetch('/api/op/account/avatar', { credentials: 'include' })).status)
      expect(gone).toBe(404)
      flog(page, 'leg6: removed — the initials stand in again')
    })
  })
})
