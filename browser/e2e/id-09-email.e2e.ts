// ═══════════════════════════════════════════════════════════════════
// TODO.identity/09 — the transactional email e2e: the identity-profile
// stack boots with the HTTPS mail provider pointed at the STUB mailer
// (e2e/fixtures/stub-mailer.ts — real HTTP, the Resend-shaped capture),
// so the whole path runs for real except the final delivery:
//
//   leg 1  the bootstrap seed (OP_ACCOUNT_SEED) mints the first admin's
//          setup link — read from the boot log, driven through /op/setup
//          (also warms the app-shell compile for the later legs);
//   leg 2  the admin signs in, opens the registry console, and invites
//          Willa THROUGH THE FORM — the console says the setup email was
//          sent (the invite-mail-status line), and the stub captured
//          exactly one message: to Willa, the invite subject, the SAME
//          one-time link the console shows;
//   leg 3  Willa's browser drives the link FROM THE CAPTURED EMAIL (not
//          from the console) through /op/setup → the password set → the
//          account page; then a password sign-in fires the new-sign-in
//          notification, also captured.
//
// SELF-CONTAINED: the suite's shared stack (E2E_BASE_URL) is untouched —
// own ports (API 8795 / astro 8595), own SQLite file, the stub mailer on
// a kernel-assigned port.
//
// THE BROWSER IS PER-LEG (the id-02 lesson: a long-lived headless-shell
// launched during a load spike wedges silently; a fresh browser per leg
// costs ~2 s and dodges the class). Cross-leg state rides the DATABASE.
// ═══════════════════════════════════════════════════════════════════

import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import puppeteer, { type Browser, type Page } from 'puppeteer'
import { spawn, type ChildProcess } from 'node:child_process'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { existsSync, mkdirSync, rmSync, cpSync, appendFileSync } from 'node:fs'
import { closeBrowser, delay } from './helpers'
import { startStubMailer, type StubMailer } from './fixtures/stub-mailer'

const BROWSER_DIR = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const FIXTURES = join(BROWSER_DIR, 'e2e', 'fixtures')
const DB_DIR = join(BROWSER_DIR, '.cache', 'id-09')

// Port-isolated: clear of the shared dev stack (5190/3190), the fed-01
// stacks (8291/8292/8491/8492), the fed-10 stub (8699), the id-01 stack
// (8693/8393/8694) and the id-02 stack (8793/8593/8794).
const ID_API = 8795
const ID_WEB = 8595

const ISSUER = `http://localhost:${ID_WEB}` // the astro origin (the browser's OP)
const MAIL_KEY = 'id09-stub-mail-key'

const ROOT = { email: 'root@oimlsmart.org', name: 'Root Operator', password: 'the root operator passphrase' }
const WILLA = { email: 'willa@example.org', name: 'Willa Example', password: 'willa has a proper passphrase' }

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

/** Boot the identity-profile stack with the mail provider bound to the
 *  stub: the API on its own SQLite file with the OP env + the mail env
 *  (EMAIL_FROM / MAIL_PROVIDER_URL / MAIL_PROVIDER_KEY), the profile
 *  seed through the dev-reset seam, astro dev against it. */
async function bootIdentityStack(mailer: StubMailer): Promise<Stack> {
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
      // The first administrator arrives by DECLARATION (invite-only means
      // nobody else can mint the first link) — the setup link lands in
      // the boot log.
      OP_ACCOUNT_SEED: JSON.stringify([{ email: ROOT.email, name: ROOT.name, role: 'admin' }]),
      // TODO.identity/09 — the mail provider UNDER TEST: the stub HTTPS
      // receiver (the Resend-shaped seam) with its expected key.
      EMAIL_FROM: 'OIML SMART Identity <no-reply@oimlsmart.org>',
      MAIL_PROVIDER_URL: `${mailer.baseUrl}/emails`,
      MAIL_PROVIDER_KEY: MAIL_KEY,
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

/** The OP's password sign-in over fetch: the session cookie value. */
async function passwordCookie(base: string, email: string, password: string): Promise<string> {
  const res = await fetch(`${base}/api/op/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
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

/** The one link line of a captured email's text body. */
function linkFromEmailText(text: string | undefined): string {
  const link = (text ?? '').split('\n').map(l => l.trim()).find(l => l.startsWith('http'))
  expect(link, 'the email text carries its action link').toBeTruthy()
  return link!
}

describe('TODO.identity/09 — the transactional email (the stub provider)', () => {
  let stack: Stack
  let mailer: StubMailer

  beforeAll(async () => {
    mailer = await startStubMailer({ expectedKey: MAIL_KEY })
    stack = await bootIdentityStack(mailer)
  }, 600_000)

  afterAll(async () => {
    await mailer?.close()
    await stopStack(stack)
  })

  it('leg 1 — the bootstrap seed: the first admin’s logged setup link sets the password through /op/setup', { timeout: 900_000 }, async () => {
    // The seed logged the one-time link (the operator's way in on a
    // fresh OP) — read it from the API's log stream. NOTE: the mailer
    // does not cover the bootstrap seed (the spec's four flows are the
    // invite, the reset, the sign-in notification, and 06's verify); the
    // logged-link posture stands here.
    const deadline = Date.now() + 60_000
    let setupUrl = ''
    while (Date.now() < deadline) {
      const m = /bootstrap: account root@oimlsmart\.org has no password[^\n]*\n\s*(\S+\/op\/setup\?token=\S+)/.exec(stack.logs.join(''))
      if (m) { setupUrl = m[1]!; break }
      await delay(500)
    }
    expect(setupUrl, 'the bootstrap setup link in the boot log').toContain('/op/setup?token=')

    await withPage(async (page) => {
      flog(page, 'leg1: going to the setup page')
      await page.goto(setupUrl, { waitUntil: 'domcontentloaded', timeout: SETTLE })
      await page.waitForSelector('[data-testid="op-setup-account"]', { timeout: SETTLE, polling: 500 })
      const who = await page.$eval('[data-testid="op-setup-account"]', el => el.textContent ?? '')
      expect(who).toContain(ROOT.name)
      await page.type('[data-testid="op-setup-password"]', ROOT.password)
      await page.type('[data-testid="op-setup-confirm"]', ROOT.password)
      await page.evaluate(() => (document.querySelector('[data-testid="op-setup-submit"]') as HTMLElement).click())
      flog(page, 'leg1: submitted; the first app-shell navigation compiles cold')
      await page.waitForSelector('[data-testid="account-name"]', { timeout: APP_COLD, polling: 500 })
      expect(new URL(page.url()).pathname).toBe('/op/account')
      expect(await page.$eval('[data-testid="account-name"]', el => el.textContent?.trim())).toBe(ROOT.name)
      flog(page, 'leg1: done')
    })
  })

  it('leg 2 — the admin invites Willa through the registry form; the console says the email was sent and the stub captured it', { timeout: 900_000 }, async () => {
    const rootCookie = await passwordCookie(stack.base, ROOT.email, ROOT.password)
    mailer.reset() // root's own sign-in notification is not this leg's subject

    await withPage(async (page) => {
      await signInViaCookie(page, stack.base, rootCookie)
      flog(page, 'leg2: opening the registry console')
      await page.goto(`${stack.base}/op/admin/users`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
      await page.waitForSelector('[data-testid="registry-invite-name"]', { timeout: SETTLE, polling: 500 })
      await page.type('[data-testid="registry-invite-name"]', WILLA.name)
      await page.type('[data-testid="registry-invite-email"]', WILLA.email)
      await page.evaluate(() => (document.querySelector('[data-testid="registry-invite-submit"]') as HTMLElement).click())
      flog(page, 'leg2: invited; waiting for the console confirmation')

      // The console leads with the email delivery (TODO.identity/09):
      // the notice and the invite card's mail-status line both say sent.
      await page.waitForSelector('[data-testid="invite-mail-status"]', { timeout: SETTLE, polling: 500 })
      expect(await page.$eval('[data-testid="invite-mail-status"]', el => el.textContent ?? ''))
        .toContain(`The setup email was sent to ${WILLA.email}`)
      expect(await page.$eval('[data-testid="op-admin-notice"]', el => el.textContent ?? ''))
        .toContain('the setup email is on its way')
      // The link stays visible as the fallback — the SAME link the email carries.
      const shown = await page.$eval('[data-testid="invite-setup-url"]', el => el.textContent ?? '')
      expect(shown).toContain('/op/setup?token=')

      expect(mailer.messages).toHaveLength(1)
      const mail = mailer.messages[0]!
      expect(mail.to).toBe(WILLA.email)
      expect(mail.from).toBe('OIML SMART Identity <no-reply@oimlsmart.org>')
      expect(mail.subject).toBe('Your OIML SMART Identity account is ready to set up')
      expect(mail.text).toContain(`Hello ${WILLA.name},`)
      expect(linkFromEmailText(mail.text)).toBe(shown.trim())
      expect(mail.html).toContain('Set your password')
      flog(page, 'leg2: done — the captured email carries the console’s link')
    })
  })

  it('leg 3 — Willa completes setup FROM THE EMAIL’s link, and the sign-in notification follows', { timeout: 900_000 }, async () => {
    const emailed = linkFromEmailText(mailer.messages[0]?.text)
    expect(emailed).toContain(`${ISSUER}/op/setup?token=`)

    await withPage(async (page) => {
      // Willa's browser is a FRESH one (no cookies) — the email's link
      // is the whole credential.
      flog(page, 'leg3: opening the emailed link')
      await page.goto(emailed, { waitUntil: 'domcontentloaded', timeout: SETTLE })
      await page.waitForSelector('[data-testid="op-setup-account"]', { timeout: SETTLE, polling: 500 })
      expect(await page.$eval('[data-testid="op-setup-account"]', el => el.textContent ?? '')).toContain(WILLA.email)
      await page.type('[data-testid="op-setup-password"]', WILLA.password)
      await page.type('[data-testid="op-setup-confirm"]', WILLA.password)
      await page.evaluate(() => (document.querySelector('[data-testid="op-setup-submit"]') as HTMLElement).click())
      await page.waitForSelector('[data-testid="account-name"]', { timeout: APP_COLD, polling: 500 })
      expect(await page.$eval('[data-testid="account-name"]', el => el.textContent?.trim())).toBe(WILLA.name)
      flog(page, 'leg3: enrolled from the email')

      // The new-sign-in notification: a password sign-in tells the
      // account holder through the same channel.
      mailer.reset()
      await passwordCookie(stack.base, WILLA.email, WILLA.password)
      const deadline = Date.now() + 15_000
      while (mailer.messages.length === 0 && Date.now() < deadline) await delay(250)
      expect(mailer.messages).toHaveLength(1)
      expect(mailer.messages[0]!.to).toBe(WILLA.email)
      expect(mailer.messages[0]!.subject).toBe('New sign-in to your OIML SMART Identity account')
      expect(mailer.messages[0]!.text).toContain('by the password sign-in')
      flog(page, 'leg3: the sign-in notification arrived')
    })
  })

  it('leg 4 — the self-service reset: the login page’s forgot-password mails the link, the emailed link resets, and no address is an oracle', { timeout: 900_000 }, async () => {
    const WILLA_RESET = 'willa has the reset passphrase 2026'
    mailer.reset()

    await withPage(async (page) => {
      // Willa forgot her password. The identity-profile login page
      // carries the forgot-password affordance (the OP's own surface).
      flog(page, 'leg4: the login page')
      await page.goto(`${stack.base}/`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
      await page.waitForSelector('[data-testid="login-forgot"]', { timeout: SETTLE, polling: 500 })
      await page.evaluate(() => (document.querySelector('[data-testid="login-forgot"]') as HTMLElement).click())
      await page.waitForSelector('[data-testid="login-reset-email"]', { timeout: SETTLE, polling: 500 })
      await page.type('[data-testid="login-reset-email"]', WILLA.email)
      await page.evaluate(() => (document.querySelector('[data-testid="login-reset-submit"]') as HTMLElement).click())
      flog(page, 'leg4: reset requested; the constant answer must show')

      // The page's answer NEVER says whether the account exists.
      await page.waitForSelector('[data-testid="login-reset-done"]', { timeout: SETTLE, polling: 500 })
      const shown = await page.$eval('[data-testid="login-reset-done"]', el => el.textContent ?? '')
      expect(shown).toContain('If an account exists')

      // The reset email arrived: to Willa, the reset subject, the
      // one-time link. NOTHING else rides the page (no URL in the DOM).
      const deadline = Date.now() + 15_000
      while (mailer.messages.length === 0 && Date.now() < deadline) await delay(250)
      expect(mailer.messages).toHaveLength(1)
      const mail = mailer.messages[0]!
      expect(mail.to).toBe(WILLA.email)
      expect(mail.subject).toBe('Your OIML SMART Identity password reset link')
      const emailed = linkFromEmailText(mail.text)
      expect(emailed).toContain(`${ISSUER}/op/setup?token=`)
      expect(await page.content()).not.toContain(emailed)

      // The emailed link drives the real password change (the /op/setup
      // ceremony), landing signed in.
      flog(page, 'leg4: opening the emailed reset link')
      await page.goto(emailed, { waitUntil: 'domcontentloaded', timeout: SETTLE })
      await page.waitForSelector('[data-testid="op-setup-account"]', { timeout: SETTLE, polling: 500 })
      expect(await page.$eval('[data-testid="op-setup-account"]', el => el.textContent ?? '')).toContain(WILLA.email)
      await page.type('[data-testid="op-setup-password"]', WILLA_RESET)
      await page.type('[data-testid="op-setup-confirm"]', WILLA_RESET)
      await page.evaluate(() => (document.querySelector('[data-testid="op-setup-submit"]') as HTMLElement).click())
      await page.waitForSelector('[data-testid="account-name"]', { timeout: APP_COLD, polling: 500 })
      flog(page, 'leg4: the reset completed, signed in')

      // The new password signs in; the old one refuses (the fetch-level
      // sign-in is the honest probe).
      const oldLogin = await fetch(`${stack.base}/api/op/login`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ email: WILLA.email, password: WILLA.password }),
      })
      expect(oldLogin.status).toBe(401)
      await passwordCookie(stack.base, WILLA.email, WILLA_RESET)
      WILLA.password = WILLA_RESET // the later legs sign in fresh
      flog(page, 'leg4: the password moved')

      // The oracle legs: an unknown address answers the SAME message and
      // sends NOTHING. (Sign OUT first — the completed reset signed the
      // browser in, and the login page bounces a signed-in visitor.)
      await page.deleteCookie({ name: 'oiml-session', url: stack.base })
      mailer.reset()
      await page.goto(`${stack.base}/`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
      await page.waitForSelector('[data-testid="login-forgot"]', { timeout: SETTLE, polling: 500 })
      await page.evaluate(() => (document.querySelector('[data-testid="login-forgot"]') as HTMLElement).click())
      await page.waitForSelector('[data-testid="login-reset-email"]', { timeout: SETTLE, polling: 500 })
      await page.type('[data-testid="login-reset-email"]', 'ghost@example.org')
      await page.evaluate(() => (document.querySelector('[data-testid="login-reset-submit"]') as HTMLElement).click())
      await page.waitForSelector('[data-testid="login-reset-done"]', { timeout: SETTLE, polling: 500 })
      expect(await page.$eval('[data-testid="login-reset-done"]', el => el.textContent ?? '')).toBe(shown)
      await delay(2_000) // a send would land promptly; prove the silence
      expect(mailer.messages).toHaveLength(0)
      flog(page, 'leg4: the unknown address is not an oracle')
    })
  })
})
