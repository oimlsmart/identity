// ═══════════════════════════════════════════════════════════════════
// id-15 — the MOBILE-VIEWPORT pass on the core flows (the responsive
// wave, TODO.identity-features/02): the OP's pages earned the desktop
// first; this leg drives the phone (390x844, the report's device class)
// through the journey and asserts the one rule the audit found broken —
// THE PAGE NEVER SCROLLS SIDEWAYS — plus the 44px touch floor on the
// primary acts:
//
//   leg 1  the setup page on the REAL bootstrap link at 390 (no
//          sideways scroll, the submit at the touch floor), the
//          enrollment landing on the account console, the sign-out, and
//          the sign-in page itself (no scroll; the submit's box ≥ 44px);
//   leg 2  the sign-in THROUGH THE FORM at 390, landing on the
//          launcher: no scroll, the section cards (the baseline audit's
//          479px offenders) fit the viewport, and the account entry
//          navigates;
//   leg 3  the account console's acts at 390: the inline rename (the
//          edit row wraps instead of overflowing), the verify-new-email
//          row (the input takes its own row), and the avatar CROP dialog
//          fitting the viewport with the page still never scrolling;
//   leg 4  the admin console's reads at 390: the overview, the registry
//          (the directory is the CARD list here — the table sleeps
//          above md), the per-user detail, and every sibling surface,
//          each proven sideways-clean.
//
// SELF-CONTAINED: own ports (API 10293 / astro 10294 — clear of id-01's
// 8693/8393, id-02's 8793/8593, id-08's 8993/8893, id-10's 9193/9093,
// id-03's 9393/9293, id-06's 9493/9393, id-09's 8795/8595, id-11's
// 9893/9894, id-13's 9993/9994, id-12's 10093/10094, id-14's
// 10193/10194), own SQLite file. THE BROWSER IS PER-LEG (the id-02
// lesson); cross-leg state (the enrolled password) rides the DATABASE.
// ═══════════════════════════════════════════════════════════════════

import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import puppeteer, { type Browser, type Page } from 'puppeteer'
import { spawn, type ChildProcess } from 'node:child_process'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { existsSync, mkdirSync, rmSync, cpSync, appendFileSync, writeFileSync } from 'node:fs'
import { closeBrowser, delay } from './helpers'
import { fixtureOpSigningKey } from './fixtures/op-signing-key'

const BROWSER_DIR = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const FIXTURES = join(BROWSER_DIR, 'e2e', 'fixtures')
const DB_DIR = join(BROWSER_DIR, '.cache', 'id-15')

const ID_API = 10293
const ID_WEB = 10294
const ISSUER = `http://localhost:${ID_WEB}`

/** The audited phone: 390x844 (the iPhone 14 class — the report's
 *  "mobile mode"; the 360 class rides the sweep's breakpoint set). */
const PHONE = { width: 390, height: 844 }

const ROOT = { email: 'root@oimlsmart.org', name: 'Root Operator', password: 'the root operator passphrase' }

interface Stack {
  api: ChildProcess
  astro: ChildProcess
  base: string
  apiBase: string
  logs: string[]
}

function spawnLogged(cmd: string, args: string[], env: NodeJS.ProcessEnv, logs: string[]): ChildProcess {
  // detached (the process group dies together); the env SCRUBS the
  // vitest markers (the 2026-08-14 stall lesson).
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

    // The tsx CLI directly (never npx — the wrapper orphans the server).
    api = spawnLogged(join(BROWSER_DIR, 'node_modules', '.bin', 'tsx'), ['server/serve.ts'], {
      PORT: String(ID_API),
      DATABASE_PATH: dbPath,
      ENTITY_BACKEND: 'server',
      INSTANCE_PROFILE: join(FIXTURES, 'instance.profile.identity.yaml'),
      OIDC_ISSUER: '',
      OIDC_CLIENT_ID: '',
      DEMO_ACCOUNTS_ENABLED: 'true',
      OP_ISSUER: ISSUER,
      OP_SIGNING_KEY: await fixtureOpSigningKey(),
      OP_ACCOUNT_SEED: JSON.stringify([{ email: ROOT.email, name: ROOT.name, role: 'admin' }]),
    }, logs)
    const apiBase = `http://localhost:${ID_API}`
    await waitForHttp(`${apiBase}/api/health`, 120_000, logs)
    const reset = await fetch(`${apiBase}/api/dev-reset`, { method: 'POST' })
    if (!reset.ok) throw new Error(`dev-reset answered ${reset.status}`)
    // The account seed is LAZY (the bootstrap middleware seeds on the
    // first /api/op/* call — the id-11 note): this probe runs it, which
    // mints + logs the setup link the beforeAll reads.
    const seedProbe = await fetch(`${apiBase}/api/op/login`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: 'nobody@example.org', password: 'a probe, not a password' }),
    })
    if (seedProbe.status !== 401) throw new Error(`the OP login probe answered ${seedProbe.status} (401 expected)`)

    // The spawned vite gets a PRIVATE cache seeded from the worktree's
    // warm one (a cold optimizer outlives the boot budget on a loaded
    // host).
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

    // The bootstrap setup link from the boot log (the operator's way in).
    let setupUrl = ''
    const deadline = Date.now() + 60_000
    while (Date.now() < deadline) {
      const m = /bootstrap: account root@oimlsmart\.org has no password[^\n]*\n\s*(\S+\/op\/setup\?token=\S+)/.exec(logs.join(''))
      if (m) { setupUrl = m[1]!; break }
      await delay(500)
    }
    if (!setupUrl) throw new Error('the bootstrap setup link never logged')
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
const APP_COLD = 840_000 // the first island navigation compiles the shell cold

const PROGRESS_LOG = join(DB_DIR, 'progress.log')
function flog(page: Page | null, msg: string): void {
  const url = page && !page.isClosed() ? page.url() : '(no page)'
  const line = `${new Date().toISOString()} ${msg} @ ${url}\n`
  try { appendFileSync(PROGRESS_LOG, line) } catch { /* the log never breaks the leg */ }
}

/** A fresh browser per leg, AT THE PHONE (the header note: a long-lived
 *  headless shell wedges silently under load). */
async function withPhone(fn: (page: Page) => Promise<void>): Promise<void> {
  const browser: Browser = await puppeteer.launch({
    headless: 'shell',
    protocolTimeout: 480_000,
    args: ['--no-sandbox', '--disable-setuid-sandbox'],
  })
  try {
    const page = await browser.newPage()
    await page.setViewport(PHONE)
    page.on('pageerror', e => flog(page, `[pageerror] ${String(e).slice(0, 300)}`))
    page.on('requestfailed', r => flog(page, `[requestfailed] ${r.url().slice(0, 140)} ${r.failure()?.errorText ?? ''}`))
    await fn(page)
  } finally {
    await closeBrowser(browser)
  }
}

/** THE RULE: the page never scrolls sideways. The +1 tolerance eats the
 *  odd sub-pixel. */
async function expectNoSidewaysScroll(page: Page, label: string): Promise<void> {
  const m = await page.evaluate(() => ({
    sw: (document.scrollingElement ?? document.documentElement).scrollWidth,
    cw: document.documentElement.clientWidth,
  }))
  expect(m.sw, `${label}: the page scrolls sideways (+${m.sw - m.cw}px at ${PHONE.width})`).toBeLessThanOrEqual(m.cw + 1)
}

/** The 44px touch floor on the named control (the audit's target rule). */
async function expectTouchFloor(page: Page, testid: string): Promise<void> {
  const box = await page.evaluate((tid) => {
    const el = document.querySelector(`[data-testid="${tid}"]`)
    if (!el) return null
    const r = el.getBoundingClientRect()
    return { height: r.height }
  }, testid)
  expect(box, `${testid} renders`).toBeTruthy()
  expect(box!.height, `${testid} stands at the 44px touch floor`).toBeGreaterThanOrEqual(44)
}

/** Click by testid (the evaluate click never misses the island's
 *  hydration state). */
async function clickTid(page: Page, testid: string): Promise<void> {
  await page.evaluate((tid) => (document.querySelector(`[data-testid="${tid}"]`) as HTMLElement).click(), testid)
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

/** The console, loaded signed in via the fetch-level cookie. */
async function openConsole(page: Page, base: string, cookie: string): Promise<void> {
  await page.setCookie({ name: 'oiml-session', value: cookie, url: base })
  await page.goto(`${base}/op/account`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
  await page.waitForSelector('[data-testid="account-name"]', { timeout: APP_COLD, polling: 500 })
}

describe('TODO.identity-features/02 — the mobile-viewport pass (390px)', () => {
  let stack: Stack
  let setupUrl: string

  beforeAll(async () => {
    stack = await bootIdentityStack()
    setupUrl = stack.logs.join('').match(/bootstrap: account root@oimlsmart\.org has no password[^\n]*\n\s*(\S+\/op\/setup\?token=\S+)/)?.[1] ?? ''
    expect(setupUrl, 'the bootstrap setup link logged').toContain('/op/setup?token=')
  }, 600_000)

  afterAll(async () => {
    await stopStack(stack)
  })

  it('leg 1: the setup page + the sign-in page at 390 — no sideways scroll, the primary acts at the touch floor', async () => {
    await withPhone(async (page) => {
      flog(page, 'leg 1: the setup page on the real bootstrap link')
      await page.goto(setupUrl, { waitUntil: 'domcontentloaded', timeout: SETTLE })
      await page.waitForSelector('[data-testid="op-setup-password"]', { timeout: SETTLE, polling: 500 })
      await expectNoSidewaysScroll(page, 'the setup page')
      await expectTouchFloor(page, 'op-setup-submit')

      await page.type('[data-testid="op-setup-password"]', ROOT.password)
      await page.type('[data-testid="op-setup-confirm"]', ROOT.password)
      await clickTid(page, 'op-setup-submit')
      await page.waitForSelector('[data-testid="account-name"]', { timeout: APP_COLD, polling: 500 })
      flog(page, 'enrolled; the account console stands')
      await expectNoSidewaysScroll(page, 'the account console after enrollment')

      // Sign out through the header chip, then the sign-in page itself.
      await page.waitForSelector('[data-testid="header-signout"]', { timeout: SETTLE, polling: 500 })
      await clickTid(page, 'header-signout')
      await page.waitForSelector('[data-testid="login-email"]', { timeout: SETTLE, polling: 500 })
      await expectNoSidewaysScroll(page, 'the sign-in page')
      await expectTouchFloor(page, 'login-submit')
    })
  })

  it('leg 2: the sign-in form at 390 lands on the launcher; the section cards fit the phone', async () => {
    await withPhone(async (page) => {
      flog(page, 'leg 2: the form sign-in at 390')
      await page.goto(`${stack.base}/`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
      await page.waitForSelector('[data-testid="login-email"]', { timeout: SETTLE, polling: 500 })
      await expectNoSidewaysScroll(page, 'the sign-in page')
      await page.type('[data-testid="login-email"]', ROOT.email)
      await page.type('[data-testid="login-password"]', ROOT.password)
      await clickTid(page, 'login-submit')
      await page.waitForSelector('[data-testid="home"]', { timeout: APP_COLD, polling: 500 })
      flog(page, 'the launcher stands')
      await expectNoSidewaysScroll(page, 'the launcher')

      // The baseline audit's offenders: the account + admin section cards
      // (blown to 479px by the implicit grid track) — both must now fit.
      const card = await page.$('[data-testid="home-account"]')
      expect(card, 'the account section card renders').toBeTruthy()
      const box = await card!.boundingBox()
      expect(box, 'the account card has a box').toBeTruthy()
      expect(box!.x).toBeGreaterThanOrEqual(0)
      expect(box!.x + box!.width, 'the account card fits the viewport').toBeLessThanOrEqual(PHONE.width + 1)

      // The account entry navigates to the console.
      await clickTid(page, 'home-account')
      await page.waitForSelector('[data-testid="account-name"]', { timeout: APP_COLD, polling: 500 })
      await expectNoSidewaysScroll(page, 'the account console from the launcher')
    })
  })

  it('leg 3: the account console\'s acts at 390 — the inline rename, the email row, the crop dialog', async () => {
    const cookie = await passwordCookie(stack.base, ROOT.email, ROOT.password)
    await withPhone(async (page) => {
      flog(page, 'leg 3: the console acts at 390')
      await openConsole(page, stack.base, cookie)
      await expectNoSidewaysScroll(page, 'the account console')

      // The inline rename: the edit row wraps (the input takes its own
      // row) instead of out-measuring the card's column.
      await clickTid(page, 'account-profile-edit')
      await page.waitForSelector('[data-testid="account-profile-name-input"]', { timeout: SETTLE, polling: 500 })
      await expectNoSidewaysScroll(page, 'the rename form open')
      await retype(page, 'account-profile-name-input', 'Root Mobile Operator')
      await clickTid(page, 'account-profile-save')
      await page.waitForFunction(
        () => document.querySelector('[data-testid="account-name"]')?.textContent?.includes('Root Mobile Operator'),
        { timeout: SETTLE, polling: 500 },
      )
      await expectNoSidewaysScroll(page, 'the rename saved')

      // The verify-new-email row: the input's own row, the act lands the
      // honestly-shown link (no mailer on this stack).
      await retype(page, 'account-email-input', 'root.mobile@example.org')
      await clickTid(page, 'account-email-submit')
      await page.waitForSelector('[data-testid="account-email-delivery"]', { timeout: SETTLE, polling: 500 })
      await expectNoSidewaysScroll(page, 'the email-change link shown')

      // The avatar crop dialog: the painted fixture, the dialog inside
      // the viewport, the page still never scrolling.
      const photoDataUrl = await page.evaluate(() => {
        const c = document.createElement('canvas')
        c.width = 640
        c.height = 320
        const ctx = c.getContext('2d')!
        ctx.fillStyle = '#c0392b'
        ctx.fillRect(0, 0, 320, 320)
        ctx.fillStyle = '#2980b9'
        ctx.fillRect(320, 0, 320, 320)
        return c.toDataURL('image/png')
      })
      const photoPath = join(DB_DIR, 'mobile-photo.png')
      writeFileSync(photoPath, Buffer.from(photoDataUrl.split(',')[1]!, 'base64'))
      const input = await page.$('[data-testid="account-avatar-input"]') as import('puppeteer').ElementHandle<HTMLInputElement> | null
      await input!.uploadFile(photoPath)
      await page.waitForSelector('[data-testid="account-avatar-crop"]', { timeout: SETTLE, polling: 500 })
      await page.waitForSelector('[data-testid="account-avatar-crop-preview"]', { timeout: SETTLE, polling: 500 })
      await expectNoSidewaysScroll(page, 'the crop dialog open')
      const geom = await page.evaluate(() => {
        const dialog = document.querySelector('[data-testid="account-avatar-crop"] > div')!.getBoundingClientRect()
        const canvas = document.querySelector('[data-testid="account-avatar-crop-canvas"]')!.getBoundingClientRect()
        return { dialog: { left: dialog.left, right: dialog.right }, canvas: { left: canvas.left, right: canvas.right } }
      })
      expect(geom.dialog.left, 'the dialog inside the viewport (left)').toBeGreaterThanOrEqual(0)
      expect(geom.dialog.right, 'the dialog inside the viewport (right)').toBeLessThanOrEqual(PHONE.width + 1)
      expect(geom.canvas.right, 'the crop window inside the dialog').toBeLessThanOrEqual(geom.dialog.right + 1)
      await clickTid(page, 'account-avatar-crop-cancel')
      await page.waitForFunction(() => !document.querySelector('[data-testid="account-avatar-crop"]'), { timeout: SETTLE })
    })
  })

  it('leg 4: the admin console\'s reads at 390 — every surface sideways-clean, the registry a card list', async () => {
    const cookie = await passwordCookie(stack.base, ROOT.email, ROOT.password)
    await withPhone(async (page) => {
      flog(page, 'leg 4: the admin reads at 390')
      await page.setCookie({ name: 'oiml-session', value: cookie, url: stack.base })

      const reads: Array<{ path: string; settle: string; label: string }> = [
        { path: '/op/admin/overview', settle: 'op-dash', label: 'the overview dashboard' },
        { path: '/op/admin/registry', settle: 'op-reg', label: 'the identity registry' },
        { path: '/op/admin/users', settle: 'op-admin-users', label: 'the organization administration' },
        { path: '/op/admin/clients', settle: 'op-clients', label: 'the relying parties' },
        { path: '/op/admin/activity', settle: 'op-act', label: 'the registry activity' },
        { path: '/op/admin/providers', settle: 'op-providers', label: 'the sign-in providers' },
        { path: '/op/admin/sessions', settle: 'op-sess', label: 'the live sessions' },
        { path: '/op/admin/security', settle: 'op-sec', label: 'the security and audit' },
      ]
      for (const read of reads) {
        await page.goto(`${stack.base}${read.path}`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
        await page.waitForSelector(`[data-testid="${read.settle}"]`, { timeout: APP_COLD, polling: 500 })
        await expectNoSidewaysScroll(page, read.label)
        flog(page, `sideways-clean: ${read.label}`)
      }

      // The registry directory is the CARD list on the phone (the table
      // sleeps above md); the card opens the per-account detail.
      const rootId = await page.evaluate(async () => {
        const res = await fetch('/api/op/registry/users', { credentials: 'include' })
        const rows = res.ok ? await res.json() as Array<{ id: string }> : []
        return rows[0]?.id ?? ''
      })
      expect(rootId, 'the registry carries the root row').toBeTruthy()
      await page.goto(`${stack.base}/op/admin/registry`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
      await page.waitForSelector('[data-testid="op-reg"]', { timeout: APP_COLD, polling: 500 })
      const visibility = await page.evaluate(() => {
        const cards = document.querySelector('[data-testid="op-reg-cards"]') as HTMLElement | null
        const table = document.querySelector('[data-testid="op-reg-list"]') as HTMLElement | null
        return { cards: !!cards && cards.offsetParent !== null, table: !!table && table.offsetParent !== null }
      })
      expect(visibility.cards, 'the card list shows on the phone').toBe(true)
      expect(visibility.table, 'the table sleeps below md').toBe(false)
      await page.waitForSelector(`[data-testid="op-reg-card-open-${rootId}"]`, { timeout: SETTLE, polling: 500 })
      await clickTid(page, `op-reg-card-open-${rootId}`)
      await page.waitForSelector('[data-testid="op-reg-user"]', { timeout: APP_COLD, polling: 500 })
      await expectNoSidewaysScroll(page, 'the registry user detail')
    })
  })
})
