// ═══════════════════════════════════════════════════════════════════
// id-26 — the visual-elevation wave over the wire (smart's
// TODO.identity-features/11, the four structural moves):
//
//   leg 1  the editorial split + the rotating feed: at desktop width the
//          sign-in is two panels — the left carries the welcome block
//          and the feed panel (the served /api/panels document — the
//          passkey promotion, proven from the API port too, with its
//          brief-cache header); at phone width the panel hides and the
//          card carries the lockup. The French switch re-renders the
//          PANEL content from the feed's own fr copy.
//   leg 2  the status pill + the incident banner, against a STUB status
//          upstream (STATUS_SUMMARY_URL): all-operational → the green
//          pill + no banner; degraded → the amber pill + the dignified
//          banner atop the sign-in; down → the red tone; the stub
//          refusing → "status unknown" and NO banner (never a fake
//          green). The stack declares STATUS_CACHE_TTL_MS=400 so the
//          phases walk in one boot.
//   leg 3  the typography floor, asserted on computed styles: the
//          heading 24px, labels 14px, inputs/buttons 16px, the
//          legitimacy line 14px (the owner's ask), the or-divider 12px
//          — nothing on the sign-in card below the 12px floor.
//
// SELF-CONTAINED: own ports (API 10609 / astro 10610 / stub 10611 —
// above id-25's 10607/10608), own SQLite file. THE BROWSER IS PER-LEG
// (the id-02 lesson).
// ═══════════════════════════════════════════════════════════════════

import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import puppeteer, { type Browser, type Page } from 'puppeteer'
import { spawn, type ChildProcess } from 'node:child_process'
import { createServer, type Server } from 'node:http'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { existsSync, mkdirSync, rmSync, cpSync, appendFileSync } from 'node:fs'
import { closeBrowser, delay } from './helpers'
import { fixtureOpSigningKey } from './fixtures/op-signing-key'

const BROWSER_DIR = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const FIXTURES = join(BROWSER_DIR, 'e2e', 'fixtures')
const DB_DIR = join(BROWSER_DIR, '.cache', 'id-26')

const ID_API = 10609
const ID_WEB = 10610
const STUB_PORT = 10611
const ISSUER = `http://localhost:${ID_WEB}`

interface Stack {
  api: ChildProcess
  astro: ChildProcess
  base: string
  apiBase: string
  logs: string[]
}

/** The stub status upstream's current answer. */
let stubDoc: unknown = {}
let stubStatus = 200
let stub: Server | undefined

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

/** The stub's summary document: fresh prober, the given services. */
function statusDoc(services: { id: string; state: string; reason?: string }[]): unknown {
  return {
    generatedAt: new Date().toISOString(),
    prober: { lastRunAt: Date.now() },
    services: services.map((s) => ({
      id: s.id,
      name: `The ${s.id} service`,
      url: `https://status-stub.invalid/${s.id}`,
      state: s.state,
      reason: s.reason ?? null,
      lastGoodAt: Date.now() - 60_000,
      uptime30d: '100',
      uptime90d: '100',
    })),
  }
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
    for (const probe of [`http://localhost:${ID_API}/api/health`, `http://localhost:${ID_WEB}/`, `http://localhost:${STUB_PORT}/`]) {
      try {
        const res = await fetch(probe)
        if (res.status < 500) throw new Error(`port for ${probe} is already serving — a leftover stack? (kill it: lsof -ti tcp:${new URL(probe).port} | xargs kill)`)
      } catch (e) {
        if (e instanceof Error && e.message.includes('already serving')) throw e
      }
    }

    // The stub status upstream (status.oimlsmart.org's stand-in).
    stubDoc = statusDoc([{ id: 'id-op', state: 'operational' }, { id: 'platform', state: 'operational' }])
    stubStatus = 200
    stub = createServer((_req, res) => {
      res.writeHead(stubStatus, { 'content-type': 'application/json' })
      res.end(JSON.stringify(stubDoc))
    })
    await new Promise<void>((r) => stub!.listen(STUB_PORT, '127.0.0.1', r))

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
      // The status projection's seams: the stub upstream + its page URL
      // + the sub-second cache window so the phases walk in one boot.
      STATUS_SUMMARY_URL: `http://127.0.0.1:${STUB_PORT}/api/summary.json`,
      STATUS_PAGE_URL: `http://127.0.0.1:${STUB_PORT}/`,
      STATUS_CACHE_TTL_MS: '400',
    }, logs)
    const apiBase = `http://localhost:${ID_API}`
    await waitForHttp(`${apiBase}/api/health`, 120_000, logs)
    const reset = await fetch(`${apiBase}/api/dev-reset`, { method: 'POST' })
    if (!reset.ok) throw new Error(`dev-reset answered ${reset.status}`)

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
    return { api, astro, base, apiBase, logs }
  } catch (e) {
    reap()
    throw e
  }
}

async function stopStack(stack: Stack | undefined): Promise<void> {
  if (stub) await new Promise<void>((r) => stub!.close(() => r()))
  stub = undefined
  if (!stack) return
  for (const proc of [stack.astro, stack.api]) killTree(proc)
  await delay(1_500)
  for (const proc of [stack.astro, stack.api]) killTreeHard(proc)
}

const SETTLE = 240_000 // spawned astro compiles page chunks cold on first hit

const PROGRESS_LOG = join(DB_DIR, 'progress.log')
function flog(page: Page | null, msg: string): void {
  const url = page && !page.isClosed() ? page.url() : '(no page)'
  const line = `${new Date().toISOString()} ${msg} @ ${url}\n`
  try { appendFileSync(PROGRESS_LOG, line) } catch { /* the log never breaks the leg */ }
}

/** A fresh browser per leg (the id-02 lesson: a long-lived headless
 *  shell wedges silently under load). */
async function withBrowser(fn: (page: Page) => Promise<void>): Promise<void> {
  const browser: Browser = await puppeteer.launch({
    headless: 'shell',
    protocolTimeout: 480_000,
    args: ['--no-sandbox', '--disable-setuid-sandbox'],
  })
  try {
    const page = await browser.newPage()
    page.on('pageerror', e => flog(page, `[pageerror] ${String(e).slice(0, 300)}`))
    page.on('requestfailed', r => flog(page, `[requestfailed] ${r.url().slice(0, 140)} ${r.failure()?.errorText ?? ''}`))
    await fn(page)
  } finally {
    await closeBrowser(browser)
  }
}

async function openSignin(page: Page, base: string, width = 1440): Promise<void> {
  await page.setViewport({ width, height: 900 })
  await page.goto(`${base}/`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
  await page.waitForSelector('[data-testid="login-email"]', { timeout: SETTLE, polling: 500 })
}

/** The pill's posture, or null while the static link stands. */
async function pill(page: Page): Promise<{ text: string; state: string | null; href: string | null }> {
  return page.evaluate(() => {
    const el = document.querySelector('[data-testid="shell-status-pill"]')
    if (!el) return { text: '', state: null, href: null }
    return { text: el.textContent?.trim() ?? '', state: el.getAttribute('data-state'), href: el.getAttribute('href') }
  })
}

describe('TODO.identity-features/11 — the visual-elevation wave', () => {
  let stack: Stack

  beforeAll(async () => {
    stack = await bootIdentityStack()
  }, 600_000)

  afterAll(async () => {
    await stopStack(stack)
  })

  it('leg 1: the editorial split + the rotating feed, desktop vs phone, EN/FR', async () => {
    // The feed over the wire: the API serves the committed document,
    // cached briefly.
    const feedRes = await fetch(`${stack.apiBase}/api/panels`)
    expect(feedRes.status).toBe(200)
    expect(feedRes.headers.get('cache-control')).toBe('public, max-age=300')
    const feed = await feedRes.json() as { panels: { id: string; enabled: boolean }[] }
    expect(feed.panels[0]).toMatchObject({ id: 'passkeys', enabled: true })

    await withBrowser(async (page) => {
      flog(page, 'leg 1: desktop — the split, the welcome, the feed')
      await openSignin(page, stack.base, 1440)

      // The panel renders the welcome block + the SERVED feed (the
      // passkey promotion — the fetch landed, not just the default).
      await page.waitForSelector('[data-testid="login-panel"]', { timeout: SETTLE, polling: 500 })
      await page.waitForSelector('[data-testid="login-panel-feed"]', { timeout: SETTLE, polling: 500 })
      const desktop = await page.evaluate(() => ({
        welcome: document.querySelector('[data-testid="login-panel-welcome"]')?.textContent ?? '',
        badge: document.querySelector('[data-testid="login-panel-badge"]')?.textContent ?? '',
        heading: document.querySelector('[data-testid="login-panel-heading"]')?.textContent ?? '',
        panelVisible: (document.querySelector('[data-testid="login-panel"]') as HTMLElement).offsetParent !== null,
        panelWidth: (document.querySelector('[data-testid="login-panel"]') as HTMLElement).getBoundingClientRect().width,
      }))
      expect(desktop.welcome).toContain('One account for all OIML services')
      expect(desktop.badge).toBe('PASSKEYS')
      expect(desktop.heading).toContain('passkey')
      expect(desktop.panelVisible).toBe(true)
      expect(desktop.panelWidth).toBeGreaterThan(500)

      // The French switch re-renders the PANEL from the feed's own fr copy.
      await page.waitForSelector('[data-testid="locale-fr"]', { timeout: SETTLE, polling: 500 })
      await page.evaluate(() => (document.querySelector('[data-testid="locale-fr"]') as HTMLElement).click())
      await page.waitForFunction(
        () => document.querySelector('[data-testid="login-panel-badge"]')?.textContent === 'CLÉS D\'ACCÈS',
        { timeout: SETTLE, polling: 500 },
      )
      const french = await page.evaluate(() => ({
        welcome: document.querySelector('[data-testid="login-panel-welcome"]')?.textContent ?? '',
        heading: document.querySelector('[data-testid="login-panel-heading"]')?.textContent ?? '',
      }))
      expect(french.welcome).toContain('services de l’OIML')
      expect(french.heading).toContain('clé d\'accès')
      await page.evaluate(() => (document.querySelector('[data-testid="locale-en"]') as HTMLElement).click())
    })

    await withBrowser(async (page) => {
      flog(page, 'leg 1: phone — the single proven column')
      await openSignin(page, stack.base, 390)
      const phone = await page.evaluate(() => {
        const logo = document.querySelector('img.dark\\:hidden') as HTMLImageElement | null
        return {
          panelVisible: (document.querySelector('[data-testid="login-panel"]') as HTMLElement).offsetParent !== null,
          // The card carries the lockup itself below lg (the panel hides).
          cardLogoVisible: !!logo && logo.offsetParent !== null,
          bodyWidth: document.documentElement.clientWidth,
          scrollWidth: document.documentElement.scrollWidth,
        }
      })
      expect(phone.panelVisible).toBe(false)
      expect(phone.cardLogoVisible).toBe(true)
      // Mobile-honest: no horizontal overflow.
      expect(phone.scrollWidth).toBeLessThanOrEqual(phone.bodyWidth)
    })
  })

  it('leg 2: the status pill + the incident banner, honest in every posture', async () => {
    await withBrowser(async (page) => {
      flog(page, 'leg 2a: all operational — the green pill, no banner')
      stubDoc = statusDoc([{ id: 'id-op', state: 'operational' }, { id: 'platform', state: 'operational' }])
      stubStatus = 200
      await openSignin(page, stack.base)
      await page.waitForSelector('[data-testid="shell-status-pill"]', { timeout: SETTLE, polling: 500 })
      let p = await pill(page)
      expect(p.state).toBe('operational')
      expect(p.text).toContain('All services operational')
      expect(p.href).toBe(`http://127.0.0.1:${STUB_PORT}/`)
      expect(await page.$('[data-testid="status-banner"]')).toBeNull()

      flog(page, 'leg 2b: degraded — the amber pill + the banner surfaces')
      stubDoc = statusDoc([
        { id: 'id-op', state: 'operational' },
        { id: 'demo', state: 'degraded', reason: 'a recent probe failed inside the watch window' },
      ])
      await delay(700) // past the stack's 400 ms cache window
      await page.reload({ waitUntil: 'domcontentloaded', timeout: SETTLE })
      await page.waitForSelector('[data-testid="status-banner"]', { timeout: SETTLE, polling: 500 })
      const degraded = await page.evaluate(() => ({
        banner: document.querySelector('[data-testid="status-banner"]')?.textContent ?? '',
        state: document.querySelector('[data-testid="status-banner"]')?.getAttribute('data-state'),
        link: (document.querySelector('[data-testid="status-banner-link"]') as HTMLAnchorElement | null)?.href ?? null,
      }))
      expect(degraded.state).toBe('degraded')
      expect(degraded.banner).toContain('Some estate services are reporting problems')
      expect(degraded.link).toBe(`http://127.0.0.1:${STUB_PORT}/`)
      p = await pill(page)
      expect(p.state).toBe('degraded')
      expect(p.text).toContain('degraded')

      flog(page, 'leg 2c: down — the banner names the disruption')
      stubDoc = statusDoc([{ id: 'platform', state: 'down', reason: 'the last probes failed' }])
      await delay(700)
      await page.reload({ waitUntil: 'domcontentloaded', timeout: SETTLE })
      await page.waitForSelector('[data-testid="status-banner"][data-state="down"]', { timeout: SETTLE, polling: 500 })
      const down = await page.evaluate(() => document.querySelector('[data-testid="status-banner"]')?.textContent ?? '')
      expect(down).toContain('are down')
      p = await pill(page)
      expect(p.state).toBe('down')

      flog(page, 'leg 2d: the stub refuses — status unknown, NO banner, never a fake green')
      stubStatus = 503
      await delay(700)
      await page.reload({ waitUntil: 'domcontentloaded', timeout: SETTLE })
      await page.waitForSelector('[data-testid="shell-status-pill"][data-state="unknown"]', { timeout: SETTLE, polling: 500 })
      p = await pill(page)
      expect(p.text).toContain('Status unknown')
      expect(await page.$('[data-testid="status-banner"]')).toBeNull()
      stubStatus = 200 // the afterAll posture is honest again
    })
  })

  it('leg 3: the typography floor holds on computed styles', async () => {
    await withBrowser(async (page) => {
      flog(page, 'leg 3: the measured type scale')
      await openSignin(page, stack.base)
      const sizes = await page.evaluate(() => {
        const px = (el: Element | null) => (el ? parseFloat(getComputedStyle(el).fontSize) : null)
        const label = document.querySelector('form label')
        let smallest = Infinity
        document.querySelectorAll('p, a, button, span, label, input, h1, h2, h3').forEach((el) => {
          const r = el.getBoundingClientRect()
          if (r.width > 0 && r.height > 0 && (el.textContent ?? '').trim()) {
            const s = parseFloat(getComputedStyle(el).fontSize)
            if (s < smallest) smallest = s
          }
        })
        return {
          h1: px(document.querySelector('h1')),
          label: px(label),
          input: px(document.querySelector('[data-testid="login-email"]')),
          submit: px(document.querySelector('[data-testid="login-submit"]')),
          legitimacy: px(document.querySelector('[data-testid="login-legitimacy"]')),
          join: px(document.querySelector('[data-testid="login-join"]')),
          footer: px(document.querySelector('[data-testid="shell-footer"]')),
          smallest,
        }
      })
      expect(sizes.h1).toBe(24)
      expect(sizes.label).toBe(14)
      expect(sizes.input).toBe(16)
      expect(sizes.submit).toBe(16)
      expect(sizes.legitimacy).toBe(14)
      expect(sizes.join).toBe(14)
      expect(sizes.footer).toBe(12)
      // The floor: nothing readable below 12px anywhere on the page.
      expect(sizes.smallest).toBeGreaterThanOrEqual(12)
    })
  })
})
