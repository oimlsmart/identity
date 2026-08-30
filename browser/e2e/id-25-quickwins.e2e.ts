// ═══════════════════════════════════════════════════════════════════
// id-25 — the ISO-benchmark quick-wins wave over the wire (smart's
// TODO.identity-features/11, items 3 + 2 + 6 + 5 + the item-9 fix):
//
//   leg 1  the anonymous surfaces: the environment ribbon names the
//          posture (this stack declares ENVIRONMENT_LABEL=Preview), the
//          footer carries the legal links (Privacy / Terms, the www
//          site's pages) and the support affordance (a plain mailto
//          link — never a third-party widget), the sign-in page states
//          the legitimacy line with the claim linked to the OIML's own
//          page, and the in-place authorize refusal (the item-9 fix) is
//          plain, zoom-friendly, and offers the way back;
//   leg 2  the locale switch, anonymous: the footer's LocaleSwitch
//          flips the sign-in page to French (the heading, the footer
//          line, <html lang>), the choice survives a reload, and
//          English restores;
//   leg 3  the per-account scope: signed in, the choice persists under
//          the ACCOUNT's key (oiml-smart-locale:<email>); signing out
//          returns the anonymous choice; signing back in restores the
//          account's own.
//
// SELF-CONTAINED: own ports (API 10607 / astro 10608 — above id-24's
// 10605/10606, the whole 3190..10606 range below), own SQLite file.
// THE BROWSER IS PER-LEG (the id-02 lesson).
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
const DB_DIR = join(BROWSER_DIR, '.cache', 'id-25')

const ID_API = 10607
const ID_WEB = 10608
const ISSUER = `http://localhost:${ID_WEB}`
const SUPPORT_URL = 'mailto:info@oimlsmart.org'

/** The demo cast member the per-account leg signs in as. */
const IA = { email: 'ia@oiml.org', password: 'demo2026' }

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
      // The quick-wins posture: the ribbon's label (item 5) + the
      // support affordance's target (item 6).
      ENVIRONMENT_LABEL: 'Preview',
      SUPPORT_URL,
    }, logs)
    const apiBase = `http://localhost:${ID_API}`
    await waitForHttp(`${apiBase}/api/health`, 120_000, logs)
    const reset = await fetch(`${apiBase}/api/dev-reset`, { method: 'POST' })
    if (!reset.ok) throw new Error(`dev-reset answered ${reset.status}`)
    // The demo cast's seed is LAZY (the bootstrap middleware seeds on the
    // first /api/op/* call): this probe runs it.
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

/** Click by testid (the evaluate click never misses the island's
 *  hydration state). */
async function clickTid(page: Page, testid: string): Promise<void> {
  await page.evaluate((tid) => (document.querySelector(`[data-testid="${tid}"]`) as HTMLElement).click(), testid)
}

/** The current <html lang>. */
async function htmlLang(page: Page): Promise<string> {
  return page.evaluate(() => document.documentElement.lang)
}

/** The demo cast's sign-in over fetch: the session cookie value. The
 *  cast answers at the DEMO endpoint (POST /api/auth/demo — the OP
 *  password endpoint is the enrolled accounts', login.vue's fallback
 *  order); the session it mints is the same shape. */
async function passwordCookie(base: string, email: string, password: string): Promise<string> {
  const res = await fetch(`${base}/api/auth/demo`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password }),
  })
  expect(res.ok, `demo sign-in ${email}`).toBe(true)
  return res.headers.get('set-cookie')!.split(';')[0]!.split('=')[1]!
}

/** The launcher, loaded signed in via the fetch-level cookie. */
async function openHome(page: Page, base: string, cookie: string): Promise<void> {
  await page.setCookie({ name: 'oiml-session', value: cookie, url: base })
  await page.goto(`${base}/op/home`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
  await page.waitForSelector('[data-testid="home"]', { timeout: APP_COLD, polling: 500 })
}

describe('TODO.identity-features/11 — the ISO-benchmark quick wins', () => {
  let stack: Stack

  beforeAll(async () => {
    stack = await bootIdentityStack()
  }, 600_000)

  afterAll(async () => {
    await stopStack(stack)
  })

  it('leg 1: the ribbon, the legal footer, the support affordance, the legitimacy line, the refusal page', async () => {
    await withBrowser(async (page) => {
      flog(page, 'leg 1: the sign-in page’s quick-wins surfaces')
      await page.goto(`${stack.base}/`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
      await page.waitForSelector('[data-testid="login-email"]', { timeout: SETTLE, polling: 500 })

      // Item 5: the ribbon names the posture (this stack is a Preview).
      await page.waitForSelector('[data-testid="env-ribbon"]', { timeout: SETTLE, polling: 500 })
      const ribbon = await page.evaluate(() => document.querySelector('[data-testid="env-ribbon"]')?.textContent ?? '')
      expect(ribbon).toContain('Preview')
      expect(ribbon).toContain('this is not the production service')

      // Item 2: the legal footer (the www site's own pages) + the status
      // link + the locale switch, all in the one-line footer. The
      // support link renders once the branding probe lands — wait for it.
      await page.waitForSelector('[data-testid="shell-support"]', { timeout: SETTLE, polling: 500 })
      await page.waitForSelector('[data-testid="login-support"]', { timeout: SETTLE, polling: 500 })
      const footerLinks = await page.evaluate(() => {
        const read = (tid: string) => (document.querySelector(`[data-testid="${tid}"]`) as HTMLAnchorElement | null)?.href ?? null
        return {
          privacy: read('shell-privacy'),
          terms: read('shell-terms'),
          status: read('shell-status'),
          support: read('shell-support'),
        }
      })
      expect(footerLinks.privacy).toBe('https://www.oimlsmart.org/privacy/')
      expect(footerLinks.terms).toBe('https://www.oimlsmart.org/terms/')
      expect(footerLinks.status).toContain('/api/health')

      // Item 6: the support affordance — a plain link (this stack's
      // SUPPORT_URL), zero third-party JavaScript.
      expect(footerLinks.support).toBe(SUPPORT_URL)
      const loginSupport = await page.evaluate(() =>
        (document.querySelector('[data-testid="login-support"]') as HTMLAnchorElement | null)?.href ?? null)
      expect(loginSupport).toBe(SUPPORT_URL)

      // Item 2: the legitimacy line, stated once, the claim linked to the
      // OIML's own page.
      const legitimacy = await page.evaluate(() => {
        const el = document.querySelector('[data-testid="login-legitimacy"]')
        return { text: el?.textContent ?? '', href: (el?.querySelector('a') as HTMLAnchorElement | null)?.href ?? null }
      })
      expect(legitimacy.text).toContain('Operated for the OIML-CS ecosystem of the OIML')
      expect(legitimacy.text).toContain('uniting member states in legal metrology')
      expect(legitimacy.href).toBe('https://www.oiml.org/en/about/what-is-the-oiml')
    })

    // Item 9's fix: the in-place authorize refusal (fetch-level — the
    // API serves the OP surface directly).
    const refusal = await fetch(`${stack.apiBase}/op/authorize?${new URLSearchParams({
      response_type: 'code',
      client_id: 'id25-unknown-client',
      redirect_uri: 'https://invalid.example/steal',
      scope: 'openid',
      code_challenge: 'whatever',
      code_challenge_method: 'S256',
    })}`, { redirect: 'manual' })
    expect(refusal.status).toBe(400)
    const refusalHtml = await refusal.text()
    expect(refusalHtml).toContain('op-authorize-error') // the contract gate's marker
    expect(refusalHtml).toContain('op-authorize-error-home') // the way back
    expect(refusalHtml).toContain('width=device-width, initial-scale=1')
    expect(refusalHtml).not.toContain('user-scalable=no') // ISO's regression is never ours
    expect(refusalHtml).toContain('color-scheme')
  })

  it('leg 2: the locale switch flips the sign-in page, persists across a reload, and restores', async () => {
    await withBrowser(async (page) => {
      flog(page, 'leg 2: the anonymous locale switch')
      await page.goto(`${stack.base}/`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
      await page.waitForSelector('[data-testid="login-email"]', { timeout: SETTLE, polling: 500 })
      await page.waitForSelector('[data-testid="locale-fr"]', { timeout: SETTLE, polling: 500 })
      expect(await htmlLang(page)).toBe('en')

      await clickTid(page, 'locale-fr')
      await page.waitForFunction(() => document.documentElement.lang === 'fr', { timeout: SETTLE, polling: 500 })
      // The front door answers in French: the heading, the submit, the
      // footer's own line.
      await page.waitForFunction(
        () => document.querySelector('h1')?.textContent?.startsWith('Connexion à'),
        { timeout: SETTLE, polling: 500 },
      )
      const french = await page.evaluate(() => ({
        submit: document.querySelector('[data-testid="login-submit"]')?.textContent ?? '',
        footer: document.querySelector('[data-testid="shell-footer"]')?.textContent ?? '',
        ribbon: document.querySelector('[data-testid="env-ribbon"]')?.textContent ?? '',
        legitimacy: document.querySelector('[data-testid="login-legitimacy"]')?.textContent ?? '',
        pressed: document.querySelector('[data-testid="locale-fr"]')?.getAttribute('aria-pressed'),
      }))
      expect(french.submit).toContain('Se connecter')
      expect(french.footer).toContain('authentification unique')
      expect(french.ribbon).toContain('Preview') // the label stays the deployment's own word
      expect(french.ribbon).toContain('pas le service de production')
      expect(french.legitimacy).toContain('métrologie légale')
      expect(french.pressed).toBe('true')

      // The choice survives a reload (the anonymous localStorage key).
      await page.reload({ waitUntil: 'domcontentloaded', timeout: SETTLE })
      await page.waitForSelector('[data-testid="login-email"]', { timeout: SETTLE, polling: 500 })
      await page.waitForFunction(
      // The pre-paint inline script applies the anonymous choice before
      // the island hydrates.
        () => document.documentElement.lang === 'fr',
        { timeout: SETTLE, polling: 500 },
      )
      await page.waitForFunction(
        () => document.querySelector('h1')?.textContent?.startsWith('Connexion à'),
        { timeout: SETTLE, polling: 500 },
      )

      await clickTid(page, 'locale-en')
      await page.waitForFunction(() => document.documentElement.lang === 'en', { timeout: SETTLE, polling: 500 })
      await page.waitForFunction(
        () => document.querySelector('h1')?.textContent?.startsWith('Sign in to'),
        { timeout: SETTLE, polling: 500 },
      )
    })
  })

  it('leg 3: the signed-in choice is the ACCOUNT’s — scoped, restored across sign-out and back', async () => {
    const cookie = await passwordCookie(stack.base, IA.email, IA.password)
    await withBrowser(async (page) => {
      flog(page, 'leg 3: the per-account locale scope')
      await openHome(page, stack.base, cookie)

      // The account holds no preference yet: English stands. Choose FR.
      await page.waitForSelector('[data-testid="locale-fr"]', { timeout: SETTLE, polling: 500 })
      await clickTid(page, 'locale-fr')
      await page.waitForFunction(() => document.documentElement.lang === 'fr', { timeout: SETTLE, polling: 500 })
      const scoped = await page.evaluate((email) => ({
        account: localStorage.getItem(`oiml-smart-locale:${email}`),
        anonymous: localStorage.getItem('oiml-smart-locale'),
      }), IA.email)
      expect(scoped.account).toBe('fr')
      // The layer persists the active value at load (the immediate
      // watcher), so the anonymous key EXISTS — the invariant is that
      // the account's choice never contaminates it.
      expect(scoped.anonymous).toBe('en')

      // Sign out through the header chip: the anonymous posture reads
      // the anonymous key (never written → the default, English).
      await page.waitForSelector('[data-testid="header-signout"]', { timeout: SETTLE, polling: 500 })
      await clickTid(page, 'header-signout')
      await page.waitForSelector('[data-testid="login-email"]', { timeout: SETTLE, polling: 500 })
      await page.waitForFunction(
        () => document.querySelector('h1')?.textContent?.startsWith('Sign in to'),
        { timeout: SETTLE, polling: 500 },
      )
      expect(await htmlLang(page)).toBe('en')

      // Sign back in: the account's own choice returns.
      const cookie2 = await passwordCookie(stack.base, IA.email, IA.password)
      await openHome(page, stack.base, cookie2)
      await page.waitForFunction(() => document.documentElement.lang === 'fr', { timeout: SETTLE, polling: 500 })
      flog(page, 'the account’s French returned')
    })
  })
})
