// ═══════════════════════════════════════════════════════════════════
// The identity-native frontend's surface leg (TODO.identity-extract/02a's
// acceptance bar): the identity host is not a platform app with extra
// routes. Against the spawned identity stack (the id-01 posture):
//
//   leg 1  / IS the sign-in page: the OP password form + the linked-
//          method surface render at the root (not the platform shell,
//          not a marketing page);
//   leg 2  the consoles render NATIVELY: /op/account is the account
//          console behind sign-in (no redirect into the platform app),
//          and /op/admin lands on the admin area;
//   leg 3  the pre-02a paths redirect WITHIN the host (/app/login → /,
//          /app/account → /op/account), and a platform-shaped path
//          answers the honest 404 with the platform pointer.
//
// The launcher/account-menu landing follows the cutover (02a's post-
// login landing is post-cutover mechanics) — this leg pins the wave-02
// surface only.
// ═══════════════════════════════════════════════════════════════════

import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import puppeteer, { type Browser } from 'puppeteer'
import { spawn, type ChildProcess } from 'node:child_process'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { existsSync, mkdirSync, rmSync, cpSync } from 'node:fs'
import { closeBrowser, delay } from './helpers'
import { fixtureOpSigningKey } from './fixtures/op-signing-key'

const BROWSER_DIR = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const FIXTURES = join(BROWSER_DIR, 'e2e', 'fixtures')
const DB_DIR = join(BROWSER_DIR, '.cache', 'id-surface')

// Port-isolated: clear of the shared dev stack (5190/3190), id-01
// (8693/8393/8694), id-02 (8793/8593/8794), id-09 (8795/8595), id-08
// (8993/8893/8994), id-10 (9193/9093), id-03 (9393/9293/9294), id-07
// (9293/9294), id-06 (9493/9393), id-04-op-side (9492/9493/9494),
// id-05 (9592/9593/9596), op-key-rotate (9693/9695).
const ID_API = 9793
const ID_WEB = 9693

interface Stack {
  api: ChildProcess
  astro: ChildProcess
  base: string
  apiBase: string
  logs: string[]
}

function spawnLogged(cmd: string, args: string[], env: NodeJS.ProcessEnv, logs: string[]): ChildProcess {
  // detached (the process group dies together — the tsx CLI wrapper
  // lesson); the env SCRUBS the vitest markers (the 2026-08-14 stall).
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

/** Boot the identity-profile stack (the id-01 posture): the API on its
 *  own SQLite file, the profile seed through the dev-reset seam, astro
 *  dev against it. */
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
    // The OIDC-/GITHUB-prefixed env is scrubbed (the id-08 discipline).
    api = spawnLogged(join(BROWSER_DIR, 'node_modules', '.bin', 'tsx'), ['server/serve.ts'], {
      PORT: String(ID_API),
      DATABASE_PATH: dbPath,
      ENTITY_BACKEND: 'server',
      INSTANCE_PROFILE: join(FIXTURES, 'instance.profile.identity.yaml'),
      OIDC_ISSUER: '',
      OIDC_CLIENT_ID: '',
      DEMO_ACCOUNTS_ENABLED: 'true',
      OP_ISSUER: `http://localhost:${ID_WEB}`,
      // identity#7: a declared-issuer stack declares its signing key too
      // (the generated dev key never registers off the dev posture).
      OP_SIGNING_KEY: await fixtureOpSigningKey(),
    }, logs)
    const apiBase = `http://localhost:${ID_API}`
    await waitForHttp(`${apiBase}/api/health`, 120_000, logs)

    const reset = await fetch(`${apiBase}/api/dev-reset`, { method: 'POST' })
    if (!reset.ok) throw new Error(`dev-reset on ${apiBase} answered ${reset.status}\n${logs.join('').slice(-2000)}`)

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
    // finishes — the fed-01 stall class).
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

describe('TODO.identity-extract/02a — the identity-native frontend surface', () => {
  let stack: Stack
  let browser: Browser

  beforeAll(async () => {
    stack = await bootIdentityStack()
    browser = await puppeteer.launch({ headless: 'shell', protocolTimeout: 480_000, args: ['--no-sandbox', '--disable-setuid-sandbox'] })
  }, 900_000)

  afterAll(async () => {
    await closeBrowser(browser)
    await stopStack(stack)
  })

  it('leg 1 — the root IS the sign-in page (the OP form, the honest footer, no platform chrome)', { timeout: 900_000 }, async () => {
    const page = await browser.newPage()
    await page.goto(`${stack.base}/`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    // The sign-in form renders at the root.
    await page.waitForSelector('[data-testid="login-email"]', { timeout: SETTLE, polling: 500 })
    await page.waitForSelector('[data-testid="login-password"]', { timeout: SETTLE, polling: 500 })
    await page.waitForSelector('[data-testid="login-submit"]', { timeout: SETTLE, polling: 500 })
    // The one-line footer + the status link.
    const footer = await page.evaluate(() => document.querySelector('footer')?.textContent ?? '')
    expect(footer).toContain('the single sign-on service for the oimlsmart.org estate')
    expect(await page.$('[data-testid="shell-status"]')).not.toBeNull()
    // No platform chrome: no federation nav, no manifest link.
    const platformChrome = await page.evaluate(() => ({
      siteNav: !!document.querySelector('.site-nav, #nav-menu'),
      manifest: !!document.querySelector('link[rel="manifest"]'),
    }))
    expect(platformChrome).toEqual({ siteNav: false, manifest: false })
    await page.close()
  })

  it('leg 2 — the consoles render natively behind sign-in', { timeout: 900_000 }, async () => {
    const page = await browser.newPage()
    // The account console behind sign-in: /op/account IS the page (no
    // redirect anywhere), rendering the console's own content.
    const cookie = await (async () => {
      const res = await fetch(`${stack.apiBase}/api/auth/demo`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ email: 'admin@oiml.org', password: 'demo2026' }),
      })
      if (!res.ok) throw new Error(`the demo sign-in → ${res.status}`)
      return res.headers.get('set-cookie')!.split(';')[0]!.split('=')[1]!
    })()
    await page.setCookie({ name: 'oiml-session', value: cookie, domain: 'localhost', path: '/' })
    await page.goto(`${stack.base}/op/account`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    expect(new URL(page.url()).pathname).toBe('/op/account')
    await page.waitForSelector('[data-testid="account-name"]', { timeout: SETTLE, polling: 500 })
    // The admin area: /op/admin lands on the registry console, native.
    await page.goto(`${stack.base}/op/admin`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await page.waitForFunction(
      () => window.location.pathname === '/op/admin/registry',
      { timeout: SETTLE, polling: 500 },
    )
    await page.waitForSelector('[data-testid="op-admin-nav"]', { timeout: SETTLE, polling: 500 })
    await page.close()
  })

  it('leg 3 — the pre-02a paths redirect within the host; a platform-shaped path 404s with the pointer', { timeout: 900_000 }, async () => {
    // Its OWN browser: leg 2's is signed in, and the sign-in page
    // honestly bounces a signed-in visitor to the console (no form ever
    // renders there — the redirect assertions below need the signed-out
    // posture).
    const legBrowser: Browser = await puppeteer.launch({ headless: 'shell', protocolTimeout: 480_000, args: ['--no-sandbox', '--disable-setuid-sandbox'] })
    const page = await legBrowser.newPage()
    try {
      // The pre-02a sign-in path redirects to the root.
      await page.goto(`${stack.base}/app/login`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
      await page.waitForSelector('[data-testid="login-email"]', { timeout: SETTLE, polling: 500 })
      expect(new URL(page.url()).pathname).toBe('/')
    // The pre-02a console path redirects to the native console (signed
    // out here: the console itself bounces to the sign-in — the REDIRECT
    // is what this leg pins, so drive it with the API's truth instead).
    const redirect = await fetch(`${stack.base}/app/account`, { redirect: 'manual' })
    // The prerendered redirect answers a 200 meta-refresh page or a 302 —
    // either way it points within the host at /op/account.
    if (redirect.status === 302) {
      expect(redirect.headers.get('location')).toBe('/op/account')
    } else {
      const html = await redirect.text()
      expect(html).toContain('/op/account')
    }
    // A platform-shaped path 404s honestly with the platform pointer.
    const notFound = await fetch(`${stack.base}/app/portal`)
    expect(notFound.status).toBe(404)
    await page.goto(`${stack.base}/app/portal`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await page.waitForFunction(
      () => document.body.innerText.includes('platform.oimlsmart.org'),
      { timeout: SETTLE, polling: 500 },
    )
    } finally {
      await closeBrowser(legBrowser)
    }
  })
})
