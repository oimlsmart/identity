// ═══════════════════════════════════════════════════════════════════
// id-41 — the TURNSTILE golden path (TODO.modern/01's UI half, the
// inch #159 could not verify without a browser): the real widget
// renders on the real sign-in page, Cloudflare's always-pass TEST
// pair arms both halves, the challenge AUTO-SOLVES, and the token
// rides the form's POST through the gate to a signed-in landing —
// plus the honest negative (a token-less POST answers the bot 403).
//
// The TEST pair (never a production widget): site key
// 1x00000000000000000000AA + secret 1x0000000000000000000000000000000AA
// — Cloudflare's documented always-pass values; the widget script
// loads from challenges.cloudflare.com (the one external dependency —
// the leg fails honestly if the CDN is unreachable).
//
// SELF-CONTAINED: own ports (API 10693 / astro 10694), own SQLite
// file. THE BROWSER IS PER-LEG (the id-02 lesson).
// ═══════════════════════════════════════════════════════════════════

import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import puppeteer, { type Browser, type Page } from 'puppeteer'
import { spawn, type ChildProcess } from 'node:child_process'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { mkdirSync, rmSync, cpSync, existsSync, appendFileSync } from 'node:fs'
import { closeBrowser, delay } from './helpers'
import { fixtureOpSigningKey } from './fixtures/op-signing-key'

const BROWSER_DIR = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const FIXTURES = join(BROWSER_DIR, 'e2e', 'fixtures')
const DB_DIR = join(BROWSER_DIR, '.cache', 'id-41')

const ID_API = 10693
const ID_WEB = 10694
const ISSUER = `http://localhost:${ID_WEB}`

const TURNSTILE_TEST_SITE_KEY = '1x00000000000000000000AA'
const TURNSTILE_TEST_SECRET = '1x0000000000000000000000000000000AA'

interface Stack {
  api: ChildProcess
  astro: ChildProcess
  base: string
  apiBase: string
  logs: string[]
}

function spawnLogged(cmd: string, args: string[], env: NodeJS.ProcessEnv, logs: string[]): ChildProcess {
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
  try { process.kill(-proc.pid, 'SIGKILL') } catch { /* already gone */ }
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

const PROGRESS_LOG = join(DB_DIR, 'progress.log')
function flog(page: Page | null, msg: string): void {
  const url = page && !page.isClosed() ? page.url() : '(no page)'
  try { appendFileSync(PROGRESS_LOG, `${new Date().toISOString()} ${msg} @ ${url}\n`) } catch { /* never breaks the leg */ }
}

let stack: Stack | undefined

beforeAll(async () => {
  const logs: string[] = []
  mkdirSync(DB_DIR, { recursive: true })
  const dbPath = join(DB_DIR, 'identity.db')
  for (const suffix of ['', '-wal', '-shm']) rmSync(dbPath + suffix, { force: true })
  rmSync(PROGRESS_LOG, { force: true })

  for (const probe of [`http://localhost:${ID_API}/api/health`, `http://localhost:${ID_WEB}/`]) {
    try {
      const res = await fetch(probe)
      if (res.status < 500) throw new Error(`port for ${probe} is already serving — a leftover stack? (kill it: lsof -ti tcp:${new URL(probe).port} | xargs kill)`)
    } catch (e) {
      if (e instanceof Error && e.message.includes('already serving')) throw e
    }
  }

  const api = spawnLogged(join(BROWSER_DIR, 'node_modules', '.bin', 'tsx'), ['server/serve.ts'], {
    PORT: String(ID_API),
    DATABASE_PATH: dbPath,
    ENTITY_BACKEND: 'server',
    INSTANCE_PROFILE: join(FIXTURES, 'instance.profile.identity.yaml'),
    OIDC_ISSUER: '',
    OIDC_CLIENT_ID: '',
    DEMO_ACCOUNTS_ENABLED: 'true',
    OP_ISSUER: ISSUER,
    OP_SIGNING_KEY: await fixtureOpSigningKey(),
    TURNSTILE_SITE_KEY: TURNSTILE_TEST_SITE_KEY,
    TURNSTILE_SECRET: TURNSTILE_TEST_SECRET,
  }, logs)
  const apiBase = `http://localhost:${ID_API}`
  await waitForHttp(`${apiBase}/api/health`, 120_000, logs)

  const stackViteCache = join(DB_DIR, `vite-${ID_WEB}`)
  const sharedViteCache = join(BROWSER_DIR, 'node_modules', '.vite')
  if (existsSync(sharedViteCache)) {
    rmSync(stackViteCache, { recursive: true, force: true })
    cpSync(sharedViteCache, stackViteCache, { recursive: true })
  }
  const astro = spawnLogged(join(BROWSER_DIR, 'node_modules', '.bin', 'astro'), ['dev', '--port', String(ID_WEB), '--ignore-lock'], {
    API_ORIGIN: apiBase,
    VITE_CACHE_DIR: stackViteCache,
    DEV_PUBLIC_HOST: `localhost:${ID_WEB}`,
  }, logs)
  const base = `http://localhost:${ID_WEB}`
  await waitForHttp(`${base}/`, 240_000, logs)
  stack = { api, astro, base, apiBase, logs }
}, 840_000)

afterAll(() => {
  if (!stack) return
  for (const proc of [stack.astro, stack.api]) killTree(proc)
  delay(1_500).then(() => {
    for (const proc of [stack!.astro, stack!.api]) killTreeHard(proc)
  })
})

describe('the Turnstile golden path (the always-pass test pair)', () => {
  it('leg 1 — the config carries the site key; the widget MOUNTS and AUTO-SOLVES on the real sign-in page; the form rides the gate to a signed-in landing', { timeout: 480_000 }, async () => {
    const cfg = await fetch(`${stack!.base}/api/config`)
    expect(cfg.status).toBe(200)
    const body = await cfg.json() as { turnstile?: { siteKey?: string | null } }
    expect(body.turnstile?.siteKey, 'the public config carries the site key through the proxy').toBe(TURNSTILE_TEST_SITE_KEY)

    const browser: Browser = await puppeteer.launch({
      headless: 'shell',
      protocolTimeout: 480_000,
      args: ['--no-sandbox', '--disable-setuid-sandbox'],
    })
    try {
      const page = await browser.newPage()
      await page.setViewport({ width: 1440, height: 900 })
      await page.goto(`${stack!.base}/`, { waitUntil: 'domcontentloaded', timeout: 240_000 })
      flog(page, 'login page loaded')

      // The widget container mounts (the armed projection drove it).
      await page.waitForSelector('[data-testid="turnstile-widget"]', { timeout: 120_000 })
      flog(page, 'widget container mounted')

      // NO iframe wait: the always-pass TEST key's auto-solve path
      // injects the response input DIRECTLY — no challenge iframe is
      // ever created (the local probe's finding: script loaded,
      // window.turnstile standing, one child, one input, zero
      // iframes). The SOLVE is the observable, never the frame.
      //
      // The always-pass key AUTO-SOLVES: the response input carries a
      // non-empty token inside our container.
      await page.waitForFunction(() => {
        const input = document.querySelector('[data-testid="turnstile-widget"] input[name="cf-turnstile-response"]') as HTMLInputElement | null
        return input !== null && input.value.length > 0
      }, { timeout: 180_000, polling: 500 })
      flog(page, 'challenge auto-solved (the token stands)')

      // The sign-in THROUGH THE FORM: the token rides the POST, the
      // gate opens, the demo cast lands signed in (a refused bot check
      // would answer the form's error instead of navigating).
      await page.type('[data-testid="login-email"]', 'ia@oiml.org')
      await page.type('[data-testid="login-password"]', 'demo2026')
      await page.evaluate(() => (document.querySelector('[data-testid="login-submit"]') as HTMLElement).click())
      flog(page, 'submitted')
      // The sign-in is an SPA route change (router.replace) — NO
      // document navigation ever fires; the landing's own marker is
      // the wait (the id-15 pattern).
      // The launcher (/op/home) is the default landing — its own
      // testid is the signed-in marker (a refused bot check leaves
      // the page on / with the form's error instead).
      await page.waitForSelector('[data-testid="home"]', { timeout: 240_000, polling: 500 })
      flog(page, `landed at ${await page.evaluate(() => window.location.pathname)}`)
      expect(await page.evaluate(() => window.location.pathname)).not.toBe('/')
    } finally {
      await closeBrowser(browser)
    }
  })

  it('leg 2 — the honest negative: a token-less POST answers the bot 403 (the gate is the arbiter, never the page)', { timeout: 60_000 }, async () => {
    const res = await fetch(`${stack!.base}/api/op/login`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: 'ia@oiml.org', password: 'demo2026' }),
    })
    expect(res.status).toBe(403)
    expect(((await res.json()) as { error: string }).error).toContain('bot')
  })
})
