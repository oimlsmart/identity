// ═══════════════════════════════════════════════════════════════════
// The account chooser in a REAL browser (the multi-account wave's
// browser-level proof, the demonstration cast's own flow):
//
//   leg 1  the first sign-in: the RP's flow, the OP's sign-in form, the
//          consent page — the code lands and the RP validates it (the
//          stub RP's REAL validation path);
//   leg 2  the SECOND account on the SAME browser profile rides
//          prompt=login (the forced re-authentication) — and the flow's
//          login_hint PREFILLS the sign-in form's address field;
//   leg 3  the chooser: prompt=select_account renders the chooser even
//          with a live session — both remembered accounts list, the
//          presenting one badged, the login_hint's entry PRE-SELECTED —
//          and clicking the pre-selected entry hands the flow to THAT
//          account: the authorize re-entry mints its code (the
//          remembered grant skips the consent page) and the RP's
//          validated claims name the CHOSEN account;
//   leg 4  the default flow stays byte-identical: no prompt, the live
//          session, the remembered grant — the RP gets its code with no
//          chooser and no consent page.
//
// SELF-CONTAINED: its own identity stack + its own stub RP (the id-01
// harness, port-isolated).
// ═══════════════════════════════════════════════════════════════════

import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import puppeteer, { type Browser, type Page } from 'puppeteer'
import { spawn, type ChildProcess } from 'node:child_process'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { existsSync, mkdirSync, rmSync, cpSync } from 'node:fs'
import { closeBrowser, delay } from './helpers'
import { fixtureOpSigningKey } from './fixtures/op-signing-key'
import { startStubRp, type StubRp } from './fixtures/stub-rp'

const BROWSER_DIR = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const FIXTURES = join(BROWSER_DIR, 'e2e', 'fixtures')
const DB_DIR = join(BROWSER_DIR, '.cache', 'id-42')

// Port-isolated: clear of id-01's stack (8693/8393/8694) and every other resident stack, the shared dev
// stack (5190/3190), the fed-01 stacks and the fed-10 stub.
const ID_API = 8791
const ID_WEB = 8793
const RP_PORT = 8792

const ISSUER = `http://localhost:${ID_WEB}`
const RP_CLIENT_ID = 'fixture-rp'
const RP_CLIENT_SECRET = 'fixture-rp-secret'

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

/** Sign in at the OP through the form (the identity instance's demo
 *  cast), answering whatever form the flow landed on. */
async function opSignIn(page: Page, email: string): Promise<void> {
  await page.waitForSelector('[data-testid="login-email"]', { timeout: SETTLE, polling: 500 })
  await page.evaluate(() => {
    (document.querySelector('[data-testid="login-email"]') as HTMLInputElement).value = ''
  })
  await page.type('[data-testid="login-email"]', email)
  await page.type('[data-testid="login-password"]', 'demo2026')
  await page.evaluate(() => (document.querySelector('[data-testid="login-submit"]') as HTMLElement).click())
}

describe('the account chooser (the multi-account wave, browser-level)', () => {
  let stack: Stack
  let rp: StubRp
  let browser: Browser
  let page: Page

  beforeAll(async () => {
    stack = await bootIdentityStack()
    rp = await startStubRp({
      port: RP_PORT,
      issuer: ISSUER,
      clientId: RP_CLIENT_ID,
      clientSecret: RP_CLIENT_SECRET,
    })
    browser = await puppeteer.launch({ headless: 'shell', protocolTimeout: 480_000, args: ['--no-sandbox', '--disable-setuid-sandbox'] })
    page = await browser.newPage()
    await page.setViewport({ width: 1440, height: 900 })
    page.on('pageerror', e => console.log('[pageerror]', String(e).slice(0, 300)))
    page.on('requestfailed', r => console.log('[requestfailed]', r.url().slice(0, 140), r.failure()?.errorText ?? ''))
  }, 600_000)

  afterAll(async () => {
    await closeBrowser(browser)
    await rp?.close()
    await stopStack(stack)
  })

  it('leg 1 — the first sign-in completes through the OP (ia@oiml.org)', { timeout: 900_000 }, async () => {
    await page.goto(`${rp.baseUrl}/signin`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await page.waitForFunction(() => window.location.pathname === '/', { timeout: SETTLE, polling: 500 })
    await opSignIn(page, 'ia@oiml.org')
    await page.waitForSelector('[data-testid="op-consent-allow"]', { timeout: SETTLE, polling: 500 })
    await page.evaluate(() => (document.querySelector('[data-testid="op-consent-allow"]') as HTMLElement).click())
    await page.waitForSelector('[data-testid="rp-signed-in"]', { timeout: SETTLE, polling: 500 })
    expect(await page.$eval('[data-testid="rp-email"]', el => el.textContent?.trim())).toBe('ia@oiml.org')
  })

  it('leg 2 — the second account on the SAME browser rides prompt=login, the login_hint prefills the form (tl@oiml.org)', { timeout: 900_000 }, async () => {
    await page.goto(`${rp.baseUrl}/signin?prompt=login&login_hint=tl%40oiml.org`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await page.waitForSelector('[data-testid="login-email"]', { timeout: SETTLE, polling: 500 })
    expect(new URL(page.url()).searchParams.get('login_hint')).toBe('tl@oiml.org')
    // The hint IS the prefill: the address field arrives already naming
    // the account the RP suggested.
    await page.waitForFunction(
      () => (document.querySelector('[data-testid="login-email"]') as HTMLInputElement | null)?.value === 'tl@oiml.org',
      { timeout: SETTLE, polling: 500 },
    )
    await page.type('[data-testid="login-password"]', 'demo2026')
    await page.evaluate(() => (document.querySelector('[data-testid="login-submit"]') as HTMLElement).click())
    await page.waitForSelector('[data-testid="op-consent-allow"]', { timeout: SETTLE, polling: 500 })
    await page.evaluate(() => (document.querySelector('[data-testid="op-consent-allow"]') as HTMLElement).click())
    await page.waitForSelector('[data-testid="rp-signed-in"]', { timeout: SETTLE, polling: 500 })
    expect(await page.$eval('[data-testid="rp-email"]', el => el.textContent?.trim())).toBe('tl@oiml.org')
  })

  it('leg 3 — prompt=select_account renders the chooser with both accounts; the hinted entry is pre-selected; the switch completes to code issuance as the CHOSEN account', { timeout: 900_000 }, async () => {
    await page.goto(`${rp.baseUrl}/signin?prompt=select_account&login_hint=ia%40oiml.org`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await page.waitForSelector('[data-testid="op-choose-account"]', { timeout: SETTLE, polling: 500 })

    // Both remembered accounts list — the presenting one badged, the
    // hinted one pre-selected.
    await page.waitForSelector('[data-testid="chooser-account-ia@oiml.org"]', { timeout: SETTLE, polling: 500 })
    await page.waitForSelector('[data-testid="chooser-account-tl@oiml.org"]', { timeout: SETTLE, polling: 500 })
    expect(await page.$$('[data-testid="chooser-use-another"]')).toHaveLength(1) // the Google shape's escape hatch
    const current = await page.$('[data-testid="chooser-account-tl@oiml.org"] [data-testid="chooser-current-badge"]')
    expect(current, 'the presenting account (tl) carries the current badge').toBeTruthy()
    const hinted = await page.$('[data-testid="chooser-hinted-badge"]')
    expect(hinted, 'the login_hint\'s account (ia) carries the pre-selection badge').toBeTruthy()
    const hintedRow = await page.$eval('[data-testid="chooser-hinted-badge"]', el => {
      const row = el.closest('[data-testid^="chooser-account-"]')
      return row?.getAttribute('data-testid')
    })
    expect(hintedRow).toBe('chooser-account-ia@oiml.org')

    mkdirSync(DB_DIR, { recursive: true })
    await page.screenshot({ path: join(DB_DIR, 'chooser-two-accounts.png') })

    // The pre-selection is an affordance, never a decision: the click
    // chooses. The flow continues as the CHOSEN account — the authorize
    // re-entry mints its code (the remembered grant skips the consent
    // page) and the RP validates ITS token.
    await page.evaluate(() => (document.querySelector('[data-testid="chooser-account-ia@oiml.org"]') as HTMLElement).click())
    await page.waitForSelector('[data-testid="rp-signed-in"]', { timeout: SETTLE, polling: 500 })
    expect(await page.$eval('[data-testid="rp-email"]', el => el.textContent?.trim())).toBe('ia@oiml.org')
  })

  it('leg 4 — the default flow stays byte-identical: no chooser, the live session mints straight through', { timeout: 900_000 }, async () => {
    await page.goto(`${rp.baseUrl}/signin`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await page.waitForSelector('[data-testid="rp-signed-in"]', { timeout: SETTLE, polling: 500 })
    // The chooser never appeared; the presenting session (ia, chosen in
    // leg 3) signed the RP in directly.
    expect(await page.$('[data-testid="op-choose-account"]')).toBeNull()
    expect(await page.$eval('[data-testid="rp-email"]', el => el.textContent?.trim())).toBe('ia@oiml.org')
  })
})
