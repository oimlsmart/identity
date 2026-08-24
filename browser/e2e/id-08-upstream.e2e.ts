// ═══════════════════════════════════════════════════════════════════
// TODO.identity/08 — the OP's upstream providers e2e: the identity-
// profile stack (its own API + its own astro, the id-01 spawned-stack
// pattern) + the stub OIDC provider (e2e/fixtures/stub-idp.ts) as the
// GENERIC provider row. The full round trip runs in the browser:
//
//   leg 1  the admin API registers + enables the provider; the OP's
//          login page renders its button (the registry drives the UI);
//   leg 2  a signed-in account LINKS the provider from the account page
//          (/op/account — TODO.identity/02's page, native on this host) —
//          the flow rides the browser to the stub's consent and back;
//   leg 3  sign out, then SIGN IN with the provider — the link resolves
//          by (provider, sub), never by email, and the session starts;
//   leg 4  an UNLINKED stub user is refused honestly ("not linked — ask
//          your administrator") — no session, no account;
//   leg 5  unlink from /op/account → the sign-in is refused again.
//          TODO.identity/06's at-least-one-method guard applies: the
//          demo-cast account has no password credential, so the leg
//          watches the guard hold (the disabled unlink + its reason),
//          sets a password through the console, and then unlinks.
//
// SELF-CONTAINED: the suite's shared stack (E2E_BASE_URL) is untouched —
// the identity instance boots on its own ports (API 8993 / astro 8893,
// the stub IdP on 8994) with its own SQLite file.
// ═══════════════════════════════════════════════════════════════════

import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import puppeteer, { type Browser, type Page } from 'puppeteer'
import { spawn, type ChildProcess } from 'node:child_process'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { existsSync, mkdirSync, rmSync, cpSync } from 'node:fs'
import { closeBrowser, delay } from './helpers'
import { fixtureOpSigningKey } from './fixtures/op-signing-key'
import { startStubIdp, type StubIdp } from './fixtures/stub-idp'

const BROWSER_DIR = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const FIXTURES = join(BROWSER_DIR, 'e2e', 'fixtures')
const DB_DIR = join(BROWSER_DIR, '.cache', 'id-08')

// Port-isolated: clear of the shared dev stack (5190/3190), the fed-01
// stacks (8291/8292/8491/8492), the id-01 stack (8693/8393/8694), the
// fed-10 stub (8699), the local identity dev stack (7390/7190) and the
// id-02 stack (8793/8593/8794).
const ID_API = 8993
const ID_WEB = 8893
const IDP_PORT = 8994

const IDP_CLIENT_ID = 'oiml-smart-op'
const IDP_SECRET = 'e2e-idp-secret'

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

/** Boot the identity-profile stack: the API on its own SQLite file with
 *  the OP env + the upstream provider's secret env, the profile seed
 *  through the dev-reset seam, astro dev against it. */
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
    // OIDC_* scrubbed + the demo override ON: a CI e2e job declares the
    // SUITE stack's SSO posture in the shared env — the identity stack
    // must not inherit it (an SSO-configured OP instance would turn the
    // demo sign-in surface off under the fed-10 default rule).
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
      // The upstream provider's client secret rides the env (the row
      // references it — the registry never stores secrets).
      IDP_E2E_SECRET: IDP_SECRET,
    }, logs)
    const apiBase = `http://localhost:${ID_API}`
    await waitForHttp(`${apiBase}/api/health`, 120_000, logs)

    // Provision the profile's seed (the demo cast + the instance admin).
    const reset = await fetch(`${apiBase}/api/dev-reset`, { method: 'POST' })
    if (!reset.ok) throw new Error(`dev-reset on ${apiBase} answered ${reset.status}\n${logs.join('').slice(-2000)}`)

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

const SETTLE = 240_000
// The account page is /op/account (TODO.identity/02 — native on this
// host). The FIRST /app/* navigation of a run compiles
// the app-shell island cold — on a contended host that outlives SETTLE.
const APP_COLD = 840_000 // spawned astro compiles page chunks cold on first hit

/** Sign in at the OP through the demo form (real password accounts are
 *  TODO.identity/02's). */
async function opSignIn(page: Page, email: string): Promise<void> {
  await page.waitForSelector('[data-testid="login-email"]', { timeout: SETTLE, polling: 500 })
  await page.evaluate(() => {
    (document.querySelector('[data-testid="login-email"]') as HTMLInputElement).value = ''
  })
  await page.type('[data-testid="login-email"]', email)
  await page.type('[data-testid="login-password"]', 'demo2026')
  await page.evaluate(() => (document.querySelector('[data-testid="login-submit"]') as HTMLElement).click())
}

/** The signed-in session's account (null when signed out). */
async function sessionEmail(page: Page): Promise<string | null> {
  return page.evaluate(async () => {
    const res = await fetch('/api/auth/session', { credentials: 'include' })
    if (!res.ok) return null
    return (await res.json() as { email: string }).email
  })
}

/** Drop the session (the cookie is httpOnly — the browser-side delete). */
async function signOut(page: Page): Promise<void> {
  await page.evaluate(async () => {
    await fetch('/api/auth/signout', { method: 'POST', credentials: 'include' })
  })
}

/** Pick the fixture user at the stub IdP's consent page. */
async function stubConsent(page: Page, userId: string): Promise<void> {
  await page.waitForSelector('[data-testid="stub-idp-consent"]', { timeout: SETTLE, polling: 500 })
  await page.evaluate((id) => {
    (document.querySelector(`[data-user="${id}"]`) as HTMLElement).click()
  }, userId)
}

describe('TODO.identity/08 — the OP’s upstream providers (the identity profile)', () => {
  let stack: Stack
  let idp: StubIdp
  let browser: Browser
  let page: Page

  beforeAll(async () => {
    // The stub IdP on its FIXED port first — the provider row points at it.
    idp = await startStubIdp({ port: IDP_PORT })
    stack = await bootIdentityStack()
    browser = await puppeteer.launch({ headless: 'shell', protocolTimeout: 480_000, args: ['--no-sandbox', '--disable-setuid-sandbox'] })
    page = await browser.newPage()
    await page.setViewport({ width: 1440, height: 900 })
    page.on('pageerror', e => console.log('[pageerror]', String(e).slice(0, 300)))
    page.on('requestfailed', r => console.log('[requestfailed]', r.url().slice(0, 140), r.failure()?.errorText ?? ''))
  }, 600_000)

  afterAll(async () => {
    await closeBrowser(browser)
    await idp?.close()
    await stopStack(stack)
  })

  it('leg 1 — the admin API registers + enables the provider; the login page renders its button', { timeout: 600_000 }, async () => {
    // The registry write rides the admin API (the real admin surface,
    // session cookie from the demo admin sign-in).
    const login = await fetch(`${stack.apiBase}/api/auth/demo`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: 'admin@oiml.org', password: 'demo2026' }),
    })
    expect(login.ok).toBe(true)
    const cookie = login.headers.get('set-cookie')!.split(';')[0]!

    const created = await fetch(`${stack.apiBase}/api/op/providers`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({
        id: 'fixture-idp',
        kind: 'oidc',
        display_name: 'Fixture IdP',
        brand_mark: 'oidc',
        issuer: idp.issuer,
        client_id: IDP_CLIENT_ID,
        client_secret_ref: 'env:IDP_E2E_SECRET',
        enabled: true,
      }),
    })
    expect(created.status).toBe(201)
    expect(await created.json()).toMatchObject({ id: 'fixture-idp', enabled: true, issuer: idp.issuer })

    // The login page renders the button FROM THE REGISTRY.
    await page.goto(`${stack.base}/`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await page.waitForSelector('[data-testid="upstream-login-fixture-idp"]', { timeout: SETTLE, polling: 500 })
    const label = await page.$eval('[data-testid="upstream-login-fixture-idp"]', el => el.textContent?.trim())
    expect(label).toBe('Sign in with Fixture IdP')
  })

  it('leg 2 — a signed-in account links the provider from the account page (the browser round trip)', { timeout: 900_000 }, async () => {
    await page.goto(`${stack.base}/`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await opSignIn(page, 'ia@oiml.org')
    // Signed in (the demo login lands on the role home).
    await page.waitForFunction(() => window.location.pathname !== '/', { timeout: SETTLE, polling: 500 })
    expect(await sessionEmail(page)).toBe('ia@oiml.org')

    await page.goto(`${stack.base}/op/account`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await page.waitForSelector('[data-testid="op-account"]', { timeout: APP_COLD, polling: 500 })
    expect(await page.$('[data-testid="op-account-no-links"]')).toBeTruthy()

    // The link action: the provider flow bound to THIS session.
    await page.evaluate(() => (document.querySelector('[data-testid="op-account-link-fixture-idp-action"]') as HTMLElement).click())
    await stubConsent(page, 'ada')

    // Back on the account page: the link shows.
    await page.waitForSelector('[data-testid="op-account-link-fixture-idp"]', { timeout: SETTLE, polling: 500 })
    expect(new URL(page.url()).pathname).toBe('/op/account')
    expect(new URL(page.url()).searchParams.get('linked')).toBe('fixture-idp')
    const notice = await page.$eval('[data-testid="op-account-notice"]', el => el.textContent ?? '')
    expect(notice).toContain('Fixture IdP')
    const row = await page.$eval('[data-testid="op-account-link-fixture-idp"]', el => el.textContent ?? '')
    expect(row).toContain('stub-ada')
  })

  it('leg 3 — sign in with the provider: the link resolves by (provider, sub), the session starts', { timeout: 900_000 }, async () => {
    await signOut(page)
    expect(await sessionEmail(page)).toBeNull()

    await page.goto(`${stack.base}/`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await page.waitForSelector('[data-testid="upstream-login-fixture-idp"]', { timeout: SETTLE, polling: 500 })
    await page.evaluate(() => (document.querySelector('[data-testid="upstream-login-fixture-idp"]') as HTMLElement).click())
    await stubConsent(page, 'ada')

    // The session started as the linked account (ia@oiml.org) — the
    // redirect landed on a signed-in page (not the login page).
    await page.waitForFunction(() => window.location.pathname !== '/', { timeout: SETTLE, polling: 500 })
    await delay(1_000)
    expect(await sessionEmail(page)).toBe('ia@oiml.org')
  })

  it('leg 4 — an unlinked upstream identity is refused honestly (never matched by email)', { timeout: 900_000 }, async () => {
    await signOut(page)
    // bob@example.org is NOBODY's account email here — and to prove the
    // guard reads ONLY the link table, carol carries no link either; an
    // email lookalike would matter only if we matched on it (we don't).
    await page.goto(`${stack.base}/`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await page.waitForSelector('[data-testid="upstream-login-fixture-idp"]', { timeout: SETTLE, polling: 500 })
    await page.evaluate(() => (document.querySelector('[data-testid="upstream-login-fixture-idp"]') as HTMLElement).click())
    await stubConsent(page, 'bob')

    // The honest refusal on the login page — no session.
    await page.waitForSelector('[data-testid="login-error"]', { timeout: SETTLE, polling: 500 })
    expect(new URL(page.url()).pathname).toBe('/')
    expect(new URL(page.url()).searchParams.get('error')).toBe('upstream_not_linked')
    const message = await page.$eval('[data-testid="login-error"]', el => el.textContent ?? '')
    expect(message).toContain('Fixture IdP')
    expect(message).toContain('not linked')
    expect(await sessionEmail(page)).toBeNull()
  })

  it('leg 5 — unlink from /op/account; the sign-in is then refused', { timeout: 900_000 }, async () => {
    await page.goto(`${stack.base}/`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await opSignIn(page, 'ia@oiml.org')
    await page.waitForFunction(() => window.location.pathname !== '/', { timeout: SETTLE, polling: 500 })

    await page.goto(`${stack.base}/op/account`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await page.waitForSelector('[data-testid="op-account-unlink-fixture-idp"]', { timeout: APP_COLD, polling: 500 })

    // TODO.identity/06's guard: an account always keeps at least one way
    // in. This account is a demo-cast row (no password credential), so
    // the linked IdP is its ONLY method — the unlink button is disabled
    // and explains itself…
    expect(await page.$eval('[data-testid="op-account-unlink-fixture-idp"]', el => (el as HTMLButtonElement).disabled)).toBe(true)
    await page.waitForSelector('[data-testid="account-link-guard"]', { timeout: SETTLE, polling: 500 })
    // …so the account sets a password first (the console's set form), and
    // THEN the unlink is allowed.
    await page.type('[data-testid="account-password-next"]', 'the ia officer passphrase')
    await page.type('[data-testid="account-password-confirm"]', 'the ia officer passphrase')
    await page.evaluate(() => (document.querySelector('[data-testid="account-password-submit"]') as HTMLElement).click())
    await page.waitForFunction(
      () => document.querySelector('[data-testid="account-method-password-state"]')?.textContent?.includes('A password is set'),
      { timeout: SETTLE, polling: 500 },
    )

    await page.evaluate(() => (document.querySelector('[data-testid="op-account-unlink-fixture-idp"]') as HTMLElement).click())
    await page.waitForSelector('[data-testid="op-account-no-links"]', { timeout: SETTLE, polling: 500 })

    await signOut(page)
    await page.goto(`${stack.base}/`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await page.waitForSelector('[data-testid="upstream-login-fixture-idp"]', { timeout: SETTLE, polling: 500 })
    await page.evaluate(() => (document.querySelector('[data-testid="upstream-login-fixture-idp"]') as HTMLElement).click())
    await stubConsent(page, 'ada')
    await page.waitForSelector('[data-testid="login-error"]', { timeout: SETTLE, polling: 500 })
    expect(new URL(page.url()).searchParams.get('error')).toBe('upstream_not_linked')
    expect(await sessionEmail(page)).toBeNull()
  })
})
