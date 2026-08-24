// ═══════════════════════════════════════════════════════════════════
// TODO.identity/02 — the OP's account model e2e: the identity-profile
// stack (its own API + its own astro, the fed-01 spawned-stack pattern)
// proves the FULL account lifecycle against the stub GitHub
// (e2e/fixtures/stub-github.ts — real HTTP; the `login` param is the
// stub's consent shortcut, injected by request interception so the
// browser drives the REAL buttons):
//
//   leg 1  the bootstrap seed (OP_ACCOUNT_SEED) mints the first admin's
//          setup link — read from the boot log, driven through the
//          /op/setup page (weak password refused by the honest meter +
//          the policy, the real one accepted) → the account page;
//   leg 2  the seeded admin invites Willa; her setup link sets the
//          password; the USED link then answers its honest card;
//   leg 3  the password sign-in (the login page's OP form);
//   leg 4  link GitHub from the account page (the real button, the
//          signed state, the stub round trip) → the link listed;
//   leg 5  sign in with GitHub (the login page's button) — matched by
//          the linked provider_account_id; the sessions card lists both
//          sessions and revokes one;
//   leg 6  unlink → the next GitHub sign-in is REFUSED honestly
//          ("not linked — ask your administrator");
//   leg 7  the consent round trip: the invited account signs in at the
//          OP mid-authorize and completes authorize → consent → token →
//          userinfo for the registered fixture RP (stub-rp.ts, the RP's
//          REAL validator against the OP's JWKS).
//
// SELF-CONTAINED: the suite's shared stack (E2E_BASE_URL) is untouched —
// own ports (API 8793 / astro 8593 / RP 8794), own SQLite file, the stub
// GitHub on a kernel-assigned port.
//
// THE BROWSER IS PER-LEG: a long-lived headless-shell launched during a
// load spike wedges silently (observed 2026-08-16: zero-CPU stall across
// every budget while fresh browsers against the SAME stack completed the
// flow in seconds). A fresh browser per leg costs ~2 s and dodges the
// class; cross-leg state rides the DATABASE (sessions survive — the
// sessions leg counts on exactly that).
// ═══════════════════════════════════════════════════════════════════

import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import puppeteer, { type Browser, type Page } from 'puppeteer'
import { spawn, type ChildProcess } from 'node:child_process'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { existsSync, mkdirSync, rmSync, cpSync, appendFileSync } from 'node:fs'
import { closeBrowser, delay } from './helpers'
import { fixtureOpSigningKey } from './fixtures/op-signing-key'
import { startStubRp, type StubRp } from './fixtures/stub-rp'
import { startStubGitHub, type StubGitHub } from './fixtures/stub-github'

const BROWSER_DIR = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const FIXTURES = join(BROWSER_DIR, 'e2e', 'fixtures')
const DB_DIR = join(BROWSER_DIR, '.cache', 'id-02')

// Port-isolated: clear of the shared dev stack (5190/3190), the fed-01
// stacks (8291/8292/8491/8492), the fed-10 stub (8699), the id-01 stack
// (8693/8393/8694) and the local identity dev stack (7390/7190).
const ID_API = 8793
const ID_WEB = 8593
const RP_PORT = 8794

const ISSUER = `http://localhost:${ID_WEB}` // the astro origin (the browser's OP)
const RP_CLIENT_ID = 'fixture-rp-02'
const RP_CLIENT_SECRET = 'fixture-rp-02-secret'

const ROOT = { email: 'root@oimlsmart.org', name: 'Root Operator', password: 'the root operator passphrase' }
const WILLA = { email: 'willa@example.org', name: 'Willa Example', password: 'willa has a proper passphrase' }
const GH_WILLA = { login: 'octocat-willa', id: 302, name: 'Octo Willa', email: 'willa-gh@example.org' }

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
 *  the OP env (the issuer, the client-registry bootstrap seed, the
 *  ACCOUNT bootstrap seed, and the stub GitHub's client pair), the
 *  profile seed through the dev-reset seam, astro dev against it. */
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
      OP_ISSUER: ISSUER,
      // identity#7: a declared-issuer stack declares its signing key too
      // (the generated dev key never registers off the dev posture).
      OP_SIGNING_KEY: await fixtureOpSigningKey(),
      // The first administrator arrives by DECLARATION (invite-only means
      // nobody else can mint the first link) — the setup link lands in
      // the boot log.
      OP_ACCOUNT_SEED: JSON.stringify([{ email: ROOT.email, name: ROOT.name, role: 'admin' }]),
      // The registry's bootstrap seed: the fixture RP (a confidential
      // client carrying the role-claim policy).
      OP_CLIENT_SEED: JSON.stringify([{
        client_id: RP_CLIENT_ID,
        name: 'The id-02 fixture RP',
        secret: RP_CLIENT_SECRET,
        redirect_uris: [`http://127.0.0.1:${RP_PORT}/callback`],
        claims_policy: { claims: ['roles', 'groups', 'org'] },
      }]),
      // The linked login's upstream: the stub GitHub as a REGISTRY ROW
      // (TODO.identity/08 — a provider is a row, never a code fork);
      // the secret resolves from the env by reference, the endpoints
      // ride the GHES seam to the stub. (No GITHUB_CLIENT_ID/SECRET on
      // the OP — that pair is the instance-local flow's, not the OP's.)
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
// island (the OP's islands — /, /op/consent, /op/account);
// on a contended host that cold compile outlives SETTLE. The first
// account-page wait of each flow carries this budget; once warm, the
// later waits are cheap.
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
 *  continuity — the account page then loads signed in). */
async function signInViaCookie(page: Page, base: string, cookieValue: string): Promise<void> {
  await page.setCookie({ name: 'oiml-session', value: cookieValue, url: base })
}

/** Sign the browser out (every cookie dropped — the session ROWS stay,
 *  which is exactly what the sessions card then lists). */
async function browserSignOut(page: Page, base: string): Promise<void> {
  const cookies = await page.cookies(base)
  if (cookies.length) await page.deleteCookie(...cookies)
}

/** The OP's password sign-in through the login page form. */
async function opPasswordSignIn(page: Page, email: string, password: string): Promise<void> {
  await page.waitForSelector('[data-testid="login-email"]', { timeout: SETTLE, polling: 500 })
  await page.type('[data-testid="login-email"]', email)
  await page.type('[data-testid="login-password"]', password)
  await page.evaluate(() => (document.querySelector('[data-testid="login-submit"]') as HTMLElement).click())
}

let stubGithub: StubGitHub

/** The stub GitHub's consent shortcut: the browser drives the REAL
 *  button/redirect, and the interception appends the fixture `login`
 *  param GitHub has no equivalent of (documented in stub-github.ts). */
async function interceptStubGitHub(page: Page, login: string): Promise<void> {
  await page.setRequestInterception(true)
  page.on('request', (req) => {
    const url = req.url()
    const p = url.startsWith(`${stubGithub.baseUrl}/login/oauth/authorize`)
      ? req.continue({ url: `${url}&login=${login}` })
      : req.continue()
    // Teardown races in-flight deliveries: a continue() landing after
    // stopIntercepting disabled interception throws "Request Interception
    // is not enabled!" — and an event-handler throw fails the suite. The
    // request is already answered or the target already closed; either
    // way there is nothing honest left to do with it.
    void p.catch(() => {})
  })
}

async function stopIntercepting(page: Page): Promise<void> {
  // Listener off FIRST: with the listener gone no continue() can race the
  // disable; the catch guard above covers the deliveries already in flight.
  page.removeAllListeners('request')
  await page.setRequestInterception(false)
}

describe('TODO.identity/02 — the OP account model (the identity profile)', () => {
  let stack: Stack
  let rp: StubRp

  beforeAll(async () => {
    stubGithub = await startStubGitHub({ clientSecret: 'op-e2e-secret', users: [GH_WILLA] })
    stack = await bootIdentityStack(stubGithub)
    rp = await startStubRp({
      port: RP_PORT,
      issuer: ISSUER,
      clientId: RP_CLIENT_ID,
      clientSecret: RP_CLIENT_SECRET,
    })
  }, 600_000)

  afterAll(async () => {
    await rp?.close()
    await stubGithub?.close()
    await stopStack(stack)
  })

  it('leg 1 — the bootstrap seed: the first admin’s logged setup link sets the password through /op/setup', { timeout: 900_000 }, async () => {
    // The seed logged the one-time link (the operator's way in on a
    // fresh OP) — read it from the API's log stream.
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
      expect(who).toContain(ROOT.email)

      // The honest meter + the policy: a short password is refused and
      // the link is NOT burned.
      await page.type('[data-testid="op-setup-password"]', 'short')
      await page.type('[data-testid="op-setup-confirm"]', 'short')
      const meter = await page.$eval('[data-testid="op-setup-meter-label"]', el => el.textContent?.trim())
      expect(meter).toBe('Too short')
      await page.evaluate(() => (document.querySelector('[data-testid="op-setup-submit"]') as HTMLElement).click())
      await page.waitForSelector('[data-testid="op-setup-error"]', { timeout: 30_000, polling: 200 })
      expect(await page.$eval('[data-testid="op-setup-error"]', el => el.textContent ?? '')).toContain('12')
      flog(page, 'leg1: the weak path refused honestly')

      // The real password: accepted, signed in, on the account page.
      // Clear WITH input events — a bare .value assignment desyncs the
      // v-model, and the next reactive flush re-applies the stale model
      // to the OTHER field mid-typing (observed: confirm = 'short' + the
      // typed text). The input events keep model and DOM in lockstep.
      await page.evaluate(() => {
        for (const t of ['op-setup-password', 'op-setup-confirm']) {
          const el = document.querySelector(`[data-testid="${t}"]`) as HTMLInputElement
          el.value = ''
          el.dispatchEvent(new Event('input', { bubbles: true }))
        }
      })
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

  it('leg 2 — the seeded admin invites Willa; her link sets the password exactly once', { timeout: 900_000 }, async () => {
    // The seeded admin invites over the API (the console UI is item 03's).
    const rootCookie = await passwordCookie(stack.base, ROOT.email, ROOT.password)
    const invite = await fetch(`${stack.base}/api/op/accounts`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: `oiml-session=${rootCookie}` },
      body: JSON.stringify({ email: WILLA.email, name: WILLA.name }),
    })
    expect(invite.status).toBe(201)
    const { setupUrl } = await invite.json() as { setupUrl: string }
    flog(null, 'leg2: invited')

    await withPage(async (page) => {
      // Willa's browser is a FRESH one (no cookies).
      await page.goto(setupUrl, { waitUntil: 'domcontentloaded', timeout: SETTLE })
      await page.waitForSelector('[data-testid="op-setup-account"]', { timeout: SETTLE, polling: 500 })
      expect(await page.$eval('[data-testid="op-setup-account"]', el => el.textContent ?? '')).toContain(WILLA.email)
      await page.type('[data-testid="op-setup-password"]', WILLA.password)
      await page.type('[data-testid="op-setup-confirm"]', WILLA.password)
      await page.evaluate(() => (document.querySelector('[data-testid="op-setup-submit"]') as HTMLElement).click())
      await page.waitForSelector('[data-testid="account-name"]', { timeout: APP_COLD, polling: 500 })
      expect(await page.$eval('[data-testid="account-name"]', el => el.textContent?.trim())).toBe(WILLA.name)
      flog(page, 'leg2: enrolled')

      // One-time means one-time: the used link answers its honest card.
      await browserSignOut(page, stack.base)
      await page.goto(setupUrl, { waitUntil: 'domcontentloaded', timeout: SETTLE })
      await page.waitForSelector('[data-testid="op-setup-used"]', { timeout: SETTLE, polling: 500 })
      flog(page, 'leg2: the used link says so')
    })
  })

  it('leg 3 — the password sign-in through the login page’s OP form', { timeout: 600_000 }, async () => {
    await withPage(async (page) => {
      await page.goto(`${stack.base}/`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
      // The OP surface: the password form AND the registry-driven GitHub
      // button (TODO.identity/08's upstream row) AND (the fixture keeps
      // the cast) the demo accounts.
      await page.waitForSelector('[data-testid="upstream-login-github"]', { timeout: SETTLE, polling: 500 })
      await opPasswordSignIn(page, WILLA.email, WILLA.password)
      // The signed-in landing is the SSO home (the launcher); the
      // account console is its entry.
      await page.waitForSelector('[data-testid="home"]', { timeout: SETTLE, polling: 500 })
      expect(new URL(page.url()).pathname).toBe('/op/home')
      await page.goto(`${stack.base}/op/account`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
      await page.waitForSelector('[data-testid="account-name"]', { timeout: SETTLE, polling: 500 })
      expect(new URL(page.url()).pathname).toBe('/op/account')
      expect(await page.$eval('[data-testid="account-password-state"]', el => el.textContent ?? '')).toContain('A password is set')
      // The sessions card marks THIS session.
      await page.waitForSelector('[data-testid="account-session-current"]', { timeout: SETTLE, polling: 500 })
      flog(page, 'leg3: done')
    })
  })

  it('leg 4 — link GitHub from the account page (the real button, the signed state, the stub round trip)', { timeout: 900_000 }, async () => {
    const cookie = await passwordCookie(stack.base, WILLA.email, WILLA.password)
    await withPage(async (page) => {
      await signInViaCookie(page, stack.base, cookie)
      await page.goto(`${stack.base}/op/account`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
      await page.waitForSelector('[data-testid="op-account-link-github-action"]', { timeout: APP_COLD, polling: 500 })
      await interceptStubGitHub(page, GH_WILLA.login)
      try {
        await page.evaluate(() => (document.querySelector('[data-testid="op-account-link-github-action"]') as HTMLElement).click())
        await page.waitForFunction(
          () => window.location.pathname === '/op/account' && window.location.search.includes('linked=github'),
          { timeout: SETTLE, polling: 500 },
        )
        // The URL matches at navigation START — the account page's load
        // (and its subresource requests) still streams through the
        // listener. Tear the interception down only once the page stands:
        // disabling it mid-load strands the queued requests un-continued,
        // and the page then never mounts (the 2026-08-16 CI red: the
        // linked row starved 240 s). account-name is the landed marker
        // (the leg-2/3 idiom).
        await page.waitForSelector('[data-testid="account-name"]', { timeout: SETTLE, polling: 500 })
      } finally {
        await stopIntercepting(page)
      }
      await page.waitForSelector('[data-testid="op-account-link-github"]', { timeout: SETTLE, polling: 500 })
      // The row names the provider and the linked account id (never an email).
      expect(await page.$eval('[data-testid="op-account-link-github"]', el => el.textContent ?? '')).toContain(String(GH_WILLA.id))
      flog(page, 'leg4: linked')
    })
  })

  it('leg 5 — sign in with GitHub (matched by the linked provider_account_id); the sessions card revokes', { timeout: 900_000 }, async () => {
    // A second live session for the account (another browser's sign-in),
    // so the card lists several and the revoke has a target.
    await passwordCookie(stack.base, WILLA.email, WILLA.password)
    await withPage(async (page) => {
      await page.goto(`${stack.base}/`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
      await page.waitForSelector('[data-testid="upstream-login-github"]', { timeout: SETTLE, polling: 500 })
      await interceptStubGitHub(page, GH_WILLA.login)
      try {
        await page.evaluate(() => (document.querySelector('[data-testid="upstream-login-github"]') as HTMLElement).click())
        // The upstream login lands on the role home (/app for a viewer)…
        await page.waitForFunction(() => window.location.pathname !== '/', { timeout: SETTLE, polling: 500 })
        // …and STANDS before the teardown: the URL flips at navigation
        // start while the landing page's subresources still stream through
        // the listener — disabling interception then strands them
        // un-continued (the leg-4 class, the 2026-08-16 CI red).
        await page.waitForFunction(
          () => !!document.querySelector('[data-layout="app"]') && !document.querySelector('.animate-spin'),
          { timeout: SETTLE, polling: 500 },
        )
      } finally {
        await stopIntercepting(page)
      }
      // …and the account page confirms the session is WILLA's.
      await page.goto(`${stack.base}/op/account`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
      await page.waitForSelector('[data-testid="account-name"]', { timeout: SETTLE, polling: 500 })
      expect(await page.$eval('[data-testid="account-name"]', el => el.textContent?.trim())).toBe(WILLA.name)
      flog(page, 'leg5: signed in with GitHub')

      // Several live sessions: revoke a non-current one — it dies; this
      // one stands.
      const sessions = await page.$$eval('[data-testid="account-session-list"] > li', rows => rows.map(r => r.getAttribute('data-testid')!))
      expect(sessions.length).toBeGreaterThanOrEqual(2)
      const rows = await page.$$('[data-testid="account-session-list"] > li')
      let revokedOther = false
      for (const row of rows) {
        const isCurrent = await row.$('[data-testid="account-session-current"]')
        if (!isCurrent) {
          const btn = await row.$('button')
          await btn!.evaluate(b => (b as HTMLElement).click())
          revokedOther = true
          break
        }
      }
      expect(revokedOther, 'a non-current session row to revoke').toBe(true)
      await page.waitForFunction(
        (n) => document.querySelectorAll('[data-testid="account-session-list"] > li').length === n - 1,
        { timeout: 60_000, polling: 500 },
        sessions.length,
      )
      flog(page, 'leg5: revoked')
    })
  })

  it('leg 6 — unlink → the next GitHub sign-in is refused honestly', { timeout: 900_000 }, async () => {
    const cookie = await passwordCookie(stack.base, WILLA.email, WILLA.password)
    await withPage(async (page) => {
      await signInViaCookie(page, stack.base, cookie)
      await page.goto(`${stack.base}/op/account`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
      await page.waitForSelector('[data-testid="op-account-unlink-github"]', { timeout: APP_COLD, polling: 500 })
      await page.evaluate(() => (document.querySelector('[data-testid="op-account-unlink-github"]') as HTMLElement).click())
      await page.waitForSelector('[data-testid="op-account-no-links"]', { timeout: 60_000, polling: 500 })
      flog(page, 'leg6: unlinked')

      // The next GitHub sign-in is refused honestly.
      await browserSignOut(page, stack.base)
      await page.goto(`${stack.base}/`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
      await page.waitForSelector('[data-testid="upstream-login-github"]', { timeout: SETTLE, polling: 500 })
      await interceptStubGitHub(page, GH_WILLA.login)
      try {
        await page.evaluate(() => (document.querySelector('[data-testid="upstream-login-github"]') as HTMLElement).click())
        await page.waitForSelector('[data-testid="login-error"]', { timeout: SETTLE, polling: 500 })
      } finally {
        await stopIntercepting(page)
      }
      const refusal = await page.$eval('[data-testid="login-error"]', el => el.textContent ?? '')
      expect(refusal).toContain('not linked')
      expect(refusal).toContain('administrator')
      expect(new URL(page.url()).pathname).toBe('/')
      flog(page, 'leg6: refused honestly')
    })
  })

  it('leg 7 — the consent round trip: the invited account authorizes the fixture RP (the RP’s real validator)', { timeout: 900_000 }, async () => {
    await withPage(async (page) => {
      // The RP starts the flow: the browser follows its 302 to the OP.
      await page.goto(`${rp.baseUrl}/signin`, { waitUntil: 'domcontentloaded', timeout: SETTLE })

      // The OP's sign-in surface with the flow's re-entry target — the
      // PASSWORD account signs in (the OP form).
      await page.waitForFunction(
        () => window.location.pathname === '/' && window.location.search.includes('redirect='),
        { timeout: SETTLE, polling: 500 },
      )
      await opPasswordSignIn(page, WILLA.email, WILLA.password)

      // The consent page: the client's name, the scopes, the account.
      await page.waitForSelector('[data-testid="op-consent-allow"]', { timeout: SETTLE, polling: 500 })
      expect(new URL(page.url()).pathname).toBe('/op/consent')
      expect(await page.$eval('[data-testid="op-consent-client"]', el => el.textContent?.trim())).toBe('The id-02 fixture RP')
      const account = await page.$eval('[data-testid="op-consent-account"]', el => el.textContent ?? '')
      expect(account).toContain(WILLA.name)
      expect(account).toContain(WILLA.email)

      // Allow → the RP's callback → the RP's signed-in page.
      await page.evaluate(() => (document.querySelector('[data-testid="op-consent-allow"]') as HTMLElement).click())
      await page.waitForSelector('[data-testid="rp-signed-in"]', { timeout: SETTLE, polling: 500 })
      flog(page, 'leg7: the RP is signed in')
    })

    // The RP's REAL validator accepted the OP's ID token — the account
    // is the invited one (its roles ride the client's claims policy).
    const who = await (await fetch(`${rp.baseUrl}/whoami`)).json() as {
      claims: { iss: string; aud: string; email: string; name: string; roles?: string[] }
      userinfo: Record<string, unknown>
      lastError: unknown
    }
    expect(who.claims.iss).toBe(ISSUER)
    expect(who.claims.aud).toBe(RP_CLIENT_ID)
    expect(who.claims.email).toBe(WILLA.email)
    expect(who.claims.name).toBe(WILLA.name)
    expect(who.claims.roles).toEqual(['viewer'])
    expect(who.lastError).toBeNull()
    expect(who.userinfo).toMatchObject({ email: WILLA.email, roles: ['viewer'] })
  })
})
