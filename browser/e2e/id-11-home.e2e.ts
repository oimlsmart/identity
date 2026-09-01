// ═══════════════════════════════════════════════════════════════════
// The SSO home (the post-login launcher) — the e2e. The
// identity-profile stack (the id-03/id-06 spawned-stack pattern: own
// API + own astro + own SQLite) drives the REAL pages against a
// registry that starts EMPTY (no OP_CLIENT_SEED — the bootstrap
// middleware seeds on the first /api/op/* call, so a declared seed
// would make the pristine state unreachable; every client below is
// registered through the admin path itself):
//
//   leg 1  / IS the sign-in page (unchanged); the launcher's honest
//          EMPTY state on the pristine registry (the session rides the
//          demo endpoint directly — the form's OP attempt would seed
//          the registry), captured light + dark;
//   leg 2  the admin's client editor BUILDS the registry: the hub
//          registered through the form (the claims policy's role
//          allowlist, the generated secret shown once, the launch card
//          with the named icon), the launch edit landing (the
//          description change), the inline URL validation refusing a
//          malformed card, and the TL / the assistant / the machine
//          relay registered through the registry API (the editor's own
//          surface); the rows name their launcher postures;
//   leg 3  the populated launcher (the admin): the sign-in lands on
//          /op/home; the hub launches, the TL shows the request posture
//          WITHOUT a working launch (the leak check: no anchor in the
//          card), the assistant is open to every account, the machine
//          client never renders; the account + admin entries; captured
//          light + dark;
//   leg 4  the viewer's launcher: the same computation from her roles,
//          no admin entry; the request-access act flips the card to
//          "requested", survives the reload, and lands
//          account.access_request on the audit chain (the registry's
//          activity feed reads it back);
//   leg 5  a role grant makes the card appear: the invited account's TL
//          card is the request posture; the admin's per-client grant
//          (account.client_roles on the chain) flips it to a working
//          launch — exactly the services her roles admit, never more.
//
// SELF-CONTAINED: own ports (API 9893 / astro 9894 — clear of id-01's
// 8693/8393, id-02's 8793/8593, id-03's 9393/9293, id-06's 9493/9393,
// id-08's 8993/8893, id-10's 9193/9093 and the rest through 9793), own
// SQLite file. THE BROWSER IS PER-LEG (cross-leg state rides the
// DATABASE).
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
const DB_DIR = join(BROWSER_DIR, '.cache', 'id-11')
const SHOTS = join(DB_DIR, 'shots')

const ID_API = 9893
const ID_WEB = 9894

const ISSUER = `http://localhost:${ID_WEB}` // the astro origin (the browser's OP)

const NADIA = { email: 'nadia.launcher@example.org', name: 'Ms. Nadia Launcher', password: 'nadia has a proper passphrase' }

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
  mkdirSync(SHOTS, { recursive: true })
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
    // OIDC_* scrubbed + NO OP_CLIENT_SEED: the client registry starts
    // PRISTINE and every row below lands through the admin path (the
    // launch metadata's honest provenance).
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
    }, logs)
    const apiBase = `http://localhost:${ID_API}`
    await waitForHttp(`${apiBase}/api/health`, 120_000, logs)

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

const SETTLE = 240_000 // spawned astro compiles page chunks cold on first hit
// The FIRST island navigation of a run compiles the shell cold; on a
// contended host that outlives SETTLE (the id-02 lesson).
const APP_COLD = 840_000

const PROGRESS_LOG = join(DB_DIR, 'progress.log')
function flog(page: Page | null, msg: string): void {
  const url = page && !page.isClosed() ? page.url() : '(no page)'
  const line = `${new Date().toISOString()} ${msg} @ ${url}\n`
  try { appendFileSync(PROGRESS_LOG, line) } catch { /* the log never breaks the leg */ }
}

/** A fresh browser at the docs-rule viewport (1440x900), the house
 *  posture: the headless SHELL (a long-lived full renderer wedges
 *  silently under load — the id-02 lesson) with the protocol timeout
 *  that carries a contended host. The theme is DECLARED per capture
 *  (the shell's inline script falls back to the host's
 *  prefers-color-scheme — a dark-mode host would render every "light"
 *  capture dark). */
async function newBrowser(dark = false): Promise<{ browser: Browser; page: Page }> {
  const browser = await puppeteer.launch({ headless: 'shell', protocolTimeout: 480_000, args: ['--no-sandbox', '--disable-setuid-sandbox'] })
  const page = await browser.newPage()
  await page.setViewport({ width: 1440, height: 900 })
  await page.evaluateOnNewDocument((mode: string) => { try { localStorage.setItem('oiml-theme', mode) } catch { /* private mode */ } }, dark ? 'dark' : 'light')
  return { browser, page }
}

/** The capture discipline (id-06): the astro dev toolbar never enters a
 *  screenshot. */
async function hideDevToolbar(page: Page): Promise<void> {
  await page.addStyleTag({ content: 'astro-dev-toolbar { display: none !important }' }).catch(() => {})
}

/** The password sign-in through the REAL form (the OP account path, or
 *  the demo fallback); lands on the launcher (the post-login landing). */
async function signIn(page: Page, base: string, email: string, password: string): Promise<void> {
  await page.goto(`${base}/`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
  await page.waitForSelector('[data-testid="login-email"]', { timeout: SETTLE, polling: 500 })
  await page.type('[data-testid="login-email"]', email)
  await page.type('[data-testid="login-password"]', password)
  await page.evaluate(() => (document.querySelector('[data-testid="login-submit"]') as HTMLElement).click())
  await page.waitForSelector('[data-testid="home"]', { timeout: APP_COLD, polling: 500 })
}

/** The launcher, loaded and settled (the feed's islands answered). */
async function gotoHome(page: Page, base: string): Promise<void> {
  await page.goto(`${base}/op/home`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
  await page.waitForSelector('[data-testid="home-empty"], [data-testid="home-services"]', { timeout: APP_COLD, polling: 500 })
}

/** A signed-in API cookie, node-side (the demo cast). */
async function demoCookie(apiBase: string, email: string): Promise<string> {
  const res = await fetch(`${apiBase}/api/auth/demo`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password: 'demo2026' }),
  })
  expect(res.ok, `demo login ${email}`).toBe(true)
  return res.headers.get('set-cookie')!.split(';')[0]!
}

/** The registry write, node-side as the admin (the editor's own
 *  endpoint — the form drives one full registration for the proof, the
 *  siblings ride the same surface directly). */
async function registerClient(apiBase: string, adminCookie: string, body: Record<string, unknown>, status = 201): Promise<any> {
  const res = await fetch(`${apiBase}/api/op/clients`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', cookie: adminCookie },
    body: JSON.stringify(body),
  })
  expect(res.status, `register ${body.client_id}`).toBe(status)
  return res.json()
}

/** The page's field driver: clear, then type (a stale value survives a
 *  bare type). */
async function fillField(page: Page, testid: string, value: string): Promise<void> {
  await page.$eval(`[data-testid="${testid}"]`, el => { (el as HTMLInputElement | HTMLTextAreaElement).value = '' })
  if (value) await page.type(`[data-testid="${testid}"]`, value)
}

/** Click by testid (the evaluate click never misses the island's
 *  hydration state). */
async function clickTid(page: Page, testid: string): Promise<void> {
  await page.evaluate((tid) => (document.querySelector(`[data-testid="${tid}"]`) as HTMLElement).click(), testid)
}

let stack: Stack | undefined

beforeAll(async () => {
  stack = await bootIdentityStack()
}, 420_000)

afterAll(async () => {
  await stopStack(stack)
}, 60_000)

describe('the SSO home', () => {
  it('leg 1: / stays the sign-in page; the pristine registry renders the honest empty launcher (light + dark)', async () => {
    const { browser, page } = await newBrowser()
    try {
      flog(page, 'leg 1: the sign-in page + the empty launcher')
      await page.goto(`${stack!.base}/`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
      await page.waitForSelector('[data-testid="login-email"]', { timeout: SETTLE, polling: 500 })
      // / IS the sign-in page (the wave-02a posture, unchanged): the
      // form renders, no redirect away.
      expect(await page.$('[data-testid="login-submit"]')).toBeTruthy()
      expect(new URL(page.url()).pathname).toBe('/')

      // The launcher's empty state on the pristine registry. The session
      // rides the DEMO endpoint directly: the form's OP password attempt
      // (/api/op/login) would seed the client registry (op-accounts'
      // bootstrap middleware) and the pristine state would be gone.
      const cookie = await demoCookie(stack!.apiBase, 'viewer@oiml.org')
      const viewerToken = cookie.split('=')[1]!
      await page.setCookie({ name: 'oiml-session', value: viewerToken, url: stack!.base })
      await gotoHome(page, stack!.base)
      await page.waitForSelector('[data-testid="home-empty"]', { timeout: SETTLE, polling: 500 })
      await hideDevToolbar(page)
      await page.screenshot({ path: join(SHOTS, 'home-empty-light.png') })

      const dark = await newBrowser(true)
      try {
        await dark.page.setCookie({ name: 'oiml-session', value: viewerToken, url: stack!.base })
        await gotoHome(dark.page, stack!.base)
        await dark.page.waitForSelector('[data-testid="home-empty"]', { timeout: SETTLE, polling: 500 })
        await hideDevToolbar(dark.page)
        await dark.page.screenshot({ path: join(SHOTS, 'home-empty-dark.png') })
      } finally {
        await closeBrowser(dark.browser)
      }
    } finally {
      await closeBrowser(browser)
    }
  }, 1_200_000)

  it('leg 2: the client editor builds the registry (the form, the edit, the inline refusal)', async () => {
    const { browser, page } = await newBrowser()
    try {
      flog(page, 'leg 2: the client editor')
      await signIn(page, stack!.base, 'admin@oiml.org', 'demo2026')
      // The post-login landing IS the launcher.
      expect(new URL(page.url()).pathname).toBe('/op/home')
      await page.goto(`${stack!.base}/op/admin/clients`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
      await page.waitForSelector('[data-testid="op-clients"]', { timeout: APP_COLD, polling: 500 })
      // The pristine registry says so honestly.
      expect(await page.$('[data-testid="op-clients-empty"]')).toBeTruthy()

      // The hub, through the form: the claims policy with its role
      // allowlist, the generated secret shown once, the launch card.
      await fillField(page, 'op-client-field-id', 'hub-instance')
      await fillField(page, 'op-client-field-name', 'OIML SMART platform hub')
      await fillField(page, 'op-client-field-uris', 'https://platform.oimlsmart.org/api/auth/callback/oidc')
      await clickTid(page, 'op-client-claim-roles')
      await clickTid(page, 'op-client-claim-groups')
      await clickTid(page, 'op-client-claim-org')
      await page.waitForSelector('[data-testid="op-client-field-role-allowlist"]', { timeout: SETTLE, polling: 500 })
      for (const role of ['admin', 'cs_admin', 'ia_officer', 'viewer']) await clickTid(page, `op-client-role-${role}`)
      await clickTid(page, 'op-client-field-launch-on')
      await page.waitForSelector('[data-testid="op-client-field-launch"]', { timeout: SETTLE, polling: 500 })
      await fillField(page, 'op-client-field-launch-url', 'https://platform.oimlsmart.org/api/auth/signin/oidc')
      await fillField(page, 'op-client-field-launch-description', 'The certification hub: applications, cases, certificates.')
      await page.select('[data-testid="op-client-field-launch-icon"]', 'grid')
      await page.select('[data-testid="op-client-field-launch-visibility"]', 'roles')
      await clickTid(page, 'op-client-save')
      await page.waitForSelector('[data-testid="op-client-secret-card"]', { timeout: SETTLE, polling: 500 })
      const posture = await page.$eval('[data-testid="op-client-launch-hub-instance"]', el => el.textContent ?? '')
      expect(posture).toContain('on the SSO home (roles)')

      // The edit: the description changes, the card rides along (the
      // form was filled from the row).
      await clickTid(page, 'op-client-edit-hub-instance')
      await page.waitForSelector('[data-testid="op-client-field-launch-url"]', { timeout: SETTLE, polling: 500 })
      const urlValue = await page.$eval('[data-testid="op-client-field-launch-url"]', el => (el as HTMLInputElement).value)
      expect(urlValue).toBe('https://platform.oimlsmart.org/api/auth/signin/oidc')
      await fillField(page, 'op-client-field-launch-description', 'The certification hub, edited.')
      await clickTid(page, 'op-client-save')
      await page.waitForSelector('[data-testid="op-clients-notice"]', { timeout: SETTLE, polling: 500 })

      // The inline refusal: a malformed launch URL never reaches the
      // server.
      await clickTid(page, 'op-client-field-launch-on')
      await fillField(page, 'op-client-field-launch-url', 'not-a-url')
      await clickTid(page, 'op-client-save')
      await page.waitForSelector('[data-testid="op-client-launch-problems"]', { timeout: SETTLE, polling: 500 })

      // The siblings ride the registry API (the editor's own surface):
      // the TL (the request-access posture), the assistant (open to
      // every signed-in account), the machine relay (no card).
      const adminCookie = await demoCookie(stack!.apiBase, 'admin@oiml.org')
      const hub = (await (await fetch(`${stack!.apiBase}/api/op/clients`, { headers: { cookie: adminCookie } })).json() as Array<{ clientId: string; launch: { description: string | null } | null }>)
        .find(c => c.clientId === 'hub-instance')
      expect(hub?.launch?.description).toBe('The certification hub, edited.')
      await registerClient(stack!.apiBase, adminCookie, {
        client_id: 'tl-instance',
        name: 'Example TL instance',
        secret: 'tl-secret-456',
        redirect_uris: ['https://tl.oimlsmart.org/api/auth/callback/oidc'],
        claims_policy: { claims: ['roles', 'groups'], roles: ['tl_operator'] },
        launch: { url: 'https://tl.oimlsmart.org/api/auth/signin/oidc', icon: 'flask', description: 'The test laboratory console.', visibility: 'request' },
      })
      await registerClient(stack!.apiBase, adminCookie, {
        client_id: 'pubs-assistant',
        name: 'OIML SMART AI',
        redirect_uris: ['https://ai.oimlsmart.org/auth/callback'],
        launch: { url: 'https://ai.oimlsmart.org/auth/login', icon: 'chat', description: 'Ask the OIML library.', visibility: 'open' },
      })
      await registerClient(stack!.apiBase, adminCookie, {
        client_id: 'machine-relay',
        name: 'A machine-only relay',
        redirect_uris: ['https://relay.example/callback'],
      })

      // The console reads them back with their postures.
      await page.goto(`${stack!.base}/op/admin/clients`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
      await page.waitForSelector('[data-testid="op-client-tl-instance"]', { timeout: APP_COLD, polling: 500 })
      expect(await page.$eval('[data-testid="op-client-launch-tl-instance"]', el => el.textContent ?? '')).toContain('on the SSO home (request)')
      expect(await page.$eval('[data-testid="op-client-launch-pubs-assistant"]', el => el.textContent ?? '')).toContain('on the SSO home (open)')
      expect(await page.$eval('[data-testid="op-client-launch-machine-relay"]', el => el.textContent ?? '')).toContain('not on the SSO home')
    } finally {
      await closeBrowser(browser)
    }
  }, 1_200_000)

  it('leg 3: the populated launcher computes the admin’s visibility (light + dark)', async () => {
    const { browser, page } = await newBrowser()
    try {
      flog(page, 'leg 3: the populated launcher')
      await signIn(page, stack!.base, 'admin@oiml.org', 'demo2026')
      await gotoHome(page, stack!.base)

      // The hub launches; the TL shows the request posture WITHOUT a
      // working launch; the assistant is open; the machine relay never
      // renders.
      const hubHref = await page.$eval('[data-testid="home-card-hub-instance"]', el => (el as HTMLAnchorElement).href)
      expect(hubHref).toBe('https://platform.oimlsmart.org/api/auth/signin/oidc')
      const tlCard = await page.$('[data-testid="home-card-tl-instance"]')
      expect(tlCard, 'the TL card renders').toBeTruthy()
      expect(await tlCard!.evaluate(el => el.tagName), 'the request-state card is not an anchor').toBe('DIV')
      expect(await page.$$('[data-testid="home-card-tl-instance"] a[href]'), 'the request-state card carries no working launch').toHaveLength(0)
      const assistantHref = await page.$eval('[data-testid="home-card-pubs-assistant"]', el => (el as HTMLAnchorElement).href)
      expect(assistantHref).toBe('https://ai.oimlsmart.org/auth/login')
      expect(await page.$('[data-testid="home-card-machine-relay"]')).toBeNull()
      // The account menu entry + (the admin) the admin area entry. The
      // admin card links the canonical destination DIRECTLY — /op/admin
      // stays the redirect fallback for stray URLs, never the card's hop.
      expect(await page.$('[data-testid="home-account"]')).toBeTruthy()
      const adminCard = await page.$('[data-testid="home-admin"]')
      expect(adminCard).toBeTruthy()
      expect(await adminCard!.evaluate(el => (el as HTMLAnchorElement).getAttribute('href'))).toBe('/op/admin/overview')
      await hideDevToolbar(page)
      await page.screenshot({ path: join(SHOTS, 'home-populated-light.png') })

      const dark = await newBrowser(true)
      try {
        await signIn(dark.page, stack!.base, 'admin@oiml.org', 'demo2026')
        await gotoHome(dark.page, stack!.base)
        await hideDevToolbar(dark.page)
        await dark.page.screenshot({ path: join(SHOTS, 'home-populated-dark.png') })
      } finally {
        await closeBrowser(dark.browser)
      }
    } finally {
      await closeBrowser(browser)
    }
  }, 1_200_000)

  it('leg 4: the viewer’s request-access act lands on the audit chain', async () => {
    const { browser, page } = await newBrowser()
    try {
      flog(page, 'leg 4: the request act')
      await signIn(page, stack!.base, 'viewer@oiml.org', 'demo2026')
      await gotoHome(page, stack!.base)
      // The viewer: the hub launches (viewer ∈ its allowlist), the admin
      // entry never renders.
      expect(await page.$('[data-testid="home-card-hub-instance"]')).toBeTruthy()
      expect(await page.$('[data-testid="home-admin"]')).toBeNull()

      await clickTid(page, 'home-request-tl-instance')
      // The notice is the sync point (the same flush flips the button's
      // state); a $eval reads the button after it.
      await page.waitForSelector('[data-testid="home-request-notice"]', { timeout: SETTLE, polling: 500 })
      const flipped = await page.$eval('[data-testid="home-request-tl-instance"]', el => el.textContent ?? '')
      expect(flipped).toContain('Access requested')
      // The state survives a reload (the feed reads the journal back).
      await gotoHome(page, stack!.base)
      const requested = await page.$eval('[data-testid="home-request-tl-instance"]', el => el.textContent ?? '')
      expect(requested).toContain('Access requested')

      // The audit chain carries it (the registry's activity feed shape).
      const adminCookie = await demoCookie(stack!.apiBase, 'admin@oiml.org')
      const activity = await (await fetch(`${stack!.apiBase}/api/op/registry/activity?q=access_request`, { headers: { cookie: adminCookie } })).json() as Array<{ action: string; metadata?: { clientId?: string } }>
      expect(activity.some(e => e.action === 'account.access_request' && e.metadata?.clientId === 'tl-instance')).toBe(true)
    } finally {
      await closeBrowser(browser)
    }
  }, 1_200_000)

  it('leg 5: a role grant makes the card appear (the audit event carries it)', async () => {
    const adminCookie = await demoCookie(stack!.apiBase, 'admin@oiml.org')
    // The invited OP account (the grant surface manages the registry's
    // own accounts — the demo cast is not assignable).
    const invite = await fetch(`${stack!.apiBase}/api/op/accounts`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: adminCookie },
      body: JSON.stringify({ email: NADIA.email, name: NADIA.name }),
    })
    expect(invite.status).toBe(201)
    const { account, setupUrl } = await invite.json() as { account: { id: string }; setupUrl: string }
    const enroll = await fetch(`${stack!.apiBase}/api/op/enroll/${new URL(setupUrl).searchParams.get('token')}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ password: NADIA.password }),
    })
    expect(enroll.status).toBe(200)

    const { browser, page } = await newBrowser()
    try {
      flog(page, 'leg 5: the grant')
      // Before the grant: the TL card is the request posture.
      await signIn(page, stack!.base, NADIA.email, NADIA.password)
      await gotoHome(page, stack!.base)
      const before = await page.$('[data-testid="home-card-tl-instance"]')
      expect(await before!.evaluate(el => el.tagName)).toBe('DIV')

      // The grant (the admin's registry act).
      const grant = await fetch(`${stack!.apiBase}/api/op/accounts/${account.id}/client-roles/tl-instance`, {
        method: 'PUT',
        headers: { 'content-type': 'application/json', cookie: adminCookie },
        body: JSON.stringify({ roles: ['tl_operator'] }),
      })
      expect(grant.status).toBe(200)

      // The card flips to a working launch.
      await gotoHome(page, stack!.base)
      const href = await page.$eval('[data-testid="home-card-tl-instance"]', el => (el as HTMLAnchorElement).href)
      expect(href).toBe('https://tl.oimlsmart.org/api/auth/signin/oidc')

      // The audit event carries the grant.
      const activity = await (await fetch(`${stack!.apiBase}/api/op/registry/activity?q=client_roles`, { headers: { cookie: adminCookie } })).json() as Array<{ action: string; entity_id: string; metadata?: { client_id?: string } }>
      expect(activity.some(e => e.action === 'account.client_roles' && e.entity_id === account.id && e.metadata?.client_id === 'tl-instance')).toBe(true)
    } finally {
      await closeBrowser(browser)
    }
  }, 1_200_000)
})
