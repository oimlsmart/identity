// ═══════════════════════════════════════════════════════════════════
// TODO.identity/10 — delegated organization administration, the e2e:
// the identity-profile stack (its own API + its own astro, the id-01/
// id-08 spawned-stack pattern), the whole flow in the browser:
//
//   leg 1  the OP's login page links to "Request an account"; the join
//          page's organization selector is fed from the participants
//          register (a REGISTERED Utilizer is offered; the mid-pipeline
//          IA is NOT — only registered orgs are selectable);
//   leg 2  BIML creates the org admin for the registered Utilizer
//          through the console (the eligibility rule's UI: the selector
//          offers registered orgs only);
//   leg 3  the reviewer requests an account — picking THEIR org from
//          the register, asking for the viewer role (the kind-bounded
//          option set); the success copy names the org's administrator;
//   leg 4  the org admin signs in, works the queue (the email-domain
//          hint shows), APPROVES — the invite is issued — and the
//          people slice shows ONLY the org's accounts (never the demo
//          cast, never another org);
//   leg 5  the colleague (the approved reviewer) signs in with the
//          local password: the session carries the org binding, and
//          the org console honestly refuses them (they are staff, not
//          the administrator) — the slice is the org's, and only the
//          org's admin sees it;
//   leg 6  a request naming a FAKE organization (the not-listed path)
//          lands in BIML's new-organizations queue, and BIML refuses it
//          with the participation pointer.
//
// SELF-CONTAINED: the suite's shared stack (E2E_BASE_URL) is untouched —
// the identity instance boots on its own ports (API 9193 / astro 9093)
// with its own SQLite file.
// ═══════════════════════════════════════════════════════════════════

import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import puppeteer, { type Browser, type Page } from 'puppeteer'
import { spawn, type ChildProcess } from 'node:child_process'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { existsSync, mkdirSync, rmSync, cpSync } from 'node:fs'
import { closeBrowser, delay } from './helpers'
import { fixtureOpSigningKey } from './fixtures/op-signing-key'

const BROWSER_DIR = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const FIXTURES = join(BROWSER_DIR, 'e2e', 'fixtures')
const DB_DIR = join(BROWSER_DIR, '.cache', 'id-10')

// Port-isolated: clear of the shared dev stack (5190/3190), the fed-01
// stacks (8291/8292/8491/8492), the id-01 stack (8693/8393/8694), the
// fed-10 stub (8699), the local identity dev stack (7390/7190), the
// id-02 stack (8793/8593/8794), the id-08 stack (8993/8893/8994) and the
// local id-10 dev loop (6390/6290).
const ID_API = 9193
const ID_WEB = 9093

// The cast this item adds on top of the demo accounts: the Utilizer's
// org admin (BIML creates it in leg 2 — a real OP password account, the
// 02 enrollment seam) and the reviewer (leg 3's join request, approved
// in leg 4). Both complete their one-time setup link in the browser.
const UTILIZER_ID = 'ut-nmi-nl'
const UTILIZER_NAME = 'Example Metrology Authority (Netherlands)'
const ORG_ADMIN_EMAIL = 'sanne.devries@nmi.example.org'
const ORG_ADMIN_PASSWORD = 'sanne de vries admin passphrase'
const REVIEWER_EMAIL = 'willem.jansen@nmi.example.org'
const REVIEWER_PASSWORD = 'willem jansen reviewer passphrase'
const FAKE_ORG_NAME = 'Metrology Institute of Nowhere'
const FAKE_ORG_EMAIL = 'contact@nowhere.example.org'

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
 *  the OP env, the profile seed through the dev-reset seam (the demo
 *  cast + the participants register — the selector's source), astro dev
 *  against it. */
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
    // must not inherit it (the id-08 discipline).
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

    // Provision the profile's seed (the demo cast + the registry).
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

/** Sign in through the demo cast (DEMO_ACCOUNTS_ENABLED=true — the OP
 *  login form falls back to the demo endpoint on a 401, 02's posture). */
async function opSignIn(page: Page, email: string): Promise<void> {
  await page.waitForSelector('[data-testid="login-email"]', { timeout: SETTLE, polling: 500 })
  await page.evaluate(() => {
    (document.querySelector('[data-testid="login-email"]') as HTMLInputElement).value = ''
  })
  await page.type('[data-testid="login-email"]', email)
  await page.type('[data-testid="login-password"]', 'demo2026')
  await page.evaluate(() => (document.querySelector('[data-testid="login-submit"]') as HTMLElement).click())
}

/** Sign in an OP PASSWORD account (02's accounts) through the login form. */
async function opPasswordSignIn(page: Page, email: string, password: string): Promise<void> {
  await page.waitForSelector('[data-testid="login-email"]', { timeout: SETTLE, polling: 500 })
  await page.evaluate(() => {
    (document.querySelector('[data-testid="login-email"]') as HTMLInputElement).value = ''
  })
  await page.type('[data-testid="login-email"]', email)
  await page.type('[data-testid="login-password"]', password)
  await page.evaluate(() => (document.querySelector('[data-testid="login-submit"]') as HTMLElement).click())
}

/** The console's one-time setup link for the last issued invite (the
 *  out-of-band handover — shown once on the approval/invite). */
async function readSetupUrl(page: Page): Promise<string> {
  await page.waitForSelector('[data-testid="invite-setup-url"]', { timeout: SETTLE, polling: 500 })
  return (await page.$eval('[data-testid="invite-setup-url"]', el => el.textContent ?? '')).trim()
}

/** Drive 02's setup page: the one-time link sets the password and signs
 *  the account in (lands on /op/account). */
async function driveSetup(page: Page, setupUrl: string, password: string, expectEmail: string): Promise<void> {
  await page.goto(setupUrl, { waitUntil: 'domcontentloaded', timeout: SETTLE })
  await page.waitForSelector('[data-testid="op-setup-account"]', { timeout: SETTLE, polling: 500 })
  const who = await page.$eval('[data-testid="op-setup-account"]', el => el.textContent ?? '')
  expect(who).toContain(expectEmail)
  await page.type('[data-testid="op-setup-password"]', password)
  await page.type('[data-testid="op-setup-confirm"]', password)
  await page.evaluate(() => (document.querySelector('[data-testid="op-setup-submit"]') as HTMLElement).click())
  await page.waitForFunction(() => window.location.pathname === '/op/account', { timeout: SETTLE, polling: 500 })
}

/** The signed-in session's payload (null when signed out). */
async function sessionPayload(page: Page): Promise<{ email: string; orgId: string | null; roles?: string[] } | null> {
  return page.evaluate(async () => {
    const res = await fetch('/api/auth/session', { credentials: 'include' })
    if (!res.ok) return null
    return res.json() as Promise<{ email: string; orgId: string | null; roles?: string[] }>
  })
}

/** Drop the session (the cookie is httpOnly — the browser-side delete),
 *  then settle the browser on the sign-in page: the console page the
 *  browser is leaving can self-redirect when the session dies (the 401
 *  posture), and a caller's next goto then races that navigation (the
 *  main-CI id-10 leg-3 ERR_ABORTED, 2026-08-24). The settle carries one
 *  retry on exactly that signature. */
async function signOut(page: Page): Promise<void> {
  await page.evaluate(async () => {
    await fetch('/api/auth/signout', { method: 'POST', credentials: 'include' })
  })
  const origin = new URL(page.url()).origin
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      await page.goto(`${origin}/`, { waitUntil: 'domcontentloaded', timeout: 60_000 })
      return
    } catch (e) {
      const msg = String(e)
      if (attempt === 1 || !(msg.includes('ERR_ABORTED') || msg.includes('Execution context was destroyed'))) throw e
      await delay(600)
    }
  }
}

/** The join-request row id for an email on the CURRENT page (the
 *  console's queue), null when absent. */
async function requestIdFor(page: Page, email: string): Promise<string | null> {
  return page.evaluate((needle) => {
    const el = [...document.querySelectorAll('[data-testid^="join-request-"]')]
      .find(e => e.textContent?.includes(needle))
    return el?.getAttribute('data-testid')?.replace('join-request-', '') ?? null
  }, email)
}

describe('TODO.identity/10 — delegated organization administration (the identity profile)', () => {
  let stack: Stack
  let browser: Browser
  let page: Page
  /** The reviewer's one-time setup link, captured at leg 4's approval. */
  let reviewerSetupUrl = ''

  beforeAll(async () => {
    stack = await bootIdentityStack()
    browser = await puppeteer.launch({ headless: 'shell', protocolTimeout: 480_000, args: ['--no-sandbox', '--disable-setuid-sandbox'] })
    page = await browser.newPage()
    await page.setViewport({ width: 1440, height: 900 })
    page.on('pageerror', e => console.log('[pageerror]', String(e).slice(0, 300)))
    page.on('requestfailed', r => console.log('[requestfailed]', r.url().slice(0, 140), r.failure()?.errorText ?? ''))
  }, 600_000)

  afterAll(async () => {
    await closeBrowser(browser)
    await stopStack(stack)
  })

  it('leg 1 — the login page links to the join page; the selector is fed from the register (registered only)', { timeout: 600_000 }, async () => {
    await page.goto(`${stack.base}/`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await page.waitForSelector('[data-testid="login-join-link"]', { timeout: SETTLE, polling: 500 })

    await page.goto(`${stack.base}/op/join`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await page.waitForSelector('[data-testid="op-join"]', { timeout: SETTLE, polling: 500 })
    // The register's orgs render: the Utilizer (signed Declaration) and
    // the IA are offered; the mid-pipeline IA (XX1, draft Declaration)
    // is NOT — only registered orgs are selectable.
    await page.waitForSelector(`[data-testid="join-org-option-${UTILIZER_ID}"]`, { timeout: SETTLE, polling: 500 })
    await page.waitForSelector('[data-testid="join-org-option-EX1"]', { timeout: SETTLE, polling: 500 })
    expect(await page.$('[data-testid="join-org-option-XX1"]')).toBeNull()
    // The search narrows the list.
    await page.type('[data-testid="join-org-search"]', 'Netherlands')
    await page.waitForFunction(() => {
      const list = document.querySelector('[data-testid="join-org-options"]')
      return list && list.textContent?.includes('Netherlands') && !list.textContent?.includes('Issuing Authority')
    }, { timeout: SETTLE, polling: 500 })
  })

  it('leg 2 — BIML creates the org admin for the registered Utilizer (the enrollment link sets her password)', { timeout: 900_000 }, async () => {
    await page.goto(`${stack.base}/`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await opSignIn(page, 'admin@oiml.org')
    await page.waitForFunction(() => window.location.pathname !== '/', { timeout: SETTLE, polling: 500 })

    await page.goto(`${stack.base}/op/admin/users`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await page.waitForSelector('[data-testid="biml-org-admins"]', { timeout: SETTLE, polling: 500 })
    await page.type('[data-testid="orgadmin-name"]', 'Ms. Sanne de Vries')
    await page.type('[data-testid="orgadmin-email"]', ORG_ADMIN_EMAIL)
    await page.select('[data-testid="orgadmin-org"]', UTILIZER_ID)
    await page.evaluate(() => (document.querySelector('[data-testid="orgadmin-submit"]') as HTMLElement).click())
    await page.waitForSelector('[data-testid="op-admin-notice"]', { timeout: SETTLE, polling: 500 })
    const notice = await page.$eval('[data-testid="op-admin-notice"]', el => el.textContent ?? '')
    expect(notice).toContain('Sanne de Vries')
    expect(notice).toContain(UTILIZER_NAME)

    // The invite is 02's one-time setup link — the admin copies it (the
    // out-of-band handover); Sanne sets her password through it and is
    // signed straight in.
    const setupUrl = await readSetupUrl(page)
    expect(setupUrl).toContain('/op/setup?token=')
    await signOut(page)
    await driveSetup(page, setupUrl, ORG_ADMIN_PASSWORD, ORG_ADMIN_EMAIL)
    expect((await sessionPayload(page))?.email).toBe(ORG_ADMIN_EMAIL)
  })

  it('leg 3 — the reviewer requests an account, picking THEIR org from the register', { timeout: 900_000 }, async () => {
    await signOut(page)
    await page.goto(`${stack.base}/op/join`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await page.waitForSelector('[data-testid="join-name"]', { timeout: SETTLE, polling: 500 })
    await page.type('[data-testid="join-name"]', 'Mr. Willem Jansen')
    await page.type('[data-testid="join-email"]', REVIEWER_EMAIL)
    await page.evaluate(() => {
      (document.querySelector('[data-testid="join-org-search"]') as HTMLInputElement).value = ''
    })
    await page.evaluate((id) => {
      (document.querySelector(`[data-testid="join-org-option-${id}"]`) as HTMLElement).click()
    }, UTILIZER_ID)
    // The role options are bounded by the org's kind — a Utilizer's staff
    // asks for the viewer role. TODO.adoption/10 added scheme_participant
    // to the acceptance-participant kinds (the ANR-declaring staffer,
    // TODO.adoption/11); the reviewer still asks for viewer.
    await page.waitForSelector('[data-testid="join-role"]', { timeout: SETTLE, polling: 500 })
    const options = await page.$$eval('[data-testid="join-role"] option', els => els.map(e => (e as HTMLOptionElement).value))
    expect(options.filter(Boolean)).toEqual(['viewer', 'scheme_participant'])
    await page.select('[data-testid="join-role"]', 'viewer')
    await page.type('[data-testid="join-note"]', 'I review R 60 certificates for the NL office.')
    await page.evaluate(() => (document.querySelector('[data-testid="join-submit"]') as HTMLElement).click())
    await page.waitForSelector('[data-testid="join-success"]', { timeout: SETTLE, polling: 500 })
    const success = await page.$eval('[data-testid="join-success"]', el => el.textContent ?? '')
    expect(success).toContain(UTILIZER_NAME)
    expect(success).toContain('administrator')
  })

  it('leg 4 — the org admin approves: the invite is issued; the people slice shows ONLY the org', { timeout: 900_000 }, async () => {
    await signOut(page)
    await page.goto(`${stack.base}/`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await opPasswordSignIn(page, ORG_ADMIN_EMAIL, ORG_ADMIN_PASSWORD)
    await page.waitForFunction(() => window.location.pathname !== '/', { timeout: SETTLE, polling: 500 })
    await page.goto(`${stack.base}/op/admin/users`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await page.waitForSelector('[data-testid="org-queue"]', { timeout: SETTLE, polling: 500 })

    // The queue carries the reviewer's request with the domain hint.
    const requestId = await requestIdFor(page, REVIEWER_EMAIL)
    expect(requestId).toBeTruthy()
    const rowText = await page.$eval(`[data-testid="join-request-${requestId}"]`, el => el.textContent ?? '')
    expect(rowText).toContain('viewer')
    expect(rowText).toContain('email domain matches the register')

    // Approve → the invite notice + the one-time setup link.
    await page.evaluate((id) => {
      (document.querySelector(`[data-testid="join-approve-${id}"]`) as HTMLElement).click()
    }, requestId)
    await page.waitForSelector('[data-testid="op-admin-notice"]', { timeout: SETTLE, polling: 500 })
    const notice = await page.$eval('[data-testid="op-admin-notice"]', el => el.textContent ?? '')
    expect(notice).toContain('Willem Jansen')
    expect(notice).toContain('Invite issued')
    reviewerSetupUrl = await readSetupUrl(page)
    expect(reviewerSetupUrl).toContain('/op/setup?token=')

    // The people slice: exactly the org's two accounts — the demo cast
    // and every other org stay invisible.
    await page.waitForFunction(() => {
      const list = document.querySelector('[data-testid="org-users-list"]')
      return list && list.textContent?.includes('Willem Jansen')
    }, { timeout: SETTLE, polling: 500 })
    const slice = await page.$eval('[data-testid="org-users-list"]', el => el.textContent ?? '')
    expect(slice).toContain('Sanne de Vries')
    expect(slice).toContain('Willem Jansen')
    expect(slice).not.toContain('OIML Admin')
    expect(slice).not.toContain('IA Officer')
    // The queue is decided (the pending section is empty again).
    await page.waitForSelector('[data-testid="org-queue-empty"]', { timeout: SETTLE, polling: 500 })
  })

  it('leg 5 — the colleague sets her password from the invite link and signs in: the org binding is theirs; the console honestly refuses them', { timeout: 900_000 }, async () => {
    await signOut(page)
    // The one-time setup link (the approval's handover) sets the
    // password and signs the account in.
    expect(reviewerSetupUrl).toContain('/op/setup?token=')
    await driveSetup(page, reviewerSetupUrl, REVIEWER_PASSWORD, REVIEWER_EMAIL)

    // The session carries the org binding (the approved request's org).
    const session = await sessionPayload(page)
    expect(session?.email).toBe(REVIEWER_EMAIL)
    expect(session?.orgId).toBe(UTILIZER_ID)

    // The colleague is STAFF, not the administrator: the org console
    // names its audience instead of serving a slice.
    await page.goto(`${stack.base}/op/admin/users`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await page.waitForSelector('[data-testid="op-admin-error"]', { timeout: SETTLE, polling: 500 })
    const refusal = await page.$eval('[data-testid="op-admin-error"]', el => el.textContent ?? '')
    expect(refusal).toContain('organization administrators')
    expect(await page.$('[data-testid="org-users-list"]')).toBeNull()

    // And the USED link answers its honest card (one-time means one-time).
    await signOut(page)
    await page.goto(reviewerSetupUrl, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await page.waitForSelector('[data-testid="op-setup-used"]', { timeout: SETTLE, polling: 500 })
  })

  it('leg 6 — a fake-organization request lands in BIML’s queue and is refused with the pointer', { timeout: 900_000 }, async () => {
    // The not-listed path on the public join page.
    await page.goto(`${stack.base}/op/join`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await page.waitForSelector('[data-testid="join-name"]', { timeout: SETTLE, polling: 500 })
    await page.type('[data-testid="join-name"]', 'Ms. Nobody Real')
    await page.type('[data-testid="join-email"]', FAKE_ORG_EMAIL)
    await page.evaluate(() => (document.querySelector('[data-testid="join-not-listed"]') as HTMLElement).click())
    await page.waitForSelector('[data-testid="join-org-name-text"]', { timeout: SETTLE, polling: 500 })
    await page.type('[data-testid="join-org-name-text"]', FAKE_ORG_NAME)
    await page.evaluate(() => (document.querySelector('[data-testid="join-submit"]') as HTMLElement).click())
    await page.waitForSelector('[data-testid="join-success"]', { timeout: SETTLE, polling: 500 })
    const success = await page.$eval('[data-testid="join-success"]', el => el.textContent ?? '')
    expect(success).toContain(FAKE_ORG_NAME)
    expect(success).toContain('BIML')

    // BIML's new-organizations queue carries it — never the org's queue.
    await signOut(page)
    await page.goto(`${stack.base}/`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await opSignIn(page, 'admin@oiml.org')
    await page.waitForFunction(() => window.location.pathname !== '/', { timeout: SETTLE, polling: 500 })
    await page.goto(`${stack.base}/op/admin/users`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await page.waitForSelector('[data-testid="biml-orgs-queue"]', { timeout: SETTLE, polling: 500 })
    const requestId = await requestIdFor(page, FAKE_ORG_EMAIL)
    expect(requestId).toBeTruthy()
    const orgName = await page.$eval(`[data-testid="join-request-orgname-${requestId}"]`, el => el.textContent ?? '')
    expect(orgName).toBe(FAKE_ORG_NAME)

    // Refuse with the participation pointer (a reasonless refusal is
    // blocked by the required reason).
    await page.evaluate((id) => {
      (document.querySelector(`[data-testid="join-refuse-open-${id}"]`) as HTMLElement).click()
    }, requestId)
    await page.waitForSelector(`[data-testid="join-refuse-reason-${requestId}"]`, { timeout: SETTLE, polling: 500 })
    await page.type(`[data-testid="join-refuse-reason-${requestId}"]`, 'The organization is not an OIML-CS participant — see the participation procedures (PD-03/PD-09) to join the scheme.')
    await page.evaluate((id) => {
      (document.querySelector(`[data-testid="join-refuse-${id}"]`) as HTMLElement).click()
    }, requestId)
    await page.waitForSelector('[data-testid="op-admin-notice"]', { timeout: SETTLE, polling: 500 })
    const notice = await page.$eval('[data-testid="op-admin-notice"]', el => el.textContent ?? '')
    expect(notice).toContain('refused')
    await page.waitForSelector('[data-testid="biml-orgs-empty"]', { timeout: SETTLE, polling: 500 })
  })
})
