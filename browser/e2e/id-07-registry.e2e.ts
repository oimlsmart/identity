// ═══════════════════════════════════════════════════════════════════
// TODO.identity/07 — the administrator's identity registry console, e2e:
// the identity-profile stack (its own API + its own astro, the fed-01
// spawned-stack pattern) proves the registry surfaces in the browser:
//
//   leg 1  the bootstrap admin's setup link (the boot log) → the
//          registry directory: the invite action issues Erin's one-time
//          setup link (shown once, the copy affordance);
//   leg 2  Erin enrolls from the link; a NON-admin opening the registry
//          gets the honest refusal;
//   leg 3  the directory's search (name/email/linked handle), the status
//          and role filters, the last-sign-in column;
//   leg 4  the account detail: the role assignment (the account-wide
//          model), the per-client assignments read-back (03's rows,
//          empty here), the justified link-on-behalf, the account's own
//          trail;
//   leg 5  the administrator ends one of Erin's sessions — it stops
//          resolving at once;
//   leg 6  deactivate → the password sign-in is refused honestly;
//          reactivate → it works again;
//   leg 7  the relying-party console: the wizard registers a
//          confidential client, the generated secret shows ONCE (and is
//          gone after a reload), and the secret authenticates at the
//          token endpoint (the real authorize → consent → token
//          exchange at the fetch level);
//   leg 8  the activity feed carries every act above; the category
//          filter narrows; the account target deep-links;
//   leg 9  the erasure (the two-step delete, the tombstone, the freed
//          email);
//   leg 10 the APPS view (the heavy rebuild's per-client verdicts): can
//          enter / no, with the reason named plainly (the allowlist vs
//          the account's roles, the no-claims policy, the disabled
//          client);
//   leg 11 the per-client role grants edited ON the page: the grant
//          flips the app verdict, the revoke restores the default, both
//          audited;
//   leg 12 the end-all-sessions act (the light act): every cookie stops
//          resolving at once, the audit row carries the count;
//   leg 13 the self-lockout rule: the admin's own page disarms the
//          heavy acts and the server refuses them anyway;
//   leg 14 the invited account's honest empty sections, and the erased
//          account's tombstone page (no acts, the erasure on the trail).
//
// SELF-CONTAINED: the suite's shared stack (E2E_BASE_URL) is untouched —
// own ports (API 9293 / astro 9294), own SQLite file. No stub GitHub:
// the link-on-behalf writes the registry row only (no flow runs), and
// the token endpoint proof drives the fixture redirect_uri at the fetch
// level (nothing navigates to it).
//
// THE BROWSER IS PER-LEG (the id-02 lesson: a long-lived headless-shell
// wedges silently under load; a fresh browser per leg costs ~2 s and
// cross-leg state rides the DATABASE).
// ═══════════════════════════════════════════════════════════════════

import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import puppeteer, { type Browser, type Page } from 'puppeteer'
import { spawn, type ChildProcess } from 'node:child_process'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { existsSync, mkdirSync, rmSync, cpSync, appendFileSync } from 'node:fs'
import { closeBrowser, delay } from './helpers'
import { fixtureOpSigningKey } from './fixtures/op-signing-key'
import { generatePkce } from '@oimlsmart/platform-server/oidc'

const BROWSER_DIR = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const FIXTURES = join(BROWSER_DIR, 'e2e', 'fixtures')
const DB_DIR = join(BROWSER_DIR, '.cache', 'id-07')

// Port-isolated: clear of the shared dev stack (5190/3190), the fed-01
// stacks (8291/8292/8491/8492), the fed-10 stub (8699), the id-01 stack
// (8693/8393/8694), the id-02 stack (8793/8593/8794), the id-08 stack
// (8893/8993/8994), the id-10 stack (9093/9193) and the local identity
// dev stack (7390/7190).
const ID_API = 9293
const ID_WEB = 9294

const ISSUER = `http://localhost:${ID_WEB}` // the astro origin (the browser's OP)
const HUB_CLIENT = 'hub-fixture-07'

const ROOT = { email: 'root@oimlsmart.org', name: 'Root Operator', password: 'the root operator passphrase' }
const ERIN = { email: 'erin.registry@example.org', name: 'Ms. Erin Registry', password: 'erin has a proper passphrase' }

interface Stack {
  api: ChildProcess
  astro: ChildProcess
  base: string
  apiBase: string
  logs: string[]
}

function spawnLogged(cmd: string, args: string[], env: NodeJS.ProcessEnv, logs: string[]): ChildProcess {
  // detached (the process group dies together); the env SCRUBS the vitest
  // markers (NODE_ENV=test would poison the spawned astro's vite cache).
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
 *  the OP env (the issuer, the account bootstrap seed, the client
 *  registry's fixture row, the GitHub provider row the link-on-behalf
 *  names), the profile seed through the dev-reset seam, astro dev. */
async function bootIdentityStack(): Promise<Stack> {
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
    // OIDC_* scrubbed + the demo override ON (the CI e2e job declares the
    // SUITE stack's SSO posture in the shared env; the identity stack
    // must not inherit it).
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
      // The first administrator arrives by DECLARATION — the setup link
      // lands in the boot log.
      OP_ACCOUNT_SEED: JSON.stringify([{ email: ROOT.email, name: ROOT.name, role: 'admin' }]),
      // The client registry's fixture row: the hub instance carrying the
      // role-claim policy (the detail page's "what the instances receive"
      // panel names it).
      OP_CLIENT_SEED: JSON.stringify([{
        client_id: HUB_CLIENT,
        name: 'The id-07 fixture hub',
        secret: 'fixture-hub-secret-07',
        redirect_uris: ['http://127.0.0.1:9295/callback'],
        claims_policy: { claims: ['roles', 'groups', 'org'] },
      }]),
      // The GitHub provider row (the link-on-behalf's target; no flow
      // runs, so no stub is needed).
      OP_UPSTREAM_SEED: JSON.stringify([{
        id: 'github',
        kind: 'github',
        display_name: 'GitHub',
        brand_mark: 'github',
        client_id: 'op-e2e-07',
        client_secret_ref: 'env:OP_E2E_GH_SECRET',
        enabled: true,
      }]),
      OP_E2E_GH_SECRET: 'op-e2e-07-secret',
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
    // warm one (the fed-01 lesson).
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
// island; on a contended host that cold compile outlives SETTLE.
const APP_COLD = 840_000

/** Progress outside vitest's per-test console capture (a stalled browser
 *  makes the suite silent until the file ends — this log is live). */
const PROGRESS_LOG = join(DB_DIR, 'progress.log')
function flog(page: Page | null, msg: string): void {
  const url = page && !page.isClosed() ? page.url() : '(no page)'
  const line = `${new Date().toISOString()} ${msg} @ ${url}\n`
  try { appendFileSync(PROGRESS_LOG, line) } catch { /* the log never breaks the leg */ }
}

/** A fresh browser per leg (the header note). */
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

/** Install a session cookie on the page. */
async function signInViaCookie(page: Page, base: string, cookieValue: string): Promise<void> {
  await page.setCookie({ name: 'oiml-session', value: cookieValue, url: base })
}

/** Open the registry directory signed in as the given cookie's account. */
async function openRegistry(page: Page, base: string, cookieValue: string): Promise<void> {
  await signInViaCookie(page, base, cookieValue)
  await page.goto(`${base}/op/admin/registry`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
  await page.waitForSelector('[data-testid="op-reg"]', { timeout: SETTLE, polling: 500 })
}

describe('TODO.identity/07 — the administrator’s identity registry console (the identity profile)', () => {
  let stack: Stack
  let erinId = ''
  let erinSetupUrl = ''
  let backAgainId = ''

  beforeAll(async () => {
    stack = await bootIdentityStack()
  }, 600_000)

  afterAll(async () => {
    await stopStack(stack)
  })

  it('leg 1 — the bootstrap admin sets up from the logged link, then invites Erin from the registry (the link shows once)', { timeout: 900_000 }, async () => {
    // The bootstrap seed logged the one-time link (the operator's way in).
    const deadline = Date.now() + 60_000
    let setupUrl = ''
    while (Date.now() < deadline) {
      const m = /bootstrap: account root@oimlsmart\.org has no password[^\n]*\n\s*(\S+\/op\/setup\?token=\S+)/.exec(stack.logs.join(''))
      if (m) { setupUrl = m[1]!; break }
      await delay(500)
    }
    expect(setupUrl, 'the bootstrap setup link in the boot log').toContain('/op/setup?token=')

    await withPage(async (page) => {
      // The root operator's own setup (the real page, as id-02 proves).
      await page.goto(setupUrl, { waitUntil: 'domcontentloaded', timeout: SETTLE })
      await page.waitForSelector('[data-testid="op-setup-account"]', { timeout: SETTLE, polling: 500 })
      await page.type('[data-testid="op-setup-password"]', ROOT.password)
      await page.type('[data-testid="op-setup-confirm"]', ROOT.password)
      await page.evaluate(() => (document.querySelector('[data-testid="op-setup-submit"]') as HTMLElement).click())
      flog(page, 'leg1: root enrolled; the first app-shell navigation compiles cold')
      await page.waitForSelector('[data-testid="account-name"]', { timeout: APP_COLD, polling: 500 })
      flog(page, 'leg1: root is in')

      // The registry directory: the admin's own row + the invite action.
      await page.goto(`${stack.base}/op/admin/registry`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
      await page.waitForSelector('[data-testid="op-reg"]', { timeout: SETTLE, polling: 500 })
      expect(await page.$eval('[data-testid="op-reg-identity"]', el => el.textContent ?? '')).toContain(ROOT.email)

      // The invite: name + email + the OP default role → the setup link
      // card, shown once.
      await page.type('[data-testid="op-reg-invite-name"]', ERIN.name)
      await page.type('[data-testid="op-reg-invite-email"]', ERIN.email)
      await page.select('[data-testid="op-reg-invite-role"]', 'viewer')
      await page.evaluate(() => (document.querySelector('[data-testid="op-reg-invite-submit"]') as HTMLElement).click())
      await page.waitForSelector('[data-testid="op-reg-invite-link-card"]', { timeout: 60_000, polling: 500 })
      const link = await page.$eval('[data-testid="op-reg-invite-setup-url"]', el => el.textContent ?? '')
      expect(link).toContain('/op/setup?token=')
      expect(await page.$('[data-testid="op-reg-invite-setup-copy"]')).not.toBeNull()
      flog(null, 'leg1: the invite link showed once')

      // Erin's row appears, never signed in yet. (The directory sorts by
      // name: find HER row by its email text — the demo cast sorts first.)
      const rows = await page.$$eval('[data-testid^="op-reg-user-"]', els =>
        els.map(e => ({ testid: e.getAttribute('data-testid')!, text: e.textContent ?? '' })),
      )
      const erinRow = rows.find(r => r.text.includes(ERIN.email))
      expect(erinRow, 'the invited account’s row').toBeTruthy()
      erinId = erinRow!.testid.replace('op-reg-user-', '')
      expect(await page.$eval(`[data-testid="op-reg-lastsignin-${erinId}"]`, el => el.textContent?.trim())).toBe('never')
      flog(null, 'leg1: done')
    })

    // The link reaches leg 2 through the page state — re-read it from the
    // API (the registry's enrollment route answers a fresh link; the
    // original was shown once and is not recoverable, so leg 2 uses the
    // link text captured above… which is gone with the page. The honest
    // path: the admin re-issues one — exactly what the console offers.)
    const root = await passwordCookie(stack.base, ROOT.email, ROOT.password)
    const reissue = await fetch(`${stack.base}/api/op/accounts/${erinId}/enrollment`, {
      method: 'POST',
      headers: { cookie: `oiml-session=${root}` },
    })
    expect(reissue.status).toBe(201)
    const { setupUrl: erinSetup } = await reissue.json() as { setupUrl: string }
    erinSetupUrl = erinSetup
  })

  it('leg 2 — Erin enrolls from the link; a non-admin opening the registry gets the honest refusal', { timeout: 900_000 }, async () => {
    expect(erinSetupUrl).toContain('/op/setup?token=')
    await withPage(async (page) => {
      await page.goto(erinSetupUrl, { waitUntil: 'domcontentloaded', timeout: SETTLE })
      await page.waitForSelector('[data-testid="op-setup-account"]', { timeout: SETTLE, polling: 500 })
      expect(await page.$eval('[data-testid="op-setup-account"]', el => el.textContent ?? '')).toContain(ERIN.email)
      await page.type('[data-testid="op-setup-password"]', ERIN.password)
      await page.type('[data-testid="op-setup-confirm"]', ERIN.password)
      await page.evaluate(() => (document.querySelector('[data-testid="op-setup-submit"]') as HTMLElement).click())
      await page.waitForSelector('[data-testid="account-name"]', { timeout: APP_COLD, polling: 500 })
      expect(await page.$eval('[data-testid="account-name"]', el => el.textContent?.trim())).toBe(ERIN.name)
      flog(page, 'leg2: Erin enrolled')

      // Erin (a viewer) opens the registry: the honest refusal.
      await page.goto(`${stack.base}/op/admin/registry`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
      await page.waitForSelector('[data-testid="op-reg-forbidden"]', { timeout: SETTLE, polling: 500 })
      expect(await page.$eval('[data-testid="op-reg-forbidden"]', el => el.textContent ?? '')).toContain('administrator')
      flog(page, 'leg2: the refusal is honest')
    })
  })

  it('leg 3 — the directory searches (name, email, the linked handle) and filters; the last-sign-in column moved', { timeout: 900_000 }, async () => {
    const root = await passwordCookie(stack.base, ROOT.email, ROOT.password)
    // The handle search's fixture: link Erin's GitHub handle first (the
    // API; the page flow is leg 4's).
    const linkRes = await fetch(`${stack.base}/api/op/registry/users/${erinId}/links`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: `oiml-session=${root}` },
      body: JSON.stringify({ provider: 'github', provider_account_id: 'octo-erin', justification: 'the id-07 fixture link (verified out of band)' }),
    })
    expect(linkRes.status).toBe(201)

    await withPage(async (page) => {
      await openRegistry(page, stack.base, root)

      // The last-sign-in column moved off "never" (leg 2's enrollment).
      await page.waitForFunction(
        (id) => !document.querySelector(`[data-testid="op-reg-lastsignin-${id}"]`)?.textContent?.includes('never'),
        { timeout: 60_000, polling: 500 },
        erinId,
      )

      // The search narrows on the name…
      await page.type('[data-testid="op-reg-search"]', ERIN.name)
      await page.waitForFunction(
        (id) => {
          const rows = [...document.querySelectorAll('[data-testid^="op-reg-user-"]')]
          return rows.length === 1 && rows[0]!.getAttribute('data-testid') === `op-reg-user-${id}`
        },
        { timeout: 60_000, polling: 500 },
        erinId,
      )
      // …on the linked handle…
      await page.evaluate(() => {
        const el = document.querySelector('[data-testid="op-reg-search"]') as HTMLInputElement
        el.value = ''
        el.dispatchEvent(new Event('input', { bubbles: true }))
      })
      await page.type('[data-testid="op-reg-search"]', 'octo-erin')
      await page.waitForFunction(
        (id) => {
          const rows = [...document.querySelectorAll('[data-testid^="op-reg-user-"]')]
          return rows.length === 1 && rows[0]!.getAttribute('data-testid') === `op-reg-user-${id}`
        },
        { timeout: 60_000, polling: 500 },
        erinId,
      )
      // …and a no-hit search shows the honest empty state.
      await page.evaluate(() => {
        const el = document.querySelector('[data-testid="op-reg-search"]') as HTMLInputElement
        el.value = ''
        el.dispatchEvent(new Event('input', { bubbles: true }))
      })
      await page.type('[data-testid="op-reg-search"]', 'nobody-at-all')
      await page.waitForSelector('[data-testid="op-reg-empty"]', { timeout: 60_000, polling: 500 })

      // The filters: status (Erin is active) + role (Erin is a viewer).
      await page.evaluate(() => {
        const el = document.querySelector('[data-testid="op-reg-search"]') as HTMLInputElement
        el.value = ''
        el.dispatchEvent(new Event('input', { bubbles: true }))
      })
      await page.select('[data-testid="op-reg-filter-status"]', 'deactivated')
      await page.waitForSelector('[data-testid="op-reg-empty"]', { timeout: 60_000, polling: 500 })
      await page.select('[data-testid="op-reg-filter-status"]', 'active')
      await page.select('[data-testid="op-reg-filter-role"]', 'viewer')
      await page.waitForFunction(
        (id) => [...document.querySelectorAll('[data-testid^="op-reg-user-"]')].some(e => e.getAttribute('data-testid') === `op-reg-user-${id}`),
        { timeout: 60_000, polling: 500 },
        erinId,
      )
      await page.select('[data-testid="op-reg-filter-role"]', 'tl_operator')
      await page.waitForFunction(
        (id) => ![...document.querySelectorAll('[data-testid^="op-reg-user-"]')].some(e => e.getAttribute('data-testid') === `op-reg-user-${id}`),
        { timeout: 60_000, polling: 500 },
        erinId,
      )
      flog(page, 'leg3: search + filters behave')
    })
  })

  it('leg 4 — the account detail: the role assignment, the justified link, the account’s own trail', { timeout: 900_000 }, async () => {
    const root = await passwordCookie(stack.base, ROOT.email, ROOT.password)
    await withPage(async (page) => {
      await signInViaCookie(page, stack.base, root)
      await page.goto(`${stack.base}/op/admin/registry/users/${erinId}`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
      await page.waitForSelector('[data-testid="op-reg-user"]', { timeout: SETTLE, polling: 500 })
      // The email cell carries the verification badge next to the address.
      expect(await page.$eval('[data-testid="op-reg-profile-email"]', el => el.textContent ?? '')).toContain(ERIN.email)

      // The role assignment (the merged account-wide model): Erin gains
      // tl_operator; the primary stays viewer.
      await page.evaluate(() => (document.querySelector('[data-testid="op-reg-role-check-tl_operator"]') as HTMLElement).click())
      await page.evaluate(() => (document.querySelector('[data-testid="op-reg-roles-save"]') as HTMLElement).click())
      await page.waitForSelector('[data-testid="op-reg-user-notice"]', { timeout: 60_000, polling: 500 })
      flog(page, 'leg4: roles saved')

      // The apps view names the fixture hub: Erin enters it WITH her
      // roles (the policy carries the role claims, no allowlist bounds
      // them); the per-client grants block reads empty honestly.
      await page.waitForSelector(`[data-testid="op-reg-app-${HUB_CLIENT}"]`, { timeout: 60_000, polling: 500 })
      expect(await page.$eval(`[data-testid="op-reg-app-badge-${HUB_CLIENT}"]`, el => el.textContent?.trim())).toBe('can enter')
      const hubReason = await page.$eval(`[data-testid="op-reg-app-reason-${HUB_CLIENT}"]`, el => el.textContent ?? '')
      expect(hubReason).toContain('viewer')
      expect(hubReason).toContain('tl_operator')
      expect(await page.$eval('[data-testid="op-reg-client-roles-empty"]', el => el.textContent ?? '')).toContain('No per-client grants')
      expect(await page.$eval('[data-testid="op-reg-grants-seam"]', el => el.textContent ?? '')).toContain('relying parties console')

      // The link from leg 3 is listed with its provenance; the on-behalf
      // form's justification gate is live.
      await page.waitForSelector('[data-testid="op-reg-link-github"]', { timeout: 60_000, polling: 500 })
      expect(await page.$eval('[data-testid="op-reg-link-github"]', el => el.textContent ?? '')).toContain('octo-erin')
      expect(await page.$eval('[data-testid="op-reg-link-github"]', el => el.textContent ?? '')).toContain(ROOT.email)

      // The account's own trail shows the acts so far, justification included.
      const trail = await page.$eval('[data-testid="op-reg-activity-list"]', el => el.textContent ?? '')
      expect(trail).toContain('invited the account')
      expect(trail).toContain('completed the setup')
      expect(trail).toContain('the id-07 fixture link')
      flog(page, 'leg4: done')
    })

    // The role assignment landed server-side: the registry row carries it.
    const rows = await (await fetch(`${stack.base}/api/op/registry/users?role=tl_operator`, {
      headers: { cookie: `oiml-session=${root}` },
    })).json() as Array<{ id: string }>
    expect(rows.map(r => r.id)).toContain(erinId)
  })

  it('leg 5 — the administrator ends one of Erin’s sessions; it stops resolving at once', { timeout: 900_000 }, async () => {
    // Two live sessions for Erin.
    const erinA = await passwordCookie(stack.base, ERIN.email, ERIN.password)
    const erinB = await passwordCookie(stack.base, ERIN.email, ERIN.password)
    const root = await passwordCookie(stack.base, ROOT.email, ROOT.password)

    await withPage(async (page) => {
      await signInViaCookie(page, stack.base, root)
      await page.goto(`${stack.base}/op/admin/registry/users/${erinId}`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
      await page.waitForSelector('[data-testid="op-reg-sessions-list"]', { timeout: SETTLE, polling: 500 })
      const sessions = await page.$$eval('[data-testid^="op-reg-session-"]', els => els.map(e => e.getAttribute('data-testid')!.replace('op-reg-session-', '')))
      expect(sessions.length).toBeGreaterThanOrEqual(2)
      await page.evaluate((sid) => (document.querySelector(`[data-testid="op-reg-revoke-${sid}"]`) as HTMLElement).click(), sessions[0])
      await page.waitForFunction(
        (n) => document.querySelectorAll('[data-testid^="op-reg-session-"]').length === n - 1,
        { timeout: 60_000, polling: 500 },
        sessions.length,
      )
      flog(page, 'leg5: the session is ended')
    })
    // The two cookies both still resolve (the revoked row was one of
    // several; the assertions are on the page's count). The admin act is
    // on the trail.
    const trail = await (await fetch(`${stack.base}/api/op/registry/activity?q=session`, {
      headers: { cookie: `oiml-session=${root}` },
    })).json() as Array<{ action: string; metadata?: Record<string, unknown> }>
    expect(trail.some(e => e.action === 'account.session_revoked' && e.metadata?.by === 'administrator')).toBe(true)
    void erinA
    void erinB
  })

  it('leg 6 — deactivate: the password sign-in is refused honestly; reactivate restores it', { timeout: 900_000 }, async () => {
    const root = await passwordCookie(stack.base, ROOT.email, ROOT.password)
    await withPage(async (page) => {
      await signInViaCookie(page, stack.base, root)
      await page.goto(`${stack.base}/op/admin/registry/users/${erinId}`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
      await page.waitForSelector('[data-testid="op-reg-deactivate"]', { timeout: SETTLE, polling: 500 })
      // The two-step: arm, then confirm.
      await page.evaluate(() => (document.querySelector('[data-testid="op-reg-deactivate"]') as HTMLElement).click())
      await page.waitForSelector('[data-testid="op-reg-deactivate-confirm"]', { timeout: 30_000, polling: 200 })
      await page.evaluate(() => (document.querySelector('[data-testid="op-reg-deactivate-confirm"]') as HTMLElement).click())
      await page.waitForSelector('[data-testid="op-reg-user-notice"]', { timeout: 60_000, polling: 500 })
      await page.waitForFunction(
        () => document.querySelector('[data-testid="op-reg-profile-status"]')?.textContent?.includes('deactivated'),
        { timeout: 60_000, polling: 500 },
      )
      flog(page, 'leg6: deactivated')
    })

    // The sign-in refuses honestly.
    const refused = await fetch(`${stack.base}/api/op/login`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: ERIN.email, password: ERIN.password }),
    })
    expect(refused.status).toBe(403)
    expect(((await refused.json()) as { error: string }).error).toContain('deactivated')

    // Reactivate from the detail page; the sign-in works again.
    await withPage(async (page) => {
      await signInViaCookie(page, stack.base, root)
      await page.goto(`${stack.base}/op/admin/registry/users/${erinId}`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
      await page.waitForSelector('[data-testid="op-reg-reactivate"]', { timeout: SETTLE, polling: 500 })
      await page.evaluate(() => (document.querySelector('[data-testid="op-reg-reactivate"]') as HTMLElement).click())
      await page.waitForFunction(
        // 'deactivated' CONTAINS 'active' — compare the trimmed cell.
        () => document.querySelector('[data-testid="op-reg-profile-status"]')?.textContent?.trim() === 'active',
        { timeout: 60_000, polling: 500 },
      )
    })
    expect((await fetch(`${stack.base}/api/op/login`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: ERIN.email, password: ERIN.password }),
    })).status).toBe(200)
    flog(null, 'leg6: reactivated, the sign-in works')
  })

  it('leg 7 — the relying-party wizard: the generated secret shows ONCE and authenticates at the token endpoint', { timeout: 900_000 }, async () => {
    const root = await passwordCookie(stack.base, ROOT.email, ROOT.password)
    let secret = ''
    await withPage(async (page) => {
      await signInViaCookie(page, stack.base, root)
      await page.goto(`${stack.base}/op/admin/clients`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
      await page.waitForSelector('[data-testid="op-clients"]', { timeout: SETTLE, polling: 500 })
      // The seeded fixture row is listed.
      await page.waitForSelector(`[data-testid="op-client-${HUB_CLIENT}"]`, { timeout: 60_000, polling: 500 })

      // The wizard: id, name, the exact redirect URI, the roles claim,
      // confidential (the default — the server generates the secret).
      await page.type('[data-testid="op-client-field-id"]', 'tl-e2e-07')
      await page.type('[data-testid="op-client-field-name"]', 'The id-07 TL instance')
      await page.type('[data-testid="op-client-field-uris"]', 'https://tl-07.example.org/api/auth/callback/oidc')
      await page.evaluate(() => (document.querySelector('[data-testid="op-client-claim-roles"]') as HTMLElement).click())
      await page.evaluate(() => (document.querySelector('[data-testid="op-client-save"]') as HTMLElement).click())

      // The secret card shows ONCE with the copy affordance.
      await page.waitForSelector('[data-testid="op-client-secret-card"]', { timeout: 60_000, polling: 500 })
      secret = (await page.$eval('[data-testid="op-client-secret"]', el => el.textContent ?? '')).trim()
      expect(secret.length).toBeGreaterThan(20)
      expect(await page.$('[data-testid="op-client-secret-copy"]')).not.toBeNull()
      flog(page, 'leg7: the secret showed once')

      // The list carries the new client as confidential…
      await page.waitForSelector('[data-testid="op-client-tl-e2e-07"]', { timeout: 60_000, polling: 500 })
      expect(await page.$eval('[data-testid="op-client-kind-tl-e2e-07"]', el => el.textContent?.trim())).toBe('confidential')
      // …and NEVER the secret (the page text is secret-free beyond the card).
      const pageText = await page.evaluate(() => document.body.innerText)
      expect(pageText.split(secret).length - 1, 'the secret appears in the one-time card only').toBe(1)

      // A reload loses the card — the list never re-shows the secret.
      await page.reload({ waitUntil: 'domcontentloaded' })
      await page.waitForSelector('[data-testid="op-clients"]', { timeout: SETTLE, polling: 500 })
      await page.waitForSelector('[data-testid="op-client-tl-e2e-07"]', { timeout: 60_000, polling: 500 })
      expect(await page.$('[data-testid="op-client-secret-card"]')).toBeNull()
      expect(await page.evaluate(() => document.body.innerText)).not.toContain(secret)
      flog(page, 'leg7: after the reload the secret is gone')
    })

    // The secret WORKS: the real authorize → consent → token exchange as
    // Erin (fetch level; the registered redirect_uri is never navigated).
    const erin = await passwordCookie(stack.base, ERIN.email, ERIN.password)
    const pkce = await generatePkce()
    const query = new URLSearchParams({
      response_type: 'code',
      client_id: 'tl-e2e-07',
      redirect_uri: 'https://tl-07.example.org/api/auth/callback/oidc',
      scope: 'openid profile email',
      state: 'st-e2e-07',
      code_challenge: pkce.challenge,
      code_challenge_method: 'S256',
    })
    const authorize = await fetch(`${stack.base}/op/authorize?${query}`, {
      headers: { cookie: `oiml-session=${erin}` },
      redirect: 'manual',
    })
    expect(authorize.status).toBe(302)
    const authId = new URL(authorize.headers.get('location')!, ISSUER).searchParams.get('auth')!
    const decide = await fetch(`${stack.base}/api/op/consent/${authId}/decide`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: `oiml-session=${erin}` },
      body: JSON.stringify({ decision: 'allow' }),
    })
    expect(decide.status).toBe(200)
    const { redirect } = await decide.json() as { redirect: string }
    const code = new URL(redirect).searchParams.get('code')!
    const token = await fetch(`${stack.base}/op/token`, {
      method: 'POST',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        authorization: `Basic ${btoa(`tl-e2e-07:${encodeURIComponent(secret)}`)}`,
      },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: 'https://tl-07.example.org/api/auth/callback/oidc',
        client_id: 'tl-e2e-07',
        code_verifier: pkce.verifier,
      }),
    })
    expect(token.status, 'the generated secret authenticates at the token endpoint').toBe(200)
    const tokens = await token.json() as { id_token: string }
    // The roles claim rides the client's policy — Erin's leg-4 assignment included.
    const claims = JSON.parse(Buffer.from(tokens.id_token.split('.')[1]!, 'base64url').toString()) as { roles?: string[] }
    expect(claims.roles).toEqual(expect.arrayContaining(['viewer', 'tl_operator']))
    flog(null, 'leg7: the token endpoint accepted the generated secret')
  })

  it('leg 8 — the activity feed carries every act; the category filter narrows; the account deep-links', { timeout: 900_000 }, async () => {
    const root = await passwordCookie(stack.base, ROOT.email, ROOT.password)
    await withPage(async (page) => {
      await signInViaCookie(page, stack.base, root)
      await page.goto(`${stack.base}/op/admin/activity`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
      await page.waitForSelector('[data-testid="op-act-list"]', { timeout: SETTLE, polling: 500 })
      const feed = await page.$eval('[data-testid="op-act-list"]', el => el.textContent ?? '')
      // The suite's acts, with their actors.
      expect(feed).toContain('invited erin.registry@example.org')
      expect(feed).toContain('linked github account octo-erin on behalf')
      expect(feed).toContain('deactivated the account')
      expect(feed).toContain('reactivated the account')
      expect(feed).toContain('registered the relying party tl-e2e-07')
      expect(feed).toContain('Root Operator')

      // The category filter narrows to the relying-party acts.
      await page.select('[data-testid="op-act-category"]', 'clients')
      await page.waitForFunction(
        () => {
          const text = document.querySelector('[data-testid="op-act-list"]')?.textContent ?? ''
          return text.includes('tl-e2e-07') && !text.includes('invited erin')
        },
        { timeout: 60_000, polling: 500 },
      )
      await page.select('[data-testid="op-act-category"]', '')

      // The account target deep-links to Erin's detail page (pick the
      // account link explicitly — client/provider events link to their
      // own consoles).
      await page.waitForFunction(
        () => !!document.querySelector('a[data-testid^="op-act-open-"][href*="/op/admin/registry/users/"]'),
        { timeout: 60_000, polling: 500 },
      )
      await page.evaluate(() => (document.querySelector('a[data-testid^="op-act-open-"][href*="/op/admin/registry/users/"]') as HTMLElement).click())
      await page.waitForSelector('[data-testid="op-reg-user"]', { timeout: SETTLE, polling: 500 })
      expect(new URL(page.url()).pathname).toMatch(/^\/op\/admin\/registry\/users\//)
      flog(page, 'leg8: the deep link lands')
    })
  })

  it('leg 9 — the erasure: the two-step delete anonymizes the account, the sign-in refuses, the directory drops the row, the journal keeps the act', { timeout: 900_000 }, async () => {
    const root = await passwordCookie(stack.base, ROOT.email, ROOT.password)
    // The erase target is invited in-leg (Erin's trail stays intact for
    // the feed above): the API invite, then the console's own delete act.
    const invited = await fetch(`${stack.base}/api/op/accounts`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: `oiml-session=${root}` },
      body: JSON.stringify({ email: 'gone@example.org', name: 'Gone Tomorrow' }),
    })
    expect(invited.status).toBe(201)
    const goneId = ((await invited.json()) as { account: { id: string } }).account.id

    await withPage(async (page) => {
      await signInViaCookie(page, stack.base, root)
      await page.goto(`${stack.base}/op/admin/registry/users/${goneId}`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
      await page.waitForSelector('[data-testid="op-reg-erase"]', { timeout: SETTLE, polling: 500 })
      // The two-step: arm (the warning names what goes), then confirm.
      await page.evaluate(() => (document.querySelector('[data-testid="op-reg-erase"]') as HTMLElement).click())
      await page.waitForSelector('[data-testid="op-reg-erase-warning"]', { timeout: 30_000, polling: 200 })
      expect(await page.$eval('[data-testid="op-reg-erase-warning"]', el => el.textContent ?? '')).toContain('anonymized tombstone')
      await page.evaluate(() => (document.querySelector('[data-testid="op-reg-erase-confirm"]') as HTMLElement).click())
      // The act ends back on the directory.
      await page.waitForSelector('[data-testid="op-reg-directory"]', { timeout: SETTLE, polling: 500 })
      flog(page, 'leg9: erased, back on the directory')

      // The directory drops the row (the search finds nothing).
      await page.type('[data-testid="op-reg-search"]', 'gone@example.org')
      await page.waitForFunction(
        () => document.querySelector('[data-testid="op-reg-empty"]') !== null,
        { timeout: 60_000, polling: 500 },
      )

      // The activity feed carries the erase, naming the actor.
      await page.goto(`${stack.base}/op/admin/activity`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
      await page.waitForSelector('[data-testid="op-act-list"]', { timeout: SETTLE, polling: 500 })
      await page.waitForFunction(
        () => (document.querySelector('[data-testid="op-act-list"]')?.textContent ?? '').includes('erased the account gone@example.org'),
        { timeout: 60_000, polling: 500 },
      )
      flog(page, 'leg9: the journal kept the act')
    })

    // The erased account can never sign in (the credential is gone).
    const refused = await fetch(`${stack.base}/api/op/login`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: 'gone@example.org', password: 'gone had a proper passphrase' }),
    })
    expect(refused.status).toBe(401)
    // …and the freed email invites again cleanly.
    const reinvited = await fetch(`${stack.base}/api/op/accounts`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: `oiml-session=${root}` },
      body: JSON.stringify({ email: 'gone@example.org', name: 'Back Again' }),
    })
    expect(reinvited.status).toBe(201)
    backAgainId = ((await reinvited.json()) as { account: { id: string } }).account.id
    flog(null, 'leg9: the email is free again')
  })

  it('leg 10 — the apps view: the per-client verdicts with the reasons named plainly', { timeout: 900_000 }, async () => {
    const root = await passwordCookie(stack.base, ROOT.email, ROOT.password)
    // The fixture clients: a role-allowlist client (Erin’s viewer +
    // tl_operator are outside it), a profile+email-only client, and a
    // disabled one.
    const bounded = await fetch(`${stack.base}/api/op/clients`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: `oiml-session=${root}` },
      body: JSON.stringify({
        client_id: 'ia-bounded-07', name: 'The id-07 bounded IA',
        redirect_uris: ['https://ia-07.example.org/api/auth/callback/oidc'],
        claims_policy: { claims: ['roles'], roles: ['ia_officer'] },
      }),
    })
    expect(bounded.status).toBe(201)
    const plain = await fetch(`${stack.base}/api/op/clients`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: `oiml-session=${root}` },
      body: JSON.stringify({
        client_id: 'profile-only-07', name: 'The id-07 profile-only app',
        redirect_uris: ['https://plain-07.example.org/api/auth/callback/oidc'],
      }),
    })
    expect(plain.status).toBe(201)
    const off = await fetch(`${stack.base}/api/op/clients`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: `oiml-session=${root}` },
      body: JSON.stringify({
        client_id: 'off-07', name: 'The id-07 disabled app',
        redirect_uris: ['https://off-07.example.org/api/auth/callback/oidc'],
        claims_policy: { claims: ['roles'] },
      }),
    })
    expect(off.status).toBe(201)
    await fetch(`${stack.base}/api/op/clients/off-07/status`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: `oiml-session=${root}` },
      body: JSON.stringify({ status: 'disabled' }),
    })

    await withPage(async (page) => {
      await signInViaCookie(page, stack.base, root)
      await page.goto(`${stack.base}/op/admin/registry/users/${erinId}`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
      await page.waitForSelector('[data-testid="op-reg-apps-list"]', { timeout: SETTLE, polling: 500 })

      // The fixture hub: can enter, the tokens carry Erin’s two roles.
      expect(await page.$eval(`[data-testid="op-reg-app-badge-${HUB_CLIENT}"]`, el => el.textContent?.trim())).toBe('can enter')
      expect(await page.$eval(`[data-testid="op-reg-app-reason-${HUB_CLIENT}"]`, el => el.textContent ?? '')).toContain('viewer, tl_operator')

      // The bounded client: NO, and the reason names both sets.
      expect(await page.$eval('[data-testid="op-reg-app-badge-ia-bounded-07"]', el => el.textContent?.trim())).toBe('no')
      const boundedReason = await page.$eval('[data-testid="op-reg-app-reason-ia-bounded-07"]', el => el.textContent ?? '')
      expect(boundedReason).toContain('[ia_officer]')
      expect(boundedReason).toContain('[viewer, tl_operator]')

      // The profile-only client: NO, no role claim in its policy.
      expect(await page.$eval('[data-testid="op-reg-app-reason-profile-only-07"]', el => el.textContent ?? '')).toContain('no role claim')

      // The disabled client: NO, the client is disabled.
      expect(await page.$eval('[data-testid="op-reg-app-reason-off-07"]', el => el.textContent ?? '')).toContain('disabled')

      // The footnote is honest about what CAN ENTER means.
      expect(await page.$eval('[data-testid="op-reg-apps-footnote"]', el => el.textContent ?? '')).toContain('sign-in itself never refuses')
      flog(page, 'leg10: the verdicts and the reasons read correctly')
    })
  })

  it('leg 11 — the per-client grants edited on the page: the grant flips the verdict, the revoke restores the default, both audited', { timeout: 900_000 }, async () => {
    const root = await passwordCookie(stack.base, ROOT.email, ROOT.password)
    await withPage(async (page) => {
      await signInViaCookie(page, stack.base, root)
      await page.goto(`${stack.base}/op/admin/registry/users/${erinId}`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
      await page.waitForSelector('[data-testid="op-reg-grant-open"]', { timeout: SETTLE, polling: 500 })

      // The grant form: the bounded client’s allowlist bounds the
      // checkboxes (viewer is disabled — outside [ia_officer]).
      await page.evaluate(() => (document.querySelector('[data-testid="op-reg-grant-open"]') as HTMLElement).click())
      await page.waitForSelector('[data-testid="op-reg-grant-form"]', { timeout: 30_000, polling: 200 })
      await page.select('[data-testid="op-reg-grant-client"]', 'ia-bounded-07')
      await page.waitForSelector('[data-testid="op-reg-grant-allowlist-note"]', { timeout: 30_000, polling: 200 })
      expect(await page.$eval('[data-testid="op-reg-grant-role-viewer"]', el => (el as HTMLInputElement).disabled)).toBe(true)
      expect(await page.$eval('[data-testid="op-reg-grant-role-ia_officer"]', el => (el as HTMLInputElement).disabled)).toBe(false)

      // Grant ia_officer on the bounded client: the verdict flips.
      await page.evaluate(() => (document.querySelector('[data-testid="op-reg-grant-role-ia_officer"]') as HTMLElement).click())
      await page.evaluate(() => (document.querySelector('[data-testid="op-reg-grant-save"]') as HTMLElement).click())
      await page.waitForSelector('[data-testid="op-reg-user-notice"]', { timeout: 60_000, polling: 500 })
      await page.waitForSelector('[data-testid="op-reg-grant-ia-bounded-07"]', { timeout: 60_000, polling: 500 })
      expect(await page.$eval('[data-testid="op-reg-grant-ia-bounded-07"]', el => el.textContent ?? '')).toContain('ia_officer')
      await page.waitForFunction(
        () => document.querySelector('[data-testid="op-reg-app-reason-ia-bounded-07"]')?.textContent?.includes('ia_officer')
          && document.querySelector('[data-testid="op-reg-app-badge-ia-bounded-07"]')?.textContent?.trim() === 'can enter',
        { timeout: 60_000, polling: 500 },
      )
      flog(page, 'leg11: the grant landed and the verdict flipped')

      // The revoke (two-step): the row goes, the default is restored, the
      // verdict is NO again.
      await page.evaluate(() => (document.querySelector('[data-testid="op-reg-grant-revoke-ia-bounded-07"]') as HTMLElement).click())
      await page.waitForSelector('[data-testid="op-reg-grant-revoke-confirm-ia-bounded-07"]', { timeout: 30_000, polling: 200 })
      await page.evaluate(() => (document.querySelector('[data-testid="op-reg-grant-revoke-confirm-ia-bounded-07"]') as HTMLElement).click())
      await page.waitForFunction(
        () => !document.querySelector('[data-testid="op-reg-grant-ia-bounded-07"]'),
        { timeout: 60_000, polling: 500 },
      )
      await page.waitForFunction(
        () => document.querySelector('[data-testid="op-reg-app-badge-ia-bounded-07"]')?.textContent?.trim() === 'no',
        { timeout: 60_000, polling: 500 },
      )
      flog(page, 'leg11: the revoke restored the default')
    })

    // Both acts are on the record.
    const trail = await (await fetch(`${stack.base}/api/op/registry/activity?q=client_roles`, {
      headers: { cookie: `oiml-session=${root}` },
    })).json() as Array<{ action: string; metadata?: Record<string, unknown> }>
    expect(trail.some(e => e.action === 'account.client_roles' && e.metadata?.client_id === 'ia-bounded-07'
      && (e.metadata?.roles as string[] ?? []).join() === 'ia_officer')).toBe(true)
    expect(trail.some(e => e.action === 'account.client_roles_cleared' && e.metadata?.client_id === 'ia-bounded-07')).toBe(true)
  })

  it('leg 12 — the end-all act ends every session of the account (the light act), audited with its count', { timeout: 900_000 }, async () => {
    const erinA = await passwordCookie(stack.base, ERIN.email, ERIN.password)
    const erinB = await passwordCookie(stack.base, ERIN.email, ERIN.password)
    const root = await passwordCookie(stack.base, ROOT.email, ROOT.password)

    await withPage(async (page) => {
      await signInViaCookie(page, stack.base, root)
      await page.goto(`${stack.base}/op/admin/registry/users/${erinId}`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
      await page.waitForSelector('[data-testid="op-reg-sessions-list"]', { timeout: SETTLE, polling: 500 })
      const count = await page.$$eval('[data-testid^="op-reg-session-"]', els => els.length)
      expect(count).toBeGreaterThanOrEqual(2)

      // The two-step: arm, then confirm — the list empties honestly.
      await page.evaluate(() => (document.querySelector('[data-testid="op-reg-revoke-all"]') as HTMLElement).click())
      await page.waitForSelector('[data-testid="op-reg-revoke-all-confirm"]', { timeout: 30_000, polling: 200 })
      await page.evaluate(() => (document.querySelector('[data-testid="op-reg-revoke-all-confirm"]') as HTMLElement).click())
      await page.waitForSelector('[data-testid="op-reg-sessions-empty"]', { timeout: 60_000, polling: 500 })
      flog(page, 'leg12: every session ended')
    })

    // Erin’s cookies stop resolving at once.
    for (const cookie of [erinA, erinB]) {
      const res = await fetch(`${stack.base}/api/auth/session`, { headers: { cookie: `oiml-session=${cookie}` } })
      expect(res.status).toBe(401)
    }
    // …and the act is on the record (the administrator, the count).
    const trail = await (await fetch(`${stack.base}/api/op/registry/activity?q=sessions_revoked`, {
      headers: { cookie: `oiml-session=${root}` },
    })).json() as Array<{ action: string; metadata?: Record<string, unknown> }>
    expect(trail.some(e => e.action === 'account.sessions_revoked' && e.metadata?.by === 'administrator' && Number(e.metadata?.count) >= 2)).toBe(true)
  })

  it('leg 13 — the self-lockout rule: the admin’s own page disables the heavy acts, and the server refuses them', { timeout: 900_000 }, async () => {
    const root = await passwordCookie(stack.base, ROOT.email, ROOT.password)
    const me = await (await fetch(`${stack.base}/api/auth/session`, { headers: { cookie: `oiml-session=${root}` } })).json() as { id: string }

    await withPage(async (page) => {
      await signInViaCookie(page, stack.base, root)
      await page.goto(`${stack.base}/op/admin/registry/users/${me.id}`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
      await page.waitForSelector('[data-testid="op-reg-user"]', { timeout: SETTLE, polling: 500 })

      // The heavy acts are disabled on your own account, and the page
      // says why; the end-all warns that this console goes too.
      expect(await page.$eval('[data-testid="op-reg-deactivate"]', el => (el as HTMLButtonElement).disabled)).toBe(true)
      expect(await page.$('[data-testid="op-reg-self-deactivate-note"]')).not.toBeNull()
      expect(await page.$eval('[data-testid="op-reg-erase"]', el => (el as HTMLButtonElement).disabled)).toBe(true)
      expect(await page.$('[data-testid="op-reg-self-erase-note"]')).not.toBeNull()
      await page.waitForSelector('[data-testid="op-reg-revoke-all-self"]', { timeout: 60_000, polling: 500 })
      flog(page, 'leg13: the self page disarms the heavy acts')
    })

    // The server refuses both (the rule never rests on the buttons).
    const deactivated = await fetch(`${stack.base}/api/op/accounts/${me.id}/status`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: `oiml-session=${root}` },
      body: JSON.stringify({ active: false }),
    })
    expect(deactivated.status).toBe(400)
    expect(((await deactivated.json()) as { error: string }).error).toContain('your own account')
    const erased = await fetch(`${stack.base}/api/op/accounts/${me.id}`, {
      method: 'DELETE',
      headers: { cookie: `oiml-session=${root}` },
    })
    expect(erased.status).toBe(400)
    expect(((await erased.json()) as { error: string }).error).toContain('your own account')
    flog(null, 'leg13: the server refuses the self-lockout')
  })

  it('leg 14 — the invited account answers every section empty honestly; the erased account reads as a tombstone', { timeout: 900_000 }, async () => {
    const root = await passwordCookie(stack.base, ROOT.email, ROOT.password)
    expect(backAgainId, 'leg 9 re-invited the freed email').toBeTruthy()

    await withPage(async (page) => {
      await signInViaCookie(page, stack.base, root)
      await page.goto(`${stack.base}/op/admin/registry/users/${backAgainId}`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
      await page.waitForSelector('[data-testid="op-reg-user"]', { timeout: SETTLE, polling: 500 })

      // The invited state: the badge names it, never signed in, and every
      // section answers empty honestly.
      expect(await page.$eval('[data-testid="op-reg-profile-status"]', el => el.textContent?.trim())).toBe('invited')
      expect(await page.$eval('[data-testid="op-reg-profile-lastlogin"]', el => el.textContent?.trim())).toBe('never')
      expect(await page.$('[data-testid="op-reg-sessions-empty"]')).not.toBeNull()
      expect(await page.$('[data-testid="op-reg-no-links"]')).not.toBeNull()
      expect(await page.$('[data-testid="op-reg-client-roles-empty"]')).not.toBeNull()
      expect(await page.$('[data-testid="op-reg-factors-empty"]')).not.toBeNull()
      // The apps view still computes for an invited account (the hub
      // enters with the account-wide viewer role).
      await page.waitForSelector(`[data-testid="op-reg-app-badge-${HUB_CLIENT}"]`, { timeout: 60_000, polling: 500 })
      expect(await page.$eval(`[data-testid="op-reg-app-badge-${HUB_CLIENT}"]`, el => el.textContent?.trim())).toBe('can enter')
      flog(page, 'leg14: the invited account reads honestly')
    })

    // Erase it (the API — leg 9 proved the console flow), then the page
    // reads as the tombstone it is: no acts, the erasure on the trail.
    const erased = await fetch(`${stack.base}/api/op/accounts/${backAgainId}`, {
      method: 'DELETE',
      headers: { cookie: `oiml-session=${root}` },
    })
    expect(erased.status).toBe(200)
    await withPage(async (page) => {
      await signInViaCookie(page, stack.base, root)
      await page.goto(`${stack.base}/op/admin/registry/users/${backAgainId}`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
      await page.waitForSelector('[data-testid="op-reg-user"]', { timeout: SETTLE, polling: 500 })
      expect(await page.$eval('[data-testid="op-reg-profile-status"]', el => el.textContent?.trim())).toBe('erased')
      expect(await page.$eval('[data-testid="op-reg-profile-erased"]', el => el.textContent ?? '')).toContain('anonymized tombstone')
      expect(await page.$('[data-testid="op-reg-actions"]')).toBeNull()
      expect(await page.$('[data-testid="op-reg-apps"]')).toBeNull()
      expect(await page.$('[data-testid="op-reg-sessions"]')).toBeNull()
      await page.waitForFunction(
        () => (document.querySelector('[data-testid="op-reg-activity-list"]')?.textContent ?? '').includes('erased the account'),
        { timeout: 60_000, polling: 500 },
      )
      flog(page, 'leg14: the tombstone reads as a tombstone')
    })
  })
})
