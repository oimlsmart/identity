// ═══════════════════════════════════════════════════════════════════
// TODO.identity-sso/01 — the admin dashboard, the e2e: the
// identity-profile stack (its own API + its own astro, the id-01/id-03
// spawned-stack pattern) plus a STUBBED GitHub Actions API (the
// heartbeat route reads the workflow history at its source — the stub
// makes the SLO panel deterministic) drive the console story in the
// browser:
//
//   leg 1  the OVERVIEW: /op/admin redirects to it; the tiles, the
//          14-day sign-in series, the anomaly counters, and the SLO
//          panel's green window (66.7% over the stub's three runs) with
//          the retention statement;
//   leg 2  the LIVE SESSIONS ladder: the invited account holds an API-
//          side session; the aggregate lists both accounts and marks
//          the administrator's own row; End session → that cookie stops
//          resolving; End all sessions (the light act, two-step) → the
//          account's fresh cookie stops too, the administrator's stands;
//          Deactivate (the heavy act, two-step) → the right-password
//          sign-in refuses honestly;
//   leg 3  the SECURITY surface: five failed passwords flag the burst
//          (the threshold is named), the audit log filters, the CSV
//          export answers an attachment over the current view, and the
//          live access review names the privileged holders;
//   leg 4  the CLIENTS activity: a real authorize→token exchange (the
//          API-side drive) lands client.token_issued, and the console's
//          per-client strip shows the issuance.
//
// SELF-CONTAINED: the suite's shared stack (E2E_BASE_URL) is untouched —
// the identity instance boots on its own ports (API 9893 / astro 9894,
// the GitHub stub on 9895) with its own SQLite file.
// ═══════════════════════════════════════════════════════════════════

import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import puppeteer, { type Browser, type Page } from 'puppeteer'
import { spawn, type ChildProcess } from 'node:child_process'
import { createServer, type Server } from 'node:http'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { existsSync, mkdirSync, rmSync, cpSync } from 'node:fs'
import { closeBrowser, delay } from './helpers'
import { fixtureOpSigningKey } from './fixtures/op-signing-key'
import { generatePkce } from '@oimlsmart/platform-server/oidc'

const BROWSER_DIR = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const FIXTURES = join(BROWSER_DIR, 'e2e', 'fixtures')
const DB_DIR = join(BROWSER_DIR, '.cache', 'id-11')

// Port-isolated: clear of every running leg (the registry lives in the
// sibling files' headers: shared 5190/3190, fed/id stacks through 9793,
// the id-03 stack 9393/9293/9294, the 9893/9894 pair).
const ID_API = 10093
const ID_WEB = 10094
const GH_STUB = 10095

const ISSUER = `http://localhost:${ID_WEB}`
const RP_CLIENT_ID = 'fixture-dash-rp'
const RP_CLIENT_SECRET = 'fixture-dash-rp-secret'

const VERA = {
  name: 'Ms. Vera Dashboard',
  email: 'vera.dashboard@example.org',
  password: 'vera dashboard passphrase',
}

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

/** Boot the identity-profile stack (the id-03 pattern) + the heartbeat
 *  route's source: a stub GitHub Actions API answering three runs. */
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
      // The heartbeat route's source is the stub (deterministic, never
      // the real GitHub).
      OP_HEARTBEAT_API_BASE: `http://127.0.0.1:${GH_STUB}`,
      OP_CLIENT_SEED: JSON.stringify([{
        client_id: RP_CLIENT_ID,
        name: 'The id-11 fixture RP',
        secret: RP_CLIENT_SECRET,
        redirect_uris: ['http://127.0.0.1:19894/callback'],
        claims_policy: { claims: ['roles'] },
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

/** Sign in through the demo cast (DEMO_ACCOUNTS_ENABLED=true). */
async function opSignIn(page: Page, email: string): Promise<void> {
  await page.waitForSelector('[data-testid="login-email"]', { timeout: SETTLE, polling: 500 })
  await page.evaluate(() => {
    (document.querySelector('[data-testid="login-email"]') as HTMLInputElement).value = ''
  })
  await page.type('[data-testid="login-email"]', email)
  await page.type('[data-testid="login-password"]', 'demo2026')
  await page.evaluate(() => (document.querySelector('[data-testid="login-submit"]') as HTMLElement).click())
}

/** A node-side password login against the API (a SECOND client's view —
 *  the revocation proofs never share the browser's cookie jar). */
async function apiPasswordLogin(stack: Stack, email: string, password: string): Promise<Response> {
  return fetch(`${stack.apiBase}/api/op/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password }),
  })
}

/** The admin-side invite through the API (the console's own route);
 *  answers the account id + the one-time setup URL. */
async function apiInvite(stack: Stack, adminCookie: string, name: string, email: string): Promise<{ id: string; setupUrl: string }> {
  const res = await fetch(`${stack.apiBase}/api/op/accounts`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', cookie: adminCookie },
    body: JSON.stringify({ name, email, role: 'viewer' }),
  })
  expect(res.status).toBe(201)
  const body = await res.json() as { account: { id: string }; setupUrl: string }
  return { id: body.account.id, setupUrl: body.setupUrl }
}

/** Complete the enrollment API-side (the browser never needs the link). */
async function apiEnroll(stack: Stack, setupUrl: string, password: string): Promise<void> {
  const token = new URL(setupUrl).searchParams.get('token')!
  const res = await fetch(`${stack.apiBase}/api/op/enroll/${token}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ password }),
  })
  expect(res.status).toBe(200)
}

/** The browser jar's admin cookie value, for API-side admin calls. */
async function adminCookie(page: Page): Promise<string> {
  const cookies = await page.cookies()
  const session = cookies.find(c => c.name === 'oiml_session' || c.name.endsWith('session'))
  expect(session, 'the admin session cookie').toBeTruthy()
  return `${session!.name}=${session!.value}`
}

describe('TODO.identity-sso/01 — the admin dashboard', () => {
  let stack: Stack
  let gh: Server
  let browser: Browser
  let page: Page
  let veraId = ''

  beforeAll(async () => {
    // The stubbed GitHub Actions API: three completed runs, two green.
    gh = createServer((req, res) => {
      res.writeHead(200, { 'content-type': 'application/json' })
      res.end(JSON.stringify({
        workflow_runs: [
          { id: 3, status: 'completed', conclusion: 'success', created_at: '2026-08-24T09:52:00Z', html_url: 'https://github.example/runs/3' },
          { id: 2, status: 'completed', conclusion: 'failure', created_at: '2026-08-24T09:37:00Z', html_url: 'https://github.example/runs/2' },
          { id: 1, status: 'completed', conclusion: 'success', created_at: '2026-08-24T09:22:00Z', html_url: 'https://github.example/runs/1' },
        ],
      }))
    })
    await new Promise<void>(resolveListen => gh.listen(GH_STUB, '127.0.0.1', resolveListen))

    stack = await bootIdentityStack()
    browser = await puppeteer.launch({ headless: 'shell', protocolTimeout: 480_000, args: ['--no-sandbox', '--disable-setuid-sandbox'] })
    page = await browser.newPage()
    await page.setViewport({ width: 1440, height: 900 })
    page.on('pageerror', e => console.log('[pageerror]', String(e).slice(0, 300)))
    page.on('requestfailed', r => console.log('[requestfailed]', r.url().slice(0, 140), r.failure()?.errorText ?? ''))
  }, 600_000)

  afterAll(async () => {
    await closeBrowser(browser)
    await new Promise<void>(r => gh?.close(() => r()))
    await stopStack(stack)
  })

  it('leg 1 — /op/admin lands on the overview: the tiles, the series, the stubbed SLO window', { timeout: 900_000 }, async () => {
    await page.goto(`${stack.base}/`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await opSignIn(page, 'admin@oiml.org')
    await page.waitForFunction(() => window.location.pathname !== '/', { timeout: SETTLE, polling: 500 })

    // The invite + the two sign-in outcomes give the tiles their numbers.
    const cookie = await adminCookie(page)
    const invited = await apiInvite(stack, cookie, VERA.name, VERA.email)
    veraId = invited.id
    await apiEnroll(stack, invited.setupUrl, VERA.password)
    expect((await apiPasswordLogin(stack, VERA.email, VERA.password)).ok).toBe(true)
    expect((await apiPasswordLogin(stack, VERA.email, 'the wrong passphrase')).status).toBe(401)

    await page.goto(`${stack.base}/op/admin`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await page.waitForFunction(() => window.location.pathname === '/op/admin/overview', { timeout: SETTLE, polling: 500 })
    await page.waitForSelector('[data-testid="op-dash-tiles"]', { timeout: SETTLE, polling: 500 })

    const accountsSplit = await page.$eval('[data-testid="op-dash-tile-accounts-split"]', el => el.textContent ?? '')
    expect(accountsSplit).toContain('active')
    expect(accountsSplit).toContain('deactivated')
    const live = await page.$eval('[data-testid="op-dash-live-sessions"]', el => el.textContent ?? '')
    expect(Number(live), 'the administrator + vera hold live sessions').toBeGreaterThanOrEqual(2)
    const anomalies = await page.$eval('[data-testid="op-dash-anomalies-split"]', el => el.textContent ?? '')
    expect(anomalies).toContain('failed sign-ins')

    // The sign-in series rendered its 14 UTC-day buckets.
    await page.waitForSelector('[data-testid="op-dash-signins-chart"]', { timeout: SETTLE, polling: 500 })

    // The SLO panel: the stub's three runs (two green) compute 66.7%.
    await page.waitForSelector('[data-testid="op-dash-slo-live"]', { timeout: SETTLE, polling: 500 })
    const rate = await page.$eval('[data-testid="op-dash-slo-rate"]', el => el.textContent ?? '')
    expect(rate).toContain('66.7%')
    const failures = await page.$eval('[data-testid="op-dash-slo-failures"]', el => el.textContent ?? '')
    expect(failures).toContain('the failed run')
    expect(await page.$('[data-testid="op-dash-slo-link"]')).not.toBeNull()
    const retention = await page.$eval('[data-testid="op-dash-retention"]', el => el.textContent ?? '')
    expect(retention).toContain('audit journal')
  })

  it('leg 2 — the live-sessions ladder: end one, end all (the light act), deactivate (the heavy act)', { timeout: 900_000 }, async () => {
    // Leg 1 left Vera a live API-side session; the row-level revoke proof
    // needs an UNAMBIGUOUS row, so the light act clears her deck first
    // (the view never exposes token values — a row cannot be mapped to a
    // cookie, so the proof drives the count to one).
    const admin = await adminCookie(page)
    const sweep = await fetch(`${stack.apiBase}/api/op/dashboard/accounts/${veraId}/sessions/revoke-all`, {
      method: 'POST',
      headers: { cookie: admin },
    })
    expect(sweep.ok).toBe(true)

    // Vera's one fresh API-side session (a second client's jar).
    const veraLogin = await apiPasswordLogin(stack, VERA.email, VERA.password)
    expect(veraLogin.ok).toBe(true)
    const veraCookie = veraLogin.headers.get('set-cookie')!.split(';')[0]!

    await page.goto(`${stack.base}/op/admin/sessions`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await page.waitForSelector('[data-testid="op-sess-list"]', { timeout: SETTLE, polling: 500 })

    // The aggregate shows her exactly once; the administrator's own row
    // is marked.
    await page.type('[data-testid="op-sess-filter"]', VERA.email)
    await page.waitForFunction(
      (email) => {
        const rows = [...document.querySelectorAll('[data-testid^="op-sess-row-"]')]
        return rows.length === 1 && rows[0]!.textContent?.includes(email)
      },
      { timeout: SETTLE, polling: 500 },
      VERA.email,
    )
    const rowId = await page.evaluate((email) => {
      const row = [...document.querySelectorAll('[data-testid^="op-sess-row-"]')]
        .find(el => el.textContent?.includes(email))
      return row?.getAttribute('data-testid')?.replace('op-sess-row-', '') ?? null
    }, VERA.email)
    expect(rowId, 'vera’s session row').toBeTruthy()

    // The administrator's own row carries the marker (clear the filter).
    await page.evaluate(() => {
      (document.querySelector('[data-testid="op-sess-filter"]') as HTMLInputElement).value = ''
      ;(document.querySelector('[data-testid="op-sess-filter"]') as HTMLInputElement).dispatchEvent(new Event('input'))
    })
    await page.waitForSelector('[data-testid^="op-sess-current-"]', { timeout: SETTLE, polling: 500 })

    // END ONE: the row's own session stops resolving.
    await page.evaluate((id) => {
      (document.querySelector(`[data-testid="op-sess-revoke-${id}"]`) as HTMLElement).click()
    }, rowId)
    await page.waitForSelector('[data-testid="op-sess-notice"]', { timeout: SETTLE, polling: 500 })
    expect((await fetch(`${stack.apiBase}/api/auth/session`, { headers: { cookie: veraCookie } })).status).toBe(401)

    // A FRESH session, then END ALL (the light act, two-step).
    const veraLogin2 = await apiPasswordLogin(stack, VERA.email, VERA.password)
    expect(veraLogin2.ok).toBe(true)
    const veraCookie2 = veraLogin2.headers.get('set-cookie')!.split(';')[0]!
    await page.goto(`${stack.base}/op/admin/sessions`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await page.waitForSelector(`[data-testid="op-sess-revoke-all-${veraId}"]`, { timeout: SETTLE, polling: 500 })
    await page.evaluate((id) => {
      (document.querySelector(`[data-testid="op-sess-revoke-all-${id}"]`) as HTMLElement).click()
    }, veraId)
    await page.waitForFunction(
      (id) => document.querySelector(`[data-testid="op-sess-revoke-all-${id}"]`)?.textContent?.includes('Confirm'),
      { timeout: SETTLE, polling: 500 },
      veraId,
    )
    await page.evaluate((id) => {
      (document.querySelector(`[data-testid="op-sess-revoke-all-${id}"]`) as HTMLElement).click()
    }, veraId)
    await page.waitForSelector('[data-testid="op-sess-notice"]', { timeout: SETTLE, polling: 500 })
    const notice = await page.$eval('[data-testid="op-sess-notice"]', el => el.textContent ?? '')
    expect(notice).toContain('session(s) ended')
    expect((await fetch(`${stack.apiBase}/api/auth/session`, { headers: { cookie: veraCookie2 } })).status).toBe(401)
    // The administrator's own session stands (the browser is the proof:
    // the page itself just reloaded the list under it).

    // DEACTIVATE (the heavy act, two-step): her right-password sign-in
    // refuses honestly afterwards.
    const veraLogin3 = await apiPasswordLogin(stack, VERA.email, VERA.password)
    expect(veraLogin3.ok).toBe(true)
    await page.goto(`${stack.base}/op/admin/sessions`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await page.waitForSelector(`[data-testid="op-sess-deactivate-${veraId}"]`, { timeout: SETTLE, polling: 500 })
    await page.evaluate((id) => {
      (document.querySelector(`[data-testid="op-sess-deactivate-${id}"]`) as HTMLElement).click()
    }, veraId)
    await page.waitForFunction(
      (id) => document.querySelector(`[data-testid="op-sess-deactivate-${id}"]`)?.textContent?.includes('Confirm'),
      { timeout: SETTLE, polling: 500 },
      veraId,
    )
    await page.evaluate((id) => {
      (document.querySelector(`[data-testid="op-sess-deactivate-${id}"]`) as HTMLElement).click()
    }, veraId)
    await page.waitForSelector('[data-testid="op-sess-notice"]', { timeout: SETTLE, polling: 500 })
    const heavy = await page.$eval('[data-testid="op-sess-notice"]', el => el.textContent ?? '')
    expect(heavy).toContain('deactivated')
    const refused = await apiPasswordLogin(stack, VERA.email, VERA.password)
    expect(refused.status).toBe(403)
    expect(((await refused.json()) as { error: string }).error).toContain('deactivated')
  })

  it('leg 3 — security: the burst flags, the log filters, the CSV exports, the review names the holders', { timeout: 900_000 }, async () => {
    // A fresh account takes the burst (vera's is deactivated; the failed
    // attempts on her are the deactivated class — the burst wants the
    // wrong-password class on a live account).
    const cookie = await adminCookie(page)
    const hammered = await apiInvite(stack, cookie, 'Ms. Hera Burst', 'hera.burst@example.org')
    await apiEnroll(stack, hammered.setupUrl, 'hera burst passphrase')
    for (let i = 0; i < 5; i++) {
      expect((await apiPasswordLogin(stack, 'hera.burst@example.org', 'wrong')).status).toBe(401)
    }

    await page.goto(`${stack.base}/op/admin/security`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await page.waitForSelector('[data-testid="op-sec-signals"]', { timeout: SETTLE, polling: 500 })
    await page.waitForSelector(`[data-testid="op-sec-burst-${hammered.id}"]`, { timeout: SETTLE, polling: 500 })
    const burst = await page.$eval(`[data-testid="op-sec-burst-${hammered.id}"]`, el => el.textContent ?? '')
    expect(burst).toContain('failed in 24 h')

    // The queryable log: the action filter narrows to the sign-in family.
    await page.waitForSelector('[data-testid="op-sec-audit-list"]', { timeout: SETTLE, polling: 500 })
    await page.select('[data-testid="op-sec-audit-action"]', 'account.sign_in')
    await page.waitForFunction(
      () => document.querySelector('[data-testid="op-sec-audit-count"]')?.textContent?.includes('row'),
      { timeout: SETTLE, polling: 500 },
    )
    await page.waitForFunction(
      () => {
        const items = [...document.querySelectorAll('[data-testid^="op-sec-audit-event-"]')]
        return items.length > 0 && items.every(el => el.textContent?.includes('account.sign_in'))
      },
      { timeout: SETTLE, polling: 500 },
    )

    // The CSV export answers an attachment over the current view (the
    // browser-side fetch carries the session cookie).
    const csv = await page.evaluate(async () => {
      const res = await fetch('/api/op/dashboard/audit?format=csv&action=account.sign_in', { credentials: 'include' })
      return {
        status: res.status,
        type: res.headers.get('content-type') ?? '',
        disposition: res.headers.get('content-disposition') ?? '',
        text: await res.text(),
      }
    })
    expect(csv.status).toBe(200)
    expect(csv.type).toContain('text/csv')
    expect(csv.disposition).toContain('attachment')
    expect(csv.text.split('\n')[0]).toBe('timestamp,action,entity_type,entity_id,user_name,user_id,metadata')
    expect(csv.text).toContain('account.sign_in_failed')

    // The live access review names the demo admin among the privileged.
    await page.waitForSelector('[data-testid="op-sec-review-holders"]', { timeout: SETTLE, polling: 500 })
    const holders = await page.$eval('[data-testid="op-sec-review-holders"]', el => el.textContent ?? '')
    expect(holders).toContain('admin@oiml.org')
  })

  it('leg 4 — the clients console: a real exchange lands the issuance; the strip shows it', { timeout: 900_000 }, async () => {
    // The API-side drive: a fresh account, a full authorize → consent →
    // token exchange against the seeded fixture client.
    const cookie = await adminCookie(page)
    const rp = await apiInvite(stack, cookie, 'Ms. Rhea Exchange', 'rhea.exchange@example.org')
    await apiEnroll(stack, rp.setupUrl, 'rhea exchange passphrase')
    const login = await apiPasswordLogin(stack, 'rhea.exchange@example.org', 'rhea exchange passphrase')
    const userCookie = login.headers.get('set-cookie')!.split(';')[0]!

    const pkce = await generatePkce()
    const query = new URLSearchParams({
      response_type: 'code',
      client_id: RP_CLIENT_ID,
      redirect_uri: 'http://127.0.0.1:19894/callback',
      scope: 'openid profile email',
      state: 'st-11',
      code_challenge: pkce.challenge,
      code_challenge_method: 'S256',
    })
    const authorize = await fetch(`${stack.apiBase}/op/authorize?${query}`, { headers: { cookie: userCookie }, redirect: 'manual' })
    expect(authorize.status).toBe(302)
    const authId = new URL(authorize.headers.get('location')!, ISSUER).searchParams.get('auth')!
    const decide = await fetch(`${stack.apiBase}/api/op/consent/${authId}/decide`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: userCookie },
      body: JSON.stringify({ decision: 'allow' }),
    })
    expect(decide.ok).toBe(true)
    const { redirect } = await decide.json() as { redirect: string }
    const code = new URL(redirect).searchParams.get('code')!
    const token = await fetch(`${stack.apiBase}/op/token`, {
      method: 'POST',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        authorization: `Basic ${Buffer.from(`${RP_CLIENT_ID}:${encodeURIComponent(RP_CLIENT_SECRET)}`).toString('base64')}`,
      },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: 'http://127.0.0.1:19894/callback',
        client_id: RP_CLIENT_ID,
        code_verifier: pkce.verifier,
      }),
    })
    expect(token.status).toBe(200)

    // The console's strip shows the issuance on the fixture client's row.
    await page.goto(`${stack.base}/op/admin/clients`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await page.waitForSelector(`[data-testid="op-client-${RP_CLIENT_ID}"]`, { timeout: SETTLE, polling: 500 })
    await page.waitForSelector(`[data-testid="op-client-activity-${RP_CLIENT_ID}"]`, { timeout: SETTLE, polling: 500 })
    const strip = await page.$eval(`[data-testid="op-client-activity-${RP_CLIENT_ID}"]`, el => el.textContent ?? '')
    expect(strip).toContain('1 token issuance(s)')
    expect(strip).toContain('last')
  })
})
