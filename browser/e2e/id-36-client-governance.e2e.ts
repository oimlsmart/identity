// ═══════════════════════════════════════════════════════════════════
// TODO.identity-sso (the client-registry governance console) — the
// governance view's e2e: the identity-profile stack (its own API + its
// own astro, the id-34 spawned-stack pattern) and the fixture Relying
// Party (e2e/fixtures/stub-rp.ts) prove the read-only per-client
// governance surface over real HTTP and the real UI, no stubs on the OP
// side:
//
//   leg 1  THE API: the browser signs tl@oiml.org in through the RP with
//          the offline ask (the consent grant + the rotation family land
//          for the fixture client); the governance endpoint — read as
//          the ADMIN over the wire — answers the client slice (the
//          registry truth, the derived class), the WHOLE consent history
//          (the account's grant, resolved name + email), the population
//          counts (1 live session token, 1 live offline grant), and the
//          audit slice (the account-side consent_granted ∪ the
//          client-side token_issued) — and NEVER a token value (the
//          RP-captured tokens are asserted absent from the body). The
//          gate holds over the wire: anonymous 401, the plain account
//          403, the unknown client 404. Then the account console's OWN
//          revoke act (tl@'s DELETE over HTTP) lands and the governance
//          re-read shows the history: the grant stays LISTED, revoked,
//          the offline count falls to 0, the audit slice gains
//          account.consent_revoked;
//   leg 2  THE CONSOLE: the admin opens /op/admin/clients in the real
//          browser, expands the fixture client's governance panel, and
//          the rendered view carries the same truth: the tokens line,
//          the grants list with the REVOKED badge (leg 1's revoke —
//          the account console would hide the row), the audit slice.
//
// SELF-CONTAINED: the suite's shared stack (E2E_BASE_URL) is untouched —
// own ports (API 10644 / astro 10645 / fixture RP 10646 — above id-35's
// 10641-10643), own SQLite file.
//
// THE BROWSER IS PER-LEG (the id-02 lesson); cross-leg state rides the
// DATABASE + the fixture RP's capture.
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

const BROWSER_DIR = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const FIXTURES = join(BROWSER_DIR, 'e2e', 'fixtures')
const DB_DIR = join(BROWSER_DIR, '.cache', 'id-36')

// Port-isolated: above id-35's 10641-10643.
const ID_API = 10644
const ID_WEB = 10645
const RP_PORT = 10646

const ISSUER = `http://localhost:${ID_WEB}` // the astro origin (the browser's OP)
const RP_CLIENT_ID = 'fixture-rp'
const RP_CLIENT_SECRET = 'fixture-rp-secret'
const ACCOUNT = 'tl@oiml.org' // the demo cast (dev-reset seeds it; the form takes demo2026)
const ADMIN = 'admin@oiml.org'

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

/** Boot the identity-profile stack with the client registry's fixture RP
 *  seed — the wave-C shape: a plain confidential application client (the
 *  offline grant's home). */
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
    // OIDC_* scrubbed + the demo override ON (the id-01 doctrine: a CI
    // e2e job's SUITE-stack SSO posture must not leak into this stack).
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

const SETTLE = 240_000 // spawned astro compiles page chunks cold on first hit

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

/** Sign in at the OP through the form (the demo cast's password). */
async function opSignIn(page: Page, email: string): Promise<void> {
  await page.waitForSelector('[data-testid="login-email"]', { timeout: SETTLE, polling: 500 })
  await page.evaluate(() => {
    (document.querySelector('[data-testid="login-email"]') as HTMLInputElement).value = ''
  })
  await page.type('[data-testid="login-email"]', email)
  await page.type('[data-testid="login-password"]', 'demo2026')
  await page.evaluate(() => (document.querySelector('[data-testid="login-submit"]') as HTMLElement).click())
}

/** The RP round trip through the REAL browser (the id-33 driver): the
 *  consent page shows for the first grant (a REMEMBERED grant skips it —
 *  the driver tolerates both); a missing session lands on the sign-in
 *  form first. */
async function rpRoundTrip(page: Page, rp: StubRp, signInAs?: string): Promise<void> {
  await page.goto(`${rp.baseUrl}/signin`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
  const consentSel = '[data-testid="op-consent-allow"]'
  const loginSel = '[data-testid="login-email"]'
  const doneSel = '[data-testid="rp-signed-in"]'
  await page.waitForFunction(
    (a: string, b: string, c: string) => Boolean(document.querySelector(a) || document.querySelector(b) || document.querySelector(c)),
    { timeout: SETTLE, polling: 500 },
    consentSel, loginSel, doneSel,
  )
  if (signInAs && await page.$(loginSel)) {
    await opSignIn(page, signInAs)
  }
  await page.waitForFunction(
    (a: string, b: string) => Boolean(document.querySelector(a) || document.querySelector(b)),
    { timeout: SETTLE, polling: 500 },
    consentSel, doneSel,
  )
  if (await page.$(consentSel)) {
    await page.evaluate((sel) => (document.querySelector(sel) as HTMLElement).click(), consentSel)
  }
  await page.waitForSelector(doneSel, { timeout: SETTLE, polling: 500 })
}

/** The fixture RP's assertion surface. */
async function rpWhoami(rp: StubRp): Promise<{
  claims: (Record<string, unknown> & { sub: string }) | null
  lastAccessToken: string | null
  lastRefreshToken: string | null
}> {
  return (await (await fetch(`${rp.baseUrl}/whoami`)).json()) as never
}

/** A demo-cast session cookie over the wire (the admin/console API reads). */
async function demoCookie(base: string, email: string): Promise<string> {
  const res = await fetch(`${base}/api/auth/demo`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password: 'demo2026' }),
  })
  expect(res.ok, `the demo login of ${email}`).toBe(true)
  return res.headers.get('set-cookie')!.split(';')[0]!
}

/** The governance answer, typed at the shape the console renders. */
interface GovernanceAnswer {
  client: { clientId: string; name: string; class: string; status: string; confidential: boolean }
  grants: Array<{
    id: string
    account: { id: string; name: string | null; email: string | null } | null
    scope: string
    createdAt: string
    revokedAt: string | null
  }>
  tokens: { accessLive: number; refreshLive: number }
  audit: Array<{
    at: string
    action: string
    actor: string | null
    account: { id: string; name: string | null; email: string | null } | null
    metadata: Record<string, unknown>
  }>
}

describe('TODO.identity-sso (the client-registry governance console) — the per-client governance view (the identity profile)', () => {
  let stack: Stack
  let rp: StubRp

  beforeAll(async () => {
    stack = await bootIdentityStack()
    rp = await startStubRp({
      port: RP_PORT,
      issuer: ISSUER,
      clientId: RP_CLIENT_ID,
      clientSecret: RP_CLIENT_SECRET,
      scopes: 'openid profile email offline_access', // the offline ask
    })
  }, 600_000)

  afterAll(async () => {
    await rp?.close()
    await stopStack(stack)
  })

  it('leg 1 — the API: the whole consent history + the population counts + the audit slice over the wire, the gate held, never a token value; the account’s own revoke lands in the re-read', { timeout: 900_000 }, async () => {
    // The offline sign-in through the RP (the browser drives the consent
    // page — the grant + the rotation family land for the fixture client).
    await withPage(async (page) => {
      flog(page, 'leg1: the offline sign-in round trip')
      await rpRoundTrip(page, rp, ACCOUNT)
      const who = await rpWhoami(rp)
      expect(who.claims?.email, 'the RP-validated sign-in landed').toBe(ACCOUNT)
      expect(who.lastRefreshToken, 'the offline grant carried the refresh token').toBeTruthy()

      const url = `${stack.apiBase}/api/op/dashboard/clients/${RP_CLIENT_ID}/governance`

      // ── THE GATE over the wire ──
      expect((await fetch(url)).status, 'the anonymous ask').toBe(401)
      const memberCookie = await demoCookie(stack.apiBase, ACCOUNT)
      expect((await fetch(url, { headers: { cookie: memberCookie } })).status, 'the plain account').toBe(403)
      const adminCookie = await demoCookie(stack.apiBase, ADMIN)
      expect((await fetch(`${stack.apiBase}/api/op/dashboard/clients/never-registered/governance`, { headers: { cookie: adminCookie } })).status,
        'the unknown client answers the honest 404').toBe(404)

      // ── THE ANSWER ──
      const res = await fetch(url, { headers: { cookie: adminCookie } })
      expect(res.status, 'the admin read').toBe(200)
      const before = await res.json() as GovernanceAnswer
      expect(before.client.clientId).toBe(RP_CLIENT_ID)
      expect(before.client.class, 'the fixture RP is the application class').toBe('application')
      expect(before.client.confidential).toBe(true)
      expect(before.client.status).toBe('active')
      expect(before.grants.length, 'the one consent grant').toBe(1)
      expect(before.grants[0]!.account?.email).toBe(ACCOUNT)
      expect(before.grants[0]!.account?.name).toBe('TL Operator')
      expect(before.grants[0]!.revokedAt, 'live').toBeNull()
      expect(before.tokens.refreshLive, 'the offline grant stands').toBe(1)
      expect(before.tokens.accessLive, 'the exchange’s mint').toBe(1)
      const actions = before.audit.map(e => e.action)
      expect(actions, 'the account-side consent act names the client').toContain('account.consent_granted')
      expect(actions, 'the client-side issuance act').toContain('client.token_issued')
      expect(before.audit[0]!.at >= before.audit[1]!.at, 'newest first').toBe(true)

      // ── THE SILENCE: the RP-captured token values never ride the body ──
      const bodyText = JSON.stringify(before)
      expect(bodyText.includes(who.lastAccessToken!), 'no access token value').toBe(false)
      expect(bodyText.includes(who.lastRefreshToken!), 'no refresh token value').toBe(false)

      // ── the account console's OWN revoke (tl@'s act over HTTP), then
      // the governance re-read shows the HISTORY ──
      const grantsList = await (await fetch(`${stack.apiBase}/api/op/account/grants`, { headers: { cookie: memberCookie } })).json() as {
        grants: Array<{ id: string; clientId: string }>
      }
      const grantId = grantsList.grants.find(g => g.clientId === RP_CLIENT_ID)!.id
      const revoke = await fetch(`${stack.apiBase}/api/op/account/grants/${grantId}`, { method: 'DELETE', headers: { cookie: memberCookie } })
      expect(revoke.status, 'the account console’s revoke').toBe(200)

      const after = await (await fetch(url, { headers: { cookie: adminCookie } })).json() as GovernanceAnswer
      expect(after.grants.length, 'the history survives the revoke — the governance view lists what the account console now hides').toBe(1)
      expect(after.grants[0]!.revokedAt, 'the revoked stamp').toBeTruthy()
      expect(after.tokens.refreshLive, 'the companion delete carried the offline half out').toBe(0)
      const revokedEvt = after.audit.find(e => e.action === 'account.consent_revoked')
      expect(revokedEvt, 'the account-side revoke act names the client').toBeTruthy()
      expect(revokedEvt!.metadata.client).toBe(RP_CLIENT_ID)
      expect(revokedEvt!.account?.email).toBe(ACCOUNT)
      flog(page, 'leg1: done')
    })
  })

  it('leg 2 — the console: the admin’s clients page renders the governance expansion (the revoked grant’s badge included)', { timeout: 900_000 }, async () => {
    await withPage(async (page) => {
      flog(page, 'leg2: the admin console')
      // The page's own posture: unauthenticated lands on the sign-in form
      // (the load's 401 redirects with ?redirect=), the admin's sign-in
      // returns to the console.
      await page.goto(`${stack.base}/op/admin/clients`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
      await page.waitForFunction(
        () => Boolean(document.querySelector('[data-testid="login-email"]') || document.querySelector('[data-testid="op-clients-list"]')),
        { timeout: SETTLE, polling: 500 },
      )
      if (await page.$('[data-testid="login-email"]')) {
        await opSignIn(page, ADMIN)
      }
      await page.waitForSelector(`[data-testid="op-client-${RP_CLIENT_ID}"]`, { timeout: SETTLE, polling: 500 })

      // Expand the fixture client's governance view.
      await page.evaluate((id) => (document.querySelector(`[data-testid="op-client-governance-toggle-${id}"]`) as HTMLElement).click(), RP_CLIENT_ID)
      await page.waitForSelector(`[data-testid="op-client-governance-tokens-${RP_CLIENT_ID}"]`, { timeout: SETTLE, polling: 500 })

      const tokensLine = await page.evaluate((id) => document.querySelector(`[data-testid="op-client-governance-tokens-${id}"]`)!.textContent!, RP_CLIENT_ID)
      expect(tokensLine, 'the counts line: the access row keeps its hour, the offline half is gone').toMatch(/1 session token\(s\).*0 offline grant\(s\)/)

      const grants = await page.evaluate((id) => document.querySelector(`[data-testid="op-client-governance-grants-${id}"]`)!.textContent!, RP_CLIENT_ID)
      expect(grants, 'the account resolves').toContain(ACCOUNT)
      expect(grants, 'the revoked badge renders (the account console would hide the row)').toContain('revoked')

      const audit = await page.evaluate((id) => document.querySelector(`[data-testid="op-client-governance-audit-${id}"]`)!.textContent!, RP_CLIENT_ID)
      expect(audit, 'the account-side acts').toContain('account.consent_granted')
      expect(audit, 'the revoke act').toContain('account.consent_revoked')
      expect(audit, 'the client-side acts').toContain('client.token_issued')
      flog(page, 'leg2: done')
    })
  })
})
