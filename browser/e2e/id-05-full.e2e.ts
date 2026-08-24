// ═══════════════════════════════════════════════════════════════════
// TODO.identity/05: the program capstone, the FULL identity arc, in one
// narrative — the OP-SIDE successor of the monorepo's id-05-full (the
// extraction map's OP/RP split, smart's PROGRESS/41 §5). The spawned
// identity stack (the id-01 posture) plus the stub GitHub (the OP's
// upstream provider, e2e/fixtures/stub-github.ts) plus the fixture
// relying party (e2e/fixtures/stub-rp.ts — the REAL RP client code, so
// the token assertions are the RP-validated claims):
//
//   leg 1  ENROLL: the OP admin invites Vera (tl_operator assigned on
//          the RP's client, TODO.identity/03's per-client set); she
//          drives the one-time setup link in the browser (the real
//          /op/setup page) and lands on her account console; the used
//          link then answers its honest card;
//   leg 2  THE OIDC ROUND TRIP: from the RP's /signin through the OP
//          (authorize → the OP's password sign-in → the consent that
//          honestly names tl_operator → the one-time code → the token
//          exchange → the RP's validation against the OP's JWKS) — the
//          RP-validated claims carry her email and the assigned role;
//   leg 3  LINK UPSTREAM: signed in at the OP, Vera links her GitHub
//          from the account console (the registry-driven button, the
//          signed state, the stub round trip); the link keys on the
//          provider account id, never the email (the stub's fixture
//          email deliberately differs);
//   leg 4  GITHUB-THROUGH-THE-OP: signed out, she signs in from the RP
//          again; the OP's sign-in surface offers the GitHub button
//          mid-authorize, the link resolves, the consent shows, and the
//          RP validates the SAME account's token (the RP only ever
//          talks to the OP);
//   leg 5  ORG ADMINISTRATION (TODO.identity/10): the scheme operator
//          creates the registered Utilizer's org admin (the org-invites
//          seam), the reviewer files a join request on the public page
//          picking THEIR org from the register, the org admin approves
//          (the invite issues), and the reviewer enrolls; the session
//          carries the org binding;
//   leg 6  PER-CLIENT ROLES GOVERN THE TOKEN: with the EXPLICIT EMPTY
//          assignment on the RP's client, the consent says "no platform
//          roles" and the RP-validated token carries NO roles claim;
//          the admin then assigns viewer on the client and the next
//          sign-in's token carries it;
//   leg 7  DEACTIVATION: the OP admin deactivates Vera; her live OP
//          session is revoked in the same act, and her next sign-in
//          never leaves the OP: the OP's own sign-in surface refuses
//          the RIGHT password with the honest "deactivated" message;
//   leg 8  REACTIVATION: the admin reactivates her (the rows, the
//          assignments, the GitHub link all kept) and she signs in from
//          the RP through the OP via the LINKED GitHub — the RP
//          validates the token again.
//
// What this file deliberately does NOT assert: the relying party's
// claim MAPPING, its approval queue, its console landings. Those are
// the platform half (the monorepo's RP-side legs over its stub-IdP
// pattern); the REAL cross-repo round trip is the deploy gate's
// preview probe.
//
// SELF-CONTAINED: the suite's shared stack (E2E_BASE_URL) is untouched:
// the stack boots on its own ports with its own SQLite file.
//
// Port-isolated: OP API 9592 / OP astro 9593 / the fixture RP on
// 127.0.0.1:9596; clear of the shared dev stack (5190/3190), the id-01
// stack (8693/8393/8694), id-02 (8793/8593/8794), id-09 (8795/8595),
// id-08 (8993/8893/8994), id-10 (9193/9093), id-03 (9393/9293/9294),
// id-07 (9293/9294), id-06 (9493/9393), id-04-op-side
// (9492/9493/9494) and op-key-rotate (9693/9695).
//
// THE BROWSER IS PER-LEG (the id-02 lesson): a long-lived headless-shell
// launched during a load spike wedges silently; a fresh browser per leg
// costs ~2 s and dodges the class. The fresh browser also answers the
// cookie discipline: no OP session survives into a new leg, so every
// sign-in leg re-authenticates at the OP. Cross-leg state rides the
// DATABASE (the OP's accounts/links/assignments).
// ═══════════════════════════════════════════════════════════════════

import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import puppeteer, { type Browser, type Page } from 'puppeteer'
import { spawn, type ChildProcess } from 'node:child_process'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { existsSync, mkdirSync, rmSync, cpSync, appendFileSync } from 'node:fs'
import { closeBrowser, delay } from './helpers'
import { fixtureOpSigningKey } from './fixtures/op-signing-key'
import { startStubGitHub, type StubGitHub } from './fixtures/stub-github'
import { startStubRp, type StubRp } from './fixtures/stub-rp'

const BROWSER_DIR = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const FIXTURES = join(BROWSER_DIR, 'e2e', 'fixtures')
const DB_DIR = join(BROWSER_DIR, '.cache', 'id-05')

const OP_API = 9592
const OP_WEB = 9593
const RP_PORT = 9596

const ISSUER = `http://localhost:${OP_WEB}` // the OP's astro origin
const CLIENT_ID = 'id05-rp'
const CLIENT_SECRET = 'id05-rp-secret'

// The fixture cast. VERA is the arc's subject (enroll → sign in → link →
// upstream sign-in → deactivation → reactivation); her GitHub fixture
// carries a DIFFERENT email on purpose; the match keys on the provider
// account id, never the address. OREN is the registered Utilizer's org
// admin; PRIYA the reviewer his queue approves.
const VERA = { name: 'Ms. Vera Fullarc', email: 'vera.fullarc@example.org', password: 'vera fullarc passphrase' }
const GH_VERA = { login: 'octocat-vera', id: 305, name: 'Octo Vera', email: 'vera-gh@example.org' }
const UTILIZER_ID = 'ut-nmi-nl'
const UTILIZER_NAME = 'Example Metrology Authority (Netherlands)'
const OREN = { name: 'Mr. Oren Degaard', email: 'oren.degaard@nmi.example.org', password: 'oren degaard admin passphrase' }
const PRIYA = { name: 'Ms. Priya Woud', email: 'priya.woud@nmi.example.org', password: 'priya woud reviewer passphrase' }

interface Stack {
  api: ChildProcess
  astro: ChildProcess
  base: string
  apiBase: string
  logs: string[]
}

function spawnLogged(cmd: string, args: string[], env: NodeJS.ProcessEnv, logs: string[]): ChildProcess {
  // detached (the process group dies together; the tsx CLI wrapper
  // lesson); the env SCRUBS the vitest markers (NODE_ENV=test would
  // poison the spawned astro's vite cache hash; the 2026-08-14 stall).
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

/** Boot the identity stack: the API on its own SQLite file, the profile
 *  seed through the dev-reset seam, astro dev against it (the private
 *  vite cache seeded from the shared one — the fed-01 lesson). The
 *  identity profile, the demo cast for the admin legs, the fixture RP
 *  registered WITH its role allowlist (TODO.identity/03), and the stub
 *  GitHub as an upstream REGISTRY ROW (TODO.identity/08; a provider is a
 *  row, never a code fork; the secret resolves from the env by
 *  reference, the endpoints ride the GHES seam to the stub). A CI e2e
 *  job declares the SUITE stack's posture in the shared env; this stack
 *  must not inherit it (the id-08 discipline). */
async function bootOpStack(github: StubGitHub): Promise<Stack> {
  const logs: string[] = []
  mkdirSync(DB_DIR, { recursive: true })
  const dbPath = join(DB_DIR, 'identity.db')
  for (const suffix of ['', '-wal', '-shm']) rmSync(dbPath + suffix, { force: true })

  let api: ChildProcess | undefined
  let astro: ChildProcess | undefined
  try {
    for (const probe of [`http://localhost:${OP_API}/api/health`, `http://localhost:${OP_WEB}/`]) {
      try {
        const res = await fetch(probe)
        if (res.status < 500) throw new Error(`port for ${probe} is already serving; a leftover stack? (kill it: lsof -ti tcp:${new URL(probe).port} | xargs kill)`)
      } catch (e) {
        if (e instanceof Error && e.message.includes('already serving')) throw e
      }
    }

    // The tsx CLI directly (never npx; the wrapper orphans the server).
    api = spawnLogged(join(BROWSER_DIR, 'node_modules', '.bin', 'tsx'), ['server/serve.ts'], {
      PORT: String(OP_API),
      DATABASE_PATH: dbPath,
      ENTITY_BACKEND: 'server',
      INSTANCE_PROFILE: join(FIXTURES, 'instance.profile.identity.yaml'),
      OIDC_ISSUER: '',
      OIDC_CLIENT_ID: '',
      OIDC_CLAIM_MAPPING: '',
      DEMO_ACCOUNTS_ENABLED: 'true',
      OP_ISSUER: ISSUER,
      // identity#7: a declared-issuer stack declares its signing key too
      // (the generated dev key never registers off the dev posture).
      OP_SIGNING_KEY: await fixtureOpSigningKey(),
      OP_CLIENT_SEED: JSON.stringify([{
        client_id: CLIENT_ID,
        name: 'The id-05 fixture RP',
        secret: CLIENT_SECRET,
        redirect_uris: [`http://127.0.0.1:${RP_PORT}/callback`],
        // The allowlist bounds WHICH roles this client's tokens may
        // carry: tl_operator (Vera) and viewer (the reviewer).
        claims_policy: { claims: ['roles', 'groups', 'org'], roles: ['ia_officer', 'tl_operator', 'viewer'] },
      }]),
      OP_UPSTREAM_SEED: JSON.stringify([{
        id: 'github',
        kind: 'github',
        display_name: 'GitHub',
        brand_mark: 'github',
        client_id: 'id05-op',
        client_secret_ref: 'env:ID05_GH_SECRET',
        enabled: true,
      }]),
      ID05_GH_SECRET: 'id05-gh-secret',
      GITHUB_OAUTH_BASE_URL: github.baseUrl,
      GITHUB_API_BASE_URL: github.baseUrl,
    }, logs)
    const apiBase = `http://localhost:${OP_API}`
    await waitForHttp(`${apiBase}/api/health`, 120_000, logs)

    // Provision the profile's seed (the demo cast + the register snapshot).
    const reset = await fetch(`${apiBase}/api/dev-reset`, { method: 'POST' })
    if (!reset.ok) throw new Error(`dev-reset on ${apiBase} answered ${reset.status}\n${logs.join('').slice(-2000)}`)

    const stackViteCache = join(DB_DIR, `vite-${OP_WEB}`)
    const sharedViteCache = join(BROWSER_DIR, 'node_modules', '.vite')
    if (existsSync(sharedViteCache)) {
      rmSync(stackViteCache, { recursive: true, force: true })
      cpSync(sharedViteCache, stackViteCache, { recursive: true })
    }
    astro = spawnLogged(join(BROWSER_DIR, 'node_modules', '.bin', 'astro'), ['dev', '--port', String(OP_WEB), '--ignore-lock'], {
      API_ORIGIN: apiBase,
      VITE_CACHE_DIR: stackViteCache,
      DEV_PUBLIC_HOST: `localhost:${OP_WEB}`,
    }, logs)
    const base = `http://localhost:${OP_WEB}`
    await waitForHttp(`${base}/`, 240_000, logs)
    // Gate on a routed page (astro answers `/` before its route table
    // finishes; the fed-01 stall class — and here the root IS the
    // sign-in page, so the table-bound gate is /op/join).
    await waitForHttp(`${base}/op/join`, 240_000, logs, true)
    return { api, astro, base, apiBase, logs }
  } catch (e) {
    for (const proc of [astro, api]) killTreeHard(proc)
    throw e
  }
}

async function stopStack(stack: Stack | undefined): Promise<void> {
  if (!stack) return
  for (const proc of [stack.astro, stack.api]) killTree(proc)
  await delay(1_500)
  for (const proc of [stack.astro, stack.api]) killTreeHard(proc)
}

const SETTLE = 240_000 // a spawned astro compiles page chunks cold on first hit
// The FIRST /app/* navigation of a run compiles the whole page island;
// on a contended host that cold compile outlives SETTLE (the id-02
// lesson). The first account-page wait of each leg carries this budget;
// once warm, the later waits are cheap.
const APP_COLD = 840_000

/** Progress outside vitest's per-test console capture (a stalled browser
 *  makes the suite silent until the file ends; this log is live). */
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
    page.on('console', m => { if (m.type() === 'error') flog(page, `[browser] ${m.text().slice(0, 300)}`) })
    page.on('requestfailed', r => {
      if (r.url().includes('fonts.g')) return // the font CDN is irrelevant to the flows
      flog(page, `[requestfailed] ${r.url().slice(0, 140)} ${r.failure()?.errorText ?? ''}`)
    })
    await fn(page)
  } finally {
    await closeBrowser(browser)
  }
}

/** The OP admin's session cookie (the demo cast's administrator) for the
 *  registry's API acts. */
async function opAdminCookie(op: Stack): Promise<string> {
  const res = await fetch(`${op.apiBase}/api/auth/demo`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email: 'admin@oiml.org', password: 'demo2026' }),
  })
  if (!res.ok) throw new Error(`the OP admin demo login → ${res.status}`)
  return res.headers.get('set-cookie')!.split(';')[0]!
}

/** An OP PASSWORD account's session cookie over the API (02's accounts). */
async function opPasswordCookie(op: Stack, email: string, password: string): Promise<string> {
  const res = await fetch(`${op.apiBase}/api/op/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password }),
  })
  if (!res.ok) throw new Error(`the OP password login for ${email} → ${res.status}`)
  return res.headers.get('set-cookie')!.split(';')[0]!
}

/** The invite over the OP's real API: the account + its per-client role
 *  assignment + the one-time setup link (no mailer configured here; the
 *  response hands the link to the admin for the out-of-band handover). */
async function opInviteAccount(
  op: Stack,
  account: { name: string; email: string },
  clientRoles: string[],
): Promise<{ id: string; setupUrl: string }> {
  const admin = await opAdminCookie(op)
  const invite = await fetch(`${op.apiBase}/api/op/accounts`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', cookie: admin },
    body: JSON.stringify({
      email: account.email,
      name: account.name,
      role: 'viewer', // the OP-side default; the per-client set rules the RP's token
      client_roles: [{ client_id: CLIENT_ID, roles: clientRoles }],
    }),
  })
  if (!invite.ok) throw new Error(`the invite for ${account.email} → ${invite.status}: ${await invite.text()}`)
  const { account: invited, setupUrl } = await invite.json() as { account: { id: string }; setupUrl: string }
  return { id: invited.id, setupUrl }
}

/** Assign (or explicitly empty) an account's roles on the RP's client;
 *  TODO.identity/03's per-client act over the API. */
async function opAssignClientRoles(op: Stack, accountId: string, roles: string[]): Promise<void> {
  const admin = await opAdminCookie(op)
  const res = await fetch(`${op.apiBase}/api/op/accounts/${accountId}/client-roles/${CLIENT_ID}`, {
    method: 'PUT',
    headers: { 'content-type': 'application/json', cookie: admin },
    body: JSON.stringify({ roles }),
  })
  if (!res.ok) throw new Error(`the client-roles assignment for ${accountId} → ${res.status}: ${await res.text()}`)
}

/** Deactivate/reactivate over the API (03's honest deactivation). */
async function opSetActive(op: Stack, accountId: string, active: boolean): Promise<void> {
  const admin = await opAdminCookie(op)
  const res = await fetch(`${op.apiBase}/api/op/accounts/${accountId}/status`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', cookie: admin },
    body: JSON.stringify({ active }),
  })
  if (!res.ok) throw new Error(`the status act for ${accountId} → ${res.status}: ${await res.text()}`)
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
  await page.waitForSelector('[data-testid="account-name"]', { timeout: APP_COLD, polling: 500 })
  expect(new URL(page.url()).pathname).toBe('/op/account')
}

/** The OP's password sign-in through the login page form (clears first). */
async function opPasswordSignIn(page: Page, email: string, password: string): Promise<void> {
  await page.waitForSelector('[data-testid="login-email"]', { timeout: SETTLE, polling: 500 })
  await page.evaluate(() => {
    (document.querySelector('[data-testid="login-email"]') as HTMLInputElement).value = ''
  })
  await page.type('[data-testid="login-email"]', email)
  await page.type('[data-testid="login-password"]', password)
  await page.evaluate(() => (document.querySelector('[data-testid="login-submit"]') as HTMLElement).click())
}

/** The full round trip from the fixture RP's /signin to the OP's consent
 *  page: the RP's real authorization request, the OP's password sign-in
 *  mid-authorize, then the consent. Leaves the browser ON the consent
 *  page (the caller reads the honest claim preview, then clicks allow). */
async function rpSignInToConsent(page: Page, rp: StubRp, account: { email: string; password: string }): Promise<void> {
  await page.goto(`${rp.baseUrl}/signin`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
  // The OP's sign-in surface (its own login page, the redirect re-entry).
  await page.waitForFunction(
    (opPort) => window.location.port === opPort && window.location.pathname === '/' && window.location.search.includes('redirect='),
    { timeout: SETTLE, polling: 500 },
    String(OP_WEB),
  )
  await opPasswordSignIn(page, account.email, account.password)
  await page.waitForSelector('[data-testid="op-consent-allow"]', { timeout: SETTLE, polling: 500 })
}

/** The same arc through the OP's GITHUB upstream button (the registry
 *  row) mid-authorize — the account's linked method carries the
 *  sign-in. Leaves the browser ON the consent page. */
async function rpViaGitHubToConsent(page: Page, rp: StubRp, login: string): Promise<void> {
  await page.goto(`${rp.baseUrl}/signin`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
  await page.waitForFunction(
    (opPort) => window.location.port === opPort && window.location.pathname === '/' && window.location.search.includes('redirect='),
    { timeout: SETTLE, polling: 500 },
    String(OP_WEB),
  )
  await page.waitForSelector('[data-testid="upstream-login-github"]', { timeout: SETTLE, polling: 500 })
  await interceptStubGitHub(page, login)
  try {
    await page.evaluate(() => (document.querySelector('[data-testid="upstream-login-github"]') as HTMLElement).click())
    // The chain (OP signin → stub consent → OP callback → the authorize
    // re-entry) lands on the consent page; it must STAND before the
    // teardown; the URL flips at navigation start while subresources
    // still stream through the listener (the id-02 lesson).
    await page.waitForSelector('[data-testid="op-consent-allow"]', { timeout: SETTLE, polling: 500 })
  } finally {
    await stopIntercepting(page)
  }
}

/** The consent page's honest per-client role preview. */
async function consentRolePreview(page: Page): Promise<string> {
  const el = await page.$('[data-testid="op-consent-role-claims"]')
  return el ? (await el.evaluate(e => e.textContent ?? '')).trim() : ''
}

/** Click the consent's allow and answer the RP's validated outcome (the
 *  claims of the ID token the RP verified against the OP's JWKS, plus
 *  the userinfo read). */
async function consentAllowToRp(page: Page, rp: StubRp): Promise<{ claims: Record<string, unknown> | null; userinfo: Record<string, unknown> | null }> {
  await page.evaluate(() => (document.querySelector('[data-testid="op-consent-allow"]') as HTMLElement).click())
  await page.waitForFunction(
    (port) => window.location.port === port,
    { timeout: SETTLE, polling: 500 },
    String(rp.port),
  )
  await page.waitForFunction(
    () => !!document.querySelector('[data-testid="rp-signed-in"], [data-testid="rp-error"]'),
    { timeout: SETTLE, polling: 500 },
  )
  return (await fetch(`${rp.baseUrl}/whoami`)).json() as Promise<{ claims: Record<string, unknown> | null; userinfo: Record<string, unknown> | null }>
}

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
    // stopIntercepting disabled interception throws; and an event-handler
    // throw fails the suite. Nothing honest left to do with that request.
    void p.catch(() => {})
  })
}

async function stopIntercepting(page: Page): Promise<void> {
  // Listener off FIRST: with the listener gone no continue() can race the
  // disable; the catch guard above covers the deliveries already in flight.
  page.removeAllListeners('request')
  await page.setRequestInterception(false)
}

let stubGithub: StubGitHub

describe('TODO.identity/05: the full identity arc, OP-side (real OP, fixture RP, stub GitHub upstream)', () => {
  let op: Stack
  let rp: StubRp
  /** The arc's cross-leg state (the DB holds the truth; these are ids). */
  let veraId = ''
  let priyaId = ''

  beforeAll(async () => {
    rmSync(PROGRESS_LOG, { force: true })
    stubGithub = await startStubGitHub({ clientSecret: 'id05-gh-secret', users: [GH_VERA] })
    op = await bootOpStack(stubGithub)
    rp = await startStubRp({ port: RP_PORT, issuer: ISSUER, clientId: CLIENT_ID, clientSecret: CLIENT_SECRET })
  }, 900_000)

  afterAll(async () => {
    await rp?.close()
    await stubGithub?.close()
    await stopStack(op)
  })

  it('leg 1: ENROLL: the invite carries the per-client role; the one-time setup link sets the password exactly once', { timeout: 900_000 }, async () => {
    const invited = await opInviteAccount(op, VERA, ['tl_operator'])
    veraId = invited.id
    expect(invited.setupUrl).toContain('/op/setup?token=')
    flog(null, 'leg1: invited')

    await withPage(async (page) => {
      await driveSetup(page, invited.setupUrl, VERA.password, VERA.email)
      expect(await page.$eval('[data-testid="account-name"]', el => el.textContent?.trim())).toBe(VERA.name)
      flog(page, 'leg1: enrolled')

      // One-time means one-time: the used link answers its honest card.
      await page.goto(invited.setupUrl, { waitUntil: 'domcontentloaded', timeout: SETTLE })
      await page.waitForSelector('[data-testid="op-setup-used"]', { timeout: SETTLE, polling: 500 })
      flog(page, 'leg1: the used link says so')
    })
  })

  it('leg 2: THE OIDC ROUND TRIP: the consent names tl_operator; the RP validates the token carrying it', { timeout: 900_000 }, async () => {
    await withPage(async (page) => {
      await rpSignInToConsent(page, rp, VERA)
      expect(new URL(page.url()).pathname).toBe('/op/consent')
      expect(await page.$eval('[data-testid="op-consent-client"]', el => el.textContent?.trim())).toBe('The id-05 fixture RP')
      expect(await consentRolePreview(page), 'the consent honestly names what THIS client receives').toContain('tl_operator')
      const { claims, userinfo } = await consentAllowToRp(page, rp)
      expect(claims, 'the RP validated the OP’s token against its JWKS').toMatchObject({ email: VERA.email })
      expect(claims?.roles, 'the emitted roles are the per-client assignment').toEqual(['tl_operator'])
      expect(userinfo).toMatchObject({ email: VERA.email })
      flog(page, 'leg2: the RP holds the validated claims')
    })
  })

  it('leg 3: LINK UPSTREAM: the account console links her GitHub (the registry row, the signed state, the stub round trip)', { timeout: 900_000 }, async () => {
    await withPage(async (page) => {
      await page.goto(`${op.base}/`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
      await opPasswordSignIn(page, VERA.email, VERA.password)
      // The signed-in landing is the SSO home (the launcher); the
      // account console is its entry.
      await page.waitForSelector('[data-testid="home"]', { timeout: APP_COLD, polling: 500 })
      await page.goto(`${op.base}/op/account`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
      await page.waitForSelector('[data-testid="account-name"]', { timeout: APP_COLD, polling: 500 })

      await page.waitForSelector('[data-testid="op-account-link-github-action"]', { timeout: SETTLE, polling: 500 })
      await interceptStubGitHub(page, GH_VERA.login)
      try {
        await page.evaluate(() => (document.querySelector('[data-testid="op-account-link-github-action"]') as HTMLElement).click())
        await page.waitForFunction(
          () => window.location.pathname === '/op/account' && window.location.search.includes('linked=github'),
          { timeout: SETTLE, polling: 500 },
        )
        // The URL matches at navigation START; the account page's load
        // still streams through the listener (the id-02 lesson);
        // account-name is the landed marker.
        await page.waitForSelector('[data-testid="account-name"]', { timeout: SETTLE, polling: 500 })
      } finally {
        await stopIntercepting(page)
      }
      await page.waitForSelector('[data-testid="op-account-link-github"]', { timeout: SETTLE, polling: 500 })
      // The row names the provider account id (305), never an email.
      expect(await page.$eval('[data-testid="op-account-link-github"]', el => el.textContent ?? '')).toContain(String(GH_VERA.id))
      flog(page, 'leg3: linked')
    })
  })

  it('leg 4: GITHUB-THROUGH-THE-OP: the linked method signs her in from the RP (the RP only ever talks to the OP)', { timeout: 900_000 }, async () => {
    await withPage(async (page) => {
      await rpViaGitHubToConsent(page, rp, GH_VERA.login)
      expect(await consentRolePreview(page)).toContain('tl_operator')
      const { claims } = await consentAllowToRp(page, rp)
      expect(claims, 'the upstream sign-in resolved the SAME account; the RP saw only the OP').toMatchObject({ email: VERA.email })
      expect(claims?.roles).toEqual(['tl_operator'])
      flog(page, 'leg4: GitHub-through-the-OP validated')
    })
  })

  it('leg 5: ORG ADMINISTRATION: the org admin is created, the reviewer requests, the queue approves, the invite enrolls (the org binding rides the session)', { timeout: 900_000 }, async () => {
    // The scheme operator creates the Utilizer's org admin (the
    // eligibility rule: a REGISTERED participant org).
    const admin = await opAdminCookie(op)
    const orgAdminInvite = await fetch(`${op.apiBase}/api/op/org-invites`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: admin },
      body: JSON.stringify({ email: OREN.email, name: OREN.name, role: 'org_admin', org_id: UTILIZER_ID }),
    })
    if (!orgAdminInvite.ok) throw new Error(`the org-admin invite → ${orgAdminInvite.status}: ${await orgAdminInvite.text()}`)
    const { invite: orenInvite } = await orgAdminInvite.json() as { invite: { setupUrl: string } }
    flog(null, 'leg5: the org admin invited')

    // He enrolls (the one-time link sets his password, signs him in).
    await withPage(async (page) => {
      await driveSetup(page, orenInvite.setupUrl, OREN.password, OREN.email)
      flog(page, 'leg5: the org admin enrolled')
    })

    // The reviewer files the join request on the PUBLIC page, picking
    // HER org from the register. The kind-bounded role set of a Utilizer
    // is viewer + scheme_participant; she asks for the viewer role.
    await withPage(async (page) => {
      await page.goto(`${op.base}/op/join`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
      await page.waitForSelector('[data-testid="join-name"]', { timeout: SETTLE, polling: 500 })
      await page.type('[data-testid="join-name"]', PRIYA.name)
      await page.type('[data-testid="join-email"]', PRIYA.email)
      await page.evaluate((id) => {
        (document.querySelector(`[data-testid="join-org-option-${id}"]`) as HTMLElement).click()
      }, UTILIZER_ID)
      await page.waitForSelector('[data-testid="join-role"]', { timeout: SETTLE, polling: 500 })
      const options = await page.$$eval('[data-testid="join-role"] option', els => els.map(e => (e as HTMLOptionElement).value))
      expect(options.filter(Boolean), 'a Utilizer’s staff asks for the kind-bounded roles only').toEqual(['viewer', 'scheme_participant'])
      await page.select('[data-testid="join-role"]', 'viewer')
      await page.type('[data-testid="join-note"]', 'I review R 60 certificates for the NL office.')
      await page.evaluate(() => (document.querySelector('[data-testid="join-submit"]') as HTMLElement).click())
      await page.waitForSelector('[data-testid="join-success"]', { timeout: SETTLE, polling: 500 })
      const success = await page.$eval('[data-testid="join-success"]', el => el.textContent ?? '')
      expect(success).toContain(UTILIZER_NAME)
      expect(success).toContain('administrator')
      flog(page, 'leg5: the join request filed')
    })

    // The org admin approves from HIS queue (the org-scoped slice); the
    // invite issues (02's enrollment seam).
    const oren = await opPasswordCookie(op, OREN.email, OREN.password)
    const queue = await fetch(`${op.apiBase}/api/op/join-requests`, { headers: { cookie: oren } })
    if (!queue.ok) throw new Error(`the org queue → ${queue.status}`)
    const { requests } = await queue.json() as { requests: Array<{ id: string; email: string; status: string }> }
    const request = requests.find(r => r.email === PRIYA.email && r.status === 'pending')
    if (!request) throw new Error(`the reviewer’s request never reached the org queue: ${JSON.stringify(requests)}`)
    const approve = await fetch(`${op.apiBase}/api/op/join-requests/${request.id}/approve`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: oren },
      body: JSON.stringify({}),
    })
    if (!approve.ok) throw new Error(`the approval → ${approve.status}: ${await approve.text()}`)
    const { invite: priyaInvite } = await approve.json() as { invite: { userId: string; setupUrl: string } }
    priyaId = priyaInvite.userId
    flog(null, 'leg5: approved, the invite issued')

    // She enrolls: the session carries the org binding (the approved
    // request's org).
    await withPage(async (page) => {
      await driveSetup(page, priyaInvite.setupUrl, PRIYA.password, PRIYA.email)
      const session = await page.evaluate(async () => {
        const res = await fetch('/api/auth/session', { credentials: 'include' })
        return res.ok ? res.json() : null
      })
      expect(session).toMatchObject({ email: PRIYA.email, orgId: UTILIZER_ID })
      flog(page, 'leg5: the reviewer enrolled, org-bound')
    })
  })

  it('leg 6: PER-CLIENT ROLES GOVERN THE TOKEN: the explicit empty assignment emits NO roles claim; the viewer assignment emits it', { timeout: 900_000 }, async () => {
    // The explicit EMPTY assignment on this client (the OP's "no roles
    // here" posture); assigned BEFORE her first RP sign-in.
    await opAssignClientRoles(op, priyaId, [])

    // Her first sign-in: the consent says so; the RP-validated token
    // carries NO roles claim. What an RP DOES with that (the approval
    // queue) is the platform half's proof.
    await withPage(async (page) => {
      await rpSignInToConsent(page, rp, PRIYA)
      expect(await consentRolePreview(page)).toContain('no platform roles')
      const { claims } = await consentAllowToRp(page, rp)
      expect(claims, 'the RP validated the token').toMatchObject({ email: PRIYA.email })
      expect(claims?.roles ?? [], 'no roles claim for the explicit-empty assignment').toEqual([])
      flog(page, 'leg6: the empty claim, honestly')
    })

    // The admin assigns viewer on THIS client; her next sign-in's token
    // carries it.
    await opAssignClientRoles(op, priyaId, ['viewer'])
    await withPage(async (page) => {
      await rpSignInToConsent(page, rp, PRIYA)
      expect(await consentRolePreview(page)).toContain('viewer')
      const { claims } = await consentAllowToRp(page, rp)
      expect(claims).toMatchObject({ email: PRIYA.email })
      expect(claims?.roles).toEqual(['viewer'])
      flog(page, 'leg6: the assignment emits viewer')
    })
  })

  it('leg 7: DEACTIVATION: her live OP session is revoked; the next sign-in is refused at the OP, honestly', { timeout: 900_000 }, async () => {
    // She holds a LIVE OP session (over the API).
    const veraCookie = await opPasswordCookie(op, VERA.email, VERA.password)
    const before = await fetch(`${op.apiBase}/api/op/account`, { headers: { cookie: veraCookie } })
    expect(before.status).toBe(200)

    await opSetActive(op, veraId, false)
    flog(null, 'leg7: deactivated')

    // The live session is REVOKED in the same act (gone, not merely
    // refused at the join).
    const after = await fetch(`${op.apiBase}/api/op/account`, { headers: { cookie: veraCookie } })
    expect(after.status).toBe(401)

    // Her next sign-in from the RP never reaches it: the OP's own
    // sign-in surface refuses the RIGHT password with the honest
    // message — the browser stays on the OP origin (no code ever
    // redirects back).
    await withPage(async (page) => {
      await page.goto(`${rp.baseUrl}/signin`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
      await page.waitForFunction(
        (opPort) => window.location.port === opPort && window.location.pathname === '/' && window.location.search.includes('redirect='),
        { timeout: SETTLE, polling: 500 },
        String(OP_WEB),
      )
      await opPasswordSignIn(page, VERA.email, VERA.password)
      await page.waitForSelector('[data-testid="login-error"]', { timeout: SETTLE, polling: 500 })
      const message = await page.$eval('[data-testid="login-error"]', el => el.textContent ?? '')
      expect(message).toContain('deactivated')
      expect(new URL(page.url()).port).toBe(String(OP_WEB))
      flog(page, 'leg7: refused at the OP')
    })
  })

  it('leg 8: REACTIVATION: the rows and the GitHub link were kept; she signs in from the RP through the OP via GitHub', { timeout: 900_000 }, async () => {
    await opSetActive(op, veraId, true)
    flog(null, 'leg8: reactivated')

    await withPage(async (page) => {
      // The LINKED GitHub (leg 3's row survived the deactivation) carries
      // this sign-in; the full upstream-through-the-OP arc again.
      await rpViaGitHubToConsent(page, rp, GH_VERA.login)
      expect(await consentRolePreview(page)).toContain('tl_operator')
      const { claims } = await consentAllowToRp(page, rp)
      expect(claims).toMatchObject({ email: VERA.email })
      expect(claims?.roles).toEqual(['tl_operator'])
      flog(page, 'leg8: validated again')
    })
  })
})
