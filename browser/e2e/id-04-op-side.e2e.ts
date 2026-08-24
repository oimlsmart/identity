// ═══════════════════════════════════════════════════════════════════
// id-04-op-side — the OP half of the monorepo's id-04-wiring (the
// extraction map's OP/RP split, smart's PROGRESS/41 §5): the invite,
// the consent honestly naming the per-client roles, and the
// explicit-empty assignment, driven over the fixture relying party
// (e2e/fixtures/stub-rp.ts — the REAL RP client code consuming the OP's
// tokens, so the assertions are the RP-validated claims, not a
// test-shaped copy).
//
//   leg 1  INVITE + CONSENT: the OP admin invites an account with a
//          per-client role set; the consent honestly names it; the
//          RP-validated ID token carries exactly the assigned roles;
//   leg 2  THE EXPLICIT-EMPTY ASSIGNMENT: the consent says "no platform
//          roles"; the RP-validated token carries NO roles claim;
//   leg 3  THE ALLOWLIST BINDS EMISSION: a role outside the client's
//          claims policy is never emitted, however the assignment
//          reads.
//
// What this leg deliberately does NOT assert: the RP's claim MAPPING,
// the approval queue, the moved-to-SSO message. Those are the platform
// half (the monorepo's RP-side successor of id-04, driven over its
// stub-IdP pattern); the REAL cross-repo round trip is the deploy
// gate's preview probe.
//
// SELF-CONTAINED: the identity instance boots on its own ports (API
// 9492 / astro 9493) with its own SQLite file; the fixture RP rides
// 127.0.0.1:9494.
// ═══════════════════════════════════════════════════════════════════

import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import puppeteer, { type Browser, type Page } from 'puppeteer'
import { spawn, type ChildProcess } from 'node:child_process'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { existsSync, mkdirSync, rmSync, cpSync } from 'node:fs'
import { closeBrowser, delay } from './helpers'
import { startStubRp, type StubRp } from './fixtures/stub-rp'

const BROWSER_DIR = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const FIXTURES = join(BROWSER_DIR, 'e2e', 'fixtures')
const DB_DIR = join(BROWSER_DIR, '.cache', 'id-04-op-side')

// Port-isolated: clear of the shared dev stack (5190/3190), the id-01
// stack (8693/8393/8694), id-02 (8793/8593/8794), id-09 (8795/8595),
// id-08 (8993/8893/8994), id-10 (9193/9093), id-03 (9393/9293/9294),
// id-07 (9293/9294), id-06 (9493/9393), id-05 (9592/9593/9596),
// op-key-rotate (9693/9695) and the contract leg's in-process boot.
const OP_API = 9492
const OP_WEB = 9493
const RP_PORT = 9494

const ISSUER = `http://localhost:${OP_WEB}` // the astro origin (the browser's OP)
const RP_CLIENT_ID = 'id04-rp'
const RP_CLIENT_SECRET = 'id04-rp-secret'

// The fixture accounts. LISE carries the per-client set (tl_operator on
// the RP's client); EMIL the explicit-empty assignment; PETR the role
// outside the client's allowlist.
const LISE = { name: 'Ms. Lise Perrole', email: 'lise.perrole@example.org', password: 'lise perrole passphrase' }
const EMIL = { name: 'Mr. Emil Norole', email: 'emil.norole@example.org', password: 'emil norole passphrase' }
const PETR = { name: 'Mr. Petr Outscope', email: 'petr.outscope@example.org', password: 'petr outscope passphrase' }

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
 *  the OP env (issuer + the client-registry bootstrap seed — the fixture
 *  RP, a confidential client carrying the role-claim policy), the
 *  profile seed through the dev-reset seam, astro dev against it. The
 *  OIDC- and GITHUB-prefixed env is scrubbed: a CI e2e job can declare
 *  the SUITE stack's posture in the shared env, and this stack must not
 *  inherit it (the id-08 discipline). */
async function bootOpStack(): Promise<Stack> {
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
    for (const probe of [`http://localhost:${OP_API}/api/health`, `http://localhost:${OP_WEB}/`]) {
      try {
        const res = await fetch(probe)
        if (res.status < 500) throw new Error(`port for ${probe} is already serving — a leftover stack? (kill it: lsof -ti tcp:${new URL(probe).port} | xargs kill)`)
      } catch (e) {
        if (e instanceof Error && e.message.includes('already serving')) throw e
      }
    }

    // The tsx CLI directly (never npx — the wrapper orphans the server).
    api = spawnLogged(join(BROWSER_DIR, 'node_modules', '.bin', 'tsx'), ['server/serve.ts'], {
      PORT: String(OP_API),
      DATABASE_PATH: dbPath,
      ENTITY_BACKEND: 'server',
      INSTANCE_PROFILE: join(FIXTURES, 'instance.profile.identity.yaml'),
      OIDC_ISSUER: '',
      OIDC_CLIENT_ID: '',
      OIDC_CLAIM_MAPPING: '',
      GITHUB_CLIENT_ID: '',
      GITHUB_CLIENT_SECRET: '',
      DEMO_ACCOUNTS_ENABLED: 'true',
      OP_ISSUER: ISSUER,
      OP_CLIENT_SEED: JSON.stringify([{
        client_id: RP_CLIENT_ID,
        name: 'The id-04 fixture RP',
        secret: RP_CLIENT_SECRET,
        redirect_uris: [`http://127.0.0.1:${RP_PORT}/callback`],
        // The policy bounds WHICH roles this client's tokens may carry:
        // tl_operator and viewer are emittable; mc_member is NOT (leg 3).
        claims_policy: { claims: ['roles', 'groups', 'org'], roles: ['tl_operator', 'viewer'] },
      }]),
    }, logs)
    const apiBase = `http://localhost:${OP_API}`
    await waitForHttp(`${apiBase}/api/health`, 120_000, logs)

    // Provision the profile's seed (the demo cast + the register snapshot).
    const reset = await fetch(`${apiBase}/api/dev-reset`, { method: 'POST' })
    if (!reset.ok) throw new Error(`dev-reset on ${apiBase} answered ${reset.status}\n${logs.join('').slice(-2000)}`)

    // The spawned vite gets a PRIVATE cache seeded from the worktree's
    // warm one (the fed-01 lesson: a cold optimizer outlives the boot
    // budget on a loaded host).
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

/** The OP admin's session cookie (the demo cast's administrator) for the
 *  registry's API acts — invite + the enrollment completion. */
async function opAdminCookie(op: Stack): Promise<string> {
  const res = await fetch(`${op.apiBase}/api/auth/demo`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email: 'admin@oiml.org', password: 'demo2026' }),
  })
  if (!res.ok) throw new Error(`the OP admin demo login → ${res.status}`)
  return res.headers.get('set-cookie')!.split(';')[0]!
}

/** The invite + the password enrollment, both over the OP's real API. */
async function opInviteAccount(
  op: Stack,
  account: { name: string; email: string; password: string },
  clientRoles: string[],
): Promise<string> {
  const admin = await opAdminCookie(op)
  const invite = await fetch(`${op.apiBase}/api/op/accounts`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', cookie: admin },
    body: JSON.stringify({
      email: account.email,
      name: account.name,
      role: 'viewer', // the OP-side default; the per-client set rules the RP's token
      client_roles: [{ client_id: RP_CLIENT_ID, roles: clientRoles }],
    }),
  })
  if (!invite.ok) throw new Error(`the invite for ${account.email} → ${invite.status}: ${await invite.text()}`)
  const { account: invited, setupUrl } = await invite.json() as { account: { id: string }; setupUrl: string }
  const token = new URL(setupUrl).searchParams.get('token')!
  const enroll = await fetch(`${op.apiBase}/api/op/enroll/${token}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ password: account.password }),
  })
  if (!enroll.ok) throw new Error(`the enrollment for ${account.email} → ${enroll.status}: ${await enroll.text()}`)
  return invited.id
}

/** The full round trip from the fixture RP through the OP's password
 *  sign-in to the consent page. Leaves the browser ON the consent page
 *  (the caller reads the honest claim preview, then clicks allow). The
 *  browser is fresh per leg (withPage below), so no OP session survives
 *  into a sign-in — the password form always shows. (The first version
 *  shared the browser: a live OP session then skipped the form AND
 *  answered the consent with the EARLIER leg's account — the fixture
 *  discipline is per-leg browsers, the id-05 lesson.) */
async function rpSignInToConsent(page: Page, rp: StubRp, account: { email: string; password: string }): Promise<void> {
  await page.goto(`${rp.baseUrl}/signin`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
  // The OP's sign-in surface (its own login page, the redirect re-entry).
  await page.waitForFunction(
    (opPort) => window.location.port === opPort && window.location.pathname === '/' && window.location.search.includes('redirect='),
    { timeout: SETTLE, polling: 500 },
    String(OP_WEB),
  )
  await page.waitForSelector('[data-testid="login-email"]', { timeout: SETTLE, polling: 500 })
  await page.evaluate(() => {
    (document.querySelector('[data-testid="login-email"]') as HTMLInputElement).value = ''
  })
  await page.type('[data-testid="login-email"]', account.email)
  await page.type('[data-testid="login-password"]', account.password)
  await page.evaluate(() => (document.querySelector('[data-testid="login-submit"]') as HTMLElement).click())
  await page.waitForSelector('[data-testid="op-consent-allow"]', { timeout: SETTLE, polling: 500 })
}

/** The consent page's honest per-client role preview. */
async function consentRolePreview(page: Page): Promise<string> {
  const el = await page.$('[data-testid="op-consent-role-claims"]')
  return el ? (await el.evaluate(e => e.textContent ?? '')).trim() : ''
}

/** Allow at the consent and return the RP's validated claims. */
async function consentAllowToRp(page: Page, rp: StubRp): Promise<{ claims: Record<string, unknown> | null; userinfo: Record<string, unknown> | null }> {
  await page.evaluate(() => (document.querySelector('[data-testid="op-consent-allow"]') as HTMLElement).click())
  // The RP's callback page names the signed-in account (or the honest
  // error) — the token exchange + validation already happened there.
  await page.waitForFunction(
    (port) => window.location.port === port,
    { timeout: SETTLE, polling: 500 },
    String(rp.port),
  )
  await page.waitForFunction(
    () => !!document.querySelector('[data-testid="rp-signed-in"], [data-testid="rp-error"]'),
    { timeout: SETTLE, polling: 500 },
  )
  const whoami = await (await fetch(`${rp.baseUrl}/whoami`)).json() as { claims: Record<string, unknown> | null; userinfo: Record<string, unknown> | null }
  return whoami
}

describe('id-04-op-side — the OP half of the wiring contract (real OP, fixture RP)', () => {
  let op: Stack
  let rp: StubRp

  beforeAll(async () => {
    op = await bootOpStack()
    rp = await startStubRp({ port: RP_PORT, issuer: ISSUER, clientId: RP_CLIENT_ID, clientSecret: RP_CLIENT_SECRET })
  }, 900_000)

  afterAll(async () => {
    await rp?.close()
    await stopStack(op)
  })

  /** A fresh browser per leg (the id-05 lesson): the page comes with the
   *  viewport; the browser closes at the leg's end, so no OP session
   *  survives into the next leg's sign-in. */
  async function withPage(fn: (page: Page) => Promise<void>): Promise<void> {
    const browser: Browser = await puppeteer.launch({
      headless: 'shell',
      protocolTimeout: 480_000,
      args: ['--no-sandbox', '--disable-setuid-sandbox'],
    })
    try {
      const page = await browser.newPage()
      await page.setViewport({ width: 1440, height: 900 })
      page.on('pageerror', e => console.log('[pageerror]', String(e).slice(0, 300)))
      await fn(page)
    } finally {
      await closeBrowser(browser)
    }
  }

  it('leg 1 — the invite carries the per-client role; the consent names it; the RP-validated token carries exactly it', { timeout: 900_000 }, async () => {
    await opInviteAccount(op, LISE, ['tl_operator'])
    await withPage(async (page) => {
      await rpSignInToConsent(page, rp, LISE)
      expect(new URL(page.url()).pathname).toBe('/op/consent')
      expect(await page.$eval('[data-testid="op-consent-client"]', el => el.textContent?.trim())).toBe('The id-04 fixture RP')
      expect(await consentRolePreview(page), 'the consent honestly names what THIS client receives').toContain('tl_operator')
      const { claims, userinfo } = await consentAllowToRp(page, rp)
      expect(claims, 'the RP validated the OP’s token against its JWKS').toMatchObject({ email: LISE.email })
      expect(claims?.roles, 'the emitted roles are the per-client assignment').toEqual(['tl_operator'])
      expect(userinfo).toMatchObject({ email: LISE.email })
    })
  })

  it('leg 2 — the explicit empty assignment: the consent says so; the token carries NO roles claim', { timeout: 900_000 }, async () => {
    await opInviteAccount(op, EMIL, []) // the OP's "no roles on this client"
    await withPage(async (page) => {
      await rpSignInToConsent(page, rp, EMIL)
      expect(await consentRolePreview(page)).toContain('no platform roles')
      const { claims } = await consentAllowToRp(page, rp)
      expect(claims, 'the RP validated the token').toMatchObject({ email: EMIL.email })
      // The honest emission for the explicit-empty assignment: the roles
      // claim is absent or empty — never an invented role. What the RP
      // DOES with that (the approval queue) is the platform half's proof.
      expect(claims?.roles ?? [], 'no roles claim for the explicit-empty assignment').toEqual([])
    })
  })

  it('leg 3 — the allowlist binds emission: a role outside the client’s claims policy is never emitted', { timeout: 900_000 }, async () => {
    // mc_member is a valid OP role but OUTSIDE this client's policy
    // allowlist (['tl_operator', 'viewer'] above) — the assignment is
    // refused at the API, and no token can ever carry it.
    const admin = await opAdminCookie(op)
    const invite = await fetch(`${op.apiBase}/api/op/accounts`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: admin },
      body: JSON.stringify({
        email: PETR.email,
        name: PETR.name,
        role: 'viewer',
        client_roles: [{ client_id: RP_CLIENT_ID, roles: ['mc_member'] }],
      }),
    })
    expect(invite.status, 'the out-of-policy assignment is refused, never silently narrowed').toBe(400)

    // The in-policy assignment still emits exactly what it says (the
    // control leg): viewer on the client, the consent + token agree.
    await opInviteAccount(op, PETR, ['viewer'])
    await withPage(async (page) => {
      await rpSignInToConsent(page, rp, PETR)
      expect(await consentRolePreview(page)).toContain('viewer')
      const { claims } = await consentAllowToRp(page, rp)
      expect(claims?.roles).toEqual(['viewer'])
    })
  })
})
