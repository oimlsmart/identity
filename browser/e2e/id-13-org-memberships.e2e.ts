// ═══════════════════════════════════════════════════════════════════
// TODO.identity/11 — the multi-organization membership model, the e2e:
// the identity-profile stack (its own API + its own astro, the id-10
// spawned-stack pattern), the whole flow for real:
//
//   leg 1  the account console's Organizations section: the IA officer's
//          primary membership shows (the acting badge); they ask to join
//          the registered Utilizer as a viewer from the console;
//   leg 2  the org admin (created through the console, the id-10 drive)
//          approves the officer's ask — the EXISTING account joins
//          directly (the notice names it: no setup link) — and the
//          people slice lists the officer with the per-org role;
//   leg 3  the officer's console shows BOTH memberships; the switch to
//          the Utilizer reloads the page under the new context (the
//          acting badge moves), and the org console honestly refuses
//          them there (they are STAFF in that org — the grant follows
//          the context);
//   leg 4  THE CLAIMS PROOF (fetch-level against the stack): the OIDC
//          round trip's ID token + userinfo carry the ACTIVE org's role
//          set — before the switch (EX1 + ia_officer), after it
//          (ut-nmi-nl + viewer), and the other membership never leaks;
//   leg 5  the identity admin's per-org registry view (the members, the
//          per-org roles, the org_admin mark, the queue) and the
//          officer's registry page's memberships section;
//   leg 6  the org admin DISABLES the officer's membership from the
//          people slice — the officer's next round trip carries the
//          primary context again (the live re-judgment), and the per-org
//          view shows the disabled state honestly.
//
// SELF-CONTAINED: the suite's shared stack (E2E_BASE_URL) is untouched —
// the identity instance boots on its own ports (API 9993 / astro 9994)
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
const DB_DIR = join(BROWSER_DIR, '.cache', 'id-13')

// Port-isolated: clear of every declared e2e stack (8393..9894) and the
// local dev loops (5190/3190, 6390/6290, 7390/7190).
const ID_API = 9993
const ID_WEB = 9994

// The cast: the Utilizer's org admin (created in leg 2 — a real OP
// password account, the 02 enrollment seam) and the IA officer (the demo
// cast's ia@oiml.org — primary EX1, the account that joins the Utilizer).
const UTILIZER_ID = 'ut-nmi-nl'
const UTILIZER_NAME = 'Example Metrology Authority (Netherlands)'
const IA_ID = 'EX1'
const ORG_ADMIN_EMAIL = 'sanne.devries@nmi.example.org'
const ORG_ADMIN_PASSWORD = 'sanne de vries admin passphrase'
const OFFICER_EMAIL = 'ia@oiml.org'

// The fixture RP for the claims proof (the contract gate's shape: a
// confidential client carrying the role-claim policy).
const RP_CLIENT_ID = 'fixture-rp'
const RP_CLIENT_SECRET = 'fixture-rp-secret'
const RP_REDIRECT_URI = 'http://127.0.0.1:9995/callback'

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

/** Boot the identity-profile stack (the id-10 posture + the fixture RP
 *  seed for the claims proof). */
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
      // The registry's bootstrap seed: the fixture RP (a confidential
      // client carrying the role-claim policy — the claims proof's reader).
      OP_CLIENT_SEED: JSON.stringify([{
        client_id: RP_CLIENT_ID,
        name: 'The id-13 fixture RP',
        secret: RP_CLIENT_SECRET,
        redirect_uris: [RP_REDIRECT_URI],
        claims_policy: { claims: ['roles', 'groups', 'org'] },
      }]),
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

/** The console's one-time setup link for the last issued invite. */
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
 *  then settle the browser on the sign-in page (the id-10 race guard). */
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

// ── the fetch-level claims proof (leg 4/6) ──────────────────────────

/** A fetch-level demo sign-in against the stack (the cookie jar is a
 *  string — the claims proof never needs a browser). */
async function apiSignIn(apiBase: string, email: string): Promise<string> {
  const login = await fetch(`${apiBase}/api/auth/demo`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password: 'demo2026' }),
  })
  expect(login.ok, `demo sign-in ${email}`).toBe(true)
  return (login.headers.get('set-cookie') ?? '').split(';')[0]!
}

/** The OIDC round trip (authorize → consent → decide → exchange →
 *  userinfo), answering the ID token's payload + userinfo. */
async function roundTrip(apiBase: string, cookie: string): Promise<{ idToken: Record<string, unknown>; userinfo: Record<string, unknown> }> {
  const verifier = 'id11-verifier-1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d'
  const challenge = Buffer.from(
    await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier)),
  ).toString('base64url')
  const authorize = await fetch(`${apiBase}/op/authorize?${new URLSearchParams({
    response_type: 'code', client_id: RP_CLIENT_ID, redirect_uri: RP_REDIRECT_URI,
    scope: 'openid profile email', state: 'st', nonce: 'nn',
    code_challenge: challenge, code_challenge_method: 'S256',
    // The consent stop is this helper's contract (TODO.identity-features/12:
    // a remembered grant would skip it when an account repeats).
    prompt: 'consent',
  })}`, { headers: { cookie }, redirect: 'manual' })
  expect(authorize.status, 'authorize redirects to consent').toBe(302)
  const authId = new URL(authorize.headers.get('location')!, apiBase).searchParams.get('auth')!
  const decide = await fetch(`${apiBase}/api/op/consent/${authId}/decide`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', cookie },
    body: JSON.stringify({ decision: 'allow' }),
  })
  expect(decide.status, 'the consent decision records').toBe(200)
  const { redirect } = await decide.json() as { redirect: string }
  const code = new URL(redirect).searchParams.get('code')!
  const exchange = await fetch(`${apiBase}/op/token`, {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      authorization: `Basic ${btoa(`${encodeURIComponent(RP_CLIENT_ID)}:${encodeURIComponent(RP_CLIENT_SECRET)}`)}`,
    },
    body: new URLSearchParams({
      grant_type: 'authorization_code', code, redirect_uri: RP_REDIRECT_URI,
      client_id: RP_CLIENT_ID, code_verifier: verifier,
    }),
  })
  expect(exchange.status, 'the code exchange answers').toBe(200)
  const tokens = await exchange.json() as { access_token: string; id_token: string }
  const userinfoRes = await fetch(`${apiBase}/op/userinfo`, { headers: { authorization: `Bearer ${tokens.access_token}` } })
  expect(userinfoRes.status, 'userinfo answers').toBe(200)
  const payload = JSON.parse(Buffer.from(tokens.id_token.split('.')[1]!, 'base64url').toString('utf-8')) as Record<string, unknown>
  return { idToken: payload, userinfo: await userinfoRes.json() as Record<string, unknown> }
}

/** The account's active-org switch (fetch-level). */
async function switchActiveOrg(apiBase: string, cookie: string, orgId: string | null): Promise<void> {
  const res = await fetch(`${apiBase}/api/op/account/active-org`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', cookie },
    body: JSON.stringify({ org_id: orgId }),
  })
  expect(res.status, `the switch to ${orgId}`).toBe(200)
}

describe('TODO.identity/11 — the multi-organization membership model (the identity profile)', () => {
  let stack: Stack
  let browser: Browser
  let page: Page

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

  it('leg 1 — the account console shows the primary membership; the officer asks to join the Utilizer', { timeout: 900_000 }, async () => {
    await page.goto(`${stack.base}/`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await opSignIn(page, OFFICER_EMAIL)
    await page.waitForFunction(() => window.location.pathname !== '/', { timeout: SETTLE, polling: 500 })
    await page.goto(`${stack.base}/op/account`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await page.waitForSelector('[data-testid="account-organizations"]', { timeout: SETTLE, polling: 500 })

    // The primary membership: EX1, the acting badge, the role line.
    await page.waitForSelector(`[data-testid="account-org-${IA_ID}"]`, { timeout: SETTLE, polling: 500 })
    expect(await page.$(`[data-testid="account-org-acting-${IA_ID}"]`)).not.toBeNull()
    const roles = await page.$eval(`[data-testid="account-org-roles-${IA_ID}"]`, el => el.textContent ?? '')
    expect(roles).toContain('ia_officer')
    const context = await page.$eval('[data-testid="account-active-context"]', el => el.textContent ?? '')
    expect(context).toContain('Example Issuing Authority')

    // The ask: pick the Utilizer + the viewer role from the console.
    await page.select('[data-testid="account-org-join-org"]', UTILIZER_ID)
    await page.waitForFunction(() => {
      const sel = document.querySelector('[data-testid="account-org-join-role"]') as HTMLSelectElement | null
      return sel && !sel.disabled && [...sel.options].some(o => o.value === 'viewer')
    }, { timeout: SETTLE, polling: 500 })
    await page.select('[data-testid="account-org-join-role"]', 'viewer')
    await page.type('[data-testid="account-org-join-note"]', 'I evaluate the joint R 60 review.')
    await page.evaluate(() => (document.querySelector('[data-testid="account-org-join-submit"]') as HTMLElement).click())
    await page.waitForSelector('[data-testid="op-account-notice"]', { timeout: SETTLE, polling: 500 })
    const notice = await page.$eval('[data-testid="op-account-notice"]', el => el.textContent ?? '')
    expect(notice).toContain(UTILIZER_NAME)
    // The pending ask shows its state honestly.
    await page.waitForFunction(() => {
      const list = document.querySelector('[data-testid="account-org-requests"]')
      return list && list.textContent?.includes('Waiting for')
    }, { timeout: SETTLE, polling: 500 })
  })

  it('leg 2 — BIML creates the org admin (the id-10 drive), then the org admin approves the officer: the EXISTING account joins directly', { timeout: 900_000 }, async () => {
    // The org admin's creation (the scheme operator's console).
    await signOut(page)
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
    const setupUrl = await readSetupUrl(page)
    expect(setupUrl).toContain('/op/setup?token=')
    await signOut(page)
    await driveSetup(page, setupUrl, ORG_ADMIN_PASSWORD, ORG_ADMIN_EMAIL)

    // The org admin's queue carries the officer's ask; the approval lands
    // the membership directly (the account EXISTS — no setup link).
    await signOut(page)
    await page.goto(`${stack.base}/`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await opPasswordSignIn(page, ORG_ADMIN_EMAIL, ORG_ADMIN_PASSWORD)
    await page.waitForFunction(() => window.location.pathname !== '/', { timeout: SETTLE, polling: 500 })
    await page.goto(`${stack.base}/op/admin/users`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await page.waitForSelector('[data-testid="org-queue"]', { timeout: SETTLE, polling: 500 })
    const requestId = await requestIdFor(page, OFFICER_EMAIL)
    expect(requestId).toBeTruthy()
    await page.evaluate((id) => {
      (document.querySelector(`[data-testid="join-approve-${id}"]`) as HTMLElement).click()
    }, requestId)
    await page.waitForSelector('[data-testid="op-admin-notice"]', { timeout: SETTLE, polling: 500 })
    const notice = await page.$eval('[data-testid="op-admin-notice"]', el => el.textContent ?? '')
    expect(notice).toContain('existing account')
    expect(notice).toContain('no new setup link')
    // NO one-time setup link card for the existing-account path.
    expect(await page.$('[data-testid="invite-setup-url"]')).toBeNull()

    // The people slice lists the officer as a member with the per-org role.
    await page.waitForFunction(() => {
      const list = document.querySelector('[data-testid="org-users-list"]')
      return list && list.textContent?.includes('IA Officer')
    }, { timeout: SETTLE, polling: 500 })
    const slice = await page.$eval('[data-testid="org-users-list"]', el => el.textContent ?? '')
    expect(slice).toContain('Sanne de Vries')
    expect(slice).toContain('viewer')
  })

  it('leg 3 — the officer switches the context from the account console; the org console honestly refuses them there', { timeout: 900_000 }, async () => {
    await signOut(page)
    await page.goto(`${stack.base}/`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await opSignIn(page, OFFICER_EMAIL)
    await page.waitForFunction(() => window.location.pathname !== '/', { timeout: SETTLE, polling: 500 })
    await page.goto(`${stack.base}/op/account`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await page.waitForSelector('[data-testid="account-organizations"]', { timeout: SETTLE, polling: 500 })

    // BOTH memberships show (the ask's approval made it active directly).
    await page.waitForSelector(`[data-testid="account-org-${UTILIZER_ID}"]`, { timeout: SETTLE, polling: 500 })

    // The switch to the Utilizer: the page reloads under the new context.
    await page.evaluate((orgId) => {
      (document.querySelector(`[data-testid="account-org-switch-${orgId}"]`) as HTMLElement).click()
    }, UTILIZER_ID)
    await page.waitForFunction((orgId) => {
      return !!document.querySelector(`[data-testid="account-org-acting-${orgId}"]`)
    }, { timeout: SETTLE, polling: 500 }, UTILIZER_ID)
    const context = await page.$eval('[data-testid="account-active-context"]', el => el.textContent ?? '')
    expect(context).toContain(UTILIZER_NAME)
    // The session payload follows.
    const session = await sessionPayload(page)
    expect(session?.orgId).toBe(UTILIZER_ID)
    expect(session?.roles).toEqual(['viewer'])
    // The return affordance shows on the non-primary context row.
    expect(await page.$(`[data-testid="account-org-return-${UTILIZER_ID}"]`)).not.toBeNull()

    // The org console honestly refuses them THERE (staff, not the
    // administrator — the grant follows the ACTIVE context).
    await page.goto(`${stack.base}/op/admin/users`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await page.waitForSelector('[data-testid="op-admin-error"]', { timeout: SETTLE, polling: 500 })
    const refusal = await page.$eval('[data-testid="op-admin-error"]', el => el.textContent ?? '')
    expect(refusal).toContain('organization administrators')
  })

  it('leg 4 — THE CLAIMS PROOF: the token carries the ACTIVE org’s role set (before and after the switch)', { timeout: 900_000 }, async () => {
    // Fetch-level (the browser stays on the account page): a fresh
    // session signs in, switches, and the round trips answer.
    const cookie = await apiSignIn(stack.apiBase, OFFICER_EMAIL)

    const before = await roundTrip(stack.apiBase, cookie)
    expect(before.idToken.org).toBe(IA_ID)
    expect(before.idToken.roles).toEqual(['ia_officer'])
    expect(before.userinfo.org).toBe(IA_ID)
    expect(before.userinfo.roles).toEqual(['ia_officer'])

    await switchActiveOrg(stack.apiBase, cookie, UTILIZER_ID)
    const after = await roundTrip(stack.apiBase, cookie)
    expect(after.idToken.org).toBe(UTILIZER_ID)
    expect(after.idToken.roles).toEqual(['viewer'])
    expect(after.userinfo.org).toBe(UTILIZER_ID)
    expect(after.userinfo.roles).toEqual(['viewer'])
    // The other membership never leaks into the claims.
    expect(JSON.stringify(after.idToken)).not.toContain(IA_ID)
    expect(JSON.stringify(after.idToken)).not.toContain('ia_officer')
    expect(JSON.stringify(after.userinfo)).not.toContain(IA_ID)

    // Back to the primary context.
    await switchActiveOrg(stack.apiBase, cookie, null)
    const home = await roundTrip(stack.apiBase, cookie)
    expect(home.idToken.org).toBe(IA_ID)
    expect(home.idToken.roles).toEqual(['ia_officer'])
  })

  it('leg 5 — the identity admin’s per-org registry view + the officer’s registry page memberships section', { timeout: 900_000 }, async () => {
    await signOut(page)
    await page.goto(`${stack.base}/`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await opSignIn(page, 'admin@oiml.org')
    await page.waitForFunction(() => window.location.pathname !== '/', { timeout: SETTLE, polling: 500 })

    // The per-org view: the members (the org_admin mark), the queue.
    await page.goto(`${stack.base}/op/admin/registry/orgs/${UTILIZER_ID}`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await page.waitForSelector('[data-testid="op-reg-org"]', { timeout: SETTLE, polling: 500 })
    const orgName = await page.$eval('[data-testid="op-reg-org-name"]', el => el.textContent ?? '')
    expect(orgName).toContain(UTILIZER_NAME)
    await page.waitForSelector('[data-testid="op-reg-org-members-list"]', { timeout: SETTLE, polling: 500 })
    const members = await page.$eval('[data-testid="op-reg-org-members-list"]', el => el.textContent ?? '')
    expect(members).toContain('Sanne de Vries')
    expect(members).toContain('IA Officer')
    const admins = await page.$eval('[data-testid="op-reg-org-admins"]', el => el.textContent ?? '')
    expect(admins).toContain('Sanne de Vries')
    const queue = await page.$eval('[data-testid="op-reg-org-requests"]', el => el.textContent ?? '')
    expect(queue).toContain(OFFICER_EMAIL)
    expect(queue).toContain('approved')

    // The officer's registry page: the memberships section lists both
    // orgs with their per-org roles + the primary mark.
    const accountsRes = await page.evaluate(async () => {
      const res = await fetch('/api/op/registry/users?q=ia@oiml.org', { credentials: 'include' })
      return res.json() as Promise<Array<{ id: string }>>
    })
    const officerId = accountsRes[0]!.id
    await page.goto(`${stack.base}/op/admin/registry/users/${officerId}`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await page.waitForSelector('[data-testid="op-reg-memberships-list"]', { timeout: SETTLE, polling: 500 })
    const memberships = await page.$eval('[data-testid="op-reg-memberships-list"]', el => el.textContent ?? '')
    expect(memberships).toContain('Example Issuing Authority')
    expect(memberships).toContain(UTILIZER_NAME)
    expect(memberships).toContain('viewer')
    const primaryRoles = await page.$eval(`[data-testid="op-reg-membership-roles-${IA_ID}"]`, el => el.textContent ?? '')
    expect(primaryRoles).toContain('ia_officer')
  })

  it('leg 6 — the org admin disables the officer’s membership: the claims fall back to the primary context (the live re-judgment)', { timeout: 900_000 }, async () => {
    // The org admin (its own context) disables from the people slice.
    await signOut(page)
    await page.goto(`${stack.base}/`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await opPasswordSignIn(page, ORG_ADMIN_EMAIL, ORG_ADMIN_PASSWORD)
    await page.waitForFunction(() => window.location.pathname !== '/', { timeout: SETTLE, polling: 500 })
    await page.goto(`${stack.base}/op/admin/users`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await page.waitForSelector('[data-testid="org-users-list"]', { timeout: SETTLE, polling: 500 })
    // The officer's membership row id from the people slice (the org
    // grant never reads the registry — the DOM names the row).
    const uid = await page.evaluate((email) => {
      const li = [...document.querySelectorAll('[data-testid^="org-user-"]')]
        .find(e => e.textContent?.includes(email))
      return li?.getAttribute('data-testid')?.replace('org-user-', '') ?? ''
    }, OFFICER_EMAIL)
    expect(uid).toBeTruthy()

    // The officer, acting as the Utilizer, mid-flow…
    const cookie = await apiSignIn(stack.apiBase, OFFICER_EMAIL)
    await switchActiveOrg(stack.apiBase, cookie, UTILIZER_ID)
    const acting = await roundTrip(stack.apiBase, cookie)
    expect(acting.idToken.org).toBe(UTILIZER_ID)

    // …the org's admin disables the membership…
    await page.evaluate((id) => {
      (document.querySelector(`[data-testid="org-user-membership-toggle-${id}"]`) as HTMLElement).click()
    }, uid)
    await page.waitForSelector('[data-testid="op-admin-notice"]', { timeout: SETTLE, polling: 500 })
    const notice = await page.$eval('[data-testid="op-admin-notice"]', el => el.textContent ?? '')
    expect(notice).toContain('disabled')

    // …and the officer's next round trip carries the PRIMARY context (the
    // stale stamp ended; the dead org's claims never emit).
    const after = await roundTrip(stack.apiBase, cookie)
    expect(after.idToken.org).toBe(IA_ID)
    expect(after.idToken.roles).toEqual(['ia_officer'])
    expect(after.userinfo.org).toBe(IA_ID)

    // The per-org view shows the disabled state honestly (the identity
    // admin's read).
    const wideCookie = await apiSignIn(stack.apiBase, 'admin@oiml.org')
    const viewRes = await fetch(`${stack.apiBase}/api/op/registry/orgs/${UTILIZER_ID}`, { headers: { cookie: wideCookie } })
    const view = await viewRes.json() as { members: Array<{ userId: string; state: string; disabledBy: string | null }> }
    const row = view.members.find(m => m.userId === uid)
    expect(row?.state).toBe('disabled')
    expect(row?.disabledBy).toBe(ORG_ADMIN_EMAIL)
  })
})
