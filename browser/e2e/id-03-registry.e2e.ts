// ═══════════════════════════════════════════════════════════════════
// TODO.identity/03 — the central user registry + the per-client role
// claims, the e2e: the identity-profile stack (its own API + its own
// astro, the id-01/id-10 spawned-stack pattern) and the fixture RP
// (e2e/fixtures/stub-rp.ts — the RP's REAL validator) drive the whole
// story in the browser:
//
//   leg 1  the registry console (the org-admin console's wide view)
//          lists the OP's accounts; the admin INVITES a new account
//          (02's enrollment seam) — the one-time setup link shows once;
//   leg 2  the invitee sets her password through the link; the admin
//          assigns her roles PER CLIENT through the console's editor —
//          the offer is bounded by the client's claims-policy allowlist
//          (a role the client is not configured to receive is not even
//          offered);
//   leg 3  the authorize→token round trip: the invitee signs in at the
//          OP, the consent page names the roles THIS client receives,
//          and the RP's validator proves the issued ID token carries
//          them (userinfo agrees);
//   leg 4  the registry's last-sign-in column reads the audit chain
//          (the sign-in from leg 3 shows; a never-signed-in account
//          shows "never");
//   leg 5  DEACTIVATE from the console: the row stays (the deactivated
//          badge), the invitee's live session is REVOKED (her cookie
//          stops resolving — gone, not merely refused), her sign-in
//          with the RIGHT password is refused honestly;
//   leg 6  REACTIVATE: she signs in again, and the round trip carries
//          her per-client assignment still (the history was kept).
//
// SELF-CONTAINED: the suite's shared stack (E2E_BASE_URL) is untouched —
// the identity instance boots on its own ports (API 9393 / astro 9293,
// the fixture RP on 9294) with its own SQLite file.
// ═══════════════════════════════════════════════════════════════════

import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import puppeteer, { type Browser, type Page } from 'puppeteer'
import { spawn, type ChildProcess } from 'node:child_process'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { existsSync, mkdirSync, rmSync, cpSync } from 'node:fs'
import { closeBrowser, delay } from './helpers'
import { fixtureOpSigningKey } from './fixtures/op-signing-key'
import { startStubRp, type StubRp } from './fixtures/stub-rp'

const BROWSER_DIR = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const FIXTURES = join(BROWSER_DIR, 'e2e', 'fixtures')
const DB_DIR = join(BROWSER_DIR, '.cache', 'id-03')

// Port-isolated: clear of the shared dev stack (5190/3190), the fed-01
// stacks (8291/8292/8491/8492), the fed-05 (8890/7890/8891/7891), fed-06
// (8690/7690/8691/7691), the id-01 stack (8693/8393/8694), the fed-10
// stub (8699), the local identity dev stack (7390/7190), the id-02
// stack (8793/8593/8794), the id-08 stack (8993/8893/8994), the local
// id-10/id-03 dev loops (6390/6290) and the id-10 stack (9193/9093).
const ID_API = 9393
const ID_WEB = 9293
const RP_PORT = 9294

const ISSUER = `http://localhost:${ID_WEB}` // the astro origin (the browser's OP)
const RP_CLIENT_ID = 'fixture-rp'
const RP_CLIENT_SECRET = 'fixture-rp-secret'

// The registry's subject: the invited account (the OP default role
// viewer), assigned tl_operator on the fixture RP — whose claims policy
// allows ONLY tl_operator/ia_officer/viewer (a role outside the
// allowlist is never even offered).
const ERIN = {
  name: 'Ms. Erin Registry',
  email: 'erin.registry@example.org',
  password: 'erin registry passphrase',
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

/** Boot the identity-profile stack: the API on its own SQLite file with
 *  the OP env (issuer + the client-registry seed: the fixture RP WITH
 *  its role allowlist), the profile seed through the dev-reset seam,
 *  astro dev against it. */
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
      OP_ISSUER: ISSUER,
      // identity#7: a declared-issuer stack declares its signing key too
      // (the generated dev key never registers off the dev posture).
      OP_SIGNING_KEY: await fixtureOpSigningKey(),
      // The client registry's bootstrap seed: the fixture RP (a
      // confidential client carrying the role-claim policy WITH its
      // role allowlist — TODO.identity/03).
      OP_CLIENT_SEED: JSON.stringify([{
        client_id: RP_CLIENT_ID,
        name: 'The id-03 fixture RP',
        secret: RP_CLIENT_SECRET,
        redirect_uris: [`http://127.0.0.1:${RP_PORT}/callback`],
        claims_policy: { claims: ['roles', 'groups', 'org'], roles: ['tl_operator', 'ia_officer', 'viewer'] },
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

/** Sign in an OP PASSWORD account through the login form. */
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
 *  out-of-band handover — shown once). */
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

/** The signed-in session's payload (null when signed out / revoked). */
async function sessionPayload(page: Page): Promise<{ email: string; orgId: string | null; roles?: string[] } | null> {
  return page.evaluate(async () => {
    const res = await fetch('/api/auth/session', { credentials: 'include' })
    if (!res.ok) return null
    return res.json() as Promise<{ email: string; orgId: string | null; roles?: string[] }>
  })
}

/** Drop the session (the cookie is httpOnly — the browser-side delete).
 *  MUST run on the OP's origin: a relative fetch on the RP's origin hits
 *  the stub and the OP cookie survives (the leg-4 lesson).
 *
 *  After the fetch, settle the browser on the sign-in page: the guarded
 *  page the browser is leaving can self-redirect when the session dies
 *  (a still-in-flight load meets the 401 and routes to
 *  /?redirect=… — the posture every console page carries), and a
 *  caller's next goto then races that navigation (the id-10 leg-3
 *  lesson, 2026-08-24; here the id-v2026.08.30-1 deploy + the post-merge
 *  main CI runs, legs 2/3/6 — leg 3's "Execution context was destroyed"
 *  is the same race landing INSIDE this fetch, leg 6 a cascade of the
 *  dead leg 2). The whole sequence — the origin correction (the login
 *  page's live-session bounce can abort THAT goto), the fetch, the
 *  settle — carries one retry on exactly that signature. A repeated
 *  signout POST is harmless (no session left to kill). */
async function signOut(page: Page, base?: string): Promise<void> {
  const target = base ?? new URL(page.url()).origin
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      if (new URL(page.url()).origin !== target) {
        await page.goto(`${target}/`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
      }
      await page.evaluate(async () => {
        await fetch('/api/auth/signout', { method: 'POST', credentials: 'include' })
      })
      await page.goto(`${target}/`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
      return
    } catch (e) {
      const msg = String(e)
      if (attempt === 1 || !(msg.includes('ERR_ABORTED') || msg.includes('Execution context was destroyed'))) throw e
      await delay(600)
    }
  }
}

/** The registry row's account id for an email on the console page. */
async function registryIdFor(page: Page, email: string): Promise<string | null> {
  return page.evaluate((needle) => {
    const el = [...document.querySelectorAll('[data-testid^="registry-user-"]')]
      .find(e => e.textContent?.includes(needle))
    return el?.getAttribute('data-testid')?.replace('registry-user-', '') ?? null
  }, email)
}

/** A node-side password login against the API (a SECOND client's view —
 *  the revocation proof never shares the browser's cookie jar). */
async function apiPasswordLogin(stack: Stack, email: string, password: string): Promise<Response> {
  return fetch(`${stack.apiBase}/api/op/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password }),
  })
}

describe('TODO.identity/03 — the central user registry + the per-client role claims', () => {
  let stack: Stack
  let rp: StubRp
  let browser: Browser
  let page: Page
  /** Erin's account id on the registry + her one-time setup link. */
  let erinId = ''
  let erinSetupUrl = ''

  beforeAll(async () => {
    stack = await bootIdentityStack()
    rp = await startStubRp({
      port: RP_PORT,
      issuer: ISSUER,
      clientId: RP_CLIENT_ID,
      clientSecret: RP_CLIENT_SECRET,
    })
    browser = await puppeteer.launch({ headless: 'shell', protocolTimeout: 480_000, args: ['--no-sandbox', '--disable-setuid-sandbox'] })
    page = await browser.newPage()
    await page.setViewport({ width: 1440, height: 900 })
    page.on('pageerror', e => console.log('[pageerror]', String(e).slice(0, 300)))
    page.on('requestfailed', r => console.log('[requestfailed]', r.url().slice(0, 140), r.failure()?.errorText ?? ''))
  }, 600_000)

  afterAll(async () => {
    await closeBrowser(browser)
    await rp?.close()
    await stopStack(stack)
  })

  it('leg 1 — the registry console lists the OP’s accounts; the admin invites one (the setup link shows once)', { timeout: 900_000 }, async () => {
    await page.goto(`${stack.base}/`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await opSignIn(page, 'admin@oiml.org')
    await page.waitForFunction(() => window.location.pathname !== '/', { timeout: SETTLE, polling: 500 })

    await page.goto(`${stack.base}/op/admin/users`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await page.waitForSelector('[data-testid="registry"]', { timeout: SETTLE, polling: 500 })

    // The invite (the registry form): name + email + the OP default role.
    await page.type('[data-testid="registry-invite-name"]', ERIN.name)
    await page.type('[data-testid="registry-invite-email"]', ERIN.email)
    await page.select('[data-testid="registry-invite-role"]', 'viewer')
    await page.evaluate(() => (document.querySelector('[data-testid="registry-invite-submit"]') as HTMLElement).click())
    await page.waitForSelector('[data-testid="op-admin-notice"]', { timeout: SETTLE, polling: 500 })
    const notice = await page.$eval('[data-testid="op-admin-notice"]', el => el.textContent ?? '')
    expect(notice).toContain('Erin Registry')
    erinSetupUrl = await readSetupUrl(page)
    expect(erinSetupUrl).toContain('/op/setup?token=')

    // The registry list carries her — never signed in yet (the audit
    // chain reads honestly).
    await page.waitForFunction(
      (email) => [...document.querySelectorAll('[data-testid^="registry-user-"]')].some(e => e.textContent?.includes(email)),
      { timeout: SETTLE, polling: 500 },
      ERIN.email,
    )
    erinId = (await registryIdFor(page, ERIN.email))!
    expect(erinId).toBeTruthy()
    const lastSignIn = await page.$eval(`[data-testid="registry-lastsignin-${erinId}"]`, el => el.textContent ?? '')
    expect(lastSignIn).toContain('never signed in')
  })

  it('leg 2 — the invitee sets her password; the admin assigns tl_operator on the fixture client (the offer is the policy’s)', { timeout: 900_000 }, async () => {
    await signOut(page, stack.base)
    await driveSetup(page, erinSetupUrl, ERIN.password, ERIN.email)
    expect((await sessionPayload(page))?.email).toBe(ERIN.email)

    // The admin assigns the per-client role through the console editor.
    await signOut(page, stack.base)
    await page.goto(`${stack.base}/`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await opSignIn(page, 'admin@oiml.org')
    await page.waitForFunction(() => window.location.pathname !== '/', { timeout: SETTLE, polling: 500 })
    await page.goto(`${stack.base}/op/admin/users`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await page.waitForSelector(`[data-testid="registry-roles-open-${erinId}"]`, { timeout: SETTLE, polling: 500 })
    await page.evaluate((id) => {
      (document.querySelector(`[data-testid="registry-roles-open-${id}"]`) as HTMLElement).click()
    }, erinId)
    await page.waitForSelector(`[data-testid="registry-roles-${erinId}"]`, { timeout: SETTLE, polling: 500 })

    // The offer is bounded by the client's claims-policy allowlist:
    // tl_operator/ia_officer/viewer are offered — admin is NOT (the OP
    // never emits a role the client is not configured to receive, so
    // the console never offers it).
    const clientRow = `[data-testid="registry-roles-client-${erinId}-${RP_CLIENT_ID}"]`
    await page.waitForSelector(clientRow, { timeout: SETTLE, polling: 500 })
    expect(await page.$(`[data-testid="registry-role-check-${erinId}-${RP_CLIENT_ID}-tl_operator"]`)).not.toBeNull()
    expect(await page.$(`[data-testid="registry-role-check-${erinId}-${RP_CLIENT_ID}-ia_officer"]`)).not.toBeNull()
    expect(await page.$(`[data-testid="registry-role-check-${erinId}-${RP_CLIENT_ID}-admin"]`)).toBeNull()
    // The current state is the account default (viewer).
    const state = await page.$eval(`[data-testid="registry-roles-state-${erinId}-${RP_CLIENT_ID}"]`, el => el.textContent ?? '')
    expect(state).toContain('account default')
    expect(state).toContain('viewer')

    await page.evaluate((id, clientId) => {
      (document.querySelector(`[data-testid="registry-role-check-${id}-${clientId}-tl_operator"]`) as HTMLElement).click()
    }, erinId, RP_CLIENT_ID)
    await page.evaluate((id, clientId) => {
      (document.querySelector(`[data-testid="registry-roles-save-${id}-${clientId}"]`) as HTMLElement).click()
    }, erinId, RP_CLIENT_ID)
    await page.waitForSelector('[data-testid="op-admin-notice"]', { timeout: SETTLE, polling: 500 })
    const notice = await page.$eval('[data-testid="op-admin-notice"]', el => el.textContent ?? '')
    expect(notice).toContain('tl_operator')

    // The row shows the assignment.
    await page.waitForFunction(
      (testid) => {
        const el = document.querySelector(`[data-testid="${testid}"]`)
        return el && el.textContent?.includes('tl_operator')
      },
      { timeout: SETTLE, polling: 500 },
      `registry-clientroles-${erinId}`,
    )
  })

  it('leg 3 — the round trip: the consent names the roles THIS client receives; the ID token carries them', { timeout: 900_000 }, async () => {
    await signOut(page, stack.base)
    // The RP starts the flow: the browser follows its 302 to the OP.
    await page.goto(`${rp.baseUrl}/signin`, { waitUntil: 'domcontentloaded', timeout: SETTLE })

    // The OP's sign-in surface — the PASSWORD account signs in.
    await page.waitForFunction(
      () => window.location.pathname === '/' && window.location.search.includes('redirect='),
      { timeout: SETTLE, polling: 500 },
    )
    await opPasswordSignIn(page, ERIN.email, ERIN.password)

    // The consent page names the EFFECTIVE roles for this client (the
    // per-client assignment through the allowlist) before anything is
    // released.
    await page.waitForSelector('[data-testid="op-consent-allow"]', { timeout: SETTLE, polling: 500 })
    expect(new URL(page.url()).pathname).toBe('/op/consent')
    const roleClaims = await page.$eval('[data-testid="op-consent-role-claims"]', el => el.textContent ?? '')
    expect(roleClaims).toContain('tl_operator')

    // Allow → the RP's callback → the RP's signed-in page.
    await page.evaluate(() => (document.querySelector('[data-testid="op-consent-allow"]') as HTMLElement).click())
    await page.waitForSelector('[data-testid="rp-signed-in"]', { timeout: SETTLE, polling: 500 })

    // The RP's REAL validator accepted the OP's ID token — and the token
    // carries the per-client assignment (NOT the account default).
    const who = await (await fetch(`${rp.baseUrl}/whoami`)).json() as {
      claims: { iss: string; aud: string; email: string; name: string; roles?: string[]; groups?: string[]; org?: string }
      userinfo: Record<string, unknown>
      lastError: unknown
    }
    expect(who.claims.iss).toBe(ISSUER)
    expect(who.claims.aud).toBe(RP_CLIENT_ID)
    expect(who.claims.email).toBe(ERIN.email)
    expect(who.claims.name).toBe(ERIN.name)
    expect(who.claims.roles).toEqual(['tl_operator'])
    expect(who.claims.groups).toEqual(['tl_operator'])
    expect(who.lastError).toBeNull()
    expect(who.userinfo).toMatchObject({ email: ERIN.email, roles: ['tl_operator'] })
  })

  it('leg 4 — the registry’s last-sign-in column reads the audit chain', { timeout: 600_000 }, async () => {
    await signOut(page, stack.base)
    await page.goto(`${stack.base}/`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await opSignIn(page, 'admin@oiml.org')
    await page.waitForFunction(() => window.location.pathname !== '/', { timeout: SETTLE, polling: 500 })
    await page.goto(`${stack.base}/op/admin/users`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await page.waitForSelector(`[data-testid="registry-lastsignin-${erinId}"]`, { timeout: SETTLE, polling: 500 })
    // Leg 3's password sign-in landed on the audit chain — the column
    // shows it (no longer "never signed in").
    const lastSignIn = await page.$eval(`[data-testid="registry-lastsignin-${erinId}"]`, el => el.textContent ?? '')
    expect(lastSignIn).toContain('last signed in')
    expect(lastSignIn).not.toContain('never')
  })

  it('leg 5 — deactivate: the row stays, her live session is revoked, her right-password sign-in refuses honestly', { timeout: 900_000 }, async () => {
    // Erin holds a LIVE session (a second client's, over the API — the
    // browser's jar stays the admin's).
    const login = await apiPasswordLogin(stack, ERIN.email, ERIN.password)
    expect(login.ok).toBe(true)
    const erinCookie = login.headers.get('set-cookie')!.split(';')[0]!
    const before = await fetch(`${stack.apiBase}/api/op/account`, { headers: { cookie: erinCookie } })
    expect(before.status).toBe(200)

    // The admin deactivates her from the console (the browser is signed
    // in as the admin from leg 4).
    await page.goto(`${stack.base}/op/admin/users`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await page.waitForSelector(`[data-testid="registry-toggle-${erinId}"]`, { timeout: SETTLE, polling: 500 })
    await page.evaluate((id) => {
      (document.querySelector(`[data-testid="registry-toggle-${id}"]`) as HTMLElement).click()
    }, erinId)
    await page.waitForSelector('[data-testid="op-admin-notice"]', { timeout: SETTLE, polling: 500 })
    const notice = await page.$eval('[data-testid="op-admin-notice"]', el => el.textContent ?? '')
    expect(notice).toContain('deactivated')
    expect(notice).toContain('session')

    // The row STAYS (the history), marked deactivated.
    await page.waitForFunction(
      (testid) => {
        const el = document.querySelector(`[data-testid="${testid}"]`)
        return el && el.textContent?.includes('deactivated')
      },
      { timeout: SETTLE, polling: 500 },
      `registry-user-${erinId}`,
    )

    // Her live session is REVOKED — the cookie resolves to nothing
    // (gone, not merely refused at the join).
    const after = await fetch(`${stack.apiBase}/api/op/account`, { headers: { cookie: erinCookie } })
    expect(after.status).toBe(401)

    // Her sign-in with the RIGHT password refuses honestly — on the
    // page AND on the API.
    const refused = await apiPasswordLogin(stack, ERIN.email, ERIN.password)
    expect(refused.status).toBe(403)
    expect(((await refused.json()) as { error: string }).error).toContain('deactivated')

    await signOut(page, stack.base)
    await page.goto(`${stack.base}/`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await opPasswordSignIn(page, ERIN.email, ERIN.password)
    await page.waitForSelector('[data-testid="login-error"]', { timeout: SETTLE, polling: 500 })
    const message = await page.$eval('[data-testid="login-error"]', el => el.textContent ?? '')
    expect(message).toContain('deactivated')
    expect(new URL(page.url()).pathname).toBe('/')
  })

  it('leg 6 — reactivate: she signs in again, and the round trip still carries her assignment (the history was kept)', { timeout: 900_000 }, async () => {
    // The admin reactivates her from the console.
    await page.goto(`${stack.base}/`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await opSignIn(page, 'admin@oiml.org')
    await page.waitForFunction(() => window.location.pathname !== '/', { timeout: SETTLE, polling: 500 })
    await page.goto(`${stack.base}/op/admin/users`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await page.waitForSelector(`[data-testid="registry-toggle-${erinId}"]`, { timeout: SETTLE, polling: 500 })
    await page.evaluate((id) => {
      (document.querySelector(`[data-testid="registry-toggle-${id}"]`) as HTMLElement).click()
    }, erinId)
    await page.waitForSelector('[data-testid="op-admin-notice"]', { timeout: SETTLE, polling: 500 })
    const notice = await page.$eval('[data-testid="op-admin-notice"]', el => el.textContent ?? '')
    expect(notice).toContain('reactivated')

    // She signs in again (the right password works)…
    await signOut(page, stack.base)
    await page.goto(`${stack.base}/`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await opPasswordSignIn(page, ERIN.email, ERIN.password)
    await page.waitForFunction(() => window.location.pathname !== '/', { timeout: SETTLE, polling: 500 })
    expect((await sessionPayload(page))?.email).toBe(ERIN.email)

    // …and a fresh round trip (her LIVE session goes straight to the
    // consent page) still carries the per-client assignment —
    // deactivation kept the rows (the history), never wiped them.
    await page.goto(`${rp.baseUrl}/signin`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await page.waitForSelector('[data-testid="op-consent-allow"]', { timeout: SETTLE, polling: 500 })
    await page.evaluate(() => (document.querySelector('[data-testid="op-consent-allow"]') as HTMLElement).click())
    await page.waitForSelector('[data-testid="rp-signed-in"]', { timeout: SETTLE, polling: 500 })
    const who = await (await fetch(`${rp.baseUrl}/whoami`)).json() as { claims: { roles?: string[] } }
    expect(who.claims.roles).toEqual(['tl_operator'])
  })
})
