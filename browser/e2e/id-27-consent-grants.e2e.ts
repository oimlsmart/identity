// ═══════════════════════════════════════════════════════════════════
// TODO.identity-features/12 — the remembered consent grants, the e2e
// (the identity-profile stack, the id-01 spawned-stack pattern + the
// fixture RP): the consent page's "Allow" is REMEMBERED per (account,
// client, scope set), so the consent page stops showing on every
// sign-in. The full arc over real HTTP:
//
//   leg 1  the FIRST sign-in prompts: RP /signin → the OP's login →
//          the consent page (the client, the scopes, the account) →
//          Allow → the RP's signed-in page; the grant is recorded (the
//          console API names the client) and the audit chain carries
//          account.consent_granted;
//   leg 2  the SECOND sign-in to the same client SKIPS the consent page
//          ENTIRELY — the main-frame navigation log never names
//          /op/consent; the code arrives in the RP's callback directly
//          and validates (the RP's real validator);
//   leg 3  prompt=consent FORCES the page even with the live grant (the
//          OIDC re-consent signal): the stub RP's own authorize URL +
//          the parameter → the page shows → Allow → signed in again;
//   leg 4  the account console's "apps they can access": the APPS
//          section lists the granted client, the "Revoke access" act
//          flips it (the audit carries account.consent_revoked), and
//          the THIRD sign-in RE-PROMPTS — Deny this time lands the RP's
//          access_denied.
//
// SELF-CONTAINED: the suite's shared stack (E2E_BASE_URL) is untouched —
// the identity instance boots on its own ports (API 10612 / astro 10613,
// the fixture RP on 10614 — above id-26's 10609-10611) with its own
// SQLite file.
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
const DB_DIR = join(BROWSER_DIR, '.cache', 'id-27')

// Port-isolated: above every declared e2e stack (…10611 is id-26's) and
// the local dev loops.
const ID_API = 10612
const ID_WEB = 10613
const RP_PORT = 10614

const ISSUER = `http://localhost:${ID_WEB}` // the astro origin (the browser's OP)
const RP_CLIENT_ID = 'fixture-rp'
const RP_CLIENT_SECRET = 'fixture-rp-secret'

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
  // poison the spawned astro's vite cache hash).
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

/** Boot the identity-profile stack (the id-01 posture), the client
 *  registry's bootstrap seed carrying the fixture RP. */
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

/** Sign in at the OP through the form (the identity instance's demo
 *  cast). */
async function opSignIn(page: Page, email: string): Promise<void> {
  await page.waitForSelector('[data-testid="login-email"]', { timeout: SETTLE, polling: 500 })
  await page.evaluate(() => {
    (document.querySelector('[data-testid="login-email"]') as HTMLInputElement).value = ''
  })
  await page.type('[data-testid="login-email"]', email)
  await page.type('[data-testid="login-password"]', 'demo2026')
  await page.evaluate(() => (document.querySelector('[data-testid="login-submit"]') as HTMLElement).click())
}

describe('TODO.identity-features/12 — the remembered consent grants (the identity profile)', () => {
  let stack: Stack
  let rp: StubRp
  let browser: Browser
  let page: Page
  /** The main-frame navigation log — the skip's trace (the consent page
   *  must never appear in the covered legs). */
  let frames: string[]

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
    page.on('framenavigated', frame => {
      if (frame === page.mainFrame()) frames.push(frame.url())
    })
  }, 600_000)

  afterAll(async () => {
    await closeBrowser(browser)
    await rp?.close()
    await stopStack(stack)
  })

  it('leg 1 — the first sign-in PROMPTS, the allow records the grant, the audit chain carries it', { timeout: 900_000 }, async () => {
    frames = []
    await page.goto(`${rp.baseUrl}/signin`, { waitUntil: 'domcontentloaded', timeout: SETTLE })

    // The OP's sign-in surface (the authorize bounce), then the consent page.
    await page.waitForFunction(() => window.location.pathname === '/', { timeout: SETTLE, polling: 500 })
    await opSignIn(page, 'ia@oiml.org')
    await page.waitForSelector('[data-testid="op-consent-allow"]', { timeout: SETTLE, polling: 500 })
    expect(new URL(page.url()).pathname, 'the FIRST sign-in stops at the consent page').toBe('/op/consent')
    expect(await page.$eval('[data-testid="op-consent-client"]', el => el.textContent?.trim())).toBe('The e2e fixture RP')

    await page.evaluate(() => (document.querySelector('[data-testid="op-consent-allow"]') as HTMLElement).click())
    await page.waitForSelector('[data-testid="rp-signed-in"]', { timeout: SETTLE, polling: 500 })
    expect(new URL(page.url()).origin).toBe(rp.baseUrl)

    // The grant is recorded: the console API names the client + the
    // scope set (a fresh session of the SAME account reads it — the
    // grant is the account's, never the session's).
    const login = await fetch(`${stack.base}/api/auth/demo`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: 'ia@oiml.org', password: 'demo2026' }),
    })
    const cookie = login.headers.get('set-cookie')!.split(';')[0]!
    const grantsRes = await fetch(`${stack.base}/api/op/account/grants`, { headers: { cookie } })
    expect(grantsRes.status).toBe(200)
    const { grants } = await grantsRes.json() as { grants: Array<{ clientId: string; clientName: string; scopes: string[] }> }
    expect(grants.length).toBe(1)
    expect(grants[0]).toMatchObject({ clientId: RP_CLIENT_ID, clientName: 'The e2e fixture RP', scopes: ['email', 'openid', 'profile'] })

    // The audit chain carries the grant on the account's own feed.
    const activity = await (await fetch(`${stack.base}/api/op/account/activity`, { headers: { cookie } })).json() as Array<{ action: string }>
    expect(activity.map(e => e.action), 'the grant act is on the audit chain').toContain('account.consent_granted')
  })

  it('leg 2 — the SECOND sign-in SKIPS the consent page entirely (the code arrives without the page)', { timeout: 900_000 }, async () => {
    frames = []
    await page.goto(`${rp.baseUrl}/signin`, { waitUntil: 'domcontentloaded', timeout: SETTLE })

    // No sign-in form (the OP session lives), NO consent page: the flow
    // lands directly on the RP's signed-in page. The document-level trace
    // proves it — a server-side 302 chain renders no intermediate
    // documents, so the ONLY document the whole second sign-in renders is
    // the RP's callback: the login page AND the consent page would each
    // have been a rendered document.
    await page.waitForSelector('[data-testid="rp-signed-in"]', { timeout: SETTLE, polling: 500 })
    expect(new URL(page.url()).origin).toBe(rp.baseUrl)
    const stops = frames.map(u => new URL(u).pathname)
    console.log('[id-27] the second sign-in’s document trace:', stops.join(' → ') || '(no documents)')
    expect(stops, 'exactly one document renders: the RP’s callback — the login page and the consent page never do').toEqual(['/callback'])

    // The RP's REAL validator accepted the skip-minted code's token.
    const who = await (await fetch(`${rp.baseUrl}/whoami`)).json() as { claims: { email: string; nonce: string } | null; lastError: unknown }
    expect(who.lastError).toBeNull()
    expect(who.claims?.email).toBe('ia@oiml.org')
  })

  it('leg 3 — prompt=consent FORCES the page even with the live grant', { timeout: 900_000 }, async () => {
    // The stub RP's own authorize URL (its state/nonce/PKCE registered),
    // plus the OIDC re-consent signal.
    const start = await fetch(`${rp.baseUrl}/signin`, { redirect: 'manual' })
    const authorizeUrl = start.headers.get('location')!
    expect(authorizeUrl).toContain('/op/authorize')

    frames = []
    await page.goto(`${authorizeUrl}&prompt=consent`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await page.waitForSelector('[data-testid="op-consent-allow"]', { timeout: SETTLE, polling: 500 })
    expect(new URL(page.url()).pathname, 'prompt=consent defeats the remembered grant').toBe('/op/consent')

    await page.evaluate(() => (document.querySelector('[data-testid="op-consent-allow"]') as HTMLElement).click())
    await page.waitForSelector('[data-testid="rp-signed-in"]', { timeout: SETTLE, polling: 500 })
    const who = await (await fetch(`${rp.baseUrl}/whoami`)).json() as { claims: { email: string } | null }
    expect(who.claims?.email).toBe('ia@oiml.org')
  })

  it('leg 4 — the console’s APPS section revokes the access; the next sign-in RE-PROMPTS', { timeout: 900_000 }, async () => {
    // The account page's APPS section lists the granted client.
    await page.goto(`${stack.base}/op/account`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await page.waitForSelector('[data-testid="account-apps"]', { timeout: SETTLE, polling: 500 })
    await page.waitForFunction(
      () => document.querySelector('[data-testid="apps-list"]')?.textContent?.includes('The e2e fixture RP'),
      { timeout: SETTLE, polling: 500 },
    )

    // The "Revoke access" act (the row's own button — the grant id is
    // the console API's).
    const grantsRes = await page.evaluate(async () => {
      const res = await fetch('/api/op/account/grants', { credentials: 'include' })
      return res.json() as Promise<{ grants: Array<{ id: string; clientId: string }> }>
    })
    const grant = grantsRes.grants.find(g => g.clientId === RP_CLIENT_ID)!
    expect(grant, 'the grant lists').toBeTruthy()
    await page.evaluate((id) => (document.querySelector(`[data-testid="app-${id}-revoke"]`) as HTMLElement).click(), grant.id)
    await page.waitForSelector('[data-testid="apps-empty"]', { timeout: SETTLE, polling: 500 })

    // The audit chain carries the revoke.
    const activity = await page.evaluate(async () => {
      const res = await fetch('/api/op/account/activity', { credentials: 'include' })
      return res.json() as Promise<Array<{ action: string }>>
    })
    expect(activity.map(e => e.action), 'the revoke act is on the audit chain').toContain('account.consent_revoked')

    // The THIRD sign-in re-prompts; the Deny lands the RP's access_denied.
    frames = []
    await page.goto(`${rp.baseUrl}/signin`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await page.waitForSelector('[data-testid="op-consent-deny"]', { timeout: SETTLE, polling: 500 })
    expect(new URL(page.url()).pathname, 'the revoke re-prompts the consent page').toBe('/op/consent')
    await page.evaluate(() => (document.querySelector('[data-testid="op-consent-deny"]') as HTMLElement).click())
    await page.waitForSelector('[data-testid="rp-error"]', { timeout: SETTLE, polling: 500 })
    expect(await page.$eval('[data-testid="rp-error-kind"]', el => el.textContent?.trim())).toBe('access_denied')
  })
})
