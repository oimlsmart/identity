// ═══════════════════════════════════════════════════════════════════
// The account chooser in a REAL browser (the multi-account wave's
// browser-level proof, the demonstration cast's own flow):
//
//   leg 1  the first sign-in: the RP's flow, the OP's sign-in form, the
//          consent page — the code lands and the RP validates it (the
//          stub RP's REAL validation path);
//   leg 2  the SECOND account on the SAME browser profile rides
//          prompt=login (the forced re-authentication) — and the flow's
//          login_hint PREFILLS the sign-in form's address field;
//   leg 3  the chooser: prompt=select_account renders the chooser even
//          with a live session — both remembered accounts list, the
//          presenting one badged, the login_hint's entry PRE-SELECTED —
//          and clicking the pre-selected entry hands the flow to THAT
//          account: the authorize re-entry mints its code (the
//          remembered grant skips the consent page) and the RP's
//          validated claims name the CHOSEN account;
//   leg 4  the default flow stays byte-identical: no prompt, the live
//          session, the remembered grant — the RP gets its code with no
//          chooser and no consent page;
//   leg 5  the GRANT-BASED ASSUMPTION: the presenting account holds the
//          declared grant, so the chooser lists the FULL declared demo
//          cast (seven personas — applicant, ia, tl, utilizer, cs, and
//          the kept System Administration pair, badged, the login_hint
//          pre-selects) — clicking a persona mints the session AS the
//          persona with NO persona credential presented and the flow
//          completes with the RP's validated token naming the PERSONA;
//   leg 6  an account without the grant sees no persona rows at all —
//          the chooser stays exactly the remembered accounts.
//
// SELF-CONTAINED: its own identity stack + its own stub RP (the id-01
// harness, port-isolated).
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
const DB_DIR = join(BROWSER_DIR, '.cache', 'id-42')

// Port-isolated: clear of id-01's stack (8693/8393/8694) and every other resident stack, the shared dev
// stack (5190/3190), the fed-01 stacks and the fed-10 stub.
const ID_API = 8791
const ID_WEB = 8793
const RP_PORT = 8792

const ISSUER = `http://localhost:${ID_WEB}`
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
      // The demonstration personas + the assumption grants (the
      // grant-based posture's browser-level proof): the FULL
      // seven-persona cast — applicant, ia, tl, utilizer, cs, the kept
      // System Administration persona (admin = full access), and the
      // market-surveillance officer (the role keys mirror the smart
      // demo mapping). The fixture credentials are THIS STACK's
      // throwaways — production personas carry minted random
      // credentials that exist in no repository.
      OP_ACCOUNT_SEED: JSON.stringify([
        {
          email: 'persona-applicant@oimlsmart.org', name: 'ACME Applicant (Demonstration)', role: 'user',
          orgId: 'mfr-acme', emailVerified: true, password: 'e2e-persona-credential-1',
          clientRoles: { [RP_CLIENT_ID]: ['applicant'] },
        },
        {
          email: 'persona-ia@oimlsmart.org', name: 'IA Officer (Demonstration)', role: 'user',
          orgId: 'EX1', emailVerified: true, password: 'e2e-persona-credential-3',
          clientRoles: { [RP_CLIENT_ID]: ['ia_officer'] },
        },
        {
          email: 'persona-tl@oimlsmart.org', name: 'TL Operator (Demonstration)', role: 'user',
          orgId: '21', emailVerified: true, password: 'e2e-persona-credential-4',
          clientRoles: { [RP_CLIENT_ID]: ['tl_operator'] },
        },
        {
          email: 'persona-utilizer@oimlsmart.org', name: 'Utilizer Officer (NL) (Demonstration)', role: 'user',
          orgId: 'ut-nmi-nl', emailVerified: true, password: 'e2e-persona-credential-5',
          clientRoles: { [RP_CLIENT_ID]: ['scheme_participant'] },
        },
        {
          email: 'persona-cs@oimlsmart.org', name: 'CS Administrator (Demonstration)', role: 'user',
          orgId: 'oiml-cs-demo', emailVerified: true, password: 'e2e-persona-credential-2',
          clientRoles: { [RP_CLIENT_ID]: ['cs_admin'] },
        },
        {
          email: 'persona-admin@oimlsmart.org', name: 'System Administrator (Demonstration)', role: 'user',
          emailVerified: true, password: 'e2e-persona-credential-6',
          clientRoles: { [RP_CLIENT_ID]: ['admin'] },
        },
        {
          email: 'persona-surveillance@oimlsmart.org', name: 'Market Surveillance (NL) (Demonstration)', role: 'user',
          orgId: 'ut-nmi-nl', emailVerified: true, password: 'e2e-persona-credential-7',
          clientRoles: { [RP_CLIENT_ID]: ['market_surveillance'] },
        },
      ]),
      OP_DEMO_ASSUME_GRANTS: JSON.stringify({ clientId: RP_CLIENT_ID, grantees: ['ia@oimlsmart.org'] }),
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
      ASTRO_DEV_BACKGROUND: '1',
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
 *  cast), answering whatever form the flow landed on. */
async function opSignIn(page: Page, email: string): Promise<void> {
  await page.waitForSelector('[data-testid="login-email"]', { timeout: SETTLE, polling: 500 })
  await page.evaluate(() => {
    (document.querySelector('[data-testid="login-email"]') as HTMLInputElement).value = ''
  })
  await page.type('[data-testid="login-email"]', email)
  await page.type('[data-testid="login-password"]', 'demo2026')
  await page.evaluate(() => (document.querySelector('[data-testid="login-submit"]') as HTMLElement).click())
}

describe('the account chooser (the multi-account wave, browser-level)', () => {
  let stack: Stack
  let rp: StubRp
  let browser: Browser
  let page: Page

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

  it('leg 1 — the first sign-in completes through the OP (ia@oimlsmart.org)', { timeout: 900_000 }, async () => {
    await page.goto(`${rp.baseUrl}/signin`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await page.waitForFunction(() => window.location.pathname === '/', { timeout: SETTLE, polling: 500 })
    await opSignIn(page, 'ia@oimlsmart.org')
    await page.waitForSelector('[data-testid="op-consent-allow"]', { timeout: SETTLE, polling: 500 })
    await page.evaluate(() => (document.querySelector('[data-testid="op-consent-allow"]') as HTMLElement).click())
    await page.waitForSelector('[data-testid="rp-signed-in"]', { timeout: SETTLE, polling: 500 })
    expect(await page.$eval('[data-testid="rp-email"]', el => el.textContent?.trim())).toBe('ia@oimlsmart.org')
  })

  it('leg 2 — the second account on the SAME browser rides prompt=login, the login_hint prefills the form (tl@oimlsmart.org)', { timeout: 900_000 }, async () => {
    await page.goto(`${rp.baseUrl}/signin?prompt=login&login_hint=tl%40oimlsmart.org`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await page.waitForSelector('[data-testid="login-email"]', { timeout: SETTLE, polling: 500 })
    expect(new URL(page.url()).searchParams.get('login_hint')).toBe('tl@oimlsmart.org')
    // The hint IS the prefill: the address field arrives already naming
    // the account the RP suggested.
    await page.waitForFunction(
      () => (document.querySelector('[data-testid="login-email"]') as HTMLInputElement | null)?.value === 'tl@oimlsmart.org',
      { timeout: SETTLE, polling: 500 },
    )
    await page.type('[data-testid="login-password"]', 'demo2026')
    await page.evaluate(() => (document.querySelector('[data-testid="login-submit"]') as HTMLElement).click())
    await page.waitForSelector('[data-testid="op-consent-allow"]', { timeout: SETTLE, polling: 500 })
    await page.evaluate(() => (document.querySelector('[data-testid="op-consent-allow"]') as HTMLElement).click())
    await page.waitForSelector('[data-testid="rp-signed-in"]', { timeout: SETTLE, polling: 500 })
    expect(await page.$eval('[data-testid="rp-email"]', el => el.textContent?.trim())).toBe('tl@oimlsmart.org')
  })

  it('leg 3 — prompt=select_account renders the chooser with both accounts; the hinted entry is pre-selected; the switch completes to code issuance as the CHOSEN account', { timeout: 900_000 }, async () => {
    await page.goto(`${rp.baseUrl}/signin?prompt=select_account&login_hint=ia%40oimlsmart.org`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await page.waitForSelector('[data-testid="op-choose-account"]', { timeout: SETTLE, polling: 500 })

    // Both remembered accounts list — the presenting one badged, the
    // hinted one pre-selected.
    await page.waitForSelector('[data-testid="chooser-account-ia@oimlsmart.org"]', { timeout: SETTLE, polling: 500 })
    await page.waitForSelector('[data-testid="chooser-account-tl@oimlsmart.org"]', { timeout: SETTLE, polling: 500 })
    expect(await page.$$('[data-testid="chooser-use-another"]')).toHaveLength(1) // the Google shape's escape hatch
    const current = await page.$('[data-testid="chooser-account-tl@oimlsmart.org"] [data-testid="chooser-current-badge"]')
    expect(current, 'the presenting account (tl) carries the current badge').toBeTruthy()
    const hinted = await page.$('[data-testid="chooser-hinted-badge"]')
    expect(hinted, 'the login_hint\'s account (ia) carries the pre-selection badge').toBeTruthy()
    const hintedRow = await page.$eval('[data-testid="chooser-hinted-badge"]', el => {
      const row = el.closest('[data-testid^="chooser-account-"]')
      return row?.getAttribute('data-testid')
    })
    expect(hintedRow).toBe('chooser-account-ia@oimlsmart.org')

    mkdirSync(DB_DIR, { recursive: true })
    await page.screenshot({ path: join(DB_DIR, 'chooser-two-accounts.png') })

    // The pre-selection is an affordance, never a decision: the click
    // chooses. The flow continues as the CHOSEN account — the authorize
    // re-entry mints its code (the remembered grant skips the consent
    // page) and the RP validates ITS token.
    await page.evaluate(() => (document.querySelector('[data-testid="chooser-account-ia@oimlsmart.org"]') as HTMLElement).click())
    await page.waitForSelector('[data-testid="rp-signed-in"]', { timeout: SETTLE, polling: 500 })
    expect(await page.$eval('[data-testid="rp-email"]', el => el.textContent?.trim())).toBe('ia@oimlsmart.org')
  })

  it('leg 4 — the default flow stays byte-identical: no chooser, the live session mints straight through', { timeout: 900_000 }, async () => {
    await page.goto(`${rp.baseUrl}/signin`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await page.waitForSelector('[data-testid="rp-signed-in"]', { timeout: SETTLE, polling: 500 })
    // The chooser never appeared; the presenting session (ia, chosen in
    // leg 3) signed the RP in directly.
    expect(await page.$('[data-testid="op-choose-account"]')).toBeNull()
    expect(await page.$eval('[data-testid="rp-email"]', el => el.textContent?.trim())).toBe('ia@oimlsmart.org')
  })

  // ── the grant-based assumption (the demo personas' own posture) ─────

  it('leg 5 — the grant-holder\'s chooser lists the FULL seven-persona cast; the click assumes the persona WITHOUT its credential and completes the flow as the PERSONA', { timeout: 900_000 }, async () => {
    // The presenting session is ia — the grant names her. The flow asks
    // for the chooser with the persona hinted.
    await page.goto(`${rp.baseUrl}/signin?prompt=select_account&login_hint=persona-applicant%40oimlsmart.org`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await page.waitForSelector('[data-testid="op-choose-account"]', { timeout: SETTLE, polling: 500 })

    // The whole cast lists (applicant, ia, tl, utilizer, cs, admin,
    // surveillance — every entry the declaration scopes to the client),
    // each badged; the hint pre-selects the applicant.
    const personaRow = '[data-testid="chooser-account-persona-applicant@oimlsmart.org"]'
    await page.waitForSelector(personaRow, { timeout: SETTLE, polling: 500 })
    expect(await page.$$('[data-testid="chooser-persona-badge"]')).toHaveLength(7)
    for (const seg of ['persona-admin', 'persona-tl', 'persona-ia', 'persona-utilizer', 'persona-cs', 'persona-surveillance']) {
      expect(await page.$(`[data-testid="chooser-account-${seg}@oimlsmart.org"] [data-testid="chooser-persona-badge"]`), `${seg} carries the persona badge`).toBeTruthy()
    }
    expect(await page.$(`${personaRow} [data-testid="chooser-persona-badge"]`), 'the persona badge marks the assumable row').toBeTruthy()
    const hintedRow = await page.$eval('[data-testid="chooser-hinted-badge"]', el => el.closest('[data-testid^="chooser-account-"]')?.getAttribute('data-testid'))
    expect(hintedRow).toBe('chooser-account-persona-applicant@oimlsmart.org')
    mkdirSync(DB_DIR, { recursive: true })
    await page.screenshot({ path: join(DB_DIR, 'chooser-persona-granted.png') })

    // The click assumes: no password field ever renders for the persona
    // — the session mints server-side and the flow rides on.
    await page.evaluate((sel) => (document.querySelector(sel) as HTMLElement).click(), personaRow)
    await page.waitForSelector('[data-testid="op-consent-allow"]', { timeout: SETTLE, polling: 500 })
    await page.evaluate(() => (document.querySelector('[data-testid="op-consent-allow"]') as HTMLElement).click())
    await page.waitForSelector('[data-testid="rp-signed-in"]', { timeout: SETTLE, polling: 500 })
    // The RP's validated token names the PERSONA — the assumption rode
    // the whole flow (the grantee's own identity appears nowhere).
    expect(await page.$eval('[data-testid="rp-email"]', el => el.textContent?.trim())).toBe('persona-applicant@oimlsmart.org')
  })

  it('leg 6 — an account without the grant sees no persona rows (the chooser stays exactly the remembered accounts)', { timeout: 900_000 }, async () => {
    // tl signs in fresh (the forced re-authentication; the hint's
    // prefill must land before the submit — the leg-2 posture).
    await page.goto(`${rp.baseUrl}/signin?prompt=login&login_hint=tl%40oimlsmart.org`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await page.waitForSelector('[data-testid="login-email"]', { timeout: SETTLE, polling: 500 })
    await page.waitForFunction(
      () => (document.querySelector('[data-testid="login-email"]') as HTMLInputElement | null)?.value === 'tl@oimlsmart.org',
      { timeout: SETTLE, polling: 500 },
    )
    await page.type('[data-testid="login-password"]', 'demo2026')
    await page.evaluate(() => (document.querySelector('[data-testid="login-submit"]') as HTMLElement).click())
    // tl's consent grant from leg 2 is REMEMBERED (prompt=login forces
    // re-authentication, never re-consent): the flow rides the grant
    // straight to the code and the signed-in landing.
    await page.waitForSelector('[data-testid="rp-signed-in"]', { timeout: SETTLE, polling: 500 })
    expect(await page.$eval('[data-testid="rp-email"]', el => el.textContent?.trim())).toBe('tl@oimlsmart.org')

    // The chooser under tl: remembered accounts only — no persona rows,
    // no persona badge (the grant gate held).
    await page.goto(`${rp.baseUrl}/signin?prompt=select_account`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await page.waitForSelector('[data-testid="op-choose-account"]', { timeout: SETTLE, polling: 500 })
    expect(await page.$$('[data-testid="chooser-persona-badge"]')).toHaveLength(0)
    expect(await page.$('[data-testid="chooser-account-persona-applicant@oimlsmart.org"] [data-testid="chooser-persona-badge"]')).toBeNull()
    await page.screenshot({ path: join(DB_DIR, 'chooser-persona-denied.png') })
  })
})

