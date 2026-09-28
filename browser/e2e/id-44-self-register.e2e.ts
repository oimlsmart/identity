// ─────────────────────────────────────────────────────────────────────
// id-44 — the Ommisa member tier's self-enrollment (the 2026-09-26
// flow, the four gates end-to-end):
//
//   leg 1  the happy path: the real pages — the start form (the
//          pickers + the name + the work email) → the attribution
//          round-trip through the stub GitHub → the emailed link shown
//          once (no mailer) → the click → the setup password → the
//          sign-in works. The account carries the registry roles.
//   leg 2  the rejections: the domain mismatch names the owning
//          organization; an unmatched domain lands in the join queue
//          with the complete sentence — and creates NO account.
//
// SELF-CONTAINED: own ports (API 9593 / astro 9493), own SQLite file,
// the stub GitHub. The attribution provider rides the stub (the
// id-08 pattern: GITHUB_*_BASE_URL point at the stub; the provider row
// 'github' is created by the demo admin over the API).
// ─────────────────────────────────────────────────────────────────────

import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import puppeteer, { type Browser, type Page } from 'puppeteer'
import { spawn, type ChildProcess } from 'node:child_process'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { mkdirSync, rmSync, existsSync, cpSync } from 'node:fs'
import { closeBrowser, delay } from './helpers'
import { startStubIdp, type StubIdp } from './fixtures/stub-idp'
import { fixtureOpSigningKey } from './fixtures/op-signing-key'

const BROWSER_DIR = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const DB_DIR = join(BROWSER_DIR, '.cache', 'id-44')

const ID_API = 9593
const ID_WEB = 9493
const SETTLE = 240_000

const ROOT = { email: 'root@oimlsmart.org', name: 'Root Operator', password: 'the root operator passphrase' }
const MEMBER = { email: 'member@nist.gov', name: 'NIST Member', password: 'the member passphrase 2026' }

interface Stack { api: ChildProcess; astro: ChildProcess; base: string; apiBase: string; logs: string[] }

let stubIdp: StubIdp | null = null

const IDP_CLIENT_ID = 'oiml-smart-op'
const IDP_SECRET = 'e2e-idp-secret'

function spawnLogged(cmd: string, args: string[], env: NodeJS.ProcessEnv, logs: string[]): ChildProcess {
  const inherited = Object.fromEntries(
    Object.entries(process.env).filter(([k]) => k !== 'NODE_ENV' && k !== 'VITEST' && !k.startsWith('VITEST_')),
  ) as NodeJS.ProcessEnv
  const proc = spawn(cmd, args, { cwd: BROWSER_DIR, env: { ...inherited, ...env }, stdio: ['ignore', 'pipe', 'pipe'], detached: true })
  proc.stdout?.on('data', d => logs.push(String(d)))
  proc.stderr?.on('data', d => logs.push(String(d)))
  return proc
}

function killTreeHard(proc: ChildProcess | undefined): void {
  if (!proc || proc.exitCode !== null || proc.pid === undefined) return
  try { process.kill(-proc.pid, 'SIGKILL') } catch { /* gone */ }
  try { proc.kill('SIGKILL') } catch { /* gone */ }
}

async function waitForHttp(url: string, timeoutMs: number, logs: string[]): Promise<void> {
  const deadline = Date.now() + timeoutMs
  let lastError = ''
  while (Date.now() < deadline) {
    try {
      const res = await fetch(url)
      if (res.status < 500) return
      lastError = `HTTP ${res.status}`
    } catch (e) { lastError = String(e) }
    await delay(1_000)
  }
  throw new Error(`timed out waiting for ${url} (${lastError})\n--- stack logs ---\n${logs.join('').slice(-4000)}`)
}

async function bootIdentityStack(idp: StubIdp): Promise<Stack> {
  const logs: string[] = []
  mkdirSync(DB_DIR, { recursive: true })
  const dbPath = join(DB_DIR, 'identity.db')
  for (const suffix of ['', '-wal', '-shm']) rmSync(dbPath + suffix, { force: true })

  let api: ChildProcess | undefined
  let astro: ChildProcess | undefined
  try {
    for (const probe of [`http://localhost:${ID_API}/api/health`, `http://localhost:${ID_WEB}/`]) {
      try {
        const res = await fetch(probe)
        if (res.status < 500) throw new Error(`port for ${probe} is already serving — a leftover stack?`)
      } catch (e) {
        if (e instanceof Error && e.message.includes('already serving')) throw e
      }
    }

    api = spawnLogged(join(BROWSER_DIR, 'node_modules', '.bin', 'tsx'), ['server/serve.ts'], {
      PORT: String(ID_API),
      DATABASE_PATH: dbPath,
      ENTITY_BACKEND: 'server',
      INSTANCE_PROFILE: join(BROWSER_DIR, 'e2e', 'fixtures', 'instance.profile.identity.yaml'),
      OIDC_ISSUER: '',
      OIDC_CLIENT_ID: '',
      DEMO_ACCOUNTS_ENABLED: 'true',
      OP_ISSUER: `http://localhost:${ID_WEB}`,
      OP_SIGNING_KEY: await fixtureOpSigningKey(),
      // The root administrator's declared seed: the boot mints the
      // one-time setup link (the log line the leg reads).
      OP_ACCOUNT_SEED: JSON.stringify([{ email: ROOT.email, name: ROOT.name, role: 'admin' }]),
      // The member tier's own config: ON, the Ommisa client carrying
      // the registry roles. The landing org needs NO configuration —
      // it is the organization the registry names, keyed by the domain.
      OP_SELF_REGISTER: '1',
      OP_SELF_REGISTER_CLIENT: 'oiml-ommisa',
      // The bot gate ARMED (the always-pass pair): the 2026-09-28
      // production finding — the start's Turnstile plumbing was
      // invisible with the gate off. Leg 1 now walks the gated path.
      TURNSTILE_SITE_KEY: '1x00000000000000000000AA',
      TURNSTILE_SECRET: '1x0000000000000000000000000000000AA',
      // The attribution upstream's client secret (the row references it).
      IDP_E2E_SECRET: IDP_SECRET,
    }, logs)
    const apiBase = `http://localhost:${ID_API}`
    await waitForHttp(`${apiBase}/api/health`, 120_000, logs)
    const reset = await fetch(`${apiBase}/api/dev-reset`, { method: 'POST' })
    if (!reset.ok) throw new Error(`dev-reset answered ${reset.status}`)

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
  } catch (err) {
    for (const proc of [astro, api]) killTreeHard(proc)
    throw err
  }

  function waitForHttp(url: string, timeoutMs: number, lgs: string[], exact200 = false): Promise<void> {
    const deadline = Date.now() + timeoutMs
    let lastError = ''
    const walk = async (): Promise<void> => {
      while (Date.now() < deadline) {
        try {
          const res = await fetch(url)
          if (exact200 ? res.status === 200 : res.status < 500) return
          lastError = `HTTP ${res.status}`
        } catch (e) { lastError = String(e) }
        await delay(1_000)
      }
      throw new Error(`timed out waiting for ${url} (${lastError})\n--- stack logs ---\n${lgs.join('').slice(-4000)}`)
    }
    return walk()
  }
}

/** The country COMBOBOX drive (an input, not a select): type to
 *  filter, click the matching option button. */
async function pickCountry(page: Page, name: string): Promise<void> {
  await page.click('[data-testid="selfreg-country"]')
  await page.type('[data-testid="selfreg-country"]', name)
  await page.waitForSelector(`[data-testid="selfreg-country-options"] [data-country="${name}"]`, { timeout: SETTLE, polling: 500 })
  await page.click(`[data-testid="selfreg-country-options"] [data-country="${name}"]`)
}

describe('id-44 — the member tier\'s self-enrollment (the four gates)', () => {
  let stack: Stack
  let browser: Browser

  beforeAll(async () => {
    stubIdp = await startStubIdp({ port: 9594 })
    stack = await bootIdentityStack(stubIdp)
    browser = await puppeteer.launch({ headless: 'shell', protocolTimeout: 480_000, args: ['--no-sandbox', '--disable-setuid-sandbox'] })
  }, 900_000)

  afterAll(async () => {
    await closeBrowser(browser)
    if (stack) {
      for (const proc of [stack.astro, stack.api]) killTreeHard(proc)
    }
    await stubIdp?.close()
  })

  it('leg 1 — the four gates, end to end: the form → the attribution → the emailed link → the verified creation → the sign-in', { timeout: 900_000 }, async () => {
    const page = await browser.newPage()
    await page.setViewport({ width: 1440, height: 900 })

    // The admin bootstraps: the root's seed link sets the password; the
    // admin activates the member org + registers the attribution
    // provider row (the stub GitHub behind it). The seed runs on the
    // FIRST credential-gated request (the lazy request-driven seed) —
    // the loop fires the gate and polls the log for the minted link.
    const deadline = Date.now() + 60_000
    let setupUrl = ''
    while (Date.now() < deadline) {
      await fetch(`${stack.apiBase}/api/op/login`, {
        method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ email: 'seed-trigger@oimlsmart.org', password: 'no such account' }),
      })
      const m = /bootstrap: account root@oimlsmart\.org has no password[^\n]*\n\s*(\S+\/op\/setup\?token=\S+)/.exec(stack.logs.join(''))
      if (m) { setupUrl = m[1]!; break }
      await delay(500)
    }
    expect(setupUrl, 'the bootstrap setup link in the log stream').toContain('/op/setup?token=')
    await page.goto(setupUrl, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await page.waitForSelector('[data-testid="op-setup-password"]', { timeout: SETTLE, polling: 500 })
    await page.type('[data-testid="op-setup-password"]', ROOT.password)
    await page.type('[data-testid="op-setup-confirm"]', ROOT.password)
    await page.evaluate(() => (document.querySelector('[data-testid="op-setup-submit"]') as HTMLElement).click())
    await page.waitForSelector('[data-testid="account-name"]', { timeout: SETTLE, polling: 500 })

    const adminLogin = await fetch(`${stack.apiBase}/api/op/login`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: ROOT.email, password: ROOT.password }),
    })
    expect(adminLogin.ok).toBe(true)
    const cookie = adminLogin.headers.get('set-cookie')!.split(';')[0]!
    // The attribution provider: id 'github' (what the start leg picks),
    // kind 'oidc', the stub IdP behind it (the id-08 pattern).
    const provider = await fetch(`${stack.apiBase}/api/op/providers`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({
        id: 'github', kind: 'oidc', display_name: 'GitHub', enabled: true,
        issuer: stubIdp!.issuer, client_id: IDP_CLIENT_ID,
        client_secret_ref: 'env:IDP_E2E_SECRET',
      }),
    })
    expect(provider.status, await provider.text()).toBe(201)

    // THE FLOW: the start form (the pickers ride the vendored
    // projection — the United States' NIST is in it).
    page.on('framenavigated', f => { if (f === page.mainFrame()) console.log(`[leg] NAV → ${f.url()}`) })
    page.on('pageerror', e => console.log(`[leg] PAGEERROR ${String(e).slice(0, 400)}`))
    page.on('console', m => { if (m.type() === 'error' || m.type() === 'warning') console.log(`[leg] CONSOLE ${m.type()} ${m.text().slice(0, 300)}`) })
    page.on('response', r => { if (r.status() >= 400) console.log(`[leg] HTTP ${r.status()} ${r.url()}`) })
    await page.goto(`${stack.base}/op/self-register`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await page.waitForSelector('[data-testid="selfreg-country"]', { timeout: SETTLE, polling: 500 })
    await pickCountry(page, 'United States')
    await page.select('[data-testid="selfreg-org"]', 'National Institute of Standards and Technology (NIST)')
    await page.type('[data-testid="selfreg-name"]', MEMBER.name)
    await page.type('[data-testid="selfreg-email"]', MEMBER.email)
    // The gate solves before the submit (the always-pass pair
    // auto-solves; the token must STAND in the form or the start
    // refuses — the exact production failure this wait pins).
    await page.waitForFunction(() => {
      const input = document.querySelector('[data-testid="turnstile-widget"] input[name="cf-turnstile-response"]')
      return input !== null && input.value.length > 0
    }, { timeout: 120_000, polling: 500 })
    await page.click('[data-testid="selfreg-submit"]')

    // THE INTERSTITIAL: the why, then the CHOICE of who attests — the
    // leg takes the github row (the only enabled one on this stack).
    await page.waitForSelector('[data-testid="selfreg-attribution"]', { timeout: SETTLE, polling: 500 })
    await page.click('[data-testid="selfreg-attribution-github"]')

    // The attribution round-trip: the stub IdP's consent page (one link
    // per fixture user) — click the first; the return carries the code;
    // the callback sends the email (no mailer — the link shows once)
    // and lands on the sent posture.
    await page.waitForSelector('[data-testid="stub-idp-consent"]', { timeout: SETTLE, polling: 500 })
    await page.evaluate(() => (document.querySelector('ul li a') as HTMLElement).click())
    try {
      await page.waitForFunction(() => window.location.search.includes('sent=1'), { timeout: 60_000, polling: 500 })
    } catch (err) {
      try { await page.screenshot({ path: '/tmp/id44-leg1-failure.png' }) } catch { /* gone */ }
      const lines = stack.logs.join('').split('\n')
      const interesting = lines.filter(l =>
        l.includes('[op]') || l.includes('self-register') || l.includes('upstream') || /\[\d{3}\]/.test(l))
      throw new Error(`the attribution never landed on sent=1: url=${page.url()}
--- interesting api logs ---
${interesting.slice(-50).join('\n')}
--- raw tail ---
${stack.logs.join('').slice(-1500)}`)
    }
    await page.waitForSelector('[data-testid="selfreg-sent-screen"] [data-testid="selfreg-dev-link"] a', { timeout: SETTLE, polling: 500 })
    const devLinkHref = await page.$eval('[data-testid="selfreg-sent-screen"] [data-testid="selfreg-dev-link"] a', el => (el as HTMLAnchorElement).href)
    expect(devLinkHref).toContain('/op/self-register?token=')

    // THE SETUP: the link proves the mailbox — and demands the SECOND
    // verification (the 2026-09-29 ruling): one more sign-in from the
    // SAME upstream account before the password step.
    page.on('response', async r => {
      if (r.url().includes('/api/op/self-register/verify')) {
        let b = ''
        try { b = (await r.text()).slice(0, 250) } catch { /* gone */ }
        console.log(`[leg] verify answered ${r.status()} ${b}`)
      }
    })
    await page.goto(devLinkHref, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await page.waitForSelector('[data-testid="selfreg-second-begin"]', { timeout: SETTLE, polling: 500 }).catch(async () => {
      const snap = await page.evaluate(() => document.querySelector('[data-testid="selfreg-page"]')?.innerHTML.slice(400, 2200) ?? 'NO PAGE')
      console.log(`[leg] SECOND-STEP ABSENT: ${snap}`)
      throw new Error('the second step never rendered')
    })
    await page.waitForSelector('[data-testid="selfreg-verified"]', { timeout: SETTLE, polling: 500 })
    const verified = await page.$eval('[data-testid="selfreg-verified"]', el => el.textContent ?? '')
    expect(verified).toContain(MEMBER.email)
    await page.click('[data-testid="selfreg-second-begin"]')
    await page.waitForSelector('[data-testid="selfreg-second-github"]', { timeout: SETTLE, polling: 500 })
    await page.click('[data-testid="selfreg-second-github"]')
    await page.waitForSelector('[data-testid="stub-idp-consent"]', { timeout: SETTLE, polling: 500 })
    await page.evaluate(() => (document.querySelector('ul li a') as HTMLElement).click())
    await page.waitForFunction(() => window.location.search.includes('setup='), { timeout: 60_000, polling: 500 })
    console.log(`[leg] setup return: ${page.url().slice(0, 80)}`)
    await page.waitForSelector('[data-testid="selfreg-password"]', { timeout: 60_000, polling: 500 }).catch(async () => {
      const snap = await page.evaluate(() => `URL=${location.href.slice(0, 90)} BODY=${document.querySelector('[data-testid="selfreg-page"]')?.innerHTML.slice(400, 1600) ?? 'NO PAGE'}`)
      console.log(`[leg] PASSWORD ABSENT: ${snap}`)
      throw new Error('the password step never rendered')
    })
    await page.type('[data-testid="selfreg-password"]', MEMBER.password)
    await page.click('[data-testid="selfreg-complete"]')
    await page.waitForSelector('[data-testid="selfreg-done"]', { timeout: SETTLE, polling: 500 })

    // The sign-in works: the created account's password.
    const signIn = await fetch(`${stack.apiBase}/api/op/login`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: MEMBER.email, password: MEMBER.password }),
    })
    expect(signIn.status).toBe(200)

    // The registry roles ride the Ommisa client (the containment the
    // registry declares) and the org OF THE SAME DOMAIN NAME stands:
    // the registry entry's FULL NAME, active, keyed by the domain.
    const rootCookie2 = (await fetch(`${stack.apiBase}/api/op/login`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: ROOT.email, password: ROOT.password }),
    })).headers.get('set-cookie')!.split(';')[0]!
    const org = await fetch(`${stack.apiBase}/api/op/registry/orgs/nist.gov`, { headers: { cookie: rootCookie2 } })
    expect(org.status).toBe(200)
    const orgRow = await org.json() as { org?: { name?: string; state?: string; country?: string } }
    expect(orgRow.org?.name).toBe('National Institute of Standards and Technology (NIST)')
    expect(orgRow.org?.state).toBe('active')
    await page.close()
  })

  it('leg 2 — the rejections: the mismatch names the owner; the unmatched domain queues without an account', { timeout: 900_000 }, async () => {
    const page = await browser.newPage()
    await page.setViewport({ width: 1440, height: 900 })
    await page.goto(`${stack.base}/op/self-register`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await page.waitForSelector('[data-testid="selfreg-country"]', { timeout: SETTLE, polling: 500 })

    // The mismatch: the US/NIST pick with a Czech address names the
    // owning organization.
    await pickCountry(page, 'United States')
    await page.select('[data-testid="selfreg-org"]', 'National Institute of Standards and Technology (NIST)')
    await page.type('[data-testid="selfreg-name"]', 'X')
    await page.type('[data-testid="selfreg-email"]', 'someone@cmi.gov.cz')
    // The gate solves first (the armed stack): the mismatch verdict
    // lives PAST the bot gate.
    await page.waitForFunction(() => {
      const input = document.querySelector('[data-testid="turnstile-widget"] input[name="cf-turnstile-response"]')
      return input !== null && input.value.length > 0
    }, { timeout: 120_000, polling: 500 })
    await page.click('[data-testid="selfreg-submit"]')
    await page.waitForSelector('[data-testid="selfreg-error"]', { timeout: SETTLE, polling: 500 })
    const error = await page.$eval('[data-testid="selfreg-error"]', el => el.textContent ?? '')
    expect(error).toContain('registered to')
    expect(error).toContain('Czech Metrology Institute')

    // The unmatched domain: the queue sentence; NO account row. The
    // field is CLEARED first (page.type appends). The FIRST start
    // burned the token at siteverify (single-use) and the island reset
    // the widget — wait for the RE-SOLVE before this submit.
    await page.$eval('[data-testid="selfreg-email"]', (el, v) => { (el as HTMLInputElement).value = v }, '')
    await page.type('[data-testid="selfreg-email"]', 'industry@acme-industry.example')
    await page.waitForFunction(() => {
      const input = document.querySelector('[data-testid="turnstile-widget"] input[name="cf-turnstile-response"]')
      return input !== null && input.value.length > 0
    }, { timeout: 120_000, polling: 500 })
    await page.click('[data-testid="selfreg-submit"]')
    await page.waitForFunction(() => document.querySelector('[data-testid="selfreg-notice"]')?.textContent?.includes('administrator'), { timeout: SETTLE, polling: 500 })
    const probe = await fetch(`${stack.apiBase}/api/op/login`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: 'industry@acme-industry.example', password: 'whatever-passphrase' }),
    })
    expect(probe.status).toBe(401) // no account was created
    await page.close()
  })
})
