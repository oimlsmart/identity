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
import { startStubGitHub, type StubGitHub } from './fixtures/stub-github'
import { fixtureOpSigningKey } from './fixtures/op-signing-key'

const BROWSER_DIR = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const DB_DIR = join(BROWSER_DIR, '.cache', 'id-44')

const ID_API = 9593
const ID_WEB = 9493
const SETTLE = 240_000

const ROOT = { email: 'root@oimlsmart.org', name: 'Root Operator', password: 'the root operator passphrase' }
const MEMBER = { email: 'member@nist.gov', name: 'NIST Member', password: 'the member passphrase 2026' }

interface Stack { api: ChildProcess; astro: ChildProcess; base: string; apiBase: string; logs: string[] }

let stubGithub: StubGitHub | null = null
const facadeLogs: string[] = []

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

async function bootIdentityStack(github: StubGitHub): Promise<Stack> {
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
      // The member tier's own config: ON, bound to the org the leg
      // activates, the Ommisa client carrying the registry roles.
      OP_SELF_REGISTER: '1',
      OP_SELF_REGISTER_ORG: 'ms-test',
      OP_SELF_REGISTER_CLIENT: 'oiml-ommisa',
      // The attribution upstream's client secret (the row references it).
      GITHUB_UPSTREAM_CLIENT_SECRET: 'id-44-stub-secret',
      // The github endpoints point at the stub.
      GITHUB_OAUTH_BASE_URL: github.baseUrl,
      GITHUB_API_BASE_URL: github.baseUrl,
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

describe('id-44 — the member tier\'s self-enrollment (the four gates)', () => {
  let stack: Stack
  let browser: Browser

  beforeAll(async () => {
    stubGithub = await startStubGitHub({ clientSecret: 'id-44-stub-secret', users: [{ login: 'the-human', id: 4401, name: 'The Human', email: 'the-human@github.example' }] })
    stack = await bootIdentityStack(stubGithub)
    browser = await puppeteer.launch({ headless: 'shell', protocolTimeout: 480_000, args: ['--no-sandbox', '--disable-setuid-sandbox'] })
  }, 900_000)

  afterAll(async () => {
    await closeBrowser(browser)
    if (stack) {
      for (const proc of [stack.astro, stack.api]) killTreeHard(proc)
    }
    await stubGithub?.close()
  })

  it('leg 1 — the four gates, end to end: the form → the attribution → the emailed link → the verified creation → the sign-in', { timeout: 900_000 }, async () => {
    const page = await browser.newPage()
    await page.setViewport({ width: 1440, height: 900 })

    // The admin bootstraps: the root's seed link sets the password; the
    // admin activates the member org + registers the attribution
    // provider row (the stub GitHub behind it).
    const setupMatch = /bootstrap: account root@oimlsmart\.org has no password[^\n]*\n\s*(\S+\/op\/setup\?token=\S+)/.exec(stack.logs.join(''))
    expect(setupMatch, 'the bootstrap setup link in the boot log').toBeTruthy()
    await page.goto(setupMatch![1]!, { waitUntil: 'domcontentloaded', timeout: SETTLE })
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
    const created = await fetch(`${stack.apiBase}/api/op/registry/orgs`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ id: 'ms-test', name: 'The Test Member State Authority', kind: 'utilizer' }),
    })
    expect(created.status, await created.text()).toBe(201)
    const activated = await fetch(`${stack.apiBase}/api/op/registry/orgs/ms-test/state`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ state: 'active' }),
    })
    expect(activated.ok).toBe(true)
    const provider = await fetch(`${stack.apiBase}/api/op/providers`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({
        id: 'github', kind: 'github', display_name: 'GitHub', enabled: true,
        client_id: 'id-44-stub-client', client_secret_ref: 'env:GITHUB_UPSTREAM_CLIENT_SECRET',
      }),
    })
    expect(provider.status, await provider.text()).toBe(201)

    // THE FLOW: the start form (the pickers ride the vendored
    // projection — the United States' NIST is in it).
    await page.goto(`${stack.base}/op/self-register`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await page.waitForSelector('[data-testid="selfreg-country"]', { timeout: SETTLE, polling: 500 })
    await page.select('[data-testid="selfreg-country"]', 'United States')
    await page.select('[data-testid="selfreg-org"]', 'National Institute of Standards and Technology (NIST)')
    await page.type('[data-testid="selfreg-name"]', MEMBER.name)
    await page.type('[data-testid="selfreg-email"]', MEMBER.email)
    await page.click('[data-testid="selfreg-submit"]')

    // The attribution round-trip: the stub's consent shortcut returns
    // the flow; the callback sends the email (no mailer — the link
    // shows once) and lands on the sent posture.
    await page.waitForFunction(() => window.location.search.includes('sent=1'), { timeout: SETTLE, polling: 500 })
    const devLinkHref = await page.$eval('[data-testid="selfreg-dev-link"] a', el => (el as HTMLAnchorElement).href)
    expect(devLinkHref).toContain('/op/self-register?token=')

    // THE CLICK: the link proves the mailbox; the setup collects the
    // password — the flow's only write.
    await page.goto(devLinkHref, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await page.waitForSelector('[data-testid="selfreg-verified"]', { timeout: SETTLE, polling: 500 })
    const verified = await page.$eval('[data-testid="selfreg-verified"]', el => el.textContent ?? '')
    expect(verified).toContain(MEMBER.email)
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
    // registry declares).
    const me = await fetch(`${stack.apiBase}/api/op/accounts/self`, { headers: { cookie: `oiml-session=${(await fetch(`${stack.apiBase}/api/op/login`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ email: ROOT.email, password: ROOT.password }) })).headers.get('set-cookie')!.split(';')[0]!}` } })
    expect(me.ok).toBe(true)
    await page.close()
  })

  it('leg 2 — the rejections: the mismatch names the owner; the unmatched domain queues without an account', { timeout: 900_000 }, async () => {
    const page = await browser.newPage()
    await page.setViewport({ width: 1440, height: 900 })
    await page.goto(`${stack.base}/op/self-register`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await page.waitForSelector('[data-testid="selfreg-country"]', { timeout: SETTLE, polling: 500 })

    // The mismatch: the US/NIST pick with a Czech address names the
    // owning organization.
    await page.select('[data-testid="selfreg-country"]', 'United States')
    await page.select('[data-testid="selfreg-org"]', 'National Institute of Standards and Technology (NIST)')
    await page.type('[data-testid="selfreg-name"]', 'X')
    await page.type('[data-testid="selfreg-email"]', 'someone@cmi.gov.cz')
    await page.click('[data-testid="selfreg-submit"]')
    await page.waitForSelector('[data-testid="selfreg-error"]', { timeout: SETTLE, polling: 500 })
    const error = await page.$eval('[data-testid="selfreg-error"]', el => el.textContent ?? '')
    expect(error).toContain('registered to')
    expect(error).toContain('Czech Metrology Institute')

    // The unmatched domain: the queue sentence; NO account row.
    await page.type('[data-testid="selfreg-email"]', 'industry@acme-industry.example')
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
