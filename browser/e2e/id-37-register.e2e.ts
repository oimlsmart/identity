// ═══════════════════════════════════════════════════════════════════
// TODO.restructure/05 — the public SELF-REGISTRATION, the e2e (the
// identity-profile stack + the stub mailer + the fixture RP, the id-29
// boot pattern): the applicant's own arc over real HTTP and the real
// UI —
//
//   leg 1  the sign-in page carries the register entry; /register
//          renders the form;
//   leg 2  a short password is refused at the POLICY gate — no account
//          exists (the honest 401 on a login attempt);
//   leg 3  the happy register: the account stands, the verify link
//          rides the mail (never the answer), the password signs in AT
//          ONCE, the console shows the unverified banner, and the RP
//          round trip answers email_verified FALSE on both surfaces;
//   leg 4  the MAILED link completes: the banner lifts, the claim
//          answers TRUE — the register arc's mailbox proof is the same
//          'verify' ceremony the invited accounts ride;
//   leg 5  the duplicate register answers the honest 409 in the form.
//
// SELF-CONTAINED: own ports (API 10647 / astro 10648 / mailer stub
// 10649 / fixture RP 10650 — above id-36's 10644-10646), own SQLite
// file. THE BROWSER IS PER-LEG (the id-02 lesson).
// ═══════════════════════════════════════════════════════════════════

import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import puppeteer, { type Browser, type Page } from 'puppeteer'
import { spawn, type ChildProcess } from 'node:child_process'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { existsSync, mkdirSync, rmSync, cpSync, appendFileSync } from 'node:fs'
import { closeBrowser, delay } from './helpers'
import { fixtureOpSigningKey } from './fixtures/op-signing-key'
import { startStubMailer, type StubMailer } from './fixtures/stub-mailer'
import { startStubRp, type StubRp } from './fixtures/stub-rp'

const BROWSER_DIR = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const FIXTURES = join(BROWSER_DIR, 'e2e', 'fixtures')
const DB_DIR = join(BROWSER_DIR, '.cache', 'id-37')

// Port-isolated: above id-36's 10644-10646.
const ID_API = 10647
const ID_WEB = 10648
const MAIL_PORT = 10649
const RP_PORT = 10650

const ISSUER = `http://localhost:${ID_WEB}`
const MAIL_KEY = 'id37-stub-mail-key'
const RP_CLIENT_ID = 'fixture-rp'
const RP_CLIENT_SECRET = 'fixture-rp-secret'

const ROOT = { email: 'root@oimlsmart.org', name: 'Root Operator', password: 'the root operator passphrase' }
const APPLICANT = { email: 'applicant@example.org', name: 'Applicant Example', password: 'an applicant passphrase' }

interface Stack {
  api: ChildProcess
  astro: ChildProcess
  base: string
  apiBase: string
  logs: string[]
}

function spawnLogged(cmd: string, args: string[], env: NodeJS.ProcessEnv, logs: string[]): ChildProcess {
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

async function bootIdentityStack(mailer: StubMailer): Promise<Stack> {
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
      OP_ACCOUNT_SEED: JSON.stringify([{ email: ROOT.email, name: ROOT.name, role: 'admin' }]),
      OP_CLIENT_SEED: JSON.stringify([{
        client_id: RP_CLIENT_ID,
        name: 'The e2e fixture RP',
        secret: RP_CLIENT_SECRET,
        redirect_uris: [`http://127.0.0.1:${RP_PORT}/callback`],
        claims_policy: { claims: ['roles', 'groups', 'org'] },
      }]),
      EMAIL_FROM: 'OIML SMART Identity <no-reply@oimlsmart.org>',
      MAIL_PROVIDER_URL: `${mailer.baseUrl}/emails`,
      MAIL_PROVIDER_KEY: MAIL_KEY,
      MAIL_RATE_LIMIT_CAPACITY: '50',
    }, logs)
    const apiBase = `http://localhost:${ID_API}`
    await waitForHttp(`${apiBase}/api/health`, 120_000, logs)

    const reset = await fetch(`${apiBase}/api/dev-reset`, { method: 'POST' })
    if (!reset.ok) throw new Error(`dev-reset on ${apiBase} answered ${reset.status}\n${logs.join('').slice(-2000)}`)

    const seedProbe = await fetch(`${apiBase}/api/op/login`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: 'nobody@example.org', password: 'a probe, not a password' }),
    })
    if (seedProbe.status !== 401) throw new Error(`the OP login probe answered ${seedProbe.status} (401 expected)\n${logs.join('').slice(-2000)}`)

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

const SETTLE = 240_000
const APP_COLD = 840_000

const PROGRESS_LOG = join(DB_DIR, 'progress.log')
function flog(page: Page | null, msg: string): void {
  const url = page && !page.isClosed() ? page.url() : '(no page)'
  const line = `${new Date().toISOString()} ${msg} @ ${url}\n`
  try { appendFileSync(PROGRESS_LOG, line) } catch { /* the log never breaks the leg */ }
}

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

async function passwordCookie(base: string, email: string, password: string): Promise<string> {
  const res = await fetch(`${base}/api/op/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password }),
  })
  expect(res.ok, `password sign-in ${email}`).toBe(true)
  await new Promise(r => setTimeout(r, 50)) // the notice rides beside the answer (TODO.restructure/27)
  return res.headers.get('set-cookie')!.split(';')[0]!.split('=')[1]!
}

async function signInViaCookie(page: Page, base: string, cookieValue: string): Promise<void> {
  await page.setCookie({ name: 'oiml-session', value: cookieValue, url: base })
}

function linkFromEmailText(text: string | undefined): string {
  const link = (text ?? '').split('\n').map(l => l.trim()).find(l => l.startsWith('http'))
  expect(link, 'the email text carries its action link').toBeTruthy()
  return link!
}

async function rpRoundTrip(page: Page, rp: StubRp): Promise<void> {
  await page.goto(`${rp.baseUrl}/signin`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
  const consentSel = '[data-testid="op-consent-allow"]'
  const doneSel = '[data-testid="rp-signed-in"]'
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

/** The register form's fill + submit, over the REAL page. */
async function fillRegister(page: Page, name: string, email: string, password: string): Promise<void> {
  await page.waitForSelector('[data-testid="register-form"], [data-testid="register"] form', { timeout: SETTLE, polling: 500 })
  await page.type('[data-testid="register-name"]', name)
  await page.type('[data-testid="register-email"]', email)
  await page.type('[data-testid="register-password"]', password)
  await page.click('[data-testid="register-submit"]')
}

describe('TODO.restructure/05 — the public self-registration (the identity profile)', () => {
  let stack: Stack
  let mailer: StubMailer
  let rp: StubRp
  let rootCookie: string

  beforeAll(async () => {
    mailer = await startStubMailer({ expectedKey: MAIL_KEY, port: MAIL_PORT })
    stack = await bootIdentityStack(mailer)
    rp = await startStubRp({
      port: RP_PORT,
      issuer: ISSUER,
      clientId: RP_CLIENT_ID,
      clientSecret: RP_CLIENT_SECRET,
    })

    // The root admin's password through the boot-logged setup link (the
    // subject never needs the admin — registration is the applicant's
    // own act — but the duplicate leg's cross-check reads the registry).
    const deadline = Date.now() + 60_000
    let setupUrl = ''
    while (Date.now() < deadline) {
      const m = /bootstrap: account root@oimlsmart\.org has no password[^\n]*\n\s*(\S+\/op\/setup\?token=\S+)/.exec(stack.logs.join(''))
      if (m) { setupUrl = m[1]!; break }
      await delay(500)
    }
    expect(setupUrl, 'the bootstrap setup link in the boot log').toContain('/op/setup?token=')
    const rootEnroll = await fetch(`${stack.apiBase}/api/op/enroll/${new URL(setupUrl).searchParams.get('token')}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ password: ROOT.password }),
    })
    expect(rootEnroll.status).toBe(200)
    rootCookie = await passwordCookie(stack.base, ROOT.email, ROOT.password)
    mailer.reset()
  }, 600_000)

  afterAll(async () => {
    await rp?.close()
    await mailer?.close()
    await stopStack(stack)
  })

  it('leg 1 — the sign-in page carries the register entry; /register renders the form', { timeout: 900_000 }, async () => {
    await withPage(async (page) => {
      flog(page, 'leg1: opening the sign-in page')
      await page.goto(`${stack.base}/`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
      await page.waitForSelector('[data-testid="login-register-link"]', { timeout: APP_COLD, polling: 500 })
      await Promise.all([
        page.waitForNavigation({ waitUntil: 'domcontentloaded', timeout: SETTLE }),
        page.click('[data-testid="login-register-link"]'),
      ])
      await page.waitForSelector('[data-testid="register-submit"]', { timeout: SETTLE, polling: 500 })
      expect(await page.$eval('[data-testid="register-email"]', el => (el as HTMLInputElement).type)).toBe('email')
      expect(await page.$eval('[data-testid="register-password"]', el => (el as HTMLInputElement).type)).toBe('password')
      flog(page, 'leg1: done')
    })
  })

  it('leg 2 — a short password is refused at the policy gate; NO account exists', { timeout: 900_000 }, async () => {
    await withPage(async (page) => {
      flog(page, 'leg2: the short-password refusal')
      await page.goto(`${stack.base}/register`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
      // The policy gate is CLIENT-side on this form: a short password
      // disables the submit (the server's own 400 is the unit spec's
      // leg — the UI never sends the request to refuse).
      await fillRegister(page, APPLICANT.name, APPLICANT.email, 'short')
      const disabled = await page.waitForFunction(
        () => (document.querySelector('[data-testid="register-submit"]') as HTMLButtonElement | null)?.disabled === true,
        { timeout: SETTLE, polling: 500 },
      )
      expect(disabled, 'the short password keeps the submit disabled').toBeTruthy()
      const hint = await page.$eval('[data-testid="register-password"]', el => (el.parentElement?.querySelector('p')?.textContent ?? ''))
      expect(hint).toContain('12')
    })
    // The refused password never touched state: the login attempt 401s.
    const login = await fetch(`${stack.base}/api/op/login`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: APPLICANT.email, password: 'short' }),
    })
    expect(login.status).toBe(401)
  })

  it('leg 3 — the happy register: mailed link, sign-in NOW, honest unverified claims', { timeout: 900_000 }, async () => {
    let verifyUrl = ''
    await withPage(async (page) => {
      flog(page, 'leg3: the register submit')
      await page.goto(`${stack.base}/register`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
      await fillRegister(page, APPLICANT.name, APPLICANT.email, APPLICANT.password)
      await page.waitForSelector('[data-testid="register-done-title"]', { timeout: SETTLE, polling: 500 })
      expect(await page.$eval('[data-testid="register-done-title"]', el => el.textContent ?? ''))
        .toContain('mailbox')
    })

    // The verify link rode the mail — the success panel never echoes it.
    const mails = mailer.messages.filter(m => m.to === APPLICANT.email && (m.text ?? '').includes('/op/email-change?token='))
    expect(mails.length, 'the verify mail was sent to the applicant').toBe(1)
    verifyUrl = linkFromEmailText(mails[0]!.text)

    // The password signs in AT ONCE; the console shows the unverified
    // banner; the RP round trip answers email_verified FALSE.
    const cookie = await passwordCookie(stack.base, APPLICANT.email, APPLICANT.password)
    await withPage(async (page) => {
      await signInViaCookie(page, stack.base, cookie)
      flog(page, 'leg3: the console banner')
      await page.goto(`${stack.base}/op/account`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
      await page.waitForSelector('[data-testid="account-verification-banner"]', { timeout: APP_COLD, polling: 500 })
      expect(await page.$eval('[data-testid="account-verification-banner"]', el => el.textContent ?? ''))
        .toContain('not verified')

      await rpRoundTrip(page, rp)
      expect(await page.$eval('[data-testid="rp-email"]', el => el.textContent?.trim())).toBe(APPLICANT.email)
      expect(rp.claims?.email_verified, 'the self-registered, unproven mailbox reads false (the ID token)').toBe(false)
      expect(rp.userinfo?.email_verified, 'userinfo answers the same').toBe(false)
      flog(page, 'leg3: done')
    })

    // leg 4 (rides the same stack state): the MAILED link completes —
    // the banner lifts, the claim answers TRUE.
    const complete = await fetch(`${stack.apiBase}/api/op/email-change/${encodeURIComponent(new URL(verifyUrl).searchParams.get('token')!)}`, { method: 'POST' })
    expect(complete.status, 'the mailed link completes').toBe(200)
    await withPage(async (page) => {
      const fresh = await passwordCookie(stack.base, APPLICANT.email, APPLICANT.password)
      await signInViaCookie(page, stack.base, fresh)
      flog(page, 'leg4: the banner lifted')
      await page.goto(`${stack.base}/op/account`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
      await page.waitForSelector('[data-testid="account-email-verified"]', { timeout: APP_COLD, polling: 500 })
      expect(await page.$('[data-testid="account-verification-banner"]')).toBeNull()
      await rpRoundTrip(page, rp)
      expect(rp.claims?.email_verified, 'the mailbox proof stamps the claim').toBe(true)
      expect(rp.userinfo?.email_verified).toBe(true)
      flog(page, 'leg4: done')
    })
  })

  it('leg 5 — the duplicate register answers the honest 409 in the form', { timeout: 900_000 }, async () => {
    await withPage(async (page) => {
      flog(page, 'leg5: the duplicate')
      await page.goto(`${stack.base}/register`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
      await fillRegister(page, APPLICANT.name, APPLICANT.email, APPLICANT.password)
      await page.waitForSelector('[data-testid="register-error"]', { timeout: SETTLE, polling: 500 })
      expect(await page.$eval('[data-testid="register-error"]', el => el.textContent ?? ''))
        .toContain('already exists')
      flog(page, 'leg5: done')
    })
    // The registry still holds exactly one row for the address (the
    // 409 never minted a second account).
    const accounts = await fetch(`${stack.base}/api/op/accounts`, {
      headers: { cookie: `oiml-session=${rootCookie}` },
    })
    const rows = await accounts.json() as Array<{ email: string }>
    expect(rows.filter(r => r.email === APPLICANT.email).length).toBe(1)
  })
})
