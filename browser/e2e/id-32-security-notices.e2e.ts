// ═══════════════════════════════════════════════════════════════════
// TODO.identity-sso/04 slice D — the security notices, the e2e (the
// identity-profile stack + the stub mailer, the id-29 boot pattern):
// the triggers fire over the REAL UI and the notices land in the stub's
// capture —
//
//   leg 1  the console password change mails 'password_changed' (the
//          reset pointer rides the text — the sign-in page's "Forgot
//          your password?" panel, `${issuer}/`);
//   leg 2  the console email change + the mailed link's completion mail
//          'email_changed' to BOTH the new primary (the fan-out) and the
//          old address (the direct send — the mailbox that stopped being
//          the address of record);
//   leg 3  the console TOTP enroll + revoke mail 'factor_enrolled' /
//          'factor_revoked' with the user-chosen name in the label;
//   leg 4  the admin's client-roles grant mails 'client_roles_granted'
//          (the registry client's display name).
//
// The in-process twin (src/__tests__/id-security-notices.test.ts) covers
// the remaining triggers (the recovery-code sign-in's specialized
// notice, the linked-method pair, the locale switch, the empty-grant
// silence).
//
// SELF-CONTAINED: own ports (API 10631 / astro 10632 / mailer stub
// 10633 — above id-30's 10623-10626 and id-31's 10627-10630; 10634
// reserved), own SQLite file.
//
// THE BROWSER IS PER-LEG (the id-02 lesson); cross-leg state rides the
// DATABASE + the stub mailer's capture.
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
import { totpAtStep } from '../server/auth/op/totp'

const BROWSER_DIR = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const FIXTURES = join(BROWSER_DIR, 'e2e', 'fixtures')
const DB_DIR = join(BROWSER_DIR, '.cache', 'id-32')

// Port-isolated: above id-31's 10627-10630.
const ID_API = 10631
const ID_WEB = 10632
const MAIL_PORT = 10633

const ISSUER = `http://localhost:${ID_WEB}` // the astro origin (the browser's OP)
const MAIL_KEY = 'id32-stub-mail-key'
const PRODUCT = 'OIML SMART Identity'

const ROOT = { email: 'root@oimlsmart.org', name: 'Root Operator', password: 'the root operator passphrase' }

interface Stack {
  api: ChildProcess
  astro: ChildProcess
  base: string
  apiBase: string
  logs: string[]
}

function spawnLogged(cmd: string, args: string[], env: NodeJS.ProcessEnv, logs: string[]): ChildProcess {
  // detached (the process group dies together); the env SCRUBS the vitest
  // markers (NODE_ENV=test would poison the spawned astro's vite cache).
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

/** Boot the identity-profile stack with the mail provider bound to the
 *  stub (the id-29 posture) + the breach corpus declared OFF (slice B's
 *  env: no enrollment reaches the live HIBP from a test). */
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
        client_id: 'hub-instance',
        name: 'OIML SMART platform hub',
        secret: 'hub-secret-123',
        redirect_uris: ['https://hub.example/api/auth/callback/oidc'],
        claims_policy: { claims: ['roles', 'groups', 'org'] },
      }]),
      EMAIL_FROM: 'OIML SMART Identity <no-reply@oimlsmart.org>',
      MAIL_PROVIDER_URL: `${mailer.baseUrl}/emails`,
      MAIL_PROVIDER_KEY: MAIL_KEY,
      // Slice B's off switch, declared (the inherited test.env already
      // carries it — the boot names it honestly).
      HIBP_RANGE_URL: 'off',
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

const SETTLE = 240_000 // spawned astro compiles page chunks cold on first hit
// The FIRST /app/* navigation compiles the whole app-shell island (the
// id-02 lesson); the first account-page wait carries this budget.
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
  return res.headers.get('set-cookie')!.split(';')[0]!.split('=')[1]!
}

async function signInViaCookie(page: Page, base: string, cookieValue: string): Promise<void> {
  await page.setCookie({ name: 'oiml-session', value: cookieValue, url: base })
}

/** Invite + enroll an account over the admin API (the setup is never the
 *  subject); answers the account id. */
async function enrollAccount(base: string, rootCookie: string, email: string, name: string, password: string): Promise<string> {
  const invite = await fetch(`${base}/api/op/accounts`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', cookie: `oiml-session=${rootCookie}` },
    body: JSON.stringify({ email, name }),
  })
  expect(invite.status).toBe(201)
  const { account, setupUrl } = await invite.json() as { account: { id: string }; setupUrl: string }
  const enroll = await fetch(`${base}/api/op/enroll/${new URL(setupUrl).searchParams.get('token')}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ password }),
  })
  expect(enroll.status).toBe(200)
  return account.id
}

function linkFromEmailText(text: string | undefined): string {
  const link = (text ?? '').split('\n').map(l => l.trim()).find(l => l.startsWith('http'))
  expect(link, 'the email text carries its action link').toBeTruthy()
  return link!
}

/** The captured notices with a subject; every one must carry the reset
 *  pointer to the sign-in page. */
function noticesWithSubject(mailer: StubMailer, subject: string) {
  const found = mailer.messages.filter(m => m.subject === subject)
  for (const m of found) {
    expect(m.text, `the "${subject}" notice carries the "was this you?" reset pointer`).toContain(`${ISSUER}/`)
  }
  return found
}

describe('TODO.identity-sso/04 slice D — the security notices (the identity profile)', () => {
  let stack: Stack
  let mailer: StubMailer
  let rootCookie: string

  beforeAll(async () => {
    mailer = await startStubMailer({ expectedKey: MAIL_KEY, port: MAIL_PORT })
    stack = await bootIdentityStack(mailer)

    // The root admin's password through the boot-logged setup link (the
    // id-29 bootstrap posture).
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
    mailer.reset() // the bootstrap's mails are not the arc's subject
  }, 600_000)

  afterAll(async () => {
    await mailer?.close()
    await stopStack(stack)
  })

  it('leg 1 — the console password change mails password_changed (the reset pointer rides)', { timeout: 900_000 }, async () => {
    await enrollAccount(stack.base, rootCookie, 'nina@example.org', 'Nina Notice', 'nina has a proper passphrase')
    const cookie = await passwordCookie(stack.base, 'nina@example.org', 'nina has a proper passphrase')
    mailer.reset()

    await withPage(async (page) => {
      await signInViaCookie(page, stack.base, cookie)
      flog(page, 'leg1: opening the console for the password change')
      await page.goto(`${stack.base}/op/account`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
      await page.waitForSelector('[data-testid="account-password-current"]', { timeout: APP_COLD, polling: 500 })
      await page.type('[data-testid="account-password-current"]', 'nina has a proper passphrase')
      await page.type('[data-testid="account-password-next"]', 'nina has a fresh passphrase')
      await page.type('[data-testid="account-password-confirm"]', 'nina has a fresh passphrase')
      await page.evaluate(() => (document.querySelector('[data-testid="account-password-submit"]') as HTMLElement).click())
      await page.waitForSelector('[data-testid="op-account-notice"]', { timeout: SETTLE, polling: 500 })
      flog(page, 'leg1: the change landed')
    })

    const notices = noticesWithSubject(mailer, `Your ${PRODUCT} password was set or changed`)
    expect(notices).toHaveLength(1)
    expect(notices[0]!.to).toBe('nina@example.org')
    flog(null, 'leg1: done')
  })

  it('leg 2 — the console email change mails email_changed to BOTH addresses', { timeout: 900_000 }, async () => {
    await enrollAccount(stack.base, rootCookie, 'oma@example.org', 'Oma Move', 'oma has a proper passphrase')
    const cookie = await passwordCookie(stack.base, 'oma@example.org', 'oma has a proper passphrase')

    await withPage(async (page) => {
      await signInViaCookie(page, stack.base, cookie)
      flog(page, 'leg2: opening the console for the change')
      await page.goto(`${stack.base}/op/account`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
      await page.waitForSelector('[data-testid="account-email-input"]', { timeout: APP_COLD, polling: 500 })
      await page.type('[data-testid="account-email-input"]', 'oma.next@example.org')
      await page.evaluate(() => (document.querySelector('[data-testid="account-email-submit"]') as HTMLElement).click())
      await page.waitForSelector('[data-testid="account-email-delivery"]', { timeout: SETTLE, polling: 500 })
      flog(page, 'leg2: the change is mailed')
    })

    const verificationMails = mailer.messages.filter(m => m.to === 'oma.next@example.org')
    expect(verificationMails).toHaveLength(1)
    const emailed = linkFromEmailText(verificationMails[0]!.text)
    mailer.reset() // the verification link is not this leg's subject

    await withPage(async (page) => {
      flog(page, 'leg2: opening the emailed link')
      await page.goto(emailed, { waitUntil: 'domcontentloaded', timeout: SETTLE })
      await page.waitForSelector('[data-testid="op-email-change-context"]', { timeout: SETTLE, polling: 500 })
      await page.evaluate(() => (document.querySelector('[data-testid="op-email-change-confirm"]') as HTMLElement).click())
      await page.waitForSelector('[data-testid="op-email-change-done"]', { timeout: SETTLE, polling: 500 })
      flog(page, 'leg2: the change completed')
    })

    const notices = noticesWithSubject(mailer, `Your ${PRODUCT} email address was changed`)
    expect(notices.map(m => m.to).sort(), 'the fan-out reaches the new primary; the direct send reaches the old address')
      .toEqual(['oma.next@example.org', 'oma@example.org'])
    for (const notice of notices) {
      expect(notice.text).toContain('oma@example.org')
      expect(notice.text).toContain('oma.next@example.org')
    }
    flog(null, 'leg2: done')
  })

  it('leg 3 — the console TOTP enroll + revoke mail the factor notices', { timeout: 900_000 }, async () => {
    await enrollAccount(stack.base, rootCookie, 'thea@example.org', 'Thea Totp', 'thea has a proper passphrase')
    const cookie = await passwordCookie(stack.base, 'thea@example.org', 'thea has a proper passphrase')
    mailer.reset()

    await withPage(async (page) => {
      await signInViaCookie(page, stack.base, cookie)
      flog(page, 'leg3: opening the console for the factor')
      await page.goto(`${stack.base}/op/account`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
      await page.waitForSelector('[data-testid="factors-totp-empty"]', { timeout: APP_COLD, polling: 500 })
      await page.evaluate(() => (document.querySelector('[data-testid="factor-totp-add"]') as HTMLElement).click())
      await page.waitForSelector('[data-testid="factor-totp-enroll"]', { timeout: 60_000, polling: 500 })
      const secretDashed = await page.$eval('[data-testid="factor-totp-secret"]', el => el.textContent?.trim() ?? '')
      const secret = secretDashed.replace(/[^A-Z2-7]/g, '')
      await page.type('[data-testid="factor-totp-name"]', 'Thea’s phone')
      await page.type('[data-testid="factor-totp-code"]', await totpAtStep(secret, Math.floor(Date.now() / 1000 / 30)))
      await page.evaluate(() => (document.querySelector('[data-testid="factor-totp-activate"]') as HTMLElement).click())
      // The FIRST factor lands the recovery dialog (the codes show once).
      await page.waitForSelector('[data-testid="factor-recovery-dialog"]', { timeout: 60_000, polling: 500 })
      await page.evaluate(() => (document.querySelector('[data-testid="factor-recovery-dismiss"]') as HTMLElement).click())
      await page.waitForSelector('[data-testid="factors-totp-list"]', { timeout: 60_000, polling: 500 })
      flog(page, 'leg3: enrolled')

      const added = noticesWithSubject(mailer, `A new sign-in factor was added to your ${PRODUCT} account`)
      expect(added, 'exactly one mail — the auto-generated recovery set rides it').toHaveLength(1)
      expect(added[0]!.to).toBe('thea@example.org')
      expect(added[0]!.text).toContain('Authenticator app "Thea’s phone"')

      mailer.reset()
      await page.evaluate(() => (document.querySelector('[data-testid^="factor-totp-"][data-testid$="-revoke"]') as HTMLElement).click())
      await page.waitForFunction(
        () => !document.querySelector('[data-testid^="factor-totp-"][data-testid$="-revoke"]'),
        { timeout: 60_000, polling: 500 },
      )
      flog(page, 'leg3: revoked')
    })

    const removed = noticesWithSubject(mailer, `A sign-in factor was removed from your ${PRODUCT} account`)
    expect(removed).toHaveLength(1)
    expect(removed[0]!.text).toContain('Authenticator app "Thea’s phone"')
    flog(null, 'leg3: done')
  })

  it('leg 4 — the admin client-roles grant mails client_roles_granted (the display name, the role set)', { timeout: 900_000 }, async () => {
    const id = await enrollAccount(stack.base, rootCookie, 'gus@example.org', 'Gus Grant', 'gus has a proper passphrase')
    mailer.reset()

    const grant = await fetch(`${stack.base}/api/op/accounts/${id}/client-roles/hub-instance`, {
      method: 'PUT',
      headers: { 'content-type': 'application/json', cookie: `oiml-session=${rootCookie}` },
      body: JSON.stringify({ roles: ['cs_admin'] }),
    })
    expect(grant.status).toBe(200)

    const notices = noticesWithSubject(mailer, `New access was granted on your ${PRODUCT} account`)
    expect(notices).toHaveLength(1)
    expect(notices[0]!.to).toBe('gus@example.org')
    expect(notices[0]!.text).toContain('OIML SMART platform hub')
    expect(notices[0]!.text).toContain('cs_admin')
    flog(null, 'leg4: done')
  })
})
