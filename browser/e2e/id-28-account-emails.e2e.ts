// ═══════════════════════════════════════════════════════════════════
// TODO.identity-features/01 — multiple emails per account, the e2e
// (the identity-profile stack + the stub mailer, the id-09 boot
// pattern): the full arc over real HTTP and the real UI —
//
//   leg 1  the ADD through the console's EMAILS section: the address
//          lands UNVERIFIED (the row's honest pill), the delivery card
//          says mailed, the stub captured the verify_added_email to the
//          NEW address — and a sign-in with the unverified address
//          REFUSES honestly;
//   leg 2  the VERIFY from the captured email's own link (the
//          kind-aware confirm page: "Confirm the email address", never
//          "change") → the sign-in WITH THE SECONDARY through the login
//          form lands (the identity is the PRIMARY — the claims'
//          source), and the new-sign-in notification fans out to BOTH
//          proven addresses;
//   leg 3  the PRIMARY SWITCH through the console → the RP round trip:
//          the relying party's ID token carries the NEW primary in the
//          same-shaped `email` claim (the RPs never notice);
//   leg 4  the REMOVAL rules: the primary row offers NO remove (and
//          the API refuses it honestly), the old primary (now an
//          additional) removes through the console, and sign-in by it
//          dies.
//
// SELF-CONTAINED: the suite's shared stack (E2E_BASE_URL) is untouched —
// own ports (API 10615 / astro 10616 / mailer stub 10617 / fixture RP
// 10618 — above id-27's 10612-10614), own SQLite file.
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
import { startStubRp, type StubRp } from './fixtures/stub-rp'

const BROWSER_DIR = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const FIXTURES = join(BROWSER_DIR, 'e2e', 'fixtures')
const DB_DIR = join(BROWSER_DIR, '.cache', 'id-28')

// Port-isolated: above id-27's 10612-10614.
const ID_API = 10615
const ID_WEB = 10616
const MAIL_PORT = 10617
const RP_PORT = 10618

const ISSUER = `http://localhost:${ID_WEB}` // the astro origin (the browser's OP)
const MAIL_KEY = 'id28-stub-mail-key'
const RP_CLIENT_ID = 'fixture-rp'
const RP_CLIENT_SECRET = 'fixture-rp-secret'

const ROOT = { email: 'root@oimlsmart.org', name: 'Root Operator', password: 'the root operator passphrase' }
const UNA = { email: 'una@example.org', name: 'Una Example', password: 'una has a proper passphrase' }
const SECONDARY = 'una.secondary@example.org'

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

/** Boot the identity-profile stack with the mail provider bound to the
 *  stub (the id-09 posture) + the client registry's fixture RP seed (the
 *  id-27 posture): the API on its own SQLite file with the OP env, the
 *  account bootstrap (the root admin by declaration — its setup link
 *  lands in the boot log), the profile seed through the dev-reset seam,
 *  astro dev against it. */
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

    // The tsx CLI directly (never npx — the wrapper orphans the server).
    // OIDC_* scrubbed + the demo override ON: a CI e2e job declares the
    // SUITE stack's SSO posture in the shared env — the identity stack
    // must not inherit it.
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
      // The first administrator arrives by DECLARATION (invite-only means
      // nobody else can mint the first link) — the setup link lands in
      // the boot log.
      OP_ACCOUNT_SEED: JSON.stringify([{ email: ROOT.email, name: ROOT.name, role: 'admin' }]),
      OP_CLIENT_SEED: JSON.stringify([{
        client_id: RP_CLIENT_ID,
        name: 'The e2e fixture RP',
        secret: RP_CLIENT_SECRET,
        redirect_uris: [`http://127.0.0.1:${RP_PORT}/callback`],
        claims_policy: { claims: ['roles', 'groups', 'org'] },
      }]),
      // TODO.identity/09's seam — the stub HTTPS provider (the
      // Resend-shaped capture) with its expected key.
      EMAIL_FROM: 'OIML SMART Identity <no-reply@oimlsmart.org>',
      MAIL_PROVIDER_URL: `${mailer.baseUrl}/emails`,
      MAIL_PROVIDER_KEY: MAIL_KEY,
    }, logs)
    const apiBase = `http://localhost:${ID_API}`
    await waitForHttp(`${apiBase}/api/health`, 120_000, logs)

    // Provision the profile's seed (the demo cast + the instance admin).
    const reset = await fetch(`${apiBase}/api/dev-reset`, { method: 'POST' })
    if (!reset.ok) throw new Error(`dev-reset on ${apiBase} answered ${reset.status}\n${logs.join('').slice(-2000)}`)

    // The account bootstrap seed runs on the first OP account request.
    const seedProbe = await fetch(`${apiBase}/api/op/login`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: 'nobody@example.org', password: 'a probe, not a password' }),
    })
    if (seedProbe.status !== 401) throw new Error(`the OP login probe answered ${seedProbe.status} (401 expected)\n${logs.join('').slice(-2000)}`)

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
// The FIRST /app/* navigation of a run compiles the whole app-shell
// island; on a contended host that cold compile outlives SETTLE (the
// id-02 lesson). The first account-page wait carries this budget.
const APP_COLD = 840_000

/** Progress outside vitest's per-test console capture (a stalled browser
 *  makes the suite silent until the file ends — this log is live). */
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
    page.on('requestfailed', r => flog(page, `[requestfailed] ${r.url().slice(0, 140)} ${r.failure()?.errorText ?? ''}`))
    await fn(page)
  } finally {
    await closeBrowser(browser)
  }
}

/** The OP's password sign-in over fetch: the session cookie value. */
async function passwordCookie(base: string, email: string, password: string): Promise<string> {
  const res = await fetch(`${base}/api/op/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password }),
  })
  expect(res.ok, `password sign-in ${email}`).toBe(true)
  return res.headers.get('set-cookie')!.split(';')[0]!.split('=')[1]!
}

/** Install a session cookie on the page (the fetch-level sign-in's
 *  continuity — the console then loads signed in). */
async function signInViaCookie(page: Page, base: string, cookieValue: string): Promise<void> {
  await page.setCookie({ name: 'oiml-session', value: cookieValue, url: base })
}

/** The one link line of a captured email's text body. */
function linkFromEmailText(text: string | undefined): string {
  const link = (text ?? '').split('\n').map(l => l.trim()).find(l => l.startsWith('http'))
  expect(link, 'the email text carries its action link').toBeTruthy()
  return link!
}

/** Sign in at the OP through the login FORM (the real surface). Answers
 *  after the submit lands. */
async function opFormSignIn(page: Page, email: string, password: string): Promise<void> {
  await page.waitForSelector('[data-testid="login-email"]', { timeout: SETTLE, polling: 500 })
  await page.evaluate(() => {
    (document.querySelector('[data-testid="login-email"]') as HTMLInputElement).value = ''
  })
  await page.type('[data-testid="login-email"]', email)
  await page.type('[data-testid="login-password"]', password)
  await page.evaluate(() => (document.querySelector('[data-testid="login-submit"]') as HTMLElement).click())
}

describe('TODO.identity-features/01 — multiple emails per account (the identity profile)', () => {
  let stack: Stack
  let mailer: StubMailer
  let rp: StubRp

  beforeAll(async () => {
    mailer = await startStubMailer({ expectedKey: MAIL_KEY, port: MAIL_PORT })
    stack = await bootIdentityStack(mailer)
    rp = await startStubRp({
      port: RP_PORT,
      issuer: ISSUER,
      clientId: RP_CLIENT_ID,
      clientSecret: RP_CLIENT_SECRET,
    })

    // ── the setup (over real HTTP, never the subject): the root admin's
    //    password through the boot-logged setup link, then Una's invite
    //    + enrollment through the admin API. ──
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

    const rootCookieValue = await passwordCookie(stack.base, ROOT.email, ROOT.password)
    const invite = await fetch(`${stack.base}/api/op/accounts`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: `oiml-session=${rootCookieValue}` },
      body: JSON.stringify({ email: UNA.email, name: UNA.name }),
    })
    expect(invite.status).toBe(201)
    const { setupUrl: unaSetup } = await invite.json() as { setupUrl: string }
    const unaEnroll = await fetch(`${stack.apiBase}/api/op/enroll/${new URL(unaSetup).searchParams.get('token')}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ password: UNA.password }),
    })
    expect(unaEnroll.status).toBe(200)
    mailer.reset() // the invite + the sign-in notices are not the arc's subject
  }, 600_000)

  afterAll(async () => {
    await rp?.close()
    await mailer?.close()
    await stopStack(stack)
  })

  it('leg 1 — the add lands the address UNVERIFIED (the honest pill + the mailed card); the unverified address never signs in', { timeout: 900_000 }, async () => {
    await withPage(async (page) => {
      const cookie = await passwordCookie(stack.base, UNA.email, UNA.password)
      await signInViaCookie(page, stack.base, cookie)
      flog(page, 'leg1: opening the account console')
      await page.goto(`${stack.base}/op/account`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
      await page.waitForSelector('[data-testid="account-emails"]', { timeout: APP_COLD, polling: 500 })

      // The EMAILS section lists the primary, verified (the enrollment's
      // stamp), with the primary pill.
      await page.waitForSelector(`[data-testid="email-primary-${UNA.email}"]`, { timeout: SETTLE, polling: 500 })
      expect(await page.$(`[data-testid="email-verified-${UNA.email}"]`)).not.toBeNull()

      // The ADD through the form.
      await page.type('[data-testid="emails-add-input"]', SECONDARY)
      await page.evaluate(() => (document.querySelector('[data-testid="emails-add-submit"]') as HTMLElement).click())
      flog(page, 'leg1: added; waiting for the delivery card')
      await page.waitForSelector('[data-testid="emails-add-delivery"]', { timeout: SETTLE, polling: 500 })
      expect(await page.$eval('[data-testid="emails-add-delivery"]', el => el.textContent ?? ''))
        .toContain(`The verification link was emailed to ${SECONDARY}`)

      // The row stands UNVERIFIED (never sign-in-usable yet).
      await page.waitForSelector(`[data-testid="email-unverified-${SECONDARY}"]`, { timeout: SETTLE, polling: 500 })

      // The stub captured the verification mail: to the NEW address, the
      // add's own subject (never the "account is moving" copy).
      const verificationMails = mailer.messages.filter(m => m.to === SECONDARY)
      expect(verificationMails).toHaveLength(1)
      expect(verificationMails[0]!.subject).toBe('Confirm the address added to your OIML SMART Identity account')
      expect(linkFromEmailText(verificationMails[0]!.text)).toContain(`${ISSUER}/op/email-change?token=`)
      flog(page, 'leg1: done')
    })

    // The unverified address REFUSES the sign-in (the same route the
    // form posts; the console posture keeps this assertion off the
    // browser's flakiness surface).
    const refused = await fetch(`${stack.base}/api/op/login`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: SECONDARY, password: UNA.password }),
    })
    expect(refused.status).toBe(401)
  })

  it('leg 2 — the verify from the captured email\'s link, then the sign-in WITH THE SECONDARY through the form', { timeout: 900_000 }, async () => {
    const verificationMail = mailer.messages.find(m => m.to === SECONDARY)
    const emailed = linkFromEmailText(verificationMail?.text)
    expect(emailed).toContain(`${ISSUER}/op/email-change?token=`)
    // The fan-out assertion below counts THIS leg's sign-in notices —
    // the earlier legs' (the fetch-level console sign-ins, the verify
    // mail itself) are not its subject.
    mailer.reset()

    await withPage(async (page) => {
      // A FRESH browser: the email's link is the whole proof.
      flog(page, 'leg2: opening the emailed verification link')
      await page.goto(emailed, { waitUntil: 'domcontentloaded', timeout: SETTLE })
      await page.waitForSelector('[data-testid="op-email-change-context"]', { timeout: SETTLE, polling: 500 })
      // The kind-aware page: the ADD's confirm, never the change's move.
      expect(await page.$eval('h1', el => el.textContent ?? '')).toContain('Confirm the email address')
      expect(await page.$eval('[data-testid="op-email-change-context"]', el => el.textContent ?? '')).toContain(SECONDARY)
      await page.evaluate(() => (document.querySelector('[data-testid="op-email-change-confirm"]') as HTMLElement).click())
      await page.waitForSelector('[data-testid="op-email-change-done"]', { timeout: SETTLE, polling: 500 })
      expect(await page.$eval('[data-testid="op-email-change-done"]', el => el.textContent ?? '')).toContain('Email address verified')
      flog(page, 'leg2: verified; signing in WITH THE SECONDARY through the form')

      // The sign-in WITH THE SECONDARY: the form lands on the account
      // page whose identity is the PRIMARY (the claims' source).
      await page.goto(`${stack.base}/`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
      await opFormSignIn(page, SECONDARY, UNA.password)
      await page.waitForSelector('[data-testid="account-name"]', { timeout: APP_COLD, polling: 500 })
      expect(new URL(page.url()).pathname).toBe('/op/account')
      expect(await page.$eval('[data-testid="account-email"]', el => el.textContent?.trim())).toBe(UNA.email)

      // The console's EMAILS section shows the secondary VERIFIED now.
      await page.waitForSelector(`[data-testid="email-verified-${SECONDARY}"]`, { timeout: SETTLE, polling: 500 })
      flog(page, 'leg2: done')
    })

    // The new-sign-in notification fanned out to BOTH proven addresses
    // (the security posture: the "was this you?" reaches every mailbox).
    const signinMails = mailer.messages.filter(m => m.subject === 'New sign-in to your OIML SMART Identity account')
    expect(signinMails.map(m => m.to).sort()).toEqual([SECONDARY, UNA.email].sort())
  })

  it('leg 3 — the primary switch through the console; the RP\'s ID token carries the NEW primary', { timeout: 900_000 }, async () => {
    await withPage(async (page) => {
      const cookie = await passwordCookie(stack.base, SECONDARY, UNA.password) // the secondary signs in over fetch too
      await signInViaCookie(page, stack.base, cookie)
      flog(page, 'leg3: opening the console for the switch')
      await page.goto(`${stack.base}/op/account`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
      await page.waitForSelector(`[data-testid="email-make-primary-${SECONDARY}"]`, { timeout: APP_COLD, polling: 500 })
      // The selector rides an evaluate ARGUMENT (a ${} inside the
      // closure would evaluate page-side, where the constant is
      // undefined — the leg-3 lesson).
      await page.evaluate((sel) => (document.querySelector(sel) as HTMLElement).click(), `[data-testid="email-make-primary-${SECONDARY}"]`)
      flog(page, 'leg3: switched; waiting for the primary pill to move')
      await page.waitForSelector(`[data-testid="email-primary-${SECONDARY}"]`, { timeout: SETTLE, polling: 500 })
      // The PROFILE's identity line carries the new primary (the claims'
      // source); the old primary stands as a verified additional.
      await page.waitForFunction(
        (expected: string) => document.querySelector('[data-testid="account-email"]')?.textContent?.trim() === expected,
        { timeout: SETTLE, polling: 500 },
        SECONDARY,
      )
      expect(await page.$(`[data-testid="email-verified-${UNA.email}"]`)).not.toBeNull()
      flog(page, 'leg3: the console carries the switch; driving the RP round trip')

      // The RP round trip: the relying party's ID token carries the NEW
      // primary in the same-shaped `email` claim (the RPs never notice).
      await page.goto(`${rp.baseUrl}/signin`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
      // The OP session exists, so the authorize bounces to the consent
      // page (the fixture RP's first grant) — Allow through it.
      await page.waitForSelector('[data-testid="op-consent-allow"]', { timeout: SETTLE, polling: 500 })
      await page.evaluate(() => (document.querySelector('[data-testid="op-consent-allow"]') as HTMLElement).click())
      await page.waitForSelector('[data-testid="rp-signed-in"]', { timeout: SETTLE, polling: 500 })
      expect(await page.$eval('[data-testid="rp-email"]', el => el.textContent?.trim())).toBe(SECONDARY)
      flog(page, 'leg3: done — the claims carry the new primary')
    })
  })

  it('leg 4 — the removal rules: the primary refuses honestly, the old primary removes, sign-in by it dies', { timeout: 900_000 }, async () => {
    // The API's refusal is honest (the console never offers the act —
    // asserted below; the route's 409 is the backstop).
    const cookie = await passwordCookie(stack.base, SECONDARY, UNA.password)
    const refuse = await fetch(`${stack.base}/api/op/account/emails/${encodeURIComponent(SECONDARY)}`, {
      method: 'DELETE',
      headers: { cookie: `oiml-session=${cookie}` },
    })
    expect(refuse.status).toBe(409)
    expect(((await refuse.json()) as { error: string }).error).toContain('primary')

    await withPage(async (page) => {
      await signInViaCookie(page, stack.base, cookie)
      flog(page, 'leg4: opening the console')
      await page.goto(`${stack.base}/op/account`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
      await page.waitForSelector(`[data-testid="email-primary-${SECONDARY}"]`, { timeout: APP_COLD, polling: 500 })

      // The primary row offers NO remove button.
      expect(await page.$(`[data-testid="email-remove-${SECONDARY}"]`)).toBeNull()
      // The old primary (now a verified additional) offers one — take it.
      await page.waitForSelector(`[data-testid="email-remove-${UNA.email}"]`, { timeout: SETTLE, polling: 500 })
      await page.evaluate((sel) => (document.querySelector(sel) as HTMLElement).click(), `[data-testid="email-remove-${UNA.email}"]`)
      flog(page, 'leg4: removed; waiting for the row to vanish')
      await page.waitForFunction(
        (email: string) => !document.querySelector(`[data-testid="email-row-${email}"]`),
        { timeout: SETTLE, polling: 500 },
        UNA.email,
      )
      expect(await page.$eval('[data-testid="emails-notice"]', el => el.textContent ?? '')).toContain(`${UNA.email} was removed`)
      flog(page, 'leg4: done')
    })

    // Sign-in by the removed address dies; the primary stands.
    const dead = await fetch(`${stack.base}/api/op/login`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: UNA.email, password: UNA.password }),
    })
    expect(dead.status).toBe(401)
    const alive = await fetch(`${stack.base}/api/op/login`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: SECONDARY, password: UNA.password }),
    })
    expect(alive.status).toBe(200)
  })
})
