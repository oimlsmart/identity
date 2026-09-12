// ═══════════════════════════════════════════════════════════════════
// TODO.identity-sso/04 (the account lifecycle discipline, slice 1) —
// the email_verified claim's HONESTY + the console's unverified banner,
// the e2e (the identity-profile stack + the stub mailer + the fixture
// RP, the id-28 boot pattern): the lifecycle arc over real HTTP and the
// real UI —
//
//   leg 1  the VERIFIED baseline: the invite ceremony's completion
//          stamps the address, the console shows NO banner, and the
//          RP round trip's ID token + userinfo answer
//          email_verified TRUE;
//   leg 2  the UNVERIFIED state: the administrator's email edit resets
//          the stamp (an admin-set address never went through the
//          ceremony) — sign-in still works (verification never gates
//          entry), the console shows the banner + the unverified pill,
//          and the same round trip answers FALSE on BOTH surfaces (an
//          RP's link-by-verified-email rule can never be fooled by an
//          unproven mailbox);
//   leg 2b the RESEND way out (wave A, the kernel 0.2.4 'verify' kind):
//          the banner's own button mails the one-time link to the
//          CURRENT address — the landing page's verify copy, the mailed
//          completion stamps the SAME address (nothing moves), the
//          banner lifts and the claim answers TRUE;
//   leg 3  the CHANGE ceremony re-judges on the move: the self-service
//          email change's mailed link verifies the NEW address (the
//          token row's delivered_by decides) — the claim answers TRUE
//          on the new primary.
//
// The demo cast stays honestly unverified (fictional mailboxes): the
// surface-contract golden's re-record of its false is deliberate.
//
// SELF-CONTAINED: the suite's shared stack (E2E_BASE_URL) is untouched —
// own ports (API 10619 / astro 10620 / mailer stub 10621 / fixture RP
// 10622 — above id-28's 10615-10618), own SQLite file.
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
const DB_DIR = join(BROWSER_DIR, '.cache', 'id-29')

// Port-isolated: above id-28's 10615-10618.
const ID_API = 10619
const ID_WEB = 10620
const MAIL_PORT = 10621
const RP_PORT = 10622

const ISSUER = `http://localhost:${ID_WEB}` // the astro origin (the browser's OP)
const MAIL_KEY = 'id29-stub-mail-key'
const RP_CLIENT_ID = 'fixture-rp'
const RP_CLIENT_SECRET = 'fixture-rp-secret'

const ROOT = { email: 'root@oimlsmart.org', name: 'Root Operator', password: 'the root operator passphrase' }
const UNA = { email: 'una@example.org', name: 'Una Example', password: 'una has a proper passphrase' }
const UNA_EDITED = 'una.renamed@example.org' // the admin-set address (unverified)
const UNA_NEXT = 'una.next@example.org' // the self-service change's target (verified by its mailed link)

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
 *  stub + the client registry's fixture RP seed (the id-28 posture). */
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
      // The arc legitimately mails one story address past the kernel
      // mailer's default 5/h recipient bucket (the sign-in notices + the
      // wave-A verify link + the slice-D email_changed direct) — the
      // bucket itself is id-mail.test.ts's subject, never this arc's.
      MAIL_RATE_LIMIT_CAPACITY: '50',
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
  await new Promise(r => setTimeout(r, 50)) // the notice rides beside the answer (TODO.restructure/27)
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

/** The RP round trip through the REAL browser: the OP session exists, so
 *  the authorize lands on the consent page for the first grant (a
 *  REMEMBERED grant skips it — the driver tolerates both). */
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

describe('TODO.identity-sso/04 — the email_verified claim + the console banner (the identity profile)', () => {
  let stack: Stack
  let mailer: StubMailer
  let rp: StubRp
  let rootCookie: string
  let unaId: string

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
    rootCookie = await passwordCookie(stack.base, ROOT.email, ROOT.password)

    const invite = await fetch(`${stack.base}/api/op/accounts`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: `oiml-session=${rootCookie}` },
      body: JSON.stringify({ email: UNA.email, name: UNA.name }),
    })
    expect(invite.status).toBe(201)
    const { account, setupUrl: unaSetup } = await invite.json() as { account: { id: string }; setupUrl: string }
    unaId = account.id
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

  it('leg 1 — the verified baseline: no banner; the RP round trip answers email_verified TRUE', { timeout: 900_000 }, async () => {
    await withPage(async (page) => {
      const cookie = await passwordCookie(stack.base, UNA.email, UNA.password)
      await signInViaCookie(page, stack.base, cookie)
      flog(page, 'leg1: opening the account console')
      await page.goto(`${stack.base}/op/account`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
      await page.waitForSelector('[data-testid="account-email-verified"]', { timeout: APP_COLD, polling: 500 })
      // The enrollment verified the primary: NO banner, the verified pill.
      expect(await page.$('[data-testid="account-verification-banner"]')).toBeNull()
      flog(page, 'leg1: no banner; driving the RP round trip')

      await rpRoundTrip(page, rp)
      expect(await page.$eval('[data-testid="rp-email"]', el => el.textContent?.trim())).toBe(UNA.email)
      expect(rp.claims?.email_verified, 'the ID token carries the enrollment stamp').toBe(true)
      expect(rp.userinfo?.email_verified, 'userinfo answers the same').toBe(true)
      flog(page, 'leg1: done')
    })
  })

  it('leg 2 — the admin-set address is UNVERIFIED: sign-in works, the banner shows, the claim answers FALSE', { timeout: 900_000 }, async () => {
    // The administrator's edit (the registry console's act, over the API):
    // an admin-set address never went through the ceremony, so the
    // verification stamp resets (the kernel's updateOpAccount doctrine).
    const edit = await fetch(`${stack.base}/api/op/accounts/${unaId}`, {
      method: 'PUT',
      headers: { 'content-type': 'application/json', cookie: `oiml-session=${rootCookie}` },
      body: JSON.stringify({ email: UNA_EDITED }),
    })
    expect(edit.status, 'the admin edit lands').toBe(200)

    // Sign-in still works (verification never gates entry — the claim +
    // the factors carry the state, not the door).
    const cookie = await passwordCookie(stack.base, UNA_EDITED, UNA.password)

    await withPage(async (page) => {
      await signInViaCookie(page, stack.base, cookie)
      flog(page, 'leg2: opening the console for the banner')
      await page.goto(`${stack.base}/op/account`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
      await page.waitForSelector('[data-testid="account-verification-banner"]', { timeout: APP_COLD, polling: 500 })
      expect(await page.$eval('[data-testid="account-verification-banner"]', el => el.textContent ?? ''))
        .toContain('not verified')
      expect(await page.$('[data-testid="account-email-unverified"]')).not.toBeNull()
      expect(await page.$eval('[data-testid="account-email"]', el => el.textContent?.trim())).toBe(UNA_EDITED)
      flog(page, 'leg2: the banner stands; driving the RP round trip')

      await rpRoundTrip(page, rp)
      expect(await page.$eval('[data-testid="rp-email"]', el => el.textContent?.trim())).toBe(UNA_EDITED)
      expect(rp.claims?.email_verified, 'an unproven mailbox never reads as vouched (the ID token)').toBe(false)
      expect(rp.userinfo?.email_verified, 'userinfo answers the same').toBe(false)
      flog(page, 'leg2: done')
    })
  })

  it('leg 2b — the resend way out (wave A): the banner button mails the CURRENT address its own link; the banner lifts, the claim answers TRUE', { timeout: 900_000 }, async () => {
    const cookie = await passwordCookie(stack.base, UNA_EDITED, UNA.password)
    mailer.reset() // the sign-in notices are not this leg's subject

    await withPage(async (page) => {
      await signInViaCookie(page, stack.base, cookie)
      flog(page, 'leg2b: opening the console for the resend')
      await page.goto(`${stack.base}/op/account`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
      await page.waitForSelector('[data-testid="account-verification-resend"]', { timeout: APP_COLD, polling: 500 })

      // The banner's own act: the one-time link mails to the CURRENT
      // primary (the kernel 0.2.4 'verify' ceremony).
      await page.evaluate(() => (document.querySelector('[data-testid="account-verification-resend"]') as HTMLElement).click())
      await page.waitForSelector('[data-testid="account-verification-resend-sent"]', { timeout: SETTLE, polling: 500 })
      expect(await page.$eval('[data-testid="account-verification-resend-sent"]', el => el.textContent ?? ''))
        .toContain(UNA_EDITED)
      flog(page, 'leg2b: the verification link is mailed')
    })

    // The stub captured the verify_primary_email to the CURRENT address.
    const verifyMails = mailer.messages.filter(m => m.to === UNA_EDITED)
    expect(verifyMails).toHaveLength(1)
    expect(verifyMails[0]!.subject ?? '', 'the verify-the-primary copy — never the change copy')
      .toBe('Confirm the email address on your OIML SMART Identity account')
    const emailed = linkFromEmailText(verifyMails[0]!.text)
    expect(emailed).toContain(`${ISSUER}/op/email-change?token=`)

    await withPage(async (page) => {
      // A FRESH browser: the email's link is the whole proof.
      flog(page, 'leg2b: opening the emailed verification link')
      await page.goto(emailed, { waitUntil: 'domcontentloaded', timeout: SETTLE })
      await page.waitForSelector('[data-testid="op-email-change-context"]', { timeout: SETTLE, polling: 500 })
      expect(await page.$eval('h1', el => el.textContent ?? '')).toContain('Verify your email address')
      await page.evaluate(() => (document.querySelector('[data-testid="op-email-change-confirm"]') as HTMLElement).click())
      await page.waitForSelector('[data-testid="op-email-change-done"]', { timeout: SETTLE, polling: 500 })
      expect(await page.$eval('[data-testid="op-email-change-done"]', el => el.textContent ?? '')).toContain('Email address verified')
      flog(page, 'leg2b: verified; the console + the claims follow')
    })

    await withPage(async (page) => {
      const fresh = await passwordCookie(stack.base, UNA_EDITED, UNA.password)
      await signInViaCookie(page, stack.base, fresh)
      await page.goto(`${stack.base}/op/account`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
      await page.waitForSelector('[data-testid="account-email-verified"]', { timeout: APP_COLD, polling: 500 })
      // The banner LIFTED — the SAME address now reads verified.
      expect(await page.$('[data-testid="account-verification-banner"]')).toBeNull()
      expect(await page.$eval('[data-testid="account-email"]', el => el.textContent?.trim())).toBe(UNA_EDITED)

      await rpRoundTrip(page, rp)
      expect(await page.$eval('[data-testid="rp-email"]', el => el.textContent?.trim())).toBe(UNA_EDITED)
      expect(rp.claims?.email_verified, 'the mailed verify completion re-verified the SAME primary').toBe(true)
      expect(rp.userinfo?.email_verified, 'userinfo answers the same').toBe(true)
      flog(page, 'leg2b: done')
    })
  })

  it('leg 3 — the change ceremony re-judges on the move: the emailed email-change link verifies the NEW address; the claim answers TRUE on the new primary', { timeout: 900_000 }, async () => {
    const cookie = await passwordCookie(stack.base, UNA_EDITED, UNA.password)
    mailer.reset() // the sign-in notices are not this leg's subject

    await withPage(async (page) => {
      await signInViaCookie(page, stack.base, cookie)
      flog(page, 'leg3: opening the console for the change')
      await page.goto(`${stack.base}/op/account`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
      await page.waitForSelector('[data-testid="account-email-input"]', { timeout: APP_COLD, polling: 500 })

      // The change request through the console's own form.
      await page.type('[data-testid="account-email-input"]', UNA_NEXT)
      await page.evaluate(() => (document.querySelector('[data-testid="account-email-submit"]') as HTMLElement).click())
      await page.waitForSelector('[data-testid="account-email-delivery"]', { timeout: SETTLE, polling: 500 })
      expect(await page.$eval('[data-testid="account-email-delivery"]', el => el.textContent ?? ''))
        .toContain(`The verification link was emailed to ${UNA_NEXT}`)
      flog(page, 'leg3: the change is mailed')
    })

    // The stub captured the verify_email to the NEW address.
    const verificationMails = mailer.messages.filter(m => m.to === UNA_NEXT)
    expect(verificationMails).toHaveLength(1)
    const emailed = linkFromEmailText(verificationMails[0]!.text)
    expect(emailed).toContain(`${ISSUER}/op/email-change?token=`)

    await withPage(async (page) => {
      // A FRESH browser: the email's link is the whole proof.
      flog(page, 'leg3: opening the emailed verification link')
      await page.goto(emailed, { waitUntil: 'domcontentloaded', timeout: SETTLE })
      await page.waitForSelector('[data-testid="op-email-change-context"]', { timeout: SETTLE, polling: 500 })
      expect(await page.$eval('h1', el => el.textContent ?? '')).toContain('Change the email address')
      await page.evaluate(() => (document.querySelector('[data-testid="op-email-change-confirm"]') as HTMLElement).click())
      await page.waitForSelector('[data-testid="op-email-change-done"]', { timeout: SETTLE, polling: 500 })
      expect(await page.$eval('[data-testid="op-email-change-done"]', el => el.textContent ?? '')).toContain('Email address changed')
      // The mailed link VERIFIED the new address (delivered_by decides).
      expect(await page.$('[data-testid="op-email-change-verified"]')).not.toBeNull()
      flog(page, 'leg3: verified; the console + the claims follow')
    })

    await withPage(async (page) => {
      const fresh = await passwordCookie(stack.base, UNA_NEXT, UNA.password)
      await signInViaCookie(page, stack.base, fresh)
      await page.goto(`${stack.base}/op/account`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
      await page.waitForSelector('[data-testid="account-email-verified"]', { timeout: APP_COLD, polling: 500 })
      expect(await page.$('[data-testid="account-verification-banner"]')).toBeNull()
      expect(await page.$eval('[data-testid="account-email"]', el => el.textContent?.trim())).toBe(UNA_NEXT)

      await rpRoundTrip(page, rp)
      expect(await page.$eval('[data-testid="rp-email"]', el => el.textContent?.trim())).toBe(UNA_NEXT)
      expect(rp.claims?.email_verified, 'the mailed completion re-verified the mailbox').toBe(true)
      expect(rp.userinfo?.email_verified, 'userinfo answers the same').toBe(true)
      flog(page, 'leg3: done')
    })
  })
})
