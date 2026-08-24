// ═══════════════════════════════════════════════════════════════════
// TODO.identity-sso/02 + /03 — the strong-authentication wave's e2e
// proof: the REAL pages + routes on the spawned identity stack (the
// id-06 pattern: own API + own astro, own SQLite file, the stub mailer),
// with the passkey ceremonies driven through CHROME'S VIRTUAL
// AUTHENTICATOR (the CDP WebAuthn domain — never a mock of the
// ceremony):
//
//   leg 1  the bootstrap + the TOTP enrollment THROUGH THE PAGE (the
//          local QR renders — the secret never leaves it), the first
//          code activates, the recovery codes show ONCE;
//   leg 2  the password + TOTP sign-in through the page (the MFA step,
//          the wrong code's refusal, the right code's landing), the
//          session's amr + the ID token's amr (['pwd','otp']);
//   leg 3  the wrong-code throttle: the cap burns, the page explains,
//          the stub mailer captured the account's lockout email;
//   leg 4  the passkey: registered from the console (the virtual
//          authenticator answers), the passwordless path signs in (the
//          page's conditional-UI autofill auto-answers under the
//          harness's simulated presence — the documented behavior — and
//          the button drives when it wins the race), the passkey as the
//          second factor (amr ['pwd','webauthn']), the console's revoke,
//          the refused passwordless after;
//   leg 5  the recovery code at the page's MFA step (one-time: the reuse
//          refuses at the API);
//   leg 6  the clone-counter refusal (the API-level leg: the test
//          kit's authenticator registered through the real ceremony
//          route, then a regressed-counter assertion — fail + audit);
//   leg 7  the lost-device path: a SECOND passkey on a second virtual
//          authenticator keeps the account reachable after the first
//          authenticator is gone (never a lockout).
//
// SELF-CONTAINED: own ports (API 9893 / astro 9993 — clear of id-01's
// 8693/8393, id-02's 8793/8593, id-06's 9493/9393, id-08's 8993/8893,
// id-10's 9193/9093, the contract gate's 9693/9694, and 9793), own
// SQLite file, the stub mailer on a kernel-assigned port. THE BROWSER IS
// PER-LEG (the id-02 header note); cross-leg state rides the DATABASE.
// ═══════════════════════════════════════════════════════════════════

import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import puppeteer, { type Browser, type Page, type CDPSession } from 'puppeteer'
import { spawn, type ChildProcess } from 'node:child_process'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { mkdirSync, rmSync, appendFileSync } from 'node:fs'
import { closeBrowser, delay } from './helpers'
import { fixtureOpSigningKey } from './fixtures/op-signing-key'
import { startStubMailer, type StubMailer } from './fixtures/stub-mailer'
import { totpAtStep } from '../server/auth/op/totp'
import { base64urlEncode } from '../server/auth/op/webauthn'
import { assertWith, attest, mintAuthenticator, userHandleFor } from '../src/__tests__/factor-testkit'

const BROWSER_DIR = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const FIXTURES = join(BROWSER_DIR, 'e2e', 'fixtures')
const DB_DIR = join(BROWSER_DIR, '.cache', 'id-13')

const ID_API = 9893
const ID_WEB = 9993
const RP_CALLBACK_PORT = 9894

const ISSUER = `http://localhost:${ID_WEB}` // the astro origin (the browser's OP)
const RP_CLIENT_ID = 'factors-rp'
const RP_CLIENT_SECRET = 'factors-rp-secret'
const RP_REDIRECT_URI = `http://127.0.0.1:${RP_CALLBACK_PORT}/callback`
const MAIL_KEY = 'op-e2e-mail-key'

const ROOT = { email: 'root@oimlsmart.org', name: 'Root Operator', password: 'the root operator passphrase' }
const CASEY = { email: 'casey@factors.example.org', name: 'Casey Factors', password: 'casey has a proper passphrase' }

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

const SETTLE = 240_000 // spawned astro compiles page chunks cold on first hit
const APP_COLD = 840_000 // the first island compile on a contended host

const PROGRESS_LOG = join(DB_DIR, 'progress.log')
function flog(page: Page | null, msg: string): void {
  const url = page && !page.isClosed() ? page.url() : '(no page)'
  const line = `${new Date().toISOString()} ${msg} @ ${url}\n`
  try { appendFileSync(PROGRESS_LOG, line) } catch { /* the log never breaks the leg */ }
}

/** A fresh browser per leg (the id-02/id-06 posture). */
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

/** The virtual authenticator on the page (the CDP WebAuthn domain — the
 *  ceremony is the browser's real WebAuthn stack). Answers the CDP
 *  session + the authenticator id (the removal is the lost-device act).
 *  The command's params wrap the options object (the CDP signature). */
async function addVirtualAuthenticator(page: Page): Promise<{ cdp: CDPSession; authenticatorId: string }> {
  const cdp = await page.createCDPSession()
  await cdp.send('WebAuthn.enable', { enableUI: false })
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      ctap2Version: 'ctap2_1',
      transport: 'internal',
      hasResidentKey: true,
      hasUserVerification: true,
      automaticPresenceSimulation: true,
      isUserVerified: true,
    },
  } as never)
  return { cdp, authenticatorId }
}

/** The passwordless landing from the login page (the leg-4 harness note):
 *  the page's conditional-UI autofill may answer on its own (the
 *  simulated presence auto-approves — the documented WebAuthn-harness
 *  behavior), or the passkey button renders and drives. Both complete
 *  the same ceremony; the leg races them and clicks the button when the
 *  form wins. */
async function passkeyLanding(page: Page): Promise<void> {
  // The launcher's convention: the login page's sign-ins land on the SSO
  // home (/op/home) by default — its `home` testid is the landing marker.
  const outcome = await Promise.race([
    page.waitForSelector('[data-testid="home"]', { timeout: APP_COLD, polling: 500 }).then(() => 'landed' as const),
    page.waitForSelector('[data-testid="login-passkey"]', { timeout: SETTLE, polling: 500 }).then(() => 'form' as const),
  ])
  if (outcome === 'form') {
    await page.evaluate(() => (document.querySelector('[data-testid="login-passkey"]') as HTMLElement).click())
    await page.waitForSelector('[data-testid="home"]', { timeout: APP_COLD, polling: 500 })
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

/** The passkey-MFA completion over the API (the account holds a passkey
 *  on the test-side authenticator): password → the challenge → the
 *  assertion → the cookie. */
async function passwordCookieWithPasskey(base: string, email: string, password: string, auth: import('../src/__tests__/factor-testkit').TestAuthenticator, userId: string): Promise<string> {
  const res = await fetch(`${base}/api/op/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password }),
  })
  expect(res.ok).toBe(true)
  const body = await res.json() as { mfaRequired?: boolean; mfaToken?: string }
  if (!body.mfaRequired) {
    return res.headers.get('set-cookie')!.split(';')[0]!.split('=')[1]!
  }
  const optRes = await fetch(`${base}/api/op/login/mfa/passkey/options`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ token: body.mfaToken }),
  })
  expect(optRes.ok).toBe(true)
  const { publicKey } = await optRes.json() as { publicKey: { challenge: string } }
  const assertion = await assertWith(auth, publicKey.challenge, { rpId: new URL(base).hostname, origin: base }, { userHandle: userHandleFor(userId) })
  const done = await fetch(`${base}/api/op/login/mfa/passkey`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ token: body.mfaToken, credential: { id: base64urlEncode(auth.credentialId), response: assertion } }),
  })
  expect(done.ok, 'the passkey-MFA completion').toBe(true)
  return done.headers.get('set-cookie')!.split(';')[0]!.split('=')[1]!
}
/** The TOTP-MFA completion over the API (the account holds a TOTP): the
 *  password leg challenges; the current code completes. */
async function passwordCookieWithTotp(base: string, email: string, password: string, secret: string): Promise<string> {
  const res = await fetch(`${base}/api/op/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password }),
  })
  expect(res.ok, `password sign-in ${email} answered ${res.status}`).toBe(true)
  const body = await res.json() as { mfaRequired?: boolean; mfaToken?: string }
  if (!body.mfaRequired) {
    return res.headers.get('set-cookie')!.split(';')[0]!.split('=')[1]!
  }
  const done = await fetch(`${base}/api/op/login/mfa/totp`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ token: body.mfaToken, code: await totpAtStep(secret, Math.floor(Date.now() / 1000 / 30)) }),
  })
  expect(done.ok, 'the TOTP completion').toBe(true)
  return done.headers.get('set-cookie')!.split(';')[0]!.split('=')[1]!
}

/** The password sign-in through the PAGE (the answer may be the MFA
 *  step — the caller decides). */
async function pagePasswordSignIn(page: Page, base: string, email: string, password: string): Promise<void> {
  await page.goto(`${base}/`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
  await page.waitForSelector('[data-testid="login-email"]', { timeout: SETTLE, polling: 500 })
  await page.type('[data-testid="login-email"]', email)
  await page.type('[data-testid="login-password"]', password)
  await page.evaluate(() => (document.querySelector('[data-testid="login-submit"]') as HTMLElement).click())
}

/** The session payload (the amr provenance read). */
async function sessionAmr(base: string, cookieValue: string): Promise<string[] | undefined> {
  const res = await fetch(`${base}/api/auth/session`, { headers: { cookie: `oiml-session=${cookieValue}` } })
  expect(res.ok).toBe(true)
  return (await res.json() as { amr?: string[] }).amr
}

/** The ID token's claims for the fixture RP (the fetch-level round trip
 *  against the page-cookie session — the contract gate's pattern). */
async function idTokenAmr(base: string, cookieValue: string): Promise<unknown> {
  const cookie = `oiml-session=${cookieValue}`
  const verifier = 'factors-e2e-verifier-9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c'
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))
  let bin = ''
  for (const b of new Uint8Array(digest)) bin += String.fromCharCode(b)
  const s256 = btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
  const authorize = await fetch(`${base}/op/authorize?${new URLSearchParams({
    response_type: 'code', client_id: RP_CLIENT_ID, redirect_uri: RP_REDIRECT_URI,
    scope: 'openid profile email', state: 's', nonce: 'n', code_challenge: s256, code_challenge_method: 'S256',
  })}`, { headers: { cookie }, redirect: 'manual' })
  expect(authorize.status).toBe(302)
  const authId = new URL(authorize.headers.get('location')!, base).searchParams.get('auth')!
  const decide = await fetch(`${base}/api/op/consent/${authId}/decide`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', cookie },
    body: JSON.stringify({ decision: 'allow' }),
  })
  expect(decide.ok).toBe(true)
  const { redirect } = await decide.json() as { redirect: string }
  const code = new URL(redirect).searchParams.get('code')!
  const exchange = await fetch(`${base}/op/token`, {
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
  expect(exchange.ok).toBe(true)
  const { id_token } = await exchange.json() as { id_token: string }
  const payload = JSON.parse(atob(id_token.split('.')[1]!.replace(/-/g, '+').replace(/_/g, '/'))) as Record<string, unknown>
  return payload.amr
}

/** The account's audit actions (the activity feed, account-scoped). */
async function auditActions(base: string, cookieValue: string): Promise<string[]> {
  const res = await fetch(`${base}/api/op/account/activity`, { headers: { cookie: `oiml-session=${cookieValue}` } })
  expect(res.ok).toBe(true)
  return (await res.json() as Array<{ action: string }>).map(e => e.action)
}

let stack: Stack
let mailer: StubMailer

/** Boot the identity-profile stack (the id-06 recipe + the mailer + the
 *  fixture RP). */
async function bootIdentityStack(): Promise<Stack> {
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
      // The fixture RP for the amr-on-token legs.
      OP_CLIENT_SEED: JSON.stringify([{
        client_id: RP_CLIENT_ID,
        name: 'The factors e2e RP',
        secret: RP_CLIENT_SECRET,
        redirect_uris: [RP_REDIRECT_URI],
        claims_policy: { claims: ['roles', 'groups', 'org'] },
      }]),
      // The stub mailer: the lockout email lands here.
      EMAIL_FROM: 'OIML SMART Identity <no-reply@oimlsmart.org>',
      MAIL_PROVIDER_URL: `${mailer.baseUrl}/emails`,
      MAIL_PROVIDER_KEY: MAIL_KEY,
    }, logs)
    const apiBase = `http://localhost:${ID_API}`
    await waitForHttp(`${apiBase}/api/health`, 120_000, logs)

    const reset = await fetch(`${apiBase}/api/dev-reset`, { method: 'POST' })
    if (!reset.ok) throw new Error(`dev-reset on ${apiBase} answered ${reset.status}\n${logs.join('').slice(-2000)}`)

    // The account bootstrap seed runs on the first OP account request.
    const seedProbe = await fetch(`${apiBase}/api/op/login`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: 'nobody@example.org', password: 'a probe, not a password' }),
    })
    if (seedProbe.status !== 401) throw new Error(`the OP login probe answered ${seedProbe.status} (401 expected)\n${logs.join('').slice(-2000)}`)

    astro = spawnLogged(join(BROWSER_DIR, 'node_modules', '.bin', 'astro'), ['dev', '--port', String(ID_WEB), '--ignore-lock'], {
      API_ORIGIN: apiBase,
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

async function stopStack(s: Stack | undefined): Promise<void> {
  if (!s) return
  for (const proc of [s.astro, s.api]) killTree(proc)
  await delay(1_500)
  for (const proc of [s.astro, s.api]) killTreeHard(proc)
}

// ── the state the legs share (the database carries it) ───────────────
let caseyId = ''
let caseyTotpSecret = ''
let caseyRecovery: string[] = []
/** Leg 4's tail registers root's passkey at the API level; the
 *  test-side authenticator + root's id carry forward so later legs can
 *  complete root's passkey-MFA (the sign-in helpers need it). */
let rootApiAuth: import('../src/__tests__/factor-testkit').TestAuthenticator | null = null
let rootId = ''

describe('TODO.identity-sso/02+03 — the strong-authentication wave (the identity profile)', () => {
  beforeAll(async () => {
    mailer = await startStubMailer({ expectedKey: MAIL_KEY })
    stack = await bootIdentityStack()
  }, 600_000)

  afterAll(async () => {
    await mailer?.close()
    await stopStack(stack)
  })

  it('leg 1 — the bootstrap, the TOTP enrollment through the page (the local QR), the recovery codes shown once', { timeout: 900_000 }, async () => {
    // The seed logged the first admin's one-time link — read it from the
    // API's log stream.
    const deadline = Date.now() + 60_000
    let setupUrl = ''
    while (Date.now() < deadline) {
      const m = /bootstrap: account root@oimlsmart\.org has no password[^\n]*\n\s*(\S+\/op\/setup\?token=\S+)/.exec(stack.logs.join(''))
      if (m) { setupUrl = m[1]!; break }
      await delay(500)
    }
    expect(setupUrl, 'the bootstrap setup link in the boot log').toContain('/op/setup?token=')

    await withPage(async (page) => {
      flog(page, 'leg1: the root setup')
      await page.goto(setupUrl, { waitUntil: 'domcontentloaded', timeout: SETTLE })
      await page.waitForSelector('[data-testid="op-setup-password"]', { timeout: SETTLE, polling: 500 })
      await page.type('[data-testid="op-setup-password"]', ROOT.password)
      await page.type('[data-testid="op-setup-confirm"]', ROOT.password)
      await page.evaluate(() => (document.querySelector('[data-testid="op-setup-submit"]') as HTMLElement).click())
      await page.waitForSelector('[data-testid="account-name"]', { timeout: APP_COLD, polling: 500 })
    })

    // The admin invites Casey over the API.
    const rootCookie = await passwordCookie(stack.base, ROOT.email, ROOT.password)
    const invite = await fetch(`${stack.base}/api/op/accounts`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: `oiml-session=${rootCookie}` },
      body: JSON.stringify({ email: CASEY.email, name: CASEY.name }),
    })
    expect(invite.status).toBe(201)
    const { account, setupUrl: caseySetup } = await invite.json() as { account: { id: string }; setupUrl: string }
    caseyId = account.id

    await withPage(async (page) => {
      // Casey's enrollment (a fresh browser).
      await page.goto(caseySetup, { waitUntil: 'domcontentloaded', timeout: SETTLE })
      await page.waitForSelector('[data-testid="op-setup-password"]', { timeout: SETTLE, polling: 500 })
      await page.type('[data-testid="op-setup-password"]', CASEY.password)
      await page.type('[data-testid="op-setup-confirm"]', CASEY.password)
      await page.evaluate(() => (document.querySelector('[data-testid="op-setup-submit"]') as HTMLElement).click())
      await page.waitForSelector('[data-testid="account-name"]', { timeout: APP_COLD, polling: 500 })

      // The factors section stands, honestly empty.
      await page.waitForSelector('[data-testid="account-factors"]', { timeout: SETTLE, polling: 500 })
      await page.waitForSelector('[data-testid="factors-passkey-empty"]', { timeout: SETTLE, polling: 500 })
      await page.waitForSelector('[data-testid="factors-totp-empty"]', { timeout: SETTLE, polling: 500 })
      flog(page, 'leg1: the factors section stands empty')

      // The TOTP enrollment THROUGH THE PAGE: the QR is the local SVG
      // renderer (never an external service — the page makes no outbound
      // image request), the manual secret shows, the first code activates.
      await page.evaluate(() => (document.querySelector('[data-testid="factor-totp-add"]') as HTMLElement).click())
      await page.waitForSelector('[data-testid="factor-totp-enroll"]', { timeout: 60_000, polling: 500 })
      await page.waitForSelector('[data-testid="factor-totp-qr"] svg', { timeout: 60_000, polling: 500 })
      const secretDashed = await page.$eval('[data-testid="factor-totp-secret"]', el => el.textContent?.trim() ?? '')
      caseyTotpSecret = secretDashed.replace(/-/g, '')
      expect(caseyTotpSecret).toMatch(/^[A-Z2-7]{32}$/)
      await page.type('[data-testid="factor-totp-name"]', 'Casey’s phone')
      await page.type('[data-testid="factor-totp-code"]', await totpAtStep(caseyTotpSecret, Math.floor(Date.now() / 1000 / 30)))
      await page.evaluate(() => (document.querySelector('[data-testid="factor-totp-activate"]') as HTMLElement).click())
      // The FIRST factor lands the recovery dialog (the codes show once).
      await page.waitForSelector('[data-testid="factor-recovery-dialog"]', { timeout: 60_000, polling: 500 })
      caseyRecovery = await page.$$eval('[data-testid="factor-recovery-codes"] li', els => els.map(e => e.textContent?.trim() ?? ''))
      expect(caseyRecovery).toHaveLength(10)
      await page.evaluate(() => (document.querySelector('[data-testid="factor-recovery-dismiss"]') as HTMLElement).click())
      // The factor row lists with its name.
      await page.waitForSelector('[data-testid="factors-totp-list"]', { timeout: 60_000, polling: 500 })
      const rowName = await page.$eval('[data-testid="factors-totp-list"] li p', el => el.textContent?.trim())
      expect(rowName).toBe('Casey’s phone')
      // The activity feed carries the enrollment + the generation.
      await page.waitForSelector('[data-testid="account-activity-factor-totp_enrolled"]', { timeout: 60_000, polling: 500 })
      flog(page, 'leg1: TOTP active, recovery codes shown once')
    })
  })

  it('leg 2 — the password + TOTP sign-in through the page; the amr on the session and the ID token', { timeout: 900_000 }, async () => {
    await withPage(async (page) => {
      await pagePasswordSignIn(page, stack.base, CASEY.email, CASEY.password)
      // The MFA step renders (the page, not a session).
      await page.waitForSelector('[data-testid="login-mfa"]', { timeout: 60_000, polling: 500 })
      flog(page, 'leg2: the MFA step stands')
      // A wrong code refuses visibly.
      await page.type('[data-testid="login-mfa-code"]', '000000')
      await page.evaluate(() => (document.querySelector('[data-testid="login-mfa-submit"]') as HTMLElement).click())
      await page.waitForSelector('[data-testid="login-error"]', { timeout: 60_000, polling: 500 })
      await page.evaluate(() => {
        const el = document.querySelector('[data-testid="login-mfa-code"]') as HTMLInputElement
        el.value = ''
        el.dispatchEvent(new Event('input', { bubbles: true }))
      })
      await delay(2_400) // the ladder: the first failure owes a 2 s backoff
      // The right code lands on the console.
      await page.type('[data-testid="login-mfa-code"]', await totpAtStep(caseyTotpSecret, Math.floor(Date.now() / 1000 / 30)))
      await page.evaluate(() => (document.querySelector('[data-testid="login-mfa-submit"]') as HTMLElement).click())
      await page.waitForSelector('[data-testid="home"]', { timeout: APP_COLD, polling: 500 })
      flog(page, 'leg2: signed in with password + TOTP (the SSO home)')
    })

    // The session's amr + the ID token's amr agree (['pwd','otp']).
    // The fetch-level password sign-in challenges too (the factor is on):
    // complete it over the API for the token leg.
    const pending = await (await fetch(`${stack.base}/api/op/login`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: CASEY.email, password: CASEY.password }),
    })).json() as { mfaRequired: boolean; mfaToken: string }
    expect(pending.mfaRequired).toBe(true)
    const done = await fetch(`${stack.base}/api/op/login/mfa/totp`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ token: pending.mfaToken, code: await totpAtStep(caseyTotpSecret, Math.floor(Date.now() / 1000 / 30)) }),
    })
    expect(done.ok).toBe(true)
    const mfaCookie = done.headers.get('set-cookie')!.split(';')[0]!.split('=')[1]!
    expect(await sessionAmr(stack.base, mfaCookie)).toEqual(['pwd', 'otp'])
    expect(await idTokenAmr(stack.base, mfaCookie)).toEqual(['pwd', 'otp'])
  })

  it('leg 3 — the wrong-code throttle: the cap burns, the account is emailed', { timeout: 900_000 }, async () => {
    mailer.reset()
    await withPage(async (page) => {
      await pagePasswordSignIn(page, stack.base, CASEY.email, CASEY.password)
      await page.waitForSelector('[data-testid="login-mfa"]', { timeout: 60_000, polling: 500 })
      // Five wrong codes. The ladder's backoff is the production default
      // (2^n seconds after the nth failure) — the leg rides it honestly.
      // Each attempt awaits its OWN response (never a stale error box).
      for (let i = 0; i < 5; i++) {
        const answered = new Promise<number>((resolve) => {
          const onResponse = (res: { url(): string; status(): number }) => {
            if (res.url().endsWith('/api/op/login/mfa/totp')) {
              page.off('response', onResponse)
              resolve(res.status())
            }
          }
          page.on('response', onResponse)
        })
        await page.type('[data-testid="login-mfa-code"]', '000000')
        await page.evaluate(() => (document.querySelector('[data-testid="login-mfa-submit"]') as HTMLElement).click())
        const status = await answered
        expect(status, `attempt ${i + 1}`).toBe(i < 4 ? 401 : 429)
        await page.waitForSelector('[data-testid="login-error"]', { timeout: 60_000, polling: 500 })
        if (i < 4) {
          await page.evaluate(() => {
            const el = document.querySelector('[data-testid="login-mfa-code"]') as HTMLInputElement
            el.value = ''
            el.dispatchEvent(new Event('input', { bubbles: true }))
          })
          await delay(2 ** (i + 1) * 1000 + 400) // the ladder: 2s, 4s, 8s, 16s
        }
      }
      // The cap burned the attempt: the page is back at the password form
      // with the honest lockout line.
      await page.waitForSelector('[data-testid="login-email"]', { timeout: 60_000, polling: 500 })
      flog(page, 'leg3: the cap burned the attempt')
    })
    // The account's lockout email landed (the stub mailer).
    const deadline = Date.now() + 30_000
    let locked = null as null | { to?: string; subject?: string }
    while (Date.now() < deadline) {
      locked = mailer.messages.find(m => m.to === CASEY.email && (m.subject ?? '').includes('second factor')) ?? null
      if (locked) break
      await delay(500)
    }
    expect(locked, 'the lockout email to the account').toBeTruthy()
  })

  it('leg 4 — the passkey on the virtual authenticator: register, passwordless, second-factor, revoke', { timeout: 900_000 }, async () => {
    // ONE browser: the virtual authenticator's credential lives on the
    // page's target, so the register → sign-in legs share it.
    await withPage(async (page) => {
      await addVirtualAuthenticator(page)

      // The console registration through the REAL ceremony (the browser's
      // WebAuthn stack + the virtual authenticator — never a mock).
      const cookie = await passwordCookie(stack.base, ROOT.email, ROOT.password)
      await page.setCookie({ name: 'oiml-session', value: cookie, url: stack.base })
      await page.goto(`${stack.base}/op/account`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
      await page.waitForSelector('[data-testid="account-factors"]', { timeout: APP_COLD, polling: 500 })
      await page.evaluate(() => (document.querySelector('[data-testid="factor-passkey-add"]') as HTMLElement).click())
      await page.waitForSelector('[data-testid="factor-passkey-name"]', { timeout: 60_000, polling: 500 })
      await page.type('[data-testid="factor-passkey-name"]', 'Root’s YubiKey')
      await page.evaluate(() => (document.querySelector('[data-testid="factor-passkey-register"]') as HTMLElement).click())
      // The FIRST factor on the ROOT account lands the recovery dialog.
      await page.waitForSelector('[data-testid="factor-recovery-dialog"]', { timeout: 120_000, polling: 500 })
      await page.evaluate(() => (document.querySelector('[data-testid="factor-recovery-dismiss"]') as HTMLElement).click())
      await page.waitForSelector('[data-testid="factors-passkey-list"]', { timeout: 60_000, polling: 500 })
      const rowName = await page.$eval('[data-testid="factors-passkey-list"] li p', el => el.textContent?.trim())
      expect(rowName).toBe('Root’s YubiKey')
      flog(page, 'leg4: the passkey registered (the virtual authenticator)')

      // Sign out (the page's own channel), then the passwordless path.
      // THE HARNESS NOTE: with the virtual authenticator attached, the
      // page's conditional-UI autofill answers on its own (the simulated
      // presence auto-approves — the documented WebAuthn-harness
      // behavior), so the console may land before the button renders.
      // The leg races the two honestly: the button drives when it wins.
      await page.evaluate(() => fetch('/api/auth/signout', { method: 'POST', credentials: 'include' }))
      await page.goto(`${stack.base}/`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
      await passkeyLanding(page)
      flog(page, 'leg4: passwordless sign-in')

      // The passkey as the SECOND factor rides the page's MFA step when a
      // human picks it — in the harness the login page's conditional
      // autofill always answers first once a credential exists on the
      // attached authenticator, so the password+passkey chain's ceremony
      // proof lives at the API level (the tail below) + the unit suite;
      // the MFA step itself renders in legs 2-3 (TOTP).

      // The console's revoke: the row's button, then the passwordless
      // path refuses (the credential is gone — the server never sees a
      // registered credential again, whichever page path produces the
      // assertion). The passwordless landing is the SSO home — the
      // console is an explicit navigation.
      await page.goto(`${stack.base}/op/account`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
      await page.waitForSelector('[data-testid="factors-passkey-list"]', { timeout: 60_000, polling: 500 })
      await page.evaluate(() => (document.querySelector('[data-testid^="factor-passkey-"][data-testid$="-revoke"]') as HTMLElement).click())
      await page.waitForSelector('[data-testid="factors-passkey-empty"]', { timeout: 60_000, polling: 500 })
      await page.evaluate(() => fetch('/api/auth/signout', { method: 'POST', credentials: 'include' }))
      await page.goto(`${stack.base}/`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
      const refusedOutcome = await Promise.race([
        page.waitForSelector('[data-testid="login-error"]', { timeout: 120_000, polling: 500 }).then(() => 'refused' as const),
        page.waitForSelector('[data-testid="login-passkey"]', { timeout: SETTLE, polling: 500 }).then(() => 'form' as const),
      ])
      if (refusedOutcome === 'form') {
        await page.evaluate(() => (document.querySelector('[data-testid="login-passkey"]') as HTMLElement).click())
        await page.waitForSelector('[data-testid="login-error"]', { timeout: 120_000, polling: 500 })
      }
      const refused = await page.$eval('[data-testid="login-error"]', el => el.textContent ?? '')
      expect(refused).toContain('passkey')
      flog(page, 'leg4: revoked; the passwordless path refuses honestly')
    })

    // The amr provenance at the protocol level, on a fresh registration
    // at the API (the same ceremony route; the virtual authenticator's
    // credential died with its page): passwordless → ['webauthn','hwk'];
    // password+passkey → ['pwd','webauthn','hwk'] — the session payload
    // AND the ID token agree.
    const rootAuth = await mintAuthenticator(-7)
    const rootCookie = await passwordCookie(stack.base, ROOT.email, ROOT.password)
    const optRes = await fetch(`${stack.base}/api/op/account/factors/passkeys/options`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie: `oiml-session=${rootCookie}` },
    })
    expect(optRes.ok).toBe(true)
    const { publicKey: regOptions } = await optRes.json() as { publicKey: { challenge: string } }
    const regAnswer = await attest(rootAuth, regOptions.challenge, { rpId: `localhost`, origin: stack.base })
    const reg = await fetch(`${stack.base}/api/op/account/factors/passkeys`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: `oiml-session=${rootCookie}` },
      body: JSON.stringify({
        name: 'Root’s second YubiKey',
        credential: { id: base64urlEncode(rootAuth.credentialId), response: regAnswer },
        transports: ['usb'],
      }),
    })
    expect(reg.status).toBe(201)

    // Passwordless: amr ['webauthn','hwk'] — the DECLARED usb transport
    // rides the hwk hint (attestation none: an honest declaration).
    const rootUser = await (await fetch(`${stack.base}/api/auth/session`, { headers: { cookie: `oiml-session=${rootCookie}` } })).json() as { id: string }
    rootApiAuth = rootAuth
    rootId = rootUser.id
    const pwOpt = await fetch(`${stack.base}/api/op/login/passkey/options`, { method: 'POST' })
    const { publicKey: pwOptions } = await pwOpt.json() as { publicKey: { challenge: string } }
    const pwAssertion = await assertWith(rootAuth, pwOptions.challenge, { rpId: 'localhost', origin: stack.base }, { userHandle: userHandleFor(rootUser.id) })
    const pw = await fetch(`${stack.base}/api/op/login/passkey`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ credential: { id: base64urlEncode(rootAuth.credentialId), response: pwAssertion } }),
    })
    expect(pw.ok).toBe(true)
    const pwCookie = pw.headers.get('set-cookie')!.split(';')[0]!.split('=')[1]!
    expect(await sessionAmr(stack.base, pwCookie)).toEqual(['webauthn', 'hwk'])
    expect(await idTokenAmr(stack.base, pwCookie)).toEqual(['webauthn', 'hwk'])

    // The password+passkey chain at the API (the page's MFA button is
    // unrachable in the harness — the conditional autofill always wins
    // the login page once a credential exists on the attached
    // authenticator; the leg comment above records it): the session +
    // the ID token carry ['pwd','webauthn'].
    const mfaCookie = await passwordCookieWithPasskey(stack.base, ROOT.email, ROOT.password, rootAuth, rootId)
    expect(await sessionAmr(stack.base, mfaCookie)).toEqual(['pwd', 'webauthn', 'hwk'])
    expect(await idTokenAmr(stack.base, mfaCookie)).toEqual(['pwd', 'webauthn', 'hwk'])
  })

  it('leg 5 — the recovery code at the page’s MFA step, one-time', { timeout: 900_000 }, async () => {
    const code = caseyRecovery[0]!
    await withPage(async (page) => {
      await pagePasswordSignIn(page, stack.base, CASEY.email, CASEY.password)
      await page.waitForSelector('[data-testid="login-mfa"]', { timeout: 60_000, polling: 500 })
      await page.evaluate(() => (document.querySelector('[data-testid="login-mfa-recovery-toggle"]') as HTMLElement).click())
      await page.waitForSelector('[data-testid="login-mfa-recovery-code"]', { timeout: 30_000, polling: 500 })
      await page.type('[data-testid="login-mfa-recovery-code"]', code)
      await page.evaluate(() => (document.querySelector('[data-testid="login-mfa-recovery-submit"]') as HTMLElement).click())
      await page.waitForSelector('[data-testid="home"]', { timeout: APP_COLD, polling: 500 })
      flog(page, 'leg5: the recovery code signed Casey in (the SSO home)')
    })
    // One-time: the same code refuses now.
    const pending = await (await fetch(`${stack.base}/api/op/login`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: CASEY.email, password: CASEY.password }),
    })).json() as { mfaToken: string }
    const reuse = await fetch(`${stack.base}/api/op/login/mfa/recovery`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ token: pending.mfaToken, code }),
    })
    expect(reuse.status).toBe(401)
    flog(null, 'leg5: the reuse refused (one-time means one-time)')
  })

  it('leg 6 — the clone-counter refusal (the API-level leg, the test kit’s real bytes)', { timeout: 900_000 }, async () => {
    // Register a fresh authenticator through the ceremony route, then
    // present a REGRESSED counter: the assertion fails + audits.
    const auth = await mintAuthenticator(-7)
    const cookie = await passwordCookieWithTotp(stack.base, CASEY.email, CASEY.password, caseyTotpSecret)
    const optRes = await fetch(`${stack.base}/api/op/account/factors/passkeys/options`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie: `oiml-session=${cookie}` },
    })
    const { publicKey: regOptions } = await optRes.json() as { publicKey: { challenge: string } }
    const regAnswer = await attest(auth, regOptions.challenge, { rpId: 'localhost', origin: stack.base })
    const reg = await fetch(`${stack.base}/api/op/account/factors/passkeys`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: `oiml-session=${cookie}` },
      body: JSON.stringify({
        name: 'Casey’s Pixel',
        credential: { id: base64urlEncode(auth.credentialId), response: regAnswer },
        transports: ['internal'],
      }),
    })
    expect(reg.status).toBe(201)

    // Two honest assertions advance the counter (1, 2)…
    for (let i = 0; i < 2; i++) {
      const o = await fetch(`${stack.base}/api/op/login/passkey/options`, { method: 'POST' })
      const { publicKey: o2 } = await o.json() as { publicKey: { challenge: string } }
      const a = await assertWith(auth, o2.challenge, { rpId: 'localhost', origin: stack.base }, { userHandle: userHandleFor(caseyId) })
      const r = await fetch(`${stack.base}/api/op/login/passkey`, {
        method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ credential: { id: base64urlEncode(auth.credentialId), response: a } }),
      })
      expect(r.ok, `assertion ${i + 1} advances`).toBe(true)
    }
    // …then the clone presents the credential with a REGRESSED counter.
    const o = await fetch(`${stack.base}/api/op/login/passkey/options`, { method: 'POST' })
    const { publicKey: o2 } = await o.json() as { publicKey: { challenge: string } }
    const cloneAnswer = await assertWith(auth, o2.challenge, { rpId: 'localhost', origin: stack.base }, { userHandle: userHandleFor(caseyId), counter: 1 })
    const refused = await fetch(`${stack.base}/api/op/login/passkey`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ credential: { id: base64urlEncode(auth.credentialId), response: cloneAnswer } }),
    })
    expect(refused.status).toBe(401)
    expect(((await refused.json()) as { error: string }).error).toContain('counter regressed')
    expect(await auditActions(stack.base, cookie)).toContain('factor.clone_refused')
    flog(null, 'leg6: the clone refused + audited')
  })

  it('leg 7 — the lost device: the second passkey keeps the account reachable', { timeout: 900_000 }, async () => {
    // Root still holds leg 4's API-registered passkey — clear it first
    // (the leg-4 browser's credential died with its page; the row is
    // server-side). Root's sign-in for that act completes the passkey
    // MFA with leg 4's test-side authenticator.
    {
      const cookie = await passwordCookieWithPasskey(stack.base, ROOT.email, ROOT.password, rootApiAuth!, rootId)
      const list = await (await fetch(`${stack.base}/api/op/account/factors`, { headers: { cookie: `oiml-session=${cookie}` } })).json() as { passkeys: Array<{ credentialId: string }> }
      for (const pk of list.passkeys) {
        const res = await fetch(`${stack.base}/api/op/account/factors/passkeys/${encodeURIComponent(pk.credentialId)}`, {
          method: 'DELETE', headers: { cookie: `oiml-session=${cookie}` },
        })
        expect(res.ok).toBe(true)
      }
    }

    await withPage(async (page) => {
      // Two devices: the first virtual authenticator is the one that gets
      // "lost"; the second stays.
      const first = await addVirtualAuthenticator(page)
      const cookie = await passwordCookie(stack.base, ROOT.email, ROOT.password)
      await page.setCookie({ name: 'oiml-session', value: cookie, url: stack.base })
      await page.goto(`${stack.base}/op/account`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
      await page.waitForSelector('[data-testid="account-factors"]', { timeout: APP_COLD, polling: 500 })

      const registerNamed = async (name: string) => {
        await page.evaluate(() => (document.querySelector('[data-testid="factor-passkey-add"]') as HTMLElement).click())
        await page.waitForSelector('[data-testid="factor-passkey-name"]', { timeout: 60_000, polling: 500 })
        await page.type('[data-testid="factor-passkey-name"]', name)
        await page.evaluate(() => (document.querySelector('[data-testid="factor-passkey-register"]') as HTMLElement).click())
        await page.waitForFunction(
          () => !document.querySelector('[data-testid="factor-passkey-form"]'),
          { timeout: 120_000, polling: 500 },
        )
      }
      await registerNamed('Root’s daily YubiKey')
      // The second device: replace the authenticator (the first stays
      // registered; adding a second instance lets both exist).
      await first.cdp.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId: first.authenticatorId })
      await addVirtualAuthenticator(page)
      await registerNamed('Root’s spare YubiKey')
      const rows = await page.$$('[data-testid="factors-passkey-list"] > li')
      expect(rows.length).toBe(2)
      flog(page, 'leg7: two passkeys on two devices')

      // The "loss": the first authenticator is already gone (removed
      // above). The SPARE still signs in passwordless — never a lockout.
      await page.evaluate(() => fetch('/api/auth/signout', { method: 'POST', credentials: 'include' }))
      await page.goto(`${stack.base}/`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
      await passkeyLanding(page)
      flog(page, 'leg7: the spare signs in — the account survived the loss')
    })
  })

  it('leg 8 — the admin’s per-user page: the factors slot lists + revokes (the registry’s acts audit)', { timeout: 900_000 }, async () => {
    // Casey at this point holds: the TOTP app (leg 1), the recovery codes
    // (leg 1), and the passkey from the clone leg (leg 6). The admin view
    // rides the demo admin's session (the cast is enabled; the registry
    // gate is the role).
    const adminCookie = await (async () => {
      const res = await fetch(`${stack.base}/api/auth/demo`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ email: 'admin@oiml.org', password: 'demo2026' }),
      })
      expect(res.ok).toBe(true)
      return res.headers.get('set-cookie')!.split(';')[0]!.split('=')[1]!
    })()

    await withPage(async (page) => {
      await page.setCookie({ name: 'oiml-session', value: adminCookie, url: stack.base })
      await page.goto(`${stack.base}/op/admin/registry/users/${encodeURIComponent(caseyId)}`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
      await page.waitForSelector('[data-testid="op-reg-factors"]', { timeout: APP_COLD, polling: 500 })
      await page.waitForSelector('[data-testid="op-reg-factors-list"]', { timeout: 60_000, polling: 500 })
      // The slot lists the TOTP app + the passkey + the recovery state.
      await page.waitForSelector('[data-testid^="op-reg-factor-totp-"]', { timeout: 60_000, polling: 500 })
      await page.waitForSelector('[data-testid^="op-reg-factor-passkey-"]', { timeout: 60_000, polling: 500 })
      await page.waitForSelector('[data-testid="op-reg-factors-recovery"]', { timeout: 60_000, polling: 500 })
      flog(page, 'leg8: the slot lists Casey’s factors')

      // The admin revokes the authenticator app; the account's chain
      // carries the event (the account's own feed shows it).
      await page.evaluate(() => (document.querySelector('[data-testid^="op-reg-factor-totp-"][data-testid$="-revoke"]') as HTMLElement).click())
      await page.waitForFunction(
        () => !document.querySelector('[data-testid^="op-reg-factor-totp-"][data-testid$="-revoke"]'),
        { timeout: 60_000, polling: 500 },
      )
      flog(page, 'leg8: the admin revoked the TOTP app')
    })

    // The account's audit chain carries the revocation (by the
    // administrator) — read through the registry's per-account activity
    // (Casey's own TOTP is gone by now, so the admin's read stands in).
    const activity = await fetch(`${stack.base}/api/op/registry/users/${encodeURIComponent(caseyId)}/activity`, {
      headers: { cookie: `oiml-session=${adminCookie}` },
    })
    expect(activity.ok).toBe(true)
    const actions = ((await activity.json()) as { events: Array<{ action: string }> }).events.map(e => e.action)
    expect(actions).toContain('factor.totp_revoked')
    flog(null, 'leg8: the revocation audited on the account’s chain')
  })
})
