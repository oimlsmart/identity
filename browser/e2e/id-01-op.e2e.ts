// ═══════════════════════════════════════════════════════════════════
// TODO.identity/01 — the OIDC Provider e2e: the identity-profile stack
// (its own API + its own astro, the fed-01 spawned-stack pattern) serves
// the OP contract, and a fixture Relying Party (e2e/fixtures/stub-rp.ts)
// drives the FULL round trip against it — authorize → the OP's sign-in
// surface → the consent page → the code → the token exchange → the ID
// token validated by the RP's REAL validator (@oimlsmart/platform-server/oidc) over
// the OP's own JWKS → userinfo. Real HTTP on every hop, no stubs on the
// OP side.
//
//   leg 1  the discovery document matches the served endpoints + JWKS;
//   leg 2  the full browser round trip: RP /signin → the OP's login
//          page (the instance's own sign-in surface) → the consent page
//          (client, scopes, account) → Allow → the RP's callback → the
//          validated claims (the RP's real validator) + userinfo;
//   leg 3  Deny → the RP receives error=access_denied (no code);
//   leg 4  an unregistered redirect_uri is refused in place (never a
//          redirect — the open-redirect wall);
//   leg 5  a replayed code is refused (invalid_grant), and a PKCE
//          failure spends the code.
//
// SELF-CONTAINED: the suite's shared stack (E2E_BASE_URL) is untouched —
// the identity instance boots on its own ports (API 8693 / astro 8393,
// the fixture RP on 8694) with its own SQLite file.
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
const DB_DIR = join(BROWSER_DIR, '.cache', 'id-01')

// Port-isolated: clear of the shared dev stack (5190/3190), the fed-01
// stacks (8291/8292/8491/8492), the fed-10 stub (8699) and the local
// identity dev stack (7390/7190).
const ID_API = 8693
const ID_WEB = 8393
const RP_PORT = 8694

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
 *  the OP env (issuer + the client-registry bootstrap seed), the profile
 *  seed through the dev-reset seam, astro dev against it. */
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
    // must not inherit it (an SSO-configured OP instance would turn the
    // demo sign-in surface off under the fed-10 default rule).
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
      // The registry's bootstrap seed: the fixture RP (a confidential
      // client carrying the role-claim policy).
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

/** Sign in at the OP through the form (the identity instance's demo
 *  cast — real password accounts are TODO.identity/02's). */
async function opSignIn(page: Page, base: string, email: string): Promise<void> {
  await page.waitForSelector('[data-testid="login-email"]', { timeout: SETTLE, polling: 500 })
  await page.evaluate(() => {
    (document.querySelector('[data-testid="login-email"]') as HTMLInputElement).value = ''
  })
  await page.type('[data-testid="login-email"]', email)
  await page.type('[data-testid="login-password"]', 'demo2026')
  await page.evaluate(() => (document.querySelector('[data-testid="login-submit"]') as HTMLElement).click())
}

describe('TODO.identity/01 — the OIDC Provider (the identity profile)', () => {
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

  it('leg 1 — the discovery document matches the served endpoints, and the JWKS carries the ES256 key', { timeout: 600_000 }, async () => {
    const meta = await (await fetch(`${stack.base}/.well-known/openid-configuration`)).json() as Record<string, string>
    expect(meta.issuer).toBe(ISSUER)
    expect(meta.authorization_endpoint).toBe(`${ISSUER}/op/authorize`)
    expect(meta.token_endpoint).toBe(`${ISSUER}/op/token`)
    expect(meta.userinfo_endpoint).toBe(`${ISSUER}/op/userinfo`)
    expect(meta.jwks_uri).toBe(`${ISSUER}/jwks.json`)

    // The declared endpoints are really served (not just named):
    const jwks = await (await fetch(meta.jwks_uri)).json() as { keys: Array<Record<string, unknown>> }
    expect(jwks.keys.length).toBeGreaterThanOrEqual(1)
    expect(jwks.keys[0]).toMatchObject({ kty: 'EC', crv: 'P-256', alg: 'ES256', use: 'sig' })
    const tokenProbe = await fetch(meta.token_endpoint, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: 'grant_type=none' })
    expect(tokenProbe.status).toBe(400) // served, refusing honestly
    const userinfoProbe = await fetch(meta.userinfo_endpoint)
    expect(userinfoProbe.status).toBe(401) // served, demanding the Bearer token
    // …and the hub-profile shared stack (E2E_BASE_URL's default) would
    // 404 these paths — the profile gate is the module's.
  })

  it('leg 2 — the full round trip: sign-in at the OP, consent, the code, the RP-validated token, userinfo', { timeout: 900_000 }, async () => {
    // The RP starts the flow: the browser follows its 302 to the OP.
    await page.goto(`${rp.baseUrl}/signin`, { waitUntil: 'domcontentloaded', timeout: SETTLE })

    // The OP's sign-in surface: the authorize endpoint bounced the
    // anonymous browser to the instance's own login page.
    await page.waitForFunction(
      () => window.location.pathname === '/',
      { timeout: SETTLE, polling: 500 },
    )
    await opSignIn(page, stack.base, 'ia@oiml.org')

    // The consent page: the client's name, the scopes, the account.
    await page.waitForSelector('[data-testid="op-consent-allow"]', { timeout: SETTLE, polling: 500 })
    expect(new URL(page.url()).pathname).toBe('/op/consent')
    const clientName = await page.$eval('[data-testid="op-consent-client"]', el => el.textContent?.trim())
    expect(clientName).toBe('The e2e fixture RP')
    const account = await page.$eval('[data-testid="op-consent-account"]', el => el.textContent ?? '')
    expect(account).toContain('IA Officer')
    expect(account).toContain('ia@oiml.org')
    const scopes = await page.$eval('[data-testid="op-consent-scopes"]', el => el.textContent ?? '')
    expect(scopes).toContain('Your name')
    expect(scopes).toContain('Your email address')
    expect(scopes).toContain('Your platform roles')

    // Allow → the RP's callback → the RP's signed-in page.
    await page.evaluate(() => (document.querySelector('[data-testid="op-consent-allow"]') as HTMLElement).click())
    await page.waitForSelector('[data-testid="rp-signed-in"]', { timeout: SETTLE, polling: 500 })
    expect(new URL(page.url()).origin).toBe(rp.baseUrl)

    // The RP's REAL validator accepted the OP's ID token (signature
    // against the OP's JWKS, iss/aud/exp/nonce) — the whoami surface.
    const who = await (await fetch(`${rp.baseUrl}/whoami`)).json() as {
      claims: { iss: string; aud: string; sub: string; email: string; name: string; roles?: string[]; groups?: string[]; org?: string; nonce: string }
      userinfo: Record<string, unknown>
      lastError: unknown
    }
    expect(who.claims.iss).toBe(ISSUER)
    expect(who.claims.aud).toBe(RP_CLIENT_ID)
    expect(who.claims.email).toBe('ia@oiml.org')
    expect(who.claims.name).toBe('IA Officer')
    expect(who.claims.roles).toEqual(['ia_officer'])
    expect(who.claims.groups).toEqual(['ia_officer'])
    expect(who.claims.org).toBe('EX1')
    expect(who.claims.nonce).toBeTruthy()
    expect(who.lastError).toBeNull()
    expect(who.userinfo).toMatchObject({ email: 'ia@oiml.org', roles: ['ia_officer'], org: 'EX1' })
  })

  it('leg 3 — Deny answers the RP with access_denied and no code', { timeout: 600_000 }, async () => {
    // Still signed in at the OP from leg 2 — the authorize goes straight
    // to consent (the OP session's whole point).
    await page.goto(`${rp.baseUrl}/signin`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await page.waitForSelector('[data-testid="op-consent-deny"]', { timeout: SETTLE, polling: 500 })
    await page.evaluate(() => (document.querySelector('[data-testid="op-consent-deny"]') as HTMLElement).click())
    await page.waitForSelector('[data-testid="rp-error"]', { timeout: SETTLE, polling: 500 })
    const kind = await page.$eval('[data-testid="rp-error-kind"]', el => el.textContent?.trim())
    expect(kind).toBe('access_denied')
    const who = await (await fetch(`${rp.baseUrl}/whoami`)).json() as { claims: unknown; lastError: Record<string, string> | null }
    expect(who.claims).toBeNull()
    expect(who.lastError?.error).toBe('access_denied')
  })

  it('leg 4 — an unregistered redirect_uri is refused in place (never redirected)', { timeout: 600_000 }, async () => {
    const query = new URLSearchParams({
      response_type: 'code',
      client_id: RP_CLIENT_ID,
      redirect_uri: 'http://127.0.0.1:9/steal',
      scope: 'openid',
      state: 's',
      nonce: 'n',
      code_challenge: 'whatever',
      code_challenge_method: 'S256',
    })
    const res = await fetch(`${stack.base}/op/authorize?${query}`, { redirect: 'manual' })
    expect(res.status).toBe(400)
    expect(res.headers.get('location')).toBeNull()
    expect(await res.text()).toContain('redirect_uri')
  })

  it('leg 5 — a replayed code and a PKCE failure both lose (invalid_grant)', { timeout: 600_000 }, async () => {
    // A full round trip over fetch (the session cookie from the demo
    // login; the consent decision API; the code from the redirect).
    const login = await fetch(`${stack.base}/api/auth/demo`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: 'tl@oiml.org', password: 'demo2026' }),
    })
    expect(login.ok).toBe(true)
    const cookie = login.headers.get('set-cookie')!.split(';')[0]!

    // The RP-side values (the same builders the RP uses).
    const { generatePkce } = await import('@oimlsmart/platform-server/oidc')
    const pkce = await generatePkce()
    const query = new URLSearchParams({
      response_type: 'code',
      client_id: RP_CLIENT_ID,
      redirect_uri: `${rp.baseUrl}/callback`,
      scope: 'openid profile email',
      state: 'replay-state',
      nonce: 'replay-nonce',
      code_challenge: pkce.challenge,
      code_challenge_method: 'S256',
    })
    const authorize = await fetch(`${stack.base}/op/authorize?${query}`, { headers: { cookie }, redirect: 'manual' })
    expect(authorize.status).toBe(302)
    const consentUrl = new URL(authorize.headers.get('location')!, stack.base)
    const authId = consentUrl.searchParams.get('auth')!
    const decide = await fetch(`${stack.base}/api/op/consent/${authId}/decide`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ decision: 'allow' }),
    })
    expect(decide.ok).toBe(true)
    const { redirect } = await decide.json() as { redirect: string }
    const code = new URL(redirect).searchParams.get('code')!

    const exchange = (verifier: string) => fetch(`${stack.base}/op/token`, {
      method: 'POST',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        authorization: `Basic ${btoa(`${encodeURIComponent(RP_CLIENT_ID)}:${encodeURIComponent(RP_CLIENT_SECRET)}`)}`,
      },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: `${rp.baseUrl}/callback`,
        client_id: RP_CLIENT_ID,
        code_verifier: verifier,
      }),
    })

    // A PKCE failure spends the code…
    const wrong = await exchange('the-wrong-verifier')
    expect(wrong.status).toBe(400)
    expect(await wrong.json()).toMatchObject({ error: 'invalid_grant' })
    // …so the RIGHT verifier now loses too (one-time means one-time)…
    const replay = await exchange(pkce.verifier)
    expect(replay.status).toBe(400)
    expect(await replay.json()).toMatchObject({ error: 'invalid_grant' })

    // …and a FRESH code exchanges exactly once.
    const authorize2 = await fetch(`${stack.base}/op/authorize?${query}`, { headers: { cookie }, redirect: 'manual' })
    const authId2 = new URL(authorize2.headers.get('location')!, stack.base).searchParams.get('auth')!
    const decide2 = await fetch(`${stack.base}/api/op/consent/${authId2}/decide`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ decision: 'allow' }),
    })
    const code2 = new URL((await decide2.json() as { redirect: string }).redirect).searchParams.get('code')!
    const body2 = (verifier: string) => new URLSearchParams({
      grant_type: 'authorization_code', code: code2, redirect_uri: `${rp.baseUrl}/callback`,
      client_id: RP_CLIENT_ID, code_verifier: verifier,
    })
    const headers2 = {
      'content-type': 'application/x-www-form-urlencoded',
      authorization: `Basic ${btoa(`${encodeURIComponent(RP_CLIENT_ID)}:${encodeURIComponent(RP_CLIENT_SECRET)}`)}`,
    }
    const first = await fetch(`${stack.base}/op/token`, { method: 'POST', headers: headers2, body: body2(pkce.verifier) })
    expect(first.status).toBe(200)
    const second = await fetch(`${stack.base}/op/token`, { method: 'POST', headers: headers2, body: body2(pkce.verifier) })
    expect(second.status, 'the replayed code').toBe(400)
    expect(await second.json()).toMatchObject({ error: 'invalid_grant' })
  })
})
