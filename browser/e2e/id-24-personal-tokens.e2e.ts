// ═══════════════════════════════════════════════════════════════════
// The developer tokens (TODO.identity-features/08 — the personal access
// tokens), the e2e (the identity-profile stack, the id-17/id-19
// spawned-stack pattern — its own API + its own astro, its own SQLite
// file):
//
//   leg 1  the MINT through the console (the account page's developer-
//          tokens section): the scope picker bounded by the account's
//          own standing (the admin class disables for the officer), the
//          mandatory expiration picker, the ONE-TIME plaintext dialog
//          (the store holds the hash — the row never re-answers the
//          plaintext), the list row's honest metadata;
//   leg 2  the EXCHANGE for real: the minted PAT exchanges at /op/token
//          (the RFC 8693 grant) for the short-lived OP JWT — verified
//          against the stack's OWN JWKS (the RP's posture), the claims
//          asserted (the scope set, the per-service roles, the active-org
//          context, never an ID-token shape); the AT-USE narrowing proof
//          runs the RP gate's own check (the kernel's patScopeCovers)
//          over the token's scope claim — within stands, outside refuses;
//   leg 3  the refusal lattice over the wire: the unknown PAT, the wrong
//          subject_token_type, the scope parameter that widens — and the
//          discovery document NEVER advertises the cone (the device
//          class's precedent: the golden's surface stays byte-identical);
//   leg 4  the NARROWING mid-flight: the administrator strips the
//          account's register role — the next exchange carries the hub
//          only (the standing re-judgment, the dropped scope audited);
//   leg 5  the REVOKE kills it mid-flight (the console act; the exchange
//          refuses from that instant — the already-minted JWT lives out
//          its short hour, the honest TTL posture), the audit chain
//          carries the arc (mint / exchange / revoke), the account's own
//          activity feed shows it, and the org-admin inventory (the org
//          detail page's developer-tokens section) renders the member's
//          row — the metadata only, the revoked state honestly.
//
// SELF-CONTAINED: the suite's shared stack (E2E_BASE_URL) is untouched —
// the identity instance boots on its own ports (API 10605 / astro
// 10606, above every live leg) with its own SQLite file.
// ═══════════════════════════════════════════════════════════════════

import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import puppeteer, { type Browser, type Page } from 'puppeteer'
import { spawn, type ChildProcess } from 'node:child_process'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { existsSync, mkdirSync, rmSync, cpSync } from 'node:fs'
import { closeBrowser, delay } from './helpers'
import { fixtureOpSigningKey } from './fixtures/op-signing-key'

const BROWSER_DIR = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const FIXTURES = join(BROWSER_DIR, 'e2e', 'fixtures')
const DB_DIR = join(BROWSER_DIR, '.cache', 'id-24')

// Port-isolated: above every declared e2e stack (…10604 is id-23's) and
// the local dev loops.
const ID_API = 10605
const ID_WEB = 10606

const IA_EMAIL = 'ia@oiml.org'
const ADMIN_EMAIL = 'admin@oiml.org'

// The estate's services for the arc (the OP's client registry IS the
// service registry): the hub + the register, both the application class.
const HUB = {
  client_id: 'hub-instance',
  name: 'OIML SMART platform hub',
  redirect_uris: ['https://hub.example/api/auth/callback/oidc'],
  claims_policy: { claims: ['roles', 'groups', 'org'] },
}
const REGISTER = {
  client_id: 'register-instance',
  name: 'The OIML register',
  redirect_uris: ['https://register.example/api/auth/callback/oidc'],
  claims_policy: { claims: ['roles'] },
}

const EXCHANGE_GRANT = 'urn:ietf:params:oauth:grant-type:token-exchange'
const PAT_TOKEN_TYPE = 'urn:oimlsmart:params:oauth:token-type:pat'

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

/** Boot the identity-profile stack (the id-19 posture), the client
 *  registry's bootstrap seed carrying the hub + the register. */
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
      OP_ISSUER: `http://localhost:${ID_WEB}`,
      OP_SIGNING_KEY: await fixtureOpSigningKey(),
      OP_CLIENT_SEED: JSON.stringify([HUB, REGISTER]),
    }, logs)
    const apiBase = `http://localhost:${ID_API}`
    await waitForHttp(`${apiBase}/api/health`, 120_000, logs)

    // Provision the profile's seed (the demo cast + the org registry —
    // EX1 among it, the IA officer's org).
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

/** Sign in through the demo cast (DEMO_ACCOUNTS_ENABLED=true). */
async function opSignIn(page: Page, email: string): Promise<void> {
  await page.waitForSelector('[data-testid="login-email"]', { timeout: SETTLE, polling: 500 })
  await page.evaluate(() => {
    (document.querySelector('[data-testid="login-email"]') as HTMLInputElement).value = ''
  })
  await page.type('[data-testid="login-email"]', email)
  await page.type('[data-testid="login-password"]', 'demo2026')
  await page.evaluate(() => (document.querySelector('[data-testid="login-submit"]') as HTMLElement).click())
}

/** A fetch-level demo sign-in against the stack (the acts that never
 *  need a browser). */
async function apiSignIn(apiBase: string, email: string): Promise<string> {
  const login = await fetch(`${apiBase}/api/auth/demo`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password: 'demo2026' }),
  })
  expect(login.ok, `demo sign-in ${email}`).toBe(true)
  return (login.headers.get('set-cookie') ?? '').split(';')[0]!
}

/** Drop the session (the id-10 pattern: the cookie is httpOnly — the
 *  browser-side delete), then settle on the sign-in page so the next
 *  goto never races a console page's self-redirect. */
async function signOut(page: Page): Promise<void> {
  await page.evaluate(async () => {
    await fetch('/api/auth/signout', { method: 'POST', credentials: 'include' })
  })
  const origin = new URL(page.url()).origin
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      await page.goto(`${origin}/`, { waitUntil: 'domcontentloaded', timeout: 60_000 })
      return
    } catch (e) {
      const msg = String(e)
      if (attempt === 1 || !(msg.includes('ERR_ABORTED') || msg.includes('Execution context was destroyed'))) throw e
      await delay(600)
    }
  }
}

/** The PAT exchange (the RFC 8693 grant, no client auth — the PAT IS the
 *  credential). */
async function exchangePat(apiBase: string, pat: string, extra?: Record<string, string>): Promise<Response> {
  return fetch(`${apiBase}/op/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: EXCHANGE_GRANT,
      subject_token_type: PAT_TOKEN_TYPE,
      subject_token: pat,
      ...extra,
    }).toString(),
  })
}

function base64urlDecode(s: string): Uint8Array {
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice(0, (4 - (s.length % 4)) % 4)
  const bin = atob(b64)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

/** Verify the exchanged JWT against the stack's OWN JWKS (the RP's
 *  posture) and answer its claims. */
async function verifyOpJwt(apiBase: string, token: string): Promise<Record<string, unknown>> {
  const [h, p, s] = token.split('.')
  expect(s, 'a 3-part JWT').toBeTruthy()
  const header = JSON.parse(new TextDecoder().decode(base64urlDecode(h!))) as { kid: string }
  const jwks = await (await fetch(`${apiBase}/jwks.json`)).json() as { keys: Array<{ kid?: string; x: string; y: string }> }
  const jwk = jwks.keys.find(k => k.kid === header.kid)
  expect(jwk, 'the signing key is on the JWKS').toBeTruthy()
  const key = await crypto.subtle.importKey(
    'jwk',
    { kty: 'EC', crv: 'P-256', x: jwk!.x, y: jwk!.y },
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['verify'],
  )
  const ok = await crypto.subtle.verify(
    { name: 'ECDSA', hash: 'SHA-256' },
    key,
    base64urlDecode(s!) as BufferSource,
    new TextEncoder().encode(`${h}.${p}`),
  )
  expect(ok, 'the exchanged token verifies against the OP’s JWKS').toBe(true)
  return JSON.parse(new TextDecoder().decode(base64urlDecode(p!))) as Record<string, unknown>
}

describe('the developer tokens (the identity profile)', () => {
  let stack: Stack
  let browser: Browser
  let page: Page
  let mintedPat = ''
  let mintedId = ''

  beforeAll(async () => {
    stack = await bootIdentityStack()
    browser = await puppeteer.launch({ headless: 'shell', protocolTimeout: 480_000, args: ['--no-sandbox', '--disable-setuid-sandbox'] })
    page = await browser.newPage()
    await page.setViewport({ width: 1440, height: 900 })
    page.on('pageerror', e => console.log('[pageerror]', String(e).slice(0, 300)))
    page.on('requestfailed', r => console.log('[requestfailed]', r.url().slice(0, 140), r.failure()?.errorText ?? ''))
  }, 600_000)

  afterAll(async () => {
    await closeBrowser(browser)
    await stopStack(stack)
  })

  it('leg 1 — the mint through the console: the bounded picker, the mandatory expiry, the one-time plaintext', { timeout: 900_000 }, async () => {
    await page.goto(`${stack.base}/`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await opSignIn(page, IA_EMAIL)
    await page.waitForFunction(() => window.location.pathname !== '/', { timeout: SETTLE, polling: 500 })
    await page.goto(`${stack.base}/op/account`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await page.waitForSelector('[data-testid="account-tokens"]', { timeout: SETTLE, polling: 500 })

    // The picker's honesty: the services the officer may mint for (the
    // hub + the register), the admin class DISABLED for the officer
    // (ia_officer holds workflow permissions, never the administration
    // class).
    await page.evaluate(() => (document.querySelector('[data-testid="token-mint-open"]') as HTMLElement).click())
    await page.waitForSelector('[data-testid="token-form"]', { timeout: SETTLE, polling: 500 })
    await page.waitForSelector(`[data-testid="token-scope-${HUB.client_id}"]`, { timeout: SETTLE, polling: 500 })
    const adminDisabled = await page.$eval(`[data-testid="token-scope-${HUB.client_id}-admin"]`, el => (el as HTMLOptionElement).disabled)
    expect(adminDisabled, 'the admin class disables for the officer').toBe(true)
    const writeEnabled = await page.$eval(`[data-testid="token-scope-${HUB.client_id}-write"]`, el => !(el as HTMLOptionElement).disabled)
    expect(writeEnabled).toBe(true)

    await page.type('[data-testid="token-name"]', 'the lab CLI (e2e)')
    await page.select(`[data-testid="token-scope-${HUB.client_id}"]`, 'write')
    await page.select(`[data-testid="token-scope-${REGISTER.client_id}"]`, 'read')
    await page.select('[data-testid="token-expiry"]', '30')
    await page.evaluate(() => (document.querySelector('[data-testid="token-mint-submit"]') as HTMLElement).click())

    // The one-time plaintext dialog (the GitHub doctrine).
    await page.waitForSelector('[data-testid="token-once"]', { timeout: SETTLE, polling: 500 })
    mintedPat = (await page.$eval('[data-testid="token-once"]', el => el.textContent ?? '')).trim()
    expect(mintedPat.startsWith('ospt_'), 'the wire prefix').toBe(true)
    expect(mintedPat.length).toBe(48)
    await page.evaluate(() => (document.querySelector('[data-testid="token-once-dismiss"]') as HTMLElement).click())

    // The list row renders the metadata — the plaintext NEVER again.
    await page.waitForSelector('[data-testid="tokens-list"]', { timeout: SETTLE, polling: 500 })
    const rowText = await page.$eval('[data-testid="tokens-list"]', el => el.textContent ?? '')
    expect(rowText).toContain('the lab CLI (e2e)')
    expect(rowText).toContain(`${HUB.client_id}:write`)
    expect(rowText).not.toContain(mintedPat)
    const revokeBtn = await page.$('[data-testid^="token-"][data-testid$="-revoke"]')
    expect(revokeBtn, 'the revoke act shows on the live row').toBeTruthy()
    mintedId = (await page.evaluate(() =>
      document.querySelector('[data-testid^="token-"][data-testid$="-revoke"]')?.getAttribute('data-testid') ?? '',
    )).replace(/^token-/, '').replace(/-revoke$/, '')
    expect(mintedId).toBeTruthy()
  })

  it('leg 2 — the exchange for real: the JWKS-verifiable scoped JWT; the at-use narrowing proof (the RP gate’s own check)', { timeout: 900_000 }, async () => {
    const res = await exchangePat(stack.apiBase, mintedPat)
    expect(res.status).toBe(200)
    const body = await res.json() as { access_token: string; issued_token_type: string; token_type: string; expires_in: number; scope: string }
    expect(body.issued_token_type).toBe('urn:ietf:params:oauth:token-type:access_token')
    expect(body.token_type).toBe('Bearer')
    expect(body.scope).toBe(`${HUB.client_id}:write ${REGISTER.client_id}:read`)

    const claims = await verifyOpJwt(stack.apiBase, body.access_token)
    expect(claims.iss).toBe(`http://localhost:${ID_WEB}`)
    expect(claims.scope).toBe(`${HUB.client_id}:write ${REGISTER.client_id}:read`)
    expect(claims.aud).toEqual([HUB.client_id, REGISTER.client_id])
    expect(claims.email).toBe(IA_EMAIL)
    expect(claims.org, 'the active-org context (the IA’s EX1)').toBe('EX1')
    expect(claims.pat).toBe(mintedId)
    expect(claims.service_roles).toMatchObject({ [HUB.client_id]: ['ia_officer'], [REGISTER.client_id]: ['ia_officer'] })
    for (const never of ['nonce', 'amr', 'id_token']) {
      expect(claims[never], `never ${never} on the exchanged token`).toBeUndefined()
    }

    // The at-use narrowing, the RP gate's OWN check (the kernel's
    // patScopeCovers — the function the platform's bearer cone calls):
    // the granted set covers the allowed acts and refuses the rest.
    const { normalizePatScopes, patScopeCovers } = await import('@oimlsmart/platform-server/store')
    const granted = normalizePatScopes(String(claims.scope).split(/\s+/))!
    expect(patScopeCovers(granted, HUB.client_id, 'read')).toBe(true)
    expect(patScopeCovers(granted, HUB.client_id, 'write'), 'the hub write stands').toBe(true)
    expect(patScopeCovers(granted, REGISTER.client_id, 'read')).toBe(true)
    expect(patScopeCovers(granted, HUB.client_id, 'admin'), 'the admin class never rides').toBe(false)
    expect(patScopeCovers(granted, REGISTER.client_id, 'write'), 'the register write never rides').toBe(false)
  })

  it('leg 3 — the refusal lattice + the discovery document never advertises the cone', { timeout: 900_000 }, async () => {
    // The unknown PAT.
    const unknown = await exchangePat(stack.apiBase, `ospt_${'x'.repeat(43)}`)
    expect(unknown.status).toBe(400)
    expect(((await unknown.json()) as { error: string }).error).toBe('invalid_grant')
    // The wrong subject_token_type.
    const wrongType = await fetch(`${stack.apiBase}/op/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: EXCHANGE_GRANT, subject_token_type: 'urn:ietf:params:oauth:token-type:jwt', subject_token: mintedPat }).toString(),
    })
    expect(wrongType.status).toBe(400)
    expect(((await wrongType.json()) as { error: string }).error).toBe('invalid_request')
    // The scope parameter that widens.
    const widened = await exchangePat(stack.apiBase, mintedPat, { scope: `${HUB.client_id}:admin` })
    expect(widened.status).toBe(400)
    expect(((await widened.json()) as { error: string }).error).toBe('invalid_scope')
    // …and narrows honestly.
    const narrowed = await exchangePat(stack.apiBase, mintedPat, { scope: `${HUB.client_id}:read` })
    expect(narrowed.status).toBe(200)
    expect(((await narrowed.json()) as { scope: string }).scope).toBe(`${HUB.client_id}:read`)

    // The discovery document: the RP contract alone (the device class's
    // precedent — the estate-internal cone never advertises).
    const discovery = await (await fetch(`${stack.apiBase}/.well-known/openid-configuration`)).json() as { grant_types_supported: string[] }
    expect(discovery.grant_types_supported).toEqual(['authorization_code'])
  })

  it('leg 4 — the narrowing mid-flight: the service’s disable shrinks the next exchange (the standing re-judgment)', { timeout: 900_000 }, async () => {
    // The trigger is the HONEST one the served acts carry: the register's
    // client leaves the estate (the admin's disable — the same act that
    // revokes a device client, id-19's precedent). The next exchange
    // re-judges the pinned set against the live registry: the dropped
    // service falls away, the hub stands. (The per-client ROLE strip —
    // the other narrowing lever — is deliberately unreachable here: the
    // registry's account acts are scoped to the OP's own password
    // accounts, never the seed-managed demo cast; the unit floor drives
    // that lever in-process.)
    const admin = await apiSignIn(stack.apiBase, ADMIN_EMAIL)
    const disable = await fetch(`${stack.apiBase}/api/op/clients/${REGISTER.client_id}/status`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: admin },
      body: JSON.stringify({ status: 'disabled' }),
    })
    expect(disable.ok, 'the client’s disable lands').toBe(true)

    const res = await exchangePat(stack.apiBase, mintedPat)
    expect(res.status).toBe(200)
    const body = await res.json() as { scope: string; access_token: string }
    expect(body.scope, 'the dropped service fell away').toBe(`${HUB.client_id}:write`)
    const claims = await verifyOpJwt(stack.apiBase, body.access_token)
    expect(claims.service_roles).toEqual({ [HUB.client_id]: ['ia_officer'] })

    // The audit names the drop (the narrowing beat).
    const feed = await (await fetch(`${stack.apiBase}/api/op/registry/activity?limit=300`, { headers: { cookie: admin } })).json() as Array<{ action: string; metadata?: Record<string, unknown> }>
    const narrowed = feed.find(e =>
      (e.action === 'account.pat_exchange_narrowed' || e.action === 'account.pat_exchange')
      && Array.isArray(e.metadata?.dropped))
    expect(narrowed, 'the narrowing is audited').toBeTruthy()
    expect((narrowed!.metadata!.dropped as string[])).toContain(`${REGISTER.client_id}:read`)

    // Re-enable: the estate stands again for the rest of the arc.
    const enable = await fetch(`${stack.apiBase}/api/op/clients/${REGISTER.client_id}/status`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: admin },
      body: JSON.stringify({ status: 'active' }),
    })
    expect(enable.ok).toBe(true)
  })

  it('leg 5 — the revoke kills it mid-flight; the audit arc; the org-admin inventory', { timeout: 900_000 }, async () => {
    // The revoke through the console.
    await page.goto(`${stack.base}/op/account`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await page.waitForSelector(`[data-testid="token-${mintedId}-revoke"]`, { timeout: SETTLE, polling: 500 })
    await page.evaluate((id) => (document.querySelector(`[data-testid="token-${id}-revoke"]`) as HTMLElement).click(), mintedId)
    await page.waitForFunction((id) => {
      const badge = document.querySelector(`[data-testid="token-${id}-state"]`)
      return badge?.textContent?.trim() === 'revoked'
    }, { timeout: SETTLE, polling: 500 }, mintedId)

    // The exchange refuses from this instant.
    const refused = await exchangePat(stack.apiBase, mintedPat)
    expect(refused.status).toBe(400)
    expect(((await refused.json()) as { error: string }).error).toBe('invalid_grant')

    // The audit chain carries the arc (the admin's registry feed).
    const admin = await apiSignIn(stack.apiBase, ADMIN_EMAIL)
    const feed = await (await fetch(`${stack.apiBase}/api/op/registry/activity?limit=300`, { headers: { cookie: admin } })).json() as Array<{ action: string; entity_id: string; metadata?: Record<string, unknown> }>
    const arc = feed.filter(e => e.metadata?.pat === mintedId)
    expect(arc.some(e => e.action === 'account.pat_minted'), 'the mint is on the chain').toBe(true)
    expect(arc.some(e => e.action === 'account.pat_exchange'), 'the exchange heartbeat is on the chain').toBe(true)
    expect(arc.some(e => e.action === 'account.pat_revoked'), 'the revoke is on the chain').toBe(true)

    // The account's own activity feed shows the arc too.
    const ia = await apiSignIn(stack.apiBase, IA_EMAIL)
    const own = await (await fetch(`${stack.apiBase}/api/op/account/activity`, { headers: { cookie: ia } })).json() as Array<{ action: string; metadata?: Record<string, unknown> }>
    expect(own.some(e => e.action === 'account.pat_minted' && e.metadata?.name === 'the lab CLI (e2e)')).toBe(true)

    // The org-admin inventory (the org detail page's section): the
    // member's row, the metadata only, the revoked state honestly. The
    // admin's UI sign-in follows a clean sign-out (the ia session never
    // leaks into it — the id-10 pattern).
    await signOut(page)
    await page.goto(`${stack.base}/`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await opSignIn(page, ADMIN_EMAIL)
    await page.waitForFunction(() => window.location.pathname !== '/', { timeout: SETTLE, polling: 500 })
    await page.goto(`${stack.base}/op/admin/registry/orgs/EX1`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await page.waitForSelector('[data-testid="op-reg-org-tokens"]', { timeout: SETTLE, polling: 500 })
    await page.waitForSelector(`[data-testid="op-reg-org-token-${mintedId}"]`, { timeout: SETTLE, polling: 500 })
    const rowText = await page.$eval(`[data-testid="op-reg-org-token-${mintedId}"]`, el => el.textContent ?? '')
    expect(rowText).toContain('the lab CLI (e2e)')
    expect(rowText).toContain('IA Officer')
    expect(rowText).toContain('revoked')
    expect(rowText).not.toContain(mintedPat)
    expect(rowText).toContain('ospt_') // the display prefix, never the secret
  })
})
