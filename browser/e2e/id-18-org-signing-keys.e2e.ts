// ═══════════════════════════════════════════════════════════════════
// TODO.trust-registry/01 — the org signing keys, the e2e: the
// identity-profile stack (its own API + its own astro, the id-17
// spawned-stack pattern), the full arc for real:
//
//   leg 1  the SEEDED demonstration key resolves publicly: EX1's demo
//          signing key on GET /op/keys/EX1.json — anonymous, the JWK
//          Set member shape, the participant standing, the short
//          max-age + the CORS-open header (through the astro proxy, the
//          verifiers' posture);
//   leg 2  the estate admin delegates org_admin to the demo IA officer
//          (fetch-level, the memberships roles act); the officer's
//          account console shows the org's signing-keys section with
//          the demonstration key active;
//   leg 3  the officer REGISTERS a key through the console (the label +
//          the PUBLIC JWK pasted; the private half never leaves the
//          test process);
//   leg 4  the public endpoint resolves BOTH keys with the standing
//          (anonymous, no cookie);
//   leg 5  the ROTATION overlaps through the console: the successor
//          registers, the predecessor keeps its row with the stamps —
//          the public endpoint carries both kids, the predecessor
//          naming its successor;
//   leg 6  the REVOCATION stamps and the at-the-time honesty: the
//          revoked predecessor STILL resolves on the public endpoint
//          with its revocation date, and the audit chain carries every
//          act of the arc;
//   leg 7  the admin's org detail page renders the custody chain
//          honestly, and the negatives hold (the applicant's 403, the
//          anonymous 401, the private-material 400, the unknown org's
//          public 404).
//
// SELF-CONTAINED: the suite's shared stack (E2E_BASE_URL) is untouched —
// the identity instance boots on its own ports (API 10593 / astro
// 10594) with its own SQLite file.
// ═══════════════════════════════════════════════════════════════════

import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import puppeteer, { type Browser, type Page } from 'puppeteer'
import { spawn, type ChildProcess } from 'node:child_process'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { existsSync, mkdirSync, rmSync, cpSync } from 'node:fs'
import { closeBrowser, delay } from './helpers'
import { fixtureOpSigningKey } from './fixtures/op-signing-key'
import { kidFor } from '../server/auth/op/keys'
import { DEMO_EX1_SIGNING_KEY } from '../server/seed-org-register'

const BROWSER_DIR = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const FIXTURES = join(BROWSER_DIR, 'e2e', 'fixtures')
const DB_DIR = join(BROWSER_DIR, '.cache', 'id-18')

// Port-isolated: clear of every declared e2e stack (3190..10495, 19894)
// and the local dev loops.
const ID_API = 10593
const ID_WEB = 10594

// The cast: EX1 the seeded active IA (the demonstration key's org), its
// officer delegated to org_admin in leg 2, the estate admin, and the
// ACME applicant (the negative — never a key administrator).
const IA_EMAIL = 'ia@oiml.org'
const ADMIN_EMAIL = 'admin@oiml.org'
const APPLICANT_EMAIL = 'applicant@oiml.org'
const DEMO_KID = DEMO_EX1_SIGNING_KEY.kid

interface Stack {
  api: ChildProcess
  astro: ChildProcess
  base: string
  apiBase: string
  logs: string[]
}

/** A fresh ES256 pair: the PUBLIC half goes to the console form; the
 *  PRIVATE half never leaves the test process (the custody rule). */
async function freshPublicJwk(): Promise<{ publicJwk: JsonWebKey; kid: string }> {
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
  const pub = await crypto.subtle.exportKey('jwk', pair.publicKey)
  const publicJwk = { kty: 'EC', crv: 'P-256', x: pub.x, y: pub.y } as JsonWebKey
  return { publicJwk, kid: await kidFor(publicJwk) }
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

/** Boot the identity-profile stack (the id-17 posture). */
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
    // must not inherit it (the id-08 discipline).
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
    }, logs)
    const apiBase = `http://localhost:${ID_API}`
    await waitForHttp(`${apiBase}/api/health`, 120_000, logs)

    // Provision the profile's seed (the demo cast + the registry + EX1's
    // demonstration signing key — TODO.trust-registry/01's seed phase).
    const reset = await fetch(`${apiBase}/api/dev-reset`, { method: 'POST' })
    if (!reset.ok) throw new Error(`dev-reset on ${apiBase} answered ${reset.status}\n${logs.join('').slice(-2000)}`)
    const seeded = await reset.json() as { signingKeys?: number }
    expect(seeded.signingKeys).toBe(1)

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

/** Sign in through the demo cast (DEMO_ACCOUNTS_ENABLED=true — the OP
 *  login form falls back to the demo endpoint on a 401, 02's posture). */
async function opSignIn(page: Page, email: string): Promise<void> {
  await page.waitForSelector('[data-testid="login-email"]', { timeout: SETTLE, polling: 500 })
  await page.evaluate(() => {
    (document.querySelector('[data-testid="login-email"]') as HTMLInputElement).value = ''
  })
  await page.type('[data-testid="login-email"]', email)
  await page.type('[data-testid="login-password"]', 'demo2026')
  await page.evaluate(() => (document.querySelector('[data-testid="login-submit"]') as HTMLElement).click())
}

/** Drop the session (the cookie is httpOnly — the browser-side delete),
 *  then settle the browser on the sign-in page (the id-10 race guard). */
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

/** A fetch-level demo sign-in against the stack (the cookie jar is a
 *  string — the acts that never need a browser). */
async function apiSignIn(apiBase: string, email: string): Promise<string> {
  const login = await fetch(`${apiBase}/api/auth/demo`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password: 'demo2026' }),
  })
  expect(login.ok, `demo sign-in ${email}`).toBe(true)
  return (login.headers.get('set-cookie') ?? '').split(';')[0]!
}

/** The public key-resolution document (anonymous — NEVER a cookie). */
async function publicKeyDoc(base: string, orgId: string): Promise<{ status: number; doc: any; headers: Headers }> {
  const res = await fetch(`${base}/op/keys/${orgId}.json`)
  return { status: res.status, doc: res.status === 200 ? await res.json() : null, headers: res.headers }
}

describe('TODO.trust-registry/01 — the org signing keys (the identity profile)', () => {
  let stack: Stack
  let browser: Browser
  let page: Page
  // The arc's key material: leg 3's registration and leg 5's successor.
  let registeredKid = ''
  let successorKid = ''

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

  it('leg 1 — the seeded demonstration key resolves publicly (anonymous, cacheable, CORS-open, through the astro proxy)', { timeout: 900_000 }, async () => {
    const { status, doc, headers } = await publicKeyDoc(stack.base, 'EX1')
    expect(status).toBe(200)
    expect(headers.get('cache-control')).toBe('public, max-age=60')
    expect(headers.get('access-control-allow-origin')).toBe('*')
    expect(doc.org_id).toBe('EX1')
    expect(doc.org_name).toBe('Example Issuing Authority')
    expect(doc.org_kind).toBe('issuing-authority')
    expect(doc.org_state).toBe('active')
    expect(doc.standing).toBe('participant')
    expect(doc.keys).toHaveLength(1)
    const demo = doc.keys[0]
    expect(demo.kid).toBe(DEMO_KID)
    expect(demo.label).toContain('demonstration')
    expect(demo).toMatchObject({ kty: 'EC', crv: 'P-256', alg: 'ES256', use: 'sig' })
    expect(typeof demo.x).toBe('string')
    expect(typeof demo.y).toBe('string')
    expect(demo.d).toBeUndefined() // the private half NEVER publishes
    expect(demo.created_at).toBeTruthy()
    expect(demo.rotated_at).toBeNull()
    expect(demo.revoked_at).toBeNull()
    // The actors' emails stay on the audit chain — never the public doc.
    expect(JSON.stringify(doc)).not.toContain('created_by')
  })

  it('leg 2 — the estate admin delegates org_admin to the IA officer; the officer’s account console shows the signing-keys section', { timeout: 900_000 }, async () => {
    // The delegation (fetch-level): the wide grant's org_admin assignment
    // on the officer's EX1 membership.
    const admin = await apiSignIn(stack.apiBase, ADMIN_EMAIL)
    const users = await (await fetch(`${stack.apiBase}/api/op/registry/users?q=ia@oiml.org`, { headers: { cookie: admin } })).json() as Array<{ id: string; email: string | null }>
    const officer = users.find(u => u.email === IA_EMAIL)!
    expect(officer).toBeTruthy()
    const roles = await fetch(`${stack.apiBase}/api/op/org-memberships/${officer.id}/EX1/roles`, {
      method: 'PUT',
      headers: { 'content-type': 'application/json', cookie: admin },
      body: JSON.stringify({ roles: ['ia_officer', 'org_admin'] }),
    })
    expect(roles.status).toBe(200)

    // The officer signs in (the fresh session carries the delegated role)
    // and the account console's organization section shows the keys.
    await page.goto(`${stack.base}/`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await opSignIn(page, IA_EMAIL)
    await page.waitForFunction(() => window.location.pathname !== '/', { timeout: SETTLE, polling: 500 })
    await page.goto(`${stack.base}/op/account`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await page.waitForSelector('[data-testid="account-org-keys"]', { timeout: SETTLE, polling: 500 })
    await page.waitForSelector(`[data-testid="account-org-key-${DEMO_KID}"]`, { timeout: SETTLE, polling: 500 })
    const demoRow = await page.$eval(`[data-testid="account-org-key-stamps-${DEMO_KID}"]`, el => el.textContent ?? '')
    expect(demoRow).toContain('demonstration seed')
    await page.waitForSelector(`[data-testid="account-org-key-active-${DEMO_KID}"]`, { timeout: SETTLE, polling: 500 })
  })

  it('leg 3 — the officer registers a key through the console (the public half pasted; the private half never leaves the test process)', { timeout: 900_000 }, async () => {
    const { publicJwk, kid } = await freshPublicJwk()
    registeredKid = kid
    await page.type('[data-testid="account-org-key-label"]', 'EX1 R 60 signing key 2026')
    await page.evaluate((jwkJson) => {
      const ta = document.querySelector('[data-testid="account-org-key-jwk"]') as HTMLTextAreaElement
      ta.value = jwkJson
      ta.dispatchEvent(new Event('input'))
    }, JSON.stringify(publicJwk))
    await page.evaluate(() => (document.querySelector('[data-testid="account-org-key-register-submit"]') as HTMLElement).click())
    await page.waitForSelector(`[data-testid="account-org-key-${registeredKid}"]`, { timeout: SETTLE, polling: 500 })
    const notice = await page.$eval('[data-testid="op-account-notice"]', el => el.textContent ?? '').catch(() => '')
    expect(notice).toContain('EX1 R 60 signing key 2026')
  })

  it('leg 4 — the public endpoint resolves BOTH keys with the standing (anonymous)', { timeout: 900_000 }, async () => {
    const { status, doc } = await publicKeyDoc(stack.apiBase, 'EX1')
    expect(status).toBe(200)
    expect(doc.standing).toBe('participant')
    const kids = doc.keys.map((k: any) => k.kid)
    expect(kids).toEqual(expect.arrayContaining([DEMO_KID, registeredKid]))
    const registered = doc.keys.find((k: any) => k.kid === registeredKid)
    expect(registered.label).toBe('EX1 R 60 signing key 2026')
    expect(registered.revoked_at).toBeNull()
    expect(registered.rotated_at).toBeNull()
  })

  it('leg 5 — the rotation overlaps through the console: the predecessor keeps its row, the public endpoint carries both', { timeout: 900_000 }, async () => {
    const { publicJwk, kid } = await freshPublicJwk()
    successorKid = kid
    await page.goto(`${stack.base}/op/account`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await page.waitForSelector(`[data-testid="account-org-key-rotate-${registeredKid}"]`, { timeout: SETTLE, polling: 500 })
    await page.evaluate((k) => (document.querySelector(`[data-testid="account-org-key-rotate-${k}"]`) as HTMLElement).click(), registeredKid)
    await page.waitForSelector(`[data-testid="account-org-key-rotate-form-${registeredKid}"]`, { timeout: SETTLE, polling: 500 })
    await page.type(`[data-testid="account-org-key-rotate-label-${registeredKid}"]`, 'EX1 R 60 signing key 2027')
    await page.evaluate((jwkJson, k) => {
      const ta = document.querySelector(`[data-testid="account-org-key-rotate-jwk-${k}"]`) as HTMLTextAreaElement
      ta.value = jwkJson
      ta.dispatchEvent(new Event('input'))
    }, JSON.stringify(publicJwk), registeredKid)
    await page.evaluate((k) => (document.querySelector(`[data-testid="account-org-key-rotate-submit-${k}"]`) as HTMLElement).click(), registeredKid)
    // The overlap, honestly rendered: the predecessor's rotated badge +
    // the successor's active row.
    await page.waitForSelector(`[data-testid="account-org-key-rotated-${registeredKid}"]`, { timeout: SETTLE, polling: 500 })
    await page.waitForSelector(`[data-testid="account-org-key-${successorKid}"]`, { timeout: SETTLE, polling: 500 })

    const { doc } = await publicKeyDoc(stack.apiBase, 'EX1')
    const kids = doc.keys.map((k: any) => k.kid)
    expect(kids).toEqual(expect.arrayContaining([DEMO_KID, registeredKid, successorKid]))
    const predecessor = doc.keys.find((k: any) => k.kid === registeredKid)
    expect(predecessor.rotated_at).toBeTruthy()
    expect(predecessor.successor_kid).toBe(successorKid)
    const successor = doc.keys.find((k: any) => k.kid === successorKid)
    expect(successor.rotated_at).toBeNull()
    expect(successor.revoked_at).toBeNull()
  })

  it('leg 6 — the revocation stamps and the at-the-time honesty; the audit chain carries the arc', { timeout: 900_000 }, async () => {
    await page.goto(`${stack.base}/op/account`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await page.waitForSelector(`[data-testid="account-org-key-revoke-${registeredKid}"]`, { timeout: SETTLE, polling: 500 })
    await page.evaluate((k) => (document.querySelector(`[data-testid="account-org-key-revoke-${k}"]`) as HTMLElement).click(), registeredKid)
    await page.waitForSelector(`[data-testid="account-org-key-revoke-confirm-${registeredKid}"]`, { timeout: SETTLE, polling: 500 })
    await page.evaluate((k) => (document.querySelector(`[data-testid="account-org-key-revoke-submit-${k}"]`) as HTMLElement).click(), registeredKid)
    await page.waitForSelector(`[data-testid="account-org-key-revoked-${registeredKid}"]`, { timeout: SETTLE, polling: 500 })

    // THE AT-THE-TIME HONESTY: the revoked key STILL resolves on the
    // public endpoint — "valid at the time; the key since revoked on
    // DATE" — with the revocation date named.
    const { doc } = await publicKeyDoc(stack.apiBase, 'EX1')
    const revoked = doc.keys.find((k: any) => k.kid === registeredKid)
    expect(revoked).toBeTruthy()
    expect(revoked.revoked_at).toBeTruthy()
    expect(revoked.rotated_at).toBeTruthy() // the rotation's stamps survive too
    expect(revoked.successor_kid).toBe(successorKid)
    const stillActive = doc.keys.filter((k: any) => !k.revoked_at && !k.rotated_at).map((k: any) => k.kid)
    expect(stillActive.sort()).toEqual([DEMO_KID, successorKid].sort())

    // THE AUDIT CHAIN: every act of the arc is on the org's slice.
    const admin = await apiSignIn(stack.apiBase, ADMIN_EMAIL)
    const view = await (await fetch(`${stack.apiBase}/api/op/registry/orgs/EX1`, { headers: { cookie: admin } })).json() as {
      activity: Array<{ action: string; metadata?: Record<string, unknown> }>
    }
    const acts = view.activity.map(e => e.action)
    expect(acts).toEqual(expect.arrayContaining([
      'organization.key_registered',
      'organization.key_rotated',
      'organization.key_revoked',
    ]))
    const rotation = view.activity.find(e => e.action === 'organization.key_rotated')
    expect(rotation!.metadata).toMatchObject({ kid: registeredKid, successor_kid: successorKid })
  })

  it('leg 7 — the admin’s org detail page renders the custody chain; the honest negatives hold', { timeout: 900_000 }, async () => {
    await signOut(page)
    await page.goto(`${stack.base}/`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await opSignIn(page, ADMIN_EMAIL)
    await page.waitForFunction(() => window.location.pathname !== '/', { timeout: SETTLE, polling: 500 })
    await page.goto(`${stack.base}/op/admin/registry/orgs/EX1`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await page.waitForSelector('[data-testid="op-reg-org-keys"]', { timeout: SETTLE, polling: 500 })
    // The whole chain: the demo key active, the rotated predecessor, the
    // revoked stamps, the successor active.
    await page.waitForSelector(`[data-testid="op-reg-org-key-active-${DEMO_KID}"]`, { timeout: SETTLE, polling: 500 })
    await page.waitForSelector(`[data-testid="op-reg-org-key-revoked-${registeredKid}"]`, { timeout: SETTLE, polling: 500 })
    await page.waitForSelector(`[data-testid="op-reg-org-key-active-${successorKid}"]`, { timeout: SETTLE, polling: 500 })
    const stamps = await page.$eval(`[data-testid="op-reg-org-key-stamps-${registeredKid}"]`, el => el.textContent ?? '')
    expect(stamps).toContain(IA_EMAIL) // the officer's acts, named
    // The org's audit slice renders the key acts in words.
    await page.waitForFunction((k) => {
      const list = document.querySelector('[data-testid="op-reg-org-activity-list"]')
      return list && list.textContent?.includes(k)
    }, { timeout: SETTLE, polling: 500 }, registeredKid)

    // The honest negatives (fetch-level).
    const applicant = await apiSignIn(stack.apiBase, APPLICANT_EMAIL)
    const refused = await fetch(`${stack.apiBase}/api/op/org-keys`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: applicant },
      body: JSON.stringify({ org_id: 'EX1', label: 'the applicant’s key', public_jwk: (await freshPublicJwk()).publicJwk }),
    })
    expect(refused.status).toBe(403)
    const anon = await fetch(`${stack.apiBase}/api/op/org-keys`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ org_id: 'EX1', label: 'anonymous', public_jwk: (await freshPublicJwk()).publicJwk }),
    })
    expect(anon.status).toBe(401)
    const leaky = await freshPublicJwk()
    const adminCookie = await apiSignIn(stack.apiBase, ADMIN_EMAIL)
    const privateBody = await fetch(`${stack.apiBase}/api/op/org-keys`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: adminCookie },
      body: JSON.stringify({ org_id: 'EX1', label: 'leaky', public_jwk: { ...leaky.publicJwk, d: 'the-private-half' } }),
    })
    expect(privateBody.status).toBe(400)
    const unknown = await fetch(`${stack.apiBase}/op/keys/no-such-org.json`)
    expect(unknown.status).toBe(404)
    expect(unknown.headers.get('access-control-allow-origin')).toBe('*')
  })
})
