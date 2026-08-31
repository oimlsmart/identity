// ═══════════════════════════════════════════════════════════════════
// TODO.identity-features/09, wave A — the org-member DATA CONE, the
// identity-side e2e (the identity-profile stack, the id-13/id-19
// spawned-stack pattern — its own API + its own astro, its own SQLite
// file):
//
//   leg 1  THE CONSOLE: the org admin (the demo cast's ACME applicant,
//          mfr-acme's org_admin) invites an existing account, the holder
//          accepts, and the people section shows the member's cone badge
//          (org-wide — the silent default); the cone PICKER opens with
//          the three postures + the plain-language implications, the
//          save lands 'assigned', the badge flips;
//   leg 2  THE CLAIMS: the member acting AS the org mints a token whose
//          `cone` claim reads 'assigned' for the client whose policy
//          names it — and NO cone key at all for the plain client (the
//          contract golden's byte-clean posture);
//   leg 3  THE AUDIT CHAIN: every cone act is journaled (the org
//          admin's own audit slice carries it with the postures named),
//          the grantless member is refused the slice, and the identity
//          admin's per-org view shows the cone honestly.
//
// Port-isolated above every live leg (…10596 is id-19's): API 10597,
// astro 10598.
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
const DB_DIR = join(BROWSER_DIR, '.cache', 'id-20')

// Port-isolated: above every declared e2e stack (…10596 is id-19's) and
// the local dev loops.
const ID_API = 10597
const ID_WEB = 10598

const ORG = 'mfr-acme'
const ORG_ADMIN = 'applicant@oiml.org' // the demo cast's mfr-acme org_admin
const MEMBER = 'tl@oiml.org'

// The plain client (the golden's posture — never the cone claim) and the
// cone-gated one (the estate's RP shape: the policy names it).
const PLAIN_RP = {
  client_id: 'hub-instance',
  name: 'OIML SMART platform hub',
  secret: 'hub-secret-123',
  redirect_uris: ['https://hub.example/api/auth/callback/oidc'],
  claims_policy: { claims: ['roles', 'groups', 'org'] },
  launch: { url: 'https://hub.example/api/auth/signin/oidc', icon: 'grid', description: 'The certification hub.', visibility: 'open' },
}
const CONE_RP = {
  client_id: 'fixture-rp-cone',
  name: 'The cone-gated fixture RP',
  secret: 'fixture-rp-cone-secret',
  redirect_uris: ['https://rp-cone.example/callback'],
  claims_policy: { claims: ['roles', 'groups', 'org', 'cone'] },
}

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
      OP_CLIENT_SEED: JSON.stringify([PLAIN_RP, CONE_RP]),
    }, logs)
    const apiBase = `http://localhost:${ID_API}`
    await waitForHttp(`${apiBase}/api/health`, 120_000, logs)

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

/** The OIDC round trip (authorize → consent → decide → exchange →
 *  userinfo) against the named client; answers the ID token's payload +
 *  userinfo (the cone claim's presence/absence is the assertion). */
async function roundTrip(apiBase: string, cookie: string, client: { client_id: string; secret: string; redirect_uris: string[] }): Promise<{ idToken: Record<string, unknown>; userinfo: Record<string, unknown> }> {
  const verifier = 'id20-verifier-09c0n3s1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d'
  const challenge = Buffer.from(
    await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier)),
  ).toString('base64url')
  const authorize = await fetch(`${apiBase}/op/authorize?${new URLSearchParams({
    response_type: 'code', client_id: client.client_id, redirect_uri: client.redirect_uris[0]!,
    scope: 'openid profile email', state: 'st', nonce: 'nn',
    code_challenge: challenge, code_challenge_method: 'S256',
    // The consent stop is this helper's contract (TODO.identity-features/12:
    // a remembered grant would skip it when an account+client repeats).
    prompt: 'consent',
  })}`, { headers: { cookie }, redirect: 'manual' })
  expect(authorize.status, 'authorize redirects to consent').toBe(302)
  const authId = new URL(authorize.headers.get('location')!, apiBase).searchParams.get('auth')!
  const decide = await fetch(`${apiBase}/api/op/consent/${authId}/decide`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', cookie },
    body: JSON.stringify({ decision: 'allow' }),
  })
  expect(decide.status, 'the consent decision records').toBe(200)
  const { redirect } = await decide.json() as { redirect: string }
  const code = new URL(redirect).searchParams.get('code')!
  const exchange = await fetch(`${apiBase}/op/token`, {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      authorization: `Basic ${btoa(`${encodeURIComponent(client.client_id)}:${encodeURIComponent(client.secret)}`)}`,
    },
    body: new URLSearchParams({
      grant_type: 'authorization_code', code, redirect_uri: client.redirect_uris[0]!,
      client_id: client.client_id, code_verifier: verifier,
    }),
  })
  expect(exchange.status, 'the code exchange answers').toBe(200)
  const tokens = await exchange.json() as { access_token: string; id_token: string }
  const userinfoRes = await fetch(`${apiBase}/op/userinfo`, { headers: { authorization: `Bearer ${tokens.access_token}` } })
  expect(userinfoRes.status, 'userinfo answers').toBe(200)
  return {
    idToken: JSON.parse(Buffer.from(tokens.id_token.split('.')[1]!, 'base64url').toString('utf-8')) as Record<string, unknown>,
    userinfo: await userinfoRes.json() as Record<string, unknown>,
  }
}

describe('TODO.identity-features/09 — the org-member cone (wave A, the identity arc)', () => {
  let stack: Stack
  let browser: Browser | undefined
  let memberId = ''

  beforeAll(async () => {
    stack = await bootIdentityStack()
  }, 420_000)

  afterAll(async () => {
    await closeBrowser(browser)
    await stopStack(stack)
  })

  it('the full arc: the picker sets the cone, the claims carry it, the audit chain records every act', { timeout: 900_000 }, async () => {
    const { apiBase, base } = stack

    // ── the setup: the org admin invites the member; the holder accepts ──
    const adminCookie = await apiSignIn(apiBase, ORG_ADMIN)
    const memberCookie = await apiSignIn(apiBase, MEMBER)
    const invite = await fetch(`${apiBase}/api/op/org-memberships`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: adminCookie },
      body: JSON.stringify({ email: MEMBER, roles: [] }),
    })
    expect(invite.status, 'the invite lands').toBe(201)
    const invited = await invite.json() as { userId: string }
    memberId = invited.userId
    const accept = await fetch(`${apiBase}/api/op/account/memberships/${ORG}/accept`, {
      method: 'POST', headers: { cookie: memberCookie },
    })
    expect(accept.status, 'the holder accepts').toBe(200)

    // The switch into the org's context: the member acts AS mfr-acme.
    const switchRes = await fetch(`${apiBase}/api/op/account/active-org`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: memberCookie },
      body: JSON.stringify({ org_id: ORG }),
    })
    expect(switchRes.status, 'the context switch').toBe(200)

    // ── leg 1: THE CONSOLE — the badge, the picker, the save ──
    browser = await puppeteer.launch({ headless: true, args: ['--no-sandbox', '--disable-dev-shm-usage'] })
    const page = await browser.newPage()
    await page.goto(`${base}/`, { waitUntil: 'domcontentloaded', timeout: 60_000 })
    await opSignIn(page, ORG_ADMIN)
    await page.waitForFunction(() => window.location.pathname !== '/', { timeout: SETTLE, polling: 500 })
    await page.goto(`${base}/op/admin/users`, { waitUntil: 'domcontentloaded', timeout: 60_000 })
    await page.waitForSelector(`[data-testid="org-user-${memberId}"]`, { timeout: SETTLE, polling: 500 })

    // The silent default: the badge reads org-wide.
    const badgeBefore = await page.$eval(`[data-testid="org-user-cone-${memberId}"]`, el => el.textContent?.trim() ?? '')
    expect(badgeBefore).toBe('org-wide')

    // The picker: the three postures with the plain-language implications.
    await page.evaluate(id => (document.querySelector(`[data-testid="org-user-cone-edit-${id}"]`) as HTMLElement).click(), memberId)
    await page.waitForSelector(`[data-testid="org-user-cone-editor-${memberId}"]`, { timeout: SETTLE, polling: 500 })
    const editorText = await page.$eval(`[data-testid="org-user-cone-editor-${memberId}"]`, el => el.textContent ?? '')
    expect(editorText).toContain('Org-wide (the default)')
    expect(editorText).toContain('Assigned only')
    expect(editorText).toContain('the work that names them')
    expect(editorText).toContain('Read-only')
    expect(editorText).toContain('every write is refused')

    // The save: assigned.
    await page.evaluate(id => (document.querySelector(`[data-testid="org-user-cone-opt-${id}-assigned"]`) as HTMLElement).click(), memberId)
    await page.evaluate(id => (document.querySelector(`[data-testid="org-user-cone-save-${id}"]`) as HTMLElement).click(), memberId)
    await page.waitForFunction(
      id => document.querySelector(`[data-testid="org-user-cone-${id}"]`)?.textContent?.trim() === 'assigned',
      { timeout: SETTLE, polling: 500 },
      memberId,
    )

    // The org's activity panel carries the cone act (the same slice the
    // API answers — leg 3 asserts its content).
    await page.waitForSelector('[data-testid="org-activity-list"]', { timeout: SETTLE, polling: 500 })
    const activityText = await page.$eval('[data-testid="org-activity-list"]', el => el.textContent ?? '')
    expect(activityText).toContain('data cone')

    // ── leg 2: THE CLAIMS — the gated client learns the posture; the
    //    plain client never does ──
    const gated = await roundTrip(apiBase, memberCookie, CONE_RP)
    expect(gated.idToken.org).toBe(ORG)
    expect(gated.idToken.cone).toBe('assigned')
    expect(gated.userinfo.cone).toBe('assigned')
    const plain = await roundTrip(apiBase, memberCookie, PLAIN_RP)
    expect(plain.idToken.org).toBe(ORG)
    expect(plain.idToken.cone).toBeUndefined()
    expect(plain.userinfo.cone).toBeUndefined()

    // ── leg 3: THE AUDIT CHAIN — every act recorded, the slice gated ──
    const sliceRes = await fetch(`${apiBase}/api/op/org-memberships/activity`, { headers: { cookie: adminCookie } })
    expect(sliceRes.status, "the org admin's slice answers").toBe(200)
    const slice = await sliceRes.json() as { activity: Array<{ action: string; entity_id: string; metadata?: Record<string, unknown> }> }
    const coneActs = slice.activity.filter(e => e.action === 'membership.cone' && e.entity_id === memberId)
    expect(coneActs.length).toBe(1)
    expect(coneActs[0]!.metadata).toMatchObject({ cone: 'assigned', previous: 'org-wide', org_id: ORG })
    // …the invite + the acceptance are on the same slice (the arc's full record)
    expect(slice.activity.some(e => e.action === 'membership.invited' && e.entity_id === memberId)).toBe(true)

    // The grantless member never reads the slice…
    const refused = await fetch(`${apiBase}/api/op/org-memberships/activity`, { headers: { cookie: memberCookie } })
    expect(refused.status).toBe(403)
    // …and the identity admin's per-org view shows the cone honestly.
    const wideCookie = await apiSignIn(apiBase, 'admin@oiml.org')
    const view = await (await fetch(`${apiBase}/api/op/registry/orgs/${ORG}`, { headers: { cookie: wideCookie } })).json() as {
      members: Array<{ userId: string; cone: { scope: string; readOnly: boolean } }>
    }
    expect(view.members.find(m => m.userId === memberId)?.cone).toEqual({ scope: 'assigned', readOnly: false })

    // ── the restore: the org-wide default through the API (the stack
    //    dies with the suite; the arc leaves the posture it found) ──
    const restore = await fetch(`${apiBase}/api/op/org-memberships/${memberId}/${ORG}/cone`, {
      method: 'PUT',
      headers: { 'content-type': 'application/json', cookie: adminCookie },
      body: JSON.stringify({ cone: 'org-wide' }),
    })
    expect(restore.status).toBe(200)
    const restored = await roundTrip(apiBase, memberCookie, CONE_RP)
    expect(restored.idToken.cone).toBe('org-wide')
  })
})
