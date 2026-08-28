// ═══════════════════════════════════════════════════════════════════
// TODO.identity-features/10 — the OIML Member category (the taxonomy
// correction), the e2e: the identity-profile stack (its own API + its
// own astro, the id-13/id-17 spawned-stack pattern), the full arc for
// real on the seeded demo cast (which now authors the LAYERED member):
//
//   leg 1  the PUBLIC join page offers the OIML MEMBER orgs (the member
//          state + the corresponding member, labeled honestly — never a
//          conflation with a utilizer), and a member state's personnel
//          files for the read/access role against their member org (the
//          role selector carries ONLY the viewer — the workflow-role
//          refusal is proven fetch-level);
//   leg 2  the admin approves; the member's personnel completes the
//          enrollment and the account console carries the membership
//          (the read/access posture, the estate's services reached);
//   leg 3  the console renders the designation chain HONESTLY both
//          directions: the layered member's page ("OIML Member —
//          Member State"; proposes EX1, designates ut-emsa), the IA's
//          page (proposed by the member state; the associated TL), the
//          utilizer's page (designated by the member state; the CS
//          status "Declaration signed — active"), and the
//          corresponding member's page (designates the associate);
//   leg 4  the designation ACT through the console's edit form (the
//          rule-bound selector lists only the member states for a
//          utilizer) + the wrong-kind refusal (fetch-level: a
//          utilizer's designator is never a corresponding member);
//   leg 5  the LEGACY utilizer row (no designation recorded — the
//          pre-0019 shape) reads correctly post-migration: the kind +
//          the participant standing intact, "not recorded" for the
//          link, and the join selector still offers it.
//
// SELF-CONTAINED: the suite's shared stack (E2E_BASE_URL) is untouched —
// the identity instance boots on its own ports (API 10599 / astro
// 10600) with its own SQLite file, above every live leg (id-20 rides
// 10597/10598).
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
const DB_DIR = join(BROWSER_DIR, '.cache', 'id-21')

// Port-isolated: above every declared e2e stack (3190..10600 range —
// id-20 holds 10597/10598) and the local dev loops.
const ID_API = 10599
const ID_WEB = 10600

// The cast: the seeded LAYERED member (ms-example with its IA EX1 + its
// TL 21 + its designated utilizer ut-emsa), the corresponding member
// (cm-demo with its associate as-demo), the member state's NEW
// personnel, the legacy-shaped utilizer (created link-less on the admin
// API — the pre-0019 row's shape), and the estate admin.
const MEMBER_PERSONNEL_EMAIL = 'ingrid.halvorsen@emb.example.org'
const MEMBER_PERSONNEL_PASSWORD = 'ingrid halvorsen member passphrase'
const LEGACY_UTILIZER_ID = 'ut-legacy'
const ADMIN_EMAIL = 'admin@oiml.org'

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

/** Boot the identity-profile stack (the id-13/id-17 posture). */
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
    // OIDC_* scrubbed + the demo override ON (the id-08 discipline).
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

    // Provision the profile's seed (the demo cast + the registry — the
    // org registry carries the layered member: ms-example with its IA +
    // its designated utilizer, ms-nl, cm-demo with its associate).
    const reset = await fetch(`${apiBase}/api/dev-reset`, { method: 'POST' })
    if (!reset.ok) throw new Error(`dev-reset on ${apiBase} answered ${reset.status}\n${logs.join('').slice(-2000)}`)

    // The spawned vite gets a PRIVATE cache seeded from the worktree's
    // warm one (the fed-01 lesson).
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
    // Gate on a routed page (the fed-01 stall class).
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

/** The console's one-time setup link for the last issued invite. */
async function readSetupUrl(page: Page): Promise<string> {
  await page.waitForSelector('[data-testid="invite-setup-url"]', { timeout: SETTLE, polling: 500 })
  return (await page.$eval('[data-testid="invite-setup-url"]', el => el.textContent ?? '')).trim()
}

/** Drive 02's setup page: the one-time link sets the password and signs
 *  the account in (lands on /op/account). */
async function driveSetup(page: Page, setupUrl: string, password: string, expectEmail: string): Promise<void> {
  await page.goto(setupUrl, { waitUntil: 'domcontentloaded', timeout: SETTLE })
  await page.waitForSelector('[data-testid="op-setup-account"]', { timeout: SETTLE, polling: 500 })
  const who = await page.$eval('[data-testid="op-setup-account"]', el => el.textContent ?? '')
  expect(who).toContain(expectEmail)
  await page.type('[data-testid="op-setup-password"]', password)
  await page.type('[data-testid="op-setup-confirm"]', password)
  await page.evaluate(() => (document.querySelector('[data-testid="op-setup-submit"]') as HTMLElement).click())
  await page.waitForFunction(() => window.location.pathname === '/op/account', { timeout: SETTLE, polling: 500 })
}

/** Drop the session (the cookie is httpOnly), then settle on the
 *  sign-in page (the id-10 race guard). */
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

/** A fetch-level demo sign-in against the stack. */
async function apiSignIn(apiBase: string, email: string): Promise<string> {
  const login = await fetch(`${apiBase}/api/auth/demo`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password: 'demo2026' }),
  })
  expect(login.ok, `demo sign-in ${email}`).toBe(true)
  return (login.headers.get('set-cookie') ?? '').split(';')[0]!
}

describe('TODO.identity-features/10 — the OIML Member category (the identity profile)', () => {
  let stack: Stack
  let browser: Browser
  let page: Page

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

  it('leg 1 — the join page offers the OIML MEMBER orgs honestly; the member’s personnel file for the read/access role', { timeout: 900_000 }, async () => {
    await page.goto(`${stack.base}/op/join`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await page.waitForSelector('[data-testid="op-join"]', { timeout: SETTLE, polling: 500 })

    // The selector carries the member state + the corresponding member,
    // LABELED as the category — never a conflation with a utilizer.
    await page.waitForSelector('[data-testid="join-org-option-ms-example"]', { timeout: SETTLE, polling: 500 })
    const memberOption = await page.$eval('[data-testid="join-org-option-ms-example"]', el => el.textContent ?? '')
    expect(memberOption).toContain('OIML Member — Member State')
    const cmOption = await page.$eval('[data-testid="join-org-option-cm-demo"]', el => el.textContent ?? '')
    expect(cmOption).toContain('OIML Member — Corresponding Member')
    // …the participants ride as before, and the disabled/mid-pipeline IA
    // never appears (the honesty the feed always had).
    await page.waitForSelector('[data-testid="join-org-option-EX1"]', { timeout: SETTLE, polling: 500 })
    expect(await page.$('[data-testid="join-org-option-XX1"]')).toBeNull()

    // The member state's personnel file against their member org.
    await page.type('[data-testid="join-name"]', 'Ms. Ingrid Halvorsen')
    await page.type('[data-testid="join-email"]', MEMBER_PERSONNEL_EMAIL)
    await page.evaluate(() => (document.querySelector('[data-testid="join-org-option-ms-example"]') as HTMLElement).click())
    // The role selector carries ONLY the read/access posture (the member
    // kinds never bound a workflow role).
    await page.waitForSelector('[data-testid="join-role"]', { timeout: SETTLE, polling: 500 })
    await page.waitForSelector('[data-testid="join-role-option-viewer"]', { timeout: SETTLE, polling: 500 })
    expect(await page.$('[data-testid="join-role-option-ia_officer"]')).toBeNull()
    await page.select('[data-testid="join-role"]', 'viewer')
    await page.evaluate(() => (document.querySelector('[data-testid="join-submit"]') as HTMLElement).click())
    await page.waitForSelector('[data-testid="join-success"]', { timeout: SETTLE, polling: 500 })

    // The workflow-role ask refuses at the server (the page never offers
    // it; the API re-checks).
    const refused = await fetch(`${stack.apiBase}/api/op/join-requests`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ name: 'Ambitious', email: 'ambitious@emb.example.org', org_id: 'ms-example', requested_role: 'ia_officer' }),
    })
    expect(refused.status).toBe(400)
    expect(((await refused.json()) as { error: string }).error).toContain('member-state')
  })

  it('leg 2 — the admin approves; the member’s personnel enroll and the account console carries the membership', { timeout: 900_000 }, async () => {
    await page.goto(`${stack.base}/`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await opSignIn(page, ADMIN_EMAIL)
    await page.waitForFunction(() => window.location.pathname !== '/', { timeout: SETTLE, polling: 500 })

    await page.goto(`${stack.base}/op/admin/users`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await page.waitForFunction((email) => {
      return [...document.querySelectorAll('[data-testid^="join-request-"]')]
        .some(e => e.textContent?.includes(email))
    }, { timeout: SETTLE, polling: 500 }, MEMBER_PERSONNEL_EMAIL)
    const requestId = await page.evaluate((needle) => {
      const el = [...document.querySelectorAll('[data-testid^="join-request-"]')]
        .find(e => e.getAttribute('data-testid')?.startsWith('join-request-kind-') === false && e.textContent?.includes(needle))
      return el?.getAttribute('data-testid')?.replace('join-request-', '') ?? null
    }, MEMBER_PERSONNEL_EMAIL)
    expect(requestId).toBeTruthy()
    await page.evaluate((id) => (document.querySelector(`[data-testid="join-approve-${id}"]`) as HTMLElement).click(), requestId)
    const setupUrl = await readSetupUrl(page)
    expect(setupUrl).toContain('/op/setup?token=')

    // The member's personnel complete the enrollment; the account
    // console carries the membership with the read/access role.
    await driveSetup(page, setupUrl, MEMBER_PERSONNEL_PASSWORD, MEMBER_PERSONNEL_EMAIL)
    await page.goto(`${stack.base}/op/account`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await page.waitForSelector('[data-testid="account-org-ms-example"]', { timeout: SETTLE, polling: 500 })
    const roles = await page.$eval('[data-testid="account-org-roles-ms-example"]', el => el.textContent ?? '')
    expect(roles).toContain('viewer')
    expect(roles).not.toContain('ia_officer')
  })

  it('leg 3 — the console renders the designation chain honestly, both directions', { timeout: 900_000 }, async () => {
    await signOut(page)
    await page.goto(`${stack.base}/`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await opSignIn(page, ADMIN_EMAIL)
    await page.waitForFunction(() => window.location.pathname !== '/', { timeout: SETTLE, polling: 500 })

    // The layered member's page: the category's kind label, the member
    // standing, "proposes: the IA", "designates: the utilizer".
    await page.goto(`${stack.base}/op/admin/registry/orgs/ms-example`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await page.waitForSelector('[data-testid="op-reg-org-kind"]', { timeout: SETTLE, polling: 500 })
    expect(await page.$eval('[data-testid="op-reg-org-kind"]', el => el.textContent ?? '')).toContain('OIML Member — Member State')
    expect(await page.$eval('[data-testid="op-reg-org-standing"]', el => el.textContent ?? '')).toContain('OIML Member')
    await page.waitForSelector('[data-testid="op-reg-org-chain"]', { timeout: SETTLE, polling: 500 })
    expect(await page.$eval('[data-testid="op-reg-org-chain-proposes"]', el => el.textContent ?? '')).toContain('Example Issuing Authority')
    const designates = await page.$eval('[data-testid="op-reg-org-chain-designates"]', el => el.textContent ?? '')
    expect(designates).toContain('Example Market Surveillance Authority')
    expect(designates).toContain('utilizer')

    // The IA's page: proposed by the member state; the associated TL.
    await page.goto(`${stack.base}/op/admin/registry/orgs/EX1`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await page.waitForSelector('[data-testid="op-reg-org-proposed-by"]', { timeout: SETTLE, polling: 500 })
    expect(await page.$eval('[data-testid="op-reg-org-proposed-by"]', el => el.textContent ?? '')).toContain('Example Member Body')
    await page.waitForSelector('[data-testid="op-reg-org-chain-tls"]', { timeout: SETTLE, polling: 500 })
    expect(await page.$eval('[data-testid="op-reg-org-chain-tls"]', el => el.textContent ?? '')).toContain('Example Test Laboratory')

    // The utilizer's page: designated by the member state; the CS
    // status facet reads the Declaration's standing.
    await page.goto(`${stack.base}/op/admin/registry/orgs/ut-emsa`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await page.waitForSelector('[data-testid="op-reg-org-designated-by"]', { timeout: SETTLE, polling: 500 })
    expect(await page.$eval('[data-testid="op-reg-org-designated-by"]', el => el.textContent ?? '')).toContain('Example Member Body')
    expect(await page.$eval('[data-testid="op-reg-org-cs-status"]', el => el.textContent ?? '')).toContain('Declaration signed — active')

    // The corresponding member's page: designates the associate.
    await page.goto(`${stack.base}/op/admin/registry/orgs/cm-demo`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await page.waitForSelector('[data-testid="op-reg-org-chain-designates"]', { timeout: SETTLE, polling: 500 })
    const cmDesignates = await page.$eval('[data-testid="op-reg-org-chain-designates"]', el => el.textContent ?? '')
    expect(cmDesignates).toContain('Demo Inspection Body')
    expect(cmDesignates).toContain('associate')

    // The list rows carry the chain's shape.
    await page.goto(`${stack.base}/op/admin/organizations`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await page.waitForSelector('[data-testid="op-orgs-row-ms-example"]', { timeout: SETTLE, polling: 500 })
    const memberLine = await page.$eval('[data-testid="op-orgs-kind-ms-example"]', el => el.textContent ?? '')
    expect(memberLine).toContain('member-state')
    expect(memberLine).toContain('proposes 1')
    expect(memberLine).toContain('designates 1')
  })

  it('leg 4 — the designation act through the console (the rule-bound selector) + the wrong-kind refusal', { timeout: 900_000 }, async () => {
    const admin = await apiSignIn(stack.apiBase, ADMIN_EMAIL)
    // A fresh utilizer row, designated at creation under the second
    // member state (the add act's link validation).
    const created = await fetch(`${stack.apiBase}/api/op/registry/orgs`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: admin },
      body: JSON.stringify({ id: 'ut-new', name: 'Newly Designated Utilizer', kind: 'utilizer', country: 'Netherlands', designated_by: 'ms-nl', cs_status: 'signed-active' }),
    })
    expect(created.status).toBe(201)

    // The console's edit form: the designator selector lists ONLY the
    // member states (the rule's eligible targets); re-designating to the
    // layered member lands.
    await page.goto(`${stack.base}/op/admin/registry/orgs/ut-new`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await page.waitForSelector('[data-testid="op-reg-org-designated-by"]', { timeout: SETTLE, polling: 500 })
    expect(await page.$eval('[data-testid="op-reg-org-designated-by"]', el => el.textContent ?? '')).toContain('Member Body of the Netherlands')
    await page.evaluate(() => (document.querySelector('[data-testid="op-reg-org-edit"]') as HTMLElement).click())
    await page.waitForSelector('[data-testid="op-reg-org-edit-designated-by"]', { timeout: SETTLE, polling: 500 })
    const options = await page.$$eval('[data-testid="op-reg-org-edit-designated-by"] option', els => els.map(el => ({ value: (el as HTMLOptionElement).value, text: el.textContent ?? '' })))
    expect(options.map(o => o.value)).toEqual(expect.arrayContaining(['', 'ms-example', 'ms-nl']))
    expect(options.map(o => o.value)).not.toContain('cm-demo') // a utilizer's designator is never a corresponding member
    expect(options.map(o => o.value)).not.toContain('EX1')
    await page.select('[data-testid="op-reg-org-edit-designated-by"]', 'ms-example')
    await page.evaluate(() => (document.querySelector('[data-testid="op-reg-org-edit-save"]') as HTMLElement).click())
    await page.waitForFunction(
      () => document.querySelector('[data-testid="op-reg-org-designated-by"]')?.textContent?.includes('Example Member Body') ?? false,
      { timeout: SETTLE, polling: 500 },
    )

    // The wrong-kind designation refuses honestly (fetch-level — the
    // server re-checks what the form never offers).
    const refused = await fetch(`${stack.apiBase}/api/op/registry/orgs/ut-new`, {
      method: 'PUT',
      headers: { 'content-type': 'application/json', cookie: admin },
      body: JSON.stringify({ designated_by: 'cm-demo' }),
    })
    expect(refused.status).toBe(400)
    expect(((await refused.json()) as { error: string }).error).toContain('must be a member-state organization')
    // …and the row keeps its honest link.
    const after = await (await fetch(`${stack.apiBase}/api/op/registry/orgs/ut-new`, { headers: { cookie: admin } })).json() as { org: { designatedBy: string } }
    expect(after.org.designatedBy).toBe('ms-example')
  })

  it('leg 5 — the LEGACY utilizer row (no designation recorded) reads correctly post-migration', { timeout: 900_000 }, async () => {
    const admin = await apiSignIn(stack.apiBase, ADMIN_EMAIL)
    // The legacy shape: a utilizer row as the pre-0019 registry carried
    // it — the kind, never the links.
    const created = await fetch(`${stack.apiBase}/api/op/registry/orgs`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: admin },
      body: JSON.stringify({ id: LEGACY_UTILIZER_ID, name: 'Legacy Utilizer (pre-0019)', kind: 'utilizer', country: 'Legacy Member State' }),
    })
    expect(created.status).toBe(201)

    // The console reads it honestly: the kind + the participant standing
    // intact, the designation "not recorded", the CS status "not
    // recorded" — never a conflation with a member, never a crash.
    await page.goto(`${stack.base}/op/admin/registry/orgs/${LEGACY_UTILIZER_ID}`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await page.waitForSelector('[data-testid="op-reg-org-designated-by"]', { timeout: SETTLE, polling: 500 })
    expect(await page.$eval('[data-testid="op-reg-org-kind"]', el => el.textContent ?? '')).toContain('utilizer')
    expect(await page.$eval('[data-testid="op-reg-org-standing"]', el => el.textContent ?? '')).toContain('OIML-CS participant')
    expect(await page.$eval('[data-testid="op-reg-org-designated-by"]', el => el.textContent ?? '')).toContain('not recorded')
    expect(await page.$eval('[data-testid="op-reg-org-cs-status"]', el => el.textContent ?? '')).toContain('not recorded')

    // …and the join selector still offers it (a designation never
    // recorded is not a deregistration).
    const feed = await (await fetch(`${stack.apiBase}/api/op/organizations`)).json() as Array<{ id: string }>
    expect(feed.map(o => o.id)).toContain(LEGACY_UTILIZER_ID)
  })
})
