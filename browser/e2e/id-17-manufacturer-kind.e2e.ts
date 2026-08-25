// ═══════════════════════════════════════════════════════════════════
// TODO.register/01 — the manufacturer org kind, the e2e: the
// identity-profile stack (its own API + its own astro, the id-13
// spawned-stack pattern), the full arc for real:
//
//   leg 1  the PUBLIC join page's manufacturer path: "my organization
//          manufactures measuring instruments" — the founder files, the
//          org is CREATED with the declared standing (the honest success
//          copy says so), and the registry carries the row (kind
//          manufacturer, standing declared — NEVER the participant
//          posture);
//   leg 2  the estate admin sees the honest standing BEFORE any
//          decision: the Organizations list row, the per-org page's
//          Standing line, and the decision queue's manufacturer chip;
//          then approves the founder's org_admin ask (the invite shows
//          its one-time setup link);
//   leg 3  the founder completes the enrollment and lands on the
//          account console — the manufacturer membership shows with the
//          org_admin role;
//   leg 4  the colleague's ask with the matching email domain JOINS the
//          same org (the member's applicant role); the founder's own
//          org queue carries it (the kind honest) and the founder
//          decides it;
//   leg 5  the IA endorses (fetch-level, the demo cast's ia@oiml.org
//          acting as EX1): the standing upgrades declared → ia-endorsed;
//   leg 6  the admin surfaces render the upgrade honestly (the per-org
//          page's Standing + the endorsement row naming the IA, the
//          list row's IA-endorsed mark) and the AUDIT CHAIN carries
//          every act of the arc (the self-registered add, both
//          approvals, the endorsement);
//   leg 7  the honest negatives: the manufacturer's own people hold no
//          endorsement grant (403), the duplicate endorsement is the
//          409, and the demo cast's mfr-acme row resolves as the
//          manufacturer kind (the platform's sample id on the OP).
//
// SELF-CONTAINED: the suite's shared stack (E2E_BASE_URL) is untouched —
// the identity instance boots on its own ports (API 10493 / astro 10494)
// with its own SQLite file.
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
const DB_DIR = join(BROWSER_DIR, '.cache', 'id-17')

// Port-isolated: clear of every declared e2e stack (3190..10395, 19894)
// and the local dev loops.
const ID_API = 10493
const ID_WEB = 10494

// The cast: the NEW manufacturer org (the ACME cast — never a real
// organization), its founder + colleague, the estate admin, and the
// demo IA officer (ia@oiml.org acts as EX1, the seeded active IA).
const MFR_ID = 'mfr-acme-instruments'
const MFR_NAME = 'ACME Instruments'
const FOUNDER_EMAIL = 'sofia.mercer@acme-instruments.example.org'
const FOUNDER_PASSWORD = 'sofia mercer founder passphrase'
const COLLEAGUE_EMAIL = 'theo.bench@acme-instruments.example.org'
const ADMIN_EMAIL = 'admin@oiml.org'
const IA_EMAIL = 'ia@oiml.org'

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

/** Boot the identity-profile stack (the id-13 posture). */
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

    // Provision the profile's seed (the demo cast + the registry — the
    // org registry carries mfr-acme with the manufacturer kind).
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
 *  string — the endorsement acts never need a browser). */
async function apiSignIn(apiBase: string, email: string): Promise<string> {
  const login = await fetch(`${apiBase}/api/auth/demo`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password: 'demo2026' }),
  })
  expect(login.ok, `demo sign-in ${email}`).toBe(true)
  return (login.headers.get('set-cookie') ?? '').split(';')[0]!
}

/** The join-request row id for an email on the CURRENT page (the
 *  console's queue), null when absent. */
async function requestIdFor(page: Page, email: string): Promise<string | null> {
  return page.evaluate((needle) => {
    const el = [...document.querySelectorAll('[data-testid^="join-request-"]')]
      .find(e => e.getAttribute('data-testid')?.startsWith('join-request-kind-') === false && e.textContent?.includes(needle))
    return el?.getAttribute('data-testid')?.replace('join-request-', '') ?? null
  }, email)
}

describe('TODO.register/01 — the manufacturer org kind (the identity profile)', () => {
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

  it('leg 1 — the public join page’s manufacturer path files the self-registration; the org is created with the declared standing', { timeout: 900_000 }, async () => {
    await page.goto(`${stack.base}/op/join`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await page.waitForSelector('[data-testid="op-join"]', { timeout: SETTLE, polling: 500 })
    await page.waitForSelector('[data-testid="join-manufacturer"]', { timeout: SETTLE, polling: 500 })

    await page.type('[data-testid="join-name"]', 'Dr. Sofia Mercer')
    await page.type('[data-testid="join-email"]', FOUNDER_EMAIL)
    await page.evaluate(() => (document.querySelector('[data-testid="join-manufacturer"]') as HTMLElement).click())
    await page.waitForSelector('[data-testid="join-mfr-name"]', { timeout: SETTLE, polling: 500 })
    // The honest framing: the declared standing, never a participation.
    const note = await page.$eval('[data-testid="join-mfr-note"]', el => el.textContent ?? '')
    expect(note).toContain('not an OIML-CS participant')
    await page.type('[data-testid="join-mfr-name"]', MFR_NAME)
    await page.type('[data-testid="join-mfr-country"]', 'Example Member State')
    await page.evaluate(() => (document.querySelector('[data-testid="join-submit"]') as HTMLElement).click())

    await page.waitForSelector('[data-testid="join-success-manufacturer-created"]', { timeout: SETTLE, polling: 500 })
    const success = await page.$eval('[data-testid="join-success"]', el => el.textContent ?? '')
    expect(success).toContain(MFR_NAME)
    expect(success).toContain('declared')

    // The registry row IS the self-registration (fetch-level, the admin's
    // read): the manufacturer kind, the declared standing, NEVER the
    // participant posture.
    const admin = await apiSignIn(stack.apiBase, ADMIN_EMAIL)
    const orgs = await (await fetch(`${stack.apiBase}/api/op/registry/orgs`, { headers: { cookie: admin } })).json() as Array<Record<string, unknown>>
    const row = orgs.find(o => o.id === MFR_ID)!
    expect(row).toBeTruthy()
    expect(row.kind).toBe('manufacturer')
    expect(row.standing).toBe('declared')
    expect(row.endorsedBy).toEqual([])
    // …and the public selector feed never offers it (the intake stays the
    // scheme's participation flow).
    const feed = await (await fetch(`${stack.apiBase}/api/op/organizations`)).json() as Array<{ id: string }>
    expect(feed.map(o => o.id)).not.toContain(MFR_ID)
  })

  it('leg 2 — the estate admin sees the honest standing, then approves the founder’s org_admin ask', { timeout: 900_000 }, async () => {
    await page.goto(`${stack.base}/`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await opSignIn(page, ADMIN_EMAIL)
    await page.waitForFunction(() => window.location.pathname !== '/', { timeout: SETTLE, polling: 500 })

    // The Organizations list: the row says what it is (manufacturer ·
    // declared standing), next to the demo cast's own manufacturer row.
    await page.goto(`${stack.base}/op/admin/organizations`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await page.waitForSelector(`[data-testid="op-orgs-row-${MFR_ID}"]`, { timeout: SETTLE, polling: 500 })
    const kindLine = await page.$eval(`[data-testid="op-orgs-kind-${MFR_ID}"]`, el => el.textContent ?? '')
    expect(kindLine).toContain('manufacturer')
    expect(kindLine).toContain('declared standing')
    const demoRow = await page.$eval('[data-testid="op-orgs-kind-mfr-acme"]', el => el.textContent ?? '')
    expect(demoRow).toContain('manufacturer')

    // The per-org page: the Standing line is the honest declared text.
    await page.goto(`${stack.base}/op/admin/registry/orgs/${MFR_ID}`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await page.waitForSelector('[data-testid="op-reg-org-standing"]', { timeout: SETTLE, polling: 500 })
    const standing = await page.$eval('[data-testid="op-reg-org-standing"]', el => el.textContent ?? '')
    expect(standing).toContain('Declared manufacturer')
    expect(standing).toContain('NOT an OIML-CS participant')
    // The endorsements section stands empty, honestly.
    await page.waitForSelector('[data-testid="op-reg-org-endorsements-empty"]', { timeout: SETTLE, polling: 500 })

    // The decision queue: the founder's ask shows the manufacturer chip
    // (a manufacturer join request is not a participant application).
    await page.goto(`${stack.base}/op/admin/users`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await page.waitForFunction((email) => {
      return [...document.querySelectorAll('[data-testid^="join-request-"]')]
        .some(e => e.textContent?.includes(email))
    }, { timeout: SETTLE, polling: 500 }, FOUNDER_EMAIL)
    const requestId = await requestIdFor(page, FOUNDER_EMAIL)
    expect(requestId).toBeTruthy()
    const chip = await page.$(`[data-testid="join-request-kind-${requestId}"]`)
    expect(chip).not.toBeNull()
    expect(await chip!.evaluate(el => el.textContent ?? '')).toContain('not an OIML-CS participant')

    // Approve: the invite issues (the one-time setup link shows once).
    await page.evaluate((id) => (document.querySelector(`[data-testid="join-approve-${id}"]`) as HTMLElement).click(), requestId)
    const setupUrl = await readSetupUrl(page)
    expect(setupUrl).toContain('/op/setup?token=')

    // The founder completes the enrollment into the account console…
    await driveSetup(page, setupUrl, FOUNDER_PASSWORD, FOUNDER_EMAIL)
    // (leg 3 continues from the signed-in founder.)
  })

  it('leg 3 — the founder’s console shows the manufacturer membership with the org_admin role', { timeout: 900_000 }, async () => {
    await page.goto(`${stack.base}/op/account`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await page.waitForSelector(`[data-testid="account-org-${MFR_ID}"]`, { timeout: SETTLE, polling: 500 })
    const roles = await page.$eval(`[data-testid="account-org-roles-${MFR_ID}"]`, el => el.textContent ?? '')
    expect(roles).toContain('org_admin')
  })

  it('leg 4 — the colleague’s matching-domain ask JOINS the same org (the applicant role); the founder decides it', { timeout: 900_000 }, async () => {
    // The colleague files through the manufacturer path (fetch-level —
    // the public intake; the typed name even differs in case).
    const filed = await fetch(`${stack.apiBase}/api/op/join-requests`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        name: 'Theo Bench', email: COLLEAGUE_EMAIL,
        org_kind: 'manufacturer', org_name_text: 'Acme Instruments',
      }),
    })
    expect(filed.status).toBe(201)
    const created = await filed.json() as { orgId: string; requestedRole: string; organization: { id: string; created: boolean } }
    expect(created.orgId).toBe(MFR_ID)
    expect(created.requestedRole).toBe('applicant')
    expect(created.organization).toEqual({ id: MFR_ID, name: MFR_NAME, created: false })

    // The founder (still signed in from leg 3) sees the ask in HER org's
    // queue — the kind honest — and approves it.
    await page.goto(`${stack.base}/op/admin/users`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await page.waitForFunction((email) => {
      return [...document.querySelectorAll('[data-testid^="join-request-"]')]
        .some(e => e.textContent?.includes(email))
    }, { timeout: SETTLE, polling: 500 }, COLLEAGUE_EMAIL)
    const requestId = await requestIdFor(page, COLLEAGUE_EMAIL)
    expect(requestId).toBeTruthy()
    expect(await page.$(`[data-testid="join-request-kind-${requestId}"]`)).not.toBeNull()
    await page.evaluate((id) => (document.querySelector(`[data-testid="join-approve-${id}"]`) as HTMLElement).click(), requestId)
    const setupUrl = await readSetupUrl(page)
    expect(setupUrl).toContain('/op/setup?token=')

    // The org's people slice (the founder's scoped read) carries the
    // colleague with the kind-bounded role.
    const people = await page.evaluate(async () => {
      const res = await fetch('/api/users', { credentials: 'include' })
      return res.json() as Promise<Array<{ email: string; role: string; orgId: string | null }>>
    })
    const colleague = people.find(u => u.email === COLLEAGUE_EMAIL)
    expect(colleague).toBeTruthy()
    expect(colleague!.role).toBe('applicant')
    expect(colleague!.orgId).toBe(MFR_ID)
  })

  it('leg 5 — the IA endorses (the demo cast’s officer acting as EX1): the standing upgrades', { timeout: 900_000 }, async () => {
    const ia = await apiSignIn(stack.apiBase, IA_EMAIL)
    const res = await fetch(`${stack.apiBase}/api/op/org-endorsements`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: ia },
      body: JSON.stringify({ org_id: MFR_ID, ia_org_id: 'EX1', note: 'R 60 application 2026-014 on file' }),
    })
    expect(res.status).toBe(201)
    const created = await res.json() as { standing: string; endorsement: { iaOrgId: string } }
    expect(created.standing).toBe('ia-endorsed')
    expect(created.endorsement.iaOrgId).toBe('EX1')
  })

  it('leg 6 — the admin surfaces render the upgrade honestly; the audit chain carries every act', { timeout: 900_000 }, async () => {
    await signOut(page)
    await page.goto(`${stack.base}/`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await opSignIn(page, ADMIN_EMAIL)
    await page.waitForFunction(() => window.location.pathname !== '/', { timeout: SETTLE, polling: 500 })

    // The per-org page: the Standing line upgrades + the endorsement row
    // names the IA.
    await page.goto(`${stack.base}/op/admin/registry/orgs/${MFR_ID}`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await page.waitForSelector('[data-testid="op-reg-org-standing"]', { timeout: SETTLE, polling: 500 })
    const standing = await page.$eval('[data-testid="op-reg-org-standing"]', el => el.textContent ?? '')
    expect(standing).toContain('IA-endorsed manufacturer')
    expect(standing).toContain('EX1')
    expect(standing).toContain('NOT an OIML-CS participant')
    await page.waitForSelector('[data-testid="op-reg-org-endorsement-EX1"]', { timeout: SETTLE, polling: 500 })
    const endorsement = await page.$eval('[data-testid="op-reg-org-endorsement-EX1"]', el => el.textContent ?? '')
    expect(endorsement).toContain('Example Issuing Authority')
    // The org's own audit slice renders the endorsement act in words.
    await page.waitForFunction(() => {
      const list = document.querySelector('[data-testid="op-reg-org-activity-list"]')
      return list && list.textContent?.includes('endorsement')
    }, { timeout: SETTLE, polling: 500 })

    // The list row carries the IA-endorsed mark.
    await page.goto(`${stack.base}/op/admin/organizations`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
    await page.waitForSelector(`[data-testid="op-orgs-row-${MFR_ID}"]`, { timeout: SETTLE, polling: 500 })
    const kindLine = await page.$eval(`[data-testid="op-orgs-kind-${MFR_ID}"]`, el => el.textContent ?? '')
    expect(kindLine).toContain('IA-endorsed (EX1)')

    // THE AUDIT CHAIN (fetch-level): every act of the arc is on the
    // journal. The org's OWN audit slice carries the whole arc (the
    // self-registered add, both approvals naming the org, the
    // endorsement)…
    const admin = await apiSignIn(stack.apiBase, ADMIN_EMAIL)
    const view = await (await fetch(`${stack.apiBase}/api/op/registry/orgs/${MFR_ID}`, { headers: { cookie: admin } })).json() as {
      activity: Array<{ action: string; entity_id: string; metadata?: Record<string, unknown> }>
    }
    const added = view.activity.find(e => e.action === 'organization.added' && e.entity_id === MFR_ID)
    expect(added).toBeTruthy()
    expect(added!.metadata).toMatchObject({ kind: 'manufacturer', self_registered: true })
    expect(view.activity.some(e => e.action === 'organization.endorsed' && e.entity_id === MFR_ID && e.metadata?.ia_org_id === 'EX1')).toBe(true)
    const approvals = view.activity.filter(e => e.action === 'org_join_request.approved')
    expect(approvals.map(e => e.metadata?.email)).toEqual(expect.arrayContaining([FOUNDER_EMAIL, COLLEAGUE_EMAIL]))
    // …and the registry's global feed carries the organization acts (the
    // identity slice's org-lifecycle journal).
    const feed = await (await fetch(`${stack.apiBase}/api/op/registry/activity?limit=500`, { headers: { cookie: admin } })).json() as Array<{
      action: string
      entity_id: string
      metadata?: Record<string, unknown>
    }>
    expect(feed.some(e => e.action === 'organization.added' && e.entity_id === MFR_ID)).toBe(true)
    expect(feed.some(e => e.action === 'organization.endorsed' && e.entity_id === MFR_ID)).toBe(true)
  })

  it('leg 7 — the honest negatives + the demo cast’s mfr-acme row', { timeout: 900_000 }, async () => {
    // The manufacturer's own people hold no endorsement grant (the
    // founder's org_admin is bounded to HER org's people) — the founder
    // signs in fetch-level (02's password account from leg 3).
    const founderLogin = await fetch(`${stack.apiBase}/api/op/login`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: FOUNDER_EMAIL, password: FOUNDER_PASSWORD }),
    })
    expect(founderLogin.status).toBe(200)
    const founderCookie = (founderLogin.headers.get('set-cookie') ?? '').split(';')[0]!
    const refused = await fetch(`${stack.apiBase}/api/op/org-endorsements`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: founderCookie },
      body: JSON.stringify({ org_id: MFR_ID, ia_org_id: 'EX1' }),
    })
    expect(refused.status).toBe(403)

    // The duplicate endorsement is the honest 409.
    const ia = await apiSignIn(stack.apiBase, IA_EMAIL)
    const dup = await fetch(`${stack.apiBase}/api/op/org-endorsements`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: ia },
      body: JSON.stringify({ org_id: MFR_ID, ia_org_id: 'EX1' }),
    })
    expect(dup.status).toBe(409)

    // The demo cast's manufacturer row resolves as the first-class kind
    // (the platform's sample mfr-acme id on the OP's org registry).
    const admin = await apiSignIn(stack.apiBase, ADMIN_EMAIL)
    const view = await (await fetch(`${stack.apiBase}/api/op/registry/orgs/mfr-acme`, { headers: { cookie: admin } })).json() as {
      org: { kind: string; standing: string; registered: boolean; roles: string[] }
    }
    expect(view.org.kind).toBe('manufacturer')
    expect(view.org.standing).toBe('declared')
    expect(view.org.registered).toBe(false)
    expect(view.org.roles).toEqual(['applicant', 'viewer'])
  })
})
