// ═══════════════════════════════════════════════════════════════════
// TODO.identity-features/09, wave B — the EFFECTIVE-PERMISSION
// EXPLAINER, the identity-side e2e (the identity-profile stack, the
// id-20 spawned-stack pattern — its own API + its own astro, its own
// SQLite file):
//
//   leg 1  THE ENDPOINT: the org admin explains the member (mfr-acme's
//          invited applicant) — the computed set answers the roles
//          attributed to their source, the permissions each named with
//          the role they came from, the cone's effect on the read/write
//          classes, and the data-visibility dry-run; the gates: the
//          grantless member is refused, the org grant never reaches
//          another org's row, the anonymous caller is the honest 401;
//   leg 2  THE CONSOLE: the people section's per-member Explain panel
//          renders the computed set — and when the cone picker moves
//          the member to 'assigned', the OPEN panel re-asks and answers
//          the narrowed reality (the org's unnamed rows hide, the named
//          rows stand);
//   leg 3  THE READ-ONLY MODIFIER: every action permission suspends in
//          the answer, and the restore leaves the posture it found.
//
// Port-isolated above every live leg (…10600 is id-21's): API 10601,
// astro 10602.
// ═══════════════════════════════════════════════════════════════════

import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import puppeteer, { type Browser } from 'puppeteer'
import { spawn, type ChildProcess } from 'node:child_process'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { existsSync, mkdirSync, rmSync, cpSync } from 'node:fs'
import { closeBrowser, delay } from './helpers'
import { fixtureOpSigningKey } from './fixtures/op-signing-key'

const BROWSER_DIR = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const FIXTURES = join(BROWSER_DIR, 'e2e', 'fixtures')
const DB_DIR = join(BROWSER_DIR, '.cache', 'id-22')

// Port-isolated: above every declared e2e stack (…10599/10600 are
// id-21's) and the local dev loops.
const ID_API = 10601
const ID_WEB = 10602

const ORG = 'mfr-acme'
const ORG_ADMIN = 'applicant@oiml.org' // the demo cast's mfr-acme org_admin
const MEMBER = 'tl@oiml.org'

const PLAIN_RP = {
  client_id: 'hub-instance',
  name: 'OIML SMART platform hub',
  secret: 'hub-secret-123',
  redirect_uris: ['https://hub.example/api/auth/callback/oidc'],
  claims_policy: { claims: ['roles', 'groups', 'org'] },
  launch: { url: 'https://hub.example/api/auth/signin/oidc', icon: 'grid', description: 'The certification hub.', visibility: 'open' },
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
      OP_CLIENT_SEED: JSON.stringify([PLAIN_RP]),
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
async function opSignIn(page: import('puppeteer').Page, email: string): Promise<void> {
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

/** The explanation payload's row (the legs read it loosely — the unit
 *  suites pin the exact shape). */
interface Explanation {
  acting: boolean
  stateNote: string
  context: { orgId: string | null; cone: { scope: string; readOnly: boolean } | null }
  roles: Array<{ id: string; source: string; known: boolean; permissions: Array<{ id: string }> }>
  permissions: Array<{ id: string; fromRoles: string[]; effective: boolean; effect: string }>
  kindBound: { orgAdminRow: boolean; outside: string[] }
  cone: { posture: string; read: { effect: string }; write: { refused: boolean; effect: string } }
  visibility: {
    orgBound: boolean
    classes: Array<{
      store: string
      personKey: string | null
      ownOrg: { visible: boolean; reason: string }
      named: { visible: boolean; reason: string } | null
      foreignOrg: { visible: boolean; reason: string }
    }>
  }
}

describe('TODO.identity-features/09 (wave B) — the effective-permission explainer', () => {
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

  it('the full arc: the endpoint computes, the console renders, the cone act re-answers', { timeout: 900_000 }, async () => {
    const { apiBase, base } = stack

    // ── the setup: the org admin invites the member (the applicant
    //    posture, in the manufacturer kind's bound); the holder accepts ──
    const adminCookie = await apiSignIn(apiBase, ORG_ADMIN)
    const memberCookie = await apiSignIn(apiBase, MEMBER)
    const invite = await fetch(`${apiBase}/api/op/org-memberships`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: adminCookie },
      body: JSON.stringify({ email: MEMBER, roles: ['applicant', 'viewer'] }),
    })
    expect(invite.status, 'the invite lands').toBe(201)
    memberId = ((await invite.json()) as { userId: string }).userId
    const accept = await fetch(`${apiBase}/api/op/account/memberships/${ORG}/accept`, {
      method: 'POST', headers: { cookie: memberCookie },
    })
    expect(accept.status, 'the holder accepts').toBe(200)

    // ── leg 1: THE ENDPOINT — the computed set + the gates ──
    const anon = await fetch(`${apiBase}/api/op/org-memberships/${memberId}/${ORG}/explain`)
    expect(anon.status, 'the anonymous caller is the honest 401').toBe(401)
    const noGrant = await fetch(`${apiBase}/api/op/org-memberships/${memberId}/${ORG}/explain`, { headers: { cookie: memberCookie } })
    expect(noGrant.status, 'the grantless member never explains').toBe(403)
    const crossOrg = await fetch(`${apiBase}/api/op/org-memberships/${memberId}/21/explain`, { headers: { cookie: adminCookie } })
    expect(crossOrg.status, 'the org grant never reaches another org (not found, never wider)').toBe(404)

    const explainRes = await fetch(`${apiBase}/api/op/org-memberships/${memberId}/${ORG}/explain`, { headers: { cookie: adminCookie } })
    expect(explainRes.status, 'the explanation answers').toBe(200)
    const x = (await explainRes.json()) as Explanation
    expect(x.acting).toBe(true)
    expect(x.context.orgId).toBe(ORG)
    // The roles held, attributed: the membership's set, never the
    // account's other-org layer (the account's primary binding is the
    // laboratory — org-bound accounts carry no account layer across).
    expect(x.roles.map(r => [r.id, r.source])).toEqual([['applicant', 'membership'], ['viewer', 'membership']])
    // The permissions, each named with the role it came from.
    const submit = x.permissions.find(p => p.id === 'application.submit')!
    expect(submit.fromRoles).toEqual(['applicant'])
    expect(submit.effective).toBe(true)
    expect(submit.effect).toBe('held')
    expect(x.permissions.every(p => p.fromRoles.includes('applicant'))).toBe(true) // the viewer grants nothing
    expect(x.kindBound.outside).toEqual([])
    // The cone's default effect + the dry-run's org-field answers.
    expect(x.cone).toMatchObject({ posture: 'org-wide', read: { effect: 'org-rows' }, write: { refused: false } })
    expect(x.visibility.orgBound).toBe(true) // the member's primary role is the laboratory operator
    const classes = new Map(x.visibility.classes.map(c => [c.store, c]))
    expect(classes.get('applications')!.ownOrg).toMatchObject({ visible: true, reason: 'org-field' })
    expect(classes.get('applications')!.foreignOrg).toMatchObject({ visible: false, reason: 'org-field-miss' })
    expect(classes.get('testRuns')!.personKey).toContain('operators')
    expect(classes.get('measuringInstrumentModels')!.ownOrg).toMatchObject({ visible: true, reason: 'catalog' })

    // ── leg 2: THE CONSOLE — the panel renders the computed set, and
    //    re-answers when the cone moves ──
    browser = await puppeteer.launch({ headless: true, args: ['--no-sandbox', '--disable-dev-shm-usage'] })
    const page = await browser.newPage()
    await page.goto(`${base}/`, { waitUntil: 'domcontentloaded', timeout: 60_000 })
    await opSignIn(page, ORG_ADMIN)
    await page.waitForFunction(() => window.location.pathname !== '/', { timeout: SETTLE, polling: 500 })
    await page.goto(`${base}/op/admin/users`, { waitUntil: 'domcontentloaded', timeout: 60_000 })
    await page.waitForSelector(`[data-testid="org-user-${memberId}"]`, { timeout: SETTLE, polling: 500 })

    // Open the explainer: the computed set renders.
    await page.evaluate(id => (document.querySelector(`[data-testid="org-user-explain-${id}"]`) as HTMLElement).click(), memberId)
    await page.waitForSelector(`[data-testid="org-user-explain-roles-${memberId}"]`, { timeout: SETTLE, polling: 500 })
    const panelText = await page.$eval(`[data-testid="org-user-explain-panel-${memberId}"]`, el => el.textContent ?? '')
    expect(panelText).toContain('the computed answer')
    expect(panelText).toContain('applicant')
    expect(panelText).toContain('application.submit')
    expect(panelText).toContain('from: applicant')
    expect(panelText).toContain('Reads: every row the organization sees.')
    expect(panelText).toContain('Writes: as the roles above grant.')
    expect(panelText).toContain('The read gate narrows this member')
    const appsRow = await page.$eval(`[data-testid="org-user-explain-vis-${memberId}-applications"]`, el => el.textContent ?? '')
    expect(appsRow).toContain("the organization's row: visible")
    expect(appsRow).toContain("another organization's row: hidden")

    // The cone picker moves the member to 'assigned' — the OPEN panel
    // re-asks and answers the narrowed reality.
    await page.evaluate(id => (document.querySelector(`[data-testid="org-user-cone-edit-${id}"]`) as HTMLElement).click(), memberId)
    await page.waitForSelector(`[data-testid="org-user-cone-editor-${memberId}"]`, { timeout: SETTLE, polling: 500 })
    await page.evaluate(id => (document.querySelector(`[data-testid="org-user-cone-opt-${id}-assigned"]`) as HTMLElement).click(), memberId)
    await page.evaluate(id => (document.querySelector(`[data-testid="org-user-cone-save-${id}"]`) as HTMLElement).click(), memberId)
    await page.waitForFunction(
      id => document.querySelector(`[data-testid="org-user-explain-vis-${id}-applications"]`)?.textContent?.includes("the organization's row: hidden"),
      { timeout: SETTLE, polling: 500 },
      memberId,
    )
    const narrowedApps = await page.$eval(`[data-testid="org-user-explain-vis-${memberId}-applications"]`, el => el.textContent ?? '')
    expect(narrowedApps).toContain('no person-level field')
    const narrowedRuns = await page.$eval(`[data-testid="org-user-explain-vis-${memberId}-testRuns"]`, el => el.textContent ?? '')
    expect(narrowedRuns).toContain('…naming the member: visible')
    const narrowedPanel = await page.$eval(`[data-testid="org-user-explain-panel-${memberId}"]`, el => el.textContent ?? '')
    expect(narrowedPanel).toContain("Reads: only the organization's rows that name them.")
    expect(narrowedPanel).toContain('in effect — over the rows naming them only')

    // ── leg 3: THE READ-ONLY MODIFIER — every act suspends; the restore ──
    const ro = await fetch(`${apiBase}/api/op/org-memberships/${memberId}/${ORG}/cone`, {
      method: 'PUT',
      headers: { 'content-type': 'application/json', cookie: adminCookie },
      body: JSON.stringify({ cone: 'assigned+read-only' }),
    })
    expect(ro.status).toBe(200)
    const roExplain = (await (await fetch(`${apiBase}/api/op/org-memberships/${memberId}/${ORG}/explain`, { headers: { cookie: adminCookie } })).json()) as Explanation
    expect(roExplain.cone).toMatchObject({ posture: 'assigned+read-only', write: { refused: true, effect: 'read-only-refused' } })
    expect(roExplain.permissions.length).toBeGreaterThan(0)
    expect(roExplain.permissions.every(p => !p.effective && p.effect === 'read-only-refused')).toBe(true)

    // The restore: the org-wide default (the stack dies with the suite;
    // the arc leaves the posture it found).
    const restore = await fetch(`${apiBase}/api/op/org-memberships/${memberId}/${ORG}/cone`, {
      method: 'PUT',
      headers: { 'content-type': 'application/json', cookie: adminCookie },
      body: JSON.stringify({ cone: 'org-wide' }),
    })
    expect(restore.status).toBe(200)
    const restored = (await (await fetch(`${apiBase}/api/op/org-memberships/${memberId}/${ORG}/explain`, { headers: { cookie: adminCookie } })).json()) as Explanation
    expect(restored.cone.posture).toBe('org-wide')
    expect(restored.permissions.every(p => p.effective)).toBe(true)
  })
})
