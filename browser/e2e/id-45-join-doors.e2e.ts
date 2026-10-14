// ═══════════════════════════════════════════════════════════════════
// The join page's DOORS (2026-10-13) — the question before the form.
// The identity-profile stack (its own API + its own astro, the id-01/
// id-10 spawned-stack pattern):
//
//   leg 1  the six doors render; each door dictates its form (the
//          register doors filter the picker to their kinds; the
//          manufacturer door declares its standing honestly; the BIML
//          door names the mailbox proof; Others names BIML's queue);
//          the back control returns to the question;
//   leg 2  THE BIML DOOR, end to end: a non-BIML domain is refused
//          honestly (nothing minted); an @oiml.org ask mints the
//          account UNREACHABLE and mails the one-time setup link (the
//          dev posture shows it in the server log); the link completes
//          through the real enrollment endpoint; the session names the
//          operator org with the floor role — the link was the
//          decision, no queue, no admin act.
//
// SELF-CONTAINED: the suite's shared stack (E2E_BASE_URL) is untouched —
// the identity instance boots on its own ports (API 10393 / astro 10394)
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
const DB_DIR = join(BROWSER_DIR, '.cache', 'id-45')

// Port-isolated: clear of the shared dev stack (5190/3190), the fed-01
// stacks, the id-01 (8703/8403/8704), id-02 (8793/8593/8794), id-08
// (8993/8893/8994), id-09 (8795/8595), id-10 (9193/9093), id-12
// (10093/10094) and id-06 (9493/9393) stacks.
const ID_API = 10393
const ID_WEB = 10394

const STAFF_EMAIL = 'ingrid.pettersson@oiml.org'
const STAFF_PASSWORD = 'the biml staffer passphrase'

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
  try { proc.kill('SIGKILL') } catch { /* already gone */ }
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
      ASTRO_DEV_BACKGROUND: '1',
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
  killTree(stack.astro)
  killTree(stack.api)
  await delay(500)
  killTreeHard(stack.astro)
  killTreeHard(stack.api)
}

const SETTLE = 30_000

let stack: Stack | undefined
let browser: Browser | undefined

async function withPage(fn: (page: Page) => Promise<void>): Promise<void> {
  const page = await browser!.newPage()
  try {
    await fn(page)
  } finally {
    await page.close()
  }
}

/** The door step, then a door (a door already open goes back first). */
async function openDoor(page: Page, key: string): Promise<void> {
  if (await page.$('[data-testid="join-door-back"]')) {
    await page.evaluate(() => (document.querySelector('[data-testid="join-door-back"]') as HTMLElement).click())
  }
  await page.waitForSelector('[data-testid="join-doors"]', { timeout: SETTLE, polling: 500 })
  await page.evaluate((k) => {
    (document.querySelector(`[data-testid="join-door-${k}"]`) as HTMLElement).click()
  }, key)
}

beforeAll(async () => {
  stack = await bootIdentityStack()
  browser = await puppeteer.launch({ headless: true, args: ['--no-sandbox'] })
})

afterAll(async () => {
  await closeBrowser(browser)
  await stopStack(stack)
  rmSync(DB_DIR, { recursive: true, force: true })
})

describe('the join page’s doors (the question before the form)', () => {
  it('leg 1 — the six doors render; each dictates its form; back returns to the question', { timeout: 900_000 }, async () => {
    await withPage(async (page) => {
      await page.goto(`${stack!.base}/op/join`, { waitUntil: 'domcontentloaded', timeout: SETTLE })
      await page.waitForSelector('[data-testid="join-doors"]', { timeout: SETTLE, polling: 500 })
      for (const key of ['ia', 'tl', 'member', 'manufacturer', 'biml', 'others']) {
        expect(await page.$(`[data-testid="join-door-${key}"]`), `the ${key} door renders`).toBeTruthy()
      }

      // The seventh card arms the registry mode IN THIS PAGE — a button,
      // and the page never links to a separate self-register surface.
      const seventh = await page.$eval('[data-testid="join-door-registry-domain"]', el => ({ tag: el.tagName, text: el.textContent ?? '' }))
      expect(seventh.tag, 'the registry door is the in-page arm, not a handoff link').toBe('BUTTON')
      const strayLinks = await page.evaluate(() => Array.from(document.querySelectorAll('a[href*="self-register"]')).length)
      expect(strayLinks, 'the join page never links to the old self-register surface').toBe(0)

      // The IA door: the picker, titled for the authority.
      await openDoor(page, 'ia')
      await page.waitForSelector('[data-testid="join-given-name"]', { timeout: SETTLE, polling: 500 })
      expect((await page.$eval('[data-testid="join-door-title"]', el => el.textContent ?? ''))).toContain('Issuing Authority')
      expect(await page.$('[data-testid="join-org-search"]'), 'the register doors pick from the register').toBeTruthy()

      // The idle picker shows no register dump; its empty state names the
      // door's own kind of organization and the support path.
      const idleEmpty = await page.$eval('[data-testid="join-org-empty"]', el => el.textContent ?? '')
      expect(idleEmpty).toContain('an OIML-CS Issuing Authority')
      expect(idleEmpty).toContain('contact support')
      expect(await page.$('[data-testid="join-org-options"]'), 'the register never dumps before the search engages').toBeNull()

      // The TL door: its own title, the picker again.
      await openDoor(page, 'tl')
      await page.waitForSelector('[data-testid="join-given-name"]', { timeout: SETTLE, polling: 500 })
      expect((await page.$eval('[data-testid="join-door-title"]', el => el.textContent ?? ''))).toContain('Test Laboratory')

      // THE PRE-APPROVED DOMAIN (0043): the seeded demonstration IA
      // carries @bmd.example — the card shows it, the comparison runs
      // live against the typed address, and the mismatch routes honestly.
      await openDoor(page, 'ia')
      await page.waitForSelector('[data-testid="join-given-name"]', { timeout: SETTLE, polling: 500 })
      await page.focus('[data-testid="join-org-search"]')
      await page.waitForSelector('[data-testid="join-org-option-EX1"]', { timeout: SETTLE, polling: 500 })
      const optionText = await page.$eval('[data-testid="join-org-option-EX1"]', el => el.textContent ?? '')
      expect(optionText).toContain('@bmd.example')
      await page.evaluate(() => (document.querySelector('[data-testid="join-org-option-EX1"]') as HTMLElement).click())
      await page.waitForSelector('[data-testid="join-domain-check"]', { timeout: SETTLE, polling: 500 })
      await page.type('[data-testid="join-given-name"]', 'Domain')
      await page.type('[data-testid="join-family-name"]', 'Probe')
      await page.type('[data-testid="join-email"]', 'domain.probe@bmd.example')
      await page.waitForSelector('[data-testid="join-domain-match"]', { timeout: SETTLE, polling: 500 })
      await page.click('[data-testid="join-email"]', { clickCount: 3 })
      await page.type('[data-testid="join-email"]', 'domain.probe@elsewhere.example')
      await page.waitForSelector('[data-testid="join-domain-mismatch"]', { timeout: SETTLE, polling: 500 })

      // The picked organization REPLACES the search field (the owner's
      // 2026-10-13 ruling); Change brings the field back, and picking
      // again resumes the form.
      expect(await page.$('[data-testid="join-org-search"]'), 'the picked card replaces the search field').toBeNull()
      await page.waitForSelector('[data-testid="join-org-picked"]', { timeout: SETTLE, polling: 500 })
      expect((await page.$eval('[data-testid="join-org-change"]', el => el.textContent ?? ''))).toBe('Change')
      await page.evaluate(() => (document.querySelector('[data-testid="join-org-change"]') as HTMLElement).click())
      await page.waitForSelector('[data-testid="join-org-search"]', { timeout: SETTLE, polling: 500 })
      expect(await page.$('[data-testid="join-org-picked"]')).toBeNull()
      await page.focus('[data-testid="join-org-search"]')
      await page.waitForSelector('[data-testid="join-org-option-EX1"]', { timeout: SETTLE, polling: 500 })
      await page.evaluate(() => (document.querySelector('[data-testid="join-org-option-EX1"]') as HTMLElement).click())
      await page.waitForSelector('[data-testid="join-org-picked"]', { timeout: SETTLE, polling: 500 })

      // The member door: the OIML Member title.
      await openDoor(page, 'member')
      await page.waitForSelector('[data-testid="join-given-name"]', { timeout: SETTLE, polling: 500 })
      expect((await page.$eval('[data-testid="join-door-title"]', el => el.textContent ?? ''))).toContain('OIML Member')

      // The manufacturer door: the declared-standing form, no picker.
      await openDoor(page, 'manufacturer')
      await page.waitForSelector('[data-testid="join-mfr-name"]', { timeout: SETTLE, polling: 500 })
      const mfrNote = await page.$eval('[data-testid="join-mfr-note"]', el => el.textContent ?? '')
      expect(mfrNote).toContain('not an OIML-CS participant')
      expect(await page.$('[data-testid="join-org-search"]')).toBeNull()

      // The BIML door: the mailbox-proof note, no org fields.
      await openDoor(page, 'biml')
      await page.waitForSelector('[data-testid="join-biml-note"]', { timeout: SETTLE, polling: 500 })
      const bimlNote = await page.$eval('[data-testid="join-biml-note"]', el => el.textContent ?? '')
      expect(bimlNote).toContain('@oiml.org')
      expect(await page.$('[data-testid="join-org-search"]')).toBeNull()

      // Others: the free-text org name, BIML's queue note.
      await openDoor(page, 'others')
      await page.waitForSelector('[data-testid="join-org-name-text"]', { timeout: SETTLE, polling: 500 })
      const othersNote = await page.$eval('[data-testid="join-not-listed-note"]', el => el.textContent ?? '')
      expect(othersNote).toContain('BIML secretariat')

      // Back returns to the question, all six still standing.
      await page.evaluate(() => (document.querySelector('[data-testid="join-door-back"]') as HTMLElement).click())
      await page.waitForSelector('[data-testid="join-doors"]', { timeout: SETTLE, polling: 500 })
      expect(await page.$$eval('[data-testid="join-doors"] [role="radio"]', els => els.length)).toBe(6)
    })
  })

  it('leg 2 — the BIML door, end to end: the domain refuses, the mailbox proves, the link decides', { timeout: 900_000 }, async () => {
    // The wrong domain: refused honestly, nothing minted.
    const refused = await fetch(`${stack!.apiBase}/api/op/join-requests`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ given_name: 'Not', family_name: 'Bureau', email: 'impostor@example.com', org_kind: 'biml' }),
    })
    expect(refused.status).toBe(400)
    const refusedBody = await refused.json() as { error?: string }
    expect(refusedBody.error).toContain('oiml.org')

    // The ask: minted unreachable, the link rides the mail only.
    const asked = await fetch(`${stack!.apiBase}/api/op/join-requests`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ given_name: 'Ingrid', family_name: 'Pettersson', email: STAFF_EMAIL, org_kind: 'biml' }),
    })
    expect(asked.status).toBe(201)
    const askedBody = await asked.json() as { invited?: boolean; org?: string }
    expect(askedBody.invited).toBe(true)
    expect(JSON.stringify(askedBody)).not.toContain('setup')

    // The dev posture shows the link in the server log (the mailer's
    // honest no-provider posture) — the same link the mailbox would
    // carry. The floor role + the operator org binding ride the invite.
    const deadline = Date.now() + 30_000
    let setupUrl = ''
    while (Date.now() < deadline && !setupUrl) {
      const m = /http:\/\/localhost:\d+\/op\/setup\?token=[A-Za-z0-9_-]+/g.exec(stack!.logs.join(''))
      // Take the LAST link addressed to the staffer (the logs carry other
      // flows' links too — match by proximity to the recipient).
      const all = m ? [...m] : []
      const tail = stack!.logs.join('')
      for (const candidate of all.reverse()) {
        const at = tail.indexOf(candidate)
        const window = tail.slice(Math.max(0, at - 600), at)
        if (window.includes(STAFF_EMAIL)) { setupUrl = candidate; break }
      }
      if (!setupUrl) await delay(1_000)
    }
    expect(setupUrl, 'the setup link reached the (log) mailbox').toBeTruthy()

    // The mailbox proof: the one-time link completes through the REAL
    // enrollment endpoint — the account answers for the first time.
    const done = await fetch(setupUrl.replace(`/op/setup?token=`, `/api/op/enroll/`), {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ password: STAFF_PASSWORD }),
    })
    expect(done.status).toBe(200)
    const cookie = done.headers.get('set-cookie')!.split(';')[0]!
    const session = await (await fetch(`${stack!.apiBase}/api/auth/session`, { headers: { cookie } })).json() as { email?: string; orgId?: string | null; roles?: string[] }
    expect(session.email).toBe(STAFF_EMAIL)
    expect(session.orgId, 'bound to the operator org').toBe('oimlsmart-id')
    expect(session.roles ?? [], 'the floor role — the admins promote').toContain('viewer')

    // The door is one account per address: a second ask refuses with
    // the sign-in pointer.
    const second = await fetch(`${stack!.apiBase}/api/op/join-requests`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ given_name: 'Ingrid', family_name: 'Pettersson', email: STAFF_EMAIL, org_kind: 'biml' }),
    })
    expect(second.status).toBe(409)
    const secondBody = await second.json() as { error?: string }
    expect(secondBody.error).toContain('already hold an account')
  })
})