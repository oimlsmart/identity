// ═══════════════════════════════════════════════════════════════════
// ux-screenshots — the identity pages' render-proof sweep (the wave-536
// account-console UX: light/dark awareness). Boots the identity-profile
// stack (the id-06 e2e recipe: own API + own astro + the stub GitHub +
// the stub RP), drives EVERY identity page in BOTH color schemes (the
// house `oiml-theme` localStorage key the shells read before paint),
// and captures 1440x900 screenshots into browser/.cache/ux/:
//
//   sign-in (/) · join · setup (a real bootstrap token) · the account
//   console (incl. the avatar CROP dialog) · the admin console (registry,
//   the registry user detail, users, clients, activity, providers) ·
//   the email-change confirmation (a real token) · the OIDC consent (a
//   real authorize round trip against the stub RP) · the 404.
//
// Run: npx tsx scripts/ux-screenshots.ts
// Ports: API 23457 / astro 23456 (clear of every e2e leg's 93-pair and the other waves' dev stacks).
// ═══════════════════════════════════════════════════════════════════

import puppeteer, { type Browser, type Page } from 'puppeteer'
import { spawn, type ChildProcess } from 'node:child_process'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { existsSync, mkdirSync, rmSync, cpSync, appendFileSync, writeFileSync } from 'node:fs'
import { fixtureOpSigningKey } from '../e2e/fixtures/op-signing-key'
import { startStubGitHub, type StubGitHub } from '../e2e/fixtures/stub-github'
import { startStubRp, type StubRp } from '../e2e/fixtures/stub-rp'

const BROWSER_DIR = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const FIXTURES = join(BROWSER_DIR, 'e2e', 'fixtures')
const WORK_DIR = join(BROWSER_DIR, '.cache', 'ux')
const OUT_DIR = join(WORK_DIR, 'shots')

const ID_API = 23457
const ID_WEB = 23456
const ISSUER = `http://localhost:${ID_WEB}`
const RP_CLIENT_ID = 'ux-shot-rp'
const RP_CLIENT_SECRET = 'ux-shot-rp-secret'

const ROOT = { email: 'root@oimlsmart.org', name: 'Root Operator', password: 'the root operator passphrase' }
const GH_ROOT = { login: 'octocat-root', id: 307, name: 'Octo Root', email: 'root-gh@example.org' }

const logs: string[] = []
function flog(msg: string): void {
  const line = `${new Date().toISOString()} ${msg}\n`
  process.stdout.write(line)
  try { appendFileSync(join(WORK_DIR, 'progress.log'), line) } catch { /* never break the sweep */ }
}

function spawnLogged(cmd: string, args: string[], env: NodeJS.ProcessEnv): ChildProcess {
  // detached (the process group dies together); the env SCRUBS the
  // vitest markers (the 2026-08-14 stall lesson).
  const inherited = Object.fromEntries(
    Object.entries(process.env).filter(([k]) => k !== 'NODE_ENV' && !k.startsWith('VITEST')),
  ) as NodeJS.ProcessEnv
  const proc = spawn(cmd, args, { cwd: BROWSER_DIR, env: { ...inherited, ...env }, stdio: ['ignore', 'pipe', 'pipe'], detached: true })
  proc.stdout?.on('data', d => logs.push(String(d)))
  proc.stderr?.on('data', d => logs.push(String(d)))
  return proc
}

function killTree(proc: ChildProcess | undefined): void {
  if (!proc || proc.exitCode !== null || proc.pid === undefined) return
  try { process.kill(-proc.pid, 'SIGTERM') } catch { /* already gone */ }
  try { proc.kill('SIGTERM') } catch { /* already gone */ }
}

function delay(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms))
}

async function waitForHttp(url: string, timeoutMs: number, exact200 = false): Promise<void> {
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

/** Set the color scheme BEFORE the next load (the shells read the
 *  oiml-theme key pre-paint), then reload to apply it. */
async function setMode(page: Page, mode: 'light' | 'dark'): Promise<void> {
  await page.evaluate(m => localStorage.setItem('oiml-theme', m), mode)
  await page.reload({ waitUntil: 'domcontentloaded', timeout: 120_000 })
}

/** Capture the current page in both modes. `settle` is the selector the
 *  page's island renders when it stands (skipped when absent). */
async function shotBoth(page: Page, name: string, settle?: string): Promise<void> {
  for (const mode of ['light', 'dark'] as const) {
    await setMode(page, mode)
    if (settle) await page.waitForSelector(settle, { timeout: 240_000 })
    await page.addStyleTag({ content: 'astro-dev-toolbar { display: none !important }' }).catch(() => {})
    await page.screenshot({ path: join(OUT_DIR, `${name}-${mode}.png`) })
    flog(`shot ${name} (${mode})`)
  }
}

async function main(): Promise<void> {
  mkdirSync(OUT_DIR, { recursive: true })
  for (const suffix of ['', '-wal', '-shm']) rmSync(join(WORK_DIR, 'identity.db') + suffix, { force: true })

  let api: ChildProcess | undefined
  let astro: ChildProcess | undefined
  let github: StubGitHub | undefined
  let rp: StubRp | undefined
  let browser: Browser | undefined

  try {
    github = await startStubGitHub({ clientSecret: 'ux-gh-secret', users: [GH_ROOT] })
    rp = await startStubRp({ issuer: ISSUER, clientId: RP_CLIENT_ID, clientSecret: RP_CLIENT_SECRET })

    api = spawnLogged(join(BROWSER_DIR, 'node_modules', '.bin', 'tsx'), ['server/serve.ts'], {
      PORT: String(ID_API),
      DATABASE_PATH: join(WORK_DIR, 'identity.db'),
      ENTITY_BACKEND: 'server',
      INSTANCE_PROFILE: join(FIXTURES, 'instance.profile.identity.yaml'),
      OIDC_ISSUER: '',
      OIDC_CLIENT_ID: '',
      DEMO_ACCOUNTS_ENABLED: 'true',
      OP_ISSUER: ISSUER,
      OP_SIGNING_KEY: await fixtureOpSigningKey(),
      OP_ACCOUNT_SEED: JSON.stringify([{ email: ROOT.email, name: ROOT.name, role: 'admin' }]),
      OP_UPSTREAM_SEED: JSON.stringify([{
        id: 'github',
        kind: 'github',
        display_name: 'GitHub',
        brand_mark: 'github',
        client_id: 'ux-e2e',
        client_secret_ref: 'env:UX_GH_SECRET',
        enabled: true,
      }]),
      UX_GH_SECRET: 'ux-gh-secret',
      GITHUB_OAUTH_BASE_URL: github.baseUrl,
      GITHUB_API_BASE_URL: github.baseUrl,
      OP_CLIENT_SEED: JSON.stringify([{
        client_id: RP_CLIENT_ID,
        name: 'The UX-shot fixture RP',
        secret: RP_CLIENT_SECRET,
        redirect_uris: [`${rp.baseUrl}/callback`],
        claims_policy: { claims: ['roles', 'groups', 'org'], roles: ['tl_operator', 'viewer'] },
      }]),
    })
    const apiBase = `http://localhost:${ID_API}`
    await waitForHttp(`${apiBase}/api/health`, 120_000)
    const reset = await fetch(`${apiBase}/api/dev-reset`, { method: 'POST' })
    if (!reset.ok) throw new Error(`dev-reset answered ${reset.status}`)
    const seedProbe = await fetch(`${apiBase}/api/op/login`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: 'nobody@example.org', password: 'a probe, not a password' }),
    })
    if (seedProbe.status !== 401) throw new Error(`the OP login probe answered ${seedProbe.status} (401 expected)`)

    const stackViteCache = join(WORK_DIR, `vite-${ID_WEB}`)
    const sharedViteCache = join(BROWSER_DIR, 'node_modules', '.vite')
    if (existsSync(sharedViteCache)) {
      rmSync(stackViteCache, { recursive: true, force: true })
      cpSync(sharedViteCache, stackViteCache, { recursive: true })
    }
    astro = spawnLogged(join(BROWSER_DIR, 'node_modules', '.bin', 'astro'), ['dev', '--port', String(ID_WEB), '--ignore-lock'], {
      API_ORIGIN: apiBase,
      VITE_CACHE_DIR: stackViteCache,
      DEV_PUBLIC_HOST: `localhost:${ID_WEB}`,
    })
    const base = `http://localhost:${ID_WEB}`
    await waitForHttp(`${base}/`, 240_000)
    await waitForHttp(`${base}/op/join`, 240_000, true)
    flog('the stack stands')

    // The bootstrap setup link from the boot log (the operator's way in).
    let setupUrl = ''
    const deadline = Date.now() + 60_000
    while (Date.now() < deadline) {
      const m = /bootstrap: account root@oimlsmart\.org has no password[^\n]*\n\s*(\S+\/op\/setup\?token=\S+)/.exec(logs.join(''))
      if (m) { setupUrl = m[1]!; break }
      await delay(500)
    }
    if (!setupUrl) throw new Error('the bootstrap setup link never logged')

    browser = await puppeteer.launch({ headless: 'shell', protocolTimeout: 480_000, args: ['--no-sandbox', '--disable-setuid-sandbox'] })
    const page = await browser.newPage()
    await page.setViewport({ width: 1440, height: 900 })

    // 1 · The sign-in landing (the bare shell — the footer carries the
    //     theme toggle there) and the join intake, signed out.
    await page.goto(`${base}/`, { waitUntil: 'domcontentloaded', timeout: 120_000 })
    await shotBoth(page, '01-signin', '[data-testid="login-email"]')
    await page.goto(`${base}/op/join`, { waitUntil: 'domcontentloaded', timeout: 120_000 })
    await shotBoth(page, '02-join', '[data-testid="op-join"]')

    // The painted photo fixture for the crop-dialog shots (a 640x320
    // red/blue PNG, the same shape the e2e leg drives).
    const photoDataUrl = await page.evaluate(() => {
      const c = document.createElement('canvas')
      c.width = 640
      c.height = 320
      const ctx = c.getContext('2d')!
      ctx.fillStyle = '#c0392b'
      ctx.fillRect(0, 0, 320, 320)
      ctx.fillStyle = '#2980b9'
      ctx.fillRect(320, 0, 320, 320)
      return c.toDataURL('image/png')
    })
    const photoPath = join(WORK_DIR, 'ux-photo.png')
    writeFileSync(photoPath, Buffer.from(photoDataUrl.split(',')[1]!, 'base64'))

    // 2 · The setup page on the REAL bootstrap token (both modes), then
    //     the enrollment (which signs the session in).
    await page.goto(setupUrl, { waitUntil: 'domcontentloaded', timeout: 120_000 })
    await shotBoth(page, '03-setup', '[data-testid="op-setup-password"]')
    await page.type('[data-testid="op-setup-password"]', ROOT.password)
    await page.type('[data-testid="op-setup-confirm"]', ROOT.password)
    await page.evaluate(() => (document.querySelector('[data-testid="op-setup-submit"]') as HTMLElement).click())
    await page.waitForSelector('[data-testid="account-name"]', { timeout: 240_000 })
    flog('enrolled; the session stands')

    // 3 · The account console, then the avatar crop dialog on top of it.
    await shotBoth(page, '04-account', '[data-testid="account-name"]')
    for (const mode of ['light', 'dark'] as const) {
      await setMode(page, mode)
      await page.waitForSelector('[data-testid="account-avatar-input"]', { timeout: 240_000 })
      const input = await page.$('[data-testid="account-avatar-input"]') as import('puppeteer').ElementHandle<HTMLInputElement> | null
      await input!.uploadFile(photoPath)
      await page.waitForSelector('[data-testid="account-avatar-crop"]', { timeout: 60_000 })
      await page.waitForSelector('[data-testid="account-avatar-crop-preview"]', { timeout: 60_000 })
      await page.addStyleTag({ content: 'astro-dev-toolbar { display: none !important }' }).catch(() => {})
      await page.screenshot({ path: join(OUT_DIR, `05-account-crop-${mode}.png`) })
      flog(`shot 05-account-crop (${mode})`)
      await page.evaluate(() => (document.querySelector('[data-testid="account-avatar-crop-cancel"]') as HTMLElement).click())
      await page.waitForFunction(() => !document.querySelector('[data-testid="account-avatar-crop"]'), { timeout: 30_000 })
    }

    // 4 · The admin console (the registry home + every sibling).
    const registryRows = await page.evaluate(async () => {
      const res = await fetch('/api/op/registry/users', { credentials: 'include' })
      return res.ok ? await res.json() as Array<{ id: string }> : []
    })
    const rootId = registryRows[0]?.id
    if (!rootId) throw new Error('the registry list carried no root row')
    await page.goto(`${base}/op/admin`, { waitUntil: 'domcontentloaded', timeout: 120_000 })
    await shotBoth(page, '06-admin-registry', '[data-testid="op-reg"]')
    await page.goto(`${base}/op/admin/registry/users/${rootId}`, { waitUntil: 'domcontentloaded', timeout: 120_000 })
    await shotBoth(page, '07-admin-registry-user', '[data-testid="op-reg-user"]')
    await page.goto(`${base}/op/admin/users`, { waitUntil: 'domcontentloaded', timeout: 120_000 })
    await shotBoth(page, '08-admin-users', '[data-testid="op-admin-users"]')
    await page.goto(`${base}/op/admin/clients`, { waitUntil: 'domcontentloaded', timeout: 120_000 })
    await shotBoth(page, '09-admin-clients', '[data-testid="op-clients"]')
    await page.goto(`${base}/op/admin/activity`, { waitUntil: 'domcontentloaded', timeout: 120_000 })
    await shotBoth(page, '10-admin-activity', '[data-testid="op-act"]')
    await page.goto(`${base}/op/admin/providers`, { waitUntil: 'domcontentloaded', timeout: 120_000 })
    await shotBoth(page, '11-admin-providers', '[data-testid="op-providers"]')

    // 5 · The email-change confirmation on a REAL token (requested now,
    //     after the console shots so the pending box never photobombs
    //     them). Rendered, never confirmed.
    const changeUrl = await page.evaluate(async () => {
      const res = await fetch('/api/op/account/email', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ email: 'root.renamed@example.org' }),
      })
      const body = await res.json().catch(() => null) as { verificationUrl?: string } | null
      return body?.verificationUrl ?? null
    })
    if (changeUrl) {
      await page.goto(new URL(changeUrl).toString(), { waitUntil: 'domcontentloaded', timeout: 120_000 })
      await shotBoth(page, '12-email-change', '[data-testid="op-email-change"]')
    } else {
      flog('NOTE: the email change answered without a shown link (a mailer configured?) — the page shot is skipped')
    }

    // 6 · The OIDC consent: the stub RP's authorize round trip, signed
    //     in, landing on the consent page. Rendered, never allowed.
    await page.goto(`${rp.baseUrl}/signin`, { waitUntil: 'domcontentloaded', timeout: 120_000 })
    await shotBoth(page, '13-consent', '[data-testid="op-consent-allow"]')

    // 7 · The 404.
    await page.goto(`${base}/this-page-is-not-here`, { waitUntil: 'domcontentloaded', timeout: 120_000 })
    await shotBoth(page, '14-not-found', '[data-testid="not-found-signin"]')

    flog('the sweep is complete')
  } finally {
    await browser?.close().catch(() => {})
    await github?.close()
    await rp?.close()
    for (const proc of [astro, api]) killTree(proc)
    await delay(1_500)
    for (const proc of [astro, api]) {
      if (proc && proc.exitCode === null && proc.pid !== undefined) {
        try { process.kill(-proc.pid, 'SIGKILL') } catch { /* already gone */ }
      }
    }
  }
}

main().catch((e) => {
  console.error(e)
  process.exit(1)
})
