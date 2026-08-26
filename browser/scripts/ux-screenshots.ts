// ═══════════════════════════════════════════════════════════════════
// ux-screenshots — the identity pages' render-proof sweep (the wave-536
// account-console UX: light/dark awareness; the wave TODO.identity-
// features/02 responsive audit: the width sweep + the overflow
// detector). Boots the identity-profile stack (the id-06 e2e recipe:
// own API + own astro + the stub GitHub + the stub RP), drives EVERY
// identity page at EVERY audited width in BOTH color schemes (the house
// `oiml-theme` localStorage key the shells read before paint), and
// captures screenshots into browser/.cache/ux/shots/:
//
//   sign-in (/) · join · setup (a real bootstrap token) · the account
//   console (incl. the avatar CROP dialog) · the launcher (/op/home) ·
//   the admin console (overview, registry, the registry user + org
//   details, users, clients, activity, providers, sessions, security) ·
//   the email-change confirmation (a real token) · the OIDC consent (a
//   real authorize round trip against the stub RP) · the 404.
//
// Every shot carries an objective HORIZONTAL-OVERFLOW measurement: the
// page must never scroll sideways (document.scrollWidth <= the viewport
// width); the offenders (the elements whose box crosses the viewport,
// skipping honestly-internal scrollers) are named per shot and the set
// lands in overflow-report.json — the audit's review artifact.
//
// Run: npx tsx scripts/ux-screenshots.ts
// Env: UX_WIDTHS=320,360,390,768,1440,2560 (the default sweep — 07's
//      320–2560 contract) · UX_MODE=both|light|dark · UX_FILTER=<shot-name substring>
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

// ── the sweep knobs ──────────────────────────────────────────────────
/** The audited widths (320–2560 per TODO.identity-features/07: the
 *  detector proves zero sideways scroll across the whole range) with
 *  the phone/tablet/desktop heights that keep the fold honest. */
const WIDTH_HEIGHTS: Record<number, number> = { 320: 700, 360: 740, 390: 844, 768: 1024, 1440: 900, 2560: 1000 }
const WIDTHS = (process.env.UX_WIDTHS ?? '320,360,390,768,1440,2560')
  .split(',').map(s => Number(s.trim())).filter(w => Number.isFinite(w) && w >= 280)
const MODES = ((): Array<'light' | 'dark'> => {
  const m = process.env.UX_MODE ?? 'both'
  return m === 'light' || m === 'dark' ? [m] : ['light', 'dark']
})()
const FILTER = process.env.UX_FILTER ?? ''
/** UX_FULLPAGE=1: capture the full scroll height (the review artifact for
 *  lists below the fold — the registry's cards on a phone). Default:
 *  the viewport shot (what the device shows). */
const FULLPAGE = process.env.UX_FULLPAGE === '1'
const heightFor = (w: number): number => WIDTH_HEIGHTS[w] ?? 900

/** The audit's overflow ledger: one entry per shot that scrolls
 *  sideways (the empty set is the wave's definition of done). */
interface OverflowEntry { shot: string; width: number; mode: string; over: number; offenders: string[]; absorbed?: string[] }
const overflowLedger: OverflowEntry[] = []

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

/** The horizontal-overflow measurement: the page scrolls sideways iff
 *  document.scrollWidth exceeds the viewport; the offenders are the
 *  outermost elements whose box crosses the viewport edge, SKIPPING the
 *  subtrees that scroll (or clip) themselves honestly — an internal
 *  overflow-x scroller is the house idiom, never a page-scroll cause.
 *  The detector runs as a RAW STRING: tsx's keepNames wraps the inner
 *  arrows in esbuild's `__name(...)` helper, which the page context
 *  never defines (the 2026-08-25 crash — it only fires past the early
 *  return, i.e. exactly when an overflow IS found). */
const OVERFLOW_PROBE = `(() => {
  window.scrollTo(0, 0)
  const vw = document.documentElement.clientWidth
  const se = document.scrollingElement || document.documentElement
  const over = se.scrollWidth - vw
  if (over <= 1) return JSON.stringify({ over: 0, offenders: [], absorbed: [] })
  const offenders = []
  const absorbedWide = []
  const reported = new Set()
  const reportedAbs = new Set()
  const describe = (el) => {
    const parts = []
    for (let cur = el; cur && cur !== document.body && parts.length < 4; cur = cur.parentElement) {
      const id = cur.getAttribute('data-testid')
      const cls = (cur.getAttribute('class') || '').split(/\\s+/).filter(Boolean).slice(0, 3).join('.')
      parts.push(cur.tagName.toLowerCase() + (id ? '#' + id : '') + (cls ? '.' + cls : ''))
    }
    return parts.join(' < ')
  }
  const isAbsorbed = (el) => {
    for (let cur = el; cur && cur !== document.body; cur = cur.parentElement) {
      const ox = getComputedStyle(cur).overflowX
      if (ox === 'auto' || ox === 'scroll' || ox === 'hidden' || ox === 'clip') return true
    }
    return false
  }
  const all = document.querySelectorAll('body *')
  for (let i = 0; i < all.length; i++) {
    const el = all[i]
    const r = el.getBoundingClientRect()
    if (r.right <= vw + 1 && r.left >= -1) continue
    if (r.width < 2 && r.height < 2) continue
    const absorbed = isAbsorbed(el)
    const seen = absorbed ? reportedAbs : reported
    let nested = false
    for (let anc = el.parentElement; anc; anc = anc.parentElement) {
      if (seen.has(anc)) { nested = true; break }
    }
    if (nested) continue
    seen.add(el)
    const line = describe(el) + ' [right=' + Math.round(r.right) + ' left=' + Math.round(r.left) + ' w=' + Math.round(r.width) + ']'
    if (absorbed) { if (absorbedWide.length < 6) absorbedWide.push(line) }
    else if (offenders.length < 8) offenders.push(line)
  }
  return JSON.stringify({ over, offenders, absorbed: absorbedWide })
})()`

async function measureOverflow(page: Page, shot: string, width: number, mode: string): Promise<void> {
  const result = JSON.parse(await page.evaluate(OVERFLOW_PROBE)) as { over: number; offenders: string[]; absorbed: string[] }
  if (result.over > 0) {
    overflowLedger.push({ shot, width, mode, over: result.over, offenders: result.offenders, absorbed: result.absorbed })
    flog(`OVERFLOW ${shot} ${width}px ${mode}: page +${result.over}px`)
    for (const o of result.offenders) flog(`  ↳ ${o}`)
    // The wide elements inside honest scrollers/clippers — innocent per
    // Chrome's scrollWidth semantics, listed so a stray cause never
    // hides behind the absorption rule (the registry page's empty
    // offenders at the baseline run).
    for (const o of result.absorbed) flog(`  ·(internal) ${o}`)
  }
}

/** The sweep's one step: every width × every mode, reload per mode (the
 *  theme key applies pre-paint), the settle selector waited, the
 *  toolbar hidden, the overflow measured, the shot taken. `prepare`
 *  runs after the reload (the crop dialog's file upload). */
async function sweep(page: Page, name: string, settle?: string, prepare?: (page: Page) => Promise<void>): Promise<void> {
  if (FILTER && !name.includes(FILTER)) return
  for (const w of WIDTHS) {
    await page.setViewport({ width: w, height: heightFor(w) })
    for (const mode of MODES) {
      // One width × mode failing (a cold-compile timeout, a page's own
      // error) never costs the rest of the audit — it lands in the log.
      try {
        await setMode(page, mode)
        if (prepare) await prepare(page)
        if (settle) await page.waitForSelector(settle, { timeout: 240_000 })
        await page.addStyleTag({ content: 'astro-dev-toolbar { display: none !important }' }).catch(() => {})
        const shot = `${name}-${w}`
        await measureOverflow(page, name, w, mode)
        await page.screenshot({ path: join(OUT_DIR, `${shot}-${mode}.png`), fullPage: FULLPAGE })
        flog(`shot ${shot} (${mode})`)
      } catch (e) {
        flog(`SWEEP-FAIL ${name}-${w} (${mode}): ${(e as Error).message?.split('\n')[0]}`)
      }
    }
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
    flog(`the stack stands (widths ${WIDTHS.join('/')}, modes ${MODES.join('+')})`)

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
    await sweep(page, '01-signin', '[data-testid="login-email"]')
    await page.goto(`${base}/op/join`, { waitUntil: 'domcontentloaded', timeout: 120_000 })
    await sweep(page, '02-join', '[data-testid="op-join"]')

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

    // 2 · The setup page on the REAL bootstrap token (every width, both
    //     modes), THEN the enrollment (which signs the session in).
    await page.goto(setupUrl, { waitUntil: 'domcontentloaded', timeout: 120_000 })
    await sweep(page, '03-setup', '[data-testid="op-setup-password"]')
    // The enrollment's own wait (a filtered sweep never settled the page —
    // the island still has to mount before the fields accept input).
    await page.waitForSelector('[data-testid="op-setup-password"]', { timeout: 240_000 })
    await page.evaluate(() => window.scrollTo(0, 0))
    await page.type('[data-testid="op-setup-password"]', ROOT.password)
    await page.type('[data-testid="op-setup-confirm"]', ROOT.password)
    await page.evaluate(() => (document.querySelector('[data-testid="op-setup-submit"]') as HTMLElement).click())
    await page.waitForSelector('[data-testid="account-name"]', { timeout: 240_000 })
    flog('enrolled; the session stands')

    // 3 · The account console, then the avatar crop dialog on top of it
    //     (the upload re-runs per width × mode: the reload wipes the
    //     dialog, the prepare opens it again).
    await sweep(page, '04-account', '[data-testid="account-name"]')
    await sweep(page, '05-account-crop', '[data-testid="account-avatar-crop-preview"]', async p => {
      await p.waitForSelector('[data-testid="account-avatar-input"]', { timeout: 240_000 })
      const input = await p.$('[data-testid="account-avatar-input"]') as import('puppeteer').ElementHandle<HTMLInputElement> | null
      await input!.uploadFile(photoPath)
      await p.waitForSelector('[data-testid="account-avatar-crop"]', { timeout: 60_000 })
    })

    // 4 · The launcher (the SSO home: the service cards + the sections).
    await page.goto(`${base}/op/home`, { waitUntil: 'domcontentloaded', timeout: 120_000 })
    await sweep(page, '06-home', '[data-testid="home"]')

    // 5 · The admin console: the overview dashboard, the registry home +
    //     the per-user/per-org details, and every sibling surface.
    const registryRows = await page.evaluate(async () => {
      const res = await fetch('/api/op/registry/users', { credentials: 'include' })
      return res.ok ? await res.json() as Array<{ id: string }> : []
    })
    const rootId = registryRows[0]?.id
    if (!rootId) throw new Error('the registry list carried no root row')
    const orgRows = await page.evaluate(async () => {
      const res = await fetch('/api/op/registry/orgs', { credentials: 'include' })
      return res.ok ? await res.json() as Array<{ id: string }> : []
    })
    const orgId = orgRows[0]?.id

    await page.goto(`${base}/op/admin/overview`, { waitUntil: 'domcontentloaded', timeout: 120_000 })
    await sweep(page, '07-admin-overview', '[data-testid="op-dash"]')

    // 5b · The console nav's disclosure sheet (TODO.identity-features/07's
    //     phone pattern): opened through the header's nav toggle at the
    //     sub-lg widths, measured with the sheet OPEN — the sheet itself
    //     must never scroll the page sideways. (At lg+ the rail is always
    //     on show and the toggle is hidden — nothing to open.)
    if (!FILTER || '07b-admin-nav-sheet'.includes(FILTER)) {
      // A filtered run may have skipped step 5's navigation — stand on
      // the admin overview first (the sheet's admin content is the
      // shot's subject).
      await page.goto(`${base}/op/admin/overview`, { waitUntil: 'domcontentloaded', timeout: 120_000 })
      await page.waitForSelector('[data-testid="op-dash"]', { timeout: 240_000 })
      for (const w of WIDTHS.filter(v => v < 1024)) {
        for (const mode of MODES) {
          try {
            await page.setViewport({ width: w, height: heightFor(w) })
            await setMode(page, mode)
            await page.waitForSelector('[data-testid="shell-nav-toggle"]', { timeout: 240_000 })
            await page.evaluate(() => (document.querySelector('[data-testid="shell-nav-toggle"]') as HTMLElement).click())
            await page.waitForSelector('#shell-console-nav:not(.hidden)', { timeout: 60_000 })
            await page.addStyleTag({ content: 'astro-dev-toolbar { display: none !important }' }).catch(() => {})
            await measureOverflow(page, '07b-admin-nav-sheet', w, mode)
            await page.screenshot({ path: join(OUT_DIR, `07b-admin-nav-sheet-${w}-${mode}.png`), fullPage: FULLPAGE })
            flog(`shot 07b-admin-nav-sheet-${w} (${mode})`)
          } catch (e) {
            flog(`SWEEP-FAIL 07b-admin-nav-sheet-${w} (${mode}): ${(e as Error).message?.split('\n')[0]}`)
          }
        }
      }
    }
    // /op/admin is the redirect to the overview; the registry settles at
    // its own route.
    await page.goto(`${base}/op/admin/registry`, { waitUntil: 'domcontentloaded', timeout: 120_000 })
    await sweep(page, '08-admin-registry', '[data-testid="op-reg"]')
    await page.goto(`${base}/op/admin/registry/users/${rootId}`, { waitUntil: 'domcontentloaded', timeout: 120_000 })
    await sweep(page, '09-admin-registry-user', '[data-testid="op-reg-user"]')
    if (orgId) {
      await page.goto(`${base}/op/admin/registry/orgs/${orgId}`, { waitUntil: 'domcontentloaded', timeout: 120_000 })
      await sweep(page, '10-admin-registry-org', '[data-testid="op-reg-org"]')
    } else {
      flog('NOTE: no org in the registry fixture — the org-detail shot is skipped')
    }
    await page.goto(`${base}/op/admin/users`, { waitUntil: 'domcontentloaded', timeout: 120_000 })
    await sweep(page, '11-admin-users', '[data-testid="op-admin-users"]')
    await page.goto(`${base}/op/admin/clients`, { waitUntil: 'domcontentloaded', timeout: 120_000 })
    await sweep(page, '12-admin-clients', '[data-testid="op-clients"]')
    await page.goto(`${base}/op/admin/activity`, { waitUntil: 'domcontentloaded', timeout: 120_000 })
    await sweep(page, '13-admin-activity', '[data-testid="op-act"]')
    await page.goto(`${base}/op/admin/providers`, { waitUntil: 'domcontentloaded', timeout: 120_000 })
    await sweep(page, '14-admin-providers', '[data-testid="op-providers"]')
    await page.goto(`${base}/op/admin/sessions`, { waitUntil: 'domcontentloaded', timeout: 120_000 })
    await sweep(page, '15-admin-sessions', '[data-testid="op-sess"]')
    await page.goto(`${base}/op/admin/security`, { waitUntil: 'domcontentloaded', timeout: 120_000 })
    await sweep(page, '16-admin-security', '[data-testid="op-sec"]')

    // 6 · The email-change confirmation on a REAL token (requested now,
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
      await sweep(page, '17-email-change', '[data-testid="op-email-change"]')
    } else {
      flog('NOTE: the email change answered without a shown link (a mailer configured?) — the page shot is skipped')
    }

    // 7 · The OIDC consent: the stub RP's authorize round trip, signed
    //     in, landing on the consent page. Rendered, never allowed.
    await page.goto(`${rp.baseUrl}/signin`, { waitUntil: 'domcontentloaded', timeout: 120_000 })
    await sweep(page, '18-consent', '[data-testid="op-consent-allow"]')

    // 8 · The 404.
    await page.goto(`${base}/this-page-is-not-here`, { waitUntil: 'domcontentloaded', timeout: 120_000 })
    await sweep(page, '19-not-found', '[data-testid="not-found-signin"]')

    // The audit's ledger: the shots that scroll sideways, machine-readable.
    writeFileSync(join(WORK_DIR, 'overflow-report.json'), JSON.stringify(overflowLedger, null, 2))
    flog(`the sweep is complete — ${overflowLedger.length} shot(s) with horizontal overflow (overflow-report.json)`)
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
