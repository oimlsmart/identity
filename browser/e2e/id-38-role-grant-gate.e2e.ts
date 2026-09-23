// ═══════════════════════════════════════════════════════════════════
// TODO.identity-sso/04 (the account lifecycle discipline, the tail) —
// the VERIFICATION GATE on the role grants over the real booted stack
// (the id-31 shape: no browser ceremony is the subject — the gate lives
// in the routes, so the legs ride real HTTP against the astro front
// door):
//
//   leg 1  the per-client grant to the never-verified invited account
//          answers the honest 409 (naming the unverified primary) and
//          mails NOTHING; the explicit-empty set stays allowed (it
//          grants nothing); the setup link's completion lifts the gate
//          (the grant lands, the holder mails);
//   leg 2  the users route's reassignment answers the same 409 for a
//          privileged set on the unverified OP account; the demotion to
//          the viewer baseline stays allowed; the demo cast (fictional
//          mailboxes, unverified by design) keeps its standing behavior;
//   leg 3  the invite's own client_roles land at invite time (the setup
//          link IS the verification channel — the carve-out), and the
//          account verifies when the link completes.
//
// The stack binds the stub mailer (the id-32 posture) so the notice
// assertions read real captures; HIBP is declared OFF (slice B's env).
//
// SELF-CONTAINED: own ports (API 10651 / astro 10652 / mailer stub
// 10653 — above id-37's 10647-10650), own SQLite file.
// ═══════════════════════════════════════════════════════════════════

import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import { spawn, type ChildProcess } from 'node:child_process'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { existsSync, mkdirSync, rmSync, cpSync, appendFileSync } from 'node:fs'
import { delay } from './helpers'
import { fixtureOpSigningKey } from './fixtures/op-signing-key'
import { startStubMailer, type StubMailer } from './fixtures/stub-mailer'

const BROWSER_DIR = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const FIXTURES = join(BROWSER_DIR, 'e2e', 'fixtures')
const DB_DIR = join(BROWSER_DIR, '.cache', 'id-38')

// Port-isolated: above id-37's 10647-10650.
const ID_API = 10651
const ID_WEB = 10652
const MAIL_PORT = 10653

const ISSUER = `http://localhost:${ID_WEB}` // the astro origin (the browser's OP)
const MAIL_KEY = 'id38-stub-mail-key'
const PRODUCT = 'OIML SMART Identity'

const ROOT = { email: 'root@oimlsmart.org', name: 'Root Operator', password: 'the root operator passphrase' }

interface Stack {
  api: ChildProcess
  astro: ChildProcess
  base: string
  apiBase: string
  logs: string[]
}

function spawnLogged(cmd: string, args: string[], env: NodeJS.ProcessEnv, logs: string[]): ChildProcess {
  // detached (the process group dies together); the env SCRUBS the vitest
  // markers (NODE_ENV=test would poison the spawned astro's vite cache).
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

/** Boot the identity-profile stack with the mail provider bound to the
 *  stub (the id-32 posture) + the breach corpus declared OFF. */
async function bootIdentityStack(mailer: StubMailer): Promise<Stack> {
  const logs: string[] = []
  mkdirSync(DB_DIR, { recursive: true })
  const dbPath = join(DB_DIR, 'identity.db')
  for (const suffix of ['', '-wal', '-shm']) rmSync(dbPath + suffix, { force: true })
  rmSync(PROGRESS_LOG, { force: true })

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
      OP_ISSUER: ISSUER,
      OP_SIGNING_KEY: await fixtureOpSigningKey(),
      OP_ACCOUNT_SEED: JSON.stringify([{ email: ROOT.email, name: ROOT.name, role: 'admin' }]),
      OP_CLIENT_SEED: JSON.stringify([{
        client_id: 'hub-instance',
        name: 'OIML SMART platform hub',
        secret: 'hub-secret-123',
        redirect_uris: ['https://hub.example/api/auth/callback/oidc'],
        claims_policy: { claims: ['roles', 'groups', 'org'] },
      }]),
      EMAIL_FROM: 'OIML SMART Identity <no-reply@oimlsmart.org>',
      MAIL_PROVIDER_URL: `${mailer.baseUrl}/emails`,
      MAIL_PROVIDER_KEY: MAIL_KEY,
      HIBP_RANGE_URL: 'off',
    }, logs)
    const apiBase = `http://localhost:${ID_API}`
    await waitForHttp(`${apiBase}/api/health`, 120_000, logs)

    const reset = await fetch(`${apiBase}/api/dev-reset`, { method: 'POST' })
    if (!reset.ok) throw new Error(`dev-reset on ${apiBase} answered ${reset.status}\n${logs.join('').slice(-2000)}`)

    const seedProbe = await fetch(`${apiBase}/api/op/login`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: 'nobody@example.org', password: 'a probe, not a password' }),
    })
    if (seedProbe.status !== 401) throw new Error(`the OP login probe answered ${seedProbe.status} (401 expected)\n${logs.join('').slice(-2000)}`)

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

const PROGRESS_LOG = join(DB_DIR, 'progress.log')
function flog(msg: string): void {
  const line = `${new Date().toISOString()} ${msg}\n`
  try { appendFileSync(PROGRESS_LOG, line) } catch { /* the log never breaks the leg */ }
}

async function passwordCookie(base: string, email: string, password: string): Promise<string> {
  const res = await fetch(`${base}/api/op/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password }),
  })
  expect(res.ok, `password sign-in ${email}`).toBe(true)
  await new Promise(r => setTimeout(r, 50)) // the notice rides beside the answer (TODO.restructure/27)
  return res.headers.get('set-cookie')!.split(';')[0]!.split('=')[1]!
}

/** The bare invite (NO enrollment — the account stays unverified);
 *  answers the account id + the setup URL. */
async function inviteAccount(base: string, rootCookie: string, email: string, name: string, body: Record<string, unknown> = {}): Promise<{ id: string; setupUrl: string }> {
  const invite = await fetch(`${base}/api/op/accounts`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', cookie: `oiml-session=${rootCookie}` },
    body: JSON.stringify({ email, name, ...body }),
  })
  expect(invite.status, `the invite of ${email}`).toBe(201)
  const { account, setupUrl } = await invite.json() as { account: { id: string }; setupUrl: string }
  return { id: account.id, setupUrl }
}

/** Complete the one-time setup link (the mailbox proof — stamps
 *  emailVerifiedAt); answers the fresh session cookie value. */
async function enroll(base: string, setupUrl: string, password: string): Promise<string> {
  const res = await fetch(`${base}/api/op/enroll/${new URL(setupUrl).searchParams.get('token')}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ password }),
  })
  expect(res.status, 'the enrollment completes').toBe(200)
  return res.headers.get('set-cookie')!.split(';')[0]!.split('=')[1]!
}

/** The admin's registry detail read (the verification state's honest
 *  surface — the console's pill reads the same field). */
async function registryDetail(base: string, rootCookie: string, id: string): Promise<{ emailVerifiedAt: string | null }> {
  const res = await fetch(`${base}/api/op/registry/users/${id}`, { headers: { cookie: `oiml-session=${rootCookie}` } })
  expect(res.status, 'the registry detail answers').toBe(200)
  return ((await res.json()) as { account: { emailVerifiedAt: string | null } }).account
}

describe('TODO.identity-sso/04 (the lifecycle tail) — the role-grant verification gate (the identity profile)', () => {
  let stack: Stack
  let mailer: StubMailer
  let rootCookie: string

  beforeAll(async () => {
    mailer = await startStubMailer({ expectedKey: MAIL_KEY, port: MAIL_PORT })
    stack = await bootIdentityStack(mailer)

    // The root admin's password through the boot-logged setup link (the
    // id-29 bootstrap posture).
    const deadline = Date.now() + 60_000
    let setupUrl = ''
    while (Date.now() < deadline) {
      const m = /bootstrap: account root@oimlsmart\.org has no password[^\n]*\n\s*(\S+\/op\/setup\?token=\S+)/.exec(stack.logs.join(''))
      if (m) { setupUrl = m[1]!; break }
      await delay(500)
    }
    expect(setupUrl, 'the bootstrap setup link in the boot log').toContain('/op/setup?token=')
    await enroll(stack.base, setupUrl, ROOT.password)
    rootCookie = await passwordCookie(stack.base, ROOT.email, ROOT.password)
    mailer.reset() // the bootstrap's mails are not the arc's subject
  }, 600_000)

  afterAll(async () => {
    await mailer?.close()
    await stopStack(stack)
  })

  it('leg 1 — the per-client grant refuses the never-verified account (409, no mail); the completion lifts the gate', { timeout: 900_000 }, async () => {
    const { id, setupUrl } = await inviteAccount(stack.base, rootCookie, 'ida@example.org', 'Ida Invite')
    expect((await registryDetail(stack.base, rootCookie, id)).emailVerifiedAt, 'the invited account is unverified').toBeNull()

    mailer.reset()
    const refused = await fetch(`${stack.base}/api/op/accounts/${id}/client-roles/hub-instance`, {
      method: 'PUT',
      headers: { 'content-type': 'application/json', cookie: `oiml-session=${rootCookie}` },
      body: JSON.stringify({ roles: ['cs_admin'] }),
    })
    expect(refused.status, 'the grant to the unverified account is refused').toBe(409)
    const refusal = await refused.json() as { error: string }
    expect(refusal.error).toContain('has not verified its primary email address')
    expect(refusal.error).toContain('ida@example.org')
    expect(mailer.messages.filter(m => m.subject === `New access was granted on your ${PRODUCT} account`),
      'the refusal never mails a "roles granted" notice').toHaveLength(0)
    flog('leg1: the refusal answered 409 + silent')

    // The empty set grants nothing — the corrective direction stays open.
    const emptied = await fetch(`${stack.base}/api/op/accounts/${id}/client-roles/hub-instance`, {
      method: 'PUT',
      headers: { 'content-type': 'application/json', cookie: `oiml-session=${rootCookie}` },
      body: JSON.stringify({ roles: [] }),
    })
    expect(emptied.status).toBe(200)

    // The setup link's completion (the mailbox proof) lifts the gate.
    await enroll(stack.base, setupUrl, 'ida has a proper passphrase')
    expect((await registryDetail(stack.base, rootCookie, id)).emailVerifiedAt, 'the completion stamped the verification').not.toBeNull()

    mailer.reset()
    const grant = await fetch(`${stack.base}/api/op/accounts/${id}/client-roles/hub-instance`, {
      method: 'PUT',
      headers: { 'content-type': 'application/json', cookie: `oiml-session=${rootCookie}` },
      body: JSON.stringify({ roles: ['cs_admin'] }),
    })
    expect(grant.status, 'the verified account takes the grant').toBe(200)
    const notices = mailer.messages.filter(m => m.subject === `New access was granted on your ${PRODUCT} account`)
    expect(notices, 'the landed grant mails the holder').toHaveLength(1)
    expect(notices[0]!.to).toBe('ida@example.org')
    flog('leg1: done')
  })

  it('leg 2 — the users route answers the same gate; the demotion + the demo cast stay open', { timeout: 900_000 }, async () => {
    const { id, setupUrl } = await inviteAccount(stack.base, rootCookie, 'ursa@example.org', 'Ursa Users')

    const refused = await fetch(`${stack.base}/api/users/${id}/roles`, {
      method: 'PUT',
      headers: { 'content-type': 'application/json', cookie: `oiml-session=${rootCookie}` },
      body: JSON.stringify({ role: 'ia_officer', roles: ['ia_officer'] }),
    })
    expect(refused.status, 'the privileged reassignment to the unverified account is refused').toBe(409)
    expect(((await refused.json()) as { error: string }).error).toContain('has not verified its primary email address')

    // The demotion to the viewer baseline grants nothing — never refused.
    const demote = await fetch(`${stack.base}/api/users/${id}/roles`, {
      method: 'PUT',
      headers: { 'content-type': 'application/json', cookie: `oiml-session=${rootCookie}` },
      body: JSON.stringify({ role: 'viewer', roles: ['viewer'] }),
    })
    expect(demote.status).toBe(200)

    // The mailbox proof lifts the gate here too.
    await enroll(stack.base, setupUrl, 'ursa has a proper passphrase')
    const grant = await fetch(`${stack.base}/api/users/${id}/roles`, {
      method: 'PUT',
      headers: { 'content-type': 'application/json', cookie: `oiml-session=${rootCookie}` },
      body: JSON.stringify({ role: 'ia_officer', roles: ['ia_officer'] }),
    })
    expect(grant.status).toBe(200)

    // The demo cast: fictional mailboxes, unverified by design — the gate
    // is the OP password accounts', never theirs.
    const users = await (await fetch(`${stack.base}/api/users`, { headers: { cookie: `oiml-session=${rootCookie}` } })).json() as Array<{ id: string; email: string; role: string; roles: string[]; provider: string }>
    const biml = users.find(u => u.email === 'biml@oimlsmart.org')!
    expect(biml.provider).toBe('demo')
    const demoGrant = await fetch(`${stack.base}/api/users/${biml.id}/roles`, {
      method: 'PUT',
      headers: { 'content-type': 'application/json', cookie: `oiml-session=${rootCookie}` },
      body: JSON.stringify({ role: 'biml_officer', roles: ['biml_officer'] }),
    })
    expect(demoGrant.status, 'the demo cast keeps its standing behavior').toBe(200)
    await fetch(`${stack.base}/api/users/${biml.id}/roles`, {
      method: 'PUT',
      headers: { 'content-type': 'application/json', cookie: `oiml-session=${rootCookie}` },
      body: JSON.stringify({ role: biml.role, roles: biml.roles }),
    }) // restore the fixture state
    flog('leg2: done')
  })

  it('leg 3 — the invite-time client_roles land (the carve-out); the account verifies at the link\'s completion', { timeout: 900_000 }, async () => {
    const { id, setupUrl } = await inviteAccount(stack.base, rootCookie, 'ines@example.org', 'Ines Invite', {
      client_roles: [{ client_id: 'hub-instance', roles: ['ia_officer'] }],
    })

    // The grant stands while the account is still unverified (the setup
    // link IS the verification channel) — the registry list carries it.
    const accounts = await (await fetch(`${stack.base}/api/op/accounts`, { headers: { cookie: `oiml-session=${rootCookie}` } })).json() as Array<{ id: string; clientRoles: Array<{ clientId: string; roles: string[] }> }>
    const row = accounts.find(a => a.id === id)!
    expect(row.clientRoles.find(a => a.clientId === 'hub-instance')?.roles, 'the invite-time grant landed').toEqual(['ia_officer'])
    expect((await registryDetail(stack.base, rootCookie, id)).emailVerifiedAt, '…while the account is still unverified').toBeNull()

    const cookie = await enroll(stack.base, setupUrl, 'ines has a proper passphrase')
    const context = await (await fetch(`${stack.base}/api/op/account`, { headers: { cookie: `oiml-session=${cookie}` } })).json() as { account: { emailVerifiedAt: string | null } }
    expect(context.account.emailVerifiedAt, 'the completion stamps the mailbox proof').not.toBeNull()
    flog('leg3: done')
  })
})
