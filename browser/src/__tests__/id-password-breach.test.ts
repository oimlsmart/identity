// ─────────────────────────────────────────────────────────────────────
// TODO.identity-sso/04 slice B — the breached-password discipline,
// proven at the ROUTES in-process (the id-accounts/id-factors pattern:
// the real routers over a real temp SQLite store; the breach corpus is
// a real local HTTP stub answering the range API's shape — the
// deployment's HIBP_RANGE_URL seam, never a mock of the check):
//
//   REFUSE    a breached password is refused at the enrollment BEFORE
//             the one-time link burns (the same 400 then lets the SAME
//             link complete with a clean password);
//   ACCEPT    an unreachable corpus never strands the ceremony: the
//             password lands, the audit carries breachCheck:
//             'unreachable', and the per-account marker arms;
//   RE-CHECK  the next successful password sign-in re-runs the query
//             on the presented password — a clean verdict disarms the
//             marker, a BREACHED verdict never strands the sign-in
//             (the audit + the holder's feed carry it), and an account
//             with no marker pays NO query at all;
//   CHANGE    the console's password change runs the same judgment
//             (the current-password gate first), refusing a breached
//             candidate with the old password still in force.
// ─────────────────────────────────────────────────────────────────────

import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createServer, type Server } from 'node:http'
import type { AddressInfo } from 'node:net'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

// The store's DB path is read at module evaluation — set it before any
// import below touches the kernel (the imports are dynamic).
const TMP = mkdtempSync(join(tmpdir(), 'oiml-op-breach-'))
process.env.DATABASE_PATH = join(TMP, 'test.db')

const ISSUER = 'http://op.test'
process.env.OP_ISSUER = ISSUER

let app: import('hono').Hono
let store: ReturnType<typeof import('@oimlsmart/platform-server/store').getStore>

// ── the HIBP range stub (the real API's shape: GET /{prefix5} → the
//    SUFFIX:count lines, CRLF included) ──────────────────────────────

let hibp: Server
let hibpPort = 0
let hibpHits = 0
let hibpCorpus = new Set<string>()
/** A port with NOTHING listening (the unreachable-corpus posture: the
 *  connection refuses fast — the honest 'unknown' path). */
let closedPort = 0

/** The candidate's range suffix (the check's own math, run by the test). */
async function sha1Suffix(password: string): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-1', new TextEncoder().encode(password)))
  return [...digest].map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase().slice(5)
}

function pointHibpAt(url: string): void {
  process.env.HIBP_RANGE_URL = url
}

// ── the small drivers ────────────────────────────────────────────────

async function demoLogin(email: string): Promise<string> {
  const res = await app.request('/api/auth/demo', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password: 'demo2026' }),
  })
  expect(res.ok, `demo login ${email}`).toBe(true)
  return res.headers.get('set-cookie')!.split(';')[0]!
}

async function invite(email: string, name: string): Promise<{ id: string; token: string }> {
  const admin = await demoLogin('admin@oiml.org')
  const res = await app.request('/api/op/accounts', {
    method: 'POST',
    headers: { 'content-type': 'application/json', cookie: admin },
    body: JSON.stringify({ email, name }),
  })
  expect(res.status, `invite ${email}`).toBe(201)
  const { account, setupUrl } = await res.json() as { account: { id: string }; setupUrl: string }
  return { id: account.id, token: new URL(setupUrl).searchParams.get('token')! }
}

async function enrollRaw(token: string, password: string): Promise<Response> {
  return app.request(`/api/op/enroll/${token}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ password }),
  })
}

async function passwordLoginRaw(email: string, password: string): Promise<Response> {
  return app.request('/api/op/login', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password }),
  })
}

async function passwordCookie(email: string, password: string): Promise<string> {
  const res = await passwordLoginRaw(email, password)
  expect(res.status, `password login ${email}`).toBe(200)
  return res.headers.get('set-cookie')!.split(';')[0]!
}

interface AuditRow {
  action: string
  entity_type: string
  entity_id: string
  metadata: Record<string, unknown>
}

async function auditRowsFor(entityId: string, action: string): Promise<AuditRow[]> {
  const rows = await store.listEntities('auditEvents')
  return rows
    .map(r => JSON.parse(r.data) as AuditRow)
    .filter(e => e.entity_id === entityId && e.action === action)
}

async function recheckMarker(userId: string): Promise<{ pending: boolean } | undefined> {
  const row = await store.getEntity('opPasswordBreach', userId)
  return row ? JSON.parse(row.data) as { pending: boolean } : undefined
}

async function auditCount(action: string): Promise<number> {
  const rows = await store.listEntities('auditEvents')
  return rows.map(r => JSON.parse(r.data) as AuditRow).filter(e => e.action === action).length
}

beforeAll(async () => {
  // The range stub: every configured suffix answers as breached; the hit
  // counter proves the no-marker-no-query pin.
  hibp = createServer((req, res) => {
    hibpHits += 1
    const body = [...hibpCorpus].map(s => `${s}:137`).join('\r\n')
    res.writeHead(200, { 'content-type': 'text/plain' })
    res.end(body ? `${body}\r\n` : '')
    void req
  })
  await new Promise<void>((resolve) => hibp.listen(0, '127.0.0.1', resolve))
  hibpPort = (hibp.address() as AddressInfo).port
  pointHibpAt(`http://127.0.0.1:${hibpPort}`)

  // The guaranteed-closed port (bound, named, released).
  const probe = createServer()
  await new Promise<void>((resolve) => probe.listen(0, '127.0.0.1', resolve))
  closedPort = (probe.address() as AddressInfo).port
  await new Promise<void>((resolve) => { probe.close(() => resolve()) })

  const { installSqliteStore } = await import('@oimlsmart/platform-server/store/sqlite')
  store = installSqliteStore()
  const profileMod = await import('@oimlsmart/platform-server/profile')
  profileMod.installInstanceProfile(profileMod.parseInstanceProfile(`
identity:
  org_id: oimlsmart-id
  org_name: OIML SMART Identity
  role_codes: [identity]
roles: [identity]
branding: { name: OIML SMART Identity }
demo_personas: true
`))

  const { Hono } = await import('hono')
  const { createAuthLeanRouter } = await import('../../server/routes/auth-lean')
  const { createOpAccountsRouter } = await import('../../server/routes/op-accounts')
  const root = new Hono()
  root.route('/api/auth', createAuthLeanRouter({ autoSeedDemo: true }))
  root.route('/', createOpAccountsRouter())
  app = root
  await demoLogin('admin@oiml.org') // the bootstrap seed lands on the first OP request
}, 120_000)

afterAll(async () => {
  await new Promise<void>((resolve) => { hibp.close(() => resolve()) })
  rmSync(TMP, { recursive: true, force: true })
  delete process.env.OP_ISSUER
  delete process.env.DATABASE_PATH
  // The suite-wide posture restored (vitest.config.ts's test.env): a
  // leaked deletion would turn a later file in this worker's process
  // toward the LIVE corpus.
  process.env.HIBP_RANGE_URL = 'off'
  const profileMod = await import('@oimlsmart/platform-server/profile')
  profileMod.resetInstanceProfileForTest()
})

describe('TODO.identity-sso/04 slice B — the breached-password discipline', () => {
  const ONE = { email: 'b-one@example.org', name: 'Bea One', breached: 'one breached passphrase', clean: 'one clean passphrase' }
  const TWO = { email: 'b-two@example.org', name: 'Bea Two', first: 'two first passphrase', next: 'two next passphrase', breached: 'two breached passphrase' }
  let twoId = '' // leg 2's account, shared by the re-check legs

  it('REFUSE: a breached password is refused BEFORE the one-time link burns', { timeout: 60_000 }, async () => {
    const { id, token } = await invite(ONE.email, ONE.name)
    hibpCorpus = new Set([await sha1Suffix(ONE.breached)])

    const refused = await enrollRaw(token, ONE.breached)
    expect(refused.status, 'the breached candidate is refused').toBe(400)
    expect(await refused.json().then(b => (b as { error: string }).error)).toContain('known data breach')

    // The link stands: its context still answers, and the SAME link
    // completes with a clean password — clean means NO marker and no
    // audit note.
    const context = await app.request(`/api/op/enroll/${token}`)
    expect(context.status, 'the refusal never burned the link').toBe(200)
    hibpCorpus = new Set()
    const done = await enrollRaw(token, ONE.clean)
    expect(done.status, 'the same link completes with a clean password').toBe(200)
    expect(await recheckMarker(id), 'a clean check arms no marker').toBeUndefined()
    const enrolled = await auditRowsFor(id, 'account.enrolled')
    expect(enrolled).toHaveLength(1)
    expect(enrolled[0]!.metadata.breachCheck, 'a clean check leaves no audit note').toBeUndefined()
  })

  it('ACCEPT: an unreachable corpus accepts, notes the audit, and arms the re-check', { timeout: 60_000 }, async () => {
    pointHibpAt(`http://127.0.0.1:${closedPort}`)
    const { id, token } = await invite(TWO.email, TWO.name)
    twoId = id
    const res = await enrollRaw(token, TWO.first)
    expect(res.status, 'the unreachable corpus never strands the ceremony').toBe(200)

    const enrolled = await auditRowsFor(id, 'account.enrolled')
    expect(enrolled).toHaveLength(1)
    expect(enrolled[0]!.metadata.breachCheck, 'the audit names the skipped check').toBe('unreachable')
    expect((await recheckMarker(id))?.pending, 'the re-check marker is armed').toBe(true)
  })

  it('RE-CHECK clean: the next password sign-in re-runs the query and disarms the marker', { timeout: 60_000 }, async () => {
    pointHibpAt(`http://127.0.0.1:${hibpPort}`)
    hibpCorpus = new Set() // the corpus answers clean

    const hits = hibpHits
    const res = await passwordLoginRaw(TWO.email, TWO.first)
    expect(res.status).toBe(200)
    expect(hibpHits, 'the marker drove exactly one query').toBe(hits + 1)

    const rechecks = await auditRowsFor(twoId, 'account.password_breach_recheck')
    expect(rechecks).toHaveLength(1)
    expect(rechecks[0]!.metadata.outcome).toBe('clean')
    expect(await recheckMarker(twoId), 'a definitive verdict disarms the marker').toBeUndefined()
  })

  it('RE-CHECK breached: a breached verdict never strands the sign-in; the chain carries it', { timeout: 60_000 }, async () => {
    // Re-arm the marker through the console's password change with the
    // corpus down (the change path's own accept-and-arm half).
    const cookie = await passwordCookie(TWO.email, TWO.first)
    pointHibpAt(`http://127.0.0.1:${closedPort}`)
    const changed = await app.request('/api/op/account/password', {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ current: TWO.first, next: TWO.next }),
    })
    expect(changed.status, 'the unreachable corpus accepts the change').toBe(200)
    expect((await recheckMarker(twoId))?.pending).toBe(true)
    const passwordAudits = await auditRowsFor(twoId, 'account.password')
    expect(passwordAudits[0]!.metadata.breachCheck, 'the change carries the note too').toBe('unreachable')

    // The corpus returns, now carrying the password: the sign-in STILL
    // completes (the holder is in) and the verdict lands on the chain.
    pointHibpAt(`http://127.0.0.1:${hibpPort}`)
    hibpCorpus = new Set([await sha1Suffix(TWO.next)])
    const rechecksBefore = await auditRowsFor(twoId, 'account.password_breach_recheck')
    const res = await passwordLoginRaw(TWO.email, TWO.next)
    expect(res.status, 'a breached verdict at the re-check never strands the sign-in').toBe(200)
    const rechecks = await auditRowsFor(twoId, 'account.password_breach_recheck')
    expect(rechecks.length, 'this sign-in adds exactly one re-check event').toBe(rechecksBefore.length + 1)
    expect(rechecks.at(-1)!.metadata.outcome).toBe('breached')
    expect(await recheckMarker(twoId), 'the breached verdict disarms too (the chain carries it)').toBeUndefined()
  })

  it('NO MARKER, NO QUERY: an ordinary sign-in never touches the corpus', { timeout: 60_000 }, async () => {
    const hits = hibpHits
    const res = await passwordLoginRaw(TWO.email, TWO.next)
    expect(res.status).toBe(200)
    expect(hibpHits, 'no marker armed → no query').toBe(hits)
  })

  it('CHANGE: the console change refuses a breached candidate with the old password in force', { timeout: 60_000 }, async () => {
    const cookie = await passwordCookie(TWO.email, TWO.next)
    hibpCorpus = new Set([await sha1Suffix(TWO.breached)])
    const passwordRowsBefore = await auditCount('account.password')

    const refused = await app.request('/api/op/account/password', {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ current: TWO.next, next: TWO.breached }),
    })
    expect(refused.status, 'the breached candidate is refused').toBe(400)
    expect(await refused.json().then(b => (b as { error: string }).error)).toContain('known data breach')

    // No mutation landed: the audit count is unchanged and the CURRENT
    // password still signs in.
    expect(await auditCount('account.password'), 'the refusal wrote no account.password event').toBe(passwordRowsBefore)
    expect((await passwordLoginRaw(TWO.email, TWO.next)).status, 'the old password still signs in').toBe(200)
  })
})
