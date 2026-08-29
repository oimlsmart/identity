// ─────────────────────────────────────────────────────────────────────
// The developer tokens (TODO.identity-features/08 — the personal access
// tokens), proven in-process: the REAL op + op-tokens + op-registry
// routers over a REAL temp SQLite store, the demo cast for the accounts,
// and the OP's own JWKS verifying the exchanged JWTs (the RP's posture —
// no stub anywhere).
//
// Covered:
//   THE MINT         — the console route's validation: the name bounds,
//                      the scope grammar (a malformed cell, an empty set,
//                      an unknown service, a DEVICE-class service refuse),
//                      the account-side narrowing bound (a viewer's write
//                      refuses, an officer's admin refuses, a scope past
//                      the holder's cone never lands), the expiration
//                      bounds (mandatory, ≤ 1 year); the ONE-TIME display
//                      (the answer carries the plaintext once; the store
//                      row + the list answer never do); the audit event +
//                      the mint email through the mailer's console
//                      posture.
//   THE EXCHANGE     — the RFC 8693 grant's lattice: the valid exchange
//     (the token     mints the scoped OP JWT (the claims verified against
//      endpoint)      the JWKS: sub, aud, scope, service_roles, org, pat);
//                      unknown / expired / revoked / deactivated-account
//                      all answer the ONE invalid_grant; the wrong
//                      subject_token_type answers invalid_request; the
//                      per-exchange scope parameter narrows, never widens
//                      (invalid_scope); the standing re-judgment narrows
//                      a token whose account LOST a role since the mint
//                      (the granted set honestly shrinks, the audit names
//                      the drop); the throttled heartbeat stamps
//                      last_used_at and beats the audit once.
//   THE INVENTORY    — the org detail route carries the members' tokens
//                      (the metadata only), the holder resolved.
//   THE ERASURE      — the account's erasure carries the tokens out (the
//                      exchange never resolves a tombstone's token).
// ─────────────────────────────────────────────────────────────────────

import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

// The store's DB path is read at module evaluation — set it before any
// import below touches @oimlsmart/platform-server/store/sqlite (the
// imports are dynamic).
const TMP = mkdtempSync(join(tmpdir(), 'oiml-op-pat-'))
process.env.DATABASE_PATH = join(TMP, 'test.db')

const ISSUER = 'http://op.test'
process.env.OP_ISSUER = ISSUER

// The estate's services for the lattice: the hub (the RP the lab CLI
// talks to) + the register; the device client proves the machine cone is
// never a PAT's service.
const HUB = { clientId: 'hub-instance', name: 'OIML SMART platform hub', claims: ['roles', 'groups', 'org'] }
const REGISTER = { clientId: 'register-instance', name: 'The OIML register', claims: ['roles'] }

let app: import('hono').Hono
let store: ReturnType<typeof import('@oimlsmart/platform-server/store').getStore>

async function demoLogin(email: string): Promise<string> {
  const res = await app.request('/api/auth/demo', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password: 'demo2026' }),
  })
  expect(res.ok, `demo login ${email}`).toBe(true)
  return res.headers.get('set-cookie')!.split(';')[0]!
}

/** The console's mint act. */
async function mintPat(cookie: string, body: Record<string, unknown>): Promise<Response> {
  return app.request(`${ISSUER}/api/op/account/tokens`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', cookie },
    body: JSON.stringify(body),
  })
}

/** The RFC 8693 exchange at the token endpoint. */
async function exchange(pat: string, extra?: Record<string, string>): Promise<Response> {
  const body = new URLSearchParams({
    grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
    subject_token_type: 'urn:oimlsmart:params:oauth:token-type:pat',
    subject_token: pat,
    ...extra,
  })
  return app.request(`${ISSUER}/op/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body,
  })
}

function base64urlDecode(s: string): Uint8Array {
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice(0, (4 - (s.length % 4)) % 4)
  const bin = atob(b64)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

function decodePart(s: string): Record<string, unknown> {
  return JSON.parse(new TextDecoder().decode(base64urlDecode(s))) as Record<string, unknown>
}

/** Verify the exchanged JWT against the OP's OWN JWKS (the RP's
 *  validation posture) and answer its claims. */
async function verifyOpJwt(token: string): Promise<Record<string, unknown>> {
  const [h, p, s] = token.split('.')
  expect(s, 'a 3-part JWT').toBeTruthy()
  const header = decodePart(h!)
  const jwks = await (await app.request(`${ISSUER}/jwks.json`)).json() as { keys: Array<{ kid?: string; x: string; y: string }> }
  const jwk = jwks.keys.find(k => k.kid === header.kid)
  expect(jwk, 'the signing key is on the JWKS').toBeTruthy()
  const key = await crypto.subtle.importKey(
    'jwk',
    { kty: 'EC', crv: 'P-256', x: jwk!.x, y: jwk!.y },
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['verify'],
  )
  const ok = await crypto.subtle.verify(
    { name: 'ECDSA', hash: 'SHA-256' },
    key,
    base64urlDecode(s!) as BufferSource,
    new TextEncoder().encode(`${h}.${p}`),
  )
  expect(ok, 'the exchanged token verifies against the OP’s JWKS').toBe(true)
  return decodePart(p!)
}

/** The audit journal (the store directly). */
async function journal(): Promise<Array<{ action: string; entity_type: string; entity_id: string; metadata?: Record<string, unknown> }>> {
  return (await store.listEntities('auditEvents')).map(row => JSON.parse(row.data) as never)
}

beforeAll(async () => {
  // The simulated deployment declares its signing key (identity#7's
  // gate: the round trips verify against the JWKS — the production
  // posture).
  const { generateSuccessorPair } = await import('../../scripts/op-key-rotate')
  process.env.OP_SIGNING_KEY = (await generateSuccessorPair()).privateJwkJson

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
  const { createOpRouter } = await import('../../server/routes/op')
  const { createOpTokensRouter } = await import('../../server/routes/op-tokens')
  const { createOpRegistryRouter } = await import('../../server/routes/op-registry')
  const root = new Hono()
  root.route('/api/auth', createAuthLeanRouter({ autoSeedDemo: true }))
  root.route('/', createOpRouter())
  root.route('/', createOpTokensRouter())
  root.route('/', createOpRegistryRouter())
  app = root

  // The estate's services: two application-class clients + a device-class
  // one (the machine cone is never a PAT's service).
  for (const c of [HUB, REGISTER]) {
    await store.upsertOidcClient({
      clientId: c.clientId,
      name: c.name,
      secretHash: null,
      redirectUris: [`https://${c.clientId}.example/callback`],
      claimsPolicy: { claims: c.claims },
      createdBy: 'the test seed',
    })
  }
  await store.upsertOidcClient({
    clientId: 'device-acme-lc500-0001',
    name: 'ACME LC-500 (the twin)',
    secretHash: 'pbkdf2:1:x:x',
    redirectUris: [],
    claimsPolicy: { claims: [], class: 'device', device: { id: 'acme-lc500-sn-0001', org: 'mfr-acme', instrument_model: 'acme-lc500@2021' } } as never,
    createdBy: 'the test seed',
  })

  // The inventory leg's org: the demo IA's EX1 on the registry.
  await store.createOrgRegistryOrg({
    id: 'EX1',
    name: 'The Example Issuing Authority',
    shortName: 'EX1',
    kind: 'issuing-authority',
    country: 'Example Member State',
    contacts: [],
    participantRef: null,
    createdBy: 'the test seed',
  })

  await demoLogin('admin@oiml.org') // the demo cast lands
})

afterAll(() => {
  rmSync(TMP, { recursive: true, force: true })
  delete process.env.OP_ISSUER
  delete process.env.OP_SIGNING_KEY
  delete process.env.DATABASE_PATH
})

// ── the mint's validation ────────────────────────────────────────────

describe('the mint (the console act)', () => {
  it('mints for the officer: the plaintext answers ONCE, the store holds only the hash, the audit + the email land', async () => {
    const ia = await demoLogin('ia@oiml.org')
    const res = await mintPat(ia, { name: 'the lab CLI', scopes: [`${HUB.clientId}:read`, `${HUB.clientId}:write`, `${REGISTER.clientId}:read`] })
    expect(res.status).toBe(201)
    const body = await res.json() as { token: { id: string; plaintext: string; prefix: string; scopes: string[]; expiresAt: string; state: string } }
    expect(body.token.plaintext.startsWith('ospt_'), 'the wire prefix').toBe(true)
    expect(body.token.prefix).toBe(body.token.plaintext.slice(0, 13))
    expect(body.token.state).toBe('active')
    // The default expiration: 90 days.
    const days = (new Date(body.token.expiresAt).getTime() - Date.now()) / 86_400_000
    expect(Math.round(days)).toBe(90)

    // The store NEVER holds the plaintext — the hash, the prefix, and
    // nothing reversible.
    const row = (await store.getPersonalAccessToken(body.token.id))!
    expect(row.tokenHash).not.toBe(body.token.plaintext)
    expect(row.tokenHash).toMatch(/^[0-9a-f]{64}$/)
    expect(JSON.stringify(row)).not.toContain(body.token.plaintext)

    // The list answer carries the metadata only — never the plaintext,
    // never the hash.
    const list = await (await app.request(`${ISSUER}/api/op/account/tokens`, { headers: { cookie: ia } })).json() as { tokens: Array<Record<string, unknown>>; services: Array<{ id: string; maxAction: string }> }
    const listed = list.tokens.find(t => t.id === body.token.id)!
    expect(listed.plaintext, 'the list never re-answers the plaintext').toBeUndefined()
    expect(JSON.stringify(listed)).not.toContain(row.tokenHash)
    expect(listed.scopes).toEqual([`${HUB.clientId}:write`, `${REGISTER.clientId}:read`]) // the widest fold + the sort
    // The picker's catalog: the officer enters both services with the
    // write class (ia_officer holds workflow permissions, never the
    // admin class); the device client never shows.
    const hub = list.services.find(s => s.id === HUB.clientId)!
    expect(hub.maxAction).toBe('write')
    expect(list.services.some(s => s.id === 'device-acme-lc500-0001'), 'the machine cone never shows').toBe(false)

    // The audit chain carries the mint; the mint email rode the mailer
    // (the console posture logs it — the audit names the template).
    const events = await journal()
    const minted = events.find(e => e.action === 'account.pat_minted' && e.metadata?.pat === body.token.id)
    expect(minted, 'the mint is on the audit chain').toBeTruthy()
    const mailed = events.find(e => e.entity_type === 'email' && (e.metadata as { template?: string })?.template === 'pat_minted')
    expect(mailed, 'the mint notification rode the mailer').toBeTruthy()
  })

  it('refuses the malformed + the over-broad, honestly', async () => {
    const ia = await demoLogin('ia@oiml.org')
    // The grammar refuses: a malformed cell, the empty set, a bare string.
    expect((await mintPat(ia, { name: 'x', scopes: ['hub'] })).status).toBe(400)
    expect((await mintPat(ia, { name: 'x', scopes: [] })).status).toBe(400)
    expect((await mintPat(ia, { name: 'x', scopes: `${HUB.clientId}:read` })).status).toBe(400)
    // The unknown service refuses.
    const unknown = await mintPat(ia, { name: 'x', scopes: ['no-such-service:read'] })
    expect(unknown.status).toBe(403)
    expect(((await unknown.json()) as { error: string }).error).toContain('no-such-service')
    // The device-class service refuses (the machine cone is not a PAT's).
    expect((await mintPat(ia, { name: 'x', scopes: ['device-acme-lc500-0001:read'] })).status).toBe(403)
    // The officer's admin class refuses (ia_officer holds no
    // administration permission — the narrowing bound).
    const admin = await mintPat(ia, { name: 'x', scopes: [`${HUB.clientId}:admin`] })
    expect(admin.status).toBe(403)
    expect(((await admin.json()) as { error: string }).error).toContain('administration')
    // The expiration is mandatory + bounded.
    expect((await mintPat(ia, { name: 'x', scopes: [`${HUB.clientId}:read`], expiresInDays: 0 })).status).toBe(400)
    expect((await mintPat(ia, { name: 'x', scopes: [`${HUB.clientId}:read`], expiresInDays: 367 })).status).toBe(400)
    const capped = await mintPat(ia, { name: 'the year', scopes: [`${HUB.clientId}:read`], expiresInDays: 366 })
    expect(capped.status, 'the one-year ceiling stands').toBe(201)
    // The name bounds.
    expect((await mintPat(ia, { name: '', scopes: [`${HUB.clientId}:read`] })).status).toBe(400)
  })

  it('the viewer mints read only — the write class refuses (the narrowing bound)', async () => {
    const viewer = await demoLogin('viewer@oiml.org')
    // The viewer enters the hub with the viewer role (no permissions):
    // read stands, write refuses.
    const read = await mintPat(viewer, { name: 'the reader', scopes: [`${HUB.clientId}:read`] })
    expect(read.status).toBe(201)
    const write = await mintPat(viewer, { name: 'the writer', scopes: [`${HUB.clientId}:write`] })
    expect(write.status).toBe(403)
    expect(((await write.json()) as { error: string }).error).toContain('no action permission')
    const list = await (await app.request(`${ISSUER}/api/op/account/tokens`, { headers: { cookie: viewer } })).json() as { services: Array<{ id: string; maxAction: string }> }
    expect(list.services.find(s => s.id === HUB.clientId)?.maxAction).toBe('read')
  })

  it('the console routes are session-gated + profile-gated', async () => {
    expect((await app.request(`${ISSUER}/api/op/account/tokens`)).status).toBe(401)
    expect((await mintPat('' , { name: 'x', scopes: [`${HUB.clientId}:read`] })).status).toBe(401)
  })
})

// ── the exchange (the RFC 8693 grant at /op/token) ───────────────────

describe('the exchange (the RFC 8693 grant)', () => {
  it('the valid exchange mints the scoped OP JWT — the claims verified against the JWKS', async () => {
    const ia = await demoLogin('ia@oiml.org')
    const minted = await (await mintPat(ia, { name: 'the exchange leg', scopes: [`${HUB.clientId}:write`, `${REGISTER.clientId}:read`] })).json() as { token: { id: string; plaintext: string } }

    const res = await exchange(minted.token.plaintext)
    expect(res.status).toBe(200)
    const body = await res.json() as { access_token: string; issued_token_type: string; token_type: string; expires_in: number; scope: string }
    expect(body.issued_token_type).toBe('urn:ietf:params:oauth:token-type:access_token')
    expect(body.token_type).toBe('Bearer')
    expect(body.scope).toBe(`${HUB.clientId}:write ${REGISTER.clientId}:read`)

    const claims = await verifyOpJwt(body.access_token)
    expect(claims.iss).toBe(ISSUER)
    expect(claims.scope).toBe(`${HUB.clientId}:write ${REGISTER.clientId}:read`)
    expect(claims.aud).toEqual([HUB.clientId, REGISTER.clientId])
    expect(claims.email).toBe('ia@oiml.org')
    expect(claims.org, 'the active-org context (the demo IA’s EX1)').toBe('EX1')
    expect(claims.pat).toBe(minted.token.id)
    expect(claims.service_roles).toMatchObject({ [HUB.clientId]: ['ia_officer'], [REGISTER.clientId]: ['ia_officer'] })
    // Never an ID-token shape: no nonce, no amr (the exchange is not an
    // authentication ceremony).
    expect(claims.nonce).toBeUndefined()
    expect(claims.amr).toBeUndefined()

    // The heartbeat: the use stamped, the audit beat landed once.
    const row = (await store.getPersonalAccessToken(minted.token.id))!
    expect(row.lastUsedAt, 'the use stamp landed').toBeTruthy()
    const beats = (await journal()).filter(e => e.action === 'account.pat_exchange' && e.metadata?.pat === minted.token.id)
    expect(beats.length).toBe(1)
    // A second exchange inside the window beats no second audit event.
    expect((await exchange(minted.token.plaintext)).status).toBe(200)
    const beats2 = (await journal()).filter(e => e.action === 'account.pat_exchange' && e.metadata?.pat === minted.token.id)
    expect(beats2.length, 'the heartbeat never writes per request').toBe(1)
  })

  it('the refusal lattice: unknown / expired / revoked / wrong-standing answer the ONE invalid_grant', async () => {
    const ia = await demoLogin('ia@oiml.org')
    const minted = await (await mintPat(ia, { name: 'the lattice', scopes: [`${HUB.clientId}:read`] })).json() as { token: { id: string; plaintext: string } }

    // Unknown (a well-shaped token no row knows).
    const unknown = await exchange('ospt_' + 'a'.repeat(43))
    expect(unknown.status).toBe(400)
    expect(((await unknown.json()) as { error: string }).error).toBe('invalid_grant')
    // The malformed subject token (never the prefix shape) — the same answer.
    expect(((await (await exchange('not-a-pat')).json()) as { error: string }).error).toBe('invalid_grant')
    // The wrong subject_token_type answers invalid_request.
    const wrongType = await app.request(`${ISSUER}/op/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
        subject_token_type: 'urn:ietf:params:oauth:token-type:access_token',
        subject_token: minted.token.plaintext,
      }),
    })
    expect(wrongType.status).toBe(400)
    expect(((await wrongType.json()) as { error: string }).error).toBe('invalid_request')

    // The revoked row refuses.
    const revoke = await app.request(`${ISSUER}/api/op/account/tokens/${minted.token.id}`, { method: 'DELETE', headers: { cookie: ia } })
    expect(revoke.status).toBe(200)
    const revoked = await exchange(minted.token.plaintext)
    expect(((await revoked.json()) as { error: string }).error).toBe('invalid_grant')
    // The refusal landed on the audit chain, naming the leg.
    const refused = (await journal()).find(e => e.action === 'account.pat_exchange_refused' && e.metadata?.reason === 'revoked')
    expect(refused, 'the revoked leg is audited').toBeTruthy()

    // The expired row refuses (the store row written directly with a
    // past expiry — the route never mints one).
    const { mintPatSecret, hashPat, patDisplayPrefix } = await import('../../server/auth/op/tokens')
    const iaRow = (await store.listUsers()).find(u => u.email === 'ia@oiml.org')!
    const expiredSecret = mintPatSecret()
    await store.createPersonalAccessToken({
      id: 'pat-expired', userId: iaRow.id, name: 'the expired one',
      tokenHash: await hashPat(expiredSecret), tokenPrefix: patDisplayPrefix(expiredSecret),
      scopes: [`${HUB.clientId}:read`], orgContext: null,
      expiresAt: new Date(Date.now() - 1000).toISOString(),
    })
    expect(((await (await exchange(expiredSecret)).json()) as { error: string }).error).toBe('invalid_grant')

    // The deactivated account's tokens die with it (the standing leg).
    const live = await (await mintPat(ia, { name: 'the standing leg', scopes: [`${HUB.clientId}:read`] })).json() as { token: { id: string; plaintext: string } }
    await store.setUserActive(iaRow.id, false)
    const standing = await exchange(live.token.plaintext)
    expect(((await standing.json()) as { error: string }).error).toBe('invalid_grant')
    await store.setUserActive(iaRow.id, true) // the reversible posture
    expect((await exchange(live.token.plaintext)).status, 'the re-activated account exchanges again').toBe(200)
  })

  it('the per-exchange scope parameter narrows, never widens', async () => {
    const ia = await demoLogin('ia@oiml.org')
    const minted = await (await mintPat(ia, { name: 'the narrowing', scopes: [`${HUB.clientId}:write`, `${REGISTER.clientId}:read`] })).json() as { token: { plaintext: string } }
    // The subset exchange.
    const narrowed = await exchange(minted.token.plaintext, { scope: `${HUB.clientId}:read` })
    expect(narrowed.status).toBe(200)
    const body = await narrowed.json() as { scope: string }
    expect(body.scope).toBe(`${HUB.clientId}:read`)
    // The widening refuses (read is pinned for the register, write is not).
    const widened = await exchange(minted.token.plaintext, { scope: `${REGISTER.clientId}:write` })
    expect(widened.status).toBe(400)
    expect(((await widened.json()) as { error: string }).error).toBe('invalid_scope')
  })

  it('the standing re-judgment: a role lost since the mint narrows the exchange honestly', async () => {
    const ia = await demoLogin('ia@oiml.org')
    const iaRow = (await store.listUsers()).find(u => u.email === 'ia@oiml.org')!
    const minted = await (await mintPat(ia, { name: 'the re-judgment', scopes: [`${HUB.clientId}:read`, `${REGISTER.clientId}:read`] })).json() as { token: { id: string; plaintext: string } }
    // The account loses the register between the mint and the exchange
    // (the explicit per-client none).
    await store.setOpClientRoles(iaRow.id, REGISTER.clientId, [], 'the test')
    const res = await exchange(minted.token.plaintext)
    expect(res.status).toBe(200)
    const body = await res.json() as { scope: string; access_token: string }
    expect(body.scope, 'the dropped service fell away').toBe(`${HUB.clientId}:read`)
    const claims = await verifyOpJwt(body.access_token)
    expect(claims.scope).toBe(`${HUB.clientId}:read`)
    expect(claims.service_roles).toEqual({ [HUB.clientId]: ['ia_officer'] })
    // The narrowed beat names the drop on the audit chain.
    const narrowed = (await journal()).find(e =>
      (e.action === 'account.pat_exchange_narrowed' || e.action === 'account.pat_exchange')
      && e.metadata?.pat === minted.token.id
      && Array.isArray(e.metadata?.dropped))
    expect(narrowed, 'the narrowing is audited').toBeTruthy()
    expect((narrowed!.metadata!.dropped as string[])).toContain(`${REGISTER.clientId}:read`)
    // The whole set gone refuses: the account's hub roles go too.
    await store.setOpClientRoles(iaRow.id, HUB.clientId, [], 'the test')
    const dead = await exchange(minted.token.plaintext)
    expect(((await dead.json()) as { error: string }).error).toBe('invalid_grant')
    // Restore (the other legs' cast stands).
    await store.deleteOpClientRoles(iaRow.id, REGISTER.clientId)
    await store.deleteOpClientRoles(iaRow.id, HUB.clientId)
  })
})

// ── the org inventory + the erasure ──────────────────────────────────

describe('the org inventory + the erasure', () => {
  it('the org detail carries the members’ tokens (the metadata only, the holder resolved)', async () => {
    const ia = await demoLogin('ia@oiml.org')
    const admin = await demoLogin('admin@oiml.org')
    const minted = await (await mintPat(ia, { name: 'the inventory row', scopes: [`${HUB.clientId}:read`] })).json() as { token: { id: string } }

    const res = await app.request(`${ISSUER}/api/op/registry/orgs/EX1`, { headers: { cookie: admin } })
    expect(res.status).toBe(200)
    const view = await res.json() as { tokens: Array<{ id: string; name: string; holder: { name: string; email: string }; state: string; prefix: string }> }
    const row = view.tokens.find(t => t.id === minted.token.id)!
    expect(row, 'the member’s token is on the org’s inventory').toBeTruthy()
    expect(row.holder).toMatchObject({ name: 'IA Officer', email: 'ia@oiml.org' })
    expect(row.state).toBe('active')
    expect(JSON.stringify(row), 'the inventory never carries the plaintext or the hash').not.toContain('ospt_2')
    // A foreign org’s inventory stays empty (the membership join).
    await store.createOrgRegistryOrg({ id: 'XX9', name: 'The Empty One', shortName: 'XX9', kind: 'issuing-authority', country: null, contacts: [], participantRef: null, createdBy: 'the test' })
    const empty = await (await app.request(`${ISSUER}/api/op/registry/orgs/XX9`, { headers: { cookie: admin } })).json() as { tokens: unknown[] }
    expect(empty.tokens).toEqual([])
  })

  it('the erasure carries the tokens out — the exchange never resolves a tombstone', async () => {
    const ia2 = await demoLogin('ia2@oiml.org')
    const ia2Row = (await store.listUsers()).find(u => u.email === 'ia2@oiml.org')!
    const minted = await (await mintPat(ia2, { name: 'the erased account’s token', scopes: [`${HUB.clientId}:read`] })).json() as { token: { id: string; plaintext: string } }
    expect((await exchange(minted.token.plaintext)).status).toBe(200)
    const erased = await store.eraseOpAccount(ia2Row.id)
    expect(erased?.personalAccessTokens).toBe(1)
    const dead = await exchange(minted.token.plaintext)
    expect(((await dead.json()) as { error: string }).error, 'the tombstone’s token never exchanges').toBe('invalid_grant')
  })
})
