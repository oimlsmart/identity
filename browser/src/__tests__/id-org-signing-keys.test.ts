// ─────────────────────────────────────────────────────────────────────
// TODO.trust-registry/01 — the org signing keys, proven in-process: the
// REAL org-signing-keys module (server/auth/org-signing-keys.ts), the
// REAL keys router (server/routes/op-keys.ts — the management acts +
// the PUBLIC key-resolution endpoint), the REAL registry router (the
// per-org aggregate's signingKeys slice) over a REAL temp SQLite store.
//
// THE DOCTRINE (TODO.trust-registry/00): a signing key is an ORG
// ACCOUNT'S property on the OP (never a deployment secret); the OP is
// the root of trust for WHO signs — the verifier resolves signer → org
// → standing in ONE anonymous, cacheable, CORS-open request. The
// PRIVATE material is NEVER stored. The rotation keeps the predecessor
// resolving (the overlap doctrine); the revocation stamps the row and
// KEEPS it (the at-the-time honesty).
//
// Covered:
//   THE VALIDATION — the public-JWK refusal: the private-material leak,
//     the wrong curve, the missing coordinates, the wrong alg;
//   THE STORE ACTS — the kid derives the OP's own way (kidFor), the
//     duplicate is never a second row, the rotation stamps the
//     predecessor (both rows resolve), the revocation keeps the row;
//   THE ACT GATES — the anonymous 401, the member-without-org_admin
//     403, the org_admin in the ACTIVE context (the primary binding AND
//     the switched context), the estate admin, the org preconditions
//     (the unknown 404, the disabled 400), the rotation/revocation
//     refusals, the audit chain carrying every act;
//   THE PUBLIC ENDPOINT — the shape (the org block + the standing
//     projection + the JWK Set members carrying their custody stamps),
//     the cache posture + the CORS-open header, the revoked key still
//     resolvable, the disabled org still resolving, the actors' emails
//     NEVER on the public document;
//   THE DEMO SEED — EX1's demonstration key lands idempotently, the
//     private half never stored.
// ─────────────────────────────────────────────────────────────────────

import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

// The store's DB path is read at module evaluation — set it before any
// import below touches @oimlsmart/platform-server/store/sqlite (the imports are dynamic).
const TMP = mkdtempSync(join(tmpdir(), 'oiml-org-keys-'))
process.env.DATABASE_PATH = join(TMP, 'test.db')
process.env.OP_ISSUER = 'http://op.test'

const ORIGIN = 'http://op.test'

let app: import('hono').Hono
let store: ReturnType<typeof import('@oimlsmart/platform-server/store').getStore>

/** A fresh ES256 pair's PUBLIC half (never the private one — the route
 *  refuses it). */
async function publicJwk(): Promise<JsonWebKey> {
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
  const pub = await crypto.subtle.exportKey('jwk', pair.publicKey)
  return { kty: 'EC', crv: 'P-256', x: pub.x, y: pub.y }
}

async function demoLogin(email: string): Promise<string> {
  const res = await app.request(`${ORIGIN}/api/auth/demo`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password: 'demo2026' }),
  })
  expect(res.ok, `demo login ${email}`).toBe(true)
  return res.headers.get('set-cookie')!.split(';')[0]!
}

/** The JSON body of a request, asserting the status first. */
async function json(res: Response, status: number): Promise<any> {
  expect(res.status, `${res.url} → ${status}`).toBe(status)
  return res.json()
}

/** The audit chain's parsed rows (the store directly). */
async function journal(): Promise<Array<{ action: string; entity_type: string; entity_id: string; user_name?: string; metadata?: Record<string, unknown> }>> {
  return (await store.listEntities('auditEvents'))
    .map(row => JSON.parse(row.data) as never)
}

beforeAll(async () => {
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
  const { createOpKeysRouter } = await import('../../server/routes/op-keys')
  const { createOpRegistryRouter } = await import('../../server/routes/op-registry')
  const { createOpAccountsRouter } = await import('../../server/routes/op-accounts')
  const root = new Hono()
  root.route('/api/auth', createAuthLeanRouter({ autoSeedDemo: true }))
  root.route('/', createOpKeysRouter())
  root.route('/', createOpRegistryRouter())
  root.route('/', createOpAccountsRouter())
  app = root

  // The registry: EX1 + EX9 the demo IAs (active), mfr-acme the demo
  // cast's manufacturer (the standing projection's per-kind honesty),
  // mfr-dormant a DISABLED org (the register act's refusal).
  await store.createOrgRegistryOrg({ id: 'EX1', name: 'Example Issuing Authority', shortName: 'EIA', kind: 'issuing-authority', country: 'Example Member State', contacts: [{ name: null, email: 'office@eia.example.org' }], participantRef: 'EX1' })
  await store.createOrgRegistryOrg({ id: 'EX9', name: 'Second Example Issuing Authority', shortName: 'EIA-2', kind: 'issuing-authority', country: 'Example Member State', contacts: [{ name: null, email: 'office@eia2.example.org' }], participantRef: 'EX9' })
  await store.createOrgRegistryOrg({ id: 'mfr-acme', name: 'ACME (the demonstration manufacturer)', shortName: 'ACME', kind: 'manufacturer', country: 'Example Member State', contacts: [{ name: 'ACME Applicant', email: 'applicant@oiml.org' }], participantRef: null })
  await store.createOrgRegistryOrg({ id: 'mfr-dormant', name: 'Dormant Instruments', shortName: null, kind: 'manufacturer', country: null, contacts: [], participantRef: null })
  await store.setOrgRegistryOrgState('mfr-dormant', 'disabled', 'the test seed')

  // The key-admin cast: EX1's delegated administrator (the primary
  // binding IS the active context) and the MULTI-org administrator
  // (primary EX9 + an active EX1 membership — the active-context rule's
  // proof needs the switch).
  await store.createLocalUser({ email: 'keys-admin@eia.example.org', name: 'EIA Key Administrator', role: 'org_admin', roles: ['org_admin'], orgId: 'EX1' })
  const multi = await store.createLocalUser({ email: 'multi-admin@example.org', name: 'Multi Administrator', role: 'org_admin', roles: ['org_admin'], orgId: 'EX9' })
  await store.createOrgMembership({ userId: multi!.id, orgId: 'EX1', roles: ['org_admin'], state: 'active' })
})

afterAll(async () => {
  const { resetInstanceProfileForTest } = await import('@oimlsmart/platform-server/profile')
  resetInstanceProfileForTest()
  rmSync(TMP, { recursive: true, force: true })
  delete process.env.DATABASE_PATH
  delete process.env.OP_ISSUER
})

// ── the public-JWK validation (the custody rule's door) ──────────────

describe('the public-JWK validation', () => {
  it('refuses the private-material leak, the wrong curve, the missing coordinates, the wrong alg; accepts the clean public half', async () => {
    const { orgSigningJwkRefusal } = await import('../../server/auth/org-signing-keys')
    const pub = await publicJwk()
    expect(orgSigningJwkRefusal(pub)).toBeNull()
    expect(orgSigningJwkRefusal({ ...pub, d: 'leaked' })).toContain('PRIVATE material')
    expect(orgSigningJwkRefusal({ ...pub, k: 'symmetric' })).toContain('PRIVATE material')
    expect(orgSigningJwkRefusal({ kty: 'EC', crv: 'P-384', x: 'a', y: 'b' })).toContain('P-256')
    expect(orgSigningJwkRefusal({ kty: 'EC', crv: 'P-256', x: 'a' })).toContain('coordinates')
    expect(orgSigningJwkRefusal({ ...pub, alg: 'ES384' })).toContain('ES256')
    expect(orgSigningJwkRefusal('not a jwk')).toContain('JSON Web Key')
  })
})

// ── the store acts (the custody chain) ───────────────────────────────
// The EX9 rows: the store-level acts prove the kid derivation, the
// duplicate guard, the rotation's overlap stamps, the revocation's
// kept row — the endpoint's disabled-org leg (below) then reuses them.

describe('the store acts', () => {
  it('register derives the kid the OP’s own way; the duplicate is never a second row', async () => {
    const { registerOrgSigningKey, listOrgSigningKeys } = await import('../../server/auth/org-signing-keys')
    const { kidFor } = await import('../../server/auth/op/keys')
    const jwk = await publicJwk()
    const key = (await registerOrgSigningKey(store, { orgId: 'EX9', publicJwk: jwk, label: 'EX9 first key', createdBy: 'the test' }))!
    expect(key.kid).toBe(await kidFor(jwk))
    expect(key.publicJwk).toMatchObject({ kty: 'EC', crv: 'P-256', kid: key.kid, alg: 'ES256', use: 'sig' })
    expect(key.publicJwk.d).toBeUndefined()
    expect(key.rotatedAt).toBeNull()
    expect(key.revokedAt).toBeNull()
    // The duplicate (the same coordinates) answers null — no second row.
    expect(await registerOrgSigningKey(store, { orgId: 'EX9', publicJwk: jwk, label: 'again', createdBy: 'the test' })).toBeNull()
    expect(await listOrgSigningKeys(store, 'EX9')).toHaveLength(1)
  })

  it('the rotation stamps the predecessor and BOTH rows keep resolving (the overlap doctrine)', async () => {
    const { listOrgSigningKeys, resolveOrgSigningKey, rotateOrgSigningKey } = await import('../../server/auth/org-signing-keys')
    const [predecessor] = await listOrgSigningKeys(store, 'EX9')
    const rotated = (await rotateOrgSigningKey(store, predecessor!, { publicJwk: await publicJwk(), label: 'EX9 successor', actor: 'the test' }))!
    expect(rotated.predecessor.kid).toBe(predecessor!.kid)
    expect(rotated.predecessor.rotatedAt).toBeTruthy()
    expect(rotated.predecessor.rotatedBy).toBe('the test')
    expect(rotated.predecessor.successorKid).toBe(rotated.successor.kid)
    expect(rotated.successor.kid).not.toBe(predecessor!.kid)
    expect(rotated.successor.rotatedAt).toBeNull()
    // The overlap: both resolve.
    expect(await resolveOrgSigningKey(store, 'EX9', predecessor!.kid)).toBeTruthy()
    expect(await resolveOrgSigningKey(store, 'EX9', rotated.successor.kid)).toBeTruthy()
  })

  it('the revocation stamps the row and KEEPS it (the at-the-time honesty)', async () => {
    const { listOrgSigningKeys, resolveOrgSigningKey, revokeOrgSigningKey } = await import('../../server/auth/org-signing-keys')
    const [predecessor] = await listOrgSigningKeys(store, 'EX9')
    const revoked = (await revokeOrgSigningKey(store, 'EX9', predecessor!.kid, 'the test'))!
    expect(revoked.revokedAt).toBeTruthy()
    expect(revoked.revokedBy).toBe('the test')
    // The revoked key STAYS resolvable — the verify answer names the date.
    const resolved = await resolveOrgSigningKey(store, 'EX9', predecessor!.kid)
    expect(resolved).toBeTruthy()
    expect(resolved!.revokedAt).toBe(revoked.revokedAt)
    expect(await listOrgSigningKeys(store, 'EX9')).toHaveLength(2)
  })
})

// ── the act gates (the router) ───────────────────────────────────────

describe('the management acts (the gates + the audit chain)', () => {
  let kidRegistered: string
  let kidSuccessor: string

  it('the anonymous + the member-without-org_admin refusals (401 / 403 naming the permission)', async () => {
    const jwk = await publicJwk()
    const anon = await app.request(`${ORIGIN}/api/op/org-keys`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ org_id: 'EX1', label: 'anon key', public_jwk: jwk }),
    })
    expect(anon.status).toBe(401)
    const anonList = await app.request(`${ORIGIN}/api/op/org-keys/EX1`)
    expect(anonList.status).toBe(401)

    // The demo cast's IA officer acts as EX1 but holds no org_admin.
    const officer = await demoLogin('ia@oiml.org')
    const refused = await app.request(`${ORIGIN}/api/op/org-keys`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie: officer },
      body: JSON.stringify({ org_id: 'EX1', label: 'officer key', public_jwk: jwk }),
    })
    expect(refused.status).toBe(403)
    expect((await refused.json()).permission).toBe('org.keys.manage')
    const refusedList = await app.request(`${ORIGIN}/api/op/org-keys/EX1`, { headers: { cookie: officer } })
    expect(refusedList.status).toBe(403)
  })

  it('the org_admin in the active context registers (the PRIMARY binding is the context); the audit chain carries the act', async () => {
    const cookie = await demoLogin('keys-admin@eia.example.org')
    const res = await app.request(`${ORIGIN}/api/op/org-keys`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ org_id: 'EX1', label: 'EX1 production key', public_jwk: await publicJwk() }),
    })
    const created = await json(res, 201)
    kidRegistered = created.key.kid
    expect(created.key.orgId).toBe('EX1')
    expect(created.key.label).toBe('EX1 production key')
    expect(created.key.createdBy).toBe('keys-admin@eia.example.org')
    expect(created.key.publicJwk.alg).toBe('ES256')

    const chain = await journal()
    const act = chain.find(e => e.action === 'organization.key_registered' && e.entity_id === 'EX1')
    expect(act).toBeTruthy()
    expect(act!.metadata).toMatchObject({ kid: kidRegistered, label: 'EX1 production key' })
  })

  it('the ACTIVE-CONTEXT rule: the multi-org org_admin acting as EX9 is refused on EX1; after the switch the same act lands', async () => {
    const cookie = await demoLogin('multi-admin@example.org')
    const asEx9 = await app.request(`${ORIGIN}/api/op/org-keys`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ org_id: 'EX1', label: 'out of context', public_jwk: await publicJwk() }),
    })
    expect(asEx9.status).toBe(403)
    // The switch (the account console's act): the session acts AS EX1.
    const switched = await app.request(`${ORIGIN}/api/op/account/active-org`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ org_id: 'EX1' }),
    })
    expect(switched.status).toBe(200)
    const asEx1 = await app.request(`${ORIGIN}/api/op/org-keys`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ org_id: 'EX1', label: 'EX1 second key', public_jwk: await publicJwk() }),
    })
    expect(asEx1.status).toBe(201)
  })

  it('the estate admin registers for any org; the org preconditions refuse honestly', async () => {
    const admin = await demoLogin('admin@oiml.org')
    const ok = await app.request(`${ORIGIN}/api/op/org-keys`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie: admin },
      body: JSON.stringify({ org_id: 'mfr-acme', label: 'ACME demo key', public_jwk: await publicJwk() }),
    })
    expect(ok.status).toBe(201)

    const unknown = await app.request(`${ORIGIN}/api/op/org-keys`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie: admin },
      body: JSON.stringify({ org_id: 'no-such-org', label: 'nowhere', public_jwk: await publicJwk() }),
    })
    expect(unknown.status).toBe(404)
    const disabled = await app.request(`${ORIGIN}/api/op/org-keys`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie: admin },
      body: JSON.stringify({ org_id: 'mfr-dormant', label: 'dormant', public_jwk: await publicJwk() }),
    })
    expect(disabled.status).toBe(400)
    expect((await disabled.json()).error).toContain('disabled')
  })

  it('the private-material body is refused at the door (400) — never stored, never audited', async () => {
    const cookie = await demoLogin('keys-admin@eia.example.org')
    const pub = await publicJwk()
    const res = await app.request(`${ORIGIN}/api/op/org-keys`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ org_id: 'EX1', label: 'leaky key', public_jwk: { ...pub, d: 'the-private-half' } }),
    })
    expect(res.status).toBe(400)
    expect((await res.json()).error).toContain('PRIVATE material')
    const keys = await json(await app.request(`${ORIGIN}/api/op/org-keys/EX1`, { headers: { cookie } }), 200)
    expect(keys.keys.some((k: any) => k.label === 'leaky key')).toBe(false)
    expect((await journal()).some(e => e.action === 'organization.key_registered' && e.metadata?.label === 'leaky key')).toBe(false)
  })

  it('the rotation overlaps: the predecessor keeps its row with the stamps + the successor link; the refusals are honest', async () => {
    const cookie = await demoLogin('keys-admin@eia.example.org')
    // The unknown predecessor.
    const missing = await app.request(`${ORIGIN}/api/op/org-keys/EX1/no-such-kid/rotate`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ label: 'nowhere', public_jwk: await publicJwk() }),
    })
    expect(missing.status).toBe(404)

    const res = await app.request(`${ORIGIN}/api/op/org-keys/EX1/${kidRegistered}/rotate`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ label: 'EX1 production key 2027', public_jwk: await publicJwk() }),
    })
    const rotated = await json(res, 201)
    kidSuccessor = rotated.successor.kid
    expect(rotated.predecessor.kid).toBe(kidRegistered)
    expect(rotated.predecessor.rotatedAt).toBeTruthy()
    expect(rotated.predecessor.rotatedBy).toBe('keys-admin@eia.example.org')
    expect(rotated.predecessor.successorKid).toBe(kidSuccessor)
    expect(rotated.successor.label).toBe('EX1 production key 2027')

    // The chain never forks: the already-rotated predecessor refuses.
    const fork = await app.request(`${ORIGIN}/api/op/org-keys/EX1/${kidRegistered}/rotate`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ label: 'the fork', public_jwk: await publicJwk() }),
    })
    expect(fork.status).toBe(409)

    const chain = await journal()
    expect(chain.some(e => e.action === 'organization.key_rotated'
      && e.entity_id === 'EX1' && e.metadata?.kid === kidRegistered && e.metadata?.successor_kid === kidSuccessor)).toBe(true)
  })

  it('the revocation stamps the terminal act; the revoked key never rotates; the second revocation is the honest 409', async () => {
    const cookie = await demoLogin('keys-admin@eia.example.org')
    const res = await app.request(`${ORIGIN}/api/op/org-keys/EX1/${kidSuccessor}/revoke`, {
      method: 'POST', headers: { cookie },
    })
    const revoked = await json(res, 200)
    expect(revoked.key.kid).toBe(kidSuccessor)
    expect(revoked.key.revokedAt).toBeTruthy()
    expect(revoked.key.revokedBy).toBe('keys-admin@eia.example.org')

    const rotateRevoked = await app.request(`${ORIGIN}/api/op/org-keys/EX1/${kidSuccessor}/rotate`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ label: 'the undead', public_jwk: await publicJwk() }),
    })
    expect(rotateRevoked.status).toBe(400)
    expect((await rotateRevoked.json()).error).toContain('revoked')

    const again = await app.request(`${ORIGIN}/api/op/org-keys/EX1/${kidSuccessor}/revoke`, {
      method: 'POST', headers: { cookie },
    })
    expect(again.status).toBe(409)

    const chain = await journal()
    expect(chain.some(e => e.action === 'organization.key_revoked' && e.entity_id === 'EX1' && e.metadata?.kid === kidSuccessor)).toBe(true)
  })

  it('the duplicate registration is the honest 409', async () => {
    const cookie = await demoLogin('keys-admin@eia.example.org')
    const keys = await json(await app.request(`${ORIGIN}/api/op/org-keys/EX1`, { headers: { cookie } }), 200)
    const existing = keys.keys.find((k: any) => k.kid === kidRegistered)
    const res = await app.request(`${ORIGIN}/api/op/org-keys`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ org_id: 'EX1', label: 'the same coordinates', public_jwk: existing.publicJwk }),
    })
    expect(res.status).toBe(409)
  })
})

// ── the PUBLIC key-resolution endpoint ───────────────────────────────

describe('the public endpoint (GET /op/keys/<org-id>.json)', () => {
  it('resolves the key set + the standing anonymously, cacheable and CORS-open; the actors’ emails NEVER publish', async () => {
    const res = await app.request(`${ORIGIN}/op/keys/EX1.json`)
    expect(res.status).toBe(200)
    expect(res.headers.get('cache-control')).toBe('public, max-age=60')
    expect(res.headers.get('access-control-allow-origin')).toBe('*')
    const doc = await res.json()
    expect(doc.org_id).toBe('EX1')
    expect(doc.org_name).toBe('Example Issuing Authority')
    expect(doc.org_kind).toBe('issuing-authority')
    expect(doc.org_state).toBe('active')
    expect(doc.standing).toBe('participant')
    expect(doc.endorsed_by).toEqual([])

    // The custody chain whole: the rotated predecessor + the revoked
    // successor + the other registered keys, every entry a JWK Set member
    // carrying its stamps.
    const kids = doc.keys.map((k: any) => k.kid)
    const keys = await json(await app.request(`${ORIGIN}/api/op/org-keys/EX1`, { headers: { cookie: await demoLogin('keys-admin@eia.example.org') } }), 200)
    expect(kids.sort()).toEqual(keys.keys.map((k: any) => k.kid).sort())
    const predecessor = doc.keys.find((k: any) => k.label === 'EX1 production key')
    expect(predecessor).toMatchObject({ kty: 'EC', crv: 'P-256', alg: 'ES256', use: 'sig' })
    expect(typeof predecessor.x).toBe('string')
    expect(typeof predecessor.y).toBe('string')
    expect(predecessor.d).toBeUndefined()
    expect(predecessor.rotated_at).toBeTruthy()
    const revoked = doc.keys.find((k: any) => k.label === 'EX1 production key 2027')
    expect(predecessor.successor_kid).toBe(revoked.kid)
    expect(revoked.revoked_at).toBeTruthy()
    // The privacy bound: no actor's email anywhere in the document.
    expect(JSON.stringify(doc)).not.toContain('keys-admin@eia.example.org')
    expect(JSON.stringify(doc)).not.toContain('created_by')
  })

  it('the per-kind standing projects honestly (the manufacturer reads declared, NEVER a participant)', async () => {
    const doc = await json(await app.request(`${ORIGIN}/op/keys/mfr-acme.json`), 200)
    expect(doc.org_kind).toBe('manufacturer')
    expect(doc.standing).toBe('declared')
    expect(doc.keys).toHaveLength(1) // the estate admin's registration above
  })

  it('the unknown org + the missing suffix are the honest 404s (CORS-open too)', async () => {
    const unknown = await app.request(`${ORIGIN}/op/keys/no-such-org.json`)
    expect(unknown.status).toBe(404)
    expect(unknown.headers.get('access-control-allow-origin')).toBe('*')
    expect((await unknown.json()).error).toContain('no-such-org')
    const noSuffix = await app.request(`${ORIGIN}/op/keys/EX1`)
    expect(noSuffix.status).toBe(404)
  })

  it('a DISABLED org still resolves — the at-the-time artifacts keep their answer, org_state says the rest', async () => {
    // EX9 carries the store-level rows (one revoked predecessor, one
    // active successor); the lifecycle act disables the org.
    await store.setOrgRegistryOrgState('EX9', 'disabled', 'the test')
    const doc = await json(await app.request(`${ORIGIN}/op/keys/EX9.json`), 200)
    expect(doc.org_state).toBe('disabled')
    expect(doc.standing).toBe('participant')
    expect(doc.keys).toHaveLength(2)
    expect(doc.keys.filter((k: any) => k.revoked_at)).toHaveLength(1)
    expect(doc.keys.filter((k: any) => k.rotated_at)).toHaveLength(1)
    await store.setOrgRegistryOrgState('EX9', 'active', 'the test')
  })
})

// ── the registry aggregate's slice (the admin console's data source) ──

describe('the registry aggregate', () => {
  it('the per-org view carries the signing keys WITH the custody actors (the gated read)', async () => {
    const admin = await demoLogin('admin@oiml.org')
    const view = await json(await app.request(`${ORIGIN}/api/op/registry/orgs/EX1`, { headers: { cookie: admin } }), 200)
    expect(view.signingKeys.length).toBeGreaterThanOrEqual(3)
    const registered = view.signingKeys.find((k: any) => k.label === 'EX1 production key')
    expect(registered.createdBy).toBe('keys-admin@eia.example.org')
    expect(registered.rotatedBy).toBe('keys-admin@eia.example.org')
    expect(registered.successorKid).toBeTruthy()
    const revoked = view.signingKeys.find((k: any) => k.label === 'EX1 production key 2027')
    expect(revoked.revokedBy).toBe('keys-admin@eia.example.org')
    // …and the org's audit slice renders the acts (the per-org page's
    // activity section reads it).
    const actions = view.activity.map((e: any) => e.action)
    expect(actions).toEqual(expect.arrayContaining([
      'organization.key_registered',
      'organization.key_rotated',
      'organization.key_revoked',
    ]))
  })
})

// ── the module gate ──────────────────────────────────────────────────

describe('the identity-module gate', () => {
  it('a non-identity profile answers 404 on BOTH the management acts and the public endpoint', async () => {
    const profileMod = await import('@oimlsmart/platform-server/profile')
    profileMod.installInstanceProfile(profileMod.parseInstanceProfile(`
identity: { org_id: biml, org_name: BIML, role_codes: [hub] }
roles: [hub]
`))
    try {
      const managed = await app.request(`${ORIGIN}/api/op/org-keys/EX1`)
      expect(managed.status).toBe(404)
      const pub = await app.request(`${ORIGIN}/op/keys/EX1.json`)
      expect(pub.status).toBe(404)
    } finally {
      profileMod.installInstanceProfile(profileMod.parseInstanceProfile(`
identity:
  org_id: oimlsmart-id
  org_name: OIML SMART Identity
  role_codes: [identity]
roles: [identity]
branding: { name: OIML SMART Identity }
demo_personas: true
`))
    }
  })
})

// ── the demo seed (EX1's demonstration key) ──────────────────────────

describe('the demo cast’s signing key (the seed)', () => {
  it('lands EX1’s demonstration key idempotently; the PRIVATE half is never stored', async () => {
    const { seedOrgSigningKeysDemo, DEMO_EX1_SIGNING_KEY } = await import('../../server/seed-org-register')
    expect(await seedOrgSigningKeysDemo(store)).toBe(1)
    expect(await seedOrgSigningKeysDemo(store)).toBe(0) // the idempotent reseed
    const { resolveOrgSigningKey } = await import('../../server/auth/org-signing-keys')
    const key = (await resolveOrgSigningKey(store, 'EX1', DEMO_EX1_SIGNING_KEY.kid))!
    expect(key.label).toContain('demonstration')
    expect(key.createdBy).toBe('the demonstration seed')
    expect(key.publicJwk.d).toBeUndefined()
    expect('d' in key.publicJwk).toBe(false)
    // The public endpoint resolves it with the standing (the full arc's
    // anonymous read).
    const doc = await json(await app.request(`${ORIGIN}/op/keys/EX1.json`), 200)
    expect(doc.keys.some((k: any) => k.kid === DEMO_EX1_SIGNING_KEY.kid)).toBe(true)
  })
})
