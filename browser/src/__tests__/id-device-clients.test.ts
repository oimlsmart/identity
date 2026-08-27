// ─────────────────────────────────────────────────────────────────────
// The machine cone (the device class on the client registry — smart's
// docs/future/07 Part I.3 item 2), proven in-process: the REAL op
// router (server/routes/op.ts) over a REAL temp SQLite store, the demo
// cast for the admin acts, and the OP's own JWKS verifying the device
// tokens (the twin endpoints' posture — no stub anywhere).
//
// Covered:
//   THE REGISTRY     — the device class's shape enforced at write: the
//     VALIDATION       device block required (id/org/instrument_model),
//                      the org resolved on the organization registry, no
//                      redirect_uris, no launch card, no user claims,
//                      always confidential; the class FIXED at
//                      registration (an app row refuses the device
//                      re-declaration, a device row's edit keeps the
//                      class and the stored block); the admin API's
//                      view carries the class + the block (what the
//                      console renders).
//   THE TOKEN        — client_credentials mints the self-contained ES256
//     ENDPOINT         device JWT (sub = the device id, org,
//                      instrument_model — NEVER a user claim, never an
//                      ID token, never a refresh); every other grant
//                      refused (authorization_code at authorize AND at
//                      token, refresh_token); the application class
//                      refused client_credentials with the pre-device
//                      answer (the contract golden's shape stands); the
//                      wrong secret + the disabled client refused; the
//                      audit chain carries register / rotate-secret /
//                      revoke naming the device.
//   THE SEED         — OP_CLIENT_SEED accepts the class (the seeded
//                      device mints); the malformed device entries fail
//                      the parse loudly (no secret, redirect_uris, a
//                      launch card, a claims policy).
// ─────────────────────────────────────────────────────────────────────

import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

// The store's DB path is read at module evaluation — set it before any
// import below touches @oimlsmart/platform-server/store/sqlite (the imports are dynamic).
const TMP = mkdtempSync(join(tmpdir(), 'oiml-op-device-'))
process.env.DATABASE_PATH = join(TMP, 'test.db')

const ISSUER = 'http://op.test'
process.env.OP_ISSUER = ISSUER

/** The demo binding: the ACME manufacturer's LC-500 twin (the demo
 *  cast's instrument — the org registry row is created in beforeAll). */
const DEVICE = { id: 'acme-lc500-sn-0001', org: 'mfr-acme', instrument_model: 'acme-lc500@2021' }
const DEVICE_CLIENT_ID = 'device-acme-lc500-0001'

let app: import('hono').Hono
let store: ReturnType<typeof import('@oimlsmart/platform-server/store').getStore>
let parseOpClientSeed: typeof import('../../server/auth/op/registry').parseOpClientSeed
let seedOidcClientsFromEnv: typeof import('../../server/auth/op/registry').seedOidcClientsFromEnv

async function demoLogin(email: string): Promise<string> {
  const res = await app.request('/api/auth/demo', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password: 'demo2026' }),
  })
  expect(res.ok, `demo login ${email}`).toBe(true)
  return res.headers.get('set-cookie')!.split(';')[0]!
}

/** The registry write (the admin API). */
async function registerClient(cookie: string, body: Record<string, unknown>): Promise<Response> {
  return app.request(`${ISSUER}/api/op/clients`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', cookie },
    body: JSON.stringify(body),
  })
}

/** The device grant at the token endpoint (client_secret_basic or post). */
async function deviceToken(clientId: string, secret: string | null, basic = true): Promise<Response> {
  const headers: Record<string, string> = { 'content-type': 'application/x-www-form-urlencoded' }
  const body = new URLSearchParams({ grant_type: 'client_credentials' })
  if (basic) {
    if (secret !== null) headers.authorization = `Basic ${btoa(`${encodeURIComponent(clientId)}:${encodeURIComponent(secret)}`)}`
    else headers.authorization = `Basic ${btoa(`${encodeURIComponent(clientId)}:`)}`
  } else {
    body.set('client_id', clientId)
    if (secret !== null) body.set('client_secret', secret)
  }
  return app.request(`${ISSUER}/op/token`, { method: 'POST', headers, body })
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

/** Verify the device JWT against the OP's OWN JWKS (the twin endpoint's
 *  validation posture) and answer its claims. */
async function verifyDeviceJwt(token: string): Promise<Record<string, unknown>> {
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
  expect(ok, 'the device token verifies against the OP’s JWKS').toBe(true)
  return decodePart(p!)
}

/** The registry's audit journal (the store directly). */
async function journal(): Promise<Array<{ action: string; entity_type: string; entity_id: string; metadata?: Record<string, unknown> }>> {
  return (await store.listEntities('auditEvents')).map(row => JSON.parse(row.data) as never)
}

beforeAll(async () => {
  // The simulated deployment declares its signing key (identity#7's gate:
  // the round trips verify against the JWKS — the production posture).
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

  const registryMod = await import('../../server/auth/op/registry')
  parseOpClientSeed = registryMod.parseOpClientSeed
  seedOidcClientsFromEnv = registryMod.seedOidcClientsFromEnv

  const { Hono } = await import('hono')
  const { createAuthLeanRouter } = await import('../../server/routes/auth-lean')
  const { createOpRouter } = await import('../../server/routes/op')
  const root = new Hono()
  root.route('/api/auth', createAuthLeanRouter({ autoSeedDemo: true }))
  root.route('/', createOpRouter())
  app = root

  // The device binding's org: the demonstration manufacturer on the
  // identity service's own registry (the seed-org-register.ts shape).
  await store.createOrgRegistryOrg({
    id: 'mfr-acme',
    name: 'ACME (the demonstration manufacturer)',
    shortName: 'ACME',
    kind: 'manufacturer',
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

// ── the registry validation (the class's shape) ──────────────────────

describe('the registry validation (the device class’s shape)', () => {
  it('registers a device client — the view carries the class + the device block, never the human-cone fields', async () => {
    const admin = await demoLogin('admin@oiml.org')
    const res = await registerClient(admin, {
      client_id: DEVICE_CLIENT_ID,
      name: 'ACME LC-500 sn 0001 (the twin)',
      class: 'device',
      device: DEVICE,
      generate_secret: true,
    })
    expect(res.status).toBe(201)
    const created = await res.json() as {
      clientId: string; class: string; device: typeof DEVICE; redirectUris: string[]
      launch: unknown; confidential: boolean; claimsPolicy: { claims: string[] }; secret?: string
    }
    expect(created.class).toBe('device')
    expect(created.device).toEqual(DEVICE)
    expect(created.redirectUris).toEqual([])
    expect(created.launch).toBeNull()
    expect(created.confidential, 'a device client is always confidential').toBe(true)
    expect(created.claimsPolicy.claims, 'the class fixes the claim set — no user claims').toEqual([])
    expect(created.secret, 'the generated secret rides the registration response once').toBeTruthy()

    // The LIST view carries the same honest shape (the console renders it).
    const list = await (await app.request(`${ISSUER}/api/op/clients`, { headers: { cookie: admin } })).json() as Array<Record<string, unknown>>
    const row = list.find(r => r.clientId === DEVICE_CLIENT_ID)!
    expect(row.class).toBe('device')
    expect(row.device).toEqual(DEVICE)
    expect(JSON.stringify(row)).not.toContain(created.secret!) // never the secret
  })

  it('refuses the human-cone shape on a device: redirect_uris, a launch card, user claims, the public posture', async () => {
    const admin = await demoLogin('admin@oiml.org')
    const base = { name: 'A misdeclared device', class: 'device', device: DEVICE, generate_secret: true }
    const cases: Array<[string, Record<string, unknown>, string]> = [
      ['redirect_uris', { ...base, client_id: 'dev-bad-uris', redirect_uris: ['https://device.example/callback'] }, 'no redirect_uris'],
      ['a launch card', { ...base, client_id: 'dev-bad-launch', launch: { url: 'https://device.example/signin' } }, 'never joins the SSO home'],
      ['user claims', { ...base, client_id: 'dev-bad-claims', claims_policy: { claims: ['roles'] } }, 'never carries user claims'],
      ['a role allowlist', { ...base, client_id: 'dev-bad-roles', claims_policy: { claims: [], roles: ['viewer'] } }, 'never carries user claims'],
      ['the public posture', { ...base, client_id: 'dev-bad-public', generate_secret: undefined, secret: null }, 'confidential'],
      ['no secret at all', { ...base, client_id: 'dev-bad-nosecret', generate_secret: undefined }, 'confidential'],
      ['an unknown org', { ...base, client_id: 'dev-bad-org', device: { ...DEVICE, org: 'no-such-org' } }, 'not on the organization registry'],
      ['a missing device id', { ...base, client_id: 'dev-bad-noid', device: { ...DEVICE, id: '' } }, 'device.id is required'],
      ['a missing model', { ...base, client_id: 'dev-bad-nomodel', device: { ...DEVICE, instrument_model: '' } }, 'instrument_model'],
      ['an unknown class', { client_id: 'dev-bad-class', name: 'X', class: 'machine', redirect_uris: ['https://x.example/cb'] }, 'class must be'],
    ]
    for (const [label, body, fragment] of cases) {
      const res = await registerClient(admin, body)
      const err = await res.json() as { error?: string }
      expect(res.status, `${label}: refused (${err.error ?? ''})`).toBe(400)
      expect(err.error, `${label}: the honest reason`).toContain(fragment)
    }
    // None of the refused rows landed.
    const list = await (await app.request(`${ISSUER}/api/op/clients`, { headers: { cookie: admin } })).json() as Array<{ clientId: string }>
    expect(list.some(r => r.clientId.startsWith('dev-bad-'))).toBe(false)
  })

  it('the class is FIXED at registration: an application never re-declares as device; a device edit keeps the class + the stored binding', async () => {
    const admin = await demoLogin('admin@oiml.org')
    // An application client…
    const appRes = await registerClient(admin, {
      client_id: 'app-fixed', name: 'The application fixture', generate_secret: true,
      redirect_uris: ['https://app-fixed.test/callback'],
    })
    expect(appRes.status).toBe(201)
    // …never becomes a device.
    const flip = await registerClient(admin, {
      client_id: 'app-fixed', name: 'The application fixture', class: 'device', device: DEVICE, generate_secret: true,
    })
    expect(flip.status).toBe(400)
    expect(((await flip.json()) as { error: string }).error).toContain('fixed at registration')

    // A device row's edit WITHOUT the class declaration stays device,
    // keeps the stored binding, and still refuses the human-cone fields.
    const edit = await registerClient(admin, {
      client_id: DEVICE_CLIENT_ID, name: 'ACME LC-500 sn 0001 (the twin, renamed)',
    })
    expect(edit.status).toBe(200)
    const edited = await edit.json() as { class: string; device: typeof DEVICE; name: string }
    expect(edited.class).toBe('device')
    expect(edited.device).toEqual(DEVICE)
    expect(edited.name).toContain('renamed')
    const uriEdit = await registerClient(admin, {
      client_id: DEVICE_CLIENT_ID, name: 'X', redirect_uris: ['https://sneaky.example/callback'],
    })
    expect(uriEdit.status).toBe(400)

    // The device block itself is editable (the model reference corrected),
    // the secret untouched.
    const rebind = await registerClient(admin, {
      client_id: DEVICE_CLIENT_ID, name: 'ACME LC-500 sn 0001 (the twin)',
      device: { ...DEVICE, instrument_model: 'acme-lc500@2021' },
    })
    expect(rebind.status).toBe(200)
  })
})

// ── the token endpoint (the device grant) ────────────────────────────

describe('the token endpoint (the device grant)', () => {
  let deviceSecret = ''

  beforeAll(async () => {
    // The grant legs' own device client (a fresh registration with a
    // known secret — the rotate/revoke legs ride it).
    const admin = await demoLogin('admin@oiml.org')
    const res = await registerClient(admin, {
      client_id: 'device-grant', name: 'The grant fixture (an LC-500 twin)',
      class: 'device', device: { ...DEVICE, id: 'acme-lc500-sn-0002' }, generate_secret: true,
    })
    expect(res.status).toBe(201)
    deviceSecret = ((await res.json()) as { secret: string }).secret!
  })

  it('mints the self-contained device JWT: the device claims exactly, verified against the OP’s JWKS — never an ID token, never a user claim', async () => {
    const res = await deviceToken('device-grant', deviceSecret)
    expect(res.status).toBe(200)
    const body = await res.json() as { access_token: string; token_type: string; expires_in: number; id_token?: string; refresh_token?: string }
    expect(body.token_type).toBe('Bearer')
    expect(body.expires_in).toBeGreaterThan(0)
    expect(body.id_token, 'no ID token — there is no user').toBeUndefined()
    expect(body.refresh_token, 'no refresh — the device re-authenticates').toBeUndefined()

    const claims = await verifyDeviceJwt(body.access_token)
    expect(claims.iss).toBe(ISSUER)
    expect(claims.sub, 'the subject is the DEVICE, not an account').toBe('acme-lc500-sn-0002')
    expect(claims.aud).toBe('device-grant')
    expect(claims.org).toBe('mfr-acme')
    expect(claims.instrument_model).toBe('acme-lc500@2021')
    expect(typeof claims.iat).toBe('number')
    expect(typeof claims.exp).toBe('number')
    // NEVER a user claim.
    for (const userClaim of ['name', 'email', 'email_verified', 'roles', 'groups', 'picture', 'amr', 'nonce']) {
      expect(claims[userClaim], `no ${userClaim} on a device token`).toBeUndefined()
    }
  })

  it('the post secret posture (client_secret_post) mints too', async () => {
    const res = await deviceToken('device-grant', deviceSecret, false)
    expect(res.status).toBe(200)
    const body = await res.json() as { access_token: string }
    expect((await verifyDeviceJwt(body.access_token)).sub).toBe('acme-lc500-sn-0002')
  })

  it('the refusals: the pre-device answer for the application class + the golden’s probe shape, the wrong secret, the unknown client', async () => {
    // No client authentication at all: the contract gate's probe shape
    // (e2e/golden/op-surface-contract.golden.json's token_wrong_grant) —
    // byte-identical to the pre-device surface.
    const bare = await app.request(`${ISSUER}/op/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: 'grant_type=client_credentials',
    })
    expect(bare.status).toBe(400)
    expect(((await bare.json()) as { error: string }).error).toBe('unsupported_grant_type')

    // The application class (a valid RP secret) never speaks the grant.
    const appRefusal = await deviceToken('app-fixed', '')
    expect(appRefusal.status).toBe(400)
    expect(((await appRefusal.json()) as { error: string }).error).toBe('unsupported_grant_type')

    // The unknown client.
    const unknown = await deviceToken('no-such-device', 'whatever')
    expect(unknown.status).toBe(401)
    expect(((await unknown.json()) as { error: string }).error).toBe('invalid_client')

    // The wrong secret.
    const wrong = await deviceToken('device-grant', 'not-the-secret')
    expect(wrong.status).toBe(401)
    expect(((await wrong.json()) as { error: string }).error).toBe('invalid_client')

    // The refresh grant: the OP never mints refresh tokens — refused for
    // the device class like every other class.
    const refresh = await app.request(`${ISSUER}/op/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', authorization: `Basic ${btoa(`device-grant:${deviceSecret}`)}` },
      body: 'grant_type=refresh_token&refresh_token=whatever',
    })
    expect(refresh.status).toBe(400)
    expect(((await refresh.json()) as { error: string }).error).toBe('unsupported_grant_type')
  })

  it('the authorization-code flow refuses the device class — at authorize IN PLACE, and at the token endpoint before any code is consumed', async () => {
    const authorize = await app.request(`${ISSUER}/op/authorize?${new URLSearchParams({
      response_type: 'code', client_id: 'device-grant',
      redirect_uri: 'https://device.example/callback', scope: 'openid',
      state: 's', code_challenge: 'whatever', code_challenge_method: 'S256',
    })}`, { redirect: 'manual' })
    expect(authorize.status).toBe(400)
    expect(authorize.headers.get('location'), 'never a redirect for a device client').toBeNull()
    expect(await authorize.text()).toContain('op-authorize-error')

    // The token leg: a device client presenting the authorization_code
    // grant is refused (no code was ever minted for it — the refusal
    // lands before the consume).
    const token = await app.request(`${ISSUER}/op/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', authorization: `Basic ${btoa(`device-grant:${deviceSecret}`)}` },
      body: new URLSearchParams({
        grant_type: 'authorization_code', code: 'never-issued',
        redirect_uri: 'https://device.example/callback', client_id: 'device-grant', code_verifier: 'whatever',
      }),
    })
    expect(token.status).toBe(400)
    expect(((await token.json()) as { error: string }).error).toBe('unsupported_grant_type')
  })

  it('the audit chain carries the device’s arc: register, rotate-secret, the issuance, the revocation (the disable)', async () => {
    const admin = await demoLogin('admin@oiml.org')

    // The secret rotation (the re-key): the old secret stops working at
    // once, the new one mints.
    const rekey = await registerClient(admin, { client_id: 'device-grant', name: 'The grant fixture (an LC-500 twin)', generate_secret: true })
    expect(rekey.status).toBe(200)
    const rotated = ((await rekey.json()) as { secret: string }).secret!
    expect((await deviceToken('device-grant', deviceSecret)).status, 'the rotated-out secret refuses').toBe(401)
    expect((await deviceToken('device-grant', rotated)).status, 'the fresh secret mints').toBe(200)
    deviceSecret = rotated

    // The revocation (the disable): the grant refuses, the row stays.
    const off = await app.request(`${ISSUER}/api/op/clients/device-grant/status`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie: admin },
      body: JSON.stringify({ status: 'disabled' }),
    })
    expect(off.status).toBe(200)
    expect((await deviceToken('device-grant', rotated)).status).toBe(401)

    const rows = await journal()
    const registered = rows.find(e => e.action === 'client.registered' && e.entity_id === 'device-grant')
    expect(registered?.metadata).toMatchObject({ class: 'device', device: { id: 'acme-lc500-sn-0002', org: 'mfr-acme', instrument_model: 'acme-lc500@2021' } })
    const rotatedRow = rows.filter(e => e.action === 'client.updated' && e.entity_id === 'device-grant').at(-1)
    expect(rotatedRow?.metadata).toMatchObject({ class: 'device', rekeyed: true })
    const issued = rows.filter(e => e.action === 'client.token_issued' && e.entity_id === 'device-grant').at(-1)
    expect(issued?.metadata).toMatchObject({ class: 'device', device: 'acme-lc500-sn-0002', org: 'mfr-acme', instrument_model: 'acme-lc500@2021' })
    const revoked = rows.filter(e => e.action === 'client.status' && e.entity_id === 'device-grant').at(-1)
    expect(revoked?.metadata).toMatchObject({ status: 'disabled', class: 'device', device: 'acme-lc500-sn-0002' })
  })
})

// ── the bootstrap seed (OP_CLIENT_SEED accepts the class) ────────────

describe('the bootstrap seed (OP_CLIENT_SEED accepts the device class)', () => {
  it('a device entry seeds the class and mints', async () => {
    const seeded = await seedOidcClientsFromEnv({
      OP_CLIENT_SEED: JSON.stringify([{
        client_id: 'device-seeded', name: 'The seeded LC-500 twin', class: 'device',
        device: { id: 'acme-lc500-sn-0003', org: 'mfr-acme', instrument_model: 'acme-lc500@2021' },
        secret: 'the-seeded-device-secret',
      }]),
    }, store)
    expect(seeded).toEqual(['device-seeded'])
    const row = await store.getOidcClient('device-seeded')
    expect(row?.redirectUris).toEqual([])
    const res = await deviceToken('device-seeded', 'the-seeded-device-secret')
    expect(res.status).toBe(200)
    const claims = await verifyDeviceJwt(((await res.json()) as { access_token: string }).access_token)
    expect(claims.sub).toBe('acme-lc500-sn-0003')
    expect(claims.org).toBe('mfr-acme')
  })

  it('the malformed device entries fail the parse loudly — the boot never guesses', () => {
    const base = { client_id: 'x', name: 'X', class: 'device', device: DEVICE, secret: 's' }
    for (const [label, entry, fragment] of [
      ['no secret', (() => { const { secret: _s, ...rest } = base; return rest })(), 'secret is required'],
      ['redirect_uris', { ...base, redirect_uris: ['https://x.example/cb'] }, 'no redirect_uris'],
      ['a launch card', { ...base, launch: { url: 'https://x.example/signin' } }, 'never joins the SSO home'],
      ['a claims policy', { ...base, claims_policy: { claims: ['roles'] } }, 'claims are fixed by the class'],
      ['a device block without the class', { client_id: 'y', name: 'Y', redirect_uris: [], device: DEVICE }, 'declare the class'],
      ['an application entry without redirect_uris', { client_id: 'z', name: 'Z' }, 'redirect_uris is required'],
    ] as Array<[string, Record<string, unknown>, string]>) {
      expect(() => parseOpClientSeed(JSON.stringify([entry])), label).toThrow(fragment)
    }
  })
})
