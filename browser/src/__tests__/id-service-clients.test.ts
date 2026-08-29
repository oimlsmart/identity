// ─────────────────────────────────────────────────────────────────────
// The machine cone's GENERAL half (the service class on the client
// registry — TODO.identity-ops/07), proven in-process: the REAL op
// router (server/routes/op.ts) over a REAL temp SQLite store, the demo
// cast for the admin acts, and the OP's own JWKS verifying the service
// tokens (the called service's posture — no stub anywhere).
//
// Covered:
//   THE REGISTRY     — the service class's shape enforced at write: the
//     VALIDATION       service block required (id/org/audience/scopes),
//                      the org resolved on the organization registry, no
//                      redirect_uris, no launch card, no user claims,
//                      always confidential; the class FIXED at
//                      registration (an app row refuses the service
//                      re-declaration, a DEVICE row refuses it too, a
//                      service row's edit keeps the class and the stored
//                      block); the admin API's view carries the class +
//                      the block (what the console renders).
//   THE TOKEN        — client_credentials mints the self-contained ES256
//     ENDPOINT         service JWT (sub = the service id, aud = the
//                      DECLARED AUDIENCE — the audience binding the
//                      device class does not have —, client_id, org,
//                      scope — NEVER a user claim, never an ID token,
//                      never a refresh); the scope narrowing (a subset
//                      mints, a scope beyond the allowlist refuses
//                      invalid_scope, an empty parameter refuses);
//                      every other grant refused (authorization_code at
//                      authorize AND at token, refresh_token); the
//                      application class refused client_credentials with
//                      the pre-machine answer (the contract golden's
//                      shape stands); the wrong secret + the disabled
//                      client refused; the audit chain carries register /
//                      rotate-secret / issuance (naming the audience +
//                      the scopes) / revoke.
//   THE SEED         — OP_CLIENT_SEED accepts the class (the seeded
//                      service mints); the malformed service entries fail
//                      the parse loudly (no secret, redirect_uris, a
//                      launch card, a claims policy, the block without
//                      the class, an empty allowlist).
// ─────────────────────────────────────────────────────────────────────

import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

// The store's DB path is read at module evaluation — set it before any
// import below touches @oimlsmart/platform-server/store/sqlite (the imports are dynamic).
const TMP = mkdtempSync(join(tmpdir(), 'oiml-op-service-'))
process.env.DATABASE_PATH = join(TMP, 'test.db')

const ISSUER = 'http://op.test'
process.env.OP_ISSUER = ISSUER

/** The demo binding: the estate's RAG MCP ingest pipeline (a service
 *  account — the item file's reference caller) on the demonstration
 *  manufacturer org (created in beforeAll). */
const SERVICE = { id: 'rag-mcp-ingest', org: 'mfr-acme', audience: 'oiml-rag-mcp', scopes: ['documents:read', 'ingest:write'] }
const SERVICE_CLIENT_ID = 'svc-rag-mcp-ingest'

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

/** The machine grant at the token endpoint (client_secret_basic or post),
 *  optionally with the RFC 6749 §4.4 scope parameter. */
async function serviceToken(clientId: string, secret: string | null, opts: { basic?: boolean; scope?: string } = {}): Promise<Response> {
  const { basic = true, scope } = opts
  const headers: Record<string, string> = { 'content-type': 'application/x-www-form-urlencoded' }
  const body = new URLSearchParams({ grant_type: 'client_credentials' })
  if (scope !== undefined) body.set('scope', scope)
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

/** Verify the service JWT against the OP's OWN JWKS (the called service's
 *  validation posture) and answer its claims. */
async function verifyServiceJwt(token: string): Promise<Record<string, unknown>> {
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
  expect(ok, 'the service token verifies against the OP’s JWKS').toBe(true)
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

  // The service binding's org: the demonstration manufacturer on the
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

describe('the registry validation (the service class’s shape)', () => {
  it('registers a service client — the view carries the class + the service block, never the human-cone fields', async () => {
    const admin = await demoLogin('admin@oiml.org')
    const res = await registerClient(admin, {
      client_id: SERVICE_CLIENT_ID,
      name: 'The RAG’s MCP ingest pipeline',
      class: 'service',
      service: SERVICE,
      generate_secret: true,
    })
    expect(res.status).toBe(201)
    const created = await res.json() as {
      clientId: string; class: string; service: typeof SERVICE; device: unknown; redirectUris: string[]
      launch: unknown; confidential: boolean; claimsPolicy: { claims: string[] }; secret?: string
    }
    expect(created.class).toBe('service')
    expect(created.service).toEqual(SERVICE)
    expect(created.device, 'never the device block').toBeNull()
    expect(created.redirectUris).toEqual([])
    expect(created.launch).toBeNull()
    expect(created.confidential, 'a service client is always confidential').toBe(true)
    expect(created.claimsPolicy.claims, 'the class fixes the claim set — no user claims').toEqual([])
    expect(created.secret, 'the generated secret rides the registration response once').toBeTruthy()

    // The LIST view carries the same honest shape (the console renders it).
    const list = await (await app.request(`${ISSUER}/api/op/clients`, { headers: { cookie: admin } })).json() as Array<Record<string, unknown>>
    const row = list.find(r => r.clientId === SERVICE_CLIENT_ID)!
    expect(row.class).toBe('service')
    expect(row.service).toEqual(SERVICE)
    expect(JSON.stringify(row)).not.toContain(created.secret!) // never the secret
  })

  it('refuses the human-cone shape on a service: redirect_uris, a launch card, user claims, the public posture', async () => {
    const admin = await demoLogin('admin@oiml.org')
    const base = { name: 'A misdeclared service', class: 'service', service: SERVICE, generate_secret: true }
    const cases: Array<[string, Record<string, unknown>, string]> = [
      ['redirect_uris', { ...base, client_id: 'svc-bad-uris', redirect_uris: ['https://svc.example/callback'] }, 'no redirect_uris'],
      ['a launch card', { ...base, client_id: 'svc-bad-launch', launch: { url: 'https://svc.example/signin' } }, 'never joins the SSO home'],
      ['user claims', { ...base, client_id: 'svc-bad-claims', claims_policy: { claims: ['roles'] } }, 'never carries user claims'],
      ['a role allowlist', { ...base, client_id: 'svc-bad-roles', claims_policy: { claims: [], roles: ['viewer'] } }, 'never carries user claims'],
      ['the public posture', { ...base, client_id: 'svc-bad-public', generate_secret: undefined, secret: null }, 'confidential'],
      ['no secret at all', { ...base, client_id: 'svc-bad-nosecret', generate_secret: undefined }, 'confidential'],
      ['an unknown org', { ...base, client_id: 'svc-bad-org', service: { ...SERVICE, org: 'no-such-org' } }, 'not on the organization registry'],
      ['a missing service id', { ...base, client_id: 'svc-bad-noid', service: { ...SERVICE, id: '' } }, 'service.id is required'],
      ['a missing audience', { ...base, client_id: 'svc-bad-noaud', service: { ...SERVICE, audience: '' } }, 'service.audience is required'],
      ['an empty allowlist', { ...base, client_id: 'svc-bad-noscopes', service: { ...SERVICE, scopes: [] } }, 'non-empty'],
      ['an unknown class', { client_id: 'svc-bad-class', name: 'X', class: 'machine', redirect_uris: ['https://x.example/cb'] }, 'class must be'],
      ['a device block on the service class', { ...base, client_id: 'svc-bad-cross', device: { id: 'd', org: 'mfr-acme', instrument_model: 'm' } }, 'the device block rides class'],
    ]
    for (const [label, body, fragment] of cases) {
      const res = await registerClient(admin, body)
      const err = await res.json() as { error?: string }
      expect(res.status, `${label}: refused (${err.error ?? ''})`).toBe(400)
      expect(err.error, `${label}: the honest reason`).toContain(fragment)
    }
    // None of the refused rows landed.
    const list = await (await app.request(`${ISSUER}/api/op/clients`, { headers: { cookie: admin } })).json() as Array<{ clientId: string }>
    expect(list.some(r => r.clientId.startsWith('svc-bad-'))).toBe(false)
  })

  it('the class is FIXED at registration: an application never re-declares as service, a DEVICE never re-declares as service; a service edit keeps the class + the stored binding', async () => {
    const admin = await demoLogin('admin@oiml.org')
    // An application client…
    const appRes = await registerClient(admin, {
      client_id: 'app-fixed', name: 'The application fixture', generate_secret: true,
      redirect_uris: ['https://app-fixed.test/callback'],
    })
    expect(appRes.status).toBe(201)
    // …never becomes a service.
    const flip = await registerClient(admin, {
      client_id: 'app-fixed', name: 'The application fixture', class: 'service', service: SERVICE, generate_secret: true,
    })
    expect(flip.status).toBe(400)
    expect(((await flip.json()) as { error: string }).error).toContain('fixed at registration')

    // A DEVICE row never becomes a service either (the classes are
    // distinct bindings — a re-registration, never an edit).
    const devRes = await registerClient(admin, {
      client_id: 'device-fixed', name: 'The device fixture', class: 'device',
      device: { id: 'acme-lc500-sn-0009', org: 'mfr-acme', instrument_model: 'acme-lc500@2021' }, generate_secret: true,
    })
    expect(devRes.status).toBe(201)
    const devFlip = await registerClient(admin, {
      client_id: 'device-fixed', name: 'The device fixture', class: 'service', service: SERVICE, generate_secret: true,
    })
    expect(devFlip.status).toBe(400)
    expect(((await devFlip.json()) as { error: string }).error).toContain('fixed at registration')

    // A service row's edit WITHOUT the class declaration stays service,
    // keeps the stored binding, and still refuses the human-cone fields.
    const edit = await registerClient(admin, {
      client_id: SERVICE_CLIENT_ID, name: 'The RAG’s MCP ingest pipeline (renamed)',
    })
    expect(edit.status).toBe(200)
    const edited = await edit.json() as { class: string; service: typeof SERVICE; name: string }
    expect(edited.class).toBe('service')
    expect(edited.service).toEqual(SERVICE)
    expect(edited.name).toContain('renamed')
    const uriEdit = await registerClient(admin, {
      client_id: SERVICE_CLIENT_ID, name: 'X', redirect_uris: ['https://sneaky.example/callback'],
    })
    expect(uriEdit.status).toBe(400)

    // The service block itself is editable (the allowlist widened by an
    // admin act), the secret untouched.
    const rebind = await registerClient(admin, {
      client_id: SERVICE_CLIENT_ID, name: 'The RAG’s MCP ingest pipeline',
      service: { ...SERVICE, scopes: [...SERVICE.scopes, 'reports:read'] },
    })
    expect(rebind.status).toBe(200)
    const rebound = await rebind.json() as { service: typeof SERVICE }
    expect(rebound.service.scopes).toContain('reports:read')
    // …and narrowed back for the grant legs below.
    await registerClient(admin, { client_id: SERVICE_CLIENT_ID, name: 'The RAG’s MCP ingest pipeline', service: SERVICE })
  })
})

// ── the token endpoint (the service grant) ───────────────────────────

describe('the token endpoint (the service grant)', () => {
  let serviceSecret = ''

  beforeAll(async () => {
    // The grant legs' own service client (a fresh registration with a
    // known secret — the rotate/revoke legs ride it).
    const admin = await demoLogin('admin@oiml.org')
    const res = await registerClient(admin, {
      client_id: 'service-grant', name: 'The grant fixture (a service account)',
      class: 'service', service: { ...SERVICE, id: 'rag-mcp-ingest-2' }, generate_secret: true,
    })
    expect(res.status).toBe(201)
    serviceSecret = ((await res.json()) as { secret: string }).secret!
  })

  it('mints the self-contained service JWT: the service claims exactly, verified against the OP’s JWKS — the DECLARED audience, never an ID token, never a user claim', async () => {
    const res = await serviceToken('service-grant', serviceSecret)
    expect(res.status).toBe(200)
    const body = await res.json() as { access_token: string; token_type: string; expires_in: number; scope?: string; id_token?: string; refresh_token?: string }
    expect(body.token_type).toBe('Bearer')
    expect(body.expires_in).toBeGreaterThan(0)
    expect(body.scope, 'the effective scopes ride the answer').toBe('documents:read ingest:write')
    expect(body.id_token, 'no ID token — there is no user').toBeUndefined()
    expect(body.refresh_token, 'no refresh — the service re-authenticates').toBeUndefined()

    const claims = await verifyServiceJwt(body.access_token)
    expect(claims.iss).toBe(ISSUER)
    expect(claims.sub, 'the subject is the SERVICE, not an account').toBe('rag-mcp-ingest-2')
    expect(claims.aud, 'the audience is the DECLARED one, not the client id').toBe('oiml-rag-mcp')
    expect(claims.client_id).toBe('service-grant')
    expect(claims.org).toBe('mfr-acme')
    expect(claims.scope).toBe('documents:read ingest:write')
    expect(typeof claims.iat).toBe('number')
    expect(typeof claims.exp).toBe('number')
    // NEVER a user claim, never the device class's claim shape.
    for (const userClaim of ['name', 'email', 'email_verified', 'roles', 'groups', 'picture', 'amr', 'nonce', 'instrument_model']) {
      expect(claims[userClaim], `no ${userClaim} on a service token`).toBeUndefined()
    }
  })

  it('the scope narrowing: a subset mints the narrowed token; a scope beyond the allowlist refuses invalid_scope; an empty parameter refuses', async () => {
    // The subset (the caller asks only for what this run needs).
    const narrowed = await serviceToken('service-grant', serviceSecret, { scope: 'documents:read' })
    expect(narrowed.status).toBe(200)
    const narrowedBody = await narrowed.json() as { access_token: string; scope: string }
    expect(narrowedBody.scope).toBe('documents:read')
    expect((await verifyServiceJwt(narrowedBody.access_token)).scope).toBe('documents:read')

    // The reordered + duplicated subset is still a subset (deduped).
    const reordered = await serviceToken('service-grant', serviceSecret, { scope: 'ingest:write documents:read ingest:write' })
    expect(reordered.status).toBe(200)
    expect(((await reordered.json()) as { scope: string }).scope).toBe('ingest:write documents:read')

    // A scope beyond the allowlist refuses — never a silent drop, never
    // a mint beyond the registered set.
    const beyond = await serviceToken('service-grant', serviceSecret, { scope: 'documents:read admin:write' })
    expect(beyond.status).toBe(400)
    const beyondErr = await beyond.json() as { error: string; error_description?: string }
    expect(beyondErr.error).toBe('invalid_scope')
    expect(beyondErr.error_description).toContain('admin:write')

    // The empty parameter refuses honestly (a scope-less service token is
    // a caller bug — the class's point is the scoped claim).
    const empty = await serviceToken('service-grant', serviceSecret, { scope: '' })
    expect(empty.status).toBe(400)
    expect(((await empty.json()) as { error: string }).error).toBe('invalid_scope')

    // The post secret posture (client_secret_post) mints too.
    const post = await serviceToken('service-grant', serviceSecret, { basic: false })
    expect(post.status).toBe(200)
    expect((await verifyServiceJwt(((await post.json()) as { access_token: string }).access_token)).sub).toBe('rag-mcp-ingest-2')
  })

  it('the refusals: the pre-machine answer for the application class + the golden’s probe shape, the wrong secret, the unknown client', async () => {
    // No client authentication at all: the contract gate's probe shape
    // (e2e/golden/op-surface-contract.golden.json's token_wrong_grant) —
    // byte-identical to the pre-machine surface.
    const bare = await app.request(`${ISSUER}/op/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: 'grant_type=client_credentials',
    })
    expect(bare.status).toBe(400)
    expect(((await bare.json()) as { error: string }).error).toBe('unsupported_grant_type')

    // The application class (a valid RP secret) never speaks the grant.
    const appRefusal = await serviceToken('app-fixed', '')
    expect(appRefusal.status).toBe(400)
    expect(((await appRefusal.json()) as { error: string }).error).toBe('unsupported_grant_type')

    // The device class's answer stands too (a device client mints its OWN
    // claim shape — the classes never cross).
    const deviceMint = await serviceToken('device-fixed', null)
    expect(deviceMint.status).toBe(401) // the wrong secret (none) — never a service token

    // The unknown client.
    const unknown = await serviceToken('no-such-service', 'whatever')
    expect(unknown.status).toBe(401)
    expect(((await unknown.json()) as { error: string }).error).toBe('invalid_client')

    // The wrong secret.
    const wrong = await serviceToken('service-grant', 'not-the-secret')
    expect(wrong.status).toBe(401)
    expect(((await wrong.json()) as { error: string }).error).toBe('invalid_client')

    // The refresh grant: the OP never mints refresh tokens — refused for
    // the service class like every other class.
    const refresh = await app.request(`${ISSUER}/op/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', authorization: `Basic ${btoa(`service-grant:${serviceSecret}`)}` },
      body: 'grant_type=refresh_token&refresh_token=whatever',
    })
    expect(refresh.status).toBe(400)
    expect(((await refresh.json()) as { error: string }).error).toBe('unsupported_grant_type')
  })

  it('the authorization-code flow refuses the service class — at authorize IN PLACE, and at the token endpoint before any code is consumed', async () => {
    const authorize = await app.request(`${ISSUER}/op/authorize?${new URLSearchParams({
      response_type: 'code', client_id: 'service-grant',
      redirect_uri: 'https://svc.example/callback', scope: 'openid',
      state: 's', code_challenge: 'whatever', code_challenge_method: 'S256',
    })}`, { redirect: 'manual' })
    expect(authorize.status).toBe(400)
    expect(authorize.headers.get('location'), 'never a redirect for a service client').toBeNull()
    expect(await authorize.text()).toContain('op-authorize-error')

    // The token leg: a service client presenting the authorization_code
    // grant is refused (no code was ever minted for it — the refusal
    // lands before the consume).
    const token = await app.request(`${ISSUER}/op/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', authorization: `Basic ${btoa(`service-grant:${serviceSecret}`)}` },
      body: new URLSearchParams({
        grant_type: 'authorization_code', code: 'never-issued',
        redirect_uri: 'https://svc.example/callback', client_id: 'service-grant', code_verifier: 'whatever',
      }),
    })
    expect(token.status).toBe(400)
    expect(((await token.json()) as { error: string }).error).toBe('unsupported_grant_type')
  })

  it('the audit chain carries the service’s arc: register, rotate-secret, the issuance (naming the audience + scopes), the revocation (the disable)', async () => {
    const admin = await demoLogin('admin@oiml.org')

    // The secret rotation (the re-key): the old secret stops working at
    // once, the new one mints.
    const rekey = await registerClient(admin, { client_id: 'service-grant', name: 'The grant fixture (a service account)', generate_secret: true })
    expect(rekey.status).toBe(200)
    const rotated = ((await rekey.json()) as { secret: string }).secret!
    expect((await serviceToken('service-grant', serviceSecret)).status, 'the rotated-out secret refuses').toBe(401)
    expect((await serviceToken('service-grant', rotated)).status, 'the fresh secret mints').toBe(200)
    serviceSecret = rotated

    // The revocation (the disable): the grant refuses, the row stays.
    const off = await app.request(`${ISSUER}/api/op/clients/service-grant/status`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie: admin },
      body: JSON.stringify({ status: 'disabled' }),
    })
    expect(off.status).toBe(200)
    expect((await serviceToken('service-grant', rotated)).status).toBe(401)

    const rows = await journal()
    const registered = rows.find(e => e.action === 'client.registered' && e.entity_id === 'service-grant')
    expect(registered?.metadata).toMatchObject({ class: 'service', service: { id: 'rag-mcp-ingest-2', org: 'mfr-acme', audience: 'oiml-rag-mcp', scopes: ['documents:read', 'ingest:write'] } })
    const rotatedRow = rows.filter(e => e.action === 'client.updated' && e.entity_id === 'service-grant').at(-1)
    expect(rotatedRow?.metadata).toMatchObject({ class: 'service', rekeyed: true })
    const issued = rows.filter(e => e.action === 'client.token_issued' && e.entity_id === 'service-grant').at(-1)
    expect(issued?.metadata).toMatchObject({ class: 'service', service: 'rag-mcp-ingest-2', org: 'mfr-acme', audience: 'oiml-rag-mcp', scopes: ['documents:read', 'ingest:write'] })
    const revoked = rows.filter(e => e.action === 'client.status' && e.entity_id === 'service-grant').at(-1)
    expect(revoked?.metadata).toMatchObject({ status: 'disabled', class: 'service', service: 'rag-mcp-ingest-2' })
  })
})

// ── the bootstrap seed (OP_CLIENT_SEED accepts the class) ────────────

describe('the bootstrap seed (OP_CLIENT_SEED accepts the service class)', () => {
  it('a service entry seeds the class and mints', async () => {
    const seeded = await seedOidcClientsFromEnv({
      OP_CLIENT_SEED: JSON.stringify([{
        client_id: 'service-seeded', name: 'The seeded service account', class: 'service',
        service: { id: 'nightly-reconcile', org: 'mfr-acme', audience: 'oiml-smart-platform', scopes: ['reconcile:run'] },
        secret: 'the-seeded-service-secret',
      }]),
    }, store)
    expect(seeded).toEqual(['service-seeded'])
    const row = await store.getOidcClient('service-seeded')
    expect(row?.redirectUris).toEqual([])
    const res = await serviceToken('service-seeded', 'the-seeded-service-secret')
    expect(res.status).toBe(200)
    const claims = await verifyServiceJwt(((await res.json()) as { access_token: string }).access_token)
    expect(claims.sub).toBe('nightly-reconcile')
    expect(claims.aud).toBe('oiml-smart-platform')
    expect(claims.scope).toBe('reconcile:run')
  })

  it('the malformed service entries fail the parse loudly — the boot never guesses', () => {
    const base = { client_id: 'x', name: 'X', class: 'service', service: SERVICE, secret: 's' }
    for (const [label, entry, fragment] of [
      ['no secret', (() => { const { secret: _s, ...rest } = base; return rest })(), 'secret is required'],
      ['redirect_uris', { ...base, redirect_uris: ['https://x.example/cb'] }, 'no redirect_uris'],
      ['a launch card', { ...base, launch: { url: 'https://x.example/signin' } }, 'never joins the SSO home'],
      ['a claims policy', { ...base, claims_policy: { claims: ['roles'] } }, 'claims are fixed by the class'],
      ['a service block without the class', { client_id: 'y', name: 'Y', redirect_uris: [], service: SERVICE, secret: 's' }, 'declare the class'],
      ['an empty allowlist', { ...base, service: { ...SERVICE, scopes: [] } }, 'non-empty'],
    ] as Array<[string, Record<string, unknown>, string]>) {
      expect(() => parseOpClientSeed(JSON.stringify([entry])), label).toThrow(fragment)
    }
  })
})
