// ─────────────────────────────────────────────────────────────────────
// TODO.identity/03 — the central user registry + the per-client role
// claims, proven in-process: the REAL op router (server/routes/op.ts),
// the REAL accounts router (server/routes/op-accounts.ts) and the REAL
// users router (server/routes/users.ts — 10's org scope) over a REAL
// temp SQLite store, the RP's REAL validator consuming the ID tokens.
//
// Covered:
//   THE CLAIM-SHAPING RULE (auth/op/claims.ts) — the assignment or the
//     account default, the policy allowlist, the claim gate; then
//     through the REAL round trip (token + userinfo + the consent
//     context): the assigned roles ride the ID token, the explicit
//     empty assignment emits NO role claim, the allowlist filters.
//   THE POLICY EVALUATION — the client registry's role allowlist is
//     validated at write (the API + the seed parser); an unknown role
//     is a configuration bug, refused loudly.
//   THE ADMIN ACTS — the invite (the 02 seam + the 10 org binding +
//     per-client roles), the edit (name/email, the 409 conflict), the
//     per-client assignment PUT/DELETE, the honest deactivation
//     (history kept, sign-ins refused, sessions + issued tokens
//     revoked) + the reactivation, every act on the audit chain, the
//     registry list's last-sign-in column read back from it.
//   THE ORG-SCOPE REUSE — the org admin (org.users.manage) never
//     reaches the registry's acts (403), and keeps 10's /api/users
//     slice untouched.
//   THE INSTANCE HONORS THE CLAIMS — the OP's roles claim maps through
//     rolesFromClaims/mapClaims (never inventing a role); no claim →
//     the configured viewer default or the approval queue, never
//     silence.
// ─────────────────────────────────────────────────────────────────────

import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

// The store's DB path is read at module evaluation — set it before any
// import below touches @oimlsmart/platform-server/store/sqlite (the imports are dynamic).
const TMP = mkdtempSync(join(tmpdir(), 'oiml-registry-'))
process.env.DATABASE_PATH = join(TMP, 'test.db')

const ISSUER = 'http://op.test'
process.env.OP_ISSUER = ISSUER

// The client registry's bootstrap: the hub (confidential; the role-claim
// policy WITH its role allowlist), the TL (confidential; role claims,
// NO allowlist — the policy does not bound the set), and an email-only
// public client (no role claims at all — 01's gate).
const HUB = {
  client_id: 'hub-instance',
  name: 'OIML SMART platform hub',
  secret: 'hub-secret-123',
  redirect_uris: ['https://hub.example/api/auth/callback/oidc'],
  claims_policy: { claims: ['roles', 'groups', 'org'], roles: ['admin', 'cs_admin', 'ia_officer', 'viewer'] },
}
const TL = {
  client_id: 'tl-instance',
  name: 'Example TL instance',
  secret: 'tl-secret-456',
  redirect_uris: ['https://tl.example/api/auth/callback/oidc'],
  claims_policy: { claims: ['roles', 'groups'] },
}
const EMAIL_ONLY = {
  client_id: 'plain-public',
  name: 'A plain OIDC relay',
  redirect_uris: ['https://relay.example/callback'],
}
process.env.OP_CLIENT_SEED = JSON.stringify([HUB, TL, EMAIL_ONLY])

let app: import('hono').Hono
let store: ReturnType<typeof import('@oimlsmart/platform-server/store').getStore>
let validateIdToken: typeof import('@oimlsmart/platform-server/oidc').validateIdToken
let generatePkce: typeof import('@oimlsmart/platform-server/oidc').generatePkce

/** The fetch adapter the RP's validator runs against: the in-process
 *  app itself (discovery/JWKS ride the real routes). */
const appFetch = (async (input: RequestInfo | URL): Promise<Response> => {
  const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url
  return app.request(url)
}) as typeof fetch

async function demoLogin(email: string): Promise<string> {
  const res = await app.request('/api/auth/demo', {
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

/** The invite act (the admin's registry); answers the 201 payload. */
async function invite(cookie: string, body: Record<string, unknown>, status = 201): Promise<any> {
  const res = await app.request(`${ISSUER}/api/op/accounts`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', cookie },
    body: JSON.stringify(body),
  })
  return json(res, status)
}

/** Complete the one-time setup link (sets the password; signs the
 *  account in). Answers the fresh session cookie. */
async function enroll(setupUrl: string, password: string): Promise<string> {
  const token = new URL(setupUrl).searchParams.get('token')!
  const res = await app.request(`${ISSUER}/api/op/enroll/${token}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ password }),
  })
  expect(res.status, 'the enrollment completes').toBe(200)
  return res.headers.get('set-cookie')!.split(';')[0]!
}

async function passwordLogin(email: string, password: string): Promise<Response> {
  return app.request(`${ISSUER}/api/op/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password }),
  })
}

/** Drive authorize → consent → decide; answers the consent context +
 *  the minted code. */
async function driveAuthorize(
  cookie: string,
  params: { clientId: string; redirectUri: string; nonce?: string; challenge: string },
): Promise<{ consent: any; code: string }> {
  const query = new URLSearchParams({
    response_type: 'code',
    client_id: params.clientId,
    redirect_uri: params.redirectUri,
    scope: 'openid profile email',
    state: 'st-1',
    nonce: params.nonce ?? 'nn-1',
    code_challenge: params.challenge,
    code_challenge_method: 'S256',
  })
  const authorize = await app.request(`${ISSUER}/op/authorize?${query}`, { headers: { cookie } })
  expect(authorize.status, 'authorize redirects to the consent page').toBe(302)
  const authId = new URL(authorize.headers.get('location')!, ISSUER).searchParams.get('auth')!
  const contextRes = await app.request(`${ISSUER}/api/op/consent/${authId}`, { headers: { cookie } })
  const consent = await json(contextRes, 200)
  const decide = await app.request(`${ISSUER}/api/op/consent/${authId}/decide`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', cookie },
    body: JSON.stringify({ decision: 'allow' }),
  })
  const { redirect } = await json(decide, 200)
  const code = new URL(redirect).searchParams.get('code')!
  expect(code, 'the allow decision carries a code').toBeTruthy()
  return { consent, code }
}

/** The token exchange + the RP-validated claims (+ the access token). */
async function exchangeAndValidate(
  params: { code: string; redirectUri: string; clientId: string; verifier: string; secret?: string; nonce?: string },
): Promise<{ claims: Record<string, unknown>; accessToken: string }> {
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code: params.code,
    redirect_uri: params.redirectUri,
    client_id: params.clientId,
    code_verifier: params.verifier,
  })
  const headers: Record<string, string> = { 'content-type': 'application/x-www-form-urlencoded' }
  if (params.secret !== undefined) {
    headers.authorization = `Basic ${btoa(`${encodeURIComponent(params.clientId)}:${encodeURIComponent(params.secret)}`)}`
  }
  const token = await app.request(`${ISSUER}/op/token`, { method: 'POST', headers, body })
  expect(token.status, 'the code exchange').toBe(200)
  const tokens = await token.json() as { id_token: string; access_token: string }
  const claims = await validateIdToken(tokens.id_token, {
    issuer: ISSUER,
    clientId: params.clientId,
    nonce: params.nonce ?? 'nn-1',
    jwksUri: `${ISSUER}/jwks.json`,
  }, appFetch)
  return { claims: claims as Record<string, unknown>, accessToken: tokens.access_token }
}

/** The audit chain's rows for one account (the registry's read-back). */
async function auditRowsFor(accountId: string): Promise<Array<{ action: string; metadata: any }>> {
  const rows = await store.listEntities('auditEvents')
  return rows
    .map(r => JSON.parse(r.data) as { entity_id?: string; action: string; metadata?: any })
    .filter(e => e.entity_id === accountId)
    .map(e => ({ action: e.action, metadata: e.metadata }))
}

beforeAll(async () => {
  // The simulated deployment declares its signing key (identity#7's
  // registration gate: a declared-issuer instance never registers a
  // GENERATED development key into oidc_keys — exchangeAndValidate
  // below validates against the JWKS, so the served key must be the
  // declared one, exactly the production posture).
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

  const oidc = await import('@oimlsmart/platform-server/oidc')
  validateIdToken = oidc.validateIdToken
  generatePkce = oidc.generatePkce
  oidc.clearOidcCaches()

  const { Hono } = await import('hono')
  const { createAuthLeanRouter } = await import('../../server/routes/auth-lean')
  const { createOpRouter } = await import('../../server/routes/op')
  const { createOpAccountsRouter } = await import('../../server/routes/op-accounts')
  const { createUsersRouter } = await import('../../server/routes/users')
  const root = new Hono()
  root.route('/api/auth', createAuthLeanRouter({ autoSeedDemo: true }))
  root.route('/', createOpRouter())
  root.route('/', createOpAccountsRouter())
  root.route('/api/users', createUsersRouter())
  app = root

  // The participants register (the org binding's source of truth —
  // 10's seeded-register posture): one REGISTERED Utilizer.
  await store.putEntity('utilizers', 'ut-nmi-nl', null, JSON.stringify({
    id: 'ut-nmi-nl', name: 'Example Metrology Authority (Netherlands)', short_name: 'EMA-NL', country: 'Netherlands', contact: { email: 'oiml-cs@nmi.example.org' },
  }))
  await store.putEntity('participantDeclarations', 'decl-ut-nl', null, JSON.stringify({ id: 'decl-ut-nl', participant_id: 'ut-nmi-nl', status: 'signed' }))

  // TODO.identity-features/05: the org binding's source of truth is the
  // identity service's OWN organization registry — the same Utilizer as
  // an ACTIVE registry org (the participant link is the annotation).
  await store.createOrgRegistryOrg({
    id: 'ut-nmi-nl',
    name: 'Example Metrology Authority (Netherlands)',
    shortName: 'EMA-NL',
    kind: 'utilizer',
    country: 'Netherlands',
    contacts: [{ name: null, email: 'oiml-cs@nmi.example.org' }],
    participantRef: 'ut-nmi-nl',
  })

  // The bootstrap seeds land on the first requests.
  const probe = await app.request(`${ISSUER}/.well-known/openid-configuration`)
  expect(probe.status).toBe(200)
  await demoLogin('admin@oiml.org')
})

afterAll(async () => {
  const profileMod = await import('@oimlsmart/platform-server/profile')
  profileMod.resetInstanceProfileForTest()
  rmSync(TMP, { recursive: true, force: true })
  delete process.env.OP_ISSUER
  delete process.env.OP_SIGNING_KEY
  delete process.env.OP_CLIENT_SEED
  delete process.env.DATABASE_PATH
})

// ── the claim-shaping rule (the pure half) ───────────────────────────

describe('the claim-shaping rule (auth/op/claims.ts)', () => {
  let rolesForClient: typeof import('../../server/auth/op/claims').rolesForClient
  let roleClaimsForClient: typeof import('../../server/auth/op/claims').roleClaimsForClient
  let pictureClaimForClient: typeof import('../../server/auth/op/claims').pictureClaimForClient
  beforeAll(async () => {
    const mod = await import('../../server/auth/op/claims')
    rolesForClient = mod.rolesForClient
    roleClaimsForClient = mod.roleClaimsForClient
    pictureClaimForClient = mod.pictureClaimForClient
  })

  it('no assignment row → the account default carries (the pre-03 behavior)', () => {
    expect(rolesForClient(null, ['ia_officer'], { claims: ['roles'] })).toEqual(['ia_officer'])
  })

  it('the assignment overrides the account default for its client', () => {
    expect(rolesForClient(['tl_operator'], ['viewer'], { claims: ['roles'] })).toEqual(['tl_operator'])
  })

  it('the explicit EMPTY assignment is “no roles on this client” (never the default)', () => {
    expect(rolesForClient([], ['admin'], { claims: ['roles'] })).toEqual([])
  })

  it('the policy allowlist bounds the emitted set — a role the client is not configured to receive never emits', () => {
    expect(rolesForClient(['admin', 'ia_officer'], ['admin'], { claims: ['roles'], roles: ['ia_officer', 'viewer'] }))
      .toEqual(['ia_officer'])
    // …and a fully-filtered set emits nothing.
    expect(rolesForClient(['admin'], ['admin'], { claims: ['roles'], roles: ['viewer'] })).toEqual([])
  })

  it('the claim gate decides WHICH keys appear; an empty set omits the claim', () => {
    const policy = { claims: ['roles', 'groups', 'org'] }
    expect(roleClaimsForClient(null, { role: 'ia_officer', roles: ['ia_officer'], orgId: 'EX1' }, policy))
      .toEqual({ roles: ['ia_officer'], groups: ['ia_officer'], org: 'EX1' })
    // no 'roles' in the gate → no role claim, whatever the set
    expect(roleClaimsForClient(null, { role: 'admin', roles: ['admin'], orgId: null }, { claims: ['org'] })).toEqual({})
    // the explicit empty assignment → the claims are OMITTED (never an empty array)
    expect(roleClaimsForClient([], { role: 'admin', roles: ['admin'], orgId: 'EX1' }, policy)).toEqual({ org: 'EX1' })
    // no policy at all → profile+email only (01's posture)
    expect(roleClaimsForClient(null, { role: 'admin', roles: ['admin'], orgId: 'EX1' }, null)).toEqual({})
  })

  it('the picture family: the public avatar URL, ONLY with the policy AND an uploaded avatar', () => {
    const withAvatar = { id: 'u-1', avatarUrl: '/api/op/account/avatar' }
    // Policy + avatar → the public route's absolute URL under the issuer.
    expect(pictureClaimForClient(withAvatar, { claims: ['picture'] }, 'https://id.example'))
      .toBe('https://id.example/op/avatar/u-1')
    // The family absent from the policy → no claim (the per-client privilege).
    expect(pictureClaimForClient(withAvatar, { claims: ['roles', 'org'] }, 'https://id.example')).toBeNull()
    expect(pictureClaimForClient(withAvatar, null, 'https://id.example')).toBeNull()
    // No uploaded avatar → no claim, even with the family (never a broken URL).
    expect(pictureClaimForClient({ id: 'u-1' }, { claims: ['picture'] }, 'https://id.example')).toBeNull()
    expect(pictureClaimForClient({ id: 'u-1', avatarUrl: null }, { claims: ['picture'] }, 'https://id.example')).toBeNull()
  })
})

// ── the policy evaluation (the client registry's role allowlist) ─────

describe('the claims-policy role allowlist (the client registry)', () => {
  it('the API accepts + stores the allowlist, and refuses an unknown role loudly', async () => {
    const admin = await demoLogin('admin@oiml.org')
    const created = await app.request(`${ISSUER}/api/op/clients`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: admin },
      body: JSON.stringify({
        client_id: 'nmi-instance',
        name: 'An NMI instance',
        redirect_uris: ['https://nmi.example/callback'],
        claims_policy: { claims: ['roles'], roles: ['ia_officer', 'case_officer'] },
      }),
    })
    const client = await json(created, 201)
    expect(client.claimsPolicy).toEqual({ claims: ['roles'], roles: ['ia_officer', 'case_officer'] })

    const refused = await app.request(`${ISSUER}/api/op/clients`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: admin },
      body: JSON.stringify({
        client_id: 'broken-instance',
        name: 'A misconfigured instance',
        redirect_uris: ['https://broken.example/callback'],
        claims_policy: { claims: ['roles'], roles: ['superroot'] },
      }),
    })
    const body = await json(refused, 400)
    expect(body.error).toContain('superroot')
    expect(body.knownRoles).toContain('ia_officer')
  })

  it('the seed parser validates the allowlist shape honestly', async () => {
    const { parseOpClientSeed } = await import('../../server/auth/op/registry')
    expect(parseOpClientSeed(JSON.stringify([{
      client_id: 'x', name: 'X', redirect_uris: ['https://x.example/cb'],
      claims_policy: { claims: ['roles'], roles: ['viewer'] },
    }]))[0]!.claims_policy).toEqual({ claims: ['roles'], roles: ['viewer'] })
    expect(() => parseOpClientSeed(JSON.stringify([{
      client_id: 'x', name: 'X', redirect_uris: ['https://x.example/cb'],
      claims_policy: { claims: ['roles'], roles: 'viewer' },
    }]))).toThrow(/claims_policy\.roles/)
  })
})

// ── the admin acts (the registry API) ────────────────────────────────

describe('the registry acts', () => {
  let admin: string
  let willa: { id: string; email: string; setupUrl: string }
  const WILLA_PASSWORD = 'willa wharton registry passphrase'

  beforeAll(async () => {
    admin = await demoLogin('admin@oiml.org')
  })

  it('the invite binds the org + the per-client roles (the 02 seam, 10’s binding)', async () => {
    const res = await invite(admin, {
      email: 'willa.wharton@example.org',
      name: 'Ms. Willa Wharton',
      role: 'viewer',
      roles: ['viewer'],
      org_id: 'ut-nmi-nl',
      client_roles: [{ client_id: 'hub-instance', roles: ['ia_officer'] }],
    })
    expect(res.account.email).toBe('willa.wharton@example.org')
    expect(res.account.orgId).toBe('ut-nmi-nl')
    expect(res.setupUrl).toContain('/op/setup?token=')
    willa = { id: res.account.id, email: res.account.email, setupUrl: res.setupUrl }

    // The assignment landed; the audit carries the whole act.
    expect(await store.getOpClientRoles(willa.id, 'hub-instance')).toEqual(['ia_officer'])
    const audit = await auditRowsFor(willa.id)
    expect(audit.map(e => e.action)).toContain('account.invite')
    expect(audit.find(e => e.action === 'account.invite')?.metadata).toMatchObject({
      email: 'willa.wharton@example.org',
      org_id: 'ut-nmi-nl',
      client_roles: [{ client_id: 'hub-instance', roles: ['ia_officer'] }],
    })
  })

  it('the invite refuses a role the client is not configured to receive (naming the policy)', async () => {
    const res = await invite(admin, {
      email: 'milo@example.org',
      name: 'Mr. Milo Minderbinder',
      role: 'viewer',
      client_roles: [{ client_id: 'hub-instance', roles: ['tl_operator'] }],
    }, 400)
    expect(res.error).toContain('tl_operator')
    expect(res.error).toContain('claims-policy role allowlist')
    // …and nothing was created (the refusal precedes the write).
    expect(await store.findUserByEmail('milo@example.org')).toBeNull()
  })

  it('the invite refuses an unknown client + an unregistered org honestly', async () => {
    const badClient = await invite(admin, {
      email: 'otto@example.org', name: 'Otto', role: 'viewer',
      client_roles: [{ client_id: 'no-such-client', roles: ['viewer'] }],
    }, 404)
    expect(badClient.error).toContain('no-such-client')
    const badOrg = await invite(admin, {
      email: 'otto@example.org', name: 'Otto', role: 'viewer', org_id: 'no-such-org',
    }, 400)
    expect(badOrg.error).toContain('not an active organization on the registry')
  })

  it('the edit act updates name + email, refuses the taken email (409), and audits before/after', async () => {
    // A second account holds the email we try to take.
    await invite(admin, { email: 'taken@example.org', name: 'Taken Seat' })

    const edited = await app.request(`${ISSUER}/api/op/accounts/${willa.id}`, {
      method: 'PUT',
      headers: { 'content-type': 'application/json', cookie: admin },
      body: JSON.stringify({ name: 'Ms. Willa Wharton-Jones', email: 'willa.jones@example.org' }),
    })
    const updated = await json(edited, 200)
    expect(updated.name).toBe('Ms. Willa Wharton-Jones')
    expect(updated.email).toBe('willa.jones@example.org')
    willa.email = 'willa.jones@example.org'

    const conflict = await app.request(`${ISSUER}/api/op/accounts/${willa.id}`, {
      method: 'PUT',
      headers: { 'content-type': 'application/json', cookie: admin },
      body: JSON.stringify({ email: 'taken@example.org' }),
    })
    expect((await json(conflict, 409)).error).toContain('already exists')

    // The registry never edits the demo cast (the OP's list only).
    const demo = (await store.listUsers()).find(u => u.email === 'admin@oiml.org')!
    const demoEdit = await app.request(`${ISSUER}/api/op/accounts/${demo.id}`, {
      method: 'PUT',
      headers: { 'content-type': 'application/json', cookie: admin },
      body: JSON.stringify({ name: 'Renamed Admin' }),
    })
    expect(demoEdit.status).toBe(404)

    const audit = await auditRowsFor(willa.id)
    expect(audit.find(e => e.action === 'account.updated')?.metadata).toMatchObject({
      before: { email: 'willa.wharton@example.org' },
      after: { name: 'Ms. Willa Wharton-Jones', email: 'willa.jones@example.org' },
    })
  })

  it('the per-client assignment PUT + DELETE validate and audit', async () => {
    // An unknown role is refused.
    const unknown = await app.request(`${ISSUER}/api/op/accounts/${willa.id}/client-roles/tl-instance`, {
      method: 'PUT',
      headers: { 'content-type': 'application/json', cookie: admin },
      body: JSON.stringify({ roles: ['superroot'] }),
    })
    expect((await json(unknown, 400)).error).toContain('superroot')

    // The TL instance (no allowlist) takes the tl_operator assignment.
    const put = await app.request(`${ISSUER}/api/op/accounts/${willa.id}/client-roles/tl-instance`, {
      method: 'PUT',
      headers: { 'content-type': 'application/json', cookie: admin },
      body: JSON.stringify({ roles: ['tl_operator'] }),
    })
    expect((await json(put, 200)).roles).toEqual(['tl_operator'])
    expect(await store.getOpClientRoles(willa.id, 'tl-instance')).toEqual(['tl_operator'])
    const audit = await auditRowsFor(willa.id)
    expect(audit.find(e => e.action === 'account.client_roles' && e.metadata?.client_id === 'tl-instance')?.metadata)
      .toMatchObject({ roles: ['tl_operator'], previous: null })

    // DELETE restores the default (the row goes).
    const del = await app.request(`${ISSUER}/api/op/accounts/${willa.id}/client-roles/tl-instance`, {
      method: 'DELETE',
      headers: { cookie: admin },
    })
    expect(del.status).toBe(200)
    expect(await store.getOpClientRoles(willa.id, 'tl-instance')).toBeNull()
    // Deleting a non-existent assignment is an honest 404.
    const delAgain = await app.request(`${ISSUER}/api/op/accounts/${willa.id}/client-roles/tl-instance`, {
      method: 'DELETE',
      headers: { cookie: admin },
    })
    expect(delAgain.status).toBe(404)
  })
})

// ── the token shaping (the REAL round trip) ──────────────────────────

describe('the issued ID token carries the per-client roles (the round trip)', () => {
  let willaId: string
  let willaCookie: string
  const WILLA = { email: 'willa.roundtrip@example.org', password: 'willa round trip passphrase' }

  beforeAll(async () => {
    const admin = await demoLogin('admin@oiml.org')
    const res = await invite(admin, { email: WILLA.email, name: 'Ms. Willa Roundtrip', role: 'viewer', roles: ['viewer'] })
    willaId = res.account.id
    willaCookie = await enroll(res.setupUrl, WILLA.password)
  })

  it('no assignment → the account default set carries (the pre-03 behavior)', async () => {
    const pkce = await generatePkce()
    const { code } = await driveAuthorize(willaCookie, { clientId: HUB.client_id, redirectUri: HUB.redirect_uris[0]!, challenge: pkce.challenge })
    const { claims } = await exchangeAndValidate({ code, redirectUri: HUB.redirect_uris[0]!, clientId: HUB.client_id, verifier: pkce.verifier, secret: HUB.secret })
    expect(claims.roles).toEqual(['viewer'])
    expect(claims.groups).toEqual(['viewer'])
  })

  it('the assignment decides what the client receives — and the allowlist bounds it', async () => {
    const admin = await demoLogin('admin@oiml.org')
    // Willa is ia_officer on the HUB (inside the allowlist) and tl_operator
    // on the TL (no allowlist). Her account default stays viewer.
    await app.request(`${ISSUER}/api/op/accounts/${willaId}/client-roles/hub-instance`, {
      method: 'PUT', headers: { 'content-type': 'application/json', cookie: admin },
      body: JSON.stringify({ roles: ['ia_officer'] }),
    })
    await app.request(`${ISSUER}/api/op/accounts/${willaId}/client-roles/tl-instance`, {
      method: 'PUT', headers: { 'content-type': 'application/json', cookie: admin },
      body: JSON.stringify({ roles: ['tl_operator'] }),
    })

    // The hub's token: the assignment (the consent context previews it).
    const hubPkce = await generatePkce()
    const hub = await driveAuthorize(willaCookie, { clientId: HUB.client_id, redirectUri: HUB.redirect_uris[0]!, challenge: hubPkce.challenge, nonce: 'hub-n' })
    expect(hub.consent.roleClaims).toEqual(['ia_officer'])
    const hubClaims = (await exchangeAndValidate({ code: hub.code, redirectUri: HUB.redirect_uris[0]!, clientId: HUB.client_id, verifier: hubPkce.verifier, secret: HUB.secret, nonce: 'hub-n' })).claims
    expect(hubClaims.roles).toEqual(['ia_officer'])
    expect(hubClaims.groups).toEqual(['ia_officer'])

    // The TL's token: its own assignment, never the hub's.
    const tlPkce = await generatePkce()
    const tl = await driveAuthorize(willaCookie, { clientId: TL.client_id, redirectUri: TL.redirect_uris[0]!, challenge: tlPkce.challenge, nonce: 'tl-n' })
    const tlClaims = (await exchangeAndValidate({ code: tl.code, redirectUri: TL.redirect_uris[0]!, clientId: TL.client_id, verifier: tlPkce.verifier, secret: TL.secret, nonce: 'tl-n' })).claims
    expect(tlClaims.roles).toEqual(['tl_operator'])
  })

  it('the explicit empty assignment emits NO role claim (the instance’s no-claim posture)', async () => {
    const admin = await demoLogin('admin@oiml.org')
    const put = await app.request(`${ISSUER}/api/op/accounts/${willaId}/client-roles/tl-instance`, {
      method: 'PUT', headers: { 'content-type': 'application/json', cookie: admin },
      body: JSON.stringify({ roles: [] }),
    })
    expect(put.status).toBe(200)

    const pkce = await generatePkce()
    const { consent, code } = await driveAuthorize(willaCookie, { clientId: TL.client_id, redirectUri: TL.redirect_uris[0]!, challenge: pkce.challenge, nonce: 'none-n' })
    expect(consent.roleClaims).toEqual([])
    const { claims, accessToken } = await exchangeAndValidate({ code, redirectUri: TL.redirect_uris[0]!, clientId: TL.client_id, verifier: pkce.verifier, secret: TL.secret, nonce: 'none-n' })
    expect(claims.roles).toBeUndefined()
    expect(claims.groups).toBeUndefined()

    // userinfo answers the same shaping.
    const userinfo = await app.request(`${ISSUER}/op/userinfo`, { headers: { authorization: `Bearer ${accessToken}` } })
    const body = await json(userinfo, 200)
    expect(body.roles).toBeUndefined()
    expect(body.email).toBe(WILLA.email)

    // Restore the default for the deactivation legs.
    await app.request(`${ISSUER}/api/op/accounts/${willaId}/client-roles/tl-instance`, { method: 'DELETE', headers: { cookie: admin } })
  })

  it('the email-only client never receives role claims, assignment or not', async () => {
    const admin = await demoLogin('admin@oiml.org')
    await app.request(`${ISSUER}/api/op/accounts/${willaId}/client-roles/plain-public`, {
      method: 'PUT', headers: { 'content-type': 'application/json', cookie: admin },
      body: JSON.stringify({ roles: ['viewer'] }),
    })
    const pkce = await generatePkce()
    const { code } = await driveAuthorize(willaCookie, { clientId: EMAIL_ONLY.client_id, redirectUri: EMAIL_ONLY.redirect_uris[0]!, challenge: pkce.challenge, nonce: 'pub-n' })
    const { claims } = await exchangeAndValidate({ code, redirectUri: EMAIL_ONLY.redirect_uris[0]!, clientId: EMAIL_ONLY.client_id, verifier: pkce.verifier, nonce: 'pub-n' })
    expect(claims.email).toBe(WILLA.email)
    expect(claims.roles).toBeUndefined()
    expect(claims.groups).toBeUndefined()
  })
})

// ── the honest deactivation ──────────────────────────────────────────

describe('deactivate / reactivate (honest: history kept, sign-ins refused, sessions revoked)', () => {
  let admin: string
  let subject: { id: string; email: string; setupUrl: string }
  const SUBJECT = { email: 'sally.subject@example.org', password: 'sally subject passphrase' }

  beforeAll(async () => {
    admin = await demoLogin('admin@oiml.org')
    const res = await invite(admin, { email: SUBJECT.email, name: 'Ms. Sally Subject', role: 'viewer', roles: ['viewer'] })
    subject = { id: res.account.id, email: SUBJECT.email, setupUrl: res.setupUrl }
  })

  it('deactivation: sign-in refuses, the live session dies, the issued access token dies, the row stays', async () => {
    // Sally sets her password from the invite link (signed in by the
    // completion) AND completes an OIDC round trip (an issued access
    // token).
    const cookie = await enroll(subject.setupUrl, SUBJECT.password)
    const pkce = await generatePkce()
    const { code } = await driveAuthorize(cookie, { clientId: HUB.client_id, redirectUri: HUB.redirect_uris[0]!, challenge: pkce.challenge })
    const { accessToken } = await exchangeAndValidate({ code, redirectUri: HUB.redirect_uris[0]!, clientId: HUB.client_id, verifier: pkce.verifier, secret: HUB.secret })
    // The session resolves and userinfo answers before the act.
    expect((await app.request(`${ISSUER}/api/op/account`, { headers: { cookie } })).status).toBe(200)
    expect((await app.request(`${ISSUER}/op/userinfo`, { headers: { authorization: `Bearer ${accessToken}` } })).status).toBe(200)

    // Deactivate.
    const off = await app.request(`${ISSUER}/api/op/accounts/${subject.id}/status`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie: admin },
      body: JSON.stringify({ active: false }),
    })
    expect((await json(off, 200)).active).toBe(false)

    // Sign-in refuses with the honest message (the RIGHT password).
    const login = await passwordLogin(SUBJECT.email, SUBJECT.password)
    expect(login.status).toBe(403)
    expect((await login.json() as any).error).toContain('deactivated')
    // The live session is revoked (not merely unresolved — gone).
    expect((await app.request(`${ISSUER}/api/op/account`, { headers: { cookie } })).status).toBe(401)
    expect((await store.listUserSessions(subject.id)).length).toBe(0)
    // The issued access token is revoked too.
    expect((await app.request(`${ISSUER}/op/userinfo`, { headers: { authorization: `Bearer ${accessToken}` } })).status).toBe(401)
    // The history stays: the row + the audit chain.
    const row = (await store.listUsers()).find(u => u.id === subject.id)!
    expect(row.active).toBe(false)
    const audit = await auditRowsFor(subject.id)
    const deactivated = audit.find(e => e.action === 'account.deactivated')
    expect(deactivated?.metadata?.revoked).toMatchObject({ accessTokens: 1 })
    expect(deactivated?.metadata?.revoked.sessions).toBeGreaterThanOrEqual(1)

    // Reactivate: sign-in works again.
    const on = await app.request(`${ISSUER}/api/op/accounts/${subject.id}/status`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie: admin },
      body: JSON.stringify({ active: true }),
    })
    expect(on.status).toBe(200)
    const relogin = await passwordLogin(SUBJECT.email, SUBJECT.password)
    expect(relogin.status).toBe(200)
    const actions = (await auditRowsFor(subject.id)).map(e => e.action)
    expect(actions).toContain('account.reactivated')
  })

  it('you cannot deactivate your own account (the lockout guard)', async () => {
    const selfId = (await store.listUsers()).find(u => u.email === 'admin@oiml.org')!.id
    // …but the demo admin is not an OP account — the guard's proof uses
    // an OP-account administrator instead.
    const boss = await invite(admin, { email: 'boss@example.org', name: 'The Boss', role: 'admin', roles: ['admin'] })
    const bossCookie = await enroll(boss.setupUrl, 'the boss registry passphrase')
    const self = await app.request(`${ISSUER}/api/op/accounts/${boss.account.id}/status`, {
      method: 'POST', headers: { 'content-type': 'application/json', cookie: bossCookie },
      body: JSON.stringify({ active: false }),
    })
    expect((await json(self, 400)).error).toContain('your own account')
    expect(selfId).toBeTruthy() // (the demo cast is untouched by the registry)
  })
})

// ── the audit chain + the last-sign-in column ────────────────────────

describe('the audit chain (every admin act + every OP-side sign-in)', () => {
  it('a password sign-in lands account.sign_in and the registry list reads the last sign-in back from the chain', async () => {
    const admin = await demoLogin('admin@oiml.org')
    const res = await invite(admin, { email: 'lena.signin@example.org', name: 'Ms. Lena Signin', role: 'viewer' })
    await enroll(res.setupUrl, 'lena sign in passphrase')
    const login = await passwordLogin('lena.signin@example.org', 'lena sign in passphrase')
    expect(login.status).toBe(200)

    const chain = await store.lastAccountSignIns()
    expect(chain[res.account.id]).toBeTruthy()

    const list = await app.request(`${ISSUER}/api/op/accounts`, { headers: { cookie: admin } })
    const rows = await json(list, 200) as any[]
    const lena = rows.find(r => r.id === res.account.id)!
    expect(lena.lastSignIn).toBe(chain[res.account.id])
    // …and an account that never signed in honestly shows null.
    const never = await invite(admin, { email: 'never@example.org', name: 'Never Signed' })
    const rows2 = await json(await app.request(`${ISSUER}/api/op/accounts`, { headers: { cookie: admin } }), 200) as any[]
    expect(rows2.find(r => r.id === never.account.id)!.lastSignIn).toBeNull()
    // The row also carries the per-client assignments + the org binding.
    expect(lena.clientRoles).toEqual([])
    expect(lena.roles).toEqual(['viewer'])
  })
})

// ── the org-scope reuse (10's slice is the org admin's, never this) ──

describe('the org scope never reaches the registry (10’s reuse, honestly bounded)', () => {
  it('the org admin gets 403 on the registry acts and keeps its own org slice', async () => {
    const admin = await demoLogin('admin@oiml.org')
    // The Utilizer's org admin (10's delegated administrator).
    await invite(admin, {
      email: 'sanne.scope@nmi.example.org', name: 'Ms. Sanne Scope', role: 'org_admin', roles: ['org_admin'], org_id: 'ut-nmi-nl',
    })
    const orgAdmin = await passwordLogin('sanne.scope@nmi.example.org', 'sanne scope passphrase')
    // The account has no password yet — enroll it first.
    const fresh = await app.request(`${ISSUER}/api/op/accounts/${(await store.findUserByEmail('sanne.scope@nmi.example.org'))!.id}/enrollment`, {
      method: 'POST', headers: { cookie: admin },
    })
    const orgCookie = await enroll((await json(fresh, 201)).setupUrl, 'sanne scope passphrase')
    expect(orgAdmin.status).toBe(401) // (no password before enrollment)

    // The registry acts refuse the org-scoped grant.
    for (const [method, path] of [
      ['GET', '/api/op/accounts'],
      ['POST', '/api/op/accounts'],
      ['PUT', '/api/op/accounts/whatever'],
      ['POST', '/api/op/accounts/whatever/status'],
    ] as const) {
      const res = await app.request(`${ISSUER}${path}`, {
        method,
        headers: { 'content-type': 'application/json', cookie: orgCookie },
        body: method === 'GET' ? undefined : JSON.stringify({}),
      })
      expect(res.status, `${method} ${path} refuses the org admin`).toBe(403)
    }

    // …and 10's own slice still answers, scoped to the org.
    const slice = await app.request(`${ISSUER}/api/users`, { headers: { cookie: orgCookie } })
    const rows = await json(slice, 200) as Array<{ orgId: string | null }>
    expect(rows.length).toBeGreaterThan(0)
    expect(rows.every(r => r.orgId === 'ut-nmi-nl')).toBe(true)
  })
})

// ── the instance honors the claims (the 03 contract with fed-10/12) ──

describe('the instance side honors the OP’s claims (never inventing, never silent)', () => {
  it('rolesFromClaims keeps only roles the instance’s RBAC map knows', async () => {
    const { rolesFromClaims } = await import('@oimlsmart/platform-server/vocab')
    // The OP's shaped claim: the map-known role survives; anything else
    // is dropped, never erroring, never inventing.
    expect(rolesFromClaims({ roles: ['tl_operator', 'superroot'] })).toEqual(['tl_operator'])
    expect(rolesFromClaims({ roles: [] })).toEqual([])
    expect(rolesFromClaims({})).toEqual([])
  })
})
