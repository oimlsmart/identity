// ─────────────────────────────────────────────────────────────────────
// The session delegation (TODO.ai-platform/03) — the RFC 8693 exchange
// whose subject is the OP's OWN opaque access token, proven in-process:
// the REAL op router over a REAL temp SQLite store, the sign-in's code
// flow driven end-to-end (authorize → consent → code → token), and the
// OP's own JWKS verifying the delegated JWT (the RP's posture — no stub
// anywhere).
//
// The cone: a service acting ON THE USER'S behalf inside the user's own
// session (the estate assistant's "my account" reads are the reference
// caller). The invariants under test:
//
//   NARROW-ONLY   — the delegated token never exceeds the account's
//                   CURRENT standing: a role lost since the sign-in
//                   narrows the answer honestly (the audit names the
//                   drop); a whole-set loss refuses invalid_grant;
//   THE BINDING   — the caller authenticates, and the subject binds to
//                   the client it was ISSUED to (another RP's token, an
//                   unknown token, a missing scope, and the wrong
//                   subject_token_type all refuse — the user-facing
//                   lattice answering the ONE invalid_grant);
//   THE ACTOR     — the answer carries act.sub (the delegating client),
//                   never pat, never amr, never a nonce (the exchange is
//                   not an authentication ceremony);
//   THE AUDIT     — every exchange lands account.delegation_exchange
//                   naming the account, the acting client, the scopes.
// ─────────────────────────────────────────────────────────────────────

import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

// The store's DB path is read at module evaluation — set it before any
// import below touches @oimlsmart/platform-server/store/sqlite (the
// imports are dynamic).
const TMP = mkdtempSync(join(tmpdir(), 'oiml-op-delegation-'))
process.env.DATABASE_PATH = join(TMP, 'test.db')

const ISSUER = 'http://op.test'
process.env.OP_ISSUER = ISSUER

// The delegating service (the estate assistant's shape): a confidential
// application-class client. The delegation's TARGET: the hub (the RP the
// assistant reads). The register is the narrowing leg's second service.
const ASSISTANT = {
  client_id: 'ai-assistant',
  name: 'The OIML SMART assistant',
  secret: 'assistant-secret-123',
  redirect_uris: ['https://ai.example/auth/callback'],
  claims_policy: { claims: ['roles', 'groups', 'org'] },
}
const HUB = {
  client_id: 'hub-instance',
  name: 'OIML SMART platform hub',
  secret: 'hub-secret-123',
  redirect_uris: ['https://hub.example/api/auth/callback/oidc'],
  claims_policy: { claims: ['roles', 'groups', 'org'] },
}
const REGISTER = {
  client_id: 'register-instance',
  name: 'The OIML register',
  redirect_uris: ['https://register.example/callback'],
  claims_policy: { claims: ['roles'] },
}
process.env.OP_CLIENT_SEED = JSON.stringify([ASSISTANT, HUB, REGISTER])

const DELEGATION_GRANT = 'urn:ietf:params:oauth:grant-type:token-exchange'
const DELEGATION_TYPE = 'urn:ietf:params:oauth:token-type:access_token'

let app: import('hono').Hono
let store: ReturnType<typeof import('@oimlsmart/platform-server/store').getStore>
let generatePkce: typeof import('@oimlsmart/platform-server/oidc').generatePkce

async function demoLogin(email: string): Promise<string> {
  const res = await app.request('/api/auth/demo', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password: 'demo2026' }),
  })
  expect(res.ok, `demo login ${email}`).toBe(true)
  return res.headers.get('set-cookie')!.split(';')[0]!
}

/** The sign-in, end-to-end: authorize → consent → code → the token
 *  endpoint's code exchange. Answers the assistant's OP access token
 *  (the delegation's subject-to-be). */
async function signInForAccessToken(email: string): Promise<string> {
  const cookie = await demoLogin(email)
  const pkce = await generatePkce()
  const query = new URLSearchParams({
    response_type: 'code',
    client_id: ASSISTANT.client_id,
    redirect_uri: ASSISTANT.redirect_uris[0]!,
    scope: 'openid profile email',
    state: 'st-delegation',
    nonce: 'nn-delegation',
    code_challenge: pkce.challenge,
    code_challenge_method: 'S256',
    // The consent stop is this helper's contract (TODO.identity-features/12:
    // a remembered grant would skip it on a repeat sign-in).
    prompt: 'consent',
  })
  const authorize = await app.request(`${ISSUER}/op/authorize?${query}`, { headers: { cookie } })
  expect(authorize.status, 'authorize redirects to the consent page').toBe(302)
  const consentUrl = new URL(authorize.headers.get('location')!, ISSUER)
  const authId = consentUrl.searchParams.get('auth')!
  const decide = await app.request(`${ISSUER}/api/op/consent/${authId}/decide`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', cookie },
    body: JSON.stringify({ decision: 'allow' }),
  })
  expect(decide.status, 'the consent decision records').toBe(200)
  const { redirect } = await decide.json() as { redirect: string }
  const code = new URL(redirect).searchParams.get('code')!
  const exchanged = await app.request(`${ISSUER}/op/token`, {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      authorization: `Basic ${btoa(`${encodeURIComponent(ASSISTANT.client_id)}:${encodeURIComponent(ASSISTANT.secret)}`)}`,
    },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: ASSISTANT.redirect_uris[0]!,
      client_id: ASSISTANT.client_id,
      code_verifier: pkce.verifier,
    }),
  })
  expect(exchanged.status, 'the code exchange answers').toBe(200)
  const body = await exchanged.json() as { access_token: string }
  expect(body.access_token, 'the sign-in minted the opaque access token').toBeTruthy()
  return body.access_token
}

/** The delegation exchange (the RFC 8693 grant, the access-token
 *  subject). The Basic pair defaults to the assistant's own. */
async function delegate(
  subject: string,
  extra?: Record<string, string>,
  auth?: { clientId: string; secret?: string } | null,
): Promise<Response> {
  const body = new URLSearchParams({
    grant_type: DELEGATION_GRANT,
    subject_token_type: DELEGATION_TYPE,
    subject_token: subject,
    ...extra,
  })
  const headers: Record<string, string> = { 'content-type': 'application/x-www-form-urlencoded' }
  const actor = auth === undefined ? { clientId: ASSISTANT.client_id, secret: ASSISTANT.secret } : auth
  if (actor) {
    body.set('client_id', actor.clientId)
    if (actor.secret !== undefined) {
      headers.authorization = `Basic ${btoa(`${encodeURIComponent(actor.clientId)}:${encodeURIComponent(actor.secret)}`)}`
    }
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

/** Verify the delegated JWT against the OP's OWN JWKS (the RP's
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
  expect(ok, 'the delegated token verifies against the OP’s JWKS').toBe(true)
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
  generatePkce = (await import('@oimlsmart/platform-server/oidc')).generatePkce

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
  const root = new Hono()
  root.route('/api/auth', createAuthLeanRouter({ autoSeedDemo: true }))
  root.route('/', createOpRouter())
  app = root

  await demoLogin('admin@oiml.org') // the demo cast lands
})

afterAll(() => {
  rmSync(TMP, { recursive: true, force: true })
  delete process.env.OP_ISSUER
  delete process.env.OP_SIGNING_KEY
  delete process.env.DATABASE_PATH
  delete process.env.OP_CLIENT_SEED
})

describe('the session delegation (the RFC 8693 exchange, the access-token subject)', () => {
  it('the valid exchange mints the narrowed JWT — the actor named, the JWKS verifies', async () => {
    const subject = await signInForAccessToken('ia@oiml.org')
    const res = await delegate(subject, { scope: `${HUB.client_id}:read` })
    expect(res.status).toBe(200)
    const body = await res.json() as { access_token: string; issued_token_type: string; token_type: string; expires_in: number; scope: string }
    expect(body.issued_token_type).toBe('urn:ietf:params:oauth:token-type:access_token')
    expect(body.token_type).toBe('Bearer')
    expect(body.scope).toBe(`${HUB.client_id}:read`)

    const claims = await verifyOpJwt(body.access_token)
    expect(claims.iss).toBe(ISSUER)
    expect(claims.scope).toBe(`${HUB.client_id}:read`)
    expect(claims.aud).toEqual([HUB.client_id])
    expect(claims.email).toBe('ia@oiml.org')
    expect(claims.org, 'the sign-in’s active-org context (the demo IA’s EX1)').toBe('EX1')
    expect(claims.service_roles).toMatchObject({ [HUB.client_id]: ['ia_officer'] })
    // The ACTOR claim names the delegating service (the relying party's
    // audit reads who ACTED) — never a credential row, never the
    // authentication ceremony's claims.
    expect(claims.act).toEqual({ sub: ASSISTANT.client_id })
    expect(claims.pat).toBeUndefined()
    expect(claims.nonce).toBeUndefined()
    expect(claims.amr).toBeUndefined()

    // The exchange is on the audit chain, the client + the scopes named.
    const events = await journal()
    const exchanged = events.find(e => e.action === 'account.delegation_exchange')
    expect(exchanged, 'the exchange is on the audit chain').toBeTruthy()
    expect(exchanged!.metadata).toMatchObject({ client: ASSISTANT.client_id, scopes: [`${HUB.client_id}:read`] })
  })

  it('the standing re-judgment: a role lost since the sign-in narrows the answer honestly', async () => {
    const iaRow = (await store.listUsers()).find(u => u.email === 'ia@oiml.org')!
    const subject = await signInForAccessToken('ia@oiml.org')
    // The account loses the register between the sign-in and the
    // exchange (the explicit per-client none).
    await store.setOpClientRoles(iaRow.id, REGISTER.client_id, [], 'the test')
    const res = await delegate(subject, { scope: `${HUB.client_id}:read ${REGISTER.client_id}:read` })
    expect(res.status).toBe(200)
    const body = await res.json() as { scope: string; access_token: string }
    expect(body.scope, 'the dropped service fell away').toBe(`${HUB.client_id}:read`)
    const claims = await verifyOpJwt(body.access_token)
    expect(claims.service_roles).toEqual({ [HUB.client_id]: ['ia_officer'] })
    // The narrowing names the drop on the audit chain.
    const narrowed = (await journal()).find(e => e.action === 'account.delegation_exchange' && Array.isArray(e.metadata?.dropped))
    expect(narrowed, 'the narrowing is audited').toBeTruthy()
    expect((narrowed!.metadata!.dropped as string[])).toContain(`${REGISTER.client_id}:read`)
    // The whole set gone refuses (the ONE invalid_grant).
    await store.setOpClientRoles(iaRow.id, HUB.client_id, [], 'the test')
    const dead = await delegate(subject, { scope: `${HUB.client_id}:read` })
    expect(((await dead.json()) as { error: string }).error).toBe('invalid_grant')
    // Restore (the other legs' cast stands).
    await store.deleteOpClientRoles(iaRow.id, REGISTER.client_id)
    await store.deleteOpClientRoles(iaRow.id, HUB.client_id)
  })

  it('the binding: another client’s token never exchanges (the foreign-token leg)', async () => {
    const subject = await signInForAccessToken('ia@oiml.org')
    // The hub (a different registered client, its own secret) presents
    // the ASSISTANT's subject — refused, indistinguishable on the wire.
    const foreign = await delegate(subject, { scope: `${HUB.client_id}:read` }, { clientId: HUB.client_id, secret: HUB.secret })
    expect(foreign.status).toBe(400)
    expect(((await foreign.json()) as { error: string }).error).toBe('invalid_grant')
    // …and the audit names the leg + the attempting client.
    const refused = (await journal()).find(e => e.action === 'account.delegation_exchange_refused' && e.metadata?.reason === 'foreign_token')
    expect(refused, 'the foreign attempt is audited').toBeTruthy()
    expect(refused!.metadata!.client).toBe(HUB.client_id)
  })

  it('the lattice: no client auth, the wrong secret, the unknown subject — all refuse honestly', async () => {
    const subject = await signInForAccessToken('ia@oiml.org')
    // No client authentication at all → invalid_client.
    const anon = await delegate(subject, { scope: `${HUB.client_id}:read` }, null)
    expect(anon.status).toBe(401)
    expect(((await anon.json()) as { error: string }).error).toBe('invalid_client')
    // The wrong secret → invalid_client.
    const wrong = await delegate(subject, { scope: `${HUB.client_id}:read` }, { clientId: ASSISTANT.client_id, secret: 'not-the-secret' })
    expect(wrong.status).toBe(401)
    expect(((await wrong.json()) as { error: string }).error).toBe('invalid_client')
    // The unknown subject → the ONE invalid_grant (never which leg).
    const unknown = await delegate('not-a-real-token', { scope: `${HUB.client_id}:read` })
    expect(unknown.status).toBe(400)
    const unknownBody = await unknown.json() as { error: string; error_description: string }
    expect(unknownBody.error).toBe('invalid_grant')
    expect(unknownBody.error_description).not.toContain('foreign')
  })

  it('the scope is required, grammatical, and account-bound', async () => {
    const subject = await signInForAccessToken('ia@oiml.org')
    // Absent → invalid_scope (the delegation names its narrowed target).
    const absent = await delegate(subject)
    expect(absent.status).toBe(400)
    expect(((await absent.json()) as { error: string }).error).toBe('invalid_scope')
    // The grammar refuses.
    expect(((await delegate(subject, { scope: 'hub' })).status)).toBe(400)
    // A service the account never enters → the whole set falls away →
    // the ONE invalid_grant (scope_standing).
    const nobody = await delegate(subject, { scope: 'no-such-service:read' })
    expect(((await nobody.json()) as { error: string }).error).toBe('invalid_grant')
    // The viewer's write class refuses (the action-class bound): the
    // viewer enters the hub read-only — write drops, the set empties.
    const viewerSubject = await signInForAccessToken('viewer@oiml.org')
    const write = await delegate(viewerSubject, { scope: `${HUB.client_id}:write` })
    expect(((await write.json()) as { error: string }).error).toBe('invalid_grant')
    const viewerRead = await delegate(viewerSubject, { scope: `${HUB.client_id}:read` })
    expect(viewerRead.status, 'the viewer’s read stands').toBe(200)
  })

  it('the wrong subject_token_type refuses, naming both cone types', async () => {
    const body = new URLSearchParams({
      grant_type: DELEGATION_GRANT,
      subject_token_type: 'urn:ietf:params:oauth:token-type:id_token',
      subject_token: 'whatever',
    })
    const res = await app.request(`${ISSUER}/op/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body,
    })
    expect(res.status).toBe(400)
    const parsed = await res.json() as { error: string; error_description: string }
    expect(parsed.error).toBe('invalid_request')
    expect(parsed.error_description).toContain('urn:oimlsmart:params:oauth:token-type:pat')
    expect(parsed.error_description).toContain(DELEGATION_TYPE)
  })

  it('the deactivated account’s sessions die with it (the standing leg)', async () => {
    const iaRow = (await store.listUsers()).find(u => u.email === 'ia@oiml.org')!
    const subject = await signInForAccessToken('ia@oiml.org')
    await store.setUserActive(iaRow.id, false)
    const dead = await delegate(subject, { scope: `${HUB.client_id}:read` })
    expect(((await dead.json()) as { error: string }).error).toBe('invalid_grant')
    await store.setUserActive(iaRow.id, true) // the reversible posture
    expect((await delegate(subject, { scope: `${HUB.client_id}:read` })).status, 'the re-activated account exchanges again').toBe(200)
  })
})
