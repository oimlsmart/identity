// ─────────────────────────────────────────────────────────────────────
// TODO.sota/09 — DPoP (RFC 9449), the first slice: the sender-constrained
// OPAQUE access tokens. A client presenting a valid DPoP proof at the
// token endpoint (the authorization_code grant here) receives a
// DPoP-bound access token (token_type: DPoP, the proof key's JKT on
// the row); userinfo then admits ONLY a proof from the SAME key with
// the token's ath bound (a stolen token replayed from elsewhere
// refuses). No proof → no change — the Bearer posture is untouched.
//
// The proofs are REAL (WebCrypto ES256 keys minted in the test), the
// store is REAL (a temp SQLite), the routes are REAL (op-token.ts +
// op-token-management.ts driven with planted rows — no choreography).
// ─────────────────────────────────────────────────────────────────────
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

const TMP = mkdtempSync(join(tmpdir(), 'oiml-dpop-'))
process.env.DATABASE_PATH = join(TMP, 'test.db')
const ISSUER = 'http://op.test'
process.env.OP_ISSUER = ISSUER
const PROFILE = join(TMP, 'profile.yaml')
writeFileSync(PROFILE, `name: dpop
roles: [identity]
branding: { name: DPoP }
demo_personas: true
`)
process.env.INSTANCE_PROFILE = PROFILE

const CLIENT_ID = 'confidential-rp'
const CLIENT_SECRET = 'the-rp-secret'
const REDIRECT = 'http://127.0.0.1:9990/cb'
const VERIFIER = 'the-verifier-with-enough-entropy-to-satisfy-s256'
const TOKEN_URL = `${ISSUER}/op/token`
const USERINFO_URL = `${ISSUER}/op/userinfo`

let store: ReturnType<typeof import('../../server/store').getStore>
let app: import('hono').Hono
let mint: typeof import('./helpers/dpop-proof').mintDpopProof
let userId: string

async function plantCode(): Promise<string> {
  const { pkceS256 } = await import('../../server/auth/op/keys')
  const code = 'the-code-' + Math.random().toString(36).slice(2)
  await store.createOidcCode({
    code, clientId: CLIENT_ID, redirectUri: REDIRECT, scope: 'openid profile email',
    nonce: null, codeChallenge: await pkceS256(VERIFIER), userId, ttlMs: 60_000,
  })
  return code
}

async function exchange(body: URLSearchParams, dpop?: string): Promise<Response> {
  return app.request('/op/token', {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      authorization: 'Basic ' + btoa(`${CLIENT_ID}:${CLIENT_SECRET}`),
      ...(dpop ? { dpop } : {}),
    },
    body: body.toString(),
  })
}

beforeAll(async () => {
  // A declared signing key (the contract gate's fixture): the declared-
  // issuer posture registers it, so the machine JWTs verify against the
  // keyset (identity#7 — the generated dev key never enters it).
  process.env.OP_SIGNING_KEY = await (await import('../../e2e/fixtures/op-signing-key')).fixtureOpSigningKey()
  const { installSqliteStore } = await import('../../server/store/sqlite')
  store = installSqliteStore()
  const profileMod = await import('../../server/profile')
  profileMod.installInstanceProfile(profileMod.parseInstanceProfile(`
identity:
  org_id: oimlsmart-id
  org_name: DPoP
  role_codes: [identity]
roles: [identity]
branding: { name: DPoP }
demo_personas: true
`))
  mint = (await import('./helpers/dpop-proof')).mintDpopProof

  await store.upsertOidcClient({
    clientId: CLIENT_ID,
    name: 'The DPoP fixture RP',
    secretHash: await (await import('../../server/auth/op/secrets')).hashClientSecret(CLIENT_SECRET),
    redirectUris: [REDIRECT],
    claimsPolicy: { claims: ['roles', 'org'] },
    createdBy: 'test',
  })
  const account = await store.createOpAccount({ email: 'dpop@oimlsmart.org', name: 'DPoP Test', role: 'user', roles: ['user'], createdBy: 'test', emailVerified: true })
  userId = account!.id

  const { Hono } = await import('hono')
  const { createOpTokenRouter } = await import('../../server/routes/op-token')
  const { createOpTokenManagementRouter, } = await import('../../server/routes/op-token-management')
  const { authenticateClient } = await import('../../server/routes/op-token')
  const root = new Hono()
  root.route('/', createOpTokenRouter({
    ensureSeeded: async () => {},
    audit: async () => {},
  }))
  root.route('/', createOpTokenManagementRouter({ audit: async () => {}, authenticateClient }))
  app = root
}, 30_000)

afterAll(async () => {
  rmSync(TMP, { recursive: true, force: true })
  delete process.env.OP_SIGNING_KEY
  delete process.env.OP_ISSUER
  delete process.env.DATABASE_PATH
  delete process.env.INSTANCE_PROFILE
  const profileMod = await import('../../server/profile')
  profileMod.resetInstanceProfileForTest()
})

const grantBody = (code: string) => new URLSearchParams({
  grant_type: 'authorization_code', code, redirect_uri: REDIRECT, code_verifier: VERIFIER,
})

describe('the proof module (auth/op/dpop.ts)', () => {
  it('a REAL ES256 proof verifies and answers its key\'s JKT', async () => {
    const { verifyDpopProof } = await import('../../server/auth/op/dpop')
    const p = await mint({ method: 'POST', uri: TOKEN_URL })
    const res = await verifyDpopProof(p.proof, { method: 'POST', uri: TOKEN_URL })
    expect('jkt' in res && res.jkt).toBe(p.jkt)
  })

  it('htm, htu, iat skew, and a broken signature all refuse', async () => {
    const { verifyDpopProof } = await import('../../server/auth/op/dpop')
    const p = await mint({ method: 'POST', uri: TOKEN_URL })
    expect('error' in await verifyDpopProof(p.proof, { method: 'GET', uri: TOKEN_URL })).toBe(true)
    expect('error' in await verifyDpopProof(p.proof, { method: 'POST', uri: `${ISSUER}/op/other` })).toBe(true)
    const stale = await mint({ method: 'POST', uri: TOKEN_URL, iat: Math.floor(Date.now() / 1000) - 3600 })
    expect('error' in await verifyDpopProof(stale.proof, { method: 'POST', uri: TOKEN_URL })).toBe(true)
    expect('error' in await verifyDpopProof(p.proof.slice(0, -3) + 'aaa', { method: 'POST', uri: TOKEN_URL })).toBe(true)
  })

  it('the ath binding: matching passes; a different token or none refuses', async () => {
    const { verifyDpopProof } = await import('../../server/auth/op/dpop')
    const token = 'an-access-token-value'
    const p = await mint({ method: 'GET', uri: USERINFO_URL, accessToken: token })
    expect('jkt' in await verifyDpopProof(p.proof, { method: 'GET', uri: USERINFO_URL, accessToken: token })).toBe(true)
    expect('error' in await verifyDpopProof(p.proof, { method: 'GET', uri: USERINFO_URL, accessToken: 'another-token' })).toBe(true)
    expect('error' in await verifyDpopProof(p.proof, { method: 'GET', uri: USERINFO_URL })).toBe(true)
  })
})

describe('the token endpoint\'s DPoP arm', () => {
  it('a proof-bound exchange answers token_type DPoP; the bound token enforces at userinfo; a replayed jti refuses', async () => {
    const keys = await (await import('./helpers/dpop-proof')).mintDpopKeys()
    const code = await plantCode()
    const p = await mint({ method: 'POST', uri: TOKEN_URL, keys })
    const res = await exchange(grantBody(code), p.proof)
    expect(res.status).toBe(200)
    const body = await res.json() as { token_type: string; access_token: string }
    expect(body.token_type).toBe('DPoP')

    // The bound token refuses userinfo WITHOUT a proof and with the
    // WRONG key; the RIGHT key answers the claims.
    const bare = await app.request('/op/userinfo', { headers: { authorization: `Bearer ${body.access_token}` } })
    expect(bare.status).toBe(401)
    const wrong = await mint({ method: 'GET', uri: USERINFO_URL, accessToken: body.access_token })
    const wrongKey = await app.request('/op/userinfo', { headers: { authorization: `DPoP ${body.access_token}`, dpop: wrong.proof } })
    expect(wrongKey.status).toBe(401)
    const right = await mint({ method: 'GET', uri: USERINFO_URL, accessToken: body.access_token, keys })
    const ok = await app.request('/op/userinfo', { headers: { authorization: `DPoP ${body.access_token}`, dpop: right.proof } })
    expect(ok.status).toBe(200)
    expect(((await ok.json()) as { sub: string }).sub).toBe(userId)

    // The replayed jti refuses at the next exchange.
    const code2 = await plantCode()
    const replay = await exchange(grantBody(code2), p.proof)
    expect(replay.status).toBe(400)
    expect(((await replay.json()) as { error: string }).error).toBe('invalid_dpop_proof')
  })

  it('a proofless exchange stays Bearer — the default posture is untouched', async () => {
    const code = await plantCode()
    const res = await exchange(grantBody(code))
    expect(res.status).toBe(200)
    expect(((await res.json()) as { token_type: string }).token_type).toBe('Bearer')
  })
})


function decodeJwt(jwt: string): Record<string, unknown> {
  return JSON.parse(atob(jwt.split('.')[1]!.replace(/-/g, '+').replace(/_/g, '/')))
}

describe('the machine cone\u2019s DPoP arm (the self-contained JWTs)', () => {
  const DEVICE_CLIENT = 'device-rig-01'
  const DEVICE_SECRET = 'the-device-secret'
  const ORG = 'nist.gov'

  beforeAll(async () => {
    await store.createOrgRegistryOrg({ id: ORG, name: 'National Institute of Standards and Technology (NIST)', country: 'United States', createdBy: 'test' })
    await store.upsertOidcClient({
      clientId: DEVICE_CLIENT,
      name: 'The DPoP fixture device',
      secretHash: await (await import('../../server/auth/op/secrets')).hashClientSecret(DEVICE_SECRET),
      redirectUris: [],
      claimsPolicy: { claims: [], class: 'device', device: { id: 'rig-01', org: ORG, instrument_model: 'acme-lc500@2021' } } as never,
      createdBy: 'test',
    })
  })

  async function machineExchange(dpop?: string): Promise<Response> {
    return app.request('/op/token', {
      method: 'POST',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        authorization: 'Basic ' + btoa(`${DEVICE_CLIENT}:${DEVICE_SECRET}`),
        ...(dpop ? { dpop } : {}),
      },
      body: new URLSearchParams({ grant_type: 'client_credentials' }).toString(),
    })
  }

  it('a proof-bound mint carries cnf.jkt inside the JWT and answers token_type DPoP', async () => {
    const keys = await mint({ method: 'POST', uri: TOKEN_URL }).then(() => import('./helpers/dpop-proof')).then(async m => m.mintDpopKeys())
    const p = await mint({ method: 'POST', uri: TOKEN_URL, keys })
    const res = await machineExchange(p.proof)
    expect(res.status).toBe(200)
    const body = await res.json() as { token_type: string; access_token: string }
    expect(body.token_type).toBe('DPoP')
    const claims = decodeJwt(body.access_token)
    expect(claims.cnf).toEqual({ jkt: p.jkt })
  })

  it('a proofless mint stays Bearer with no cnf — the machine default is untouched', async () => {
    const res = await machineExchange()
    expect(res.status).toBe(200)
    const body = await res.json() as { token_type: string; access_token: string }
    expect(body.token_type).toBe('Bearer')
    expect(decodeJwt(body.access_token).cnf).toBeUndefined()
  })

  it('introspection discloses the binding on BOTH halves (the machine JWT and the opaque row)', async () => {
    const keys = await (await import('./helpers/dpop-proof')).mintDpopKeys()
    const p = await mint({ method: 'POST', uri: TOKEN_URL, keys })
    const bound = await machineExchange(p.proof)
    const jwt = ((await bound.json()) as { access_token: string }).access_token

    const probe = (token: string) => app.request('/op/introspect', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', authorization: 'Basic ' + btoa(`${DEVICE_CLIENT}:${DEVICE_SECRET}`) },
      body: new URLSearchParams({ token }).toString(),
    })
    const machineAnswer = await (await probe(jwt)).json() as { active: boolean; cnf?: { jkt: string }; token_type: string }
    expect(machineAnswer.active).toBe(true)
    expect(machineAnswer.cnf).toEqual({ jkt: p.jkt })
    expect(machineAnswer.token_type).toBe('DPoP')

    // The opaque half: the earlier round-trip's binding reads through
    // the same disclosure.
    const code = await plantCode()
    const userProof = await mint({ method: 'POST', uri: TOKEN_URL })
    const exchanged = await exchange(grantBody(code), userProof.proof)
    const opaque = ((await exchanged.json()) as { access_token: string }).access_token
    const opaqueAnswer = await (await probe(opaque)).json() as { active: boolean; cnf?: { jkt: string }; token_type: string }
    expect(opaqueAnswer.active).toBe(true)
    expect(opaqueAnswer.cnf).toEqual({ jkt: userProof.jkt })
    expect(opaqueAnswer.token_type).toBe('DPoP')
  })
})


describe('the delegation exchange\u2019s DPoP enforcement (RFC 9449 \u00a77 — the endpoint consumes the bound subject)', () => {
  it('a bound subject token delegates ONLY with a possession proof from the bound key', async () => {
    const keys = await (await import('./helpers/dpop-proof')).mintDpopKeys()
    const minted = await mint({ method: 'POST', uri: TOKEN_URL, keys })
    const code = await plantCode()
    const res = await exchange(grantBody(code), minted.proof)
    const subject = ((await res.json()) as { access_token: string }).access_token

    const attempt = (dpop?: string) => app.request('/op/token', {
      method: 'POST',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        authorization: 'Basic ' + btoa(`${CLIENT_ID}:${CLIENT_SECRET}`),
        ...(dpop ? { dpop } : {}),
      },
      body: new URLSearchParams({
        grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
        subject_token_type: 'urn:ietf:params:oauth:token-type:access_token',
        subject_token: subject,
        scope: 'assist:read',
      }).toString(),
    })

    const journal = async () => (await store.listEntities('auditEvents'))
      .map(row => JSON.parse(row.data) as { action: string; metadata?: { reason?: string } })
      .filter(e => e.action === 'account.delegation_exchange_refused')
      .map(e => e.metadata?.reason)

    const before = (await journal()).length
    const bare = await attempt()
    expect(bare.status).toBe(400)
    expect((await journal()).slice(before)).toContain('dpop_proof')

    const wrongKeyProof = await mint({ method: 'POST', uri: TOKEN_URL, accessToken: subject })
    const wrong = await attempt(wrongKeyProof.proof)
    expect(wrong.status).toBe(400)
    expect((await journal()).slice(before)).toEqual(['dpop_proof', 'dpop_proof'])

    // The bound key's proof (ath over the subject) passes the DPoP leg —
    // the journal names the LATER leg (the scope standing), never
    // dpop_proof again.
    const rightProof = await mint({ method: 'POST', uri: TOKEN_URL, keys, accessToken: subject })
    const right = await attempt(rightProof.proof)
    expect(right.status).toBe(400)
    const reasons = (await journal()).slice(before)
    expect(reasons[reasons.length - 1]).not.toBe('dpop_proof')
  })
})
