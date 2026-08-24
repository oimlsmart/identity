// ═══════════════════════════════════════════════════════════════════
// The stub OIDC provider (TODO.federation/10) — a tiny, honest OpenID
// Connect Identity Provider for the e2e + in-process integration tests.
// NO external dependency, no network: node:http + node:crypto, a real
// RS256 keypair generated at boot, real discovery/JWKS/authorize/token/
// end-session endpoints.
//
// What it implements (OIDC Core):
//   GET  /.well-known/openid-configuration — the metadata (issuer is the
//        stub's own base URL);
//   GET  /jwks — the public signing key (JWK, kid 'stub-key-1');
//   GET  /authorize — the consent page: one link per fixture user (the
//        e2e clicks a user = the user authenticating at the IdP);
//   GET  /authorize/complete — issues a one-time code, 302s back to the
//        client's redirect_uri with code+state;
//   POST /token — the code exchange: verifies the PKCE S256 verifier,
//        the client_id and the one-time code, then signs an ID token
//        carrying the fixture user's claims (email, email_verified,
//        name, groups, plus any extra claims) and the request's nonce;
//   GET  /logout — the RP-initiated-logout endpoint: records the hit
//        (logoutHits) and 302s to post_logout_redirect_uri.
//
// Failure injection for the validation tests: signIdpJwt() is exported
// so a test can mint deliberately-broken tokens (wrong iss/aud, expired,
// bad nonce, wrong key) without running the server.
//
// The fixture users model the claim-mapping classes (the full table is
// at STUB_IDP_USERS below): mapped roles (ada → ia_officer @ EX1,
// bob → tl_operator @ 21 via orgFromClaim, cs → cs_admin), the
// verified-email LINK leg (vic → the demo viewer account, role kept),
// and the approval queue (carol: no groups; erin: an unmapped group).
// ═══════════════════════════════════════════════════════════════════

import { createServer, type Server } from 'node:http'
import { createSign, generateKeyPairSync, randomUUID, type KeyObject } from 'node:crypto'

export interface StubIdpUser {
  id: string
  sub: string
  email: string
  name: string
  emailVerified: boolean
  groups: string[]
  /** Extra claims merged into the ID token (e.g. bob's lab_id). */
  claims?: Record<string, unknown>
}

export const STUB_IDP_USERS: StubIdpUser[] = [
  { id: 'ada', sub: 'stub-ada', email: 'ada@example.org', name: 'Ada IA', emailVerified: true, groups: ['oiml-ia-officers'] },
  { id: 'bob', sub: 'stub-bob', email: 'bob@example.org', name: 'Bob Lab', emailVerified: true, groups: ['oiml-tl-21'], claims: { lab_id: '21' } },
  { id: 'cs', sub: 'stub-cs', email: 'cs@example.org', name: 'CS Admin SSO', emailVerified: true, groups: ['oiml-cs-admins'] },
  // The verified-email LINK leg: vic's email is the demo viewer
  // account's — signing in links the identity, and the account keeps
  // ITS role (the ia-officers group must NOT widen it).
  { id: 'vic', sub: 'stub-vic', email: 'viewer@oiml.org', name: 'Viewer Linked', emailVerified: true, groups: ['oiml-ia-officers'] },
  { id: 'carol', sub: 'stub-carol', email: 'carol@example.org', name: 'Carol Unknown', emailVerified: true, groups: [] },
  // The reject leg: an UNMAPPED group value maps to nothing.
  { id: 'erin', sub: 'stub-erin', email: 'erin@example.org', name: 'Erin Stranger', emailVerified: true, groups: ['oiml-strangers'] },
]

// ── keys + JWT signing (exported for the validation-failure tests) ──

export interface IdpKeys {
  privateKey: KeyObject
  jwk: JsonWebKey & { kty: string; n?: string; e?: string; kid: string }
}

export function generateIdpKeys(kid = 'stub-key-1'): IdpKeys {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 })
  const jwk = publicKey.export({ format: 'jwk' }) as unknown as IdpKeys['jwk']
  return { privateKey, jwk: { ...jwk, kid, alg: 'RS256', use: 'sig' } }
}

function b64url(input: Buffer | string): string {
  return Buffer.from(input).toString('base64url')
}

/** Sign a JWT (RS256) — the ID token shape the IdP issues. */
export function signIdpJwt(
  keys: IdpKeys,
  claims: Record<string, unknown>,
  opts?: { kid?: string; alg?: string },
): string {
  const header = b64url(JSON.stringify({ alg: opts?.alg ?? 'RS256', typ: 'JWT', kid: opts?.kid ?? keys.jwk.kid }))
  const payload = b64url(JSON.stringify(claims))
  const signature = createSign('RSA-SHA256').update(`${header}.${payload}`).sign(keys.privateKey)
  return `${header}.${payload}.${signature.toString('base64url')}`
}

/** The well-formed ID-token claims for a fixture user (tests mutate
 *  copies of this to mint broken tokens). */
export function idTokenClaimsFor(
  user: StubIdpUser,
  params: { issuer: string; clientId: string; nonce: string; expiresInSec?: number },
): Record<string, unknown> {
  const now = Math.floor(Date.now() / 1000)
  return {
    iss: params.issuer,
    sub: user.sub,
    aud: params.clientId,
    exp: now + (params.expiresInSec ?? 600),
    iat: now,
    nonce: params.nonce,
    email: user.email,
    email_verified: user.emailVerified,
    name: user.name,
    groups: user.groups,
    ...(user.claims ?? {}),
  }
}

// ── the server ──────────────────────────────────────────────────────

interface PendingCode {
  user: StubIdpUser
  clientId: string
  redirectUri: string
  nonce: string
  codeChallenge: string
}

export interface StubIdp {
  /** The issuer URL (== base URL, no trailing slash). */
  issuer: string
  port: number
  /** The RP-initiated-logout hits (each: the query params seen). */
  logoutHits: Array<Record<string, string>>
  close(): Promise<void>
}

export async function startStubIdp(opts: { port?: number; users?: StubIdpUser[] } = {}): Promise<StubIdp> {
  const users = opts.users ?? STUB_IDP_USERS
  const keys = generateIdpKeys()
  const codes = new Map<string, PendingCode>()
  const logoutHits: Array<Record<string, string>> = []

  const server: Server = createServer((req, res) => {
    void (async () => {
      const url = new URL(req.url ?? '/', `http://localhost`)
      const issuer = issuerOf()

      if (url.pathname === '/.well-known/openid-configuration') {
        return json(res, {
          issuer,
          authorization_endpoint: `${issuer}/authorize`,
          token_endpoint: `${issuer}/token`,
          jwks_uri: `${issuer}/jwks`,
          end_session_endpoint: `${issuer}/logout`,
        })
      }

      if (url.pathname === '/jwks') {
        return json(res, { keys: [keys.jwk] })
      }

      if (url.pathname === '/authorize') {
        // The consent page: one link per fixture user, the original
        // query carried through + the chosen user id.
        const links = users.map(u =>
          `<li><a data-user="${u.id}" href="/authorize/complete?${url.searchParams.toString()}&user=${u.id}">Sign in as ${u.name} (${u.email})</a></li>`,
        ).join('\n')
        res.writeHead(200, { 'content-type': 'text/html' })
        return res.end(`<html><head><title>Stub IdP</title></head><body>
          <h1>Stub identity provider</h1>
          <p data-testid="stub-idp-consent">Choose the user to authenticate as:</p>
          <ul>${links}</ul>
        </body></html>`)
      }

      if (url.pathname === '/authorize/complete') {
        const user = users.find(u => u.id === url.searchParams.get('user'))
        const redirectUri = url.searchParams.get('redirect_uri')
        const clientId = url.searchParams.get('client_id')
        const state = url.searchParams.get('state')
        const nonce = url.searchParams.get('nonce') ?? ''
        const codeChallenge = url.searchParams.get('code_challenge') ?? ''
        const method = url.searchParams.get('code_challenge_method')
        if (!user || !redirectUri || !clientId || !state) {
          res.writeHead(400, { 'content-type': 'text/plain' })
          return res.end('bad authorization request')
        }
        if (method !== 'S256') {
          const back = new URL(redirectUri)
          back.searchParams.set('error', 'invalid_request')
          back.searchParams.set('error_description', 'PKCE S256 required')
          back.searchParams.set('state', state)
          res.writeHead(302, { location: back.toString() })
          return res.end()
        }
        const code = randomUUID()
        codes.set(code, { user, clientId, redirectUri, nonce, codeChallenge })
        const back = new URL(redirectUri)
        back.searchParams.set('code', code)
        back.searchParams.set('state', state)
        res.writeHead(302, { location: back.toString() })
        return res.end()
      }

      if (url.pathname === '/token' && req.method === 'POST') {
        const raw = await readBody(req)
        const form = new URLSearchParams(raw)
        const code = form.get('code') ?? ''
        const pending = codes.get(code)
        const fail = (status: number, error: string, description: string) => {
          res.writeHead(status, { 'content-type': 'application/json' })
          res.end(JSON.stringify({ error, error_description: description }))
        }
        if (!pending) return fail(400, 'invalid_grant', 'unknown or spent code')
        codes.delete(code) // one-time
        if (form.get('grant_type') !== 'authorization_code') return fail(400, 'unsupported_grant_type', 'authorization_code only')
        if (form.get('client_id') !== pending.clientId) return fail(401, 'invalid_client', 'client_id mismatch')
        if (form.get('redirect_uri') !== pending.redirectUri) return fail(400, 'invalid_grant', 'redirect_uri mismatch')
        // PKCE S256: base64url(sha256(verifier)) must equal the challenge.
        const verifier = form.get('code_verifier') ?? ''
        const { createHash } = await import('node:crypto')
        const computed = createHash('sha256').update(verifier).digest('base64url')
        if (computed !== pending.codeChallenge) return fail(400, 'invalid_grant', 'PKCE verification failed')

        const issuerNow = issuerOf()
        const idToken = signIdpJwt(keys, idTokenClaimsFor(pending.user, {
          issuer: issuerNow, clientId: pending.clientId, nonce: pending.nonce,
        }))
        return json(res, {
          access_token: randomUUID(),
          token_type: 'Bearer',
          expires_in: 600,
          id_token: idToken,
        })
      }

      if (url.pathname === '/logout') {
        logoutHits.push(Object.fromEntries(url.searchParams.entries()))
        const back = url.searchParams.get('post_logout_redirect_uri')
        if (back) {
          res.writeHead(302, { location: back })
          return res.end()
        }
        res.writeHead(200, { 'content-type': 'text/plain' })
        return res.end('signed out')
      }

      res.writeHead(404, { 'content-type': 'text/plain' })
      res.end('stub IdP: not found')
    })().catch((err) => {
      res.writeHead(500, { 'content-type': 'text/plain' })
      res.end(`stub IdP error: ${(err as Error).message}`)
    })
  })

  const port = await new Promise<number>((resolve, reject) => {
    server.once('error', reject)
    server.listen(opts.port ?? 0, '127.0.0.1', () => {
      const address = server.address()
      if (address && typeof address === 'object') resolve(address.port)
      else reject(new Error('the stub IdP did not bind a port'))
    })
  })

  function issuerOf(): string {
    return `http://127.0.0.1:${port}`
  }

  function json(res: import('node:http').ServerResponse, body: unknown) {
    res.writeHead(200, { 'content-type': 'application/json' })
    res.end(JSON.stringify(body))
  }

  function readBody(req: import('node:http').IncomingMessage): Promise<string> {
    return new Promise((resolve, reject) => {
      let data = ''
      req.on('data', (chunk) => { data += chunk })
      req.on('end', () => resolve(data))
      req.on('error', reject)
    })
  }

  return {
    issuer: `http://127.0.0.1:${port}`,
    port,
    logoutHits,
    close: () => new Promise((resolve) => server.close(() => resolve())),
  }
}
