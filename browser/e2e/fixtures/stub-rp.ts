// ═══════════════════════════════════════════════════════════════════
// The fixture OIDC relying party (TODO.identity/01) — a tiny, honest
// RP for the OP's e2e: node:http over the REAL client code
// (@oimlsmart/platform-server/oidc — the module the platform's instances run), so
// the round trip proves the OP against the RP's real validation path,
// not a test-shaped copy.
//
// The surface:
//   GET /signin   — builds the authorization request (discovery, PKCE,
//                   state, nonce — oidc.ts's own builders) and 302s the
//                   browser to the OP;
//   GET /callback — the OP's redirect back: state check, the code
//                   exchange at the OP's token endpoint
//                   (client_secret_basic), the ID-token validation
//                   (signature against the OP's JWKS, iss/aud/exp/nonce)
//                   and the userinfo read; serves a page naming the
//                   signed-in account — or the honest error page the OP
//                   sent back (error=access_denied & co.);
//   GET /whoami   — the last validated claims (JSON), the test's
//                   assertion surface.
//
// NO per-test state beyond the last flow's — this is a fixture, not a
// product.
// ═══════════════════════════════════════════════════════════════════

import { createServer, type Server } from 'node:http'
import {
  buildAuthorizationUrl,
  clearOidcCaches,
  discoverIssuer,
  exchangeCode,
  generatePkce,
  randomToken,
  validateIdToken,
  type OidcIdTokenClaims,
} from '@oimlsmart/platform-server/oidc'

export interface StubRpFlow {
  state: string
  nonce: string
  verifier: string
}

export interface StubRp {
  port: number
  baseUrl: string
  /** The last completed sign-in's validated ID-token claims. */
  claims: OidcIdTokenClaims | null
  /** The last userinfo read. */
  userinfo: Record<string, unknown> | null
  /** The last error redirect the OP sent (access_denied & co.). */
  lastError: Record<string, string> | null
  close(): Promise<void>
}

export async function startStubRp(opts: {
  port?: number
  issuer: string
  clientId: string
  clientSecret?: string
  scopes?: string
}): Promise<StubRp> {
  let pending: StubRpFlow | null = null
  let claims: OidcIdTokenClaims | null = null
  let userinfo: Record<string, unknown> | null = null
  let lastError: Record<string, string> | null = null

  const server: Server = createServer((req, res) => {
    void (async () => {
      const url = new URL(req.url ?? '/', 'http://localhost')
      const issuer = opts.issuer.replace(/\/$/, '')

      if (url.pathname === '/signin') {
        clearOidcCaches() // every leg discovers fresh (the OP may have rotated)
        const metadata = await discoverIssuer(issuer)
        const state = randomToken()
        const nonce = randomToken()
        const pkce = await generatePkce()
        pending = { state, nonce, verifier: pkce.verifier }
        claims = null
        userinfo = null
        lastError = null
        res.writeHead(302, {
          location: buildAuthorizationUrl(metadata, {
            clientId: opts.clientId,
            redirectUri: `${baseUrl()}/callback`,
            scopes: opts.scopes ?? 'openid profile email',
            state,
            nonce,
            codeChallenge: pkce.challenge,
          }),
        })
        return res.end()
      }

      if (url.pathname === '/callback') {
        const error = url.searchParams.get('error')
        if (error) {
          lastError = Object.fromEntries(url.searchParams.entries())
          res.writeHead(200, { 'content-type': 'text/html' })
          return res.end(`<html><body>
            <h1 data-testid="rp-error">Sign-in refused</h1>
            <p data-testid="rp-error-kind">${error}</p>
            <p>${url.searchParams.get('error_description') ?? ''}</p>
          </body></html>`)
        }

        const code = url.searchParams.get('code')
        const state = url.searchParams.get('state')
        if (!code || !state || !pending || state !== pending.state) {
          res.writeHead(400, { 'content-type': 'text/plain' })
          return res.end('bad callback (code/state)')
        }
        const flow = pending
        pending = null

        try {
          const metadata = await discoverIssuer(issuer)
          const tokens = await exchangeCode(metadata, {
            clientId: opts.clientId,
            clientSecret: opts.clientSecret,
            code,
            redirectUri: `${baseUrl()}/callback`,
            codeVerifier: flow.verifier,
          })
          // THE REAL RP VALIDATION PATH — signature against the OP's
          // JWKS, issuer, audience, expiry, the nonce we issued.
          claims = await validateIdToken(tokens.id_token, {
            issuer,
            clientId: opts.clientId,
            nonce: flow.nonce,
            jwksUri: metadata.jwks_uri,
          })
          if (tokens.access_token) {
            const ui = await fetch(metadata.userinfo_endpoint!, {
              headers: { authorization: `Bearer ${tokens.access_token}` },
            })
            userinfo = ui.ok ? await ui.json() as Record<string, unknown> : { error: `HTTP ${ui.status}` }
          }
        } catch (err) {
          res.writeHead(500, { 'content-type': 'text/plain' })
          return res.end(`RP validation failed: ${(err as Error).message}`)
        }

        res.writeHead(200, { 'content-type': 'text/html' })
        return res.end(`<html><body>
          <h1 data-testid="rp-signed-in">Signed in</h1>
          <p data-testid="rp-email">${claims.email ?? ''}</p>
          <p data-testid="rp-sub">${claims.sub}</p>
        </body></html>`)
      }

      if (url.pathname === '/whoami') {
        res.writeHead(200, { 'content-type': 'application/json' })
        return res.end(JSON.stringify({ claims, userinfo, lastError }))
      }

      res.writeHead(404, { 'content-type': 'text/plain' })
      res.end('stub RP: not found')
    })().catch((err) => {
      res.writeHead(500, { 'content-type': 'text/plain' })
      res.end(`stub RP error: ${(err as Error).message}`)
    })
  })

  const port = await new Promise<number>((resolve, reject) => {
    server.once('error', reject)
    server.listen(opts.port ?? 0, '127.0.0.1', () => {
      const address = server.address()
      if (address && typeof address === 'object') resolve(address.port)
      else reject(new Error('the stub RP did not bind a port'))
    })
  })

  function baseUrl(): string {
    return `http://127.0.0.1:${port}`
  }

  return {
    port,
    baseUrl: baseUrl(),
    get claims() { return claims },
    get userinfo() { return userinfo },
    get lastError() { return lastError },
    close: () => new Promise((resolve) => server.close(() => resolve())),
  }
}
