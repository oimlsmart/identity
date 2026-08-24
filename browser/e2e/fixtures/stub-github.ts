// ═══════════════════════════════════════════════════════════════════
// The stub GitHub OAuth provider — the GitHub-shaped counterpart of
// stub-idp.ts (which is OIDC-shaped). A tiny, honest github.com for the
// in-process integration tests: NO external dependency, node:http only.
//
// What it implements (GitHub's OAuth web flow + the REST reads the
// sign-in makes):
//   GET  /login/oauth/authorize — the consent shortcut: the tests pick
//        the fixture user with a `login` query param (GitHub has no
//        such param — it IS the stub's consent), records the requested
//        scope, issues a one-time code and 302s back to redirect_uri
//        with code+state;
//   POST /login/oauth/access_token — the code exchange (the platform
//        posts JSON): verifies the one-time code, the client_id and the
//        client_secret, then issues the access token bound to the user;
//   GET  /user — the token user's profile (id, login, name, avatar);
//   GET  /user/emails — the token user's email rows (primary + verified
//        when the fixture carries an email; EMPTY when it does not, so
//        the platform's noreply fallback is exercised);
//   GET  /user/memberships/orgs/:org — the token user's membership in
//        the org: the fixture's state (`active`/`pending`), or 404 when
//        the fixture holds no membership — exactly GitHub's semantics
//        for "not a member (that this token may see)".
//
// One server plays BOTH endpoint roles (the OAuth web flow and the REST
// API): the tests point GITHUB_OAUTH_BASE_URL and GITHUB_API_BASE_URL
// at the same base (@oimlsmart/platform-server/github's GHES seam).
// ═══════════════════════════════════════════════════════════════════

import { createServer, type Server, type IncomingMessage, type ServerResponse } from 'node:http'
import { randomUUID } from 'node:crypto'

export interface StubGitHubUser {
  login: string
  id: number
  name: string
  /** null → /user/emails answers [] (the platform's noreply fallback). */
  email: string | null
  avatarUrl?: string
  /** Org slug → membership state; an undeclared org 404s. */
  memberships?: Record<string, 'active' | 'pending'>
}

export const STUB_GITHUB_USERS: StubGitHubUser[] = [
  { login: 'octocat-admin', id: 101, name: 'Octo Admin', email: 'admin@example.org' },
  { login: 'octocat-staff', id: 102, name: 'Octo Staff', email: 'staff@example.org' },
  { login: 'octocat-mapped', id: 103, name: 'Octo Mapped', email: 'mapped@example.org' },
  { login: 'octocat-org', id: 104, name: 'Octo Org', email: 'org@example.org', memberships: { oimlsmart: 'active' } },
  { login: 'octocat-pending', id: 105, name: 'Octo Pending', email: 'pending@example.org', memberships: { oimlsmart: 'pending' } },
  { login: 'octocat-stranger', id: 106, name: 'Octo Stranger', email: 'stranger@example.org' },
  // The noreply leg: GitHub users who hide their email entirely.
  { login: 'octocat-private', id: 107, name: 'Octo Private', email: null },
]

export interface StubGitHub {
  /** The base URL (no trailing slash) — both endpoint roles. */
  baseUrl: string
  port: number
  /** The scope of every authorize request, in order (the read:org
   *  widening assertions read this). */
  requestedScopes: string[]
  close(): Promise<void>
}

export async function startStubGitHub(opts: { port?: number; users?: StubGitHubUser[]; clientSecret?: string; tokenPlainText?: boolean } = {}): Promise<StubGitHub> {
  const users = opts.users ?? STUB_GITHUB_USERS
  const codes = new Map<string, StubGitHubUser>()
  const tokens = new Map<string, StubGitHubUser>()
  const requestedScopes: string[] = []

  const server: Server = createServer((req: IncomingMessage, res: ServerResponse) => {
    void (async () => {
      const url = new URL(req.url ?? '/', 'http://localhost')

      if (url.pathname === '/login/oauth/authorize') {
        const login = url.searchParams.get('login')
        const user = users.find(u => u.login === login)
        const redirectUri = url.searchParams.get('redirect_uri')
        const state = url.searchParams.get('state')
        requestedScopes.push(url.searchParams.get('scope') ?? '')
        if (!user || !redirectUri || !state) {
          res.writeHead(400, { 'content-type': 'text/plain' })
          return res.end('bad authorization request (the stub needs ?login=<fixture login>)')
        }
        const code = randomUUID()
        codes.set(code, user)
        const back = new URL(redirectUri)
        back.searchParams.set('code', code)
        back.searchParams.set('state', state)
        res.writeHead(302, { location: back.toString() })
        return res.end()
      }

      if (url.pathname === '/login/oauth/access_token' && req.method === 'POST') {
        const body = JSON.parse(await readBody(req)) as {
          client_id?: string; client_secret?: string; code?: string
        }
        // The GitHub failure class that 500'd the callback (2026-08-16):
        // a refused exchange (a flagged app, rate limits) answers PLAIN
        // TEXT, not JSON — the platform must redirect, not throw.
        if (opts.tokenPlainText) {
          res.writeHead(403, { 'content-type': 'text/plain' })
          return res.end('\r\nRequest forbidden')
        }
        const user = body.code ? codes.get(body.code) : undefined
        if (!user || (opts.clientSecret && body.client_secret !== opts.clientSecret)) {
          res.writeHead(200, { 'content-type': 'application/json' })
          // GitHub answers 200 with an error payload on a bad exchange.
          return res.end(JSON.stringify({ error: 'bad_verification_code' }))
        }
        codes.delete(body.code!) // one-time
        const token = `gho_${randomUUID()}`
        tokens.set(token, user)
        res.writeHead(200, { 'content-type': 'application/json' })
        return res.end(JSON.stringify({ access_token: token, token_type: 'bearer', scope: '' }))
      }

      if (url.pathname === '/user') {
        const user = bearerUser(req)
        if (!user) return unauthorized(res)
        return json(res, {
          id: user.id,
          login: user.login,
          name: user.name,
          avatar_url: user.avatarUrl ?? `https://avatars.example.org/${user.login}`,
        })
      }

      if (url.pathname === '/user/emails') {
        const user = bearerUser(req)
        if (!user) return unauthorized(res)
        return json(res, user.email ? [{ email: user.email, primary: true, verified: true }] : [])
      }

      const membership = /^\/user\/memberships\/orgs\/([^/]+)$/.exec(url.pathname)
      if (membership) {
        const user = bearerUser(req)
        if (!user) return unauthorized(res)
        const org = decodeURIComponent(membership[1]!)
        const state = user.memberships?.[org] ?? user.memberships?.[org.toLowerCase()]
        if (!state) {
          res.writeHead(404, { 'content-type': 'application/json' })
          return res.end(JSON.stringify({ message: 'Not Found' }))
        }
        return json(res, { state, role: 'member', organization: { login: org } })
      }

      res.writeHead(404, { 'content-type': 'text/plain' })
      res.end('stub GitHub: not found')
    })().catch((err) => {
      res.writeHead(500, { 'content-type': 'text/plain' })
      res.end(`stub GitHub error: ${(err as Error).message}`)
    })
  })

  const port = await new Promise<number>((resolve, reject) => {
    server.once('error', reject)
    server.listen(opts.port ?? 0, '127.0.0.1', () => {
      const address = server.address()
      if (address && typeof address === 'object') resolve(address.port)
      else reject(new Error('the stub GitHub did not bind a port'))
    })
  })

  function bearerUser(req: IncomingMessage): StubGitHubUser | undefined {
    const auth = req.headers.authorization ?? ''
    const token = auth.startsWith('Bearer ') ? auth.slice(7) : ''
    return tokens.get(token)
  }

  function unauthorized(res: ServerResponse) {
    res.writeHead(401, { 'content-type': 'application/json' })
    return res.end(JSON.stringify({ message: 'Bad credentials' }))
  }

  function json(res: ServerResponse, body: unknown) {
    res.writeHead(200, { 'content-type': 'application/json' })
    res.end(JSON.stringify(body))
  }

  function readBody(req: IncomingMessage): Promise<string> {
    return new Promise((resolve, reject) => {
      let data = ''
      req.on('data', (chunk) => { data += chunk })
      req.on('end', () => resolve(data))
      req.on('error', reject)
    })
  }

  return {
    baseUrl: `http://127.0.0.1:${port}`,
    port,
    requestedScopes,
    close: () => new Promise((resolve) => server.close(() => resolve())),
  }
}
