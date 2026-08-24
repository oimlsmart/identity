// ═══════════════════════════════════════════════════════════════════
// The OIDC Provider's endpoints (TODO.identity/01) — the OP half of the
// Authorization Code + PKCE flow our instances (the RP side,
// TODO.federation/10) already consume. Hand-rolled on WebCrypto + the
// ServerStore seam, the same discipline as auth/oidc.ts: NO library
// dependency, every runtime (node ≥ 18, Cloudflare Workers) ships what
// this uses, and EVERY piece of state that must survive an isolate lives
// in the database (clients, pending authorizations, one-time codes,
// access tokens, the key history) — NOTHING in per-process Maps (the
// GitHub-flow lesson).
//
// The surface:
//   GET  /.well-known/openid-configuration — the discovery document;
//   GET  /jwks.json                        — the OP's public keys (ES256,
//                                            kid, rotation history);
//   GET  /op/authorize                     — the authorization endpoint:
//                                            client-registry validation,
//                                            the signed-in session (or a
//                                            redirect to the instance's
//                                            own login page), then the
//                                            consent page (/op/consent,
//                                            the Vue island);
//   GET  /api/op/consent/:id               — the consent page's context
//   POST /api/op/consent/:id/decide        — the consent decision → the
//                                            one-time code back to the RP;
//   POST /op/token                         — the code exchange: one-time
//                                            code + PKCE verify + the
//                                            client's secret → the signed
//                                            ES256 ID token + access token;
//   GET  /op/userinfo                      — the access token's claims;
//   GET/POST /api/op/clients[…]            — the client registry's admin
//                                            surface (admin/cs_admin).
//
// The routes mount on EVERY instance (app.ts) but answer 404 unless the
// deployment profile carries the identity module (roles: [identity]) —
// one build, the profile decides (the same posture as the module-gated
// client routes).
//
// WORKER-SAFE: WebCrypto + the store seam only, no node built-ins.
// ═══════════════════════════════════════════════════════════════════

import { Hono, type Context, type MiddlewareHandler } from 'hono'
import { env as runtimeEnv } from 'hono/adapter'
import { getStore, type AuthUserPayload, type OidcClient } from '@oimlsmart/platform-server/store'
import { getInstanceProfile } from '@oimlsmart/platform-server/profile'
import { opRequestOrigin, resolveOpConfig, type OpConfig } from '../auth/op/config'
import { ensureOpKeyRegistered, opJwks, opRandomToken, pkceS256, resolveOpSigningKey, signOpIdToken } from '../auth/op/keys'
import { hashClientSecret, verifyClientSecret } from '../auth/op/secrets'
import { seedOidcClientsFromEnv } from '../auth/op/registry'
import { roleClaimsForClient } from '../auth/op/claims'
import { APP_ROLES } from '@oimlsmart/platform-server/vocab'
import { sessionUser } from '@oimlsmart/platform-server/session'

type EnvLike = Record<string, string | undefined>

/** The OAuth/OIDC error body (RFC 6749 §5.2), never a stack trace. */
function oidcError(c: Context, status: 400 | 401, error: string, description: string): Response {
  return c.json({ error, error_description: description }, status)
}

export function createOpRouter(): Hono {
  const op = new Hono()

  // ── the profile gate ─────────────────────────────────────────────
  // Only an identity-profile instance (roles: [identity] → the identity
  // module) serves the OP contract; every other deployment answers a
  // plain 404 — the routes exist in the ONE build, the profile decides.
  // (Scoped to the OP's own paths: this router mounts at the root, so a
  // bare '*' would gate the WHOLE app.)
  const profileGate: MiddlewareHandler = async (c, next) => {
    if (!getInstanceProfile().modules.includes('identity')) {
      return c.json({ error: 'not found' }, 404)
    }
    await next()
  }
  op.use('/.well-known/openid-configuration', profileGate)
  op.use('/jwks.json', profileGate)
  op.use('/op/*', profileGate)
  op.use('/api/op/*', profileGate)

  /** The request's effective OP config (env + this request's origin). */
  function configFor(c: Context): OpConfig {
    return resolveOpConfig(runtimeEnv<EnvLike>(c), opRequestOrigin(c.req.raw))
  }

  // The bootstrap client seed runs once per process/isolate (the
  // registry's known instances; idempotent upserts).
  let seeded: Promise<void> | null = null
  function ensureSeeded(c: Context): Promise<void> {
    if (!seeded) {
      seeded = (async () => {
        const ids = await seedOidcClientsFromEnv(runtimeEnv<EnvLike>(c), getStore())
        if (ids.length) console.log(`[op] client registry bootstrap seeded: ${ids.join(', ')}`)
      })()
      seeded.catch(() => { seeded = null }) // a failed seed retries next request
    }
    return seeded
  }

  // ── discovery + keys ─────────────────────────────────────────────

  // GET /.well-known/openid-configuration — the discovery document. The
  // RP side (auth/oidc.ts) requires issuer/authorization_endpoint/
  // token_endpoint/jwks_uri and an exact issuer match.
  op.get('/.well-known/openid-configuration', async (c) => {
    const { issuer } = configFor(c)
    return c.json({
      issuer,
      authorization_endpoint: `${issuer}/op/authorize`,
      token_endpoint: `${issuer}/op/token`,
      userinfo_endpoint: `${issuer}/op/userinfo`,
      jwks_uri: `${issuer}/jwks.json`,
      response_types_supported: ['code'],
      grant_types_supported: ['authorization_code'],
      subject_types_supported: ['public'],
      id_token_signing_alg_values_supported: ['ES256'],
      scopes_supported: ['openid', 'profile', 'email'],
      token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post', 'none'],
      code_challenge_methods_supported: ['S256'],
      claims_supported: ['iss', 'sub', 'aud', 'exp', 'iat', 'nonce', 'name', 'email', 'email_verified', 'roles', 'groups', 'org'],
    })
  })

  // GET /jwks.json — the public halves of the key history. The answer
  // is the REGISTERED TABLE, never gated on the signing secret's
  // availability: a Worker secret mid-propagation (a fresh isolate whose
  // OP_SIGNING_KEY binding reads malformed or rejects the key material
  // while the rollout settles) must never 500 the public key set. The
  // secret matters for SIGNING, not for serving public keys. The active
  // key's self-registration stays (a fresh deployment answers its own
  // key before the first token issuance, and the rotation ceremony's
  // overlap poll rides it) but is best-effort: a failed resolve serves
  // the table as it stands, and a genuinely empty table answers an
  // honest empty JWKS.
  op.get('/jwks.json', async (c) => {
    const store = getStore()
    try {
      const key = await resolveOpSigningKey(runtimeEnv<EnvLike>(c))
      await ensureOpKeyRegistered(store, key)
    } catch (err) {
      console.warn('[op] jwks.json: the signing key is unavailable on this isolate; serving the registered table:', (err as Error).message)
    }
    return c.json(await opJwks(store))
  })

  // ── authorize ────────────────────────────────────────────────────

  /** The browser-facing refusal for a request we may NEVER redirect
   *  back (unknown client / unregistered redirect_uri): a plain page,
   *  honest about what happened. The audience is the RP developer. */
  function authorizeRefusal(c: Context, title: string, detail: string): Response {
    return c.html(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>${title} — OIML SMART Identity</title>
<style>
  body { font-family: ui-sans-serif, system-ui, sans-serif; background: #faf8f5; color: #0f172a; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; }
  main { max-width: 28rem; padding: 2rem; background: #fff; border: 1px solid #e2e8f0; border-radius: 0.75rem; }
  h1 { font-size: 1.125rem; margin: 0 0 0.5rem; } p { font-size: 0.875rem; color: #475569; margin: 0; }
  code { background: #f1f5f9; padding: 0 0.25rem; border-radius: 0.25rem; }
  @media (prefers-color-scheme: dark) { body { background: #0f172a; color: #fff; } main { background: #1e293b; border-color: #334155; } p { color: #94a3b8; } code { background: #0f172a; } }
</style></head>
<body><main><h1 data-testid="op-authorize-error">${title}</h1><p>${detail}</p></main></body></html>`, 400)
  }

  /** The redirect-back error (the redirect_uri is validated, so the
   *  OIDC error redirect is safe). */
  function authorizeErrorRedirect(redirectUri: string, state: string | undefined, error: string, description: string): string {
    const back = new URL(redirectUri)
    back.searchParams.set('error', error)
    back.searchParams.set('error_description', description)
    if (state) back.searchParams.set('state', state)
    return back.toString()
  }

  // GET /op/authorize — the authorization endpoint.
  op.get('/op/authorize', async (c) => {
    await ensureSeeded(c)
    const config = configFor(c)
    const q = (name: string) => c.req.query(name)?.trim() || undefined
    const [responseType, clientId, redirectUri, scope, state, nonce, challenge, challengeMethod] =
      ['response_type', 'client_id', 'redirect_uri', 'scope', 'state', 'nonce', 'code_challenge', 'code_challenge_method'].map(q)

    // 1. The client must be KNOWN + active — before any redirect logic.
    if (!clientId) {
      return authorizeRefusal(c, 'Cannot authorize this request', 'The request names no <code>client_id</code>.')
    }
    const client = await getStore().getOidcClient(clientId)
    if (!client || client.status !== 'active') {
      return authorizeRefusal(c, 'Cannot authorize this request', `The client <code>${escapeHtml(clientId)}</code> is not registered on this identity provider (or is disabled).`)
    }

    // 2. The redirect URI must be registered EXACTLY — an unregistered
    //    one is refused in place, NEVER redirected to (the open-redirect
    //    wall).
    if (!redirectUri || !client.redirectUris.includes(redirectUri)) {
      return authorizeRefusal(c, 'Cannot authorize this request', 'The <code>redirect_uri</code> is not one this client registered.')
    }

    // 3. From here the error redirect is safe (the URI is the client's own).
    if (responseType !== 'code') {
      return c.redirect(authorizeErrorRedirect(redirectUri, state, 'unsupported_response_type', 'only response_type=code is served'))
    }
    if (!(scope ?? '').split(/\s+/).includes('openid')) {
      return c.redirect(authorizeErrorRedirect(redirectUri, state, 'invalid_scope', 'the openid scope is required'))
    }
    if (!challenge || challengeMethod !== 'S256') {
      return c.redirect(authorizeErrorRedirect(redirectUri, state, 'invalid_request', 'PKCE is required (code_challenge + code_challenge_method=S256)'))
    }

    // 4. The sign-in surface: no session → the instance's own login
    //    page, with this very request as the post-login destination (the
    //    flow re-enters /op/authorize, now signed in). NOTHING is stored
    //    yet — the row is created only for an authenticated request.
    const user = await sessionUser(c)
    if (!user) {
      const here = new URL(c.req.url)
      const target = `${here.pathname}${here.search}`
      return c.redirect(`/?redirect=${encodeURIComponent(target)}`)
    }

    // 5. The pending authorization (D1 — the consent decision may land
    //    on another isolate), then the consent page.
    const id = opRandomToken()
    await getStore().createOidcAuthorization({
      id,
      clientId: client.clientId,
      redirectUri,
      scope: scope!,
      state: state ?? '',
      nonce: nonce ?? null,
      codeChallenge: challenge,
      userId: user.id,
      ttlMs: config.authorizationTtlMs,
    })
    return c.redirect(`/op/consent?auth=${encodeURIComponent(id)}`)
  })

  // ── consent (the Vue island's API) ───────────────────────────────

  /** The pending row for the consent API, or the error response. */
  async function consentRow(c: Context, id: string) {
    const row = await getStore().getOidcAuthorization(id)
    if (!row) return { row: null, error: oidcError(c, 400, 'invalid_request', 'unknown authorization') }
    if (row.decision) return { row: null, error: oidcError(c, 400, 'invalid_request', 'this authorization was already decided') }
    if (new Date(row.expiresAt).getTime() <= Date.now()) {
      return { row: null, error: oidcError(c, 400, 'invalid_request', 'the authorization request expired — start the sign-in again') }
    }
    return { row, error: null }
  }

  /** Rebuild the original authorize URL from the pending row (the
   *  re-entry target after a mid-flow sign-in). */
  function authorizeUrlFor(row: { clientId: string; redirectUri: string; scope: string; state: string; nonce: string | null; codeChallenge: string }): string {
    const url = new URL('/op/authorize', 'http://op.local')
    url.searchParams.set('response_type', 'code')
    url.searchParams.set('client_id', row.clientId)
    url.searchParams.set('redirect_uri', row.redirectUri)
    url.searchParams.set('scope', row.scope)
    url.searchParams.set('state', row.state)
    if (row.nonce) url.searchParams.set('nonce', row.nonce)
    url.searchParams.set('code_challenge', row.codeChallenge)
    url.searchParams.set('code_challenge_method', 'S256')
    return `${url.pathname}${url.search}`
  }

  // GET /api/op/consent/:id — the consent page's context: the client,
  // the scopes, the account being shared. Session required, and it must
  // be the account the authorization row belongs to.
  op.get('/api/op/consent/:id', async (c) => {
    await ensureSeeded(c)
    const { row, error } = await consentRow(c, c.req.param('id'))
    if (error) return error
    const user = await sessionUser(c)
    if (!user) {
      return c.json({
        error: 'authentication_required',
        login: `/?redirect=${encodeURIComponent(authorizeUrlFor(row!))}`,
      }, 401)
    }
    if (row!.userId && row!.userId !== user.id) {
      // A different account than the flow's — the honest refusal (the
      // page offers to restart the sign-in as that account).
      return c.json({
        error: 'account_mismatch',
        login: `/?redirect=${encodeURIComponent(authorizeUrlFor(row!))}`,
      }, 403)
    }
    const client = await getStore().getOidcClient(row!.clientId)
    const profile = getInstanceProfile()
    // The role claims this client's tokens carry for THIS account (shown
    // honestly on the consent page — the account shares more than its
    // name): the per-client assignment through the client's policy
    // allowlist (TODO.identity/03, auth/op/claims.ts).
    const assigned = await getStore().getOpClientRoles(user.id, row!.clientId)
    const roleClaims = client
      ? roleClaimsForClient(assigned, { role: user.role, roles: user.roles, orgId: user.orgId }, client.claimsPolicy)
      : {}
    return c.json({
      id: row!.id,
      client: client ? { id: client.clientId, name: client.name } : { id: row!.clientId, name: row!.clientId },
      scopes: row!.scope.split(/\s+/).filter(Boolean),
      // The role claims this client's tokens carry (shown honestly on
      // the consent page — the account shares more than its name).
      policyClaims: client?.claimsPolicy?.claims ?? [],
      roleClaims: (roleClaims.roles ?? []) as string[],
      orgClaim: (roleClaims.org ?? null) as string | null,
      account: { name: user.name, email: user.email, avatarUrl: user.avatarUrl ?? null },
      issuer: configFor(c).issuer,
      issuerName: profile.branding.name || profile.identity.org_name,
    })
  })

  // POST /api/op/consent/:id/decide — the consent decision. allow mints
  // the one-time code; deny answers error=access_denied. Both answer
  // the redirect the page navigates to.
  op.post('/api/op/consent/:id/decide', async (c) => {
    const { row, error } = await consentRow(c, c.req.param('id'))
    if (error) return error
    const user = await sessionUser(c)
    if (!user) return oidcError(c, 401, 'authentication_required', 'sign in to decide the authorization')
    const body = await c.req.json<{ decision?: string }>().catch(() => null)
    if (!body || (body.decision !== 'allow' && body.decision !== 'deny')) {
      return oidcError(c, 400, 'invalid_request', 'decision must be "allow" or "deny"')
    }
    // The decision binds to the row's own account — atomically (a
    // double-submit / a different signed-in account loses).
    const decided = await getStore().decideOidcAuthorization(row!.id, { userId: user.id, decision: body.decision })
    if (!decided) {
      return oidcError(c, 400, 'invalid_request', 'this authorization was already decided, or belongs to another account')
    }

    const back = new URL(decided.redirectUri)
    if (decided.state) back.searchParams.set('state', decided.state)
    if (body.decision === 'deny') {
      back.searchParams.set('error', 'access_denied')
      back.searchParams.set('error_description', 'the account holder declined the authorization')
      return c.json({ redirect: back.toString() })
    }

    const config = configFor(c)
    const code = opRandomToken()
    await getStore().createOidcCode({
      code,
      clientId: decided.clientId,
      redirectUri: decided.redirectUri,
      scope: decided.scope,
      nonce: decided.nonce,
      codeChallenge: decided.codeChallenge,
      userId: user.id,
      ttlMs: config.codeTtlMs,
    })
    back.searchParams.set('code', code)
    return c.json({ redirect: back.toString() })
  })

  // ── token ────────────────────────────────────────────────────────

  /** The token endpoint's client authentication: HTTP Basic
   *  (client_secret_basic) or the form's client_secret (post). Public
   *  clients (no registered secret) authenticate by client_id + PKCE. */
  async function authenticateClient(c: Context, form: URLSearchParams): Promise<{ client: OidcClient | null; error: Response | null }> {
    let clientId = form.get('client_id') ?? ''
    let secret = form.get('client_secret')
    const basic = c.req.header('authorization')
    if (basic?.startsWith('Basic ')) {
      let decoded: string
      try {
        decoded = atob(basic.slice(6))
      } catch {
        return { client: null, error: oidcError(c, 401, 'invalid_client', 'the Authorization header is not valid Basic') }
      }
      const idx = decoded.indexOf(':')
      clientId = decodeURIComponent(decoded.slice(0, idx))
      secret = decoded.slice(idx + 1)
      // The RP sends the secret percent-encoded per RFC 6749 §2.3.1.
      try { secret = decodeURIComponent(secret) } catch { /* a literal secret stands */ }
    }
    if (!clientId) {
      return { client: null, error: oidcError(c, 401, 'invalid_client', 'no client authentication (client_secret_basic or a public client_id) presented') }
    }
    const client = await getStore().getOidcClient(clientId)
    if (!client || client.status !== 'active') {
      return { client: null, error: oidcError(c, 401, 'invalid_client', 'unknown or disabled client') }
    }
    if (client.secretHash) {
      if (!secret || !(await verifyClientSecret(secret, client.secretHash))) {
        return { client: null, error: oidcError(c, 401, 'invalid_client', 'the client secret does not verify') }
      }
    }
    return { client, error: null }
  }

  // POST /op/token — the code exchange.
  op.post('/op/token', async (c) => {
    await ensureSeeded(c)
    const config = configFor(c)
    const store = getStore()

    const contentType = c.req.header('content-type') ?? ''
    if (!contentType.includes('application/x-www-form-urlencoded')) {
      return oidcError(c, 400, 'invalid_request', 'the token endpoint speaks application/x-www-form-urlencoded')
    }
    const form = new URLSearchParams(await c.req.raw.text())
    if (form.get('grant_type') !== 'authorization_code') {
      return oidcError(c, 400, 'unsupported_grant_type', 'authorization_code only')
    }

    const { client, error } = await authenticateClient(c, form)
    if (error) return error

    // The one-time code — consumed ATOMICALLY here, so whatever fails
    // below never gives the code a second life, and a replay always
    // loses (invalid_grant).
    const codeValue = form.get('code') ?? ''
    const code = codeValue ? await store.consumeOidcCode(codeValue) : null
    if (!code) return oidcError(c, 400, 'invalid_grant', 'the code is unknown, expired, or already used')
    if (code.clientId !== client!.clientId) {
      return oidcError(c, 400, 'invalid_grant', 'the code was not issued to this client')
    }
    if (code.redirectUri !== (form.get('redirect_uri') ?? '')) {
      return oidcError(c, 400, 'invalid_grant', 'redirect_uri does not match the authorization request')
    }
    const verifier = form.get('code_verifier') ?? ''
    if (!verifier || (await pkceS256(verifier)) !== code.codeChallenge) {
      return oidcError(c, 400, 'invalid_grant', 'the PKCE verifier does not match the challenge')
    }

    const user = await store.getUserById(code.userId)
    if (!user) return oidcError(c, 400, 'invalid_grant', 'the code’s account no longer exists')

    // The claims the client is allowed: profile+email per the scopes;
    // roles/groups/org ONLY per the client's claims policy (a client
    // with no policy never receives role claims). TODO.identity/03: the
    // role VALUES are the account's per-client assignment (no row = the
    // account's OP-side default set), bounded by the policy's optional
    // role allowlist — the OP never emits a role the client is not
    // configured to receive (auth/op/claims.ts).
    const scopes = code.scope.split(/\s+/).filter(Boolean)
    const nowSec = Math.floor(Date.now() / 1000)
    const claims: Record<string, unknown> = {
      iss: config.issuer,
      sub: user.id,
      aud: client!.clientId,
      exp: nowSec + config.idTokenTtlSec,
      iat: nowSec,
    }
    if (code.nonce) claims.nonce = code.nonce
    if (scopes.includes('profile')) claims.name = user.name
    if (scopes.includes('email')) {
      claims.email = user.email
      // The OP's registry IS the account list (invite-only,
      // admin-managed) — an account's email is vouched for by
      // construction.
      claims.email_verified = true
    }
    const assigned = await store.getOpClientRoles(user.id, client!.clientId)
    Object.assign(claims, roleClaimsForClient(assigned, user, client!.claimsPolicy))

    const key = await resolveOpSigningKey(runtimeEnv<EnvLike>(c))
    await ensureOpKeyRegistered(store, key)
    const idToken = await signOpIdToken(key, claims)

    const accessToken = opRandomToken()
    await store.createOidcAccessToken({
      token: accessToken,
      userId: user.id,
      clientId: client!.clientId,
      scope: code.scope,
      ttlMs: config.accessTokenTtlMs,
    })

    return c.json({
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: config.accessTokenTtlMs / 1000,
      id_token: idToken,
    })
  })

  // GET /op/userinfo — the access token's claims (the same policy the
  // ID token carried).
  op.get('/op/userinfo', async (c) => {
    const header = c.req.header('authorization') ?? ''
    const token = header.startsWith('Bearer ') ? header.slice(7).trim() : ''
    if (!token) {
      return c.json({ error: 'invalid_token', error_description: 'a Bearer access token is required' }, 401)
    }
    const store = getStore()
    const access = await store.getOidcAccessToken(token)
    if (!access) {
      return c.json({ error: 'invalid_token', error_description: 'the access token is unknown or expired' }, 401)
    }
    const user = await store.getUserById(access.userId)
    if (!user) return c.json({ error: 'invalid_token', error_description: 'the token’s account no longer exists' }, 401)

    const scopes = access.scope.split(/\s+/).filter(Boolean)
    const client = await store.getOidcClient(access.clientId)
    const claims: Record<string, unknown> = { sub: user.id }
    if (scopes.includes('profile')) claims.name = user.name
    if (scopes.includes('email')) {
      claims.email = user.email
      claims.email_verified = true
    }
    // The same shaping the ID token carried (TODO.identity/03): the
    // per-client assignment through the client's policy allowlist.
    const assigned = await store.getOpClientRoles(user.id, access.clientId)
    Object.assign(claims, roleClaimsForClient(assigned, user, client?.claimsPolicy ?? null))
    return c.json(claims)
  })

  // ── the client registry's admin surface ────────────────────────────
  // The same gate as the identity admin (routes/auth.ts): the platform
  // admin and the scheme operator manage relying parties. The secret is
  // write-only (hashed on receipt, never listed back); a GENERATED secret
  // (TODO.identity/07's registration wizard) is answered exactly once, in
  // the registration response, and only its hash survives. Every mutation
  // lands an auditEvents row (the registry's activity view).

  /** The registry mutations' audit trail (the same discipline as
   *  routes/op-accounts.ts: the audit never blocks the path). */
  async function audit(
    action: string,
    entityId: string,
    actor: { userId?: string; userName?: string },
    metadata: Record<string, unknown>,
  ): Promise<void> {
    try {
      const id = crypto.randomUUID()
      await getStore().putEntity('auditEvents', id, null, JSON.stringify({
        id,
        timestamp: new Date().toISOString(),
        standard_id: '',
        entity_type: 'client',
        entity_id: entityId,
        action,
        user_id: actor.userId,
        user_name: actor.userName,
        metadata,
      }))
    } catch (err) {
      console.error(`[op] client audit event ${action} failed to persist:`, (err as Error).message)
    }
  }

  async function requireAdmin(c: Context): Promise<{ user: AuthUserPayload | null; error: Response | null }> {
    const user = await sessionUser(c)
    if (!user) return { user: null, error: c.json({ error: 'authentication required' }, 401) }
    if (user.role !== 'admin' && user.role !== 'cs_admin') {
      return { user: null, error: c.json({ error: 'administrator role required' }, 403) }
    }
    return { user, error: null }
  }

  /** A registry row's PUBLIC view (never the secret hash). */
  function clientView(client: OidcClient) {
    return {
      clientId: client.clientId,
      name: client.name,
      redirectUris: client.redirectUris,
      claimsPolicy: client.claimsPolicy,
      confidential: !!client.secretHash,
      status: client.status,
      createdAt: client.createdAt,
      createdBy: client.createdBy,
    }
  }

  // GET /api/op/clients — the registry.
  op.get('/api/op/clients', async (c) => {
    await ensureSeeded(c)
    const gate = await requireAdmin(c)
    if (gate.error) return gate.error
    return c.json((await getStore().listOidcClients()).map(clientView))
  })

  // POST /api/op/clients — register/refresh a client. `secret` present
  // re-keys the client; ABSENT keeps the stored hash (or a public
  // client); `secret: null` (explicit) makes the client public.
  // `generate_secret: true` (TODO.identity/07's wizard) mints the secret
  // server-side instead: the plaintext rides the response ONCE, only its
  // hash is stored; the two secret postures never mix in one call.
  op.post('/api/op/clients', async (c) => {
    const gate = await requireAdmin(c)
    if (gate.error || !gate.user) return gate.error!
    const body = await c.req.json<{
      client_id?: string
      name?: string
      secret?: string | null
      generate_secret?: boolean
      redirect_uris?: string[]
      claims_policy?: { claims?: unknown; roles?: unknown } | null
    }>().catch(() => null)
    if (!body || typeof body.client_id !== 'string' || !body.client_id.trim()) {
      return c.json({ error: 'client_id is required' }, 400)
    }
    if (typeof body.name !== 'string' || !body.name.trim()) {
      return c.json({ error: 'name is required' }, 400)
    }
    if (!Array.isArray(body.redirect_uris) || body.redirect_uris.length === 0 || body.redirect_uris.some(u => typeof u !== 'string' || !u)) {
      return c.json({ error: 'redirect_uris must be a non-empty list of exact URIs' }, 400)
    }
    for (const uri of body.redirect_uris) {
      try { new URL(uri) } catch { return c.json({ error: `redirect_uris entry ${JSON.stringify(uri)} is not an absolute URI` }, 400) }
    }
    if (body.claims_policy != null && (!Array.isArray(body.claims_policy?.claims) || body.claims_policy.claims.some(x => typeof x !== 'string'))) {
      return c.json({ error: 'claims_policy.claims must be a list of claim names (roles, groups, org)' }, 400)
    }
    // TODO.identity/03 — the optional role allowlist: the closed set of
    // roles the ID token may carry for this client. A role outside the
    // platform vocabulary is a configuration bug, refused loudly (the OP
    // would never emit it anyway — better to fail at write time).
    const policyRoles = body.claims_policy?.roles
    if (policyRoles !== undefined) {
      if (!Array.isArray(policyRoles) || policyRoles.some(r => typeof r !== 'string')) {
        return c.json({ error: 'claims_policy.roles must be a list of role ids' }, 400)
      }
      const unknown = (policyRoles as string[]).filter(r => !(APP_ROLES as readonly string[]).includes(r))
      if (unknown.length) {
        return c.json({ error: `claims_policy.roles names unknown role(s): ${unknown.join(', ')}`, knownRoles: [...APP_ROLES] }, 400)
      }
    }
    if (body.generate_secret === true && typeof body.secret === 'string' && body.secret) {
      return c.json({ error: 'pass either secret or generate_secret, never both' }, 400)
    }

    const existing = await getStore().getOidcClient(body.client_id.trim())
    const generatedSecret = body.generate_secret === true ? opRandomToken() : null
    const secretHash = generatedSecret
      ? await hashClientSecret(generatedSecret)
      : typeof body.secret === 'string' && body.secret
        ? await hashClientSecret(body.secret)
        : body.secret === null
          ? null
          : existing?.secretHash ?? null
    const client = await getStore().upsertOidcClient({
      clientId: body.client_id.trim(),
      name: body.name.trim(),
      secretHash,
      redirectUris: body.redirect_uris,
      claimsPolicy: body.claims_policy
        ? {
            claims: body.claims_policy.claims as string[],
            ...(policyRoles ? { roles: policyRoles as string[] } : {}),
          }
        : null,
      createdBy: gate.user.email,
    })
    await audit(existing ? 'client.updated' : 'client.registered', client.clientId, { userId: gate.user.id, userName: gate.user.name }, {
      name: client.name,
      confidential: !!client.secretHash,
      rekeyed: !!generatedSecret || typeof body.secret === 'string',
      made_public: body.secret === null,
      redirect_uris: client.redirectUris.length,
      claims: client.claimsPolicy?.claims ?? [],
    })
    return c.json(
      generatedSecret ? { ...clientView(client), secret: generatedSecret } : clientView(client),
      existing ? 200 : 201,
    )
  })

  // POST /api/op/clients/:id/status — enable/disable. A disabled client
  // is refused at authorize AND token, its rows kept (the audit trail).
  op.post('/api/op/clients/:id/status', async (c) => {
    const gate = await requireAdmin(c)
    if (gate.error || !gate.user) return gate.error!
    const body = await c.req.json<{ status?: string }>().catch(() => null)
    if (!body || (body.status !== 'active' && body.status !== 'disabled')) {
      return c.json({ error: 'status must be "active" or "disabled"' }, 400)
    }
    const client = await getStore().setOidcClientStatus(c.req.param('id'), body.status)
    if (!client) return c.json({ error: 'not found' }, 404)
    await audit('client.status', client.clientId, { userId: gate.user.id, userName: gate.user.name }, { status: client.status })
    return c.json(clientView(client))
  })

  return op
}

function escapeHtml(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')
}
