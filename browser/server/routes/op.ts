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
//                                            ALSO the machine cone
//                                            (grant_type=client_credentials,
//                                            the device + service classes
//                                            only → the self-contained
//                                            machine JWT — auth/op/
//                                            device-clients.ts +
//                                            service-clients.ts; the
//                                            RP-facing wire is unchanged —
//                                            the contract golden holds) AND
//                                            the person-bearing exchanges
//                                            (the RFC 8693 token exchange:
//                                            the developer cone's personal
//                                            access tokens, TODO.identity-
//                                            features/08; the session
//                                            delegation's access-token
//                                            subject, TODO.ai-platform/03 —
//                                            auth/op/tokens.ts; the same
//                                            estate-internal posture, the
//                                            golden byte-identical);
//   GET  /op/userinfo                      — the access token's claims;
//   GET  /op/avatar/<account id>           — the PUBLIC avatar serve (no
//                                            session — the `picture`
//                                            claim's target, the
//                                            GitHub-avatars convention);
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
import { getStore, normalizePatScopes, type AuthUserPayload, type OidcClient, type OidcClientLaunch, type PatScope } from '@oimlsmart/platform-server/store'
import { getInstanceProfile } from '@oimlsmart/platform-server/profile'
import { opRequestOrigin, resolveOpConfig, type OpConfig } from '../auth/op/config'
import { ensureOpKeyRegistered, opJwks, opRandomToken, pkceS256, resolveOpSigningKey, signOpIdToken, type OpSigningKey } from '../auth/op/keys'
import { hashClientSecret, verifyClientSecret } from '../auth/op/secrets'
import { seedOidcClientsFromEnv } from '../auth/op/registry'
import { roleClaimsForContext, pictureClaimForClient } from '../auth/op/claims'
import { claimsContextFor } from '../auth/op/memberships'
import { avatarKeys, AVATAR_PUBLIC_CACHE, initialsAvatarSvg } from '../auth/op/avatars'
import { getBlobStore } from '../blobs'
import { validateLaunch, type LaunchInput } from '../auth/op/launch'
import {
  DEVICE_CLASS, deviceClassOf, deviceTokenClaims, validateDeviceBlock,
  type DeviceClientClaims, type OpClientPolicy,
} from '../auth/op/device-clients'
import {
  SERVICE_CLASS, narrowServiceScopes, serviceClassOf, serviceTokenClaims, validateServiceBlock,
  type OpServicePolicy, type ServiceClientClaims,
} from '../auth/op/service-clients'
import {
  auditPat, hashPat, narrowPatScopesParam, patExchangeBeatDue, patExpiryNoticeDue,
  patPlausible, patTokenClaims, resolvePatScopesForAccount,
  delegationScopesParam, delegationTokenClaims,
  DELEGATION_TOKEN_TYPE, PAT_EXCHANGE_GRANT, PAT_EXCHANGE_HEARTBEAT_MS, PAT_TOKEN_TYPE,
} from '../auth/op/tokens'
import { sendOpMail } from '../auth/op/mail'
import type { MailEnv } from '@oimlsmart/platform-server/mailer'
import { resolveRegistryOrg } from '../auth/org-registry'
import { APP_ROLES } from '@oimlsmart/platform-server/vocab'
import { SESSION_COOKIE, sessionUser } from '@oimlsmart/platform-server/session'
import { getCookie } from 'hono/cookie'

type EnvLike = Record<string, string | undefined>

/** The OAuth/OIDC error body (RFC 6749 §5.2), never a stack trace. */
function oidcError(c: Context, status: 400 | 401, error: string, description: string): Response {
  return c.json({ error, error_description: description }, status)
}

/** The oidc_keys self-registration gate (oimlsmart/identity#7): the
 *  DECLARED secret's key always registers (the fresh-deployment answer
 *  and the rotation ceremony's overlap poll ride it); a GENERATED
 *  development key registers ONLY in the dev posture — the issuer
 *  derived from the request origin (OP_ISSUER unset, config.ts's
 *  documented dev fallback; a deployment declares it, wrangler.toml).
 *  On the production identity service a mid-propagation secret read
 *  that falls to the dev generation must never mint + register an
 *  ephemeral per-isolate key into the keyset the RPs validate against:
 *  the table stays exactly as the declared deployments left it. */
function maySelfRegisterOpKey(key: OpSigningKey, config: OpConfig): boolean {
  return key.declared || config.issuerFromRequest
}

/** The gate's loud skip: the registration refused, the reason named. */
function warnDevKeyRegistrationSkipped(path: string, key: OpSigningKey): void {
  console.warn(
    `[op] ${path}: the resolved signing key is a GENERATED development key (kid ${key.kid}), but this deployment `
    + 'declares OP_ISSUER (the production posture) — refusing to register the ephemeral key into oidc_keys. '
    + 'The OP_SIGNING_KEY secret is undeclared or unreadable on this isolate (a secret put mid-propagation?); '
    + 'the registered table is served as it stands.',
  )
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
      claims_supported: ['iss', 'sub', 'aud', 'exp', 'iat', 'nonce', 'name', 'email', 'email_verified', 'picture', 'roles', 'groups', 'org', 'amr'],
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
  // overlap poll rides it) but is best-effort AND GATED
  // (maySelfRegisterOpKey, identity#7): a failed resolve serves the
  // table as it stands, a genuinely empty table answers an honest empty
  // JWKS, and a generated development key registers only in the dev
  // posture — never into the production keyset.
  op.get('/jwks.json', async (c) => {
    const store = getStore()
    try {
      const key = await resolveOpSigningKey(runtimeEnv<EnvLike>(c))
      if (maySelfRegisterOpKey(key, configFor(c))) {
        await ensureOpKeyRegistered(store, key)
      } else {
        warnDevKeyRegistrationSkipped('/jwks.json', key)
      }
    } catch (err) {
      console.warn('[op] jwks.json: the signing key is unavailable on this isolate; serving the registered table:', (err as Error).message)
    }
    return c.json(await opJwks(store))
  })

  // ── authorize ────────────────────────────────────────────────────

  /** The browser-facing refusal for a request we may NEVER redirect
   *  back (unknown client / unregistered redirect_uri): a plain page,
   *  honest about what happened. The audience is the RP developer.
   *
   *  The ISO-benchmark error-parity audit (smart's
   *  TODO.identity-features/11 item 9): this page is deliberately
   *  server-rendered and dependency-free (a refusal that must never
   *  depend on the frontend build answering), but it holds the house
   *  line — the sane viewport (pinch-zoom never disabled; ISO's error
   *  theme ships user-scalable=no), the color-scheme honesty, plain
   *  language, and a way back. */
  function authorizeRefusal(c: Context, title: string, detail: string): Response {
    return c.html(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark"><meta name="theme-color" content="#004996">
<title>${title} — OIML SMART Identity</title>
<style>
  body { font-family: ui-sans-serif, system-ui, sans-serif; background: #faf8f5; color: #0f172a; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; }
  main { max-width: 28rem; padding: 2rem; background: #fff; border: 1px solid #e2e8f0; border-radius: 0.75rem; }
  h1 { font-size: 1.125rem; margin: 0 0 0.5rem; } p { font-size: 0.875rem; color: #475569; margin: 0; }
  code { background: #f1f5f9; padding: 0 0.25rem; border-radius: 0.25rem; }
  p.home { margin-top: 1rem; } a { color: #004996; }
  @media (prefers-color-scheme: dark) { body { background: #0f172a; color: #fff; } main { background: #1e293b; border-color: #334155; } p { color: #94a3b8; } code { background: #0f172a; } a { color: #7cb3ff; } }
</style></head>
<body><main><h1 data-testid="op-authorize-error">${title}</h1><p>${detail}</p><p class="home"><a href="/" data-testid="op-authorize-error-home">Back to the sign-in page</a></p></main></body></html>`, 400)
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

    // 1b. The machine classes (the machine cone, auth/op/device-clients.ts
    //     + service-clients.ts) never enter a sign-in flow: they speak
    //     client_credentials at the token endpoint, nothing here. Refused
    //     IN PLACE — a machine client has no registered redirect URI, so
    //     no error redirect could ever be safe.
    const authorizeMachineClass = deviceClassOf(client.claimsPolicy) ? DEVICE_CLASS
      : serviceClassOf(client.claimsPolicy) ? SERVICE_CLASS
        : null
    if (authorizeMachineClass) {
      return authorizeRefusal(c, 'Cannot authorize this request', `The client <code>${escapeHtml(clientId)}</code> is a ${authorizeMachineClass} client — it authenticates with its secret at the token endpoint (client_credentials), never through a sign-in flow.`)
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
    // allowlist (TODO.identity/03, auth/op/claims.ts). TODO.identity/11:
    // resolved under the session's ACTIVE-ORG CONTEXT (the membership
    // model) — the page shows exactly the claims the token will carry.
    const store = getStore()
    const assigned = await store.getOpClientRoles(user.id, row!.clientId)
    const rawUser = await store.getUserById(user.id)
    const activeOrg = await store.getSessionActiveOrg(getCookie(c, SESSION_COOKIE) ?? '')
    const context = rawUser
      ? await claimsContextFor(store, rawUser, activeOrg)
      : { orgId: null, roles: [] as string[] }
    const roleClaims = client
      ? roleClaimsForContext(assigned, context, client.claimsPolicy)
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
    // TODO.identity/11: the code inherits the session's stamped
    // active-org context — the token endpoint emits the claims of the
    // context the account consented IN (re-judged against the live
    // membership at the exchange).
    const sessionToken = getCookie(c, SESSION_COOKIE)
    const contextOrg = sessionToken ? await getStore().getSessionActiveOrg(sessionToken) : null
    await getStore().createOidcCode({
      code,
      clientId: decided.clientId,
      redirectUri: decided.redirectUri,
      scope: decided.scope,
      nonce: decided.nonce,
      codeChallenge: decided.codeChallenge,
      userId: user.id,
      contextOrg,
      // TODO.identity-sso/02+03: the consenting session's authentication
      // provenance rides the code into the ID token (the session's truth
      // at the moment of consent — never recomputed later).
      amr: user.amr ?? null,
      ttlMs: config.codeTtlMs,
    })
    back.searchParams.set('code', code)
    return c.json({ redirect: back.toString() })
  })

  // ── token ────────────────────────────────────────────────────────

  /** The PRESENTED client credentials (never verified here): HTTP Basic
   *  (client_secret_basic) or the form's pair. The token endpoint reads
   *  the client id BEFORE the grant dispatch (the device class's cone is
   *  decided per client); the secret verify stays per path. */
  function presentedClientCredentials(c: Context, form: URLSearchParams): { clientId: string; secret: string | null; error: Response | null } {
    let clientId = form.get('client_id') ?? ''
    let secret = form.get('client_secret')
    const basic = c.req.header('authorization')
    if (basic?.startsWith('Basic ')) {
      let decoded: string
      try {
        decoded = atob(basic.slice(6))
      } catch {
        return { clientId: '', secret: null, error: oidcError(c, 401, 'invalid_client', 'the Authorization header is not valid Basic') }
      }
      const idx = decoded.indexOf(':')
      clientId = decodeURIComponent(decoded.slice(0, idx))
      secret = decoded.slice(idx + 1)
      // The RP sends the secret percent-encoded per RFC 6749 §2.3.1.
      try { secret = decodeURIComponent(secret) } catch { /* a literal secret stands */ }
    }
    return { clientId, secret, error: null }
  }

  /** The token endpoint's client authentication: HTTP Basic
   *  (client_secret_basic) or the form's client_secret (post). Public
   *  clients (no registered secret) authenticate by client_id + PKCE. */
  async function authenticateClient(c: Context, form: URLSearchParams): Promise<{ client: OidcClient | null; error: Response | null }> {
    const creds = presentedClientCredentials(c, form)
    if (creds.error) return { client: null, error: creds.error }
    const { clientId, secret } = creds
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

    /** The token endpoint's refusals land on the audit chain
     *  (TODO.identity-sso/01's token-anomaly signal): the OIDC error code
     *  and the client id WHEN one authenticated (never the code, the
     *  secret, or the verifier). The success is journaled as
     *  client.token_issued below. */
    async function refuseToken(status: 400 | 401, code: string, description: string, clientId?: string): Promise<Response> {
      await audit('client.token_refused', clientId ?? 'unauthenticated', {}, { error: code })
      return oidcError(c, status, code, description)
    }

    const contentType = c.req.header('content-type') ?? ''
    if (!contentType.includes('application/x-www-form-urlencoded')) {
      return oidcError(c, 400, 'invalid_request', 'the token endpoint speaks application/x-www-form-urlencoded')
    }
    const form = new URLSearchParams(await c.req.raw.text())
    const grantType = form.get('grant_type')

    // ── the machine cone: client_credentials, the machine classes ONLY ──
    // (auth/op/device-clients.ts + service-clients.ts). The OIDC wire the
    // RPs pin is UNCHANGED: a request naming no client, an unknown client,
    // or an APPLICATION client gets the pre-machine answer
    // (unsupported_grant_type / invalid_client exactly as before — the
    // contract gate's golden holds byte-identical). Only a registered,
    // active MACHINE client (the device class or the service class)
    // presenting its secret mints: a self-contained ES256 JWT access token
    // (the consumers validate it against the OP's JWKS — no call-back),
    // the class's claims exactly, never an ID token, never a user claim.
    if (grantType === 'client_credentials') {
      const creds = presentedClientCredentials(c, form)
      if (creds.error) {
        await audit('client.token_refused', 'unauthenticated', {}, { error: 'invalid_client' })
        return creds.error
      }
      if (!creds.clientId) {
        return refuseToken(400, 'unsupported_grant_type', 'authorization_code only')
      }
      const machineClient = await store.getOidcClient(creds.clientId)
      if (!machineClient || machineClient.status !== 'active') {
        await audit('client.token_refused', creds.clientId, {}, { error: 'invalid_client' })
        return oidcError(c, 401, 'invalid_client', 'unknown or disabled client')
      }
      const device = deviceClassOf(machineClient.claimsPolicy)
      const service = device ? null : serviceClassOf(machineClient.claimsPolicy)
      if (!device && !service) {
        return refuseToken(400, 'unsupported_grant_type', 'authorization_code only (client_credentials is the machine classes’ cone)', machineClient.clientId)
      }
      // The machine caller authenticates with its secret — the machine
      // classes are always confidential (the registry refuses a public
      // one at write), so a secret-less row here is a hand-edit: refused,
      // never guessed.
      const machineClass = device ? DEVICE_CLASS : SERVICE_CLASS
      if (!machineClient.secretHash || !creds.secret || !(await verifyClientSecret(creds.secret, machineClient.secretHash))) {
        await audit('client.token_refused', machineClient.clientId, {}, { error: 'invalid_client', class: machineClass })
        return oidcError(c, 401, 'invalid_client', 'the client secret does not verify')
      }
      // The service class's scope narrowing (RFC 6749 §4.4's scope
      // parameter): the request may name a SUBSET of the registered
      // allowlist — a scope beyond it refuses loudly (never a silent
      // drop, never a mint beyond the allowlist).
      let serviceScopes: string[] = []
      if (service) {
        const narrowed = narrowServiceScopes(service, form.get('scope'))
        if (narrowed.error) {
          return refuseToken(400, 'invalid_scope', narrowed.error, machineClient.clientId)
        }
        serviceScopes = narrowed.scopes
      }
      const machineKey = await resolveOpSigningKey(runtimeEnv<EnvLike>(c))
      // The first-use registration rides the SAME gate as the auth-code
      // path (identity#7): a generated development key never enters the
      // keyset on a declared-issuer deployment.
      if (maySelfRegisterOpKey(machineKey, config)) {
        await ensureOpKeyRegistered(store, machineKey)
      } else {
        warnDevKeyRegistrationSkipped('/op/token', machineKey)
      }
      const machineToken = await signOpIdToken(machineKey, device
        ? deviceTokenClaims(machineClient.clientId, device, config)
        : serviceTokenClaims(machineClient.clientId, service!, serviceScopes, config))
      // The issuance lands on the audit chain, naming the MACHINE CALLER
      // (never the token value, never the secret).
      await audit('client.token_issued', machineClient.clientId, {}, device
        ? { class: DEVICE_CLASS, device: device.id, org: device.org, instrument_model: device.instrument_model }
        : { class: SERVICE_CLASS, service: service!.id, org: service!.org, audience: service!.audience, scopes: serviceScopes })
      return c.json({
        access_token: machineToken,
        token_type: 'Bearer',
        expires_in: config.accessTokenTtlMs / 1000,
        // The effective scopes ride the service class's answer (RFC 6749
        // §5.1's explicitness — the caller reads what it actually got).
        ...(service ? { scope: serviceScopes.join(' ') } : {}),
      })
    }

    // ── the person-bearing exchanges: the RFC 8693 grant, two subject
    // classes (auth/op/tokens.ts). The DEVELOPER cone (TODO.identity-
    // features/08): the PAT subject — the subject_token IS the credential
    // (no client auth — the PAT names its account). The SESSION
    // DELEGATION (TODO.ai-platform/03): the OP's own access token as the
    // subject — the caller authenticates and the subject binds to the
    // client it was issued to. The device class's precedent holds for
    // both: the discovery document keeps advertising the RP contract
    // alone (the exchange grant is an estate-internal cone, not an RP
    // flow — the contract golden stays byte-identical), and the exchanged
    // token is the OP's ONE token shape (a self-contained ES256 JWT the
    // RPs validate against the JWKS, no call-back).
    if (grantType === PAT_EXCHANGE_GRANT) {
      const subjectTokenType = form.get('subject_token_type') ?? ''

      // ── the session delegation (TODO.ai-platform/03 — tokens.ts's
      // delegation section): the subject is the OP's OWN opaque access
      // token, minted to the AUTHENTICATED client by the sign-in's code
      // exchange. Where the PAT cone's subject IS the credential (no
      // client auth), the opaque subject is a bearer artifact — the
      // caller authenticates, and the exchange binds the subject to the
      // client it was ISSUED to (a service exchanges only its own
      // sign-ins' tokens, never another RP's). The answer carries the
      // actor claim (act.sub — the relying party's audit names the
      // acting service, never just the account).
      if (subjectTokenType === DELEGATION_TOKEN_TYPE) {
        const { client: actor, error: actorError } = await authenticateClient(c, form)
        if (actorError || !actor) {
          await auditPat('account.delegation_exchange_refused', 'unauthenticated', {}, { error: 'invalid_client' })
          return actorError ?? oidcError(c, 401, 'invalid_client', 'the delegation exchange requires client authentication')
        }
        // The refusal is ONE answer for the whole lattice (the PAT
        // cone's enrollment doctrine); the audit chain names the leg.
        // NEVER the token value.
        const refuseDelegation = async (reason: string, userId?: string): Promise<Response> => {
          await auditPat('account.delegation_exchange_refused', userId ?? 'unauthenticated', {}, { error: 'invalid_grant', reason, client: actor.clientId })
          return oidcError(c, 400, 'invalid_grant', 'the subject token is unknown, expired, or its account no longer stands')
        }
        const presentedDelegation = form.get('subject_token') ?? ''
        const subject = presentedDelegation ? await store.getOidcAccessToken(presentedDelegation) : null
        if (!subject) return refuseDelegation('unknown')
        if (subject.clientId !== actor.clientId) return refuseDelegation('foreign_token', subject.userId)
        // The account's standing (a deactivated or erased account's
        // sessions die with it) — the PAT cone's lattice leg.
        const subjectAccountRow = (await store.listUsers()).find(u => u.id === subject.userId)
        const subjectAccount = await store.getUserById(subject.userId)
        if (!subjectAccountRow || !subjectAccount || !subjectAccountRow.active || subjectAccountRow.provider === 'erased') {
          return refuseDelegation('account_standing', subject.userId)
        }
        // The sign-in's pinned org context, re-judged against the LIVE
        // membership (never a dead org's claims).
        const delegationContext = await claimsContextFor(store, subjectAccount, subject.contextOrg)
        // The scope is REQUIRED (the delegation names its narrowed
        // target) and re-judged per scope against the live standing —
        // the PAT cone's own machinery, verbatim.
        const delegationScope = delegationScopesParam(form.get('scope'))
        if (delegationScope.error || !delegationScope.scopes) {
          await auditPat('account.delegation_exchange_refused', subject.userId, {}, { error: 'invalid_scope', client: actor.clientId })
          return oidcError(c, 400, 'invalid_scope', delegationScope.error ?? 'the scope parameter is required')
        }
        const delegationGranted: PatScope[] = []
        const delegationRoles: Record<string, string[]> = {}
        const delegationDropped: string[] = []
        for (const scope of delegationScope.scopes) {
          const verdict = await resolvePatScopesForAccount(store, subjectAccount, delegationContext, [scope], runtimeEnv<EnvLike>(c))
          if (verdict.ok) {
            delegationGranted.push(scope)
            Object.assign(delegationRoles, verdict.serviceRoles)
          } else {
            delegationDropped.push(`${scope.service}:${scope.action}`)
          }
        }
        if (!delegationGranted.length) return refuseDelegation('scope_standing', subject.userId)
        const delegationKey = await resolveOpSigningKey(runtimeEnv<EnvLike>(c))
        // The first-use registration rides the SAME gate as the other
        // grants (identity#7).
        if (maySelfRegisterOpKey(delegationKey, config)) {
          await ensureOpKeyRegistered(store, delegationKey)
        } else {
          warnDevKeyRegistrationSkipped('/op/token', delegationKey)
        }
        const delegated = await signOpIdToken(delegationKey, delegationTokenClaims(subjectAccount, delegationContext, delegationGranted, delegationRoles, config, actor.clientId))
        // The exchange lands on the audit chain EVERY time (the
        // delegation's cadence is per-session — the PAT cone's throttled
        // heartbeat never applies), the dropped narrowing named.
        await auditPat('account.delegation_exchange', subject.userId, {}, {
          client: actor.clientId,
          scopes: delegationGranted.map(s => `${s.service}:${s.action}`),
          ...(delegationDropped.length ? { dropped: delegationDropped } : {}),
        })
        return c.json({
          access_token: delegated,
          issued_token_type: 'urn:ietf:params:oauth:token-type:access_token',
          token_type: 'Bearer',
          expires_in: config.accessTokenTtlMs / 1000,
          scope: delegationGranted.map(s => `${s.service}:${s.action}`).join(' '),
        })
      }

      if (subjectTokenType !== PAT_TOKEN_TYPE) {
        await auditPat('account.pat_exchange_refused', 'unauthenticated', {}, { error: 'invalid_request' })
        return oidcError(c, 400, 'invalid_request', `the token-exchange grant speaks subject_token_type ${PAT_TOKEN_TYPE} or ${DELEGATION_TOKEN_TYPE} only`)
      }
      const presented = form.get('subject_token') ?? ''
      const pat = patPlausible(presented) ? await store.findPersonalAccessTokenByHash(await hashPat(presented)) : null
      // The refusal is ONE answer for the whole lattice — unknown /
      // expired / revoked / wrong-standing are deliberately
      // indistinguishable on the wire (the enrollment doctrine); the
      // audit chain names the leg. NEVER the token value.
      const refuseExchange = async (reason: string, patId?: string, userId?: string): Promise<Response> => {
        await auditPat('account.pat_exchange_refused', userId ?? 'unauthenticated', {}, { error: 'invalid_grant', reason, ...(patId ? { pat: patId } : {}) })
        return oidcError(c, 400, 'invalid_grant', 'the subject token is unknown, expired, revoked, or its account no longer stands')
      }
      if (!pat) return refuseExchange('unknown')
      if (pat.revokedAt) return refuseExchange('revoked', pat.id, pat.userId)
      if (new Date(pat.expiresAt).getTime() <= Date.now()) return refuseExchange('expired', pat.id, pat.userId)
      // The account's standing (a deactivated or erased account's tokens
      // die with it): the registry row carries the active flag.
      const accountRow = (await store.listUsers()).find(u => u.id === pat.userId)
      const account = await store.getUserById(pat.userId)
      if (!accountRow || !account || !accountRow.active || accountRow.provider === 'erased') {
        return refuseExchange('account_standing', pat.id, pat.userId)
      }
      // The pinned org context, re-judged against the LIVE membership
      // (the token endpoint's own doctrine: a membership disabled since
      // the mint falls back to the primary context, never a dead org's
      // claims).
      const context = await claimsContextFor(store, account, pat.orgContext)
      const pinned = normalizePatScopes(pat.scopes) ?? []
      // The optional per-exchange narrowing (RFC 8693's scope parameter:
      // a subset of the pinned set, never wider).
      const narrowing = narrowPatScopesParam(form.get('scope'), pinned)
      if (narrowing.error) {
        await auditPat('account.pat_exchange_refused', pat.userId, {}, { error: 'invalid_scope', pat: pat.id })
        return oidcError(c, 400, 'invalid_scope', narrowing.error)
      }
      // The standing re-judgment, per scope: what the account lost since
      // the mint falls away (the audit names the dropped scopes); a
      // token whose WHOLE set fell away refuses.
      const granted: PatScope[] = []
      const serviceRoles: Record<string, string[]> = {}
      const dropped: string[] = []
      for (const scope of narrowing.scopes ?? pinned) {
        const verdict = await resolvePatScopesForAccount(store, account, context, [scope], runtimeEnv<EnvLike>(c))
        if (verdict.ok) {
          granted.push(scope)
          Object.assign(serviceRoles, verdict.serviceRoles)
        } else {
          dropped.push(`${scope.service}:${scope.action}`)
        }
      }
      if (!granted.length) {
        return refuseExchange('scope_standing', pat.id, pat.userId)
      }
      const patKey = await resolveOpSigningKey(runtimeEnv<EnvLike>(c))
      // The first-use registration rides the SAME gate as the other
      // grants (identity#7).
      if (maySelfRegisterOpKey(patKey, config)) {
        await ensureOpKeyRegistered(store, patKey)
      } else {
        warnDevKeyRegistrationSkipped('/op/token', patKey)
      }
      const exchanged = await signOpIdToken(patKey, patTokenClaims(pat, account, context, granted, serviceRoles, config))
      // The throttled heartbeat (never a per-request write): the use
      // stamp + the audit beat share the one-hour window.
      const nowMs = Date.now()
      const nowIso = new Date(nowMs).toISOString()
      const useStale = !pat.lastUsedAt || nowMs - new Date(pat.lastUsedAt).getTime() >= PAT_EXCHANGE_HEARTBEAT_MS
      const beatDue = patExchangeBeatDue(pat, nowMs)
      if (useStale || beatDue) {
        await store.stampPersonalAccessTokenUse(pat.id, { usedAt: nowIso, ...(beatDue ? { auditAt: nowIso } : {}) })
      }
      if (beatDue) {
        await auditPat('account.pat_exchange', pat.userId, {}, {
          pat: pat.id,
          name: pat.name,
          scopes: granted.map(s => `${s.service}:${s.action}`),
          ...(dropped.length ? { dropped } : {}),
        })
      } else if (dropped.length) {
        // A narrowing between beats still lands on the chain.
        await auditPat('account.pat_exchange_narrowed', pat.userId, {}, { pat: pat.id, name: pat.name, dropped })
      }
      // The expiry-soon notice rides the use (the lazy sweep — no
      // scheduler on this deployment shape): the in-use token's owner
      // learns while the automation still works, ONCE per token. The
      // one-shot mark lands when the send resolved (or honestly logged —
      // the console posture); a transient provider failure retries on
      // the next exchange.
      if (patExpiryNoticeDue(pat, nowMs)) {
        const mail = await sendOpMail(runtimeEnv<MailEnv>(c), {
          to: account.email,
          template: 'pat_expiring',
          issuer: config.issuer,
          params: { name: account.name, tokenName: pat.name, expires: pat.expiresAt.slice(0, 10) },
        })
        if (mail.sent || mail.posture === 'console') {
          await store.stampPersonalAccessTokenUse(pat.id, { usedAt: nowIso, expiryNotifiedAt: nowIso })
        }
      }
      return c.json({
        access_token: exchanged,
        issued_token_type: 'urn:ietf:params:oauth:token-type:access_token',
        token_type: 'Bearer',
        expires_in: config.accessTokenTtlMs / 1000,
        scope: granted.map(s => `${s.service}:${s.action}`).join(' '),
      })
    }

    if (grantType !== 'authorization_code') {
      return refuseToken(400, 'unsupported_grant_type', 'authorization_code only', form.get('client_id') ?? undefined)
    }

    const { client, error } = await authenticateClient(c, form)
    if (error) {
      await audit('client.token_refused', form.get('client_id')?.trim() || 'unauthenticated', {}, { error: 'invalid_client' })
      return error
    }

    // A machine client never redeems an authorization code (the machine
    // classes speak client_credentials only) — refused BEFORE the one-time
    // code is consumed, so a confused-deputy mixup never burns another
    // flow's code.
    const redeemMachineClass = deviceClassOf(client!.claimsPolicy) ? DEVICE_CLASS
      : serviceClassOf(client!.claimsPolicy) ? SERVICE_CLASS
        : null
    if (redeemMachineClass) {
      return refuseToken(400, 'unsupported_grant_type', `the ${redeemMachineClass} class speaks client_credentials only — never an authorization code`, client!.clientId)
    }

    // The one-time code — consumed ATOMICALLY here, so whatever fails
    // below never gives the code a second life, and a replay always
    // loses (invalid_grant).
    const codeValue = form.get('code') ?? ''
    const code = codeValue ? await store.consumeOidcCode(codeValue) : null
    if (!code) return refuseToken(400, 'invalid_grant', 'the code is unknown, expired, or already used', client!.clientId)
    if (code.clientId !== client!.clientId) {
      return refuseToken(400, 'invalid_grant', 'the code was not issued to this client', client!.clientId)
    }
    if (code.redirectUri !== (form.get('redirect_uri') ?? '')) {
      return refuseToken(400, 'invalid_grant', 'redirect_uri does not match the authorization request', client!.clientId)
    }
    const verifier = form.get('code_verifier') ?? ''
    if (!verifier || (await pkceS256(verifier)) !== code.codeChallenge) {
      return refuseToken(400, 'invalid_grant', 'the PKCE verifier does not match the challenge', client!.clientId)
    }

    const user = await store.getUserById(code.userId)
    if (!user) return refuseToken(400, 'invalid_grant', 'the code’s account no longer exists', client!.clientId)

    // The claims the client is allowed: profile+email per the scopes;
    // roles/groups/org ONLY per the client's claims policy (a client
    // with no policy never receives role claims); the picture claim
    // follows the same per-client privilege (below). TODO.identity/03:
    // the role VALUES are the account's per-client assignment (no row =
    // the account's OP-side default set), bounded by the policy's
    // optional role allowlist — the OP never emits a role the client is
    // not configured to receive (auth/op/claims.ts). TODO.identity/11: the
    // default set is resolved under the code's stamped ORG CONTEXT (the
    // consent's active org, re-judged against the live membership — a
    // membership disabled mid-flow falls back to the primary context,
    // never a dead org's claims).
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
    const context = await claimsContextFor(store, user, code.contextOrg ?? null)
    Object.assign(claims, roleClaimsForContext(assigned, context, client!.claimsPolicy))
    // The picture family (auth/op/claims.ts): the public avatar route's
    // absolute URL, ONLY when the policy names the family AND the account
    // has an uploaded avatar — absent otherwise, never a broken URL.
    const picture = pictureClaimForClient(user, client!.claimsPolicy, config.issuer)
    if (picture) claims.picture = picture
    // TODO.identity-sso/02+03: the authorizing authentication's amr
    // provenance (the consenting session's, carried by the code) — the
    // RP-visible claim matches the session's truth. Absent when no
    // OP-side credential event was recorded (an upstream sign-in).
    if (code.amr?.length) claims.amr = code.amr

    const key = await resolveOpSigningKey(runtimeEnv<EnvLike>(c))
    // The first-use registration rides the SAME gate as the JWKS route
    // (identity#7): a generated development key never enters the keyset
    // on a declared-issuer deployment. Signing itself still proceeds
    // (the documented dev posture — the loud warning fired at resolve).
    if (maySelfRegisterOpKey(key, config)) {
      await ensureOpKeyRegistered(store, key)
    } else {
      warnDevKeyRegistrationSkipped('/op/token', key)
    }
    const idToken = await signOpIdToken(key, claims)

    const accessToken = opRandomToken()
    await store.createOidcAccessToken({
      token: accessToken,
      userId: user.id,
      clientId: client!.clientId,
      scope: code.scope,
      contextOrg: code.contextOrg ?? null,
      // The same provenance rides the access token — userinfo answers
      // the amr the ID token carried.
      amr: code.amr,
      ttlMs: config.accessTokenTtlMs,
    })

    // The issuance lands on the audit chain (TODO.identity-sso/01's
    // per-client activity + the anomaly baseline): the client, the
    // account, the scope. NEVER the token values.
    await audit('client.token_issued', client!.clientId, {}, { account: user.id, scope: code.scope })

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
    // per-client assignment through the client's policy allowlist, under
    // the granting code's org context (TODO.identity/11).
    const assigned = await store.getOpClientRoles(user.id, access.clientId)
    const context = await claimsContextFor(store, user, access.contextOrg ?? null)
    Object.assign(claims, roleClaimsForContext(assigned, context, client?.claimsPolicy ?? null))
    const picture = pictureClaimForClient(user, client?.claimsPolicy ?? null, configFor(c).issuer)
    if (picture) claims.picture = picture
    // TODO.identity-sso/02+03: userinfo answers the same amr the ID
    // token carried (the authorizing authentication's provenance).
    if (access.amr?.length) claims.amr = access.amr
    return c.json(claims)
  })

  // ── the public avatar serve ────────────────────────────────────────

  // GET /op/avatar/:id — the PUBLIC read side of the account's avatar
  // (the GitHub-avatars pattern: an avatar is semi-public by convention,
  // so the RP's cross-origin <img> needs no session). This is the URL
  // the `picture` claim names. The doctrine (auth/op/avatars.ts):
  //
  //   - the account resolves FIRST: an unknown or ERASED account answers
  //     the plain 404 (the erasure's promise is stronger than a stray
  //     surviving blob — the account is gone, nothing serves);
  //   - the stored upload serves with its real content type, nosniff,
  //     and a short PUBLIC cache;
  //   - a KNOWN account without an upload (or a deployment with no blob
  //     store bound) answers the GENERATED-INITIALS fallback — the
  //     console's own fallback, served — so the <img> never breaks;
  //   - NEVER an error page: every answer is an image or a small JSON.
  op.get('/op/avatar/:id', async (c) => {
    const userId = c.req.param('id')
    const user = await getStore().getUserById(userId)
    if (!user || user.provider === 'erased') {
      return c.json({ error: 'not found' }, 404)
    }
    const blobs = getBlobStore()
    if (blobs) {
      for (const key of avatarKeys(userId)) {
        const obj = await blobs.get(key)
        if (!obj) continue
        c.header('content-type', obj.contentType ?? 'application/octet-stream')
        c.header('content-length', String(obj.size))
        c.header('x-content-type-options', 'nosniff')
        c.header('cache-control', AVATAR_PUBLIC_CACHE)
        return c.body(obj.data)
      }
    }
    c.header('content-type', 'image/svg+xml')
    // The served SVG is server-generated and inert; the deny-all CSP is
    // the belt-and-suspenders for direct navigation (an image channel
    // never becomes a script channel — the avatar doctrine's rule).
    c.header('content-security-policy', "default-src 'none'")
    c.header('x-content-type-options', 'nosniff')
    c.header('cache-control', AVATAR_PUBLIC_CACHE)
    return c.body(initialsAvatarSvg(user.name))
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

  /** A registry row's PUBLIC view (never the secret hash). The machine
   *  classes (the machine cone) read honestly: `class` + the bound
   *  device/service block derive from the stored policy. */
  function clientView(client: OidcClient) {
    const device = deviceClassOf(client.claimsPolicy)
    const service = device ? null : serviceClassOf(client.claimsPolicy)
    return {
      clientId: client.clientId,
      name: client.name,
      class: device ? DEVICE_CLASS : service ? SERVICE_CLASS : 'application',
      device,
      service,
      redirectUris: client.redirectUris,
      claimsPolicy: client.claimsPolicy,
      // The SSO home's launch card (null = the client is not on the
      // launcher — the machine classes NEVER are).
      launch: client.launch,
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
  //
  // THE MACHINE CLASSES (the machine cone, auth/op/device-clients.ts +
  // service-clients.ts): `class: "device"` registers a NON-HUMAN,
  // per-device client binding `device: { id, org, instrument_model }`;
  // `class: "service"` registers a NON-HUMAN, per-service-account client
  // binding `service: { id, org, audience, scopes }`. Both:
  // client_credentials only, always confidential, no redirect_uris, no
  // launch card, no user claims; the org must resolve on the organization
  // registry (the token's org claim names an org this OP knows). The
  // class is FIXED AT REGISTRATION: an edit never declares a class the
  // stored row does not carry (an application row refuses a machine
  // `class`; a machine row's edit omits `class` and keeps its class).
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
      launch?: LaunchInput | null
      class?: unknown
      device?: unknown
      service?: unknown
    }>().catch(() => null)
    if (!body || typeof body.client_id !== 'string' || !body.client_id.trim()) {
      return c.json({ error: 'client_id is required' }, 400)
    }
    if (typeof body.name !== 'string' || !body.name.trim()) {
      return c.json({ error: 'name is required' }, 400)
    }

    // The class resolution (fixed at registration): the stored row's
    // class wins on an edit; a create takes the body's declaration.
    const existing = await getStore().getOidcClient(body.client_id.trim())
    const existingDevice = deviceClassOf(existing?.claimsPolicy ?? null)
    const existingService = existingDevice ? null : serviceClassOf(existing?.claimsPolicy ?? null)
    if (body.class !== undefined && body.class !== DEVICE_CLASS && body.class !== SERVICE_CLASS) {
      return c.json({ error: `class must be "${DEVICE_CLASS}" or "${SERVICE_CLASS}" when declared (absent = the application class)` }, 400)
    }
    const declaredClass = body.class as typeof DEVICE_CLASS | typeof SERVICE_CLASS | undefined
    const existingClass = existingDevice ? DEVICE_CLASS : existingService ? SERVICE_CLASS : null
    if (existing && declaredClass !== undefined && declaredClass !== existingClass) {
      return c.json({ error: `the client class is fixed at registration — ${existing.clientId} is the ${existingClass ?? 'application'} class; register a fresh client for the ${declaredClass}` }, 400)
    }
    const isDevice = existing ? existingDevice !== null : declaredClass === DEVICE_CLASS
    const isService = existing ? existingService !== null : declaredClass === SERVICE_CLASS

    // THE MACHINE CLASSES' shape (the registry enforces it at write — the
    // token endpoint then trusts the class).
    let deviceBlock: DeviceClientClaims | null = null
    let serviceBlock: ServiceClientClaims | null = null
    if (isDevice) {
      if (body.device !== undefined) {
        const { device, error } = validateDeviceBlock(body.device)
        if (error) return c.json({ error }, 400)
        deviceBlock = device
      } else {
        deviceBlock = existingDevice // the edit keeps the stored binding
      }
      if (!deviceBlock) {
        return c.json({ error: 'the device class binds a device: device: { id, org, instrument_model } is required' }, 400)
      }
      // The org claim the twin endpoints consume names an org this OP
      // actually knows — resolved against the organization registry.
      if (!(await resolveRegistryOrg(getStore(), deviceBlock.org))) {
        return c.json({ error: `device.org '${deviceBlock.org}' is not on the organization registry — the device token's org claim must name an org this OP knows` }, 400)
      }
      if (body.redirect_uris !== undefined && (!Array.isArray(body.redirect_uris) || body.redirect_uris.length > 0)) {
        return c.json({ error: 'the device class carries no redirect_uris (nothing redirects — client_credentials only)' }, 400)
      }
      if (body.launch) {
        return c.json({ error: 'a device client never joins the SSO home (the launcher is a human surface) — no launch card' }, 400)
      }
      const deviceClaims = body.claims_policy?.claims
      if ((Array.isArray(deviceClaims) && deviceClaims.length > 0) || body.claims_policy?.roles !== undefined) {
        return c.json({ error: 'the device class’s claims are fixed by the class (the device id, its org, its instrument model) — the policy never carries user claims' }, 400)
      }
      if (body.secret === null) {
        return c.json({ error: 'a device client is confidential — it never goes public (the secret is the device’s credential)' }, 400)
      }
      if (!existing && body.generate_secret !== true && !(typeof body.secret === 'string' && body.secret)) {
        return c.json({ error: 'a device client is confidential — pass generate_secret (the server mints it, shown once) or secret' }, 400)
      }
      if (body.service !== undefined) {
        return c.json({ error: `the service block rides class "${SERVICE_CLASS}" — declare the class, or drop the block` }, 400)
      }
    } else if (isService) {
      if (body.service !== undefined) {
        const { service, error } = validateServiceBlock(body.service)
        if (error) return c.json({ error }, 400)
        serviceBlock = service
      } else {
        serviceBlock = existingService // the edit keeps the stored binding
      }
      if (!serviceBlock) {
        return c.json({ error: 'the service class binds a service account: service: { id, org, audience, scopes } is required' }, 400)
      }
      // The org claim the called service consumes names an org this OP
      // actually knows — resolved against the organization registry.
      if (!(await resolveRegistryOrg(getStore(), serviceBlock.org))) {
        return c.json({ error: `service.org '${serviceBlock.org}' is not on the organization registry — the service token's org claim must name an org this OP knows` }, 400)
      }
      if (body.redirect_uris !== undefined && (!Array.isArray(body.redirect_uris) || body.redirect_uris.length > 0)) {
        return c.json({ error: 'the service class carries no redirect_uris (nothing redirects — client_credentials only)' }, 400)
      }
      if (body.launch) {
        return c.json({ error: 'a service client never joins the SSO home (the launcher is a human surface) — no launch card' }, 400)
      }
      const serviceClaims = body.claims_policy?.claims
      if ((Array.isArray(serviceClaims) && serviceClaims.length > 0) || body.claims_policy?.roles !== undefined) {
        return c.json({ error: 'the service class’s claims are fixed by the class (the service id, its org, the audience, the scope allowlist) — the policy never carries user claims' }, 400)
      }
      if (body.secret === null) {
        return c.json({ error: 'a service client is confidential — it never goes public (the secret is the service account’s credential)' }, 400)
      }
      if (!existing && body.generate_secret !== true && !(typeof body.secret === 'string' && body.secret)) {
        return c.json({ error: 'a service client is confidential — pass generate_secret (the server mints it, shown once) or secret' }, 400)
      }
      if (body.device !== undefined) {
        return c.json({ error: `the device block rides class "${DEVICE_CLASS}" — declare the class, or drop the block` }, 400)
      }
    } else {
      // THE APPLICATION CLASS (the relying-party posture — unchanged).
      if (body.device !== undefined || body.service !== undefined) {
        return c.json({ error: 'the device/service blocks ride their machine classes — declare the class, or drop the block' }, 400)
      }
      if (!Array.isArray(body.redirect_uris) || body.redirect_uris.length === 0 || body.redirect_uris.some(u => typeof u !== 'string' || !u)) {
        return c.json({ error: 'redirect_uris must be a non-empty list of exact URIs' }, 400)
      }
      for (const uri of body.redirect_uris) {
        try { new URL(uri) } catch { return c.json({ error: `redirect_uris entry ${JSON.stringify(uri)} is not an absolute URI` }, 400) }
      }
    }
    if (body.claims_policy != null && (!Array.isArray(body.claims_policy?.claims) || body.claims_policy.claims.some(x => typeof x !== 'string'))) {
      return c.json({ error: 'claims_policy.claims must be a list of claim names (roles, groups, org, picture)' }, 400)
    }
    // TODO.identity/03 — the optional role allowlist: the closed set of
    // roles the ID token may carry for this client. A role outside the
    // platform vocabulary is a configuration bug, refused loudly (the OP
    // would never emit it anyway — better to fail at write time). The
    // machine classes never name it (the class checks above already
    // refused).
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
    // The SSO home's launch card (OPTIONAL): absent leaves the stored
    // metadata untouched (the protocol fields edit never disturbs the
    // launcher); null takes the client OFF the launcher; an object sets
    // the card, validated like the seed (auth/op/launch.ts). The machine
    // classes refused the card above.
    let launchWrite: OidcClientLaunch | null | undefined = undefined
    if (body.launch === null) launchWrite = null
    else if (body.launch !== undefined) {
      const { launch, error } = validateLaunch(body.launch)
      if (error) return c.json({ error }, 400)
      launchWrite = launch
    }

    const generatedSecret = body.generate_secret === true ? opRandomToken() : null
    const secretHash = generatedSecret
      ? await hashClientSecret(generatedSecret)
      : typeof body.secret === 'string' && body.secret
        ? await hashClientSecret(body.secret)
        : body.secret === null
          ? null
          : existing?.secretHash ?? null
    // The class marker + the machine block ride the policy JSON (the store
    // seam round-trips it opaquely — the data-level extension).
    const policy: OpClientPolicy | OpServicePolicy | null = isDevice
      ? { claims: [], class: DEVICE_CLASS, device: deviceBlock! }
      : isService
        ? { claims: [], class: SERVICE_CLASS, service: serviceBlock! }
        : body.claims_policy
          ? {
              claims: body.claims_policy.claims as string[],
              ...(policyRoles ? { roles: policyRoles as string[] } : {}),
            }
          : null
    const client = await getStore().upsertOidcClient({
      clientId: body.client_id.trim(),
      name: body.name.trim(),
      secretHash,
      redirectUris: isDevice || isService ? [] : body.redirect_uris!,
      claimsPolicy: policy,
      createdBy: gate.user.email,
    })
    // The launch card rides its own write (the upsert never touches the
    // launch columns — a protocol-fields edit keeps the stored card).
    const settled = launchWrite === undefined
      ? client
      : (await getStore().setOidcClientLaunch(client.clientId, launchWrite))!
    await audit(existing ? 'client.updated' : 'client.registered', client.clientId, { userId: gate.user.id, userName: gate.user.name }, {
      name: client.name,
      class: isDevice ? DEVICE_CLASS : isService ? SERVICE_CLASS : 'application',
      // The machine act names the bound caller (register / rotate-secret /
      // revoke all read off the same chain).
      ...(isDevice && deviceBlock ? { device: deviceBlock } : {}),
      ...(isService && serviceBlock ? { service: serviceBlock } : {}),
      confidential: !!client.secretHash,
      rekeyed: !!generatedSecret || typeof body.secret === 'string',
      made_public: body.secret === null,
      redirect_uris: client.redirectUris.length,
      claims: client.claimsPolicy?.claims ?? [],
      // The launch write's record (undefined = untouched, null = off
      // the launcher, object = the card as written).
      ...(launchWrite !== undefined ? { launch: launchWrite } : {}),
    })
    return c.json(
      generatedSecret ? { ...clientView(settled), secret: generatedSecret } : clientView(settled),
      existing ? 200 : 201,
    )
  })

  // POST /api/op/clients/:id/status — enable/disable. A disabled client
  // is refused at authorize AND token, its rows kept (the audit trail).
  // On a machine client the disable IS the revocation (the machine cone
  // has no other lifecycle act — the chain names the class honestly).
  op.post('/api/op/clients/:id/status', async (c) => {
    const gate = await requireAdmin(c)
    if (gate.error || !gate.user) return gate.error!
    const body = await c.req.json<{ status?: string }>().catch(() => null)
    if (!body || (body.status !== 'active' && body.status !== 'disabled')) {
      return c.json({ error: 'status must be "active" or "disabled"' }, 400)
    }
    const client = await getStore().setOidcClientStatus(c.req.param('id'), body.status)
    if (!client) return c.json({ error: 'not found' }, 404)
    const device = deviceClassOf(client.claimsPolicy)
    const service = device ? null : serviceClassOf(client.claimsPolicy)
    await audit('client.status', client.clientId, { userId: gate.user.id, userName: gate.user.name }, {
      status: client.status,
      class: device ? DEVICE_CLASS : service ? SERVICE_CLASS : 'application',
      ...(device ? { device: device.id, org: device.org } : {}),
      ...(service ? { service: service.id, org: service.org, audience: service.audience } : {}),
    })
    return c.json(clientView(client))
  })

  return op
}

function escapeHtml(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')
}
