// ═══════════════════════════════════════════════════════════════════
// The OP's upstream sign-in providers (TODO.identity/08) — the identity
// instance links + accepts GitHub, Google, Apple, Microsoft Entra and
// generic OIDC providers from the REGISTRY (identity_providers — adding
// a provider is a row, never a code fork).
//
// The surface (all gated to the identity deployment profile — any other
// profile answers 404, the op.ts posture):
//
//   GET  /api/op/providers/public        — the login page's buttons
//                                          (enabled rows, public fields
//                                          only — never the secret ref);
//   GET  /op/upstream/:id/signin         — start the SIGN-IN flow
//                                          (?redirect= carried through);
//   GET  /op/upstream/:id/link           — start the LINK flow, bound to
//                                          the current session's account;
//   GET|POST /op/upstream/:id/callback   — the upstream return (POST is
//                                          Apple's form_post);
//   GET/POST/DELETE /api/op/providers[…] — the registry's admin surface
//                                          (admin/cs_admin; the full
//                                          console UI is TODO.identity/07's);
//   GET  /api/op/account/links           — the account's linked identities;
//   DELETE /api/op/account/links/:id     — the unlink action.
//
// THE MATCH RULE (the program's invariant): an upstream sign-in resolves
// by (provider, provider_account_id/sub) against identity_links — NEVER
// by email alone. An unlinked identity gets the honest refusal
// (/?error=upstream_not_linked) — NO account, NO session.
//
// The flow state is STATELESS + signed (auth/upstream/state.ts — the
// GitHub flow's lesson: nothing rides a per-process Map, so a sibling
// Worker isolate verifies the callback exactly).
//
// WORKER-SAFE: WebCrypto + the store seam only, no node built-ins.
// ═══════════════════════════════════════════════════════════════════

import { Hono, type Context, type MiddlewareHandler } from 'hono'
import { setCookie } from 'hono/cookie'
import { env as runtimeEnv } from 'hono/adapter'
import { getStore, type AuthUserPayload, type IdentityProvider } from '@oimlsmart/platform-server/store'
import { getInstanceProfile } from '@oimlsmart/platform-server/profile'
import { opRequestOrigin } from '../auth/op/config'
import { clientInfo } from '@oimlsmart/platform-server/client-info'
import { resolveOpSigningKey } from '../auth/op/keys'
import { sendOpMail } from '../auth/op/mail'
import type { MailEnv } from '@oimlsmart/platform-server/mailer'
import { roleHome } from '@oimlsmart/platform-server/vocab'
import {
  isAppleProvider,
  providerScopes,
  resolveProviderSecret,
  seedIdentityProvidersFromEnv,
  validateProviderInput,
} from '../auth/upstream/registry'
import { safeLocalRedirect, signUpstreamState, verifyUpstreamState, type UpstreamStatePayload } from '../auth/upstream/state'
import {
  buildUpstreamAuthorizationUrl,
  discoverIssuer,
  exchangeUpstreamCode,
  generatePkce,
  randomToken,
  validateIdToken,
  OidcError,
} from '../auth/upstream/oidc-client'
import { generateAppleClientSecret, resolveAppleSecretConfig } from '../auth/upstream/apple'
import { buildGitHubAuthorizeUrl, fetchGitHubIdentity, gitHubEndpoints, GitHubUpstreamError } from '../auth/upstream/github-client'
import { SESSION_COOKIE, sessionCookieOpts, sessionUser } from '@oimlsmart/platform-server/session'

type EnvLike = Record<string, string | undefined>

/** The resolved upstream identity (either kind's read path). */
interface UpstreamIdentity {
  /** The link row's provider_account_id: GitHub's numeric profile id,
   *  the OIDC ID token's `sub`. */
  accountId: string
  /** The display handle (the login, the email) — the refusal/audit copy. */
  handle: string
  /** The name claim (OIDC) / the profile name (GitHub), when shared. */
  name?: string
}

export function createOpUpstreamRouter(): Hono {
  const router = new Hono()

  // ── the profile gate (the op.ts posture: one build, the profile
  //    decides) ─────────────────────────────────────────────────────
  const profileGate: MiddlewareHandler = async (c, next) => {
    if (!getInstanceProfile().modules.includes('identity')) {
      return c.json({ error: 'not found' }, 404)
    }
    await next()
  }
  router.use('/op/upstream/*', profileGate)
  router.use('/api/op/providers', profileGate)
  router.use('/api/op/providers/*', profileGate)
  router.use('/api/op/account/*', profileGate)

  /** The registry's bootstrap seed (OP_UPSTREAM_SEED) runs once per
   *  process/isolate (idempotent upserts; a failure retries next request). */
  let seeded: Promise<void> | null = null
  function ensureSeeded(c: Context): Promise<void> {
    if (!seeded) {
      seeded = (async () => {
        const ids = await seedIdentityProvidersFromEnv(runtimeEnv<EnvLike>(c), getStore())
        if (ids.length) console.log(`[op] upstream registry bootstrap seeded: ${ids.join(', ')}`)
      })()
      seeded.catch(() => { seeded = null })
    }
    return seeded
  }

  /** The audit trail (the auth.ts SSO discipline): every upstream
   *  sign-in/link/refusal lands an auditEvents row, and every ADMIN act
   *  on the provider registry too (TODO.identity/07); a store hiccup is
   *  logged, never thrown. */
  async function audit(
    action: string,
    entityId: string,
    actor: { userId?: string; userName?: string },
    metadata: Record<string, unknown>,
    entityType = 'auth',
  ): Promise<void> {
    try {
      const id = crypto.randomUUID()
      await getStore().putEntity('auditEvents', id, null, JSON.stringify({
        id,
        timestamp: new Date().toISOString(),
        standard_id: '',
        entity_type: entityType,
        entity_id: entityId,
        action,
        user_id: actor.userId,
        user_name: actor.userName,
        metadata,
      }))
    } catch (err) {
      console.error(`[op] upstream audit event ${action} failed to persist:`, (err as Error).message)
    }
  }

  // ── the plain-language failure exits ───────────────────────────────

  /** Login-mode failures land on the login page's error box. */
  function loginErrorRedirect(origin: string, reason: string, providerName?: string): string {
    const url = new URL('/', origin)
    url.searchParams.set('error', `upstream_${reason}`)
    if (providerName) url.searchParams.set('provider', providerName)
    return url.toString()
  }

  /** Link-mode failures land on the account page's error box
   *  (/op/account — TODO.identity/02's page, native on this host). */
  function linkErrorRedirect(origin: string, reason: string, providerId?: string): string {
    const url = new URL('/op/account', origin)
    url.searchParams.set('error', reason)
    if (providerId) url.searchParams.set('provider', providerId)
    return url.toString()
  }

  /** The provider the route addresses: known + enabled, or the honest
   *  refusal target (a disabled/unknown provider never starts a flow). */
  async function enabledProvider(c: Context, id: string): Promise<IdentityProvider | null> {
    const provider = await getStore().getIdentityProvider(id)
    return provider?.enabled ? provider : null
  }

  // ── the public registry view (the login page's buttons) ───────────

  // GET /api/op/providers/public — enabled providers, public fields only.
  router.get('/api/op/providers/public', async (c) => {
    await ensureSeeded(c)
    const providers = (await getStore().listIdentityProviders())
      .filter(p => p.enabled)
      .map(p => ({ id: p.id, kind: p.kind, displayName: p.displayName, brandMark: p.brandMark }))
    return c.json(providers)
  })

  // ── the flow starters ──────────────────────────────────────────────

  /** Build the upstream redirect for a flow (both kinds share the state
   *  minting; the OIDC kind adds the nonce + PKCE pair). */
  async function startFlow(
    c: Context,
    provider: IdentityProvider,
    mode: 'login' | 'link',
    extra: { linkUserId?: string; redirect?: string },
  ): Promise<Response> {
    const env = runtimeEnv<EnvLike>(c)
    const origin = opRequestOrigin(c.req.raw)
    const callbackUri = `${origin}/op/upstream/${provider.id}/callback`
    const key = await resolveOpSigningKey(env)

    if (provider.kind === 'github') {
      const state = await signUpstreamState(key.secretMaterial, {
        p: provider.id, m: mode, ...(extra.linkUserId ? { u: extra.linkUserId } : {}), ...(extra.redirect ? { r: extra.redirect } : {}),
      })
      return c.redirect(buildGitHubAuthorizeUrl(gitHubEndpoints(env), {
        clientId: provider.clientId,
        redirectUri: callbackUri,
        scopes: providerScopes(provider),
        state,
      }))
    }

    const metadata = await discoverIssuer(provider.issuer!)
    const nonce = randomToken()
    const pkce = await generatePkce()
    const state = await signUpstreamState(key.secretMaterial, {
      p: provider.id, m: mode, n: nonce, v: pkce.verifier,
      ...(extra.linkUserId ? { u: extra.linkUserId } : {}), ...(extra.redirect ? { r: extra.redirect } : {}),
    })
    return c.redirect(buildUpstreamAuthorizationUrl(provider, metadata, {
      redirectUri: callbackUri,
      state,
      nonce,
      codeChallenge: pkce.challenge,
    }))
  }

  // GET /op/upstream/:id/signin — the login-page button's target.
  router.get('/op/upstream/:id/signin', async (c) => {
    await ensureSeeded(c)
    const origin = opRequestOrigin(c.req.raw)
    const provider = await enabledProvider(c, c.req.param('id'))
    if (!provider) return c.redirect(loginErrorRedirect(origin, 'unknown'))
    try {
      return await startFlow(c, provider, 'login', { redirect: safeLocalRedirect(c.req.query('redirect')) })
    } catch (err) {
      const reason = err instanceof OidcError ? err.reason : 'config'
      console.error(`[op] upstream sign-in start failed (${provider.id}/${reason}):`, (err as Error).message)
      return c.redirect(loginErrorRedirect(origin, reason, provider.displayName))
    }
  })

  // GET /op/upstream/:id/link — the account page's link action: the flow
  // BOUND to the current session's account (state.u). No session → the
  // login page, with this very URL as the post-login destination.
  router.get('/op/upstream/:id/link', async (c) => {
    await ensureSeeded(c)
    const origin = opRequestOrigin(c.req.raw)
    const provider = await enabledProvider(c, c.req.param('id'))
    if (!provider) return c.redirect(loginErrorRedirect(origin, 'unknown'))
    const user = await sessionUser(c)
    if (!user) {
      return c.redirect(`${origin}/?redirect=${encodeURIComponent(`/op/upstream/${provider.id}/link`)}`)
    }
    // Fail fast: the account already holds a link for this provider —
    // the honest refusal BEFORE the round trip (unlink first).
    const mine = await getStore().listIdentityLinks(user.id)
    if (mine.some(l => l.provider === provider.id)) {
      return c.redirect(linkErrorRedirect(origin, 'provider_linked', provider.id))
    }
    try {
      return await startFlow(c, provider, 'link', { linkUserId: user.id })
    } catch (err) {
      const reason = err instanceof OidcError ? err.reason : 'config'
      console.error(`[op] upstream link start failed (${provider.id}/${reason}):`, (err as Error).message)
      return c.redirect(linkErrorRedirect(origin, `upstream_${reason}`, provider.id))
    }
  })

  // ── the callback ───────────────────────────────────────────────────

  /** The request's flow parameters: GET's query, or Apple's form_post
   *  body (the `user` field — the first-consent name — is parsed here
   *  too; the link row keys on `sub`, the name is logged). */
  async function callbackParams(c: Context): Promise<Record<string, string | undefined>> {
    if (c.req.method === 'GET') {
      const q = (name: string) => c.req.query(name)
      return { code: q('code'), state: q('state'), error: q('error'), errorDescription: q('error_description') }
    }
    const contentType = c.req.header('content-type') ?? ''
    if (!contentType.includes('application/x-www-form-urlencoded')) return {}
    const form = new URLSearchParams(await c.req.raw.text())
    return {
      code: form.get('code') ?? undefined,
      state: form.get('state') ?? undefined,
      error: form.get('error') ?? undefined,
      errorDescription: form.get('error_description') ?? undefined,
      user: form.get('user') ?? undefined,
    }
  }

  /** Resolve the upstream identity (the code exchange + validation per
   *  kind). Throws OidcError / GitHubUpstreamError / an honest Error. */
  async function resolveUpstreamIdentity(
    c: Context,
    provider: IdentityProvider,
    payload: UpstreamStatePayload,
    code: string,
  ): Promise<UpstreamIdentity> {
    const env = runtimeEnv<EnvLike>(c)
    const origin = opRequestOrigin(c.req.raw)
    const callbackUri = `${origin}/op/upstream/${provider.id}/callback`

    if (provider.kind === 'github') {
      const secret = resolveProviderSecret(provider, env)
      if (!secret) throw new GitHubUpstreamError(`provider ${provider.id} declares no client secret (client_secret_ref) — the GitHub exchange needs it`)
      const identity = await fetchGitHubIdentity(gitHubEndpoints(env), {
        clientId: provider.clientId, clientSecret: secret, code, redirectUri: callbackUri,
      })
      return { accountId: identity.id, handle: identity.login, name: identity.name }
    }

    if (!payload.n || !payload.v) {
      // A GitHub-minted state replayed against an OIDC callback never
      // carries the nonce/verifier — the state check's honest failure.
      throw new OidcError('token_nonce', 'the flow state carries no nonce/verifier (wrong provider kind)')
    }
    const metadata = await discoverIssuer(provider.issuer!)
    const secret = isAppleProvider(provider)
      // Apple's quirk: the client secret is a short-lived ES256 JWT
      // signed with the portal key, minted per exchange.
      ? await generateAppleClientSecret(await resolveAppleSecretConfig(env), provider.clientId)
      : resolveProviderSecret(provider, env)
    const tokens = await exchangeUpstreamCode(provider, metadata, {
      clientSecret: secret, code, redirectUri: callbackUri, codeVerifier: payload.v,
    })
    const claims = await validateIdToken(tokens.id_token, {
      issuer: metadata.issuer,
      clientId: provider.clientId,
      nonce: payload.n,
      jwksUri: metadata.jwks_uri,
    })
    if (typeof claims.sub !== 'string' || !claims.sub) {
      throw new OidcError('token_malformed', 'the ID token carries no sub')
    }
    return {
      accountId: claims.sub,
      handle: typeof claims.email === 'string' && claims.email ? claims.email : claims.sub,
      ...(typeof claims.name === 'string' && claims.name ? { name: claims.name } : {}),
    }
  }

  // GET|POST /op/upstream/:id/callback — the upstream's redirect back.
  router.all('/op/upstream/:id/callback', async (c) => {
    await ensureSeeded(c)
    const origin = opRequestOrigin(c.req.raw)
    if (c.req.method !== 'GET' && c.req.method !== 'POST') return c.json({ error: 'method not allowed' }, 405)

    const providerId = c.req.param('id')
    const provider = await getStore().getIdentityProvider(providerId)
    const params = await callbackParams(c)

    // The upstream's own refusal (the user declined at the IdP, etc.).
    if (params.error) {
      console.warn(`[op] upstream ${providerId} answered error=${params.error}: ${params.errorDescription ?? ''}`)
      return c.redirect(loginErrorRedirect(origin, 'refused', provider?.displayName))
    }
    if (!params.code || !params.state) {
      return c.redirect(loginErrorRedirect(origin, 'exchange', provider?.displayName))
    }

    // The state verifies FIRST (signature + TTL), then binds to this
    // very provider (a state minted for another provider's callback
    // never crosses over).
    const key = await resolveOpSigningKey(runtimeEnv<EnvLike>(c))
    const payload = await verifyUpstreamState(key.secretMaterial, params.state)
    if (!payload || payload.p !== providerId) {
      return c.redirect(loginErrorRedirect(origin, 'state', provider?.displayName))
    }
    if (!provider || !provider.enabled) {
      return c.redirect(loginErrorRedirect(origin, 'unknown', provider?.displayName))
    }
    if (isAppleProvider(provider) && params.user) {
      // Apple's first-consent name (the ONLY time it is shared). The
      // link keys on `sub`; the name is logged for the operator's trail.
      try {
        const appleUser = JSON.parse(params.user) as { name?: { firstName?: string; lastName?: string } }
        const fullName = [appleUser.name?.firstName, appleUser.name?.lastName].filter(Boolean).join(' ')
        if (fullName) console.log(`[op] apple first-consent name for the new link: ${fullName}`)
      } catch { /* a malformed user field never blocks the flow */ }
    }

    let identity: UpstreamIdentity
    try {
      identity = await resolveUpstreamIdentity(c, provider, payload, params.code)
    } catch (err) {
      const reason = err instanceof OidcError ? err.reason : err instanceof GitHubUpstreamError ? 'exchange' : 'config'
      console.error(`[op] upstream ${providerId} ${payload.m} failed (${reason}):`, (err as Error).message)
      return c.redirect(payload.m === 'link'
        ? linkErrorRedirect(origin, `upstream_${reason}`, providerId)
        : loginErrorRedirect(origin, reason, provider.displayName))
    }

    const store = getStore()

    if (payload.m === 'link') {
      // The link binds to the flow's OWN account — the current session
      // must still be it (a switched account mid-flow fails honestly).
      const user = await sessionUser(c)
      if (!user || user.id !== payload.u) {
        return c.redirect(linkErrorRedirect(origin, 'link_session', providerId))
      }
      const existing = await store.findIdentityLink(providerId, identity.accountId)
      if (existing && existing.userId !== user.id) {
        // The upstream account is already linked to a DIFFERENT account.
        await audit('upstream_link_conflict', user.id, { userId: user.id, userName: user.name }, {
          provider: providerId, handle: identity.handle, conflict: 'other_account',
        })
        return c.redirect(linkErrorRedirect(origin, 'link_taken', providerId))
      }
      if (!existing) {
        const created = await store.createIdentityLink({
          userId: user.id, provider: providerId, providerAccountId: identity.accountId, linkedBy: user.email,
        })
        if (!created) return c.redirect(linkErrorRedirect(origin, 'link_taken', providerId)) // the race lost honestly
        await audit('upstream_link', user.id, { userId: user.id, userName: user.name }, {
          provider: providerId, handle: identity.handle,
        })
      }
      const done = new URL('/op/account', origin)
      done.searchParams.set('linked', providerId)
      return c.redirect(done.toString())
    }

    // mode 'login' — THE MATCH RULE: (provider, account id) against the
    // linked identities, NEVER by email. Unlinked → the honest refusal:
    // NO account, NO session.
    const link = await store.findIdentityLink(providerId, identity.accountId)
    const user = link ? await store.getUserById(link.userId) : null
    if (!link || !user) {
      console.warn(`[op] upstream sign-in refused: ${providerId} identity ${JSON.stringify(identity.handle)} is not linked`)
      await audit('upstream_refused', providerId, { userName: identity.handle }, {
        provider: providerId, handle: identity.handle, reason: link ? 'account_gone' : 'not_linked',
      })
      return c.redirect(loginErrorRedirect(origin, 'not_linked', provider.displayName))
    }

    const token = await store.createSession(user.id, clientInfo(c))
    await store.touchLastLogin(user.id)
    setCookie(c, SESSION_COOKIE, token, sessionCookieOpts(c))
    await audit('upstream_sign_in', user.id, { userId: user.id, userName: user.name }, {
      provider: providerId, handle: identity.handle,
    })
    // TODO.identity/09 — the account holder learns of every entry (the
    // method is the provider's display name). Never blocks the flow.
    await sendOpMail(runtimeEnv<MailEnv>(c), {
      to: user.email,
      template: 'signin',
      issuer: origin,
      params: { name: user.name, when: new Date().toISOString().slice(0, 16).replace('T', ' '), method: provider.displayName },
    })
    return c.redirect(`${origin}${safeLocalRedirect(payload.r) ?? roleHome(user.role)}`)
  })

  // ── the registry's admin surface (admin/cs_admin — the op.ts gate;
  //    the full console UI is TODO.identity/07's) ─────────────────────

  async function requireAdmin(c: Context): Promise<{ user: AuthUserPayload | null; error: Response | null }> {
    const user = await sessionUser(c)
    if (!user) return { user: null, error: c.json({ error: 'authentication required' }, 401) }
    if (user.role !== 'admin' && user.role !== 'cs_admin') {
      return { user: null, error: c.json({ error: 'administrator role required' }, 403) }
    }
    return { user, error: null }
  }

  /** The admin view (the secret REFERENCE is shown — it names an env
   *  var, never the secret; the resolved value never leaves the env). */
  function providerView(provider: IdentityProvider) {
    return {
      id: provider.id,
      kind: provider.kind,
      displayName: provider.displayName,
      brandMark: provider.brandMark,
      issuer: provider.issuer,
      clientId: provider.clientId,
      clientSecretRef: provider.clientSecretRef,
      scopes: provider.scopes,
      enabled: provider.enabled,
      apple: isAppleProvider(provider),
      createdAt: provider.createdAt,
      createdBy: provider.createdBy,
      updatedAt: provider.updatedAt,
    }
  }

  // GET /api/op/providers — the registry.
  router.get('/api/op/providers', async (c) => {
    await ensureSeeded(c)
    const gate = await requireAdmin(c)
    if (gate.error) return gate.error
    return c.json((await getStore().listIdentityProviders()).map(providerView))
  })

  // POST /api/op/providers — register/refresh a provider (upsert by id).
  router.post('/api/op/providers', async (c) => {
    const gate = await requireAdmin(c)
    if (gate.error || !gate.user) return gate.error!
    const body = await c.req.json<Record<string, unknown>>().catch(() => null)
    if (!body) return c.json({ error: 'a JSON body is required' }, 400)
    const { problems, input } = validateProviderInput(body)
    if (!input) return c.json({ error: 'invalid provider', problems }, 400)
    const existing = await getStore().getIdentityProvider(input.id)
    const provider = await getStore().upsertIdentityProvider({ ...input, createdBy: gate.user.email })
    await audit(existing ? 'provider.updated' : 'provider.registered', provider.id, { userId: gate.user.id, userName: gate.user.name }, {
      kind: provider.kind, enabled: provider.enabled,
    }, 'provider')
    return c.json(providerView(provider), existing ? 200 : 201)
  })

  // POST /api/op/providers/:id/status — the enable toggle. A disabled
  // provider vanishes from the login page and refuses flows; its rows
  // (and the links against it) stay — re-enabling restores them.
  router.post('/api/op/providers/:id/status', async (c) => {
    const gate = await requireAdmin(c)
    if (gate.error || !gate.user) return gate.error!
    const body = await c.req.json<{ enabled?: unknown }>().catch(() => null)
    if (!body || typeof body.enabled !== 'boolean') {
      return c.json({ error: 'enabled must be a boolean' }, 400)
    }
    const provider = await getStore().setIdentityProviderEnabled(c.req.param('id'), body.enabled)
    if (!provider) return c.json({ error: 'not found' }, 404)
    await audit('provider.status', provider.id, { userId: gate.user.id, userName: gate.user.name }, {
      enabled: provider.enabled,
    }, 'provider')
    return c.json(providerView(provider))
  })

  // DELETE /api/op/providers/:id — remove the row. Links against it
  // stay (the audit trail); sign-ins fail closed on the missing row.
  router.delete('/api/op/providers/:id', async (c) => {
    const gate = await requireAdmin(c)
    if (gate.error || !gate.user) return gate.error!
    const id = c.req.param('id')
    const gone = await getStore().deleteIdentityProvider(id)
    if (!gone) return c.json({ error: 'not found' }, 404)
    await audit('provider.removed', id, { userId: gate.user.id, userName: gate.user.name }, {}, 'provider')
    return c.json({ ok: true })
  })

  // ── the account surface (the link list + unlink) ──────────────────
  // The page these APIs serve is TODO.identity/02's /op/account; the
  // admin console is TODO.identity/06's.

  async function requireSession(c: Context): Promise<{ user: AuthUserPayload | null; error: Response | null }> {
    const user = await sessionUser(c)
    if (!user) return { user: null, error: c.json({ error: 'authentication required' }, 401) }
    return { user, error: null }
  }

  // GET /api/op/account/links — the current account's linked identities,
  // joined with the registry for the display names.
  router.get('/api/op/account/links', async (c) => {
    const gate = await requireSession(c)
    if (gate.error || !gate.user) return gate.error!
    const store = getStore()
    const providers = new Map((await store.listIdentityProviders()).map(p => [p.id, p]))
    const links = (await store.listIdentityLinks(gate.user.id)).map(l => ({
      provider: l.provider,
      displayName: providers.get(l.provider)?.displayName ?? l.provider,
      brandMark: providers.get(l.provider)?.brandMark ?? null,
      providerAccountId: l.providerAccountId,
      linkedAt: l.linkedAt,
      linkedBy: l.linkedBy,
    }))
    return c.json(links)
  })

  // DELETE /api/op/account/links/:provider — the unlink action (the
  // account's OWN link only). THE GUARD (TODO.identity/06): an account
  // always keeps at least one way in — unlinking the last linked identity
  // while no password is set would strand the account behind an
  // administrator's fresh setup link, so the route refuses and explains.
  router.delete('/api/op/account/links/:provider', async (c) => {
    const gate = await requireSession(c)
    if (gate.error || !gate.user) return gate.error!
    const providerId = c.req.param('provider')
    const store = getStore()
    const methods = await store.countSignInMethods(gate.user.id)
    if (methods.links <= 1 && !methods.password) {
      return c.json({
        error: 'This link is your only way to sign in. Set a password first, or keep the link — an account always keeps at least one sign-in method.',
      }, 409)
    }
    const gone = await store.deleteIdentityLink(gate.user.id, providerId)
    if (!gone) return c.json({ error: 'not linked' }, 404)
    await audit('upstream_unlink', gate.user.id, { userId: gate.user.id, userName: gate.user.name }, { provider: providerId })
    return c.json({ ok: true })
  })

  return router
}
