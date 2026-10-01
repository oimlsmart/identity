// ═══════════════════════════════════════════════════════════════════
// TODO.sota/07.4 — the PROTOCOL module, extracted from op.ts as the
// sixth proof of the domain-model split (the pure refactor; the golden
// + the suite are the proof — zero behavior change).
//
// The browser-facing OIDC half — everything an agent's user agent
// drives:
//
//   GET  /op/authorize            — the authorization endpoint (the
//        prompt ladder, the consent redirect, the JARM jwt mode).
//   POST /op/par                  — RFC 9126, the pushed authorization
//        request.
//   GET/POST /api/op/consent/:id  — the consent page's API (the Vue
//        island's context + the decision).
//   GET/POST /api/op/choose-account — the account chooser's API (the
//        multi-account wave + the persona assumption).
//
// The token arms (the machine half) stay in op.ts; the seed + audit
// seams ride in as dependencies.
// ═══════════════════════════════════════════════════════════════════

import { Hono, type Context } from 'hono'
import { getCookie, setCookie } from 'hono/cookie'
import { env as runtimeEnv } from 'hono/adapter'
import {
  getStore, type AuthUserPayload,
} from '../store'
import { getInstanceProfile } from '../profile'
import { clientInfo } from '../client-info'
import { opRequestOrigin, resolveOpConfig } from '../auth/op/config'
import {
  opRandomToken, resolveOpSigningKey, signOpIdToken,
} from '../auth/op/keys'
import { oidcError } from '../auth/op/oidc-error'
import { roleClaimsForContext } from '../auth/op/claims'
import { claimsContextFor } from '../auth/op/memberships'
import { DEVICE_CLASS, deviceClassOf } from '../auth/op/device-clients'
import { SERVICE_CLASS, serviceClassOf } from '../auth/op/service-clients'
import { sessionMeetsMaxAge } from '../auth/op/step-up'
import { computeSessionState } from '../auth/op/session-state'
import { SESSION_COOKIE, sessionCookieOpts, sessionUser } from '../session'
import {
  activeJarContext, liveJarEntryForUser, loginUrlForContinue,
  resolveAccountJar, sanitizeContinueTarget, touchAccountJar,
} from '../auth/op/account-jar'
import {
  declaredPersonaByEmail, declaredPersonasForClient, grantsAllowEmail,
  personaGrantsFromEnv, type DeclaredPersona, type OpPersonaGrants,
} from '../auth/op/persona-assume'
import { parseOpAccountSeed, type OpAccountSeedEntry } from '../auth/op/accounts'
import { auditGrant } from '../auth/op/grants'

type EnvLike = Record<string, string | undefined>

/** The pushed request's life (RFC 9126 recommends <= 90 s). */
const PAR_TTL_MS = 90 * 1000

function escapeHtml(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')
}

/** The request's effective OP config (env + this request's origin) —
 *  the same formula every OP route reads. */
function configFor(c: Context) {
  return resolveOpConfig(runtimeEnv<EnvLike>(c), opRequestOrigin(c.req.raw))
}

export function createOpProtocolRouter(deps: {
  ensureSeeded: (c: Context) => Promise<void>
  audit: (
    action: string,
    entityId: string,
    actor: { userId?: string; userName?: string },
    metadata: Record<string, unknown>,
  ) => Promise<void>
  authenticateClient: (c: Context, form: URLSearchParams) => Promise<{ client: import('../store').OidcClient | null; error: Response | null }>

}): Hono {
  const op = new Hono()
  const { ensureSeeded, authenticateClient } = deps
  const audit = deps.audit

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
  async function authorizeErrorRedirect(
    c: Context,
    redirectUri: string,
    state: string | undefined,
    error: string,
    description: string,
    responseMode: string = 'query',
    clientId: string = '',
  ): Promise<string> {
    const back = new URL(redirectUri)
    back.searchParams.set('error', error)
    back.searchParams.set('error_description', description)
    if (state) back.searchParams.set('state', state)
    return jarmWrap(c, back, responseMode, clientId)
  }

  /** RFC 9150 (TODO.modern/12): the JARM wrap — response_mode=jwt
   *  moves every response parameter into redirect_uri?response=<JWT>,
   *  ES256-signed with the OP's own key (the RPs verify against the
   *  JWKS they already hold), iss + aud + the parameters verbatim.
   *  Any other mode: the URL stands untouched (the default's
   *  byte-identical answers). */
  async function jarmWrap(c: Context, back: URL, responseMode: string, clientId: string): Promise<string> {
    if (responseMode !== 'jwt') return back.toString()
    const claims: Record<string, unknown> = {
      iss: configFor(c).issuer,
      ...(clientId ? { aud: clientId } : {}),
    }
    for (const [key, value] of back.searchParams) claims[key] = value
    const key = await resolveOpSigningKey(runtimeEnv<EnvLike>(c))
    const jwt = await signOpIdToken(key, claims)
    return `${back.origin}${back.pathname}?response=${encodeURIComponent(jwt)}`
  }

  // GET /op/authorize — the authorization endpoint.
  op.get('/op/authorize', async (c) => {
    await ensureSeeded(c)
    const config = configFor(c)
    const q = (name: string) => c.req.query(name)?.trim() || undefined
    let [responseType, clientId, redirectUri, scope, state, nonce, challenge, challengeMethod, prompt, maxAgeParam, responseModeParam, loginHintParam, personaParam] =
      ['response_type', 'client_id', 'redirect_uri', 'scope', 'state', 'nonce', 'code_challenge', 'code_challenge_method', 'prompt', 'max_age', 'response_mode', 'login_hint', 'persona'].map(q)
    // RFC 9126 (TODO.modern/11): the PUSHED request — the pushed
    // parameters REPLACE the query's (any other query parameter is
    // ignored, never merged); the consume is single-use, expiry-bound,
    // and client-bound (a query client_id must match the owner). An
    // unknown/consumed/expired request_uri answers the IN-PLACE refusal
    // — no validated redirect remains to error to (the wall).
    const requestUri = q('request_uri')
    if (requestUri) {
      const queryClientId = clientId
      const pushed = await getStore().consumePushedAuthorizationRequest(requestUri)
      // The client binding: a query client_id must match the pushed
      // owner; absent, the owner stands.
      if (!pushed || (queryClientId && queryClientId !== pushed.clientId)) {
        return authorizeRefusal(c, 'Cannot authorize this request', 'The <code>request_uri</code> is unknown, expired, already used, or belongs to another client.')
      }
      let pushedParams: Record<string, unknown>
      try {
        pushedParams = JSON.parse(pushed.params) as Record<string, unknown>
      } catch {
        return authorizeRefusal(c, 'Cannot authorize this request', 'The pushed request is malformed.')
      }
      const g = (name: string): string | undefined => {
        const value = pushedParams[name]
        return typeof value === 'string' ? (value.trim() || undefined) : undefined
      }
      ;[responseType, clientId, redirectUri, scope, state, nonce, challenge, challengeMethod, prompt, maxAgeParam, responseModeParam, loginHintParam, personaParam] =
        ['response_type', 'client_id', 'redirect_uri', 'scope', 'state', 'nonce', 'code_challenge', 'code_challenge_method', 'prompt', 'max_age', 'response_mode', 'login_hint', 'persona'].map(g)
      clientId = clientId ?? pushed.clientId
    }


    // 1. The client must be KNOWN + active — before any redirect logic.
    if (!clientId) {
      return authorizeRefusal(c, 'Cannot authorize this request', 'The request names no <code>client_id</code>.')
    }
    // The client read and the session read are INDEPENDENT — ONE phase
    // on every authorize (TODO.restructure/12: this is the register's
    // hottest path, every RP sign-in pays it). The validation order
    // below is unchanged; a refused client just also paid the session
    // read, never an observable difference (a read, no state).
    const [client, initialUser] = await Promise.all([
      getStore().getOidcClient(clientId),
      sessionUser(c),
    ])
    // The flow's user REBINDS when the persona= parameter mints the
    // assumption below (the session flips mid-flow; the consent + code
    // mints then read the persona's row).
    let user = initialUser
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
    // RFC 9150 (TODO.modern/12): the response mode — absent = the
    // default query (byte-identical for every existing RP); 'jwt' is
    // JARM (the signed response); anything else refuses.
    const responseMode = responseModeParam ?? 'query'
    if (responseMode !== 'query' && responseMode !== 'jwt') {
      return c.redirect(await authorizeErrorRedirect(c, redirectUri, state, 'invalid_request', `the response_mode ${responseMode} is not supported (query, jwt)`, responseMode, clientId))
    }
    if (responseType !== 'code') {
      return c.redirect(await authorizeErrorRedirect(c, redirectUri, state, 'unsupported_response_type', 'only response_type=code is served', responseMode, clientId))
    }
    if (!(scope ?? '').split(/\s+/).includes('openid')) {
      return c.redirect(await authorizeErrorRedirect(c, redirectUri, state, 'invalid_scope', 'the openid scope is required', responseMode, clientId))
    }
    if (!challenge || challengeMethod !== 'S256') {
      return c.redirect(await authorizeErrorRedirect(c, redirectUri, state, 'invalid_request', 'PKCE is required (code_challenge + code_challenge_method=S256)', responseMode, clientId))
    }

    // max_age (TODO.modern/06): the RP's freshness demand — seconds. A
    // present-but-unparseable value refuses the redirect-shaped way
    // (invalid_request), never a silent ignore. (This check sits BELOW
    // the redirect_uri wall — an error redirect is only safe for a
    // registered URI.)
    let maxAge: number | null = null
    if (maxAgeParam !== undefined) {
      maxAge = /^\d+$/.test(maxAgeParam) ? Number(maxAgeParam) : null
      if (maxAge === null) {
        return c.redirect(await authorizeErrorRedirect(c, redirectUri, state, 'invalid_request', 'max_age must be a non-negative integer (seconds)', responseMode, clientId))
      }
    }

    // persona=<email> (the persona-assumption streamline — the RP's
    // account switcher names the DECLARED demo persona directly): a
    // signed-in request the grant covers mints the assumption HERE — the
    // session flips to the persona, the chooser never paints, and the
    // flow continues as the persona's own (the personas' consent is
    // pre-seeded per client, so the remembered-grant skip mints the code
    // with no further stop). Every verdict re-reads the declaration and
    // the store, identically to the chooser POST's — never the RP's
    // claim. A refusal is the redirect-shaped access_denied (the
    // redirect_uri is already validated above). A signed-OUT request
    // falls through to the login redirect with the parameter riding the
    // re-entry — the presenter signs in as THEMSELVES (the hint prefill
    // suppresses), the persona applies on the re-entry.
    let personaApplied = false
    if (personaParam && user) {
      const personaPosture = personaGrantsFor(c)
      const persona = personaPosture
        ? declaredPersonaByEmail(personaPosture.personas, personaParam.trim().toLowerCase())
        : null
      if (!persona) {
        return c.redirect(await authorizeErrorRedirect(c, redirectUri, state, 'access_denied', 'the persona is not declared for this client', responseMode, clientId))
      }
      // The verdict judges the PRINCIPAL — the presenting account, or the
      // original grantee behind an assumed session (the chaining rule).
      const principal = await assumptionPrincipalFor({ user })
      const personaEmails = new Set(personaPosture!.personas.map(p => p.email))
      if (!principal || !grantsAllowEmail(personaPosture!.grants, principal.email, personaEmails)) {
        return c.redirect(await authorizeErrorRedirect(c, redirectUri, state, 'access_denied', 'the presenting account is not granted the persona assumption', responseMode, clientId))
      }
      const personaAccount = await getStore().findUserByEmail(persona.email)
      if (!personaAccount) {
        return c.redirect(await authorizeErrorRedirect(c, redirectUri, state, 'access_denied', 'the persona account is not provisioned', responseMode, clientId))
      }
      const personaToken = await mintPersonaAssumption(c, personaPosture!.grants.clientId, principal, personaAccount)
      // Rebind from the NEW session row — the exact session-projected
      // payload (id, amr, sessionCreatedAt) the consent + code mints read.
      const assumedUser = await getStore().getSessionUser(personaToken)
      if (!assumedUser) {
        return c.redirect(await authorizeErrorRedirect(c, redirectUri, state, 'server_error', 'the persona session did not take', responseMode, clientId))
      }
      user = assumedUser
      personaApplied = true
    }

    // 4. The sign-in surface: no session → the instance's own login
    //    page, with this very request as the post-login destination (the
    //    flow re-enters /op/authorize, now signed in). NOTHING is stored
    //    yet — the row is created only for an authenticated request.
    //
    //    prompt=login (TODO.identity-sso, the wave-A tail — the OIDC
    //    forced re-authentication) takes the SAME path WITH a live
    //    session: the re-entry URL sheds the 'login' value (consumed by
    //    this redirect — the stateless loop guard) and the login page's
    //    own prompt flag forces the form past its existing-session
    //    bounce. The RP's freshness PROOF is the ID token's auth_time
    //    (the code carries the new session's authentication instant) —
    //    the strip is the flow's bookkeeping, never the assurance. The
    //    remaining prompt values (consent) ride on.
    const prompts = (prompt ?? '').split(/\s+/).filter(Boolean)
    // prompt=select_account (the account-chooser wave): the flow ALWAYS
    // routes through the chooser (/op/choose-account) — a live session
    // never shortcuts the question "which account?". The continue target
    // carries the request's RESOLVED parameters (the query's or the
    // pushed request's — a re-presented request_uri is already consumed)
    // with the 'select_account' value shed (consumed by this redirect —
    // the same stateless loop guard prompt=login uses); the remaining
    // values (login, consent) ride on so their semantics re-apply on the
    // re-entry. The chooser itself decides between the remembered
    // accounts, a fresh sign-in, and (no jar) the plain login form.
    if (prompts.includes('select_account') && !personaApplied) {
      const carried = new URLSearchParams()
      const params: Array<[string, string | undefined]> = [
        ['response_type', responseType], ['client_id', clientId], ['redirect_uri', redirectUri],
        ['scope', scope], ['state', state], ['nonce', nonce], ['code_challenge', challenge],
        ['code_challenge_method', challengeMethod], ['max_age', maxAgeParam],
        ['response_mode', responseModeParam],
        // The hint stays in the carried request (the re-entry IS the
        // original authorize)…
        ['login_hint', loginHintParam],
        // …and so does the persona= streamline — a signed-out chooser
        // visit ends in a fresh sign-in whose re-entry applies it.
        ['persona', personaParam],
      ]
      for (const [name, value] of params) if (value !== undefined) carried.set(name, value)
      const rest = prompts.filter(p => p !== 'select_account')
      if (rest.length) carried.set('prompt', rest.join(' '))
      // …and rides the chooser URL itself: a jar entry whose address
      // matches is PRE-SELECTED on the chooser page (the Google shape);
      // a hint nothing matches lands on the fresh sign-in form as the
      // prefill. A persona= request suppresses the ride-along — the
      // persona's address never prefills a credential form (the presenter
      // signs in as themselves). The re-entry sheds nothing else — the
      // carried request is the RP's, verbatim.
      const hintParam = loginHintParam && !personaParam ? `&login_hint=${encodeURIComponent(loginHintParam)}` : ''
      return c.redirect(`/op/choose-account?continue=${encodeURIComponent(`/op/authorize?${carried}`)}${hintParam}`)
    }
    // The freshness gate (TODO.modern/06): a max_age ask judges the
    // session's authentication instant — stale (or unprovable) sends
    // the SAME sign-in path as prompt=login (the re-entry re-checks;
    // the fresh session satisfies the gate).
    const authFresh = maxAge === null || sessionMeetsMaxAge(user?.sessionCreatedAt ?? null, maxAge)
    const forceLogin = prompts.includes('login') || !authFresh
    // `user` arrived with the client read above (TODO.restructure/12's
    // one-phase boot).
    if (!user || forceLogin) {
      // prompt=none (the OIDC-correct silent probe): a request that
      // cannot be answered silently answers the CLIENT at its
      // redirect_uri with login_required — never the login page (the
      // sessionless boot probe lands anonymous cleanly; the
      // full-page login never flashes).
      if (prompts.includes('none')) {
        return c.redirect(await authorizeErrorRedirect(c, redirectUri, state, 'login_required',
          'the end-user is not authenticated', responseModeParam, clientId))
      }
      const here = new URL(c.req.url)
      if (forceLogin) {
        const rest = prompts.filter(p => p !== 'login')
        if (rest.length) here.searchParams.set('prompt', rest.join(' '))
        else here.searchParams.delete('prompt')
      }
      const target = `${here.pathname}${here.search}`
      const flag = forceLogin ? '&prompt=login' : ''
      // TODO.modern/17: the login_hint rides the sign-in page (the
      // address field prefills — a hint, the human corrects). A persona=
      // request suppresses the prefill: the persona's address never
      // fills a credential form — the presenter signs in as THEMSELVES,
      // the persona applies on the re-entry.
      const hintSuffix = loginHintParam && !personaParam ? `&login_hint=${encodeURIComponent(loginHintParam)}` : ''
      return c.redirect(`/?redirect=${encodeURIComponent(target)}${flag}${hintSuffix}`)
    }

    // 4b. The remembered consent (TODO.identity-features/12): a LIVE
    //     grant covering this request's scope set skips the consent page
    //     — the code mints through the flow's ONE mint path (the consent
    //     decision's allow's own) and the RP's redirect carries it
    //     directly. prompt=consent in the request (the OIDC re-consent
    //     signal) ALWAYS shows the page, grant or no grant.
    const forceConsent = (prompt ?? '').split(/\s+/).includes('consent')
    if (!forceConsent && (await getStore().getConsentGrant(user.id, client.clientId, scope!))) {
      const redirect = await mintAuthorizationCode(c, {
        clientId: client.clientId,
        redirectUri,
        scope: scope!,
        state: state ?? '',
        nonce: nonce ?? null,
        codeChallenge: challenge,
        userId: user.id,
        amr: user.amr ?? null,
        authTime: user.sessionCreatedAt ?? null,
        responseMode,
      })
      return c.redirect(redirect)
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
      responseMode,
      ttlMs: config.authorizationTtlMs,
    })
    return c.redirect(`/op/consent?auth=${encodeURIComponent(id)}`)
  })

  // ── PAR (TODO.modern/11, RFC 9126) ────────────────────────────────

  // POST /op/par — the PUSHED authorization request: the authorize
  // parameter set posted to the back channel (the token endpoint's own
  // client authentication), the browser redirect carrying only the
  // request_uri. The open-redirect wall applies AT PAR TIME — an
  // unregistered redirect_uri refuses before anything is stored; the
  // machine classes refuse exactly as the authorize itself does.
  op.post('/op/par', async (c) => {
    await ensureSeeded(c)
    const form = await c.req.parseBody()
    const params: Record<string, string> = {}
    for (const [key, value] of Object.entries(form)) {
      if (typeof value === 'string') params[key] = value
    }
    const { client, error: clientError } = await authenticateClient(c, new URLSearchParams(Object.entries(params)))
    if (clientError || !client) return clientError!
    const redirectUri = params.redirect_uri ?? ''
    if (!redirectUri || !client.redirectUris.includes(redirectUri)) {
      return oidcError(c, 400, 'invalid_request', 'the redirect_uri is not one this client registered')
    }
    const machineClass = deviceClassOf(client.claimsPolicy) ? DEVICE_CLASS
      : serviceClassOf(client.claimsPolicy) ? SERVICE_CLASS
        : null
    if (machineClass) {
      return oidcError(c, 400, 'invalid_request', `a ${machineClass} client authenticates at the token endpoint (client_credentials), never through a sign-in flow`)
    }
    const uri = `urn:ietf:params:oauth:request_uri:${opRandomToken()}`
    await getStore().createPushedAuthorizationRequest({
      uri,
      clientId: client.clientId,
      params: JSON.stringify(params),
      expiresAt: new Date(Date.now() + PAR_TTL_MS).toISOString(),
    })
    return c.json({ request_uri: uri, expires_in: Math.round(PAR_TTL_MS / 1000) }, 201)
  })

  // ── consent (the Vue island's API) ───────────────────────────────

  /** The allow's mint, THE ONE PATH (TODO.identity-features/12): the
   *  consent decision's allow AND the remembered-grant skip both mint
   *  through here — the one-time code carries the session's stamped
   *  active-org context (TODO.identity/11) and the session's amr
   *  provenance (TODO.identity-sso/02+03) exactly as the consent page's
   *  allow does, and the redirect back to the RP composes the same way
   *  (the state first, the code last). */
  async function mintAuthorizationCode(c: Context, input: {
    clientId: string
    redirectUri: string
    scope: string
    state: string
    nonce: string | null
    codeChallenge: string
    userId: string
    amr: string[] | null
    /** TODO.identity-sso (the wave-A tail): the consenting session's
     *  authentication instant (AuthUserPayload.sessionCreatedAt, verbatim)
     *  — the ID token's auth_time. Null = none recorded. */
    authTime: string | null
    /** TODO.modern/12 (RFC 9150): the JARM mode ('jwt' wraps the
     *  redirect; the default stands). */
    responseMode?: string | null
  }): Promise<string> {
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
      clientId: input.clientId,
      redirectUri: input.redirectUri,
      scope: input.scope,
      nonce: input.nonce,
      codeChallenge: input.codeChallenge,
      userId: input.userId,
      contextOrg,
      // TODO.identity-sso/02+03: the consenting session's authentication
      // provenance rides the code into the ID token (the session's truth
      // at the moment of consent — never recomputed later). The wave-A
      // tail adds the authentication INSTANT (the auth_time claim).
      amr: input.amr,
      authTime: input.authTime,
      ttlMs: config.codeTtlMs,
    })
    const back = new URL(input.redirectUri)
    if (input.state) back.searchParams.set('state', input.state)
    back.searchParams.set('code', code)
    // The session_state (TODO.modern/03): the RP's session-observation
    // digest, bound to (this client, the RP's origin, the live session
    // token). The check_session_iframe re-judges exactly this value on
    // every poll — a signed-out or revoked session changes it.
    if (sessionToken) {
      back.searchParams.set(
        'session_state',
        await computeSessionState(input.clientId, new URL(input.redirectUri).origin, sessionToken),
      )
    }
    return jarmWrap(c, back, input.responseMode ?? 'query', input.clientId)
  }

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
      // The flow's re-entry URL (the account-chooser wave): the consent
      // page's "switch account" link builds its chooser target from it —
      // a switch re-runs the authorize with the newly chosen session,
      // which re-derives every per-account artifact (the pending row,
      // the remembered grant, the claims) from scratch.
      authorizeUrl: authorizeUrlFor(row!),
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
      // TODO.modern/12: the refusal wraps in the row's own mode.
      return c.json({ redirect: await jarmWrap(c, back, decided.responseMode ?? 'query', decided.clientId) })
    }

    // TODO.identity-features/12: the allow is REMEMBERED — the grant per
    // (account, client, scope set) lets the next authorize skip this page
    // (the upsert refreshes a live triple, lands fresh over a revoked
    // one); the audit chain carries the act on the account's own feed
    // (naming the client's display name, the PAT events' posture).
    const grant = await getStore().recordConsentGrant({
      userId: user.id,
      clientId: decided.clientId,
      scope: decided.scope,
    })
    const grantClient = await getStore().getOidcClient(decided.clientId)
    await auditGrant('account.consent_granted', user.id, { userId: user.id, userName: user.name }, {
      grant: grant.id,
      client: decided.clientId,
      name: grantClient?.name ?? decided.clientId,
      scope: grant.scope,
    })
    const redirect = await mintAuthorizationCode(c, {
      clientId: decided.clientId,
      redirectUri: decided.redirectUri,
      scope: decided.scope,
      state: decided.state,
      nonce: decided.nonce,
      codeChallenge: decided.codeChallenge,
      userId: user.id,
      amr: user.amr ?? null,
      authTime: user.sessionCreatedAt ?? null,
      responseMode: decided.responseMode,
    })
    return c.json({ redirect })
  })

  // ── the account chooser (the multi-account wave) ───────────────────

  /** The request's persona-assumption posture: the declared grants and
   *  the persona set they serve — or null (the feature stands closed:
   *  no declaration, no personas, ever). A malformed declaration closes
   *  the posture honestly (logged) — it never widens it. */
  function personaGrantsFor(c: Context): { grants: OpPersonaGrants; personas: DeclaredPersona[] } | null {
    const env = runtimeEnv<EnvLike>(c)
    const grants = personaGrantsFromEnv(env)
    if (!grants) return null
    const rawSeed = env.OP_ACCOUNT_SEED?.trim()
    if (!rawSeed) return null
    let seed: OpAccountSeedEntry[]
    try {
      seed = parseOpAccountSeed(rawSeed)
    } catch (err) {
      console.error(`[op] the persona-assumption posture stays closed — the account seed does not parse: ${(err as Error).message}`)
      return null
    }
    return { grants, personas: declaredPersonasForClient(seed, grants.clientId) }
  }

  /** The account the persona-assumption verdicts judge (the persona→
   *  persona chaining): the presenting account itself, or — for an
   *  ASSUMED session (amr carries the OP-private marker) — the ORIGINAL
   *  grantee the session row stamps (sessions.assumed_by), so a chained
   *  switch never returns to the personal account first. A chain whose
   *  actor no longer resolves (the account erased, or a session row
   *  minted before the stamp existed) closes honestly: null answers no
   *  persona rows and a 403 on the attempt, and the jar's ordinary swap
   *  back to the personal account stays the way out. One bounded read,
   *  only for an assumed session. */
  async function assumptionPrincipalFor(active: { user: AuthUserPayload } | null): Promise<AuthUserPayload | null> {
    if (!active) return null
    if (!active.user.amr?.includes('assumed')) return active.user
    if (!active.user.assumedBy) return null
    return getStore().getUserById(active.user.assumedBy)
  }

  /** The persona-assumption mint — the ONE shared path (the chooser
   *  POST's click and the authorize persona= parameter alike): the
   *  session mints AS the persona, same shape as a completed sign-in
   *  minus the credential — writes SERIAL (the store seam's own
   *  discipline), amr carries the OP-private 'assumed' marker,
   *  assumed_by stamps the PRINCIPAL (a direct hop's grantee, a chain
   *  hop's ORIGINAL actor — carried verbatim). The journal records who
   *  assumed which persona for which client (the grant-holder of record,
   *  identically for a direct hop and a chained one) and never blocks
   *  the answer; the persona joins the caller's jar (one entry per
   *  account), so the next switch to it rides the ordinary live-session
   *  swap. Sets the session cookie and answers the token. */
  async function mintPersonaAssumption(c: Context, clientId: string, principal: AuthUserPayload, account: AuthUserPayload): Promise<string> {
    await getStore().touchLastLogin(account.id)
    const token = await getStore().createSession(account.id, { ...clientInfo(c), amr: ['assumed'], assumedBy: principal.id })
    try {
      await getStore().recordOpAssumption({
        id: crypto.randomUUID(),
        actorUserId: principal.id,
        actorEmail: principal.email,
        personaUserId: account.id,
        personaEmail: account.email,
        clientId,
        createdAt: new Date().toISOString(),
      })
    } catch (err) {
      console.error(`[op] the assumption journal write failed:`, (err as Error).message)
    }
    await audit('account.assumed', account.id, { userId: principal.id, userName: principal.name }, {
      actorEmail: principal.email,
      personaEmail: account.email,
      clientId,
      method: 'assumed',
    })
    setCookie(c, SESSION_COOKIE, token, sessionCookieOpts(c))
    touchAccountJar(c, token, account)
    return token
  }

  // GET /api/op/choose-account — the chooser page's context: the jar's
  // accounts, each re-judged against its live session row (the trust
  // posture — auth/op/account-jar.ts), the presenting account badged,
  // and the RP's display name resolved from the continue target's
  // client_id when the chooser rides an authorize flow. The request's
  // login_hint rides along: the matching entry answers `hinted` (the
  // page pre-selects it — a hint is never a decision, the click is) and
  // the raw value echoes back for the no-match prefill. Works signed
  // out (the jar may hold accounts while no session is active); an
  // invalid or absent `continue` reads as the standalone posture (the
  // chooser that ends at the account console).
  //
  // THE PERSONA ROWS (the grant-based assumption): when the presenting
  // session's account holds the declared grant, the chooser ALSO lists
  // the declared demo personas (`assumable` — the row's click assumes
  // the persona, no persona password ever presented). An ASSUMED session
  // lists them on the ORIGINAL grantee's standing (the persona→persona
  // chaining — assumptionPrincipalFor), so the switch never returns to
  // the personal account first. An account without a grant — and the
  // signed-out posture — never sees them.
  op.get('/api/op/choose-account', async (c) => {
    await ensureSeeded(c)
    const continueTarget = sanitizeContinueTarget(c.req.query('continue'))
    const loginHint = c.req.query('login_hint')?.trim().toLowerCase() || null
    const [active, resolved] = await Promise.all([activeJarContext(c), resolveAccountJar(c)])
    // The RP's name (display only): the continue target's client_id.
    let clientName: string | null = null
    if (continueTarget) {
      const clientId = new URL(continueTarget, 'http://op.local').searchParams.get('client_id')
      if (clientId) clientName = (await getStore().getOidcClient(clientId))?.name ?? null
    }
    // The org display names, one read per distinct org (the jar's and
    // the declared personas').
    const posture = personaGrantsFor(c)
    const personaEmails = new Set(posture?.personas.map(p => p.email) ?? [])
    // The grant verdict judges the PRINCIPAL — the presenting account,
    // or the original grantee behind an assumed session (the chaining).
    const principal = await assumptionPrincipalFor(active ? { user: active.user } : null)
    const granted = !!posture && !!principal && grantsAllowEmail(posture.grants, principal.email, personaEmails)
    const personas = granted ? posture!.personas : []
    // The persona row's display truth is the LIVE account row — one
    // admin rename fixes every surface the persona appears on; the seed
    // declaration is the fallback for a persona whose account is not
    // provisioned yet. One read per persona: the declaration bounds the
    // set, never the row count.
    const personaAccounts = new Map<string, AuthUserPayload | null>()
    for (const p of personas) {
      personaAccounts.set(p.email, await getStore().findUserByEmail(p.email))
    }
    const personaOrgId = (p: DeclaredPersona) => personaAccounts.get(p.email)?.orgId ?? p.orgId
    const orgIds = [...new Set([
      ...resolved.map(r => r.entry.orgId),
      ...personas.map(p => personaOrgId(p)),
    ].filter((id): id is string => !!id))]
    const orgNames = new Map<string, string | null>()
    for (const id of orgIds) {
      orgNames.set(id, (await getStore().getOrgRegistryOrg(id))?.name ?? null)
    }
    // The jar never duplicates a RENDERED persona: a past assumption
    // joined the persona to the jar, and the assumable row IS the same
    // account — the persona row (the grant's own surface) wins, the jar
    // row drops. The filter keys on the RENDERED set only: an ungranted
    // posture lists no personas and hides nothing.
    const renderedPersonaEmails = new Set(personas.map(p => p.email))
    const jarRows = resolved.filter(r =>
      !renderedPersonaEmails.has((r.live && r.user ? r.user.email : r.entry.email).trim().toLowerCase()))
    return c.json({
      continue: continueTarget,
      loginHint,
      client: clientName ? { name: clientName } : null,
      currentUserId: active?.user.id ?? null,
      accounts: [
        ...jarRows.map(({ entry, live, user }) => ({
          userId: entry.userId,
          name: live && user ? user.name : entry.displayName,
          email: live && user ? user.email : entry.email,
          // THE PHOTO (2026-09-23's report): the avatar is PUBLIC data —
          // the /op/avatar/<id> route serves the stored photo or the
          // generated-initials SVG for any non-erased account, live or
          // not. The trust posture hides the dead entry's name/email,
          // never its public photo. A live user's OWN avatarUrl (a
          // provider photo) wins over the route.
          avatarUrl: (live && user?.avatarUrl) || (entry.userId ? `/op/avatar/${entry.userId}` : null),
          org: entry.orgId ? (orgNames.get(entry.orgId) ?? entry.orgId) : null,
          live,
          current: !!active && active.user.id === entry.userId,
          hinted: loginHint !== null && (live && user ? user.email : entry.email).trim().toLowerCase() === loginHint,
          assumable: false,
        })),
        ...personas.map(p => {
          const account = personaAccounts.get(p.email) ?? null
          const orgId = personaOrgId(p)
          return {
            userId: null as string | null,
            name: account?.name ?? p.name,
            email: p.email,
            // The same public-photo doctrine as the jar rows: the account
            // row's own photo wins, else the avatar route's serve.
            avatarUrl: account ? (account.avatarUrl || `/op/avatar/${account.id}`) : null,
            org: orgId ? (orgNames.get(orgId) ?? orgId) : null,
            live: true,
            current: !!active && active.user.email.trim().toLowerCase() === p.email,
            hinted: loginHint !== null && p.email === loginHint,
            assumable: true,
          }
        }),
      ],
    })
  })

  // POST /api/op/choose-account — continue as the named account. A LIVE
  // jar entry: the active session cookie swaps to the remembered token
  // (the old session row stays alive — switching accounts never signs
  // the other account out), the jar refreshes its order, and the answer
  // carries the navigation target (the authorize re-entry, or the
  // account console for the standalone chooser). No live session behind
  // the choice: the honest fallback — the login page with the flow's
  // re-entry target and the remembered email prefilled — UNLESS the
  // choice names a DECLARED persona the presenting account is GRANTED
  // to assume: then the assumption mints (the grant-based posture, the
  // route's verdict — never the page's claim).
  op.post('/api/op/choose-account', async (c) => {
    await ensureSeeded(c)
    const body = await c.req.json<{ userId?: string; email?: string; continue?: string }>().catch(() => null)
    if (!body || (typeof body.userId !== 'string' || !body.userId) && (typeof body.email !== 'string' || !body.email)) {
      return c.json({ error: 'userId or email is required' }, 400)
    }
    const continueTarget = sanitizeContinueTarget(body.continue)
    const target = body.userId ? await liveJarEntryForUser(c, body.userId) : null
    if (!target) {
      // ── the persona-assumption attempt (the grant-based posture) ──
      // Only a DECLARED persona address can take this branch, and only
      // a LIVE presenting session holding the GRANT may mint — every
      // verdict re-reads the declaration and the store, never the page.
      // The address resolves from the caller's own claim or the named
      // account's row (an assumed persona's dead jar row POSTs the
      // userId) — but a row-derived address NEVER rides an answer: the
      // prefill is the requester's own jar entry or the address the
      // caller itself sent (the id is not a secret; the email is).
      const bodyEmail = typeof body.email === 'string' && body.email ? body.email.trim().toLowerCase() : null
      const requestedEmail = bodyEmail
        ?? (await getStore().getUserById(body.userId ?? ''))?.email.trim().toLowerCase()
        ?? null
      const posture = personaGrantsFor(c)
      const persona = posture && requestedEmail ? declaredPersonaByEmail(posture.personas, requestedEmail) : null
      const active = persona ? await activeJarContext(c) : null
      if (persona && active) {
        // The verdict judges the PRINCIPAL: the presenting account, or —
        // for an assumed session — the original grantee it stamps (the
        // persona→persona chain; assumptionPrincipalFor's doctrine). A
        // chain whose actor fails the grant is refused exactly like an
        // ungranted presenting account.
        const principal = await assumptionPrincipalFor(active)
        const personaEmails = new Set(posture!.personas.map(p => p.email))
        if (!principal || !grantsAllowEmail(posture!.grants, principal.email, personaEmails)) {
          return c.json({ error: 'the presenting account is not granted the persona assumption' }, 403)
        }
        const account = await getStore().findUserByEmail(persona.email)
        if (!account) {
          // The declaration runs ahead of the roster (the seed has not
          // landed yet): the honest fallback, never a guess.
          return c.json({ ok: false, login: loginUrlForContinue(continueTarget, bodyEmail) })
        }
        // The mint is the ONE shared path (mintPersonaAssumption — the
        // authorize persona= parameter takes it identically).
        await mintPersonaAssumption(c, posture!.grants.clientId, principal, account)
        return c.json({ ok: true, redirect: continueTarget ?? '/op/account' })
      }
      // The honest fallback: the remembered entry (if the jar still
      // knows the account) lends its email to the login prefill — never
      // the named account's own address.
      const entry = body.userId
        ? (await resolveAccountJar(c)).find(r => r.entry.userId === body.userId)
        : undefined
      return c.json({ ok: false, login: loginUrlForContinue(continueTarget, entry?.entry.email ?? bodyEmail) })
    }
    setCookie(c, SESSION_COOKIE, target.entry.sessionId, sessionCookieOpts(c))
    // The chosen account moves to the jar's front (the LRU refresh) —
    // the same act a fresh sign-in would perform.
    touchAccountJar(c, target.entry.sessionId, target.payload)
    return c.json({ ok: true, redirect: continueTarget ?? '/op/account' })
  })

  return op
}
