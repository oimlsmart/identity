// ═══════════════════════════════════════════════════════════════════
// TODO.sota/07.4 — the END-SESSION module, extracted from op.ts as the
// fourth proof of the domain-model split (the pure refactor; the golden
// + the suite are the proof — zero behavior change).
//
// GET/POST /op/endsession — RP-Initiated Logout 1.0: the RP's redirect
// (or form POST) lands with the id_token_hint, client_id,
// post_logout_redirect_uri + state. The ACT is the point: the agent's
// OP session ends (the cookie's row + the cookie) and the OP-initiated
// backchannel fan-out notifies the account's other live-grant clients
// (fire-and-forget — the answer never waits on an RP). The redirect is
// courtesy: it fires ONLY to a URI the RESOLVED client registered in
// its logout block (the open-redirector guard); every other shape
// answers the honest signed-out page. A hint that fails validation
// never blocks the act — it only narrows the client resolution to the
// client_id param; an EXPIRED hint stays valid (the spec's rule).
// ═══════════════════════════════════════════════════════════════════

import { Hono, type Context } from 'hono'
import { deleteCookie, getCookie } from 'hono/cookie'
import { env as runtimeEnv } from 'hono/adapter'
import { getStore } from '../store'
import { SESSION_COOKIE } from '../session'
import { opJwks } from '../auth/op/keys'
import { logoutBlockOf, prepareBackchannelLogout, verifyOpIdTokenHint } from '../auth/op/logout'
import { dropAccountJarSession } from '../auth/op/account-jar'
import { opRequestOrigin, resolveOpConfig } from '../auth/op/config'

type EnvLike = Record<string, string | undefined>

/** The request's effective OP config (env + this request's origin) —
 *  the same formula every OP route reads. */
function configFor(c: Context) {
  return resolveOpConfig(runtimeEnv<EnvLike>(c), opRequestOrigin(c.req.raw))
}

/** The signed-out page: the end-session's honest landing when no
 *  REGISTERED post_logout_redirect_uri applies (absent, or not on the
 *  resolved client's logout block — the open-redirector guard never
 *  redirects to an unregistered URI). Server-rendered and
 *  dependency-free, the authorizeRefusal doctrine. */
function signedOutPage(c: Context): Response {
  return c.html(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark"><meta name="theme-color" content="#004996">
<title>Signed out — OIML SMART Identity</title>
<style>
  body { font-family: ui-sans-serif, system-ui, sans-serif; background: #faf8f5; color: #0f172a; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; }
  main { max-width: 28rem; padding: 2rem; background: #fff; border: 1px solid #e2e8f0; border-radius: 0.75rem; }
  h1 { font-size: 1.125rem; margin: 0 0 0.5rem; } p { font-size: 0.875rem; color: #475569; margin: 0; }
  p.home { margin-top: 1rem; } a { color: #004996; }
  @media (prefers-color-scheme: dark) { body { background: #0f172a; color: #fff; } main { background: #1e293b; border-color: #334155; } p { color: #94a3b8; } a { color: #7cb3ff; } }
</style></head>
<body><main><h1 data-testid="op-signed-out">Signed out</h1><p>Your session on this identity provider has ended. You can close this page, or return to the sign-in page.</p><p class="home"><a href="/" data-testid="op-signed-out-home">Back to the sign-in page</a></p></main></body></html>`, 200)
}

export function createOpEndSessionRouter(deps: { ensureSeeded: (c: Context) => Promise<void> }): Hono {
  const router = new Hono()

  const endSession = async (c: Context) => {
    await deps.ensureSeeded(c)
    const config = configFor(c)
    const params = c.req.method === 'POST'
      ? new URLSearchParams(await c.req.raw.text())
      : new URL(c.req.url).searchParams
    const hint = params.get('id_token_hint')?.trim() || null
    const clientIdParam = params.get('client_id')?.trim() || null
    const postLogout = params.get('post_logout_redirect_uri')?.trim() || null
    const state = params.get('state') ?? null

    const store = getStore()
    // The hint validates against the LOCAL registered keyset (the OP's
    // own mint — never an HTTP fetch).
    const verified = hint ? await verifyOpIdTokenHint((await opJwks(store)).keys, config.issuer, hint) : null
    const client = await store.getOidcClient(verified?.aud ?? clientIdParam ?? '')

    // The session ends FIRST; the fan-out's targets collect BEFORE the
    // delete (the grant set is the one the ending presence belonged to).
    // No live session → nothing to notify (the redirect/honest page
    // still stands — the RP's user IS signed out).
    const sessionToken = getCookie(c, SESSION_COOKIE)
    const sessionOwner = sessionToken ? await store.getSessionUser(sessionToken) : null
    if (sessionToken && sessionOwner) {
      const floatBackchannel = await prepareBackchannelLogout(c, runtimeEnv<EnvLike>(c), c.req.raw, sessionOwner.id)
      await store.deleteSession(sessionToken)
      deleteCookie(c, SESSION_COOKIE, { path: '/' })
      // The account jar (the chooser wave): the ended session's entry
      // goes; the other remembered accounts stay.
      dropAccountJarSession(c, sessionToken)
      floatBackchannel()
    } else if (sessionToken) {
      // The cookie named a dead/expired row — clear it honestly (the
      // jar's matching entry goes with it).
      deleteCookie(c, SESSION_COOKIE, { path: '/' })
      dropAccountJarSession(c, sessionToken)
    }

    // The redirect's guard: ONLY a registered URI of the RESOLVED,
    // ACTIVE client — an unknown/disabled client or an unregistered URI
    // never redirects (the page stands).
    const logout = logoutBlockOf(client?.claimsPolicy ?? null)
    if (client?.status === 'active' && postLogout && logout?.post_logout_redirect_uris.includes(postLogout)) {
      const back = new URL(postLogout)
      if (state) back.searchParams.set('state', state)
      return c.redirect(back.toString())
    }
    return signedOutPage(c)
  }
  router.get('/op/endsession', endSession)
  router.post('/op/endsession', endSession)

  return router
}
