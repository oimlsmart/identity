// ═══════════════════════════════════════════════════════════════════
// TODO.sota/07.4 — the SESSION MANAGEMENT module, extracted from op.ts
// as the third proof of the domain-model split (the pure refactor; the
// golden + the suite are the proof — zero behavior change).
//
// The RP's session observation (TODO.modern/03, the OIDC Session
// Management poll): the RP embeds /op/session/check (this OP's origin,
// so the cookie rides), posts `client_id=…&session_state=…` at it, and
// the iframe answers 'unchanged'/'changed' via postMessage — the
// recomputation runs per poll against the LIVE session (a revoked or
// signed-out session is an honest 'changed', the state endpoint
// refusing). Any failure of the poll itself is ALSO 'changed' — the
// fail-closed direction (the RP re-authenticates; it never trusts a
// dead session). client_secret is deliberately unused here: no RP
// secret belongs in browser JS (the public-client posture; the
// confidential client authenticates at the token endpoint, never in an
// iframe).
//
// The check iframe's own script hash (TODO.modern/19): the CSP's
// script-src names the EXACT inline script the iframe carries —
// computed once per isolate from the same literal the answer serves
// (WebCrypto, worker-safe), so an edit to the poll re-derives the hash
// and never rots into a stale allowlist.
// ═══════════════════════════════════════════════════════════════════

import { Hono, type Context } from 'hono'
import { getCookie } from 'hono/cookie'
import { getStore } from '../store'
import { SESSION_COOKIE } from '../session'
import { computeSessionState } from '../auth/op/session-state'

/** The check iframe's poll script (TODO.modern/03, verbatim): the
 *  ONE inline script this OP renders — its hash IS the iframe CSP's
 *  script-src (TODO.modern/19; the constant + the hash derive from
 *  the same literal, and the sec-headers spec recomputes it from the
 *  served html). */
const CHECK_IFRAME_POLL = [
  'window.addEventListener("message", function (e) {',
  '  var params = new URLSearchParams(String(e.data || ""))',
  '  var cid = params.get("client_id")',
  '  var ss = params.get("session_state")',
  '  if (!cid) return',
  '  fetch("/op/session/state?client_id=" + encodeURIComponent(cid) + "&origin=" + encodeURIComponent(e.origin), { credentials: "include" })',
  '    .then(function (r) { return r.ok ? r.json() : null })',
  '    .then(function (body) {',
  '      var state = (body && body.session_state && ss && body.session_state === ss) ? "unchanged" : "changed"',
  '      e.source.postMessage(state, e.origin)',
  '    })',
  '    .catch(function () { e.source.postMessage("changed", e.origin) })',
  '})',
].join('\n')

export function createOpSessionManagementRouter(): Hono {
  const router = new Hono()

  let checkIframeHashP: Promise<string> | null = null
  const checkIframeHash = (): Promise<string> => {
    checkIframeHashP ??= crypto.subtle
      .digest('SHA-256', new TextEncoder().encode(`\n${CHECK_IFRAME_POLL}\n`))
      .then(digest => `'sha256-${btoa(String.fromCharCode(...new Uint8Array(digest)))}'`)
    return checkIframeHashP
  }

  router.get('/op/session/check', async (c: Context) => {
    const clientId = c.req.query('client_id')?.trim() ?? ''
    if (!clientId) {
      return c.html('<!doctype html><html><body><p>client_id is required</p></body></html>', 400)
    }
    const html = `<!doctype html><html><body><script>\n${CHECK_IFRAME_POLL}\n<\/script></body></html>`
    return c.html(
      html,
      200,
      {
        // Frameable by ANY RP (the poll's whole point) — the CSP form;
        // the X-Frame-Options header has no allow-all value. The
        // script-src names the iframe's ONE inline script (TODO.modern/19).
        'content-security-policy': `frame-ancestors *; script-src ${await checkIframeHash()}`,
        'cache-control': 'no-store',
      },
    )
  })

  // The digest the iframe compares against: the live session's
  // session_state for (client_id, RP origin). 401 = no live session =
  // the honest 'changed'. One point read (the session's own), never a
  // list — the scaling gate's doctrine holds trivially.
  router.get('/op/session/state', async (c: Context) => {
    const clientId = c.req.query('client_id')?.trim() ?? ''
    const origin = c.req.query('origin')?.trim() ?? ''
    if (!clientId || !origin) {
      return c.json({ error: 'client_id and origin are required' }, 400)
    }
    const token = getCookie(c, SESSION_COOKIE)
    const user = token ? await getStore().getSessionUser(token) : null
    if (!user || !token) return c.json({ error: 'no session' }, 401)
    c.header('Cache-Control', 'no-store')
    return c.json({ session_state: await computeSessionState(clientId, origin, token) })
  })

  return router
}
