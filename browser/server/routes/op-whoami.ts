// ═══════════════════════════════════════════════════════════════════
// The whoami beacon (the estate's SSO-UX last mile — smart's
// docs/future/07 Part I.3 item 3): GET /op/whoami answers the current
// OP session's MINIMAL projection for the static properties' account
// chips (www + the minisites render the signed-in face without a full
// RP round trip).
//
//   signed out  → { "signedIn": false }                    — cheap and
//                 cacheable (public, short max-age; Vary: Cookie, so a
//                 cookie-bearing request never takes the anonymous
//                 cached answer);
//   signed in   → { signedIn: true, name, picture, admin } — never
//                 cached (no-store): name is the display name; picture
//                 is the PUBLIC avatar URL (the session-less serve,
//                 routes/op.ts's /op/avatar/<id> — the GitHub-avatars
//                 convention, null without an upload so the chip renders
//                 its initials fallback); admin is the home feed's ONE
//                 rule (op-home.ts: admin || cs_admin). NEVER emails,
//                 never roles, never orgs — the chip needs a face, not
//                 a dossier.
//
// THE CORS POSTURE (the static sites fetch cross-origin WITH
// credentials — the oiml-session cookie is same-site on
// id.oimlsmart.org, so it rides): the allowed origins are DERIVED from
// the live client registry — every ACTIVE client's launch URL origin +
// redirect-URI origins (the registered properties' host list), never a
// hand-maintained list and never '*'. A request whose Origin is
// allowlisted gets the reflected access-control-allow-origin +
// allow-credentials; a request naming a FOREIGN origin gets NO CORS
// headers (the browser blocks the read; the answer itself stays a plain
// 200 — curl and same-origin callers read it without an Origin header).
// The machine classes contribute nothing (no launch card, no redirect
// URIs — the machine cone is never a chip surface).
//
// Profile-gated like every OP route (a non-identity deployment answers
// 404). WORKER-SAFE: the store seam only, no node built-ins.
// ═══════════════════════════════════════════════════════════════════

import { Hono, type Context, type MiddlewareHandler } from 'hono'
import { env as runtimeEnv } from 'hono/adapter'
import { getStore, type ServerStore } from '@oimlsmart/platform-server/store'
import { getInstanceProfile } from '@oimlsmart/platform-server/profile'
import { sessionUser } from '@oimlsmart/platform-server/session'
import { opRequestOrigin, resolveOpConfig } from '../auth/op/config'

type EnvLike = Record<string, string | undefined>

/** The beacon's allowlist: the ORIGINS the registered, ACTIVE clients
 *  declare — every launch URL's origin and every redirect URI's origin.
 *  Derived per request (the registry is small, and an admin's registry
 *  act takes effect at once — never a stale memo). */
export async function whoamiAllowedOrigins(store: ServerStore): Promise<Set<string>> {
  const origins = new Set<string>()
  for (const client of await store.listOidcClients()) {
    if (client.status !== 'active') continue
    for (const url of [client.launch?.url, ...client.redirectUris]) {
      if (!url) continue
      try { origins.add(new URL(url).origin) } catch { /* a malformed stored URI never breaks the beacon */ }
    }
  }
  return origins
}

/** The CORS headers for this request: the reflected origin ONLY when the
 *  request carries an allowlisted one (never '*', never a foreign
 *  origin). `Vary: Origin` rides whenever the answer could differ. */
function whoamiCorsHeaders(c: Context, allowed: Set<string>): Record<string, string> {
  const origin = c.req.header('origin')
  if (!origin) return {}
  if (!allowed.has(origin)) return { vary: 'Origin' }
  return {
    'access-control-allow-origin': origin,
    'access-control-allow-credentials': 'true',
    vary: 'Origin',
  }
}

export function createOpWhoamiRouter(): Hono {
  const whoami = new Hono()

  // ── the profile gate (the same posture as routes/op.ts: the route
  // exists in the ONE build, the identity module decides) ─────────────
  const profileGate: MiddlewareHandler = async (c, next) => {
    if (!getInstanceProfile().modules.includes('identity')) {
      return c.json({ error: 'not found' }, 404)
    }
    await next()
  }
  whoami.use('/op/whoami', profileGate)

  // OPTIONS /op/whoami — the preflight: the allowlisted origin's
  // credentialed GET admitted; a foreign origin answers bare (the
  // browser blocks the fetch before it ever leaves).
  whoami.options('/op/whoami', async (c) => {
    const allowed = await whoamiAllowedOrigins(getStore())
    const headers = whoamiCorsHeaders(c, allowed)
    if (headers['access-control-allow-origin']) {
      headers['access-control-allow-methods'] = 'GET'
      headers['access-control-max-age'] = '300'
    }
    return c.body(null, 204, headers)
  })

  // GET /op/whoami — the session's minimal projection (the contract is
  // the header above).
  whoami.get('/op/whoami', async (c) => {
    const allowed = await whoamiAllowedOrigins(getStore())
    const cors = whoamiCorsHeaders(c, allowed)
    const user = await sessionUser(c)
    if (!user) {
      // The anonymous answer: cheap and cacheable — Vary: Cookie keeps a
      // signed-in visitor's cookie-bearing request off the cached entry.
      return c.json({ signedIn: false }, 200, {
        ...cors,
        'cache-control': 'public, max-age=60',
        vary: [cors.vary, 'Cookie'].filter(Boolean).join(', '),
      })
    }
    const config = resolveOpConfig(runtimeEnv<EnvLike>(c), opRequestOrigin(c.req.raw))
    return c.json({
      signedIn: true,
      name: user.name,
      // The PUBLIC avatar URL (the session-less serve) or null — the chip
      // renders its initials fallback on null, exactly like the console.
      picture: user.avatarUrl ? `${config.issuer}/op/avatar/${user.id}` : null,
      // The home feed's ONE admin rule (op-home.ts) — the chip may offer
      // the administration console's entry.
      admin: user.role === 'admin' || user.role === 'cs_admin',
    }, 200, {
      ...cors,
      // The per-account projection is never cached anywhere.
      'cache-control': 'no-store',
    })
  })

  return whoami
}
