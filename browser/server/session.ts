// ═══════════════════════════════════════════════════════════════════
// The session seam (TODO.identity-extract/01, the map: PROGRESS/41
// §1.4): the `oiml-session` cookie + the store's getSessionUser,
// unified from the per-router inline copies (routes/auth.ts, op.ts,
// op-accounts.ts and their nine federation/entity siblings). The cookie
// name is the contract — live sessions survive the extraction.
//
// WORKER-SAFE: hono's cookie/adapter helpers only, no node built-ins.
// The public signatures take the structural KernelContext (see
// context.ts) — never hono's own Context — so the consumer's and the
// kernel's hono instances never meet nominally.
// ═══════════════════════════════════════════════════════════════════

import type { Context } from 'hono'
import { getCookie } from 'hono/cookie'
import { env as runtimeEnv } from 'hono/adapter'
import { getStore, type AuthUserPayload } from './store'
import { requestIsSecure } from './auth/op/config'
import type { KernelContext } from './context'

export type { KernelContext } from './context'

export const SESSION_COOKIE = 'oiml-session'

/** The session's user payload for the request, or null (no cookie or
 *  an expired/unknown token). */
export async function sessionUser(c: KernelContext): Promise<AuthUserPayload | null> {
  // The cast is the seam: a KernelContext IS a hono Context at runtime
  // (every caller passes one); the structural type only keeps the two
  // hono module instances from meeting in the type graph.
  const token = getCookie(c as Context, SESSION_COOKIE)
  return token ? getStore().getSessionUser(token) : null
}

/** The cookie posture follows the REQUEST, never NODE_ENV (2026-10-12,
 *  the cold-eyes audit): the Worker's env bindings never carry NODE_ENV,
 *  so `secure` evaluated false in production — the session cookie rode
 *  plain http. The https scheme or a declared https issuer decides
 *  (auth/op/config.ts's requestIsSecure). */
export function sessionCookieOpts(c: KernelContext) {
  return {
    httpOnly: true,
    secure: requestIsSecure(c.req.raw, runtimeEnv<{ OP_ISSUER?: string }>(c as Context)),
    sameSite: 'Lax' as const,
    maxAge: 7 * 24 * 60 * 60,
    path: '/',
  }
}
