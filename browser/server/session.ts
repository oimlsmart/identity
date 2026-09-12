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

/** The cookie posture follows the request's runtime env (hono/adapter
 *  reads c.env on the Worker, process.env on node — the one env seam
 *  both platforms share, TODO.cs-e2e/14). */
export function sessionCookieOpts(c: KernelContext) {
  return {
    httpOnly: true,
    secure: runtimeEnv<{ NODE_ENV?: string }>(c as Context).NODE_ENV === 'production',
    sameSite: 'Lax' as const,
    maxAge: 7 * 24 * 60 * 60,
    path: '/',
  }
}
