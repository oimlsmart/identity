// ═══════════════════════════════════════════════════════════════════
// The trusted-device cookie (0042, the SOTA arc): the shared seam for
// the "remember this browser" grant — the cookie's name, its 14-day
// TTL, and its opts. The SKIP the cookie buys lives at the login
// branch (op-accounts.ts); the MINT lives at the factor completions
// (op-mfa.ts); the KILL lives at every credential-replacement act.
// WORKER-SAFE: hono's cookie helpers only.
// ═══════════════════════════════════════════════════════════════════

import type { Context } from 'hono'
import { env as runtimeEnv } from 'hono/adapter'

export const TRUST_COOKIE = 'oiml-mfa-device'
export const TRUST_DEVICE_TTL_MS = 14 * 24 * 3600_000

export function trustCookieOpts(c: Context) {
  return {
    httpOnly: true,
    secure: runtimeEnv<{ NODE_ENV?: string }>(c).NODE_ENV === 'production',
    sameSite: 'Lax' as const,
    maxAge: Math.floor(TRUST_DEVICE_TTL_MS / 1000),
    path: '/',
  }
}
