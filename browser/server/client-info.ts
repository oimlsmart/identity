// ═══════════════════════════════════════════════════════════════════
// The request's client context (TODO.identity/06) — the user agent and
// the client IP, stamped on the session row at creation so the account
// console's sessions section can name every sign-in. The IP resolves
// from the platform's proxy headers (the Worker's cf-connecting-ip
// first, then the first x-forwarded-for hop, the rate-limit.ts rule);
// a request that carries neither records NULL, and the console says
// "not recorded" — never a guessed value.
//
// WORKER-SAFE: headers only, no node built-ins.
// ═══════════════════════════════════════════════════════════════════

import type { KernelContext } from './context'

export interface ClientInfo {
  userAgent: string | null
  ip: string | null
}

export function clientInfo(c: KernelContext): ClientInfo {
  const ua = c.req.header('user-agent') ?? null
  const forwarded = c.req.header('x-forwarded-for')?.split(',')[0]?.trim()
  const ip = c.req.header('cf-connecting-ip') ?? (forwarded || null)
  return { userAgent: ua || null, ip }
}
