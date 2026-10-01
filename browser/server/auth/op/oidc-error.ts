// ═══════════════════════════════════════════════════════════════════
// The OAuth/OIDC error body (RFC 6749 §5.2), never a stack trace —
// the ONE helper every OP route module shares (TODO.sota/07.4's split
// pulled it out of routes/op.ts).
// ═══════════════════════════════════════════════════════════════════

import type { Context } from 'hono'

export function oidcError(c: Context, status: 400 | 401, error: string, description: string): Response {
  return c.json({ error, error_description: description }, status)
}
