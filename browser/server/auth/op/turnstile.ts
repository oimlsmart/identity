// ═══════════════════════════════════════════════════════════════════
// The bot gate (TODO.modern/01) — Cloudflare Turnstile on the public
// credential surfaces. Config-gated: TURNSTILE_SITE_KEY +
// TURNSTILE_SECRET, BOTH declared, or the gate is OFF and every
// surface's behavior is byte-identical (the doctrine: configuration
// over hardcoding). WORKER-SAFE: fetch + WebCrypto only.
//
// The refusal posture: 403 with the bot-shaped error, BEFORE any
// credential work — never a 401 shape (a bot answer must differ from
// an auth answer; no enumeration aid).
// ═══════════════════════════════════════════════════════════════════

type EnvLike = Record<string, string | undefined>

/** The gate's posture: both declarations present, or off. */
export function turnstileEnabled(env: EnvLike): boolean {
  return Boolean(env.TURNSTILE_SITE_KEY?.trim() && env.TURNSTILE_SECRET?.trim())
}

/** Verify a Turnstile token server-side (the siteverify round trip).
 * The remote IP rides along (the honest posture; absent is fine). */
export async function turnstileVerify(env: EnvLike, token: string, ip: string | null): Promise<boolean> {
  const secret = env.TURNSTILE_SECRET
  if (!secret) return false
  try {
    const body = new URLSearchParams({ secret, response: token })
    if (ip) body.set('remoteip', ip)
    const res = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: body.toString(),
    })
    if (!res.ok) return false
    const verdict = await res.json() as { success?: boolean }
    return verdict.success === true
  } catch {
    // The gate never fails OPEN on a network error — a broken
    // siteverify refuses the act (fail-closed), honestly retriable.
    return false
  }
}
