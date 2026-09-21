// ═══════════════════════════════════════════════════════════════════
// The bot gate's armed posture, read once per page (TODO.modern/01's
// widget half): /api/config carries the SITE key only when the gate is
// armed — null mounts nothing, and the server's own gate is the
// arbiter regardless of what the page decided.
// ═══════════════════════════════════════════════════════════════════

export async function fetchTurnstileSiteKey(): Promise<string | null> {
  try {
    const res = await fetch('/api/config')
    if (!res.ok) return null
    const cfg = await res.json() as { turnstile?: { siteKey?: string | null } }
    return cfg.turnstile?.siteKey ?? null
  } catch {
    return null
  }
}
