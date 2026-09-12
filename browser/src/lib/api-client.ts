// ═══════════════════════════════════════════════════════════════════
// The console pages' ONE fetch wrapper (TODO.restructure/08 — the seven
// per-page byte-identical copies dissolved): credentials always ride
// (the session cookie), a JSON body carries the content type, and every
// other init field passes through. A cross-cutting change (an
// auth-error redirect, a retry posture) lands HERE, never in seven
// files. The login page's bounded-fetch variant stays local — its
// abort-timeout bound is that page's own ceremony.
// ═══════════════════════════════════════════════════════════════════
export async function api(path: string, init?: RequestInit): Promise<Response> {
  return fetch(path, {
    credentials: 'include',
    ...(init?.body ? { headers: { 'content-type': 'application/json' } } : {}),
    ...init,
  })
}
