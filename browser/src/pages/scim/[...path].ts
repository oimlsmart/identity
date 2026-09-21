// ─────────────────────────────────────────────────────────────────────
// The SCIM 2.0 provisioning surface's worker shim (TODO.modern/05):
// the same dual posture as the /api and /op catch-alls — the worker's
// Hono API answers inside the same worker; under the node posture the
// dev proxy forwards /scim to the API server, so this endpoint answers
// a plain 404 there. prerender = false: never a build-time page.
// (The route's absence here is why production answered the Astro 404
// page for /scim/* — the API never saw the request — for as long as
// the surface shipped unset; the bearer posture's own 404 masked it.)
// ─────────────────────────────────────────────────────────────────────

import type { APIRoute } from 'astro'

export const prerender = false

async function cloudflareEnv(): Promise<Cloudflare.Env | null> {
  try {
    const mod = await import('cloudflare:workers')
    return mod.env
  } catch {
    return null
  }
}

export const ALL: APIRoute = async ({ request }) => {
  const env = await cloudflareEnv()
  if (!env?.DB) {
    return new Response(JSON.stringify({ error: 'not found' }), {
      status: 404,
      headers: { 'content-type': 'application/json' },
    })
  }
  const { handleWorkerApi } = await import('../../server/cloudflare')
  return handleWorkerApi(request, env)
}
