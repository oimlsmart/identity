// ─────────────────────────────────────────────────────────────────────
// The OIDC Provider's API endpoints under /op (TODO.identity/01):
// authorize, token, userinfo (the consent PAGE, /op/consent, is the
// astro shell src/pages/op/consent.astro — a static route, which Astro
// always prefers over this rest-parameter endpoint, so the two never
// collide).
//
// Same dual posture as the /api catch-all: the worker's Hono API
// answers inside the same worker; the node posture's dev proxy forwards
// these paths to the API server, so this endpoint answers a plain 404
// there.
//
// prerender = false: the OP endpoints are never build-time pages.
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
  const { handleWorkerApi } = await import('../../../server/cloudflare')
  return handleWorkerApi(request, env)
}
