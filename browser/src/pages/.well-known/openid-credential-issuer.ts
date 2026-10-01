// The OIDC4VCI credential-issuer metadata's production shim
// (TODO.sota/08-09): under the Cloudflare adapter the Hono API answers
// this inside the worker (routes/op-credentials.ts); this page is the
// front-door delegate the Worker's static shell needs — the id-v2026.10.02-1
// lesson, now held by the routing guard's server half. Under the node
// posture the dev proxy forwards the path and this answers 404 (the
// discovery shim's exact posture).
//
// prerender = false: the document is per-request.

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

export const GET: APIRoute = async ({ request }) => {
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
