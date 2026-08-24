// ─────────────────────────────────────────────────────────────────────
// The OIDC Provider's discovery document (TODO.identity/01).
//
// Under the Cloudflare adapter the Hono API answers this inside the
// worker (routes/op.ts, mounted by server/app.ts — 404 unless the
// instance profile carries the identity module). Under the node posture
// the dev proxy (astro.config) forwards the path to the API server
// before Astro ever sees it, so the cloudflare:workers import rejects,
// the endpoint answers a plain 404, and nothing changes (the exact
// posture of src/pages/api/[...path].ts and the federation descriptor's
// well-known endpoint).
//
// prerender = false: discovery is never a build-time page.
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
