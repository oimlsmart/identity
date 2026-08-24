// ─────────────────────────────────────────────────────────────────────
// The OIDC Provider's JWKS (TODO.identity/01) — the public halves of
// the OP's ES256 key history.
//
// Same dual posture as the sibling well-known endpoint: the worker's
// Hono API answers it (routes/op.ts); the node posture proxies it to
// the API server in dev and fronts it with its own server in
// production, so this endpoint answers a plain 404 there.
//
// prerender = false: the key set is never a build-time page.
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
  const { handleWorkerApi } = await import('../../server/cloudflare')
  return handleWorkerApi(request, env)
}
