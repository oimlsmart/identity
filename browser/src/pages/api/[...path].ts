// ─────────────────────────────────────────────────────────────────────
// The /api/* catch-all (TODO.cs-e2e/14 — the Cloudflare deployment).
//
// Under the Cloudflare adapter the Hono API (server/app.ts, composed by
// server/cloudflare.ts) answers /api/* INSIDE the same worker — the D1
// binding in the workerd env is the store. Under the node adapter this
// endpoint is inert: the dev proxy forwards /api to the tsx API server
// before Astro ever sees it, and a production node deployment fronts
// /api with its own server — so the cloudflare:workers import rejects,
// the endpoint answers a plain 404, and nothing changes.
//
// prerender = false: the API is never a build-time page.
// ─────────────────────────────────────────────────────────────────────

import type { APIRoute } from 'astro'

export const prerender = false

/** The workerd env when this build runs under the Cloudflare adapter;
 *  null in the node posture (the module scheme exists only in workerd;
 *  the node build marks it external so the import rejects at runtime). */
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
