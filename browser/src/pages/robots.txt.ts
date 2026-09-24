// ─────────────────────────────────────────────────────────────────────
// The robots.txt's worker routing (the owner directive: no OIML SMART
// property is indexed) — the same posture as the security.txt shim: the
// Hono API answers this inside the worker (the route in server/app.ts);
// under the node posture the dev proxy fronts the API server, so this
// endpoint answers a plain 404 there. prerender = false: never a
// build-time page.
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
    return new Response('not found', { status: 404, headers: { 'content-type': 'text/plain' } })
  }
  const { handleWorkerApi } = await import('../../server/cloudflare')
  return handleWorkerApi(request, env)
}
