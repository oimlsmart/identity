// ─────────────────────────────────────────────────────────────────────
// The RFC 9116 security.txt's worker routing (TODO.modern/14) — the
// same posture as the discovery document beside it: the Hono API
// answers this inside the worker (routes in server/app.ts); under the
// node posture the dev proxy forwards the path to the API server
// before Astro ever sees it. prerender = false: never a build-time
// page.
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
  const { handleWorkerApi } = await import('../../../server/cloudflare')
  return handleWorkerApi(request, env)
}
