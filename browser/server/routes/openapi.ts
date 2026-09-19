// ═══════════════════════════════════════════════════════════════════
// The spec-serving endpoint: GET /api/openapi.json — the identity
// service's OpenAPI 3.1 document (server/openapi/spec.ts, edition 1),
// machine-consumable at the canonical path. Public (the spec documents
// no secrets), edge-cacheable (it changes only on deploys).
// ═══════════════════════════════════════════════════════════════════

import { Hono } from 'hono'
import { OPENAPI_SPEC } from '../openapi/spec'

export function createOpenApiRouter(): Hono {
  const openapi = new Hono()

  openapi.get('/api/openapi.json', (c) => {
    c.header('Cache-Control', 'public, max-age=300')
    return c.json(OPENAPI_SPEC)
  })

  return openapi
}
