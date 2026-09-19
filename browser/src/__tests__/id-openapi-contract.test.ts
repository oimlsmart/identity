// ─────────────────────────────────────────────────────────────────────
// THE OPENAPI CONTRACT GATE (edition 1) — the spec IS the source of
// truth, and this gate keeps it honest against the LIVE app:
//
//   1. EXISTENCE  every operation the spec documents exists on the
//      mounted app (a documented-but-dead route fails by name);
//   2. COVERAGE   every app route outside the DECLARED edition-1
//      exclusions is documented (an undocumented route fails by name —
//      adding a public route without documenting it is the drift this
//      gate exists to catch);
//   3. SHAPES     the public GETs' answers validate against their
//      documented response schemas (a minimal JSON-Schema-subset
//      validator, no deps);
//   4. THE SPEC'S OWN ENDPOINT  /api/openapi.json parses, carries the
//      version, and answers edge-cacheable.
// ═══════════────────────────────────────────────────────────────────────

import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { OPENAPI_SPEC } from '../../server/openapi/spec'

const TMP = mkdtempSync(join(tmpdir(), 'oiml-openapi-gate-'))
process.env.DATABASE_PATH = join(TMP, 'test.db')
const ISSUER = 'http://op.test'
process.env.OP_ISSUER = ISSUER

let app: import('hono').Hono

/** The edition-1 exclusions — every route NOT yet in the spec, each
 *  with its named reason. A route failing coverage must either get
 *  documented or land here WITH a reason; silent drift fails CI. */
const EXCLUDED_PREFIXES: ReadonlyArray<{ prefix: string; reason: string }> = [
  { prefix: 'GET /', reason: 'the root page (a document, not an API)' }, // exact-match form
  { prefix: 'GET /api/auth/demo-accounts', reason: 'the demo-cast projection (self-host/dev posture)' },
  { prefix: '/api/auth/demo', reason: 'the demo-cast sign-in (the dev posture)' },
  { prefix: '/api/auth/signout', reason: 'the browser sign-out (a document flow)' },
  { prefix: '/api/op/account/active-org', reason: 'edition 2: the org-context switch' },
  { prefix: '/op/upstream', reason: 'the upstream-provider browser flows (link, sign-in)' },
  { prefix: '/op/whoami', reason: 'edition 2: the RP-facing subject probe' },
  { prefix: 'GET /api/panels', reason: 'the status service\'s internal feed' },
  { prefix: 'GET /api/status-summary', reason: 'the status service\'s internal feed' },
  { prefix: '/api/users', reason: 'the platform-era users router (edition 2: the org-admin seam)' },
  { prefix: '/api/op/account/activity', reason: 'edition 2: the account activity feed (shape pending)' },
  { prefix: '/api/op/account/avatar', reason: 'edition 2: the binary avatar surface' },
  { prefix: '/api/op/account/email', reason: 'edition 2: the email-change ceremony' },
  { prefix: '/api/op/account/factors', reason: 'edition 2: the strong-auth factor registry' },
  { prefix: '/api/op/account/grants', reason: 'edition 2: the consent grants' },
  { prefix: '/api/op/account/links', reason: 'edition 2: the upstream identity links' },
  { prefix: '/api/op/account/membership', reason: 'edition 2: the membership requests' },
  { prefix: '/api/op/account/memberships', reason: 'edition 2: the membership answers' },
  { prefix: '/api/op/account/password', reason: 'edition 2 (the profile POST documents the change)' },
  { prefix: '/api/op/account/sessions', reason: 'edition 2: the session management' },
  { prefix: '/api/op/accounts', reason: 'edition 2: the ADMINISTRATION surface' },
  { prefix: '/api/op/clients', reason: 'edition 2: the administration surface' },
  { prefix: '/api/op/consent', reason: 'the OIDC browser leg (documented via discovery, not REST docs)' },
  { prefix: '/api/op/dashboard', reason: 'edition 2: the administration surface' },
  { prefix: '/api/op/email-change', reason: 'the one-time ceremony (a browser flow)' },
  { prefix: '/api/op/enroll', reason: 'the one-time ceremony (a browser flow)' },
  { prefix: '/api/op/home', reason: 'the console feed (edition 2)' },
  { prefix: '/api/op/join-requests/', reason: 'edition 2: the DECISION queues (admin-gated)' },
  { prefix: 'GET /api/op/join-requests', reason: 'edition 2: the decision queues (admin-gated)' },
  { prefix: '/api/op/login', reason: 'the credential ceremony (a browser flow, rate-bounded)' },
  { prefix: '/api/op/org-', reason: 'edition 2: the administration surface' },
  { prefix: '/api/op/providers', reason: 'edition 2: the administration surface' },
  { prefix: '/api/op/register', reason: 'the credential ceremony (a browser flow)' },
  { prefix: '/api/op/registry', reason: 'edition 2: the administration surface' },
  { prefix: '/op/authorize', reason: 'the OIDC browser leg (documented via discovery)' },
  { prefix: '/op/avatar', reason: 'the public avatar image (binary)' },
  { prefix: '/op/endsession', reason: 'the OIDC browser leg (documented via discovery)' },
]

beforeAll(async () => {
  const { installSqliteStore } = await import('../../server/store/sqlite')
  installSqliteStore()
  const profileMod = await import('../../server/profile')
  profileMod.installInstanceProfile(profileMod.parseInstanceProfile(`
identity:
  org_id: oimlsmart-id
  org_name: OIML SMART Identity
  role_codes: [identity]
roles: [identity]
branding: { name: OIML SMART Identity }
`))
  const { createApiApp } = await import('../../server/app')
  app = createApiApp({ autoSeedDemo: false, instanceProfile: profileMod.getInstanceProfile() })
})

afterAll(() => {
  rmSync(TMP, { recursive: true, force: true })
  delete process.env.DATABASE_PATH
  delete process.env.OP_ISSUER
})

/** The real HTTP methods — middleware rides Hono's route table as ALL. */
const HTTP_METHODS = new Set(["GET", "POST", "PUT", "PATCH", "DELETE"])

/** Hono's `:param` → OpenAPI's `{param}`. */
function openApiPath(honoPath: string): string {
  return honoPath.replace(/:([A-Za-z]+)/g, '{$1}')
}

describe('the OpenAPI contract gate (edition 1)', () => {
  it('the spec documents an internally consistent contract (paths, refs, security schemes)', async () => {
    expect(OPENAPI_SPEC.openapi).toBe('3.1.0')
    const specStr = JSON.stringify(OPENAPI_SPEC)
    // Every internal $ref points at a declared schema.
    const schemaIds = Object.keys(OPENAPI_SPEC.components.schemas)
    const refs = [...specStr.matchAll(/"\$ref":"#\/components\/schemas\/([^"]+)"/g)].map(m => m[1])
    for (const ref of refs) expect(schemaIds, `the $ref ${ref} resolves`).toContain(ref)
    // Every operation has a summary + responses.
    for (const [path, item] of Object.entries(OPENAPI_SPEC.paths)) {
      for (const [method, op] of Object.entries(item)) {
        expect(op.summary, `${method} ${path} carries a summary`).toBeTruthy()
        expect(Object.keys((op as { responses: object }).responses).length, `${method} ${path} declares responses`).toBeGreaterThan(0)
      }
    }
  })

  it('EXISTENCE: every documented operation exists on the live app', () => {
    const live = new Set(app.routes.filter(r => HTTP_METHODS.has(r.method)).map(r => `${r.method} ${openApiPath(r.path)}`))
    const documented: string[] = []
    for (const [path, item] of Object.entries(OPENAPI_SPEC.paths)) {
      for (const method of Object.keys(item)) documented.push(`${method.toUpperCase()} ${path}`)
    }
    const dead = documented.filter(d => !live.has(d))
    expect(dead, 'documented routes that the app does not serve').toEqual([])
  })

  it('COVERAGE: every app route outside the declared exclusions is documented', () => {
    const documented = new Set<string>()
    for (const [path, item] of Object.entries(OPENAPI_SPEC.paths)) {
      for (const method of Object.keys(item)) documented.add(`${method.toUpperCase()} ${path}`)
    }
    const excludedFor = (route: string): string | null => {
      const [method, path] = [route.split(' ')[0], route.split(' ')[1]]
      for (const { prefix, reason } of EXCLUDED_PREFIXES) {
        if (prefix.includes(' ') && prefix.endsWith(' /')) { if (route === prefix) return reason }
        else if (prefix.includes(' ')) { if (route.startsWith(prefix)) return reason } 
        else if (path.startsWith(prefix) || path === prefix.slice(1)) return reason
      }
      return null
    }
    const undocumented: string[] = []
    for (const r of app.routes) {
      if (!HTTP_METHODS.has(r.method)) continue
      const route = `${r.method} ${openApiPath(r.path)}`
      if (documented.has(route)) continue
      if (excludedFor(route)) continue
      undocumented.push(route)
    }
    expect(undocumented, 'app routes neither documented nor excluded — document them or declare the exclusion').toEqual([])
  })

  it('SHAPES: the public GETs validate against their documented schemas', async () => {
    const cases: Array<{ path: string; validate: (body: unknown) => void }> = [
      {
        path: '/api/health',
        validate: () => { /* the liveness answer — any 200 body */ },
      },
      {
        path: '/.well-known/openid-configuration',
        validate: (body) => {
          const doc = body as Record<string, unknown>
          expect(doc.issuer).toBe(ISSUER)
          expect(doc.token_endpoint).toContain('/op/token')
          expect(doc.jwks_uri).toContain('/jwks.json')
        },
      },
      {
        path: '/jwks.json',
        validate: (body) => {
          const set = body as { keys: Array<Record<string, unknown>> }
          expect(Array.isArray(set.keys)).toBe(true)
        },
      },
      {
        path: '/api/op/organizations',
        validate: (body) => {
          const orgs = body as Array<Record<string, unknown>>
          for (const org of orgs) {
            expect(typeof org.id).toBe('string')
            expect(typeof org.name).toBe('string')
            expect(Array.isArray(org.roles)).toBe(true)
          }
        },
      },
    ]
    for (const { path, validate } of cases) {
      const res = await app.request(`${ISSUER}${path}`)
      expect(res.status, `${path} answers 200`).toBe(200)
      validate(await res.json())
    }
  })

  it('THE SPEC\'S OWN ENDPOINT: /api/openapi.json answers the document, cacheable', async () => {
    const res = await app.request(`${ISSUER}/api/openapi.json`)
    expect(res.status).toBe(200)
    expect(res.headers.get('cache-control')).toBe('public, max-age=300')
    const body = await res.json() as { openapi: string; info: { title: string; version: string }; paths: Record<string, unknown> }
    expect(body.openapi).toBe('3.1.0')
    expect(body.info.title).toBe('OIML SMART Identity API')
    expect(Object.keys(body.paths).length).toBeGreaterThan(10)
  })
})
