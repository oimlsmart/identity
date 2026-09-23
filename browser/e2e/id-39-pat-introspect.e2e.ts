// ═══════════════════════════════════════════════════════════════════
// The PAT introspection + the permissions catalog (TODO.openapi/03) —
// the platform contract's access-token class over the real booted
// stack (the id-16 posture: the subject is served by the Hono app, so
// no astro and no browser — the legs ride real HTTP against the API):
//
//   leg 1  the TARGET INSTANCE's permissions catalog, end to end: the
//          fixture instance (a local http server serving
//          /api/openapi.json under x-oiml-permissions-catalog) is the
//          registered client's redirect-URI origin — the same-origin
//          proxy projects it (never a local copy), and the mint
//          VALIDATES against it over the wire: the unknown id refuses
//          400 naming it, the valid set pins;
//   leg 2  the RAW PAT introspects ACTIVE with the full claim set —
//          iss/sub/scope/permissions/service_roles/org/cone/pat/
//          token_type=access_token/exp — the LIVE judgment, the exact
//          shape the platform's enforcement reads; the unauthenticated
//          caller refuses; the well-shaped unknown answers the honest
//          inactive;
//   leg 3  the revoke kills it at the NEXT introspection (the instant
//          revocation the per-request posture buys), and the audit
//          chain carries the arc: mint / the throttled introspected
//          beat / revoke.
//
// SELF-CONTAINED: own ports (API 10655 / the catalog fixture 10657 —
// above id-38's 10651-10653), own SQLite file.
// ═══════════════════════════════════════════════════════════════════

import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import { spawn, type ChildProcess } from 'node:child_process'
import { createServer, type Server } from 'node:http'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { mkdirSync, rmSync } from 'node:fs'
import { delay } from './helpers'
import { fixtureOpSigningKey } from './fixtures/op-signing-key'

const BROWSER_DIR = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const FIXTURES = join(BROWSER_DIR, 'e2e', 'fixtures')
const DB_DIR = join(BROWSER_DIR, '.cache', 'id-39')

// Port-isolated: above id-38's 10651-10653.
const ID_API = 10655
const CATALOG_PORT = 10657

const ISSUER = `http://127.0.0.1:${ID_API}` // loopback is the test posture (id-16)
const API_BASE = ISSUER
const CATALOG_BASE = `http://127.0.0.1:${CATALOG_PORT}`

const IA_EMAIL = 'ia@oimlsmart.org'
const ADMIN_EMAIL = 'admin@oimlsmart.org'

// The register's service: the hub, whose redirect URI's ORIGIN is the
// fixture instance (the registry's one true source for the instance
// base URL — the same resolution the mint validation runs).
const HUB = {
  client_id: 'hub-instance',
  name: 'OIML SMART platform hub',
  redirect_uris: [`${CATALOG_BASE}/api/auth/callback/oidc`],
  claims_policy: { claims: ['roles', 'org'] },
}

/** The fixture instance's served permissions catalog (the projection
 *  the smart platform's openapi assembler emits). */
const CATALOG_DOC = {
  'x-oiml-permissions-catalog': {
    version: 1,
    verbs: ['read', 'edit'],
    groups: {
      'tl-workbench': {
        description: 'The test-laboratory workbench.',
        permissions: {
          'runs.read': 'Reads the runs.',
          'runs.edit': 'Edits the runs.',
        },
      },
    },
  },
}

/** The fixture instance: answers GET /api/openapi.json with the catalog
 *  document, 404 for everything else. */
function startCatalogServer(): Promise<Server> {
  const server = createServer((req, res) => {
    if (req.url === '/api/openapi.json') {
      res.writeHead(200, { 'content-type': 'application/json' })
      res.end(JSON.stringify(CATALOG_DOC))
      return
    }
    res.writeHead(404, { 'content-type': 'text/plain' })
    res.end('not found')
  })
  return new Promise(resolve => server.listen(CATALOG_PORT, () => resolve(server)))
}

let api: ChildProcess | undefined
const logs: string[] = []
let catalogServer: Server | undefined

function killTreeHard(proc: ChildProcess | undefined): void {
  if (!proc || proc.exitCode !== null || proc.pid === undefined) return
  try { process.kill(-proc.pid, 'SIGKILL') } catch { /* already gone */ }
}

async function waitForHttp(url: string, timeoutMs: number): Promise<void> {
  const deadline = Date.now() + timeoutMs
  let lastError = ''
  while (Date.now() < deadline) {
    try {
      const res = await fetch(url)
      if (res.status < 500) return
      lastError = `HTTP ${res.status}`
    } catch (e) {
      lastError = String(e)
    }
    await delay(1_000)
  }
  throw new Error(`timed out waiting for ${url} (${lastError})\n--- stack logs ---\n${logs.join('').slice(-4000)}`)
}

/** Sign in through the demo cast (DEMO_ACCOUNTS_ENABLED=true). */
async function apiSignIn(email: string): Promise<string> {
  const login = await fetch(`${API_BASE}/api/auth/demo`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, password: 'demo2026' }),
  })
  expect(login.ok, `demo sign-in ${email}`).toBe(true)
  return (login.headers.get('set-cookie') ?? '').split(';')[0]!
}

/** RFC 7662 over the raw PAT (the platform's posture: the token +
 *  client_id in the form — the hub is a public client in this stack). */
async function introspect(token: string): Promise<Response> {
  return fetch(`${API_BASE}/op/introspect`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ token, client_id: HUB.client_id }),
  })
}

describe('the PAT introspection + the permissions catalog (TODO.openapi/03)', () => {
  beforeAll(async () => {
    catalogServer = await startCatalogServer()
    const logs_: string[] = logs
    mkdirSync(DB_DIR, { recursive: true })
    const dbPath = join(DB_DIR, 'identity.db')
    for (const suffix of ['', '-wal', '-shm']) rmSync(dbPath + suffix, { force: true })

    api = spawn(join(BROWSER_DIR, 'node_modules', '.bin', 'tsx'), ['server/serve.ts'], {
      cwd: BROWSER_DIR,
      env: {
        ...Object.fromEntries(Object.entries(process.env).filter(([k]) => k !== 'NODE_ENV' && k !== 'VITEST' && !k.startsWith('VITEST_'))),
        PORT: String(ID_API),
        DATABASE_PATH: dbPath,
        ENTITY_BACKEND: 'server',
        INSTANCE_PROFILE: join(FIXTURES, 'instance.profile.identity.yaml'),
        OIDC_ISSUER: '',
        OIDC_CLIENT_ID: '',
        DEMO_ACCOUNTS_ENABLED: 'true',
        OP_ISSUER: ISSUER,
        OP_SIGNING_KEY: await fixtureOpSigningKey(),
        OP_CLIENT_SEED: JSON.stringify([HUB]),
      } as NodeJS.ProcessEnv,
      stdio: ['ignore', 'pipe', 'pipe'],
      detached: true,
    })
    api.stdout?.on('data', d => logs_.push(String(d)))
    api.stderr?.on('data', d => logs_.push(String(d)))
    await waitForHttp(`${API_BASE}/api/health`, 120_000, logs_)
    const reset = await fetch(`${API_BASE}/api/dev-reset`, { method: 'POST' })
    if (!reset.ok) throw new Error(`dev-reset answered ${reset.status}\n${logs.join('').slice(-2000)}`)
  }, 300_000)

  afterAll(async () => {
    if (api) {
      try { process.kill(-api.pid!, 'SIGKILL') } catch { /* group already gone */ }
    }
    catalogServer?.close()
    await delay(500)
  })

  it('leg 1 — the instance\'s catalog end to end: the proxy projects it, the mint validates against it (the unknown id refuses, naming it)', { timeout: 300_000 }, async () => {
    const ia = await apiSignIn(IA_EMAIL)

    // The proxy: the fixture instance's document, projected (the OP
    // never holds a copy — this IS the served answer).
    const proxy = await fetch(`${API_BASE}/api/op/account/tokens/catalog?service=${HUB.client_id}`, { headers: { cookie: ia } })
    expect(proxy.status).toBe(200)
    const projected = await proxy.json() as {
      service: string
      baseUrl: string
      catalog: { version: number; groups: Array<{ id: string; permissions: Array<{ id: string; description: string }> }> }
    }
    expect(projected.service).toBe(HUB.client_id)
    expect(projected.baseUrl).toBe(CATALOG_BASE)
    const group = projected.catalog.groups.find(g => g.id === 'tl-workbench')!
    expect(group.description).toBe('The test-laboratory workbench.')
    expect(group.permissions.map(p => p.id).sort()).toEqual(['tl-workbench.runs.edit', 'tl-workbench.runs.read'])

    // The mint with an id the instance does NOT carry: 400, naming it.
    const refused = await fetch(`${API_BASE}/api/op/account/tokens`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: ia },
      body: JSON.stringify({ name: 'the over-reach', scopes: [`${HUB.client_id}:read`], permissions: ['tl-workbench.runs.purge'] }),
    })
    expect(refused.status).toBe(400)
    expect(((await refused.json()) as { error: string }).error).toContain('tl-workbench.runs.purge')

    // The valid mint: 201, the plaintext answers ONCE, the set pins
    // (deduped + sorted).
    const mint = await fetch(`${API_BASE}/api/op/account/tokens`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie: ia },
      body: JSON.stringify({
        name: 'the introspected CLI',
        scopes: [`${HUB.client_id}:read`],
        permissions: ['tl-workbench.runs.edit', 'tl-workbench.runs.read', 'tl-workbench.runs.edit'],
      }),
    })
    expect(mint.status).toBe(201)
    const mintBody = await mint.json() as { token: { id: string; plaintext: string; permissions: string[] } }
    expect(mintBody.token.plaintext.startsWith('ospt_')).toBe(true)
    expect(mintBody.token.permissions).toEqual(['tl-workbench.runs.edit', 'tl-workbench.runs.read'])
    mintedPat = mintBody.token.plaintext
    mintedId = mintBody.token.id
  })

  it('leg 2 — the raw PAT introspects ACTIVE with the full claim set (the live judgment)', { timeout: 300_000 }, async () => {
    const res = await introspect(mintedPat)
    expect(res.status).toBe(200)
    const answer = await res.json() as Record<string, unknown>
    expect(answer.active).toBe(true)
    expect(answer.iss).toBe(ISSUER)
    expect(answer.scope).toBe(`${HUB.client_id}:read`)
    expect(answer.permissions).toEqual(['tl-workbench.runs.edit', 'tl-workbench.runs.read'])
    expect(answer.service_roles).toMatchObject({ [HUB.client_id]: ['ia_officer'] })
    expect(answer.org, 'the active-org context (the IA’s EX1)').toBe('EX1')
    expect(typeof answer.cone, 'the live membership cone rides').toBe('string')
    expect(answer.pat).toBe(mintedId)
    expect(answer.token_type).toBe('access_token')
    expect(typeof answer.exp).toBe('number')
    expect((answer.exp as number) * 1000, 'the exp is the credential’s own expiry (days out, never an hour)').toBeGreaterThan(Date.now() + 86_400_000)

    // The well-shaped unknown answers the honest inactive; the
    // unauthenticated caller never reaches any of it.
    expect(await (await introspect(`ospt_${'c'.repeat(43)}`)).json()).toEqual({ active: false })
    const noAuth = await fetch(`${API_BASE}/op/introspect`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ token: mintedPat }),
    })
    expect(noAuth.status).toBe(401)
  })

  it('leg 3 — the revoke kills it at the next introspection; the audit chain carries the arc', { timeout: 300_000 }, async () => {
    const ia = await apiSignIn(IA_EMAIL)
    const revoke = await fetch(`${API_BASE}/api/op/account/tokens/${mintedId}`, { method: 'DELETE', headers: { cookie: ia } })
    expect(revoke.status).toBe(200)

    // The instant revocation the per-request posture buys.
    const dead = await introspect(mintedPat)
    expect(await dead.json()).toEqual({ active: false })

    // The audit arc: mint / the throttled introspected beat / revoke.
    const admin = await apiSignIn(ADMIN_EMAIL)
    const feed = await (await fetch(`${API_BASE}/api/op/registry/activity?limit=300`, { headers: { cookie: admin } })).json() as Array<{ action: string; metadata?: Record<string, unknown> }>
    const arc = feed.filter(e => e.metadata?.pat === mintedId)
    expect(arc.some(e => e.action === 'account.pat_minted'), 'the mint is on the chain').toBe(true)
    expect(arc.some(e => e.action === 'account.pat_introspected'), 'the introspection beat is on the chain').toBe(true)
    expect(arc.some(e => e.action === 'account.pat_revoked'), 'the revoke is on the chain').toBe(true)
  })
})

let mintedPat = ''
let mintedId = ''
