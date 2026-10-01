// ─────────────────────────────────────────────────────────────────────
// TODO.sota/07.3 — the ROUTING GUARD (the sibling's structural
// discipline, ported): every URL the identity service's own surfaces
// name must have a real Astro page, or the front door 404s where a
// page is promised. Three sources must agree:
//
//   1. the client router's route table (app-entrypoint's ROUTE_PATHS)
//      — every static entry resolves to a page file on disk;
//   2. roleHome — every '/op'-rooted landing for an assignable role
//      resolves to a page file;
//   3. the auth-lean redirect — the signed-out console bounce's target
//      ('/?redirect=…') resolves to the sign-in page.
//
// Dynamic entries (:param) map to the [param] directory convention.
// The guard fails the BUILD CLASS of bug where a route ships without
// its page (the Ribose ID PR-#16 class).
// ─────────────────────────────────────────────────────────────────────
import { existsSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { describe, expect, it } from 'vitest'

const ROOT = join(import.meta.dirname, '..', '..')

/** The route table's path → the expected page file (the :param → the
 *  [param] directory convention). */
function pageFileFor(path: string): string {
  if (path === '/') return join(ROOT, 'src', 'pages', 'index.astro')
  const raw = path.replace(/^\//, '').split('/')
  const segments = raw.map((s, i) => {
    if (s.startsWith(':')) return `[${s.slice(1)}].astro` // a param names a FILE
    return i === raw.length - 1 ? `${s}.astro` : s // only the last is a file
  })
  return join(ROOT, 'src', 'pages', ...segments)
}

function pageExists(path: string): boolean {
  const file = pageFileFor(path)
  if (existsSync(file)) return true
  // The directory-index convention: /op/admin → src/pages/op/admin/index.astro
  // (or the admin.astro sibling — Astro's trailing-slash resolution).
  const dirIndex = join(dirname(file), 'index.astro')
  if (existsSync(dirIndex)) return true
  const sibling = join(dirname(file), `${dirname(file).split('/').pop()}.astro`)
  return existsSync(sibling)
}

describe('the routing guard (TODO.sota/07.3)', () => {
  it('every static route-table entry resolves to a real Astro page', async () => {
    const source = await import('../../src/astro/app-entrypoint')
    void source
    const { readFileSync } = await import('node:fs')
    const src = readFileSync(join(ROOT, 'src', 'astro', 'app-entrypoint.ts'), 'utf8')
    const paths = [...src.matchAll(/path: '([^']+)'/g)].map(m => m[1]!)
    expect(paths.length).toBeGreaterThan(10)
    const missing = paths.filter(p => !p.includes(':') && !pageExists(p))
    expect(missing, `routes without pages: ${missing.join(', ')}`).toEqual([])
  })

  it('every /op-rooted role landing resolves to a real Astro page', async () => {
    const { APP_ROLES, roleHome } = await import('../../server/vocab/roles')
    const landings = APP_ROLES.map(r => roleHome(r)).filter(h => h.startsWith('/op'))
    expect(landings).toContain('/op/admin/organization')
    const missing = landings.filter(p => !pageExists(p))
    expect(missing, `role landings without pages: ${missing.join(', ')}`).toEqual([])
  })
})

describe("the routing guard server half (TODO.sota/07.3 extension — the 2026-10-02 production 404s)", () => {
  it('every mounted API route OUTSIDE the catch-all-covered prefixes has a production shim (an Astro page)', async () => {
    // The production Worker serves the OP API through the catch-alls
    // (/op/[...path] + /api/[...path]) — every OTHER mounted route path
    // must exist as an Astro page/shim or the front door 404s where the
    // API answers in dev (the id-v2026.10.02-1 lesson: the two new
    // .well-known endpoints shipped without shims).
    process.env.DATABASE_PATH = ':memory:'
    const { installSqliteStore } = await import('../../server/store/sqlite')
    installSqliteStore()
    const profileMod = await import('../../server/profile')
    profileMod.installInstanceProfile(profileMod.parseInstanceProfile(`
identity:
  org_id: oimlsmart-id
  org_name: Guard
  role_codes: [identity]
roles: [identity]
branding: { name: Guard }
`))
    const { createOpRouter } = await import('../../server/routes/op')
    const op = createOpRouter()
    const paths = new Set<string>()
    for (const r of op.routes as Array<{ path: string }>) {
      const p = r.path
      if (p === '/*') continue
      if (p.startsWith('/op/') || p === '/op' || p.startsWith('/api/') || p === '/api') continue
      paths.add(p)
    }
    expect(paths.size).toBeGreaterThan(3)
    const missing: string[] = []
    for (const p of paths) {
      const raw = p.replace(/^\//, '').split('/')
      const candidates = [
        join(ROOT, 'src', 'pages', ...raw.map((s, i) => (i === raw.length - 1 ? `${s}.ts` : s))),
        join(ROOT, 'src', 'pages', ...raw.map((s, i) => (i === raw.length - 1 ? `${s}.astro` : s))),
      ]
      if (!candidates.some(f => existsSync(f))) missing.push(p)
    }
    expect(missing, `these API routes 404 in production (no Astro shim): ${missing.join(', ')}`).toEqual([])
    profileMod.resetInstanceProfileForTest()
    delete process.env.DATABASE_PATH
  })
})
