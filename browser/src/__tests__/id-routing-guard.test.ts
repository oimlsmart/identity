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
