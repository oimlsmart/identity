// ─────────────────────────────────────────────────────────────────────
// The permissions catalog's hierarchy (TODO.openapi/03's stem grants):
// a minted id may name a SUBTREE — the group (`portal`) or the
// resource (`portal.models`) — and the enforcement honors it by
// SEGMENT-BOUNDARY PREFIX (`portal.models` covers portal.models.read
// and everything the catalog later adds under it; `portal.model`
// covers nothing — the dot is the boundary, never a string prefix).
// The catalog itself stays FLAT and closed: hierarchy lives in the
// grant, never in the authored declaration.
// ─────────────────────────────────────────────────────────────────────

import { describe, expect, it } from 'vitest'
import {
  grantsCover,
  normalizePermissionIds,
  parsePermissionsPayload,
  permissionIdPlausible,
  permissionsOutsideCatalogs,
  type PermissionsCatalog,
} from '../../server/auth/op/catalog'

const CATALOG: PermissionsCatalog = {
  version: 1,
  verbs: ['read', 'edit'],
  groups: [
    {
      id: 'portal',
      description: 'the console',
      permissions: [
        { id: 'portal.models.read', description: 'read the models' },
        { id: 'portal.models.edit', description: 'maintain the models' },
        { id: 'portal.claims.edit', description: 'file the claims' },
      ],
    },
    {
      id: 'twin',
      description: 'the engine',
      permissions: [{ id: 'twin.engine.read', description: 'read the engine' }],
    },
  ],
}

describe('the id grammar admits stems (1–3 segments, kebab)', () => {
  it('the group stem, the resource stem, and the exact id are all plausible', () => {
    expect(permissionIdPlausible('portal')).toBe(true)
    expect(permissionIdPlausible('portal.models')).toBe(true)
    expect(permissionIdPlausible('portal.models.read')).toBe(true)
  })

  it('the garbage stays out (empty segments, case, four+ segments, junk)', () => {
    expect(permissionIdPlausible('portal..read')).toBe(false)
    expect(permissionIdPlausible('Portal.models')).toBe(false)
    expect(permissionIdPlausible('portal.models.read.extra')).toBe(false)
    expect(permissionIdPlausible('portal models')).toBe(false)
    expect(permissionIdPlausible(42)).toBe(false)
  })

  it('the payload parse checks the shape; the normalization folds at the verdict', () => {
    // The module's documented division: parse = the honest shape check
    // (verbatim), normalizePermissionIds = the canonical stored form.
    const parsed = parsePermissionsPayload(['portal.models.read', 'portal', 'portal.models.read'])
    expect(parsed).toEqual({ ok: true, requested: ['portal.models.read', 'portal', 'portal.models.read'] })
    expect(parsePermissionsPayload('nope')).toEqual({ ok: false })
    expect(parsePermissionsPayload(['portal', 42])).toEqual({ ok: false })
    expect(parsePermissionsPayload(undefined)).toEqual({ ok: true, requested: [] })
    expect(normalizePermissionIds(['portal.models.read', 'portal', 'portal.models.read']))
      .toEqual(['portal', 'portal.models.read'])
  })
})

describe('permissionsOutsideCatalogs — a stem is INSIDE when it prefixes a served id', () => {
  it('the exact ids stay exact', () => {
    expect(permissionsOutsideCatalogs([CATALOG], ['portal.models.read'])).toEqual([])
  })

  it('the resource stem and the group stem cover their subtrees', () => {
    expect(permissionsOutsideCatalogs([CATALOG], ['portal.models'])).toEqual([])
    expect(permissionsOutsideCatalogs([CATALOG], ['portal'])).toEqual([])
    expect(permissionsOutsideCatalogs([CATALOG], ['twin'])).toEqual([])
  })

  it('a near-miss stem is OUTSIDE (the segment boundary, never a string prefix)', () => {
    expect(permissionsOutsideCatalogs([CATALOG], ['portal.model'])).toEqual(['portal.model'])
    expect(permissionsOutsideCatalogs([CATALOG], ['portalish'])).toEqual(['portalish'])
    expect(permissionsOutsideCatalogs([CATALOG], ['twin.engine.read.extra'])).toEqual(['twin.engine.read.extra'])
  })

  it('the union across instances serves the validation', () => {
    expect(permissionsOutsideCatalogs([CATALOG, CATALOG], ['twin.engine.read'])).toEqual([])
  })
})

describe('grantsCover — the enforcement half (the same semantics the platform runs)', () => {
  it('the exact grant covers the exact requirement', () => {
    expect(grantsCover(['portal.models.read'], 'portal.models.read')).toBe(true)
  })

  it('a resource stem covers everything under it (today and later)', () => {
    expect(grantsCover(['portal.models'], 'portal.models.read')).toBe(true)
    expect(grantsCover(['portal.models'], 'portal.models.edit')).toBe(true)
    // A permission the catalog adds TOMORROW is covered by the stem
    // minted YESTERDAY — the hierarchy's deliberate semantics.
    expect(grantsCover(['portal.models'], 'portal.models.export')).toBe(true)
  })

  it('a group stem covers the whole group and nothing across it', () => {
    expect(grantsCover(['portal'], 'portal.claims.edit')).toBe(true)
    expect(grantsCover(['portal'], 'twin.engine.read')).toBe(false)
  })

  it('the boundary is the dot (the near-miss grants nothing)', () => {
    expect(grantsCover(['portal.model'], 'portal.models.read')).toBe(false)
    expect(grantsCover(['portalish'], 'portalish.x.read')).toBe(true)
    expect(grantsCover(['portalish'], 'portal.x.read')).toBe(false)
  })

  it('an ungranted requirement refuses', () => {
    expect(grantsCover([], 'twin.engine.read')).toBe(false)
    expect(grantsCover(['portal.claims.edit'], 'twin.engine.read')).toBe(false)
  })
})
