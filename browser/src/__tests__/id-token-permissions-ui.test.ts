// ─────────────────────────────────────────────────────────────────────
// The permissions picker's hierarchy helpers (TODO.openapi/19 — the
// human half of the stem grants): the group and resource stems derive
// from the served catalog's flat ids, a held stem IMPLIES its leaves
// (the UI renders them covered, the payload omits them), and the edit
// seeding keeps pinned STEMS (a flat-only filter would silently drop
// them — the latent bug this module exists to close).
// ─────────────────────────────────────────────────────────────────────

import { describe, expect, it } from 'vitest'
import {
  effectiveSelection,
  resourceStemsOf,
  seedSelection,
  stemHeldFor,
} from '../components/token-permissions'

const GROUP = {
  id: 'portal',
  description: 'the console',
  permissions: [
    { id: 'portal.models.read', description: 'r' },
    { id: 'portal.models.edit', description: 'e' },
    { id: 'portal.claims.edit', description: 'c' },
  ],
}

describe('resourceStemsOf — the mid tier derives from the flat ids', () => {
  it('the distinct <group>.<resource> prefixes, sorted', () => {
    expect(resourceStemsOf(GROUP)).toEqual(['portal.claims', 'portal.models'])
  })

  it('an empty group answers nothing', () => {
    expect(resourceStemsOf({ id: 'cnml', description: '', permissions: [] })).toEqual([])
  })
})

describe('stemHeldFor — what covers a leaf', () => {
  it('nothing held answers null', () => {
    expect(stemHeldFor([], 'portal.models.read')).toBeNull()
  })

  it('the exact id covers itself; a leaf does not cover its sibling', () => {
    expect(stemHeldFor(['portal.models.read'], 'portal.models.read')).toBe('portal.models.read')
    expect(stemHeldFor(['portal.models.read'], 'portal.models.edit')).toBeNull()
  })

  it('the resource stem and the group stem cover their subtrees; the near-miss covers nothing', () => {
    expect(stemHeldFor(['portal.models'], 'portal.models.edit')).toBe('portal.models')
    expect(stemHeldFor(['portal'], 'portal.claims.edit')).toBe('portal')
    expect(stemHeldFor(['portal.model'], 'portal.models.edit')).toBeNull()
  })
})

describe('effectiveSelection — the payload form', () => {
  it('leaves covered by a held stem drop out (the stem suffices)', () => {
    expect(effectiveSelection(['portal.models', 'portal.models.read', 'portal.claims.edit']))
      .toEqual(['portal.claims.edit', 'portal.models'])
  })

  it('the group stem subsumes everything in the group', () => {
    expect(effectiveSelection(['portal', 'portal.models', 'portal.claims.edit'])).toEqual(['portal'])
  })

  it('an unrelated set passes through deduped and sorted', () => {
    expect(effectiveSelection(['twin.engine.read', 'twin.engine.read'])).toEqual(['twin.engine.read'])
  })
})

describe('seedSelection — the edit mode keeps the STEMS (the latent-bug fix)', () => {
  const exactIds = GROUP.permissions.map(p => p.id)

  it('a pinned stem survives the seeding (a flat-only filter drops it)', () => {
    expect(seedSelection(['portal.models', 'portal.models.read'], exactIds))
      .toEqual(['portal.models', 'portal.models.read'])
    expect(seedSelection(['portal'], exactIds)).toEqual(['portal'])
  })

  it('a pinned id outside the catalog still drops (the honest narrow)', () => {
    expect(seedSelection(['portal.models.read', 'gone.service.read'], exactIds))
      .toEqual(['portal.models.read'])
    expect(seedSelection(['portal.mod'], exactIds)).toEqual([])
  })
})
