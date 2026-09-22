// ═══════════════════════════════════════════════════════════════════
// The permissions picker's hierarchy helpers (TODO.openapi/19 — the
// human half of the stem grants, ADR 0008): the served catalog is
// flat, the picker derives the two stem tiers from it, and a held
// stem IMPLIES its leaves — the UI renders them covered, the payload
// omits them, and the edit seeding keeps pinned stems (a flat-only
// filter would silently drop them).
// ═══════════════════════════════════════════════════════════════════

export interface CatalogPermission { id: string; description: string }
export interface CatalogGroup { id: string; description: string; permissions: CatalogPermission[] }

/** The group's distinct `<group>.<resource>` stems, sorted — the
 *  picker's mid tier. */
export function resourceStemsOf(group: CatalogGroup): string[] {
  const stems = new Set<string>()
  for (const permission of group.permissions) {
    const segments = permission.id.split('.')
    if (segments.length >= 3) stems.add(`${segments[0]}.${segments[1]}`)
  }
  return [...stems].sort((a, b) => a.localeCompare(b))
}

/** The covering entry for a leaf: a selected id that EQUALS it or is
 *  its segment-boundary prefix — null when uncovered. The rule is the
 *  enforcement's own (grantsCover's shape, named for the UI's ask). */
export function stemHeldFor(selection: readonly string[], leaf: string): string | null {
  let covering: string | null = null
  for (const held of selection) {
    if (leaf === held || leaf.startsWith(`${held}.`)) {
      if (covering === null || held.length < covering.length) covering = held
    }
  }
  return covering
}

/** The payload form: sorted unique, minus every leaf a shorter held
 *  stem already covers (the stem suffices — the token stays small and
 *  the grant stays honest). */
export function effectiveSelection(selection: readonly string[]): string[] {
  const held = [...new Set(selection)].sort((a, b) => a.localeCompare(b))
  return held.filter(id => {
    const cover = stemHeldFor(held, id)
    return cover === null || cover === id
  })
}

/** The edit-mode seeding: keep a pinned id when it exactly names a
 *  served permission OR stems one (a pinned `portal` or
 *  `portal.models` survives; `portal.mod` and gone-service ids drop —
 *  the honest narrow the flat filter already gave the exact ids). */
export function seedSelection(pinned: readonly string[], exactIds: readonly string[]): string[] {
  const exact = new Set(exactIds)
  return [...new Set(pinned)].filter(id =>
    exact.has(id) || [...exact].some(exactId => exactId.startsWith(`${id}.`)),
  ).sort((a, b) => a.localeCompare(b))
}
