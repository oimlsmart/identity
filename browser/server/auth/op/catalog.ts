// ═══════════════════════════════════════════════════════════════════
// The permissions catalog's client half (TODO.openapi/03 — the
// identity-service half of the account-token permissions).
//
// THE ONE RULE: the OP NEVER HOLDS A COPY of the catalog. Each SMART
// instance serves its own at GET <instance>/api/openapi.json under
// `x-oiml-permissions-catalog` (version + the closed verb set + the
// groups → descriptions → permission ids → descriptions). When a PAT
// names catalog permissions, THIS module fetches the TARGET INSTANCE's
// served document and validates the requested ids against it — fail
// closed: an instance that cannot answer refuses the mint (a permission
// grant is a deliberate act, never a guess past a dead probe).
//
// The instance base URL resolves from the ONE source the registry
// already vouches for: the registered client's redirect URIs (the RP
// registration's own URLs — the origin of the first http(s) entry).
// The projection for the mint picker normalizes the served document to
// sorted arrays (stable wire shape for the UI).
//
// WORKER-SAFE: fetch only, no node built-ins.
// ═══════════════════════════════════════════════════════════════════

/** The served projection's shape (the smart platform's openapi
 *  assembler emits exactly this under x-oiml-permissions-catalog). */
export interface PermissionsCatalog {
  version: number
  verbs: string[]
  groups: PermissionsCatalogGroup[]
}

export interface PermissionsCatalogGroup {
  id: string
  description: string
  /** The FULL ids (`<group>.<resource>.<verb>` — the group key joined
   *  onto the served `<resource>.<verb>` keys), sorted. */
  permissions: Array<{ id: string; description: string }>
}

/** The light id grammar (the catalog does the real judging): dot-
 *  separated kebab-case segments, at least `<resource>.<verb>` long —
 *  the full ids are `<group>.<resource>.<verb>`. */
const PERMISSION_ID_RE = /^[a-z0-9-]+(\.[a-z0-9-]+)+$/

/** A requested permission id's plausibility (before any fetch — the
 *  malformed names the 400 without an instance round trip). */
export function permissionIdPlausible(raw: unknown): raw is string {
  return typeof raw === 'string' && raw.length <= 200 && PERMISSION_ID_RE.test(raw)
}

/** The instance base URL from the client registry's own record: the
 *  origin of the first http(s) redirect URI. Null when the client
 *  registers none (a machine-class shape — never a PAT's service). */
export function instanceBaseUrlOf(redirectUris: readonly string[]): string | null {
  for (const uri of redirectUris) {
    try {
      const url = new URL(uri)
      if (url.protocol === 'https:' || url.protocol === 'http:') return url.origin
    } catch { /* a relative or broken entry never resolves — keep looking */ }
  }
  return null
}

export type CatalogFetchResult =
  | { ok: true; catalog: PermissionsCatalog }
  | { ok: false; reason: 'unreachable' | 'no_catalog' | 'malformed' }

/** The fetch's bound (a deliberate act may wait, but not long). */
const CATALOG_TIMEOUT_MS = 5_000
/** The short per-process cache (the picker's repeats + a mint burst
 *  share one fetch per instance); failures never cache — the next act
 *  re-probes honestly. */
const CATALOG_CACHE_TTL_MS = 300_000

const catalogCache = new Map<string, { at: number; catalog: PermissionsCatalog }>()

/** Parse + structurally validate a served document into the catalog
 *  projection. Total and honest: anything unexpected answers null. */
export function parsePermissionsCatalog(doc: unknown): PermissionsCatalog | null {
  if (typeof doc !== 'object' || doc === null) return null
  const entry = (doc as Record<string, unknown>)['x-oiml-permissions-catalog']
  if (typeof entry !== 'object' || entry === null) return null
  const raw = entry as Record<string, unknown>
  if (raw.version !== 1) return null
  if (!Array.isArray(raw.verbs) || !raw.verbs.every(v => typeof v === 'string')) return null
  if (typeof raw.groups !== 'object' || raw.groups === null) return null
  const groups: PermissionsCatalogGroup[] = []
  for (const [groupId, value] of Object.entries(raw.groups as Record<string, unknown>)) {
    if (!/^[a-z0-9-]+$/.test(groupId)) return null
    if (typeof value !== 'object' || value === null) return null
    const group = value as Record<string, unknown>
    if (typeof group.description !== 'string') return null
    if (typeof group.permissions !== 'object' || group.permissions === null) return null
    const permissions: Array<{ id: string; description: string }> = []
    for (const [key, blurb] of Object.entries(group.permissions as Record<string, unknown>)) {
      // The served keys are `<resource>.<verb>`; the FULL id joins the
      // group (the served document's own assembly rule).
      if (!/^[a-z0-9-]+\.[a-z0-9-]+$/.test(key)) return null
      if (typeof blurb !== 'string') return null
      permissions.push({ id: `${groupId}.${key}`, description: blurb })
    }
    permissions.sort((a, b) => a.id.localeCompare(b.id))
    groups.push({ id: groupId, description: group.description, permissions })
  }
  groups.sort((a, b) => a.id.localeCompare(b.id))
  return { version: 1, verbs: raw.verbs as string[], groups }
}

/** Fetch the instance's served catalog (the timeout-bounded, fail-
 *  closed probe; the per-process success cache never outlives its TTL). */
export async function fetchPermissionsCatalog(baseUrl: string, now = Date.now()): Promise<CatalogFetchResult> {
  const cached = catalogCache.get(baseUrl)
  if (cached && now - cached.at < CATALOG_CACHE_TTL_MS) return { ok: true, catalog: cached.catalog }
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), CATALOG_TIMEOUT_MS)
  try {
    const res = await fetch(new URL('/api/openapi.json', baseUrl).toString(), {
      signal: controller.signal,
      headers: { accept: 'application/json' },
    })
    if (!res.ok) return { ok: false, reason: 'unreachable' }
    const catalog = parsePermissionsCatalog(await res.json().catch(() => null))
    if (!catalog) return { ok: false, reason: 'no_catalog' }
    catalogCache.set(baseUrl, { at: now, catalog })
    return { ok: true, catalog }
  } catch {
    return { ok: false, reason: 'unreachable' }
  } finally {
    clearTimeout(timer)
  }
}

/** The requested set against the fetched catalogs: every id must be in
 *  the UNION (a token scoped to several services may draw on any of
 *  their instances). Answers the offenders, sorted + deduped. */
export function permissionsOutsideCatalogs(
  catalogs: readonly PermissionsCatalog[],
  requested: readonly string[],
): string[] {
  const known = new Set<string>()
  for (const catalog of catalogs) {
    for (const group of catalog.groups) {
      for (const permission of group.permissions) known.add(permission.id)
    }
  }
  return [...new Set(requested)].filter(id => !known.has(id)).sort((a, b) => a.localeCompare(b))
}

/** The canonical stored form: dedupe + sort (the stable wire/claim
 *  shape — the same discipline the scope set's fold follows). */
export function normalizePermissionIds(raw: readonly string[]): string[] {
  return [...new Set(raw)].sort((a, b) => a.localeCompare(b))
}

/** The mint/edit payload's permissions field: an OPTIONAL array of
 *  catalog-id strings (the absent field = "no catalog permissions" at
 *  mint, "untouched" at edit; a non-array or a non-string entry is the
 *  honest 400). Duplicates fold at the validation. */
export function parsePermissionsPayload(raw: unknown): { ok: true; requested: string[] } | { ok: false } {
  if (raw === undefined) return { ok: true, requested: [] }
  if (!Array.isArray(raw) || raw.some(cell => typeof cell !== 'string')) return { ok: false }
  return { ok: true, requested: raw as string[] }
}

// ── the mint-time validation (the one computation the self-service
//    mint and the admin mint share — never a copy) ────────────────────

export type PatPermissionsVerdict =
  | { ok: true; permissions: string[] }
  | { ok: false; error: string }

/** Validate a requested permission-id set against the TARGET
 *  INSTANCES' served catalogs (the services the token scopes to name
 *  the instances; the union of their catalogs is the valid set). Fail
 *  closed at every leg: a service with no resolvable instance URL, an
 *  instance that cannot answer, and any id outside the served catalogs
 *  all refuse — a permission grant is a deliberate act. The answer
 *  names the offenders (the caller's 400 body quotes it). */
export async function validatePatPermissions(
  store: import('../../store').ServerStore,
  services: readonly string[],
  requested: readonly string[],
): Promise<PatPermissionsVerdict> {
  if (!requested.length) return { ok: true, permissions: [] }
  const malformed = requested.filter(id => !permissionIdPlausible(id))
  if (malformed.length) {
    return { ok: false, error: `these are not permission ids (the '<group>.<resource>.<verb>' grammar): ${malformed.join(', ')}` }
  }
  const bases = new Map<string, string>()
  for (const service of services) {
    const client = await store.getOidcClient(service)
    const base = client && client.status === 'active' ? instanceBaseUrlOf(client.redirectUris) : null
    if (!base) {
      return { ok: false, error: `the service '${service}' exposes no instance URL to validate permissions against — a scoped service needs a registered http(s) redirect URI` }
    }
    bases.set(service, base)
  }
  const catalogs: PermissionsCatalog[] = []
  for (const base of new Set(bases.values())) {
    const result = await fetchPermissionsCatalog(base)
    if (!result.ok) {
      return { ok: false, error: `the instance at ${base} does not serve a permissions catalog (${result.reason}) — the mint refuses (fail closed; a permission grant is a deliberate act)` }
    }
    catalogs.push(result.catalog)
  }
  const offenders = permissionsOutsideCatalogs(catalogs, requested)
  if (offenders.length) {
    const probed = [...new Set(bases.values())].sort().join(', ')
    return { ok: false, error: `these permission ids are not in the target instances' catalogs (${probed}): ${offenders.join(', ')}` }
  }
  return { ok: true, permissions: normalizePermissionIds(requested) }
}
