// ═══════════════════════════════════════════════════════════════════
// The member-domains registry projection (the pipeline's
// dist/domains.json, vendored at src/generated/domains.json): the
// version-checked loader and the contract's own resolveOrg matcher —
// the flat map, then the dot-boundary label walk. The semantics are
// the member-domains contract's, verbatim: an email matches when its
// domain EQUALS an entry or ends with '.' + entry (subdomains yes, a
// longer label sharing the prefix never).
//
// WORKER-SAFE: the JSON is bundled at build (a static import); no fs,
// no fetch, no node built-ins.
// ═══════════════════════════════════════════════════════════════════

import raw from '../../../src/generated/domains.json'

export interface DomainOwner {
  country: string
  country_fr: string
  iso: string
  status: string
  org: string
  roles: string[]
  verification: string
  evidence: string
}

export interface PickerOrg {
  name: string
  roles: string[]
  domains: string[]
  website_domains: string[]
  web_domains: string[]
  /** TODO.sota/05 — the ROR enrichment (the member-domains pipeline's
   *  website-domain anchor): the full https://ror.org/… id, present
   *  only on a matched org; ror_match names the matching posture. */
  ror_id?: string
  ror_match?: string
  verification: string
  admin_queue: boolean
}

export interface PickerCountry {
  country: string
  country_fr: string
  iso: string
  status: string
  orgs: PickerOrg[]
}

export interface DomainsCatalog {
  version: number
  matchingRule: string
  generatedAt: string
  domains: Map<string, DomainOwner>
  countries: PickerCountry[]
  /** TODO.sota/05 — the enrichment index: `${iso}|${name}` → the ROR
   *  id (only the matched orgs carry an entry). */
  rorByOrg: Map<string, string>
}

/** The artifact's shape gate: a foreign version fails loudly, never
 *  guesses (the enrollment's eligibility rides this data). */
export function assertVersion(candidate: { version?: number }): void {
  if (candidate.version !== 2) {
    throw new Error(`the member-domains artifact is not version 2 (got ${JSON.stringify(candidate.version)}) — refresh the vendored copy`)
  }
}

let catalog: DomainsCatalog | null = null

export function loadDomains(): DomainsCatalog {
  if (!catalog) {
    const source = raw as {
      version: number
      matching_rule: string
      generated_at: string
      domains: Record<string, DomainOwner>
      countries: PickerCountry[]
    }
    assertVersion(source)
    catalog = {
      version: source.version,
      matchingRule: source.matching_rule,
      generatedAt: source.generated_at,
      domains: new Map(Object.entries(source.domains)),
      countries: source.countries,
      rorByOrg: new Map(
        source.countries.flatMap(c =>
          c.orgs.filter(o => o.ror_id).map(o => [`${c.iso}|${o.name}`, o.ror_id!] as const),
        ),
      ),
    }
  }
  return catalog
}

/** The contract's matcher, verbatim: the exact flat-map hit, else the
 *  dot-boundary label walk (subdomains only), else null. */
export function resolveOrg(email: string): DomainOwner | null {
  return resolveOrgDomain(email)?.owner ?? null
}

/** The resolved org WITH its registry domain — the domain IS the
 *  organization's id in the identity registry (the org of the same
 *  domain name). */
export function resolveOrgDomain(email: string): { domain: string; owner: DomainOwner } | null {
  const d = email.split('@')[1]?.toLowerCase()
  if (!d) return null
  const { domains } = loadDomains()
  if (domains.has(d)) return { domain: d, owner: domains.get(d)! }
  const labels = d.split('.')
  for (let i = 1; i < labels.length; i++) {
    const candidate = labels.slice(i).join('.')
    if (domains.has(candidate)) return { domain: candidate, owner: domains.get(candidate)! }
  }
  return null
}

/** TODO.sota/05 — the owner's ROR id, joined from the countries'
 *  enriched org entries by the (iso, name) key both projections share
 *  (the pipeline derives them from one source; the probe proves 141/141
 *  coverage). NULL when the org carries no matched ROR id — never a
 *  guess. */
export function rorFor(owner: DomainOwner): string | null {
  const { rorByOrg } = loadDomains()
  return rorByOrg.get(`${owner.iso}|${owner.org}`) ?? null
}
