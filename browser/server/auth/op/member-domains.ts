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
    }
  }
  return catalog
}

/** The contract's matcher, verbatim: the exact flat-map hit, else the
 *  dot-boundary label walk (subdomains only), else null. */
export function resolveOrg(email: string): DomainOwner | null {
  const d = email.split('@')[1]?.toLowerCase()
  if (!d) return null
  const { domains } = loadDomains()
  if (domains.has(d)) return domains.get(d) ?? null
  const labels = d.split('.')
  for (let i = 1; i < labels.length; i++) {
    const candidate = labels.slice(i).join('.')
    if (domains.has(candidate)) return domains.get(candidate) ?? null
  }
  return null
}
