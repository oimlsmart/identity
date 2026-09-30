// ─────────────────────────────────────────────────────────────────────
// The member-domains registry projection (the pipeline's
// dist/domains.json, vendored): the version-checked loader and the
// contract's own resolveOrg matcher — the flat map, then the
// dot-boundary label walk. The semantics pinned here are the
// member-domains contract's, verbatim.
// ─────────────────────────────────────────────────────────────────────

import { describe, expect, it } from 'vitest'
import { loadDomains, resolveOrg, assertVersion, rorFor } from '../../server/auth/op/member-domains'

describe('loadDomains (the vendored dist/domains.json)', () => {
  it('loads the version-2 artifact with both projections', () => {
    const catalog = loadDomains()
    expect(catalog.version).toBe(2)
    expect(catalog.domains.size).toBeGreaterThan(100)
    expect(catalog.countries.length).toBeGreaterThan(50)
    expect(catalog.generatedAt).toBeTruthy()
  })

  it('assertVersion refuses a foreign shape loudly', () => {
    expect(() => assertVersion({ version: 1 })).toThrow()
    expect(() => assertVersion({ version: 2 } as never)).not.toThrow()
  })
})

describe('resolveOrg (the member-domains contract, dot-boundary mandatory)', () => {
  it('matches the exact domain and carries the roles on the hit', () => {
    const hit = resolveOrg('someone@nist.gov')
    expect(hit).not.toBeNull()
    expect(hit?.org).toContain('National Institute of Standards and Technology')
    expect(hit?.roles).toContain('ciml-member')
  })

  it('matches a subdomain — only under the dot boundary', () => {
    expect(resolveOrg('x@sub.nist.gov')?.org).toBeTruthy()
    expect(resolveOrg('x@nist.gov.example.com')).toBeNull()
    expect(resolveOrg('x@nistgovie.gov')).toBeNull()
  })

  it('a free-mail or disposable provider matches nothing', () => {
    expect(resolveOrg('x@gmail.com')).toBeNull()
    expect(resolveOrg('x@mailinator.com')).toBeNull()
  })

  it('is case-insensitive on the domain', () => {
    expect(resolveOrg('x@NIST.GOV')?.org).toBeTruthy()
  })

  it('carries the bilingual country on the hit', () => {
    const czech = [...loadDomains().domains.entries()].find(([, v]) => v.country_fr === 'Tchéquie')
    expect(czech).toBeTruthy()
    expect(resolveOrg(`x@${czech![0]}`)?.country_fr).toBe('Tchéquie')
  })

  it('answers null for a malformed address', () => {
    expect(resolveOrg('not-an-address')).toBeNull()
    expect(resolveOrg('')).toBeNull()
  })
})

describe('rorFor (TODO.sota/05 — the ROR enrichment, the iso+name join)', () => {
  it('answers the matched org\'s ROR id (NIST, the domain-anchored hit)', () => {
    expect(rorFor(resolveOrg('someone@nist.gov')!)).toBe('https://ror.org/05xpvk416')
  })

  it('answers null for an unmatched org — never a guess', () => {
    const unmatched = [...loadDomains().domains.entries()].find(([, v]) => rorFor(v) === null)
    expect(unmatched).toBeTruthy()
    expect(rorFor(unmatched![1])).toBeNull()
  })

  it('answers null outside the catalog (an org the artifact does not name)', () => {
    expect(rorFor({ country: 'x', country_fr: 'x', iso: 'XX', status: 'associate', org: 'No Such Org', roles: [], verification: 'inferred', evidence: '' })).toBeNull()
  })
})
