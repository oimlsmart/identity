// ═══════════════════════════════════════════════════════════════════
// TODO.sota/05 — the ROR backfill planner: the vendored member-domains
// artifact's ROR enrichment swept onto the EXISTING org_registry rows.
// The rows born of the self-registration materialization carry their
// rorId at birth (routes/op-self-register.ts); every row PREDATING the
// enrichment — and every row the owner's GAPS curation later enriches
// upstream — reaches its id through THIS plan.
//
// The join, in order (the probe-verified coverage):
//   1. the row's id IS an artifact domain (the self-register
//      materialization keys rows by domain — exact, no ambiguity);
//   2. the (country, name) pair matches a countries' org entry (the
//      bootstrap-imported rows, keyed by slug).
//
// PURE: the planner reads nothing, writes nothing — the script
// (scripts/ror-backfill.ts) prints the plan, applies it through the
// store seam locally (--execute), and emits the apply SQL for the live
// D1 (the operator's deliberate act, the import-org-registry
// convention). The artifact is the source of truth: a DRIFTED id is
// corrected, never preserved.
// ═══════════════════════════════════════════════════════════════════

import { loadDomains, type DomainsCatalog } from './auth/op/member-domains'

export interface RorBackfillAction {
  id: string
  name: string
  from: string | null
  to: string
  basis: 'domain-id' | 'iso-name' | 'member-body'
}

export interface RorBackfillPlan {
  actions: RorBackfillAction[]
  /** Matched rows whose id already agrees — no write. */
  unchanged: number
  /** Rows neither join matched — reported, never touched. */
  unmatched: string[]
}

/** The plan against the LIVE rows (id, name, country, rorId) using the
 *  vendored catalog (default: the bundled loadDomains()). Deterministic
 *  order (by row id) — the operator compares plans, not sets. */
export function planRorBackfill(
  rows: Array<{ id: string; name: string; country: string | null; rorId: string | null; kind?: string | null }>,
  catalog: DomainsCatalog = loadDomains(),
): RorBackfillPlan {
  // Join 2's index: (country name, org name) → the ROR id (the rows'
  // country column carries the artifact's English name — the same
  // source's spelling).
  const byCountryName = new Map<string, string>()
  for (const c of catalog.countries) {
    for (const o of c.orgs) {
      if (o.ror_id) byCountryName.set(`${c.country}|${o.name}`, o.ror_id)
    }
  }
  // Join 3's index (the SSOT arc, 2026-10-02): the MEMBER rows are
  // country-named BY DESIGN (the corrected member model — the row IS
  // the state), while the artifact enriches the member BODY org behind
  // the state. A member-state/corresponding-member row joins its
  // country's SINGLE enriched member body (the state's own metrology
  // organization); TWO enriched orgs is ambiguity — reported, never
  // guessed.
  const soleMemberBodyByCountry = new Map<string, string>()
  const memberBodyCounts = new Map<string, number>()
  for (const c of catalog.countries) {
    for (const o of c.orgs) {
      if (!o.ror_id) continue
      const key = c.country
      memberBodyCounts.set(key, (memberBodyCounts.get(key) ?? 0) + 1)
      soleMemberBodyByCountry.set(key, o.ror_id)
    }
  }
  for (const [key, count] of memberBodyCounts) {
    if (count > 1) soleMemberBodyByCountry.delete(key)
  }

  const actions: RorBackfillAction[] = []
  let unchanged = 0
  const unmatched: string[] = []
  for (const row of [...rows].sort((a, b) => a.id.localeCompare(b.id))) {
    let to: string | undefined
    let basis: RorBackfillAction['basis'] = 'domain-id'
    const owner = catalog.domains.get(row.id)
    if (owner) {
      to = catalog.rorByOrg.get(`${owner.iso}|${owner.org}`)
    }
    if (to === undefined && row.country && row.name) {
      to = byCountryName.get(`${row.country}|${row.name}`)
      basis = 'iso-name'
    }
    if (to === undefined && row.country && (row.kind === 'member-state' || row.kind === 'corresponding-member')) {
      to = soleMemberBodyByCountry.get(row.country)
      basis = 'member-body'
    }
    if (to === undefined) {
      unmatched.push(row.id)
      continue
    }
    if (row.rorId === to) {
      unchanged += 1
      continue
    }
    actions.push({ id: row.id, name: row.name, from: row.rorId, to, basis })
  }
  return { actions, unchanged, unmatched }
}

/** The apply SQL for one action — the live-D1 statement the operator
 *  runs (identical semantics to the store seam's update path: the
 *  updated_at/by stamps ride every write). */
export function actionToSql(action: RorBackfillAction, actor: string): string {
  const esc = (v: string) => `'${v.replace(/'/g, "''")}'`
  return `UPDATE org_registry SET ror_id = ${esc(action.to)}, updated_at = datetime('now'), updated_by = ${esc(actor)} WHERE id = ${esc(action.id)};`
}
