// ═══════════════════════════════════════════════════════════════════
// The org-register snapshot seed (the extraction map, smart's
// PROGRESS/41 §3): the identity service's dev/e2e posture reads the
// vendored demonstration register (browser/data/
// org-register.snapshot.yaml) into the entity store, so the join
// selector and the org-admin/registry consoles have real rows. The
// production feed from published content is a later wave (either
// repo), unchanged by the extraction — production degrades honestly
// (the "not listed" path routes to the scheme operator).
//
// TODO.identity-features/05 (organizations as first-class citizens):
// the SAME snapshot projects into the identity service's OWN org
// registry (the org_registry table) — the identity plane's membership
// graph. The mapping is the spec's §4: a participant org's id IS its
// OIML code, and participant_ref documents the participant record the
// row mirrors. The scheme-side admission state maps to the identity
// side's lifecycle honestly: a REGISTERED participant seeds ACTIVE; a
// mid-pipeline org (the demo register's XX1) seeds DISABLED — on the
// registry, never joinable, the lifecycle's demonstration. The demo
// cast's manufacturer binding (mfr-acme) seeds with the MANUFACTURER
// kind (TODO.register/01 — declared standing, never a participant): the
// registry row the platform's sample data names, resolvable on the OP's
// org id.
//
// NODE-ONLY (node:fs) — the dev-reset seam and the e2e stacks consume
// this; the Worker never imports it.
// ═══════════════════════════════════════════════════════════════════

import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { load as parseYaml } from 'js-yaml'
import type { ServerStore } from '@oimlsmart/platform-server/store'

const SNAPSHOT = join(dirname(fileURLToPath(import.meta.url)), '..', 'data', 'org-register.snapshot.yaml')

interface OrgRegisterSnapshot {
  organizations?: Array<Record<string, unknown>>
  utilizers?: Array<Record<string, unknown>>
  associates?: Array<Record<string, unknown>>
  participantDeclarations?: Array<Record<string, unknown>>
  participantApplications?: Array<Record<string, unknown>>
}

/** Upsert the snapshot into the entity store. Idempotent. Answers the
 *  per-collection counts for the caller's log line. */
export async function seedOrgRegisterSnapshot(store: ServerStore): Promise<Record<string, number>> {
  const snapshot = parseYaml(readFileSync(SNAPSHOT, 'utf-8')) as OrgRegisterSnapshot
  const counts: Record<string, number> = {}
  for (const [storeName, rows] of Object.entries(snapshot)) {
    if (!Array.isArray(rows)) continue
    let n = 0
    for (const row of rows) {
      const id = String(row.id ?? '')
      if (!id) continue
      await store.putEntity(storeName, id, null, JSON.stringify(row))
      n += 1
    }
    counts[storeName] = n
  }
  return counts
}

interface SnapshotContact { person?: string; email?: string }

/** The demonstration manufacturer's registry row (the demo cast's
 *  applicant binding): the MANUFACTURER kind (TODO.register/01) with
 *  the DECLARED standing — a first-class registry kind, never a PD-03
 *  participant. The contact declares the email-domain hint (the demo
 *  cast's ACME Applicant). The snapshot (the participants register)
 *  never carries it: manufacturers are not scheme participants. */
const DEMO_MANUFACTURER_ORGS = [
  {
    id: 'mfr-acme',
    name: 'ACME (the demonstration manufacturer)',
    shortName: 'ACME',
    country: 'Example Member State',
    contacts: [{ name: 'ACME Applicant', email: 'applicant@oiml.org' }],
  },
] as const

/** Project the snapshot into the identity service's OWN org registry
 *  (TODO.identity-features/05): one org_registry row per register
 *  organization, the scheme-side admission mapped to the lifecycle
 *  (registered → active; mid-pipeline → disabled), plus the demo cast's
 *  manufacturer binding (TODO.register/01). Idempotent (create-then-
 *  update). Answers the count for the caller's log line. */
export async function seedOrgRegistryFromSnapshot(store: ServerStore): Promise<number> {
  const snapshot = parseYaml(readFileSync(SNAPSHOT, 'utf-8')) as OrgRegisterSnapshot

  // The scheme-side admission state (the same rule the participants
  // register's resolver reads): a signed Declaration registers the
  // participant; the TL leg's ACTIVE participation case registers it.
  const registered = new Set<string>()
  for (const d of snapshot.participantDeclarations ?? []) {
    if (d.status === 'signed' && typeof d.participant_id === 'string') registered.add(d.participant_id)
  }
  for (const a of snapshot.participantApplications ?? []) {
    if (a.status === 'ACTIVE' && typeof a.applicant_organization_id === 'string') registered.add(a.applicant_organization_id)
  }

  let n = 0
  const rows: Array<[Array<Record<string, unknown>> | undefined, string]> = [
    [snapshot.organizations, ''],
    [snapshot.utilizers, 'utilizer'],
    [snapshot.associates, 'associate'],
  ]
  for (const [list, fixedKind] of rows) {
    for (const row of list ?? []) {
      const id = String(row.id ?? '')
      const name = typeof row.name === 'string' ? row.name : ''
      if (!id || !name) continue
      const contact = (row.contact ?? {}) as SnapshotContact
      const input = {
        id,
        name,
        shortName: typeof row.short_name === 'string' ? row.short_name : null,
        kind: fixedKind || (typeof row.kind === 'string' ? row.kind : null),
        country: typeof row.country === 'string' ? row.country : null,
        contacts: typeof contact.email === 'string' && contact.email
          ? [{ name: typeof contact.person === 'string' ? contact.person : null, email: contact.email }]
          : [],
        // §4: the participant org's id IS its code; participant_ref
        // documents the participant record the row mirrors.
        participantRef: id,
        createdBy: 'the demonstration seed',
      }
      const created = await store.createOrgRegistryOrg(input)
      if (!created) await store.updateOrgRegistryOrg(id, input, 'the demonstration seed')
      if (!registered.has(id)) {
        await store.setOrgRegistryOrgState(id, 'disabled', 'the demonstration seed')
      }
      n += 1
    }
  }
  for (const row of DEMO_MANUFACTURER_ORGS) {
    const input = {
      id: row.id,
      name: row.name,
      shortName: row.shortName,
      kind: 'manufacturer',
      country: row.country,
      contacts: [...row.contacts],
      participantRef: null,
      createdBy: 'the demonstration seed',
    }
    const created = await store.createOrgRegistryOrg(input)
    if (!created) await store.updateOrgRegistryOrg(row.id, input, 'the demonstration seed')
    n += 1
  }
  return n
}
