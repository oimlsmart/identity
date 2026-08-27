// ═══════════════════════════════════════════════════════════════════
// The per-org AUDIT SLICE (TODO.identity-features/09) — the ONE
// computation two readers share: the identity administrator's per-org
// aggregate (routes/op-registry.ts) and the org administrator's own
// slice (routes/op-memberships.ts, the org.users.manage grant). The
// org's own acts, newest first, 50 deep:
//
//   - the organization's lifecycle acts (entity_type 'organization'
//     naming the org);
//   - the membership acts NAMING the org (org_memberships rows whose
//     metadata carries the org — the invites, the role sets, the
//     lifecycle, and the CONE acts);
//   - the join-request + org-invite acts naming it.
//
// The slice is a READ projection of the journal (the auditEvents store)
// — the platform's caveat-close (the whole journal to any authenticated
// account) has no echo here: the org admin gets their org's acts,
// exactly, gated on the grant.
//
// WORKER-SAFE: the store seam only, no node built-ins.
// ═══════════════════════════════════════════════════════════════════

import type { ServerStore } from '@oimlsmart/platform-server/store'

/** The audit journal's parsed row (the shape every writer serializes
 *  into the entity's data — the twin of routes/op-registry.ts's and
 *  routes/op-dashboard.ts's local copies; the journal writers own the
 *  shape, the readers parse it defensively). */
export interface AuditEvent {
  id: string
  timestamp: string
  entity_type: string
  entity_id: string
  action: string
  user_id?: string
  user_name?: string
  metadata?: Record<string, unknown>
}

export function parseAuditEvent(data: string): AuditEvent | null {
  try {
    const parsed = JSON.parse(data) as AuditEvent
    if (typeof parsed?.id !== 'string' || typeof parsed?.action !== 'string') return null
    return parsed
  } catch {
    return null
  }
}

/** The org's own audit slice (newest first, 50 deep). */
export async function orgAuditSlice(store: ServerStore, orgId: string): Promise<AuditEvent[]> {
  const rows = await store.listEntities('auditEvents')
  return rows
    .map(row => parseAuditEvent(row.data))
    .filter((e): e is AuditEvent => !!e && (
      (e.entity_type === 'organization' && e.entity_id === orgId)
      || ((e.entity_type === 'org_memberships' || e.entity_type === 'org_join_requests' || e.action.startsWith('org_invite.'))
        && e.metadata?.org_id === orgId)
    ))
    .sort((a, b) => b.timestamp.localeCompare(a.timestamp))
    .slice(0, 50)
}
