// The audit journal's filtered read — the ONE builder both stores share
// (the D1 and SQLite impls are the same dialect; the entity row's shape
// is the seam's contract). json_extract narrows the candidate set in SQL
// on the indexed action/entity_id/entity_type/timestamp columns (the
// json_valid guard spells idx_entities_store_action's expression exactly
// — migration 0023), newest first, LIMIT-bounded: an index walk, never
// the O(journal) full load + in-memory filter (the 2026-11-25 launcher
// red — ~90k rows / ~36 MB per request as the journal grew).
import type { AuditEventQuery } from '../store'

const LEG = (path: string) =>
  `json_extract(CASE WHEN json_valid(data) THEN data ELSE '{}' END, '$.${path}')`

/** Build the WHERE clauses + params for an audit query. Returns the SQL
 *  fragment (the leading AND …) and its bound params. */
export function auditQuerySql(filter: AuditEventQuery): { where: string; params: unknown[] } {
  const clauses: string[] = [`store = 'auditEvents'`]
  const params: unknown[] = []
  if (filter.entityId) { clauses.push(`${LEG('entity_id')} = ?`); params.push(filter.entityId) }
  if (filter.entityTypes?.length) {
    clauses.push(`${LEG('entity_type')} IN (${filter.entityTypes.map(() => '?').join(',')})`)
    params.push(...filter.entityTypes)
  }
  if (filter.actionEquals) { clauses.push(`${LEG('action')} = ?`); params.push(filter.actionEquals) }
  if (filter.actionPrefixes?.length) {
    clauses.push(`(${filter.actionPrefixes.map(() => `${LEG('action')} LIKE ?`).join(' OR ')})`)
    params.push(...filter.actionPrefixes.map(p => `${p}%`))
  }
  // A registry-style OR group: (entity_type IN …) OR (action LIKE …) —
  // the feed's admission is a UNION, never an intersection (an
  // 'account.invite' rides its entity_type, an 'org_invite.*' rides its
  // prefix). */
  if (filter.anyOf?.length) {
    const parts: string[] = []
    const anyParams: unknown[] = []
    for (const branch of filter.anyOf) {
      const b = auditQuerySql({ ...branch })
      // strip the always-true store clause from the branch fragment
      const branchClauses = b.where.replace("store = 'auditEvents'", '').trim().replace(/^AND\s+/, '')
      if (branchClauses) { parts.push(`(${branchClauses})`); anyParams.push(...b.params) }
    }
    if (parts.length) { clauses.push(`(${parts.join(' OR ')})`); params.push(...anyParams) }
  }
  if (filter.excludeActions?.length) {
    clauses.push(`${LEG('action')} NOT IN (${filter.excludeActions.map(() => '?').join(',')})`)
    params.push(...filter.excludeActions)
  }
  if (filter.from) { clauses.push(`${LEG('timestamp')} >= ?`); params.push(filter.from) }
  if (filter.to) { clauses.push(`${LEG('timestamp')} <= ?`); params.push(filter.to) }
  if (filter.orgId) {
    clauses.push(`(${LEG('entity_id')} = ? OR ${LEG('metadata.org_id')} = ?)`)
    params.push(filter.orgId, filter.orgId)
  }
  return { where: clauses.join(' AND '), params }
}

/** The full statement: newest-first. LIMIT applies ONLY when the caller
 *  declares one — a subject/org-scoped slice is bounded by the subject's
 *  own activity, and a trail's caller often needs the complete total (the
 *  registry detail's "first page + total"). The broad audit views declare
 *  their page size explicitly. */
export function auditQueryStatement(filter: AuditEventQuery): { sql: string; params: unknown[] } {
  const { where, params } = auditQuerySql(filter)
  const limit = filter.limit && Number.isFinite(filter.limit) && filter.limit > 0 ? Math.trunc(filter.limit) : undefined
  return {
    sql: `SELECT store, id, org_id, data, updated_at FROM entities WHERE ${where} ORDER BY ${LEG('timestamp')} DESC${limit ? ' LIMIT ?' : ''}`,
    params: limit ? [...params, limit] : params,
  }
}
